// Package tools 实现面向 LLM 的工具调度层（SPEC §7、§9）：query_events、
// query_stats、execute_js 与 submit_report。
//
// 约定：Handle 返回 (结果JSON, nil)；参数校验失败、非法用法与基础设施
// 故障一律返回 ("", error)，由 llm 客户端包装成 {"error":"..."} 回传模型，
// 因此错误消息必须面向模型可读，便于其自行纠正后重试。
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modenc/e3-security-analyst/internal/config"
	"github.com/modenc/e3-security-analyst/internal/llm"
	"github.com/modenc/e3-security-analyst/internal/sandbox"
	"github.com/modenc/e3-security-analyst/internal/store"
)

// defaultMaxSpanDays 在配置缺失（<=0）时兜底的最大查询跨度（天）。
const defaultMaxSpanDays = 31

// TaskWindow 约束一次分析任务：查询窗口默认值、报告类型与审计关联。
type TaskWindow struct {
	Since, Until time.Time
	Type         string // daily|weekly
	RunID        string // analysis_runs.id，供 script_runs 审计关联
}

// ReportSubmitter 校验并接收报告草稿（由 reports 层实现）。
type ReportSubmitter interface {
	// 校验通过收下草稿（返回 accepted=true）；否则给出模型可读的拒绝原因。
	SubmitDraft(ctx context.Context, draft []byte, taskType string) (bool, string)
}

// Dispatcher 把模型工具调用分派到本地实现。无内部可变状态，可并发使用。
type Dispatcher struct {
	cfg       *config.Config
	db        *store.DB
	runner    *sandbox.Runner
	submitter ReportSubmitter
	log       *slog.Logger
}

// NewDispatcher 创建调度器。runner 为 nil 时 execute_js 返回“已禁用”；
// submitter 为 nil 时 submit_report 返回不可用错误；log 为 nil 时静默。
func NewDispatcher(cfg *config.Config, db *store.DB, runner *sandbox.Runner,
	submitter ReportSubmitter, log *slog.Logger) *Dispatcher {
	if cfg == nil {
		cfg = config.Default()
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Dispatcher{cfg: cfg, db: db, runner: runner, submitter: submitter, log: log}
}

// Handle 执行一次工具调用，返回结果 JSON。未知工具名返回 "unknown tool" 错误。
func (d *Dispatcher) Handle(ctx context.Context, call llm.ToolCall, win TaskWindow) (string, error) {
	switch call.Name {
	case "query_events":
		return d.handleQueryEvents(ctx, call, win)
	case "query_stats":
		return d.handleQueryStats(ctx, call, win)
	case "execute_js":
		return d.handleExecuteJS(ctx, call, win)
	case "submit_report":
		return d.handleSubmitReport(ctx, call, win)
	default:
		return "", fmt.Errorf(
			"unknown tool %q（可用工具：query_events、query_stats、execute_js、submit_report）",
			call.Name)
	}
}

// Specs 返回暴露给模型的四个工具定义（名称 + JSON Schema）。
func (d *Dispatcher) Specs() []llm.ToolSpec {
	return []llm.ToolSpec{
		{
			Name: "query_events",
			Description: "查询蜜罐事件明细，时间窗口 [since,until) 左闭右开。" +
				"since/until 缺省用当前任务窗口；可按来源 IP、会话、事件类型过滤。" +
				"返回字段按配置裁剪；结果受 256KiB 字节上限与 limit 条数上限约束，" +
				"超出时返回 next_cursor，请携带 cursor 参数续查剩余数据。",
			ParametersJSON: []byte(queryEventsSchema),
		},
		{
			Name: "query_stats",
			Description: "获取窗口内确定性统计：连接数、独立来源 IP、登录成功/失败、" +
				"来源 IP/用户名/命令排名、事件类型分布、会话时长、文件制品、" +
				"小时/日趋势、与前一周期对比及数据质量。所有数值来自 SQL 聚合，" +
				"报告中 key_stats 必须使用这些数值，禁止估算。",
			ParametersJSON: []byte(queryStatsSchema),
		},
		{
			Name: "execute_js",
			Description: "在受限沙箱子进程中执行一段 JavaScript 完成自定义计算。" +
				"全局环境只有 input 变量与 JS 标准内建对象：没有网络、文件、" +
				"系统命令或宿主接口。需要更多数据时请重新调用 query_events/query_stats。" +
				"脚本错误（语法错误、超时、输出超限）会结构化返回 ok=false，" +
				"请根据 error 修正代码后重试。",
			ParametersJSON: []byte(executeJSSchema),
		},
		{
			Name: "submit_report",
			Description: "提交最终安全报告草稿。type 必须与当前任务类型一致；" +
				"字段长度受限；key_stats 四个指标必须与 query_stats 结果一致；" +
				"结论需在 findings.evidence 中引用事件/会话 ID。" +
				"不允许携带 url/topic/token 字段；发布目标由系统配置固定。",
			ParametersJSON: []byte(submitReportSchema),
		},
	}
}

// resolveWindow 解析查询窗口：参数为 null/缺省时沿用任务窗口对应边界，
// 显式给出时必须为合法 RFC3339；合成后的 [since,until) 必须有效且跨度
// 不超过 cfg.Reports.MaxQuerySpanDays（超出时错误消息给出允许的最大跨度）。
func (d *Dispatcher) resolveWindow(win TaskWindow, sinceArg, untilArg *string) (time.Time, time.Time, error) {
	since, until := win.Since, win.Until
	if sinceArg != nil {
		t, err := time.Parse(time.RFC3339, *sinceArg)
		if err != nil {
			return time.Time{}, time.Time{},
				fmt.Errorf("since=%q 不是合法的 RFC3339 时间: %v", *sinceArg, err)
		}
		since = t
	}
	if untilArg != nil {
		t, err := time.Parse(time.RFC3339, *untilArg)
		if err != nil {
			return time.Time{}, time.Time{},
				fmt.Errorf("until=%q 不是合法的 RFC3339 时间: %v", *untilArg, err)
		}
		until = t
	}
	if since.IsZero() || until.IsZero() {
		return time.Time{}, time.Time{}, fmt.Errorf(
			"查询窗口不完整：since/until 未给出且任务窗口缺失（since=%s until=%s）",
			since.Format(time.RFC3339), until.Format(time.RFC3339))
	}
	if !until.After(since) {
		return time.Time{}, time.Time{}, fmt.Errorf(
			"查询窗口无效：until（%s）必须晚于 since（%s）",
			until.Format(time.RFC3339), since.Format(time.RFC3339))
	}
	maxDays := d.cfg.Reports.MaxQuerySpanDays
	if maxDays <= 0 {
		maxDays = defaultMaxSpanDays
	}
	if spanDays := until.Sub(since).Hours() / 24; spanDays > float64(maxDays) {
		return time.Time{}, time.Time{}, fmt.Errorf(
			"查询窗口跨度 %.2f 天超过允许的最大跨度 %d 天（reports.max_query_span_days），"+
				"请缩小 since/until 范围或改用 query_stats 获取聚合统计",
			spanDays, maxDays)
	}
	return since.UTC(), until.UTC(), nil
}

// 四个工具的 JSON Schema（ParametersJSON，均为合法 JSON）。
const (
	queryEventsSchema = `{
  "type": "object",
  "properties": {
    "since":       {"type": "string", "format": "date-time", "description": "窗口起点（含），RFC3339；null/省略=任务窗口起点"},
    "until":       {"type": "string", "format": "date-time", "description": "窗口终点（不含），RFC3339；null/省略=任务窗口终点"},
    "src_ip":      {"type": "string", "description": "按来源 IP 精确过滤"},
    "session":     {"type": "string", "description": "按会话 ID 精确过滤"},
    "event_types": {"type": "array", "items": {"type": "string"}, "maxItems": 100, "description": "按 cowrie eventid 过滤，如 cowrie.login.failed"},
    "limit":       {"type": "integer", "minimum": 1, "maximum": 1000, "description": "返回条数上限；默认 500，最大 1000"},
    "cursor":      {"type": "integer", "minimum": 0, "description": "分页游标：上一页返回的 next_cursor，返回 id 更大的事件"}
  },
  "additionalProperties": false
}`

	queryStatsSchema = `{
  "type": "object",
  "properties": {
    "since":     {"type": "string", "format": "date-time", "description": "窗口起点（含），RFC3339；null/省略=任务窗口起点"},
    "until":     {"type": "string", "format": "date-time", "description": "窗口终点（不含），RFC3339；null/省略=任务窗口终点"},
    "top_n":     {"type": "integer", "minimum": 1, "maximum": 50, "description": "各排行榜返回条数；默认 10，最大 50"},
    "with_prev": {"type": "boolean", "description": "是否包含紧邻前一同长窗口对比；默认 true"}
  },
  "additionalProperties": false
}`

	executeJSSchema = `{
  "type": "object",
  "properties": {
    "code":       {"type": "string", "minLength": 1, "description": "JavaScript 源码；只能访问 input 与 JS 内建对象"},
    "input":      {"description": "任意 JSON 输入，脚本内通过 input 变量访问"},
    "timeout_ms": {"type": "integer", "minimum": 1, "description": "执行超时；缺省与上限由系统配置决定"}
  },
  "required": ["code"],
  "additionalProperties": false
}`

	submitReportSchema = `{
  "type": "object",
  "properties": {
    "type":             {"type": "string", "enum": ["daily", "weekly"], "description": "必须与当前任务类型一致"},
    "title":            {"type": "string", "minLength": 1, "maxLength": 120},
    "summary":          {"type": "string", "minLength": 10, "maxLength": 4000},
    "findings":         {"type": "array", "maxItems": 50, "items": {
        "type": "object",
        "properties": {
            "title":    {"type": "string", "minLength": 1, "maxLength": 120},
            "detail":   {"type": "string", "maxLength": 2000},
            "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
            "evidence": {"type": "array", "maxItems": 20, "items": {"type": "string", "maxLength": 200}}
        },
        "required": ["title", "detail", "severity"],
        "additionalProperties": false
    }},
    "key_stats":        {"type": "object",
        "properties": {
            "connections":   {"type": "integer", "minimum": 0},
            "unique_src_ips": {"type": "integer", "minimum": 0},
            "login_success": {"type": "integer", "minimum": 0},
            "login_failed":  {"type": "integer", "minimum": 0}
        },
        "required": ["connections", "unique_src_ips", "login_success", "login_failed"],
        "additionalProperties": false,
        "description": "数值必须与 query_stats 的 SQL 统计一致"},
    "confidence":       {"type": "number", "minimum": 0, "maximum": 1},
    "data_limitations": {"type": "string", "description": "数据缺口与置信不足说明；无则空串"}
  },
  "required": ["type", "title", "summary", "findings", "key_stats", "confidence"],
  "additionalProperties": false
}`
)

// decodeStrict 解码工具参数（严格模式）：未知字段报错，帮助模型发现拼写
// 错误（如 srcip vs src_ip）；空参数视为 {}。
func decodeStrict(argsJSON string, dst any) error {
	s := strings.TrimSpace(argsJSON)
	if s == "" {
		s = "{}"
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// rawString 从原始 JSON 行的对象键中提取字符串值；键不存在或值非字符串
// 时返回 ok=false（Cowrie 的 message/password/url/outfile 均为字符串）。
func rawString(raw map[string]json.RawMessage, key string) (string, bool) {
	v, ok := raw[key]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", false
	}
	return s, true
}

// truncateRunes 把字符串截断到最多 max 个 rune（用于 raw.message 输出）。
func truncateRunes(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max])
}

// truncateBytes 把字符串截断到最多 max 字节；必要时回退到合法 rune 边界，
// 避免产生非法 UTF-8 尾部（用于 script_runs.output_preview）。输入须为
// 合法 UTF-8。
func truncateBytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := s[:max]
	for n := 0; n < utf8.UTFMax && len(cut) > 0 && !utf8.ValidString(cut); n++ {
		cut = cut[:len(cut)-1]
	}
	return cut
}
