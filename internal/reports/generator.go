package reports

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/modenc/e3-security-analyst/internal/config"
	"github.com/modenc/e3-security-analyst/internal/llm"
	"github.com/modenc/e3-security-analyst/internal/ntfy"
	"github.com/modenc/e3-security-analyst/internal/query"
	"github.com/modenc/e3-security-analyst/internal/sandbox"
	"github.com/modenc/e3-security-analyst/internal/scheduler"
	"github.com/modenc/e3-security-analyst/internal/store"
	"github.com/modenc/e3-security-analyst/internal/tools"
	"github.com/modenc/e3-security-analyst/prompts"
)

// generateTimeout 是一次 Generate 的总预算（LLM 循环 + 草稿校验）。
const generateTimeout = 10 * time.Minute

// statsTopN 是注入提示词的统计排行榜条数。
const statsTopN = 15

// runIDBytes 是 analysis_runs.id 的随机字节数（hex 编码后 32 字符）。
const runIDBytes = 16

// Generator 生成日报/周报（SPEC §8.1 十步流程）。零内部可变共享状态：
// 每次 Generate 构造 run 级 Dispatcher 与草稿校验器，可安全并发调用。
type Generator struct {
	cfg    *config.Config
	db     *store.DB
	client *llm.Client
	runner *sandbox.Runner
	pub    *ntfy.Publisher
	log    *slog.Logger
	loc    *time.Location

	// disp 是契约规定的 Generator 自有 Dispatcher（submitter=Generator
	// 自身，见 CONTRACTS internal/reports）。Generate 实际执行时另建
	// run 级 Dispatcher 绑定局部草稿校验器，避免并发任务互相串状态；
	// disp.SubmitDraft 经 active 转发到当前进行中的任务。
	disp *tools.Dispatcher

	mu     sync.Mutex
	active *runSubmitter // 当前注册的运行级草稿校验器（供 Generator.SubmitDraft 转发）
}

// NewGenerator 创建报告生成器。runner 为 nil 或 cfg.ScriptRunner.Enabled=false
// 时 execute_js 不可用；pub 为 nil 时跳过 ntfy 发布（仅归档落库）。
func NewGenerator(cfg *config.Config, db *store.DB, client *llm.Client,
	runner *sandbox.Runner, pub *ntfy.Publisher, log *slog.Logger) (*Generator, error) {
	if cfg == nil {
		cfg = config.Default()
	}
	if db == nil {
		return nil, fmt.Errorf("reports.NewGenerator: db 不能为 nil")
	}
	if client == nil {
		return nil, fmt.Errorf("reports.NewGenerator: client 不能为 nil")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	loc, err := cfg.Location()
	if err != nil {
		return nil, fmt.Errorf("reports.NewGenerator: 加载时区 %q 失败: %w", cfg.App.Timezone, err)
	}
	g := &Generator{
		cfg:    cfg,
		db:     db,
		client: client,
		runner: runner,
		pub:    pub,
		log:    log,
		loc:    loc,
	}
	g.disp = tools.NewDispatcher(cfg, db, runner, g, log)
	return g, nil
}

// SubmitDraft 实现 tools.ReportSubmitter（转发到当前进行中任务的 run 级
// 校验器）。Generate 的工具调用实际绑定 run 级 Dispatcher，不经此路径；
// 该方法服务于契约（g 自身作为 NewDispatcher 的 submitter）。
func (g *Generator) SubmitDraft(ctx context.Context, draft []byte, taskType string) (bool, string) {
	g.mu.Lock()
	active := g.active
	g.mu.Unlock()
	if active == nil {
		return false, "当前没有进行中的分析任务，无法接收报告草稿"
	}
	return active.SubmitDraft(ctx, draft, taskType)
}

// setActive/clearActive 维护当前运行级校验器（仅清除同一实例，防止并发
// 任务间误清）。
func (g *Generator) setActive(s *runSubmitter) {
	g.mu.Lock()
	g.active = s
	g.mu.Unlock()
}

func (g *Generator) clearActive(s *runSubmitter) {
	g.mu.Lock()
	if g.active == s {
		g.active = nil
	}
	g.mu.Unlock()
}

// Generate 按 SPEC §8.1 十步流程生成一份报告：
//
//	窗口 → 记录(reports/analysis_runs) → SQL 统计 → 关键事件 → 提示词
//	→ LLM（工具循环）→ 收稿（submit_report 优先，否则解析最终输出）
//	→ SubmitDraft 校验 → 归档落库 → ntfy 发布。
//
// 失败路径：FinishAnalysisRun(failed) + UpsertReport(status=failed) +
// 返回 error，不发送任何报告通知。通知发送失败不算生成失败（报告保持
// validated，通知留 pending 由 daemon 重试，返回 nil）。
func (g *Generator) Generate(ctx context.Context, kind string) error {
	if kind != scheduler.KindDaily && kind != scheduler.KindWeekly {
		return fmt.Errorf("reports.Generate: 未知报告类型 %q（仅支持 daily/weekly）", kind)
	}

	// —— 步骤 1：统计窗口 ——
	since, until, err := scheduler.WindowFor(kind, time.Now(), g.loc)
	if err != nil {
		return fmt.Errorf("reports.Generate: 计算统计窗口失败: %w", err)
	}

	// —— 步骤 2：记录 reports（pending，attempts=上一次+1）与 analysis_runs ——
	prev, err := g.db.GetReport(ctx, kind, since)
	if err != nil {
		return fmt.Errorf("reports.Generate: 读取历史报告失败: %w", err)
	}
	rep := &store.Report{
		Type:        kind,
		WindowStart: since,
		WindowEnd:   until,
		Status:      "pending",
		Model:       g.cfg.LLM.Model,
		Attempts:    1,
		UpdatedAt:   time.Now().UTC(),
	}
	if prev != nil {
		rep.Attempts = prev.Attempts + 1
	}
	if err := g.db.UpsertReport(ctx, rep); err != nil {
		return fmt.Errorf("reports.Generate: 写入报告记录失败: %w", err)
	}

	runID, err := newRunID()
	if err != nil {
		return fmt.Errorf("reports.Generate: 生成运行 ID 失败: %w", err)
	}
	run := &store.AnalysisRun{
		ID:        runID,
		Task:      kind,
		StartedAt: time.Now().UTC(),
		Status:    "running",
		Model:     g.cfg.LLM.Model,
	}
	if err := g.db.CreateAnalysisRun(ctx, run); err != nil {
		return g.failRun(rep, nil, fmt.Errorf("创建分析运行记录失败: %w", err))
	}
	fail := func(cause error) error {
		return g.failRun(rep, run, cause)
	}
	g.log.Info("开始生成报告", "kind", kind, "run_id", runID,
		"window_start", since.In(g.loc).Format("2006-01-02 15:04:05"),
		"window_end", until.In(g.loc).Format("2006-01-02 15:04:05"),
		"attempts", rep.Attempts)

	// —— 步骤 3：SQL 确定性统计 ——
	stats, err := query.ComputeStats(ctx, g.db, query.StatsQuery{
		Since: since, Until: until, TopN: statsTopN, WithPrev: true,
	})
	if err != nil {
		return fail(fmt.Errorf("计算窗口统计失败: %w", err))
	}

	// —— 步骤 4：关键事件采样（总字节 ≤ 32KiB）——
	keyEvents, err := g.collectKeyEvents(ctx, since, until, stats)
	if err != nil {
		return fail(err)
	}

	// —— 步骤 5：提示词组装 ——
	systemPrompt, userPrompt, err := g.buildPrompts(kind, since, until, stats, keyEvents)
	if err != nil {
		return fail(err)
	}

	// —— 步骤 6：LLM（ctx 总预算 10 分钟；工具绑定任务窗口）——
	runCtx, cancel := context.WithTimeout(ctx, generateTimeout)
	defer cancel()
	win := tools.TaskWindow{Since: since, Until: until, Type: kind, RunID: runID}

	sub := &runSubmitter{kind: kind, stats: stats}
	g.setActive(sub)
	defer g.clearActive(sub)
	rdisp := tools.NewDispatcher(g.cfg, g.db, g.runner, sub, g.log)

	req := llm.RunRequest{SystemPrompt: systemPrompt, UserPrompt: userPrompt}
	if g.cfg.LLM.EnableTools {
		specs := rdisp.Specs()
		req.Tools = make(map[string]llm.ToolSpec, len(specs))
		req.Handlers = make(map[string]llm.ToolHandler, len(specs))
		for _, s := range specs {
			req.Tools[s.Name] = s
			req.Handlers[s.Name] = func(ctx context.Context, call llm.ToolCall) (string, error) {
				return rdisp.Handle(ctx, call, win)
			}
		}
	}
	res, err := g.client.Run(runCtx, req)
	if err != nil {
		return fail(fmt.Errorf("LLM 分析失败: %w", err))
	}

	// —— 步骤 7/8：收稿与 SubmitDraft 校验 ——
	// 优先使用循环中 submit_report 被接受的草稿；否则把最终输出当作草稿
	// 走同一校验。两者都失败 → 报告失败。
	draftRaw, draft, ok := sub.result()
	if !ok {
		content := strings.TrimSpace(string(res.Content))
		accepted, reason := sub.SubmitDraft(runCtx, []byte(content), kind)
		if !accepted {
			return fail(fmt.Errorf("模型最终输出未通过报告校验: %s", reason))
		}
		draftRaw, draft, ok = sub.result()
		if !ok {
			return fail(fmt.Errorf("报告草稿校验内部错误：校验通过但未保存草稿"))
		}
	}

	// —— 步骤 9：归档与落库 ——
	payload := g.buildPayload(kind, since, until, stats, draftRaw)
	data, sha, archivePath, err := g.archiveReport(kind, since, payload)
	if err != nil {
		return fail(err)
	}
	rep.Status = "validated"
	rep.Payload = string(data)
	rep.ContentSHA256 = sha
	rep.UpdatedAt = time.Now().UTC()
	if err := g.db.UpsertReport(ctx, rep); err != nil {
		return fail(fmt.Errorf("落库报告结果失败: %w", err))
	}

	// —— 步骤 10：ntfy 发布（发送失败不算生成失败）——
	if g.pub != nil {
		if err := g.publishReport(ctx, kind, since, until, draft, stats.Quality.Gaps, archivePath); err != nil {
			return fail(err)
		}
		if status := g.notificationStatus(ctx, fmt.Sprintf("report:%s:%d", kind, since.Unix())); status == "sent" {
			rep.Status = "published"
			rep.UpdatedAt = time.Now().UTC()
			if err := g.db.UpsertReport(ctx, rep); err != nil {
				// 通知已发送、报告已归档为 validated：仅记日志，不算生成失败。
				g.log.Warn("标记报告 published 失败（通知已发送，报告保持 validated）",
					"kind", kind, "err", err)
			}
		} else {
			g.log.Warn("报告通知未送达，报告保持 validated 由 daemon 补发",
				"kind", kind, "notification_status", status)
		}
	}

	// —— 成功：补全运行记录（rounds/tokens/toolcalls 来自 RunResult）——
	run.Status = "ok"
	run.Rounds = res.Rounds
	run.PromptTokens = res.PromptTokens
	run.CompletionTokens = res.CompletionTokens
	run.ToolCalls = res.ToolCalls
	if err := g.db.FinishAnalysisRun(ctx, run); err != nil {
		g.log.Warn("记录分析运行成功状态失败（报告已完成）", "run_id", runID, "err", err)
	}
	g.log.Info("报告生成完成", "kind", kind, "run_id", runID, "status", rep.Status,
		"archive", archivePath, "rounds", res.Rounds, "tool_calls", res.ToolCalls)
	return nil
}

// failRun 是统一失败路径：FinishAnalysisRun(failed)（error 摘要截 500 字）
// + UpsertReport(status=failed) + 返回包装 error；不发送任何报告通知。
// run 为 nil 表示运行记录尚未创建。失败落库使用独立短超时上下文，避免
// 调用方 ctx 已取消时连失败状态都写不进去。
func (g *Generator) failRun(rep *store.Report, run *store.AnalysisRun, cause error) error {
	fctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	summary := clipErr(cause.Error(), notifyMaxErrRunes)
	if run != nil {
		run.Status = "failed"
		run.Error = summary
		if err := g.db.FinishAnalysisRun(fctx, run); err != nil {
			g.log.Warn("记录失败运行状态出错", "run_id", run.ID, "err", err)
		}
	}
	rep.Status = "failed"
	rep.Error = summary
	rep.UpdatedAt = time.Now().UTC()
	if err := g.db.UpsertReport(fctx, rep); err != nil {
		g.log.Warn("更新失败报告状态出错", "kind", rep.Type, "err", err)
	}
	kind := rep.Type
	runID := ""
	if run != nil {
		runID = run.ID
	}
	g.log.Error("报告生成失败", "kind", kind, "run_id", runID, "error", cause)
	return fmt.Errorf("reports.Generate(%s): %w", kind, cause)
}

// buildPrompts 读取内嵌模板并替换占位符：
//
//	__WINDOW_START__/__WINDOW_END__：北京时间 "2006-01-02 15:04:05"；
//	__STATS_JSON__：完整 Stats（缩进序列化）；
//	__QUALITY_JSON__：Stats.Quality；
//	__KEY_EVENTS_JSON__：关键事件样本。
func (g *Generator) buildPrompts(kind string, since, until time.Time, stats *query.Stats, keyEvents []byte) (system, user string, err error) {
	sysBytes, err := prompts.FS.ReadFile("analyst.md")
	if err != nil {
		return "", "", fmt.Errorf("读取系统提示词失败: %w", err)
	}
	tplName := "daily-report.md"
	if kind == scheduler.KindWeekly {
		tplName = "weekly-report.md"
	}
	tplBytes, err := prompts.FS.ReadFile(tplName)
	if err != nil {
		return "", "", fmt.Errorf("读取报告模板 %s 失败: %w", tplName, err)
	}
	statsJSON, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("序列化统计失败: %w", err)
	}
	qualityJSON, err := json.MarshalIndent(stats.Quality, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("序列化数据质量失败: %w", err)
	}
	replacer := strings.NewReplacer(
		"__WINDOW_START__", since.In(g.loc).Format("2006-01-02 15:04:05"),
		"__WINDOW_END__", until.In(g.loc).Format("2006-01-02 15:04:05"),
		"__STATS_JSON__", string(statsJSON),
		"__QUALITY_JSON__", string(qualityJSON),
		"__KEY_EVENTS_JSON__", string(keyEvents),
	)
	return string(sysBytes), replacer.Replace(string(tplBytes)), nil
}

// newRunID 用 crypto/rand 生成 16 字节随机数的 hex（32 字符）。
func newRunID() (string, error) {
	b := make([]byte, runIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
