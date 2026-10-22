package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/modenc/e3-security-analyst/internal/llm"
)

// runeLen 返回字符串的 rune 数（长度限制均按 rune 计）。
func runeLen(s string) int { return utf8.RuneCountInString(s) }

// submit_report 校验约束。
const (
	maxTitleRunes         = 120 // 报告标题
	minSummaryRunes       = 10  // 摘要下限
	maxSummaryRunes       = 4000
	maxFindings           = 50
	maxFindingTitleRunes  = 120
	maxFindingDetailRunes = 2000
	maxEvidenceItems      = 20
	maxEvidenceRunes      = 200
)

// validSeverities 是 findings.severity 允许的取值。
var validSeverities = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true,
}

// bannedDraftKeys 是草稿顶层禁止携带的键：报告发布目标由系统配置固定，
// 模型不得指定任意 URL / ntfy 主题 / Token（防注入面，SPEC §7.4、§12）。
var bannedDraftKeys = []string{"url", "topic", "token"}

// reportDraft 是 submit_report 草稿的已知字段（未知字段忽略不报错，
// 兼容模型附加说明性字段）。
type reportDraft struct {
	Type            string         `json:"type"`
	Title           string         `json:"title"`
	Summary         string         `json:"summary"`
	Findings        []findingDraft `json:"findings"`
	KeyStats        *keyStatsDraft `json:"key_stats"`
	Confidence      *float64       `json:"confidence"`
	DataLimitations string         `json:"data_limitations"`
}

type findingDraft struct {
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
	Severity string   `json:"severity"`
	Evidence []string `json:"evidence"`
}

// keyStatsDraft 用 *float64 承载，以便区分“缺失”与 0，并校验非负整数。
type keyStatsDraft struct {
	Connections  *float64 `json:"connections"`
	UniqueSrcIPs *float64 `json:"unique_src_ips"`
	LoginSuccess *float64 `json:"login_success"`
	LoginFailed  *float64 `json:"login_failed"`
}

// handleSubmitReport 执行 submit_report：先拒绝 url/topic/token 键，再做
// 严格校验（type 必须等于任务窗口 Type、长度限制、severity 枚举、
// key_stats 四项非负整数齐全、confidence∈[0,1]），全部通过后把原始
// draft JSON 原样交给 submitter。被 submitter 拒绝不是错误：返回
// {"accepted":false,"reason":...}，让模型读取 reason 修正后重试。
func (d *Dispatcher) handleSubmitReport(ctx context.Context, call llm.ToolCall, win TaskWindow) (string, error) {
	if d.submitter == nil {
		return "", fmt.Errorf("submit_report 不可用：未配置报告提交器")
	}
	draft := []byte(strings.TrimSpace(call.ArgsJSON))
	var top map[string]json.RawMessage
	if err := json.Unmarshal(draft, &top); err != nil {
		return "", fmt.Errorf("submit_report 参数不是合法 JSON 对象: %v", err)
	}
	for _, banned := range bannedDraftKeys {
		if _, ok := top[banned]; ok {
			return "", fmt.Errorf(
				"submit_report 不允许携带 %q 字段：报告发布目标由系统配置固定，模型不能指定",
				banned)
		}
	}

	var dr reportDraft
	if err := json.Unmarshal(draft, &dr); err != nil {
		return "", fmt.Errorf("submit_report 参数不合法: %v", err)
	}

	if dr.Type != win.Type {
		return "", fmt.Errorf("报告 type=%q 与当前任务类型 %q 不符：本任务只能提交 %s 报告",
			dr.Type, win.Type, win.Type)
	}
	if n := runeLen(dr.Title); n < 1 || n > maxTitleRunes {
		return "", fmt.Errorf("title 长度需在 1..%d rune 之间，当前 %d", maxTitleRunes, n)
	}
	if n := runeLen(dr.Summary); n < minSummaryRunes || n > maxSummaryRunes {
		return "", fmt.Errorf("summary 长度需在 %d..%d rune 之间，当前 %d",
			minSummaryRunes, maxSummaryRunes, n)
	}
	if len(dr.Findings) > maxFindings {
		return "", fmt.Errorf("findings 数量超过上限：最多 %d 条，当前 %d 条", maxFindings, len(dr.Findings))
	}
	for i, f := range dr.Findings {
		if n := runeLen(f.Title); n < 1 || n > maxFindingTitleRunes {
			return "", fmt.Errorf("findings[%d].title 长度需在 1..%d rune 之间，当前 %d",
				i, maxFindingTitleRunes, n)
		}
		if n := runeLen(f.Detail); n > maxFindingDetailRunes {
			return "", fmt.Errorf("findings[%d].detail 超过 %d rune 上限，当前 %d",
				i, maxFindingDetailRunes, n)
		}
		if !validSeverities[f.Severity] {
			return "", fmt.Errorf("findings[%d].severity=%q 非法，必须为 info/low/medium/high/critical 之一",
				i, f.Severity)
		}
		if len(f.Evidence) > maxEvidenceItems {
			return "", fmt.Errorf("findings[%d].evidence 最多 %d 项，当前 %d 项",
				i, maxEvidenceItems, len(f.Evidence))
		}
		for j, ev := range f.Evidence {
			if n := runeLen(ev); n > maxEvidenceRunes {
				return "", fmt.Errorf("findings[%d].evidence[%d] 超过 %d rune 上限，当前 %d",
					i, j, maxEvidenceRunes, n)
			}
		}
	}
	if dr.Confidence == nil {
		return "", fmt.Errorf("confidence 缺失：请给出 [0,1] 区间的分析置信度")
	}
	if *dr.Confidence < 0 || *dr.Confidence > 1 {
		return "", fmt.Errorf("confidence=%v 超出 [0,1] 区间", *dr.Confidence)
	}
	if err := validateKeyStats(dr.KeyStats); err != nil {
		return "", err
	}

	// 原始 draft JSON 原样提交（不经序列化往返，保留模型的原始内容）。
	accepted, reason := d.submitter.SubmitDraft(ctx, draft, win.Type)
	if accepted {
		d.log.Info("报告草稿被接受", "type", win.Type, "run_id", win.RunID)
		return `{"accepted":true}`, nil
	}
	out, err := json.Marshal(map[string]any{"accepted": false, "reason": reason})
	if err != nil {
		return "", fmt.Errorf("submit_report 序列化拒绝原因失败: %w", err)
	}
	d.log.Info("报告草稿被拒绝", "type", win.Type, "reason", reason)
	return string(out), nil
}

// validateKeyStats 校验 key_stats 四个字段齐全且为非负整数。
func validateKeyStats(ks *keyStatsDraft) error {
	if ks == nil {
		return fmt.Errorf(
			"key_stats 缺失：必须包含 connections、unique_src_ips、login_success、login_failed 四个非负整数（数值请使用 query_stats 的 SQL 统计结果）")
	}
	fields := []struct {
		name string
		v    *float64
	}{
		{"connections", ks.Connections},
		{"unique_src_ips", ks.UniqueSrcIPs},
		{"login_success", ks.LoginSuccess},
		{"login_failed", ks.LoginFailed},
	}
	for _, f := range fields {
		if f.v == nil {
			return fmt.Errorf(
				"key_stats.%s 缺失：四个字段（connections、unique_src_ips、login_success、login_failed）均必须为非负整数，请补全",
				f.name)
		}
		if *f.v < 0 || *f.v != math.Trunc(*f.v) {
			return fmt.Errorf("key_stats.%s 必须为非负整数，当前 %v", f.name, *f.v)
		}
	}
	return nil
}
