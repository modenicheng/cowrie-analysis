// Package reports 实现周期安全报告的生成流程（SPEC §8.1/§11/§16）：
// 窗口计算 → SQL 统计 → 关键事件采样 → 提示词组装 → LLM（带工具调用）
// → submit_report 草稿校验（key_stats 必须与 SQL 统计一致）→ 归档落库
// → ntfy 发布。数据缺口（gaps/采集停滞）必须写入报告 data_quality，
// 不得掩盖。
package reports

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"unicode/utf8"

	"github.com/modenc/e3-security-analyst/internal/query"
)

// 草稿字段长度约束（与 tools 层 submit_report 的校验口径一致，此处兜底：
// 无工具模式下模型最终输出不经过 tools 层，直接由 SubmitDraft 校验）。
const (
	draftMaxTitleRunes         = 120
	draftMinSummaryRunes       = 10
	draftMaxSummaryRunes       = 4000
	draftMaxFindings           = 50
	draftMaxFindingTitleRunes  = 120
	draftMaxFindingDetailRunes = 2000
	draftMaxEvidenceItems      = 20
	draftMaxEvidenceRunes      = 200
)

// draftValidSeverities 是 findings.severity 允许的取值。
var draftValidSeverities = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true,
}

// Draft 是 submit_report 草稿的结构化形态（严格解码：未知字段拒绝）。
type Draft struct {
	Type            string    `json:"type"`
	Title           string    `json:"title"`
	Summary         string    `json:"summary"`
	Findings        []Finding `json:"findings"`
	KeyStats        *KeyStats `json:"key_stats"`
	Confidence      *float64  `json:"confidence"`
	DataLimitations string    `json:"data_limitations"`
}

// Finding 是一条重要发现。
type Finding struct {
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
	Severity string   `json:"severity"`
	Evidence []string `json:"evidence"`
}

// KeyStats 是报告必须对齐 SQL 统计的四个核心指标。用 *float64 承载以
// 区分「缺失」与 0，并校验非负整数（与 tools 层口径一致）。
type KeyStats struct {
	Connections  *float64 `json:"connections"`
	UniqueSrcIPs *float64 `json:"unique_src_ips"`
	LoginSuccess *float64 `json:"login_success"`
	LoginFailed  *float64 `json:"login_failed"`
}

// runSubmitter 是单次 Generate 内的草稿校验器（实现 tools.ReportSubmitter）。
// 每次 Generate 构造一个实例、绑定该次任务的 kind 与 SQL 统计，避免跨任务
// 共享可变状态（并发安全：同一 submitter 只会被同一次 Run 循环串行调用，
// 互斥锁仅作兜底）。校验通过后保存模型原始草稿（raw）与解析结果。
type runSubmitter struct {
	kind  string
	stats *query.Stats // 步骤 3 的 SQL 统计，key_stats 的唯一对齐基准

	mu       sync.Mutex
	accepted bool
	raw      json.RawMessage
	draft    *Draft
}

// SubmitDraft 校验并接收草稿：JSON 严格解码 → type/长度/枚举/confidence
// 兜底校验 → key_stats 四值与 SQL 统计逐一相等。任何一项不通过都返回
// 模型可读的中文拒绝原因（附正确值与模型给出的值），让模型修正后重试。
func (s *runSubmitter) SubmitDraft(_ context.Context, draftJSON []byte, taskType string) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accepted {
		return false, "本任务已接收一份报告草稿，请勿重复提交"
	}

	var d Draft
	dec := json.NewDecoder(bytes.NewReader(draftJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return false, "报告草稿不是合法的 Draft JSON（严格模式，未知字段与类型错误均拒绝）: " + err.Error()
	}

	if reason := validateDraftFields(taskType, &d); reason != "" {
		return false, reason
	}
	if reason := checkKeyStats(d.KeyStats, s.stats); reason != "" {
		return false, reason
	}

	s.accepted = true
	s.raw = append(json.RawMessage(nil), draftJSON...)
	s.draft = &d
	return true, ""
}

// result 返回已接受的草稿（raw 原文 + 解析结果）；尚未接受时 ok=false。
func (s *runSubmitter) result() (raw json.RawMessage, d *Draft, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.accepted {
		return nil, nil, false
	}
	return s.raw, s.draft, true
}

// validateDraftFields 做结构兜底校验（tools 层已做过等价校验；无工具模式
// 下这是唯一一道防线），全部通过返回空串。
func validateDraftFields(taskType string, d *Draft) string {
	if d.Type != taskType {
		return fmt.Sprintf("报告 type=%q 与当前任务类型 %q 不符：本任务只能提交 %s 报告", d.Type, taskType, taskType)
	}
	if n := utf8.RuneCountInString(d.Title); n < 1 || n > draftMaxTitleRunes {
		return fmt.Sprintf("title 长度需在 1..%d rune 之间，当前 %d", draftMaxTitleRunes, n)
	}
	if n := utf8.RuneCountInString(d.Summary); n < draftMinSummaryRunes || n > draftMaxSummaryRunes {
		return fmt.Sprintf("summary 长度需在 %d..%d rune 之间，当前 %d",
			draftMinSummaryRunes, draftMaxSummaryRunes, n)
	}
	if len(d.Findings) > draftMaxFindings {
		return fmt.Sprintf("findings 数量超过上限：最多 %d 条，当前 %d 条", draftMaxFindings, len(d.Findings))
	}
	for i, f := range d.Findings {
		if n := utf8.RuneCountInString(f.Title); n < 1 || n > draftMaxFindingTitleRunes {
			return fmt.Sprintf("findings[%d].title 长度需在 1..%d rune 之间，当前 %d",
				i, draftMaxFindingTitleRunes, n)
		}
		if n := utf8.RuneCountInString(f.Detail); n > draftMaxFindingDetailRunes {
			return fmt.Sprintf("findings[%d].detail 超过 %d rune 上限，当前 %d",
				i, draftMaxFindingDetailRunes, n)
		}
		if !draftValidSeverities[f.Severity] {
			return fmt.Sprintf("findings[%d].severity=%q 非法，必须为 info/low/medium/high/critical 之一", i, f.Severity)
		}
		if len(f.Evidence) > draftMaxEvidenceItems {
			return fmt.Sprintf("findings[%d].evidence 最多 %d 项，当前 %d 项", i, draftMaxEvidenceItems, len(f.Evidence))
		}
		for j, ev := range f.Evidence {
			if n := utf8.RuneCountInString(ev); n > draftMaxEvidenceRunes {
				return fmt.Sprintf("findings[%d].evidence[%d] 超过 %d rune 上限，当前 %d",
					i, j, draftMaxEvidenceRunes, n)
			}
		}
	}
	if d.Confidence == nil {
		return "confidence 缺失：请给出 [0,1] 区间的分析置信度"
	}
	if *d.Confidence < 0 || *d.Confidence > 1 {
		return fmt.Sprintf("confidence=%v 超出 [0,1] 区间", *d.Confidence)
	}
	return ""
}

// checkKeyStats 校验 key_stats 四项齐全、为非负整数，且与步骤 3 的 SQL
// 统计逐一相等；不一致时返回附正确值与模型值的中文原因。
func checkKeyStats(ks *KeyStats, stats *query.Stats) string {
	if ks == nil {
		return "key_stats 缺失：必须包含 connections、unique_src_ips、login_success、login_failed 四个非负整数（数值请使用任务 STATS_JSON 或 query_stats 的 SQL 统计结果）"
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
			return fmt.Sprintf(
				"key_stats.%s 缺失：四个字段（connections、unique_src_ips、login_success、login_failed）均必须为非负整数，请补全",
				f.name)
		}
		if *f.v < 0 || *f.v != math.Trunc(*f.v) {
			return fmt.Sprintf("key_stats.%s 必须为非负整数，当前 %v", f.name, *f.v)
		}
	}
	want := []struct {
		name  string
		value int
		got   *float64
	}{
		{"connections", stats.Connections, ks.Connections},
		{"unique_src_ips", stats.UniqueSrcIPs, ks.UniqueSrcIPs},
		{"login_success", stats.LoginSuccess, ks.LoginSuccess},
		{"login_failed", stats.LoginFailed, ks.LoginFailed},
	}
	for _, w := range want {
		if int(*w.got) != w.value {
			return fmt.Sprintf(
				"key_stats.%s=%d 与 SQL 统计 %d 不一致：正确值为 %d（以任务 STATS_JSON 或 query_stats 返回为准），请修正后重新提交",
				w.name, int(*w.got), w.value, w.value)
		}
	}
	return ""
}
