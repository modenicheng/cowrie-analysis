package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modenc/e3-security-analyst/internal/llm"
	"github.com/modenc/e3-security-analyst/internal/query"
)

// query_stats 工具约束。
const (
	defaultStatsTopN = 10 // top_n 缺省值
	maxStatsTopN     = 50 // top_n 钳制上限
)

// queryStatsArgs 是 query_stats 的参数。
type queryStatsArgs struct {
	Since    *string `json:"since"`
	Until    *string `json:"until"`
	TopN     *int    `json:"top_n"`
	WithPrev *bool   `json:"with_prev"`
}

// handleQueryStats 执行 query_stats：窗口规则与 query_events 相同（默认
// 任务窗口、跨度校验），top_n 默认 10 / 上限 50，with_prev 缺省 true。
// 结果为 query.ComputeStats 的原样 JSON——所有数值来自 SQL 聚合，
// 本层不做任何改动。
func (d *Dispatcher) handleQueryStats(ctx context.Context, call llm.ToolCall, win TaskWindow) (string, error) {
	var a queryStatsArgs
	if err := decodeStrict(call.ArgsJSON, &a); err != nil {
		return "", fmt.Errorf("query_stats 参数不合法: %v", err)
	}
	since, until, err := d.resolveWindow(win, a.Since, a.Until)
	if err != nil {
		return "", err
	}

	topN := defaultStatsTopN
	if a.TopN != nil {
		if *a.TopN < 1 {
			return "", fmt.Errorf("query_stats.top_n 必须为 1..%d 的整数，当前 %d", maxStatsTopN, *a.TopN)
		}
		if *a.TopN > maxStatsTopN {
			topN = maxStatsTopN
		} else {
			topN = *a.TopN
		}
	}
	withPrev := true
	if a.WithPrev != nil {
		withPrev = *a.WithPrev
	}

	st, err := query.ComputeStats(ctx, d.db, query.StatsQuery{
		Since: since, Until: until, TopN: topN, WithPrev: withPrev,
	})
	if err != nil {
		return "", fmt.Errorf("query_stats 统计失败: %w", err)
	}
	out, err := json.Marshal(st)
	if err != nil {
		return "", fmt.Errorf("query_stats 序列化结果失败: %w", err)
	}
	d.log.Debug("query_stats 完成", "since", since, "until", until)
	return string(out), nil
}
