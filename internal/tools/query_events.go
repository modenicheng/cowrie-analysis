package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/modenc/e3-security-analyst/internal/config"
	"github.com/modenc/e3-security-analyst/internal/llm"
	"github.com/modenc/e3-security-analyst/internal/query"
	"github.com/modenc/e3-security-analyst/internal/store"
)

// query_events 工具约束。
const (
	defaultEventLimit = 500       // limit 缺省值
	maxEventLimit     = 1000      // limit 钳制上限
	maxEventsBytes    = 256 << 10 // 裁剪后事件对象序列化字节的累计上限（256KiB）
	maxMessageRunes   = 200       // raw.message 输出截断长度（rune）
	maxEventTypes     = 100       // event_types 条目上限（防巨型 IN 子句）
	truncationNote    = "字节上限截断，请用 cursor 续查"
)

// queryEventsArgs 是 query_events 的参数。
type queryEventsArgs struct {
	Since      *string  `json:"since"`
	Until      *string  `json:"until"`
	SrcIP      *string  `json:"src_ip"`
	Session    *string  `json:"session"`
	EventTypes []string `json:"event_types"`
	Limit      *int     `json:"limit"`
	Cursor     *int64   `json:"cursor"`
}

// eventsResult 是 query_events 的返回信封。Events 为逐条预序列化的裁剪
// 事件（json.RawMessage 原样嵌入，不重复序列化）。
type eventsResult struct {
	Events     []json.RawMessage `json:"events"`
	Count      int               `json:"count"`
	NextCursor *int64            `json:"next_cursor,omitempty"`
	Truncated  bool              `json:"truncated"`
	Note       string            `json:"note,omitempty"`
	TotalHint  *int              `json:"total_hint,omitempty"`
}

// handleQueryEvents 执行 query_events：窗口校验（默认任务窗口，跨度受
// MaxQuerySpanDays 限制）、limit 钳制（默认 500 / 上限 1000）、cursor 分页、
// 256KiB 字节预算（超出即停，不塞半条，置 truncated=true + next_cursor）。
// 首页（无 cursor）附 total_hint（同条件 CountEvents）；带 cursor 的后续
// 页省略，避免每页全量计数。raw 全文不输出。
func (d *Dispatcher) handleQueryEvents(ctx context.Context, call llm.ToolCall, win TaskWindow) (string, error) {
	var a queryEventsArgs
	if err := decodeStrict(call.ArgsJSON, &a); err != nil {
		return "", fmt.Errorf("query_events 参数不合法: %v", err)
	}
	since, until, err := d.resolveWindow(win, a.Since, a.Until)
	if err != nil {
		return "", err
	}

	limit := defaultEventLimit
	if a.Limit != nil {
		if *a.Limit < 1 {
			return "", fmt.Errorf("query_events.limit 必须为 1..%d 的整数，当前 %d", maxEventLimit, *a.Limit)
		}
		if *a.Limit > maxEventLimit {
			limit = maxEventLimit
		} else {
			limit = *a.Limit
		}
	}
	var cursor int64
	if a.Cursor != nil {
		if *a.Cursor < 0 {
			return "", fmt.Errorf("query_events.cursor 不能为负数，当前 %d", *a.Cursor)
		}
		cursor = *a.Cursor
	}
	if len(a.EventTypes) > maxEventTypes {
		return "", fmt.Errorf("query_events.event_types 最多 %d 项，当前 %d 项", maxEventTypes, len(a.EventTypes))
	}
	for _, t := range a.EventTypes {
		if strings.TrimSpace(t) == "" {
			return "", fmt.Errorf("query_events.event_types 包含空字符串，请使用完整 cowrie eventid（如 cowrie.login.failed）")
		}
	}

	f := store.EventFilter{Since: since, Until: until, Limit: limit, CursorID: cursor}
	if a.SrcIP != nil {
		f.SrcIP = *a.SrcIP
	}
	if a.Session != nil {
		f.Session = *a.Session
	}
	if len(a.EventTypes) > 0 {
		f.EventIDs = a.EventTypes
	}

	events, err := query.QueryEvents(ctx, d.db, f)
	if err != nil {
		return "", fmt.Errorf("query_events 查询失败: %w", err)
	}

	// 按字节预算逐条序列化；达到上限即停止（不塞半条）。
	res := eventsResult{Events: make([]json.RawMessage, 0, len(events))}
	budget := maxEventsBytes
	var lastID int64
	for i, e := range events {
		b, err := json.Marshal(TrimEvent(d.cfg, e))
		if err != nil {
			return "", fmt.Errorf("query_events 序列化事件 id=%d 失败: %w", e.ID, err)
		}
		if len(b) > budget {
			res.Truncated = true
			if i == 0 {
				// 单条事件即超预算：仍返回这一条（略微超出预算），
				// 保证 next_cursor 可推进、模型不会卡死在同一页。
				res.Events = append(res.Events, json.RawMessage(b))
				lastID = e.ID
			}
			break
		}
		budget -= len(b)
		res.Events = append(res.Events, json.RawMessage(b))
		lastID = e.ID
	}
	res.Count = len(res.Events)
	if res.Truncated {
		res.NextCursor = &lastID
		res.Note = truncationNote
	} else if len(events) == limit && len(events) > 0 {
		// 未超字节预算但取满 limit：提供游标供翻页。
		res.NextCursor = &lastID
	}
	if cursor == 0 {
		// 首页才计算 total_hint（CountEvents 忽略 Limit/CursorID）。
		n, err := query.CountEvents(ctx, d.db, f)
		if err != nil {
			return "", fmt.Errorf("query_events 统计总数失败: %w", err)
		}
		res.TotalHint = &n
	}

	out, err := json.Marshal(res)
	if err != nil {
		return "", fmt.Errorf("query_events 序列化结果失败: %w", err)
	}
	d.log.Debug("query_events 完成", "count", res.Count, "truncated", res.Truncated)
	return string(out), nil
}

// TrimEvent 构造单条事件的裁剪输出对象（§9/§13 字段矩阵）。这是字段
// 裁剪口径的唯一实现，query_events（模型工具输出）与 reports 的关键事件
// 采样（提示词注入）共用，保证模型在两条路径看到的事件字段完全一致：
//
//	id/event_id/time/src_port/session/username/duration_s 恒定输出；
//	src_ip 受 reports.include_source_ips 控制（关闭时输出 src_ip_omitted）；
//	command 受 reports.include_commands；
//	filename/shasum/outfile/url 受 reports.include_paths；
//	message 从 raw 提取并截 200 rune，恒定输出；
//	password 仅当 llm.include_passwords 时从 raw 提取输出（原值）；
//	raw 全文与其余字段一律不输出（模型需要细节时引用 event id 人工复查）。
//
// Agent 自身凭据（API Key/Token 等）从不进入本函数的任何输出。
func TrimEvent(cfg *config.Config, e *store.Event) map[string]any {
	m := map[string]any{
		"id":         e.ID,
		"event_id":   e.EventID,
		"time":       e.EventTime.UTC().Format(time.RFC3339),
		"src_port":   e.SrcPort,
		"session":    e.Session,
		"username":   e.Username,
		"duration_s": e.DurationS,
	}
	if cfg.Reports.IncludeSourceIPs {
		m["src_ip"] = e.SrcIP
	} else {
		m["src_ip_omitted"] = true
	}

	var raw map[string]json.RawMessage
	if e.Raw != "" {
		// raw 由 collector 校验过；解析失败只是缺少 raw 提取字段，不失败。
		_ = json.Unmarshal([]byte(e.Raw), &raw)
	}

	if cfg.Reports.IncludeCommands && e.Command != "" {
		m["command"] = e.Command
	}
	if cfg.Reports.IncludePaths {
		if e.Filename != "" {
			m["filename"] = e.Filename
		}
		if e.Shasum != "" {
			m["shasum"] = e.Shasum
		}
		if v, ok := rawString(raw, "outfile"); ok && v != "" {
			m["outfile"] = v
		}
		if v, ok := rawString(raw, "url"); ok && v != "" {
			m["url"] = v
		}
	}
	if v, ok := rawString(raw, "message"); ok && v != "" {
		m["message"] = TruncateRunes(v, maxMessageRunes)
	}
	if cfg.LLM.IncludePasswords {
		if v, ok := rawString(raw, "password"); ok && v != "" {
			m["password"] = v
		}
	}
	return m
}
