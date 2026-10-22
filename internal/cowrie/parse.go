// Package cowrie 的解析实现：把一行 Cowrie JSONL 日志解析为结构化事件。
//
// 解析原则（SPEC §6.1/§9）：未知字段不丢弃、不报错；攻击者可控字段一律视为
// 数据保持原值（不脱敏）；字段类型异常时尽力转换（如数字型 src_ip），无法合理
// 转换则留空，绝不因未知/缺失字段拒绝整行。只有 JSON 本身非法才返回 error，
// 由调用方写入 parse_errors 隔离表。
package cowrie

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Event 是 ParseEvent 的解析结果，字段与 store.Event 一一对应。
//
// 契约说明：CONTRACTS.md 原文签名为 (*store.Event, error)，但 internal/store
// 的 events.go 已依赖本包的 Classify（store → cowrie），若本包再 import store
// 会构成导入循环（已实测 "import cycle not allowed"）。store 属并行开发中的
// 禁改文件，故这里定义字段完全一致的 Event，由 internal/collector 做零损耗
// 字段拷贝；待 orchestrator 解除 store → cowrie 依赖后可一处改回 *store.Event。
type Event struct {
	EventID     string    // cowrie eventid
	EventTime   time.Time // 事件时间（UTC）
	CollectedAt time.Time // 采集时间（UTC），零值由 store.InsertEvents 填充
	SrcIP       string
	SrcPort     int64
	Session     string
	Username    string
	Command     string // cowrie.command.input 的 input 字段（原值，不脱敏）
	Filename    string // file_upload/file_download 的文件名
	Shasum      string
	DurationS   float64 // session.closed 的 duration
	Raw         string  // 原始 JSON 行（去掉行尾 \r\n），无损保留
}

// ParseEvent 解析一行 JSON。JSON 非法 → (nil, error)，调用方写 parse_errors。
// JSON 合法但缺 timestamp → EventTime = fallback；缺 eventid → EventID=""。
// message 等未映射字段不单列，只保留在 Raw 中（契约要求）。
// input 仅在为字符串时映射到 Command（契约要求）。
// Filename 按 filename > url > outfile 顺序取第一个非空字符串（覆盖
// file_download 的 url/filename 变体与 file_upload 的 outfile）。
func ParseEvent(line []byte, fallbackTime time.Time) (*Event, error) {
	var obj map[string]any
	if err := json.Unmarshal(line, &obj); err != nil {
		return nil, fmt.Errorf("cowrie.ParseEvent: JSON 非法: %w", err)
	}
	ev := &Event{Raw: strings.TrimRight(string(line), "\r\n")}
	if obj == nil { // JSON "null" 合法：视为空对象
		ev.EventTime = fallbackTime
		return ev, nil
	}

	ev.EventID = asString(obj["eventid"])
	if ts := asString(obj["timestamp"]); ts != "" {
		if t, err := ParseTimestamp(ts); err == nil {
			ev.EventTime = t
		} else {
			ev.EventTime = fallbackTime // 非法时间戳：回退 fallback，不报错（契约）
		}
	} else {
		ev.EventTime = fallbackTime // 缺省：回退 fallback
	}

	ev.Session = asString(obj["session"])
	ev.SrcIP = asString(obj["src_ip"])
	ev.SrcPort = asInt64(obj["src_port"])
	ev.Username = asString(obj["username"])
	if s, ok := obj["input"].(string); ok {
		ev.Command = s
	}
	ev.Filename = firstNonEmpty(asString(obj["filename"]), asString(obj["url"]), asString(obj["outfile"]))
	ev.Shasum = asString(obj["shasum"])
	ev.DurationS = asFloat64(obj["duration"])
	return ev, nil
}

// timestampLayouts 按契约顺序尝试的 Cowrie 时间格式。
var timestampLayouts = []string{
	time.RFC3339Nano,                  // 2026-01-02T15:04:05.999999999+08:00
	"2006-01-02T15:04:05.999999-0700", // +0000 无冒号数字时区变体
	"2006-01-02 15:04:05.999999",      // 空格分隔、无时区（按 UTC 解析）
	time.RFC3339,
}

// ParseTimestamp 兼容 Cowrie 多种时间格式，按序尝试；全失败返回 error。
// 返回值统一转换为 UTC（无时区的布局按 UTC 解析）。
func ParseTimestamp(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("cowrie.ParseTimestamp: 空时间串")
	}
	var firstErr error
	for _, layout := range timestampLayouts {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t.UTC(), nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return time.Time{}, fmt.Errorf("cowrie.ParseTimestamp: 无法解析 %q: %w", s, firstErr)
}

// asString 尽力把 JSON 值转成字符串：字符串原样；数字用最短十进制表示
// （如 src_ip 写成数字 3232235777 → "3232235777"）；布尔转文本；
// null/数组/对象无合理字符串语义，返回空。
func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	default:
		return ""
	}
}

// asInt64 数字直接取整，字符串按十进制解析，其余返回 0（字段缺失/类型不符留空）。
func asInt64(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n
	default:
		return 0
	}
}

// asFloat64 数字直接取值，字符串按浮点解析，其余返回 0。
func asFloat64(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f
	default:
		return 0
	}
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
