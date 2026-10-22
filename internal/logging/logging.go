// Package logging 提供结构化 JSON 日志（slog），输出到 stdout，供 journald 收集。
// 约束：任何日志字段不得包含 API Key、ntfy Token 等凭据。
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// ParseLevel 解析日志级别字符串，非法值返回错误。
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("未知日志级别 %q（支持 debug/info/warn/error）", s)
	}
}

// New 创建输出到 w 的 JSON Logger。
func New(level string, w io.Writer) (*slog.Logger, error) {
	lv, err := ParseLevel(level)
	if err != nil {
		return nil, err
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lv})
	return slog.New(h), nil
}
