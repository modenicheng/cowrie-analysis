// Package prompts 内嵌分析提示词模板。
//
// FS 包含 analyst.md（系统提示词）、daily-report.md 与 weekly-report.md
// （用户消息模板）。模板中的 __NAME__ 占位符由调用方用 strings.NewReplacer
// 替换为窗口时间、统计 JSON、数据质量 JSON 与代表性事件 JSON。
package prompts

import "embed"

//go:embed *.md
var FS embed.FS
