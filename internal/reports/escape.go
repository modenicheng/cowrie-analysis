// 本文件实现报告 Markdown 正文的注入防御：报告 summary 与 finding
// 标题会回显攻击者可控内容（用户名、命令原文等可能嵌入其中），在以
// Markdown 发送（ntfy X-Markdown 渲染）前必须转义，防止组成可点击的
// 链接/图片/自动链接（与 rules.sanitizeField 同类防线，Medium 级）。
package reports

import "strings"

// escapeCommonMark 把自由文本安全地嵌入 Markdown 正文：
//
//  1. 先转义反斜杠——否则攻击者自带的 "\[" 加上对 "[" 的转义会拼出
//     "\\[x](url)"，CommonMark 把 "\\" 解析为字面反斜杠后，剩余
//     "[x](url)" 仍组成链接；
//  2. 再转义 '[' 与 '<'——链接/图片 "[text](url)" 与自动链接 "<url>"
//     的构成字符，前置反斜杠后渲染端最多显示字面量。
//
// severity 等经 SubmitDraft 枚举校验的字段、图表 URL 与归档路径等
// 程序生成串不经此函数。纯文本正文路径不渲染 Markdown，无需转义。
func escapeCommonMark(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		if r == '\\' || r == '[' || r == '<' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
