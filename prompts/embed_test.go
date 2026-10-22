package prompts

import (
	"strings"
	"testing"
)

// TestFSContainsTemplates 确认内嵌 FS 恰好包含且能读出 3 个 .md 模板。
func TestFSContainsTemplates(t *testing.T) {
	for _, name := range []string{"analyst.md", "daily-report.md", "weekly-report.md"} {
		b, err := FS.ReadFile(name)
		if err != nil {
			t.Fatalf("读取模板 %s 失败: %v", name, err)
		}
		if len(b) == 0 {
			t.Fatalf("模板 %s 为空", name)
		}
	}
	entries, err := FS.ReadDir(".")
	if err != nil {
		t.Fatalf("FS.ReadDir 失败: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("内嵌 .md 模板数量 = %d，期望 3", len(entries))
	}
}

// TestTemplatesContainPlaceholders 确认两个用户消息模板包含全部
// __NAME__ 占位符，且都声明了 submit_report 与 key_stats 一致性要求。
func TestTemplatesContainPlaceholders(t *testing.T) {
	placeholders := []string{
		"__WINDOW_START__", "__WINDOW_END__",
		"__STATS_JSON__", "__QUALITY_JSON__", "__KEY_EVENTS_JSON__",
	}
	for _, name := range []string{"daily-report.md", "weekly-report.md"} {
		b, err := FS.ReadFile(name)
		if err != nil {
			t.Fatalf("读取模板 %s 失败: %v", name, err)
		}
		s := string(b)
		for _, p := range placeholders {
			if !strings.Contains(s, p) {
				t.Fatalf("%s 缺少占位符 %s", name, p)
			}
		}
		if !strings.Contains(s, "submit_report") {
			t.Fatalf("%s 未声明 submit_report 提交要求", name)
		}
		if !strings.Contains(s, "key_stats") {
			t.Fatalf("%s 未声明 key_stats 一致性要求", name)
		}
	}
}
