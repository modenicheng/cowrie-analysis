package reports

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// —— escapeCommonMark 单元 ——
func TestEscapeCommonMark(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"plain ascii 123", "plain ascii 123"},
		{"中文与 ASCII 混排", "中文与 ASCII 混排"},
		{"[点我](https://evil.example)", `\[点我](https://evil.example)`},
		{"![img](https://evil.example/x.png)", `!\[img](https://evil.example/x.png)`},
		{"<https://evil.example>", `\<https://evil.example>`},
		// 攻击者自带的反斜杠转义不得拆解重组出链接。
		{`\[x](https://evil.example)`, `\\\[x](https://evil.example)`},
		{`反斜杠 \ 单独出现`, `反斜杠 \\ 单独出现`},
		{"引用 [b](u) 与 <v> 同时出现", `引用 \[b](u) 与 \<v> 同时出现`},
	}
	for _, c := range cases {
		if got := escapeCommonMark(c.in); got != c.want {
			t.Errorf("escapeCommonMark(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

// —— 端到端：恶意 summary/finding 标题进入 Markdown 正文时被转义 ——
func TestGenerateMarkdownBodyEscapesAttackerContent(t *testing.T) {
	te := newTestEnv(t, nil)
	fi := &fakeImager{}
	te.gen.SetImager(fi)
	_, ks := seedDailyWindow(t, te.db, te.loc)

	evilSummary := `摘要 [点我](https://evil.example) <https://evil.example> \[再来](javascript:x)`
	evilTitle := `用户名 "[admin](https://evil.example) 注入"`
	d := map[string]any{
		"type":    "daily",
		"title":   "E3 安全日报｜测试窗口",
		"summary": evilSummary,
		"findings": []map[string]any{{
			"title":    evilTitle,
			"detail":   "x",
			"severity": "high",
			"evidence": []string{"stats:login_success"},
		}},
		"key_stats": map[string]any{
			"connections":    ks[0],
			"unique_src_ips": ks[1],
			"login_success":  ks[2],
			"login_failed":   ks[3],
		},
		"confidence":       0.85,
		"data_limitations": "无",
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("构造恶意草稿失败: %v", err)
	}
	te.llm.steps = []mockStep{
		stepTool("query_stats", "{}"),
		stepTool("submit_report", string(b)),
		stepFinal(`{"done":true}`),
	}

	if err := te.gen.Generate(context.Background(), "daily"); err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}
	reqs := te.ntfy.requests()
	if len(reqs) != 1 {
		t.Fatalf("ntfy 收到 %d 条, 期望 1", len(reqs))
	}
	body := reqs[0].Body

	// summary 是正文首段：精确断言前缀（Contains 会被转义形态的子串
	// 污染，只能精确比较）。
	if want := `摘要 \[点我](https://evil.example) \<https://evil.example> \\\[再来](javascript:x)`; !strings.HasPrefix(body, want) {
		t.Errorf("summary 转义不符:\n got 前 120 字: %q\n want: %q", firstN(body, 120), want)
	}
	if want := "\n- [high] " + `用户名 "\[admin](https://evil.example) 注入"`; !strings.Contains(body, want) {
		t.Errorf("finding 标题转义不符，正文:\n%s", body)
	}
}

// firstN 返回 s 的前 n 个 rune（错误信息截断用）。
func firstN(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}
