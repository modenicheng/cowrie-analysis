package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 默认值：软/硬轮数上限、思考开关与输出 Token 上限。
func TestLLMDefaults(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("Default() 应通过校验: %v", err)
	}
	if c.LLM.MaxToolRounds != 8 {
		t.Errorf("默认 max_tool_rounds = %d, want 8（软上限）", c.LLM.MaxToolRounds)
	}
	if c.LLM.HardToolRounds != 24 {
		t.Errorf("默认 hard_tool_rounds = %d, want 24", c.LLM.HardToolRounds)
	}
	if c.LLM.MaxOutputTokens != 131072 {
		t.Errorf("默认 max_output_tokens = %d, want 131072", c.LLM.MaxOutputTokens)
	}
	if c.LLM.Thinking != "auto" {
		t.Errorf("默认 thinking = %q, want auto", c.LLM.Thinking)
	}
	if c.LLM.ReasoningEffort != "" {
		t.Errorf("默认 reasoning_effort = %q, want 空串", c.LLM.ReasoningEffort)
	}
}

// thinking / reasoning_effort 枚举校验：报错必须含字段名与允许值。
func TestLLMThinkingAndEffortValidation(t *testing.T) {
	cases := []struct {
		mutate    func(*Config)
		wantSubs  []string
		wantError bool
	}{
		{func(c *Config) { c.LLM.Thinking = "auto" }, nil, false},
		{func(c *Config) { c.LLM.Thinking = "on" }, nil, false},
		{func(c *Config) { c.LLM.Thinking = "off" }, nil, false},
		{func(c *Config) { c.LLM.Thinking = "enabled" },
			[]string{"llm.thinking", "auto", "on", "off"}, true},
		{func(c *Config) { c.LLM.ReasoningEffort = "" }, nil, false},
		{func(c *Config) { c.LLM.ReasoningEffort = "low" }, nil, false},
		{func(c *Config) { c.LLM.ReasoningEffort = "medium" }, nil, false},
		{func(c *Config) { c.LLM.ReasoningEffort = "high" }, nil, false},
		{func(c *Config) { c.LLM.ReasoningEffort = "max" }, nil, false},
		{func(c *Config) { c.LLM.ReasoningEffort = "extreme" },
			[]string{"llm.reasoning_effort", "low", "medium", "high", "max"}, true},
	}
	for _, tc := range cases {
		c := Default()
		tc.mutate(c)
		err := c.Validate()
		if !tc.wantError {
			if err != nil {
				t.Errorf("mutate 后不应报错: %v", err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("期望校验报错，实际通过")
		}
		for _, sub := range tc.wantSubs {
			if !strings.Contains(err.Error(), sub) {
				t.Errorf("报错应包含 %q: %v", sub, err)
			}
		}
	}
}

// max_output_tokens 范围 [256, 131072]；软/硬轮数范围 [1, 64] 且
// hard_tool_rounds >= max_tool_rounds（报错含两个键名与关系）。
func TestLLMRangeValidation(t *testing.T) {
	intCases := []struct {
		field    string
		value    int
		wantPass bool
	}{
		{"llm.max_output_tokens", 255, false},
		{"llm.max_output_tokens", 256, true},
		{"llm.max_output_tokens", 131072, true},
		{"llm.max_output_tokens", 131073, false},
		{"llm.max_tool_rounds", 0, false},
		{"llm.max_tool_rounds", 1, true},
		{"llm.max_tool_rounds", 64, true},
		{"llm.max_tool_rounds", 65, false},
		{"llm.hard_tool_rounds", 0, false},
		{"llm.hard_tool_rounds", 64, true},
		{"llm.hard_tool_rounds", 65, false},
	}
	for _, tc := range intCases {
		c := Default()
		switch tc.field {
		case "llm.max_output_tokens":
			c.LLM.MaxOutputTokens = tc.value
		case "llm.max_tool_rounds":
			c.LLM.MaxToolRounds = tc.value
			if tc.value > c.LLM.HardToolRounds {
				c.LLM.HardToolRounds = tc.value // 抬高硬限，单测软限自身范围
			}
		case "llm.hard_tool_rounds":
			c.LLM.HardToolRounds = tc.value // 范围检查先于关系检查，直接单测硬限边界
		}
		err := c.Validate()
		if tc.wantPass && err != nil {
			t.Errorf("%s=%d 应通过: %v", tc.field, tc.value, err)
		}
		if !tc.wantPass && (err == nil || !strings.Contains(err.Error(), tc.field)) {
			t.Errorf("%s=%d 应报错且含字段名, got %v", tc.field, tc.value, err)
		}
	}

	// 软 >= 硬：必须报错，且报错含两个键名与关系说明。
	c := Default()
	c.LLM.MaxToolRounds = 24
	c.LLM.HardToolRounds = 8
	err := c.Validate()
	if err == nil {
		t.Fatal("hard < soft 应报错")
	}
	for _, sub := range []string{"llm.hard_tool_rounds", "llm.max_tool_rounds", ">="} {
		if !strings.Contains(err.Error(), sub) {
			t.Errorf("报错应包含 %q: %v", sub, err)
		}
	}
	// hard == soft 是合法配置（两档合一）。
	c.LLM.HardToolRounds = 24
	if err := c.Validate(); err != nil {
		t.Errorf("hard == soft 应通过: %v", err)
	}
}

// YAML 键 thinking / reasoning_effort / hard_tool_rounds 可解码且未知键仍被拒绝。
func TestLoadNewLLMKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
app:
  timezone: Asia/Shanghai
  state_dir: /tmp/e3
cowrie:
  log_path: /var/log/cowrie/cowrie.json
database:
  path: /tmp/e3/events.db
llm:
  thinking: "on"
  reasoning_effort: "low"
  max_tool_rounds: 10
  hard_tool_rounds: 20
  max_output_tokens: 65536
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("写临时配置: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.LLM.Thinking != "on" || c.LLM.ReasoningEffort != "low" {
		t.Errorf("thinking/effort = %q/%q, want on/low", c.LLM.Thinking, c.LLM.ReasoningEffort)
	}
	if c.LLM.MaxToolRounds != 10 || c.LLM.HardToolRounds != 20 {
		t.Errorf("rounds = %d/%d, want 10/20", c.LLM.MaxToolRounds, c.LLM.HardToolRounds)
	}
	if c.LLM.MaxOutputTokens != 65536 {
		t.Errorf("max_output_tokens = %d, want 65536", c.LLM.MaxOutputTokens)
	}

	bad := filepath.Join(dir, "bad.yaml")
	badYaml := strings.Replace(yaml, "thinking: \"on\"", "thinking: maybe", 1)
	if err := os.WriteFile(bad, []byte(badYaml), 0o600); err != nil {
		t.Fatalf("写临时配置: %v", err)
	}
	if _, err := Load(bad); err == nil || !strings.Contains(err.Error(), "llm.thinking") {
		t.Errorf("非法 thinking 应在 Load 时报错且含字段名, got %v", err)
	}
}

// Redacted 打印 llm/ntfy base_url 前剥离 URL userinfo，防凭据进 journald。
func TestRedactedStripsUserinfo(t *testing.T) {
	c := Default()
	c.LLM.BaseURL = "https://user:secret@api.deepseek.com"
	c.Ntfy.BaseURL = "http://alice:hunter2@localhost"
	out := c.Redacted()

	for _, sub := range []string{"https://api.deepseek.com", "http://localhost"} {
		if !strings.Contains(out, sub) {
			t.Errorf("Redacted 应包含剥 userinfo 后的 URL %q: %s", sub, out)
		}
	}
	for _, leak := range []string{"user:secret", "alice:hunter2", ":secret@", "hunter2"} {
		if strings.Contains(out, leak) {
			t.Errorf("Redacted 泄露 URL userinfo %q: %s", leak, out)
		}
	}
}

// redactURL：无 userinfo / 非法输入原样返回。
func TestRedactURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://api.deepseek.com", "https://api.deepseek.com"},
		{"https://user:pass@host.example/path?q=1", "https://host.example/path?q=1"},
		{"http://token@localhost", "http://localhost"},
	}
	for _, tc := range cases {
		if got := redactURL(tc.in); got != tc.want {
			t.Errorf("redactURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
