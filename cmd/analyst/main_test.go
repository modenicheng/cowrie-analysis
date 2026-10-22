package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// analystBin 是 TestMain 构建的一次性 e3-analyst 二进制（verify 冒烟测试用）。
var analystBin string

// TestMain 构建本包二进制，供子进程冒烟测试（与 internal/tools 相同方式）。
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "e3-analyst-test")
	if err != nil {
		fmt.Fprintf(os.Stderr, "MkdirTemp: %v\n", err)
		os.Exit(1)
	}
	bin := filepath.Join(dir, "e3-analyst")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Abs: %v\n", err)
		os.Exit(1)
	}
	build := exec.Command("go", "build", "-o", bin, "./cmd/analyst")
	build.Dir = root
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building e3-analyst failed: %v\n%s\n", err, out)
		os.Exit(1)
	}
	analystBin = bin

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// TestVerifySmokeMissingEnv：临时配置 + 缺失 NTFY_TOKEN / 日志文件 →
// 退出码 1，输出含 ✗，且绝不包含已设置环境变量的值。
func TestVerifySmokeMissingEnv(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgYAML := fmt.Sprintf(`app:
  timezone: UTC
  state_dir: %s
  log_level: info
cowrie:
  log_path: %s
database:
  path: %s
llm:
  base_url: https://api.deepseek.com
  model: deepseek-chat
  api_key_env: DEEPSEEK_API_KEY
ntfy:
  base_url: https://notify.example.com
  topic: e3verify
  token_env: NTFY_TOKEN
script_runner:
  enabled: false
`,
		filepath.ToSlash(dir),
		filepath.ToSlash(filepath.Join(dir, "cowrie", "cowrie.json")),
		filepath.ToSlash(filepath.Join(dir, "db", "events.db")))
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("写入配置失败: %v", err)
	}

	const secret = "sk-verify-secret-do-not-print-9f8e7d6c"
	cmd := exec.Command(analystBin, "verify", "--config", cfgPath)
	// 过滤可能干扰的环境变量，再注入带密值的 DEEPSEEK_API_KEY：
	// 验证输出只允许出现变量名，绝不允许出现其值。
	env := []string{}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "NTFY_TOKEN=") || strings.HasPrefix(kv, "DEEPSEEK_API_KEY=") ||
			strings.HasPrefix(kv, "E3_ANALYST_CONFIG=") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "DEEPSEEK_API_KEY="+secret)
	cmd.Env = env

	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("verify 应以退出码 1 失败，实际成功。输出:\n%s", output)
	}
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
		t.Fatalf("verify 退出码异常: %v（输出:\n%s）", err, output)
	}
	if !strings.Contains(output, "✗") {
		t.Errorf("输出应包含 ✗ 项:\n%s", output)
	}
	if !strings.Contains(output, "NTFY_TOKEN") {
		t.Errorf("输出应指出 NTFY_TOKEN 未设置:\n%s", output)
	}
	if strings.Contains(output, secret) {
		t.Errorf("输出泄露了环境变量值:\n%s", output)
	}
	// cowrie.log_path 不存在必须被点名。
	if !strings.Contains(output, "cowrie.log_path") && !strings.Contains(output, "cowrie.json") {
		t.Errorf("输出应指出日志路径不可读:\n%s", output)
	}
}
