package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/modenc/e3-security-analyst/internal/config"
	"github.com/modenc/e3-security-analyst/internal/store"

	"github.com/modenc/e3-security-analyst/migrations"
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

// TestRetentionSweep：daemon 保留清理 sweep 的最小端到端验证——
// retention_days=0 时不动任何数据；>0 时按服务侧入库时间老删新留。
// （24h ticker 的循环接线本身不可单测，靠该函数覆盖清理路径。）
func TestRetentionSweep(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "events.db"),
		store.Options{WAL: true, BusyTimeoutMs: 2000})
	if err != nil {
		t.Fatalf("store.Open 失败: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Migrate(migrations.FS); err != nil {
		t.Fatalf("Migrate 失败: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.Add(-100 * 24 * time.Hour)
	mk := func(raw string, at time.Time) *store.Event {
		ev := &store.Event{
			EventID: "cowrie.login.failed", EventTime: at,
			CollectedAt: at, Session: "s1", SrcIP: "198.51.100.9", Raw: raw,
		}
		return ev
	}
	if _, _, err := db.InsertEvents(ctx, []*store.Event{
		mk(`{"old":1}`, old), mk(`{"new":1}`, now),
	}); err != nil {
		t.Fatalf("InsertEvents 失败: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Default()
	env := &analystEnv{cfg: cfg, db: db}

	// 0 = 禁用：两行都在。
	cfg.App.RetentionDays = 0
	env.retentionSweep(ctx, log)
	if n, err := db.CountEvents(ctx, store.EventFilter{}); err != nil || n != 2 {
		t.Fatalf("禁用清理后 events = %d (err %v), 期望 2", n, err)
	}

	// 90 天：入库 100 天的老事件删除，新事件保留。
	cfg.App.RetentionDays = 90
	env.retentionSweep(ctx, log)
	filter := store.EventFilter{Since: now.Add(-time.Minute), Until: now.Add(time.Minute)}
	if n, err := db.CountEvents(ctx, filter); err != nil || n != 1 {
		t.Fatalf("清理后新事件应剩 1, got %d (err %v)", n, err)
	}
	oldFilter := store.EventFilter{Since: old.Add(-time.Minute), Until: old.Add(time.Minute)}
	if n, err := db.CountEvents(ctx, oldFilter); err != nil || n != 0 {
		t.Fatalf("老事件应已删除, got %d (err %v)", n, err)
	}
}
