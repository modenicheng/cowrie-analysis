package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/modenc/e3-security-analyst/internal/config"
	"github.com/modenc/e3-security-analyst/internal/llm"
	"github.com/modenc/e3-security-analyst/internal/sandbox"
	"github.com/modenc/e3-security-analyst/internal/store"
	"github.com/modenc/e3-security-analyst/migrations"
)

// runnerBin 是整个测试周期共用的一次性 script-runner 二进制。
var runnerBin string

// TestMain 构建真实 cmd/script-runner 子进程二进制，供 execute_js 端到端
// 测试使用（与 internal/sandbox 测试相同的方式）。
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "e3-tools-test")
	if err != nil {
		fmt.Fprintf(os.Stderr, "MkdirTemp: %v\n", err)
		os.Exit(1)
	}
	bin := filepath.Join(dir, "script-runner")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Abs: %v\n", err)
		os.Exit(1)
	}
	build := exec.Command("go", "build", "-o", bin, "./cmd/script-runner")
	build.Dir = root
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building script-runner failed: %v\n%s\n", err, out)
		os.Exit(1)
	}
	runnerBin = bin

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// testCfg 返回确定性的测试配置（字段裁剪默认全开、密码默认不外发）。
func testCfg() *config.Config {
	cfg := config.Default()
	cfg.Reports.MaxQuerySpanDays = 31
	cfg.Reports.IncludeSourceIPs = true
	cfg.Reports.IncludePaths = true
	cfg.Reports.IncludeCommands = true
	cfg.LLM.IncludePasswords = false
	cfg.ScriptRunner.Enabled = true
	cfg.ScriptRunner.RunnerPath = runnerBin
	cfg.ScriptRunner.TimeoutMS = 2000
	cfg.ScriptRunner.MaxInputBytes = 1 << 20
	cfg.ScriptRunner.MaxOutputBytes = 1 << 20
	cfg.ScriptRunner.MaxConcurrency = 1
	return cfg
}

// newRunner 构建指向 TestMain 二进制的真实 Runner；timeoutMS 可与
// cfg.ScriptRunner.TimeoutMS 不同（用于验证 handler 侧钳制）。
func newRunner(timeoutMS int) *sandbox.Runner {
	return sandbox.NewRunner(runnerBin, sandbox.Limits{
		TimeoutMS:      timeoutMS,
		MaxInputBytes:  1 << 20,
		MaxOutputBytes: 1 << 20,
	}, 1)
}

// openDB 在临时目录打开并迁移全新数据库。
func openDB(t *testing.T) *store.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "tools.db")
	db, err := store.Open(path, store.Options{WAL: true, BusyTimeoutMs: 2000})
	if err != nil {
		t.Fatalf("store.Open 失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(migrations.FS); err != nil {
		t.Fatalf("Migrate 失败: %v", err)
	}
	return db
}

// testWin 返回固定的一天窗口（daily 任务）。
func testWin() TaskWindow {
	since := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	return TaskWindow{Since: since, Until: since.Add(24 * time.Hour), Type: "daily", RunID: "run-test"}
}

// rawSeq 保证每个种子事件 raw 唯一（InsertEvents 按 raw 哈希去重）。
var rawSeq int64

// mkEvent 构造带完整 raw JSON 的种子事件；extra 同时写入 raw 与对应列。
func mkEvent(eventID string, at time.Time, extra map[string]any) *store.Event {
	rawSeq++
	m := map[string]any{
		"eventid":   eventID,
		"timestamp": at.UTC().Format(time.RFC3339Nano),
		"src_ip":    "203.0.113.7",
		"src_port":  40001,
		"session":   fmt.Sprintf("sess-%d", rawSeq),
		"username":  "root",
		"message":   "test message",
		"seq":       rawSeq,
	}
	for k, v := range extra {
		m[k] = v
	}
	raw, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	e := &store.Event{
		EventID:   eventID,
		EventTime: at,
		SrcIP:     "203.0.113.7",
		SrcPort:   40001,
		Session:   fmt.Sprintf("sess-%d", rawSeq),
		Username:  "root",
		Raw:       string(raw),
	}
	if v, ok := extra["src_ip"].(string); ok {
		e.SrcIP = v
	}
	if v, ok := extra["session"].(string); ok {
		e.Session = v
	}
	if v, ok := extra["username"].(string); ok {
		e.Username = v
	}
	if v, ok := extra["input"].(string); ok {
		e.Command = v
	}
	if v, ok := extra["filename"].(string); ok {
		e.Filename = v
	}
	if v, ok := extra["shasum"].(string); ok {
		e.Shasum = v
	}
	return e
}

func mustInsert(t *testing.T, db *store.DB, evs ...*store.Event) {
	t.Helper()
	if _, _, err := db.InsertEvents(context.Background(), evs); err != nil {
		t.Fatalf("InsertEvents 失败: %v", err)
	}
}

// mustHandle 调用 Handle 并要求成功，返回结果 JSON。
func mustHandle(t *testing.T, d *Dispatcher, name, args string, win TaskWindow) string {
	t.Helper()
	out, err := d.Handle(context.Background(), llm.ToolCall{ID: "t1", Name: name, ArgsJSON: args}, win)
	if err != nil {
		t.Fatalf("Handle(%s) 意外失败: %v", name, err)
	}
	return out
}

// wantErr 调用 Handle 并要求失败，返回错误消息。
func wantErr(t *testing.T, d *Dispatcher, name, args string, win TaskWindow) string {
	t.Helper()
	_, err := d.Handle(context.Background(), llm.ToolCall{ID: "t1", Name: name, ArgsJSON: args}, win)
	if err == nil {
		t.Fatalf("Handle(%s) 应返回错误，实际成功", name)
	}
	return err.Error()
}

// TestSpecsValid：四个 schema 均为合法 JSON、name 齐全且不重复。
func TestSpecsValid(t *testing.T) {
	d := NewDispatcher(testCfg(), nil, nil, nil, nil)
	specs := d.Specs()
	if len(specs) != 4 {
		t.Fatalf("Specs 返回 %d 个工具，期望 4", len(specs))
	}
	seen := map[string]bool{}
	for _, s := range specs {
		if !map[string]bool{"query_events": true, "query_stats": true, "execute_js": true, "submit_report": true}[s.Name] {
			t.Errorf("意外工具 %q", s.Name)
			continue
		}
		if seen[s.Name] {
			t.Errorf("工具 %q 重复", s.Name)
		}
		seen[s.Name] = true
		if s.Description == "" {
			t.Errorf("工具 %q 缺少描述", s.Name)
		}
		if !json.Valid(s.ParametersJSON) {
			t.Errorf("工具 %q 的 ParametersJSON 不是合法 JSON: %s", s.Name, s.ParametersJSON)
			continue
		}
		var schema map[string]any
		if err := json.Unmarshal(s.ParametersJSON, &schema); err != nil {
			t.Errorf("工具 %q schema 解码失败: %v", s.Name, err)
			continue
		}
		if schema["type"] != "object" {
			t.Errorf("工具 %q schema 顶层 type=%v，期望 object", s.Name, schema["type"])
		}
	}
	for _, name := range []string{"query_events", "query_stats", "execute_js", "submit_report"} {
		if !seen[name] {
			t.Errorf("缺少工具 %q", name)
		}
	}
}

// TestUnknownTool：未知工具名返回 "unknown tool" 错误。
func TestUnknownTool(t *testing.T) {
	d := NewDispatcher(testCfg(), nil, nil, nil, nil)
	got := wantErr(t, d, "read_file", `{}`, testWin())
	if !strings.Contains(got, "unknown tool") {
		t.Fatalf("错误消息应含 unknown tool，实际 %q", got)
	}
}
