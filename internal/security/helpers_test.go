// Package security 承载 SPEC §17 阶段 G 的安全验收测试：
// 提示词注入（S1）、凭据隔离（S2）与资源耗尽（S3）。
// 全部使用 mock HTTP server 与临时目录，绝不真实外呼。
//
// 本文件提供共享测试基建：script-runner 子进程二进制、OpenAI 兼容
// LLM mock、ntfy mock 与测试环境装配。
package security

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modenc/e3-security-analyst/internal/config"
	"github.com/modenc/e3-security-analyst/internal/llm"
	"github.com/modenc/e3-security-analyst/internal/ntfy"
	"github.com/modenc/e3-security-analyst/internal/reports"
	"github.com/modenc/e3-security-analyst/internal/store"
	"github.com/modenc/e3-security-analyst/migrations"
)

// runnerBin 是整个测试周期共用的一次性 script-runner 二进制。
var runnerBin string

// TestMain 构建真实 cmd/script-runner 子进程二进制（与 internal/sandbox
// 测试相同方式），供 S2/S3 验证进程级隔离与资源限制。
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "e3-security-test")
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

// —— LLM mock（OpenAI 兼容 wire 协议的最小实现，含凭据断言所需记录）——

type wireFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type wireToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function wireFunction `json:"function"`
}

type wireMessage struct {
	Role      string         `json:"role"`
	Content   string         `json:"content"`
	ToolCalls []wireToolCall `json:"tool_calls,omitempty"`
}

type wireResponse struct {
	Choices []struct {
		Message      wireMessage `json:"message"`
		FinishReason string      `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// mockStep 是一轮 scripted 响应：toolName 非空 → tool_calls 轮；
// content 非空 → 最终输出。
type mockStep struct {
	toolName string
	toolArgs string
	content  string
}

func stepTool(name, args string) mockStep { return mockStep{toolName: name, toolArgs: args} }
func stepFinal(content string) mockStep   { return mockStep{content: content} }

type llmMock struct {
	mu     sync.Mutex
	steps  []mockStep
	step   int
	bodies []string // 按序记录每个请求体（含 tool 结果消息）
	auths  []string // 按序记录 Authorization 头
	srv    *httptest.Server
}

func newLLMMock(t *testing.T) *llmMock {
	t.Helper()
	m := &llmMock{}
	m.srv = httptest.NewServer(m)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *llmMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bodies = append(m.bodies, string(body))
	m.auths = append(m.auths, r.Header.Get("Authorization"))
	if m.step >= len(m.steps) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	st := m.steps[m.step]
	m.step++

	var resp wireResponse
	resp.Usage = struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	}{PromptTokens: 100, CompletionTokens: 50}
	if st.toolName != "" {
		msg := wireMessage{Role: "assistant", ToolCalls: []wireToolCall{{
			ID:       fmt.Sprintf("call-%d", m.step),
			Type:     "function",
			Function: wireFunction{Name: st.toolName, Arguments: st.toolArgs},
		}}}
		resp.Choices = append(resp.Choices, struct {
			Message      wireMessage `json:"message"`
			FinishReason string      `json:"finish_reason"`
		}{Message: msg, FinishReason: "tool_calls"})
	} else {
		resp.Choices = append(resp.Choices, struct {
			Message      wireMessage `json:"message"`
			FinishReason string      `json:"finish_reason"`
		}{Message: wireMessage{Role: "assistant", Content: st.content}, FinishReason: "stop"})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (m *llmMock) requests() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.bodies...)
}

func (m *llmMock) authorizations() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.auths...)
}

// —— ntfy mock ——

type ntfyReq struct {
	Path, Title, Body, Priority, Tags, Auth string
}

type ntfyMock struct {
	mu     sync.Mutex
	got    []ntfyReq
	status int
	srv    *httptest.Server
}

func newNtfyMock(t *testing.T) *ntfyMock {
	t.Helper()
	m := &ntfyMock{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.got = append(m.got, ntfyReq{
			Path:     r.URL.Path,
			Title:    r.Header.Get("Title"),
			Body:     string(body),
			Priority: r.Header.Get("Priority"),
			Tags:     r.Header.Get("Tags"),
			Auth:     r.Header.Get("Authorization"),
		})
		status := m.status
		m.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"mock-msg-1"}`))
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *ntfyMock) requests() []ntfyReq {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]ntfyReq(nil), m.got...)
}

func (m *ntfyMock) setStatus(code int) {
	m.mu.Lock()
	m.status = code
	m.mu.Unlock()
}

// —— 通用工具 ——

// openTestDB 打开并迁移一个临时 SQLite store。
func openTestDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "events.db"),
		store.Options{WAL: true, BusyTimeoutMs: 2000})
	if err != nil {
		t.Fatalf("store.Open 失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(migrations.FS); err != nil {
		t.Fatalf("Migrate 失败: %v", err)
	}
	return db
}

// genEnv 是 S1 使用的报告生成环境（真实 store + mock LLM + mock ntfy）。
type genEnv struct {
	cfg  *config.Config
	db   *store.DB
	gen  *reports.Generator
	llm  *llmMock
	ntfy *ntfyMock
}

// newGenEnv 装配报告生成环境：mock LLM（工具模式）、mock ntfy、
// script_runner 禁用（S1 的脚本不需要 execute_js）。
func newGenEnv(t *testing.T) *genEnv {
	t.Helper()
	te := &genEnv{llm: newLLMMock(t), ntfy: newNtfyMock(t)}
	dir := t.TempDir()
	cfg := config.Default()
	cfg.App.Timezone = "Asia/Shanghai"
	cfg.App.StateDir = dir
	cfg.Database.Path = filepath.Join(dir, "events.db")
	cfg.Reports.Dir = filepath.Join(dir, "reports")
	cfg.LLM.BaseURL = te.llm.srv.URL
	cfg.LLM.Model = "mock-model"
	cfg.LLM.APIKeyEnv = "DEEPSEEK_API_KEY"
	cfg.LLM.EnableTools = true
	cfg.LLM.TimeoutSeconds = 30
	cfg.LLM.MaxToolRounds = 6
	cfg.Ntfy.BaseURL = te.ntfy.srv.URL
	cfg.Ntfy.Topic = "e3reports"
	cfg.Ntfy.MaxRetries = 2
	cfg.Ntfy.MaxMessageBytes = 4000
	cfg.ScriptRunner.Enabled = false
	te.cfg = cfg

	te.db = openTestDB(t)
	client := llm.NewClient(llm.ClientConfig{
		BaseURL:       cfg.LLM.BaseURL,
		Model:         cfg.LLM.Model,
		APIKey:        "test-key",
		Timeout:       30 * time.Second,
		MaxToolRounds: cfg.LLM.MaxToolRounds,
		EnableTools:   true,
	})
	pub := ntfy.NewPublisher(
		ntfy.NewClient(ntfy.ClientConfig{BaseURL: cfg.Ntfy.BaseURL, Timeout: 5 * time.Second}),
		te.db, cfg.Ntfy.MaxRetries, cfg.Ntfy.MaxMessageBytes,
		slog.New(slog.DiscardHandler))
	gen, err := reports.NewGenerator(cfg, te.db, client, nil, pub, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewGenerator 失败: %v", err)
	}
	te.gen = gen
	return te
}

// rawColumn 查询单列字符串集合（testConn 辅助）。
func rawColumn(t *testing.T, db *store.DB, q string, args ...any) []string {
	t.Helper()
	rows, err := db.SQL().QueryContext(context.Background(), q, args...)
	if err != nil {
		t.Fatalf("查询失败 %q: %v", q, err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("扫描失败 %q: %v", q, err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍历失败 %q: %v", q, err)
	}
	return out
}

// containsAll 报告 s 是否包含所有子串（失败时列出缺失项）。
func containsAll(s string, subs ...string) ([]string, bool) {
	var missing []string
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			missing = append(missing, sub)
		}
	}
	return missing, len(missing) == 0
}
