package reports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/modenc/e3-security-analyst/internal/cowrie"
	"github.com/modenc/e3-security-analyst/internal/llm"
	"github.com/modenc/e3-security-analyst/internal/ntfy"
	"github.com/modenc/e3-security-analyst/internal/sandbox"
	"github.com/modenc/e3-security-analyst/internal/scheduler"
	"github.com/modenc/e3-security-analyst/internal/store"
	"github.com/modenc/e3-security-analyst/migrations"
)

// runnerBin 是整个测试周期共用的一次性 script-runner 二进制（备用：
// Generator 装配真实 Runner，模拟模型调用 execute_js 的路径可随时启用）。
var runnerBin string

// TestMain 构建真实 cmd/script-runner 子进程二进制（与 internal/tools
// 测试相同的方式）。
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "e3-reports-test")
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

// —— LLM mock（OpenAI 兼容 wire 协议的最小实现）——

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
// content 非空 → 最终输出；status 非 0 → 返回该 HTTP 状态（可带
// Retry-After 秒数，用于加速 llm 客户端的退避重试）。
type mockStep struct {
	toolName   string
	toolArgs   string
	content    string
	status     int
	retryAfter string
}

func stepTool(name, args string) mockStep { return mockStep{toolName: name, toolArgs: args} }
func stepFinal(content string) mockStep   { return mockStep{content: content} }
func stepHTTPStatus(code int, retryAfter string) mockStep {
	return mockStep{status: code, retryAfter: retryAfter}
}

type llmMock struct {
	mu     sync.Mutex
	steps  []mockStep
	step   int
	bodies []string // 按序记录每个请求体（含 tool 结果消息）
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
	if m.step >= len(m.steps) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	st := m.steps[m.step]
	m.step++

	if st.status != 0 {
		if st.retryAfter != "" {
			w.Header().Set("Retry-After", st.retryAfter)
		}
		w.WriteHeader(st.status)
		return
	}
	var resp wireResponse
	usage := struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	}{PromptTokens: 100, CompletionTokens: 50}
	resp.Usage = usage
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

// —— 测试环境装配 ——

type testEnv struct {
	cfg  *config.Config
	db   *store.DB
	gen  *Generator
	llm  *llmMock
	ntfy *ntfyMock
	loc  *time.Location
}

func newTestEnv(t *testing.T, mutate func(*config.Config)) *testEnv {
	t.Helper()
	te := &testEnv{llm: newLLMMock(t), ntfy: newNtfyMock(t)}
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatalf("加载时区失败: %v", err)
	}
	te.loc = loc

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
	cfg.ScriptRunner.Enabled = true
	cfg.ScriptRunner.RunnerPath = runnerBin
	if mutate != nil {
		mutate(cfg)
	}
	te.cfg = cfg

	te.db = openTestDB(t)
	client := llm.NewClient(llm.ClientConfig{
		BaseURL:         cfg.LLM.BaseURL,
		Model:           cfg.LLM.Model,
		APIKey:          "test-key",
		Timeout:         30 * time.Second,
		MaxToolRounds:   cfg.LLM.MaxToolRounds,
		MaxOutputTokens: cfg.LLM.MaxOutputTokens,
		MaxTotalTokens:  cfg.LLM.MaxTotalTokens,
		EnableTools:     cfg.LLM.EnableTools,
	})
	var runner *sandbox.Runner
	if cfg.ScriptRunner.Enabled {
		runner = sandbox.NewRunner(cfg.ScriptRunner.RunnerPath, sandbox.Limits{
			TimeoutMS:      cfg.ScriptRunner.TimeoutMS,
			MaxInputBytes:  cfg.ScriptRunner.MaxInputBytes,
			MaxOutputBytes: cfg.ScriptRunner.MaxOutputBytes,
		}, cfg.ScriptRunner.MaxConcurrency)
	}
	pub := ntfy.NewPublisher(
		ntfy.NewClient(ntfy.ClientConfig{BaseURL: cfg.Ntfy.BaseURL, Timeout: 5 * time.Second}),
		te.db, cfg.Ntfy.MaxRetries, cfg.Ntfy.MaxMessageBytes, slog.New(slog.DiscardHandler))
	gen, err := NewGenerator(cfg, te.db, client, runner, pub, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewGenerator 失败: %v", err)
	}
	te.gen = gen
	return te
}

func openTestDB(t *testing.T) *store.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "reports.db")
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

// —— 种子数据 ——

var rawSeq int64

// seedEvent 构造带完整 raw JSON 的种子事件（raw 全局唯一保证幂等插入）。
func seedEvent(t *testing.T, db *store.DB, eventID string, at time.Time, fields map[string]any) {
	t.Helper()
	rawSeq++
	m := map[string]any{
		"eventid":   eventID,
		"timestamp": at.UTC().Format(time.RFC3339Nano),
		"src_ip":    "203.0.113.1",
		"src_port":  40000 + int(rawSeq%1000),
		"session":   fmt.Sprintf("sess-%d", rawSeq),
		"username":  "root",
		"message":   "test message",
		"seq":       rawSeq,
	}
	for k, v := range fields {
		m[k] = v
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("构造 raw 失败: %v", err)
	}
	e := &store.Event{
		EventID:     eventID,
		EventTime:   at,
		CollectedAt: at,
		SrcIP:       "203.0.113.1",
		SrcPort:     int64(40000 + rawSeq%1000),
		Session:     fmt.Sprintf("sess-%d", rawSeq),
		Username:    "root",
		Raw:         string(raw),
	}
	if v, ok := fields["src_ip"].(string); ok {
		e.SrcIP = v
	}
	if v, ok := fields["session"].(string); ok {
		e.Session = v
	}
	if v, ok := fields["username"].(string); ok {
		e.Username = v
	}
	if v, ok := fields["input"].(string); ok {
		e.Command = v
	}
	if v, ok := fields["filename"].(string); ok {
		e.Filename = v
	}
	if v, ok := fields["shasum"].(string); ok {
		e.Shasum = v
	}
	if _, _, err := db.InsertEvents(context.Background(), []*store.Event{e}); err != nil {
		t.Fatalf("InsertEvents 失败: %v", err)
	}
}

// seedWindow 在 daily 窗口内种入 3 IP / 4 会话：
// 连接 4、独立 IP 3、登录成功 1、登录失败 5，含 command 与 file_upload。
// 返回 (since, keyStats)。
func seedDailyWindow(t *testing.T, db *store.DB, loc *time.Location) (time.Time, [4]int) {
	t.Helper()
	since, until, err := scheduler.WindowFor(scheduler.KindDaily, time.Now(), loc)
	if err != nil {
		t.Fatalf("WindowFor 失败: %v", err)
	}
	if !since.Before(time.Now()) || !until.After(since) {
		// 保持与 Generate 相同的窗口口径（理论恒真，防御性断言）。
		t.Fatalf("daily 窗口计算异常: %v ~ %v", since, until)
	}
	at := func(offset time.Duration) time.Time { return since.Add(offset) }

	// IP1 / sess-a：connect + login.failed + login.success + 2×command + file_upload
	seedEvent(t, db, cowrie.EventConnect, at(1*time.Hour), map[string]any{"src_ip": "203.0.113.1", "session": "sess-a"})
	seedEvent(t, db, cowrie.EventLoginFailed, at(1*time.Minute), map[string]any{"src_ip": "203.0.113.1", "session": "sess-a", "username": "root"})
	seedEvent(t, db, cowrie.EventLoginSuccess, at(2*time.Minute), map[string]any{"src_ip": "203.0.113.1", "session": "sess-a", "username": "root"})
	seedEvent(t, db, cowrie.EventCommandInput, at(3*time.Minute), map[string]any{"src_ip": "203.0.113.1", "session": "sess-a", "input": "uname -a"})
	seedEvent(t, db, cowrie.EventCommandInput, at(4*time.Minute), map[string]any{"src_ip": "203.0.113.1", "session": "sess-a", "input": "cat /etc/passwd"})
	seedEvent(t, db, cowrie.EventFileUpload, at(5*time.Minute), map[string]any{
		"src_ip": "203.0.113.1", "session": "sess-a", "filename": "mal.sh", "shasum": "deadbeef01",
	})
	// IP1 / sess-b：connect + login.failed
	seedEvent(t, db, cowrie.EventConnect, at(2*time.Hour), map[string]any{"src_ip": "203.0.113.1", "session": "sess-b"})
	seedEvent(t, db, cowrie.EventLoginFailed, at(1*time.Minute), map[string]any{"src_ip": "203.0.113.1", "session": "sess-b"})
	// IP2 / sess-c：connect + login.failed ×2
	seedEvent(t, db, cowrie.EventConnect, at(3*time.Hour), map[string]any{"src_ip": "203.0.113.2", "session": "sess-c"})
	seedEvent(t, db, cowrie.EventLoginFailed, at(1*time.Minute), map[string]any{"src_ip": "203.0.113.2", "session": "sess-c"})
	seedEvent(t, db, cowrie.EventLoginFailed, at(2*time.Minute), map[string]any{"src_ip": "203.0.113.2", "session": "sess-c"})
	// IP3 / sess-d：connect + login.failed + command
	seedEvent(t, db, cowrie.EventConnect, at(4*time.Hour), map[string]any{"src_ip": "203.0.113.3", "session": "sess-d"})
	seedEvent(t, db, cowrie.EventLoginFailed, at(1*time.Minute), map[string]any{"src_ip": "203.0.113.3", "session": "sess-d"})
	seedEvent(t, db, cowrie.EventCommandInput, at(2*time.Minute), map[string]any{"src_ip": "203.0.113.3", "session": "sess-d", "input": "id"})

	return since, [4]int{4, 3, 1, 5}
}

// draftFor 构造与 keyStats 对齐的合法草稿 JSON（submit_report 参数 /
// 无工具模式的最终输出共用）。
func draftFor(kind string, keyStats [4]int) string {
	d := map[string]any{
		"type":    kind,
		"title":   "E3 安全日报｜测试窗口",
		"summary": "测试摘要：窗口内攻击面概览，蜜罐内出现一次模拟登录成功，命令探测与文件上传行为已覆盖。",
		"findings": []map[string]any{{
			"title":    "蜜罐内出现模拟登录成功",
			"detail":   "来源 203.0.113.1 使用用户名 root 在蜜罐内模拟登录成功（非真实系统失陷），随后执行系统信息探测命令。",
			"severity": "high",
			"evidence": []string{"stats:login_success", "session:sess-a"},
		}},
		"key_stats": map[string]any{
			"connections":    keyStats[0],
			"unique_src_ips": keyStats[1],
			"login_success":  keyStats[2],
			"login_failed":   keyStats[3],
		},
		"confidence":       0.85,
		"data_limitations": "未发现明显数据缺口",
	}
	b, err := json.Marshal(d)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// successSteps 返回标准成功脚本：query_stats → submit_report（正确值）→ 终稿。
func successSteps(kind string, keyStats [4]int) []mockStep {
	return []mockStep{
		stepTool("query_stats", "{}"),
		stepTool("submit_report", draftFor(kind, keyStats)),
		stepFinal(`{"done":true}`),
	}
}

// archivePayload 是归档 JSON 的断言视图。
type archivePayload struct {
	Kind   string `json:"kind"`
	Window struct {
		Since time.Time `json:"since"`
		Until time.Time `json:"until"`
		TZ    string    `json:"tz"`
	} `json:"window"`
	GeneratedAt time.Time `json:"generated_at"`
	ModelName   string    `json:"model_name"`
	DataQuality struct {
		Gaps           []store.Gap `json:"gaps"`
		ParseErrors    int         `json:"parse_errors"`
		StalledWarning string      `json:"stalled_warning"`
	} `json:"data_quality"`
	Stats struct {
		Connections  int `json:"connections"`
		UniqueSrcIPs int `json:"unique_src_ips"`
		LoginSuccess int `json:"login_success"`
		LoginFailed  int `json:"login_failed"`
	} `json:"stats"`
	Model map[string]any `json:"model"`
}

func archivePathFor(cfg *config.Config, loc *time.Location, kind string, since time.Time) string {
	s := since.In(loc)
	return filepath.Join(cfg.ReportsDir(), s.Format("2006"), s.Format("01"),
		fmt.Sprintf("%s-%s.json", kind, s.Format("20060102")))
}

func runRow(t *testing.T, db *store.DB, task string) (status string, rounds, toolCalls int, errStr string) {
	t.Helper()
	err := db.SQL().QueryRowContext(context.Background(),
		`SELECT status, rounds, tool_calls, COALESCE(error,'') FROM analysis_runs
		 WHERE task = ? ORDER BY started_at DESC LIMIT 1`, task).
		Scan(&status, &rounds, &toolCalls, &errStr)
	if err != nil {
		t.Fatalf("查询 analysis_runs 失败: %v", err)
	}
	return
}

func notificationRow(t *testing.T, db *store.DB, kind string) (status string, attempts int) {
	t.Helper()
	err := db.SQL().QueryRowContext(context.Background(),
		`SELECT status, attempts FROM notifications WHERE kind = ?`, "report."+kind).
		Scan(&status, &attempts)
	if err != nil {
		t.Fatalf("查询 notifications 失败: %v", err)
	}
	return
}

// —— 1. 成功全流程（daily，工具模式）——

func TestGenerateDailySuccess(t *testing.T) {
	te := newTestEnv(t, nil)
	since, ks := seedDailyWindow(t, te.db, te.loc)
	te.llm.steps = successSteps("daily", ks)

	if err := te.gen.Generate(context.Background(), "daily"); err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}

	// reports 表：published，payload 与 sha 一致。
	rep, err := te.db.GetReport(context.Background(), "daily", since)
	if err != nil || rep == nil {
		t.Fatalf("GetReport 失败: %v %v", rep, err)
	}
	if rep.Status != "published" {
		t.Errorf("reports.status = %q, 期望 published", rep.Status)
	}
	if rep.Attempts != 1 {
		t.Errorf("reports.attempts = %d, 期望 1", rep.Attempts)
	}

	// 归档文件存在；content_sha256 与文件内容一致；payload 与文件一致。
	path := archivePathFor(te.cfg, te.loc, "daily", since)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取归档文件 %s 失败: %v", path, err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != rep.ContentSHA256 {
		t.Errorf("content_sha256 不一致: 报告 %s, 文件 %s", rep.ContentSHA256, got)
	}
	if string(data) != rep.Payload {
		t.Errorf("reports.payload 与归档文件内容不一致")
	}

	var p archivePayload
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("解析归档 payload 失败: %v", err)
	}
	if p.Kind != "daily" || p.Window.TZ != "Asia/Shanghai" || p.ModelName != "mock-model" {
		t.Errorf("payload 元数据异常: %+v", p)
	}
	if p.Stats.Connections != ks[0] || p.Stats.UniqueSrcIPs != ks[1] ||
		p.Stats.LoginSuccess != ks[2] || p.Stats.LoginFailed != ks[3] {
		t.Errorf("payload.stats 与种子不一致: %+v（期望 %v）", p.Stats, ks)
	}
	if s, _ := p.Model["summary"].(string); s == "" || !strings.Contains(s, "测试摘要") {
		t.Errorf("payload.model.summary 与模型草稿不一致: %v", p.Model["summary"])
	}
	if _, ok := p.Model["key_stats"].(map[string]any); !ok {
		t.Errorf("payload.model 缺少 key_stats: %v", p.Model)
	}

	// analysis_runs：ok 且 rounds≥2、tool_calls≥2。
	status, rounds, toolCalls, runErr := runRow(t, te.db, "daily")
	if status != "ok" || runErr != "" {
		t.Errorf("analysis_runs: status=%q error=%q, 期望 ok", status, runErr)
	}
	if rounds < 2 || toolCalls < 2 {
		t.Errorf("analysis_runs: rounds=%d tool_calls=%d, 期望均 ≥2", rounds, toolCalls)
	}

	// ntfy：恰一条，标题/正文含统计数字，topic 正确。
	reqs := te.ntfy.requests()
	if len(reqs) != 1 {
		t.Fatalf("ntfy 收到 %d 条, 期望 1", len(reqs))
	}
	r := reqs[0]
	if r.Path != "/"+te.cfg.Ntfy.Topic {
		t.Errorf("ntfy topic = %q, 期望 /%s", r.Path, te.cfg.Ntfy.Topic)
	}
	wantTitle := fmt.Sprintf("[E3 安全日报] %s", since.In(te.loc).Format("2006-01-02"))
	if r.Title != wantTitle {
		t.Errorf("ntfy title = %q, 期望 %q", r.Title, wantTitle)
	}
	wantStats := fmt.Sprintf("连接 %d|独立IP %d|登录成功 %d|失败 %d", ks[0], ks[1], ks[2], ks[3])
	if !strings.Contains(r.Body, wantStats) {
		t.Errorf("ntfy body 缺少统计行 %q, 实际:\n%s", wantStats, r.Body)
	}
	if !strings.Contains(r.Body, "[high] 蜜罐内出现模拟登录成功") {
		t.Errorf("ntfy body 缺少 finding 标题, 实际:\n%s", r.Body)
	}
	if !strings.Contains(r.Body, "归档: ") {
		t.Errorf("ntfy body 缺少归档路径, 实际:\n%s", r.Body)
	}
	if r.Priority != "3" || r.Tags != "chart_with_upwards_trend" {
		t.Errorf("ntfy priority/tags = %q/%q, 期望 3/chart_with_upwards_trend", r.Priority, r.Tags)
	}
}

// —— 2. key_stats 不符被拒，模型修正后成功 ——

func TestKeyStatsMismatchRejectedThenCorrected(t *testing.T) {
	te := newTestEnv(t, nil)
	_, ks := seedDailyWindow(t, te.db, te.loc)
	wrong := ks
	wrong[0] = 999 // connections 给错
	te.llm.steps = []mockStep{
		stepTool("submit_report", draftFor("daily", wrong)),
		stepTool("submit_report", draftFor("daily", ks)),
		stepFinal(`{"done":true}`),
	}

	if err := te.gen.Generate(context.Background(), "daily"); err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}

	reqs := te.llm.requests()
	if len(reqs) != 3 {
		t.Fatalf("LLM 请求数 = %d, 期望 3", len(reqs))
	}
	// 第二个请求应包含第一轮 submit_report 的工具结果：accepted:false +
	// 附正确值与模型值的拒绝原因。
	second := reqs[1]
	if !strings.Contains(second, `accepted\":false`) {
		t.Errorf("第二轮请求未包含 accepted:false 工具结果:\n%.800s", second)
	}
	if !strings.Contains(second, "key_stats.connections") ||
		!strings.Contains(second, "999") || !strings.Contains(second, "正确值为 4") {
		t.Errorf("拒绝原因缺少正确值/模型值:\n%.1200s", second)
	}

	rep, err := te.db.GetReport(context.Background(), "daily",
		mustWindow(t, te.loc))
	if err != nil || rep == nil {
		t.Fatalf("GetReport 失败: %v", err)
	}
	if rep.Status != "published" {
		t.Errorf("reports.status = %q, 期望 published（修正后成功）", rep.Status)
	}
}

// mustWindow 返回当前 daily 窗口起点（测试内重算，与 Generate 相差毫秒级）。
func mustWindow(t *testing.T, loc *time.Location) time.Time {
	t.Helper()
	since, _, err := scheduler.WindowFor(scheduler.KindDaily, time.Now(), loc)
	if err != nil {
		t.Fatalf("WindowFor 失败: %v", err)
	}
	return since
}

// —— 3. LLM 恒 500：全链路失败，不发任何通知 ——

func TestLLMFailureFailsReport(t *testing.T) {
	te := newTestEnv(t, nil)
	seedDailyWindow(t, te.db, te.loc)
	// Retry-After: 1 使 llm 客户端退避固定 1s，避免默认指数退避拖慢用例。
	te.llm.steps = []mockStep{
		stepHTTPStatus(500, "1"), stepHTTPStatus(500, "1"),
		stepHTTPStatus(500, "1"), stepHTTPStatus(500, "1"),
	}

	err := te.gen.Generate(context.Background(), "daily")
	if err == nil {
		t.Fatalf("Generate 应返回 error")
	}
	if !strings.Contains(err.Error(), "LLM") {
		t.Errorf("错误应说明 LLM 失败: %v", err)
	}

	rep, gerr := te.db.GetReport(context.Background(), "daily", mustWindow(t, te.loc))
	if gerr != nil || rep == nil {
		t.Fatalf("GetReport 失败: %v", gerr)
	}
	if rep.Status != "failed" || rep.Error == "" {
		t.Errorf("reports: status=%q error=%q, 期望 failed 且带原因", rep.Status, rep.Error)
	}

	status, _, _, runErr := runRow(t, te.db, "daily")
	if status != "failed" || runErr == "" {
		t.Errorf("analysis_runs: status=%q error=%q, 期望 failed 且带原因", status, runErr)
	}

	if reqs := te.ntfy.requests(); len(reqs) != 0 {
		t.Errorf("失败路径不应发送报告通知, 实际 %d 条", len(reqs))
	}
}

// —— 4. 无工具模式：单轮最终 JSON 走 content 解析路径 ——

func TestNoToolsModeParsesContent(t *testing.T) {
	te := newTestEnv(t, func(c *config.Config) { c.LLM.EnableTools = false })
	_, ks := seedDailyWindow(t, te.db, te.loc)
	te.llm.steps = []mockStep{stepFinal(draftFor("daily", ks))}

	if err := te.gen.Generate(context.Background(), "daily"); err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}

	rep, err := te.db.GetReport(context.Background(), "daily", mustWindow(t, te.loc))
	if err != nil || rep == nil {
		t.Fatalf("GetReport 失败: %v", err)
	}
	if rep.Status != "published" {
		t.Errorf("reports.status = %q, 期望 published", rep.Status)
	}
	status, rounds, toolCalls, _ := runRow(t, te.db, "daily")
	if status != "ok" || rounds != 1 || toolCalls != 0 {
		t.Errorf("analysis_runs: status=%s rounds=%d tool_calls=%d, 期望 ok/1/0", status, rounds, toolCalls)
	}
	if reqs := te.ntfy.requests(); len(reqs) != 1 {
		t.Errorf("ntfy 收到 %d 条, 期望 1", len(reqs))
	}
}

// —— 5. 数据缺口呈现：payload.data_quality.gaps + 通知正文 ——

func TestDataGapPresented(t *testing.T) {
	te := newTestEnv(t, nil)
	since, ks := seedDailyWindow(t, te.db, te.loc)
	ctx := context.Background()
	if err := te.db.AddGap(ctx, since.Add(2*time.Hour), since.Add(3*time.Hour), "测试缺口：模拟采集停滞"); err != nil {
		t.Fatalf("AddGap 失败: %v", err)
	}
	te.llm.steps = successSteps("daily", ks)

	if err := te.gen.Generate(ctx, "daily"); err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}

	data, err := os.ReadFile(archivePathFor(te.cfg, te.loc, "daily", since))
	if err != nil {
		t.Fatalf("读取归档文件失败: %v", err)
	}
	var p archivePayload
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("解析归档 payload 失败: %v", err)
	}
	if len(p.DataQuality.Gaps) == 0 {
		t.Fatalf("payload.data_quality.gaps 为空, 数据缺口被掩盖")
	}
	if p.DataQuality.Gaps[0].Reason != "测试缺口：模拟采集停滞" {
		t.Errorf("gap reason = %q", p.DataQuality.Gaps[0].Reason)
	}

	reqs := te.ntfy.requests()
	if len(reqs) != 1 {
		t.Fatalf("ntfy 收到 %d 条, 期望 1", len(reqs))
	}
	if !strings.Contains(reqs[0].Body, "数据缺口") {
		t.Errorf("ntfy body 缺少数据缺口提示:\n%s", reqs[0].Body)
	}
}

// —— 6. 窗口正确性：reports.window 与 scheduler.WindowFor 一致 ——

func TestWindowMatchesScheduler(t *testing.T) {
	te := newTestEnv(t, nil)
	te.llm.steps = []mockStep{
		stepTool("submit_report", draftFor("daily", [4]int{0, 0, 0, 0})),
		stepFinal(`{}`),
	}

	if err := te.gen.Generate(context.Background(), "daily"); err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}

	rep, err := te.db.GetReport(context.Background(), "daily", mustWindow(t, te.loc))
	if err != nil || rep == nil {
		t.Fatalf("GetReport 失败: %v", err)
	}
	wantSince, wantUntil, err := scheduler.WindowFor(scheduler.KindDaily, time.Now(), te.loc)
	if err != nil {
		t.Fatalf("WindowFor 失败: %v", err)
	}
	if d := rep.WindowStart.Sub(wantSince); d < -time.Second || d > time.Second {
		t.Errorf("window_start 偏差 %v 超过 1s", d)
	}
	if d := rep.WindowEnd.Sub(wantUntil); d < -time.Second || d > time.Second {
		t.Errorf("window_end 偏差 %v 超过 1s", d)
	}
	if rep.WindowEnd.Sub(rep.WindowStart) != 24*time.Hour {
		t.Errorf("daily 窗口长度 = %v, 期望 24h", rep.WindowEnd.Sub(rep.WindowStart))
	}
}

// —— 7. 通知发送失败不影响报告 ——

func TestPublishFailureKeepsValidated(t *testing.T) {
	te := newTestEnv(t, nil)
	_, ks := seedDailyWindow(t, te.db, te.loc)
	te.ntfy.setStatus(503) // 可重试错误：TrySend 内联 1 次退避后保持 pending
	te.llm.steps = successSteps("daily", ks)

	if err := te.gen.Generate(context.Background(), "daily"); err != nil {
		t.Fatalf("通知发送失败不应导致 Generate 失败: %v", err)
	}

	rep, err := te.db.GetReport(context.Background(), "daily", mustWindow(t, te.loc))
	if err != nil || rep == nil {
		t.Fatalf("GetReport 失败: %v", err)
	}
	if rep.Status != "validated" {
		t.Errorf("reports.status = %q, 期望 validated", rep.Status)
	}
	status, attempts := notificationRow(t, te.db, "daily")
	if status != "pending" {
		t.Errorf("notifications.status = %q, 期望 pending（留待 daemon 重试）", status)
	}
	if attempts < 1 {
		t.Errorf("notifications.attempts = %d, 期望 ≥1", attempts)
	}
	// 归档文件仍然存在。
	if _, err := os.Stat(archivePathFor(te.cfg, te.loc, "daily", mustWindow(t, te.loc))); err != nil {
		t.Errorf("归档文件缺失: %v", err)
	}
}

// —— 附加：weekly 窗口与标题格式 ——

func TestGenerateWeeklySuccess(t *testing.T) {
	te := newTestEnv(t, nil)
	since, _, err := scheduler.WindowFor(scheduler.KindWeekly, time.Now(), te.loc)
	if err != nil {
		t.Fatalf("WindowFor 失败: %v", err)
	}
	seedEvent(t, te.db, cowrie.EventConnect, since.Add(24*time.Hour),
		map[string]any{"src_ip": "198.51.100.9", "session": "sess-w1"})
	te.llm.steps = successSteps("weekly", [4]int{1, 1, 0, 0})

	if err := te.gen.Generate(context.Background(), "weekly"); err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}
	rep, err := te.db.GetReport(context.Background(), "weekly", since)
	if err != nil || rep == nil {
		t.Fatalf("GetReport 失败: %v", err)
	}
	if rep.Status != "published" {
		t.Errorf("reports.status = %q, 期望 published", rep.Status)
	}
	reqs := te.ntfy.requests()
	if len(reqs) != 1 {
		t.Fatalf("ntfy 收到 %d 条, 期望 1", len(reqs))
	}
	wantPrefix := fmt.Sprintf("[E3 安全周报] %s ~ ", since.In(te.loc).Format("2006-01-02"))
	if !strings.HasPrefix(reqs[0].Title, wantPrefix) {
		t.Errorf("周报标题 = %q, 期望前缀 %q", reqs[0].Title, wantPrefix)
	}
	if _, err := os.Stat(archivePathFor(te.cfg, te.loc, "weekly", since)); err != nil {
		t.Errorf("周报归档文件缺失: %v", err)
	}
}

// —— 附加：重复 Generate 幂等（同窗口 attempts 递增、通知去重不重发）——

func TestRegenerateAttemptsAndDedupe(t *testing.T) {
	te := newTestEnv(t, nil)
	_, ks := seedDailyWindow(t, te.db, te.loc)
	te.llm.steps = successSteps("daily", ks)
	if err := te.gen.Generate(context.Background(), "daily"); err != nil {
		t.Fatalf("第一次 Generate 失败: %v", err)
	}
	// 重置 LLM 脚本（同一 mock server 复用）。
	te.llm.mu.Lock()
	te.llm.step = 0
	te.llm.steps = successSteps("daily", ks)
	te.llm.mu.Unlock()
	if err := te.gen.Generate(context.Background(), "daily"); err != nil {
		t.Fatalf("第二次 Generate 失败: %v", err)
	}
	rep, err := te.db.GetReport(context.Background(), "daily", mustWindow(t, te.loc))
	if err != nil || rep == nil {
		t.Fatalf("GetReport 失败: %v", err)
	}
	if rep.Attempts != 2 {
		t.Errorf("attempts = %d, 期望 2", rep.Attempts)
	}
	if reqs := te.ntfy.requests(); len(reqs) != 1 {
		// 第二次 Enqueue 命中同一 dedupe key 且此前已 sent → 不再发送。
		t.Errorf("ntfy 收到 %d 条, 期望 1（去重后不重发）", len(reqs))
	}
	nStatus, _ := notificationRow(t, te.db, "daily")
	// 同一 dedupe key 只有一行通知。
	var rows int
	if err := te.db.SQL().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM notifications WHERE kind = 'report.daily'`).Scan(&rows); err != nil {
		t.Fatalf("统计通知行数失败: %v", err)
	}
	if rows != 1 {
		t.Errorf("通知行数 = %d, 期望 1（dedupe 唯一）", rows)
	}
	if nStatus != "sent" {
		t.Errorf("通知状态 = %q, 期望 sent", nStatus)
	}
}
