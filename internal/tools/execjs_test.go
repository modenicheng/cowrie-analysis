package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// jsResp 是测试侧对 execute_js 结果的解码目标。
type jsResp struct {
	OK         bool            `json:"ok"`
	Result     json.RawMessage `json:"result"`
	Error      *jsErrorInfo    `json:"error"`
	DurationMS int64           `json:"duration_ms"`
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestExecuteJSDisabled：配置禁用或 runner 为 nil 都返回“execute_js 已禁用”。
func TestExecuteJSDisabled(t *testing.T) {
	db := openDB(t)

	cfg := testCfg()
	cfg.ScriptRunner.Enabled = false
	got := wantErr(t, NewDispatcher(cfg, db, newRunner(2000), nil, nil), "execute_js", `{"code":"1"}`, testWin())
	if !strings.Contains(got, "execute_js 已禁用") {
		t.Fatalf("配置禁用应报 execute_js 已禁用，实际 %q", got)
	}

	got = wantErr(t, NewDispatcher(testCfg(), db, nil, nil, nil), "execute_js", `{"code":"1"}`, testWin())
	if !strings.Contains(got, "execute_js 已禁用") {
		t.Fatalf("runner=nil 应报 execute_js 已禁用，实际 %q", got)
	}
}

// TestExecuteJSSuccessAndAudit：真实子进程执行 ok:true，script_runs 记录
// RunID/CodeSHA256/耗时/输出。
func TestExecuteJSSuccessAndAudit(t *testing.T) {
	db := openDB(t)
	cfg := testCfg()
	d := NewDispatcher(cfg, db, newRunner(5000), nil, nil)
	win := testWin()
	win.RunID = "run-42"

	code := "input.a + input.b"
	args := `{"code":"input.a + input.b","input":{"a":40,"b":2},"timeout_ms":1500}`
	var r jsResp
	if err := json.Unmarshal([]byte(mustHandle(t, d, "execute_js", args, win)), &r); err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if !r.OK {
		t.Fatalf("期望 ok:true，得到 error %q: %q", r.Error.Type, r.Error.Message)
	}
	if strings.TrimSpace(string(r.Result)) != "42" {
		t.Fatalf("result=%s，期望 42", r.Result)
	}
	if r.DurationMS < 0 {
		t.Fatalf("duration_ms=%d 应非负", r.DurationMS)
	}

	var (
		runID, sha string
		dur        int64
		okv        int
		outBytes   int64
		preview    string
	)
	err := db.SQL().QueryRow(`SELECT run_id, code_sha256, duration_ms, ok, output_bytes, output_preview
		FROM script_runs ORDER BY id DESC LIMIT 1`).
		Scan(&runID, &sha, &dur, &okv, &outBytes, &preview)
	if err != nil {
		t.Fatalf("读取 script_runs 失败: %v", err)
	}
	if runID != "run-42" {
		t.Errorf("run_id=%q，期望 run-42", runID)
	}
	if want := sha256hex(code); sha != want {
		t.Errorf("code_sha256=%s，期望 %s", sha, want)
	}
	if okv != 1 {
		t.Errorf("ok=%d，期望 1", okv)
	}
	if outBytes != int64(len("42")) {
		t.Errorf("output_bytes=%d，期望 %d", outBytes, len("42"))
	}
	if preview != "42" {
		t.Errorf("output_preview=%q，期望 \"42\"", preview)
	}
	if dur < 0 {
		t.Errorf("duration_ms=%d 应非负", dur)
	}
}

// TestExecuteJSScriptErrorStructured：脚本错误结构化返回 ok:false 且同样
// 记录 script_runs（ok=0）。
func TestExecuteJSScriptErrorStructured(t *testing.T) {
	db := openDB(t)
	d := NewDispatcher(testCfg(), db, newRunner(5000), nil, nil)
	win := testWin()
	win.RunID = "run-err"

	var r jsResp
	res := mustHandle(t, d, "execute_js", `{"code":"var x = ;"}`, win) // 不应返回 error
	if err := json.Unmarshal([]byte(res), &r); err != nil {
		t.Fatalf("解码失败: %v\n%s", err, res)
	}
	if r.OK {
		t.Fatal("语法错误脚本应返回 ok:false")
	}
	if r.Error == nil {
		t.Fatal("ok:false 时应携带 error 对象")
	}
	if r.Error.Type != "SyntaxError" {
		t.Errorf("error.type=%q，期望 SyntaxError", r.Error.Type)
	}
	if r.Error.Message == "" {
		t.Error("error.message 不应为空")
	}

	var runID string
	var okv int
	var preview string
	if err := db.SQL().QueryRow(`SELECT run_id, ok, output_preview
		FROM script_runs ORDER BY id DESC LIMIT 1`).Scan(&runID, &okv, &preview); err != nil {
		t.Fatalf("读取 script_runs 失败: %v", err)
	}
	if runID != "run-err" || okv != 0 {
		t.Errorf("script_runs run_id=%q ok=%d，期望 run-err/0", runID, okv)
	}
	if !strings.Contains(preview, "SyntaxError") {
		t.Errorf("失败审计的 output_preview 应包含错误信息: %q", preview)
	}
}

// TestExecuteJSInputTooLarge：input 序列化后超过配置上限返回 error。
func TestExecuteJSInputTooLarge(t *testing.T) {
	db := openDB(t)
	cfg := testCfg()
	cfg.ScriptRunner.MaxInputBytes = 64
	d := NewDispatcher(cfg, db, newRunner(5000), nil, nil)

	big := strings.Repeat("x", 200)
	args := `{"code":"1","input":"` + big + `"}`
	got := wantErr(t, d, "execute_js", args, testWin())
	if !strings.Contains(got, "请缩小 input") {
		t.Fatalf("input 超限错误应提示缩小 input，实际 %q", got)
	}
}

// TestExecuteJSTimeoutClamp：请求的 timeout_ms 被钳制到 cfg.ScriptRunner.TimeoutMS
// （runner 自身上限故意放宽到 10s，验证 handler 侧钳制生效）。
func TestExecuteJSTimeoutClamp(t *testing.T) {
	db := openDB(t)
	cfg := testCfg()
	cfg.ScriptRunner.TimeoutMS = 400
	d := NewDispatcher(cfg, db, newRunner(10000), nil, nil)

	start := time.Now()
	var r jsResp
	res := mustHandle(t, d, "execute_js", `{"code":"while (true) {}","timeout_ms":60000}`, testWin())
	elapsed := time.Since(start)
	if err := json.Unmarshal([]byte(res), &r); err != nil {
		t.Fatalf("解码失败: %v\n%s", err, res)
	}
	if r.OK {
		t.Fatal("死循环脚本应超时失败")
	}
	if r.Error == nil || r.Error.Type != "TimeoutError" {
		t.Fatalf("期望结构化 TimeoutError，得到 %+v", r.Error)
	}
	if elapsed >= 5*time.Second {
		t.Fatalf("超时钳制未生效，耗时 %v", elapsed)
	}
}
