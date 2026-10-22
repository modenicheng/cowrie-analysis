// S3 资源耗尽组合级复验（SPEC §17 阶段 G、§18 无上限禁止）。
//
// 各单项限制已在对应包覆盖；此处做组合级复验，验证限制之间的配合
// 与错误消息对模型/运维的可读性：
//
//	execute_js：无限循环超时中断（<5s 返回）；超大输入 ErrInputTooLarge；
//	            超大输出 OutputTooLarge 结构化错误；经 tools 层调度同构。
//	query_events：跨度超限报错；limit 超上限钳制（不报错、不无界）；
//	            非法 limit 报可读错误。
package security

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modenc/e3-security-analyst/internal/config"
	"github.com/modenc/e3-security-analyst/internal/cowrie"
	"github.com/modenc/e3-security-analyst/internal/llm"
	"github.com/modenc/e3-security-analyst/internal/sandbox"
	"github.com/modenc/e3-security-analyst/internal/store"
	"github.com/modenc/e3-security-analyst/internal/tools"
)

// TestS3ExecuteJSTimeoutBounded：无限循环脚本被超时中断，远快于 5s。
func TestS3ExecuteJSTimeoutBounded(t *testing.T) {
	r := sandbox.NewRunner(runnerBin, sandbox.Limits{
		TimeoutMS:      200,
		MaxInputBytes:  1 << 20,
		MaxOutputBytes: 1 << 20,
	}, 1)

	start := time.Now()
	res, err := r.Execute(context.Background(), "while (true) {}", nil, 200)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.OK {
		t.Fatalf("无限循环不应成功: %s", res.Result)
	}
	if res.ErrorType != "TimeoutError" {
		t.Fatalf("ErrorType = %q, 期望 TimeoutError（实际 %q）", res.ErrorType, res.ErrorMessage)
	}
	if elapsed >= 5*time.Second {
		t.Fatalf("超时中断过慢: %v（应 <5s）", elapsed)
	}
	if res.ErrorMessage == "" {
		t.Error("超时错误消息为空，应可读")
	}
}

// TestS3ExecuteJSInputTooLarge：任务输入超限时在启动子进程前拒绝。
func TestS3ExecuteJSInputTooLarge(t *testing.T) {
	r := sandbox.NewRunner(runnerBin, sandbox.Limits{
		TimeoutMS:      1000,
		MaxInputBytes:  128,
		MaxOutputBytes: 4096,
	}, 1)
	_, err := r.Execute(context.Background(), "// "+strings.Repeat("x", 300), nil, 100)
	if !errors.Is(err, sandbox.ErrInputTooLarge) {
		t.Fatalf("期望 ErrInputTooLarge, 实际 %v", err)
	}
	if !strings.Contains(err.Error(), "128") {
		t.Errorf("错误消息应包含上限值便于纠正: %v", err)
	}
}

// TestS3ExecuteJSOutputTooLarge：超大输出以 OutputTooLarge 结构化错误
// 返回（而非无界缓冲或进程崩溃）。
func TestS3ExecuteJSOutputTooLarge(t *testing.T) {
	r := sandbox.NewRunner(runnerBin, sandbox.Limits{
		TimeoutMS:      3000,
		MaxInputBytes:  1 << 20,
		MaxOutputBytes: 64,
	}, 1)
	res, err := r.Execute(context.Background(), `"x".repeat(10000)`, nil, 2000)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.OK {
		t.Fatalf("超大输出不应成功: %s", res.Result)
	}
	if res.ErrorType != "OutputTooLarge" {
		t.Fatalf("ErrorType = %q, 期望 OutputTooLarge（实际 %q）", res.ErrorType, res.ErrorMessage)
	}
	if !strings.Contains(res.ErrorMessage, "64") {
		t.Errorf("错误消息应包含上限值: %q", res.ErrorMessage)
	}
}

// TestS3DispatcherResourceLimits：经 tools 层（模型实际路径）复验
// execute_js 超时结构化回传、query_events 跨度/limit 约束。
func TestS3DispatcherResourceLimits(t *testing.T) {
	db := openTestDB(t)
	cfg := config.Default()
	cfg.ScriptRunner.Enabled = true
	cfg.ScriptRunner.RunnerPath = runnerBin
	cfg.ScriptRunner.TimeoutMS = 2000
	cfg.Reports.MaxQuerySpanDays = 31
	runner := sandbox.NewRunner(runnerBin, sandbox.Limits{
		TimeoutMS:      cfg.ScriptRunner.TimeoutMS,
		MaxInputBytes:  cfg.ScriptRunner.MaxInputBytes,
		MaxOutputBytes: cfg.ScriptRunner.MaxOutputBytes,
	}, 1)
	disp := tools.NewDispatcher(cfg, db, runner, nil, nil)
	ctx := context.Background()

	now := time.Now().UTC()
	seedSimpleEvents(t, db, now)

	// —— execute_js 超时：结构化 {"ok":false,"error":{"type":"TimeoutError"}} ——
	out, err := disp.Handle(ctx, llm.ToolCall{
		ID: "t1", Name: "execute_js",
		ArgsJSON: `{"code":"while(true){}","timeout_ms":200}`,
	}, tools.TaskWindow{Since: now.Add(-time.Hour), Until: now, Type: "daily", RunID: "sec-s3"})
	if err != nil {
		t.Fatalf("execute_js 基础错误应结构化返回而非中断: %v", err)
	}
	var jsRes struct {
		OK    bool `json:"ok"`
		Error *struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &jsRes); err != nil {
		t.Fatalf("解析 execute_js 结果: %v（%s）", err, out)
	}
	if jsRes.OK || jsRes.Error == nil || jsRes.Error.Type != "TimeoutError" {
		t.Fatalf("execute_js 超时应结构化返回 TimeoutError, 实际 %s", out)
	}
	// script_runs 审计已记录（RunID 关联）。
	var runID, preview string
	if err := db.SQL().QueryRowContext(ctx,
		`SELECT run_id, COALESCE(output_preview,'') FROM script_runs ORDER BY id DESC LIMIT 1`).
		Scan(&runID, &preview); err != nil {
		t.Fatalf("查询 script_runs: %v", err)
	}
	if runID != "sec-s3" {
		t.Errorf("script_runs.run_id = %q, 期望 sec-s3（审计关联）", runID)
	}

	// —— query_events 跨度超限：可读错误给出允许上限 ——
	_, err = disp.Handle(ctx, llm.ToolCall{
		ID: "q1", Name: "query_events", ArgsJSON: "{}",
	}, tools.TaskWindow{
		Since: now.Add(-40 * 24 * time.Hour), Until: now, Type: "daily", RunID: "sec-s3",
	})
	if err == nil {
		t.Fatal("跨度 40 天（>31）应报错")
	}
	if miss, ok := containsAll(err.Error(), "跨度", "31"); !ok {
		t.Errorf("跨度错误消息应含允许上限（缺失 %v）: %v", miss, err)
	}

	// —— query_events limit 超 1000：钳制而非报错、而非无界查询 ——
	out, err = disp.Handle(ctx, llm.ToolCall{
		ID: "q2", Name: "query_events",
		ArgsJSON: `{"limit": 100000}`,
	}, tools.TaskWindow{Since: now.Add(-time.Hour), Until: now, Type: "daily", RunID: "sec-s3"})
	if err != nil {
		t.Fatalf("limit=100000 应被钳制而非报错: %v", err)
	}
	var evRes struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal([]byte(out), &evRes); err != nil {
		t.Fatalf("解析 query_events 结果: %v", err)
	}
	if evRes.Count != 3 {
		t.Errorf("query_events count = %d, 期望 3（钳制后仍返回全部命中）", evRes.Count)
	}

	// —— 非法 limit（0 / 负数）：可读错误 ——
	for _, bad := range []string{`{"limit":0}`, `{"limit":-5}`} {
		if _, err := disp.Handle(ctx, llm.ToolCall{ID: "q3", Name: "query_events", ArgsJSON: bad},
			tools.TaskWindow{Since: now.Add(-time.Hour), Until: now, Type: "daily", RunID: "sec-s3"}); err == nil {
			t.Errorf("limit=%s 应报错", bad)
		} else if !strings.Contains(err.Error(), "1..1000") {
			t.Errorf("limit 错误消息应给出合法区间: %v", err)
		}
	}
}

// seedSimpleEvents 种入 3 条 connect 事件（近一小时内）。
func seedSimpleEvents(t *testing.T, db *store.DB, now time.Time) {
	t.Helper()
	for i := 0; i < 3; i++ {
		ts := now.Add(-time.Duration(10+i) * time.Minute)
		raw, err := json.Marshal(map[string]any{
			"eventid":   cowrie.EventConnect,
			"timestamp": ts.UTC().Format(time.RFC3339Nano),
			"src_ip":    "192.0.2." + itoa(i+1),
			"session":   "s3-" + itoa(i),
			"seq":       ts.UnixNano(),
		})
		if err != nil {
			t.Fatalf("构造 raw: %v", err)
		}
		e := &store.Event{
			EventID:   cowrie.EventConnect,
			EventTime: ts,
			SrcIP:     "192.0.2." + itoa(i+1),
			Session:   "s3-" + itoa(i),
			Raw:       string(raw),
		}
		if _, _, err := db.InsertEvents(context.Background(), []*store.Event{e}); err != nil {
			t.Fatalf("InsertEvents: %v", err)
		}
	}
}

// itoa 是 strconv.Itoa 的简写别名，避免各处重复导入。
func itoa(i int) string { return strconv.Itoa(i) }
