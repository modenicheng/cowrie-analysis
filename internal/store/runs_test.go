package store

import (
	"context"
	"testing"
	"time"
)

// TestAnalysisRunRoundTrip：CreateAnalysisRun → FinishAnalysisRun → 读回。
func TestAnalysisRunRoundTrip(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	if err := db.CreateAnalysisRun(ctx, &AnalysisRun{ID: ""}); err == nil {
		t.Fatal("空 ID 应报错")
	}

	started := time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)
	run := &AnalysisRun{
		ID: "run-20261021-daily", Task: "daily-report",
		StartedAt: started, Status: "running", Model: "deepseek-chat",
	}
	if err := db.CreateAnalysisRun(ctx, run); err != nil {
		t.Fatalf("CreateAnalysisRun 失败: %v", err)
	}

	var status string
	if err := db.SQL().QueryRow(
		`SELECT status FROM analysis_runs WHERE id = ?`, run.ID).Scan(&status); err != nil {
		t.Fatalf("查询 analysis_runs 失败: %v", err)
	}
	if status != "running" {
		t.Errorf("初始 status = %q, 期望 running", status)
	}

	endedAt := started.Add(3 * time.Minute)
	run.EndedAt = &endedAt
	run.Status = "ok"
	run.Rounds = 4
	run.PromptTokens = 12000
	run.CompletionTokens = 800
	run.ToolCalls = 6
	if err := db.FinishAnalysisRun(ctx, run); err != nil {
		t.Fatalf("FinishAnalysisRun 失败: %v", err)
	}

	var (
		gotStatus, gotModel string
		gotEnded            string
		rounds, pt, ct, tc  int
		gotErr              *string
	)
	if err := db.SQL().QueryRow(`SELECT status, model, ended_at, rounds,
		prompt_tokens, completion_tokens, tool_calls, error
		FROM analysis_runs WHERE id = ?`, run.ID).
		Scan(&gotStatus, &gotModel, &gotEnded, &rounds, &pt, &ct, &tc, &gotErr); err != nil {
		t.Fatalf("读回 analysis_runs 失败: %v", err)
	}
	if gotStatus != "ok" || gotModel != "deepseek-chat" || rounds != 4 ||
		pt != 12000 || ct != 800 || tc != 6 {
		t.Errorf("终态字段不正确: status=%s model=%s rounds=%d pt=%d ct=%d tc=%d",
			gotStatus, gotModel, rounds, pt, ct, tc)
	}
	if got, _ := parseTime(gotEnded); !got.Equal(endedAt) {
		t.Errorf("ended_at = %v, 期望 %v", got, endedAt)
	}

	// 不存在的 ID 拒绝。
	if err := db.FinishAnalysisRun(ctx, &AnalysisRun{ID: "nope", Status: "failed"}); err == nil {
		t.Error("不存在的运行记录 Finish 应报错")
	}
}

// TestScriptRunRoundTrip：InsertScriptRun 落库字段（含 run_id 关联与失败脚本）。
func TestScriptRunRoundTrip(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	if err := db.InsertScriptRun(ctx, &ScriptRun{CodeSHA256: ""}); err == nil {
		t.Fatal("空 CodeSHA256 应报错")
	}

	createdAt := time.Date(2026, 10, 21, 8, 1, 0, 0, time.UTC)
	s := &ScriptRun{
		RunID: "run-20261021-daily", CodeSHA256: "deadbeef",
		DurationMS: 137, OK: true, OutputBytes: 2048,
		OutputPreview: `{"top":1}`, CreatedAt: createdAt,
	}
	if err := db.InsertScriptRun(ctx, s); err != nil {
		t.Fatalf("InsertScriptRun 失败: %v", err)
	}
	s2 := &ScriptRun{
		RunID: "", CodeSHA256: "cafebabe",
		DurationMS: 12, OK: false, OutputBytes: 0,
		OutputPreview: "", CreatedAt: createdAt,
	}
	if err := db.InsertScriptRun(ctx, s2); err != nil {
		t.Fatalf("InsertScriptRun(失败脚本) 失败: %v", err)
	}

	var (
		runID, sha, preview, created string
		duration, ob                 int64
		ok                           int
	)
	if err := db.SQL().QueryRow(`SELECT run_id, code_sha256, duration_ms, ok,
		output_bytes, output_preview, created_at FROM script_runs
		WHERE code_sha256 = 'deadbeef'`).
		Scan(&runID, &sha, &duration, &ok, &ob, &preview, &created); err != nil {
		t.Fatalf("读回 script_runs 失败: %v", err)
	}
	if runID != "run-20261021-daily" || duration != 137 || ok != 1 || ob != 2048 || preview != `{"top":1}` {
		t.Errorf("成功脚本记录不正确: %+v", s)
	}
	if got, _ := parseTime(created); !got.Equal(createdAt) {
		t.Errorf("created_at = %v, 期望 %v", got, createdAt)
	}
	if err := db.SQL().QueryRow(
		`SELECT ok FROM script_runs WHERE code_sha256 = 'cafebabe'`).Scan(&ok); err != nil {
		t.Fatalf("读回失败脚本失败: %v", err)
	}
	if ok != 0 {
		t.Errorf("失败脚本 ok 应为 0, got %d", ok)
	}
}
