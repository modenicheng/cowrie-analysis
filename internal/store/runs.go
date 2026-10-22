package store

import (
	"context"
	"fmt"
	"time"
)

// AnalysisRun 是一次 LLM 分析任务的运行记录。
type AnalysisRun struct {
	ID, Task                                          string
	StartedAt                                         time.Time
	EndedAt                                           *time.Time
	Status                                            string // running|ok|failed
	Model                                             string
	Rounds, PromptTokens, CompletionTokens, ToolCalls int
	Error                                             string
}

// CreateAnalysisRun 插入一条分析运行记录（通常 status=running）。
func (db *DB) CreateAnalysisRun(ctx context.Context, r *AnalysisRun) error {
	if r.ID == "" {
		return fmt.Errorf("store.CreateAnalysisRun: ID 不能为空")
	}
	if r.Task == "" {
		return fmt.Errorf("store.CreateAnalysisRun: Task 不能为空")
	}
	startedAt := r.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	if r.Status == "" {
		r.Status = "running"
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO analysis_runs
		(id, task, started_at, ended_at, status, model, rounds,
		 prompt_tokens, completion_tokens, tool_calls, error)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.Task, fmtTime(startedAt), fmtTimePtr(r.EndedAt), r.Status,
		r.Model, r.Rounds, r.PromptTokens, r.CompletionTokens, r.ToolCalls,
		r.Error); err != nil {
		return fmt.Errorf("store.CreateAnalysisRun: %w", err)
	}
	return nil
}

// FinishAnalysisRun 按主键补全运行结果（结束时间、状态与用量统计）。
func (db *DB) FinishAnalysisRun(ctx context.Context, r *AnalysisRun) error {
	if r.ID == "" {
		return fmt.Errorf("store.FinishAnalysisRun: ID 不能为空")
	}
	if r.EndedAt == nil {
		now := time.Now().UTC()
		r.EndedAt = &now
	}
	res, err := db.sql.ExecContext(ctx, `UPDATE analysis_runs
		SET ended_at = ?, status = ?, model = ?, rounds = ?,
		    prompt_tokens = ?, completion_tokens = ?, tool_calls = ?, error = ?
		WHERE id = ?`,
		fmtTime(*r.EndedAt), r.Status, r.Model, r.Rounds,
		r.PromptTokens, r.CompletionTokens, r.ToolCalls, r.Error, r.ID)
	if err != nil {
		return fmt.Errorf("store.FinishAnalysisRun: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store.FinishAnalysisRun: 运行记录 id=%s 不存在", r.ID)
	}
	return nil
}

// ScriptRun 是一次受限 JavaScript 执行的审计记录。
type ScriptRun struct {
	RunID, CodeSHA256 string
	DurationMS        int64
	OK                bool
	OutputBytes       int64
	OutputPreview     string
	CreatedAt         time.Time
}

// InsertScriptRun 记录一次脚本执行。
func (db *DB) InsertScriptRun(ctx context.Context, s *ScriptRun) error {
	if s.CodeSHA256 == "" {
		return fmt.Errorf("store.InsertScriptRun: CodeSHA256 不能为空")
	}
	createdAt := s.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	ok := 0
	if s.OK {
		ok = 1
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO script_runs
		(run_id, code_sha256, duration_ms, ok, output_bytes, output_preview, created_at)
		VALUES (?,?,?,?,?,?,?)`,
		s.RunID, s.CodeSHA256, s.DurationMS, ok, s.OutputBytes,
		s.OutputPreview, fmtTime(createdAt)); err != nil {
		return fmt.Errorf("store.InsertScriptRun: %w", err)
	}
	return nil
}
