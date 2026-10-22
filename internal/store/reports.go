package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Report 是一次周期报告的元数据与归档内容。
type Report struct {
	ID                     int64
	Type                   string // daily|weekly
	WindowStart, WindowEnd time.Time
	Status                 string // pending|validated|published|failed
	Model                  string
	Attempts               int
	ContentSHA256          string
	Payload                string // 完整报告 JSON
	Error                  string
	CreatedAt, UpdatedAt   time.Time
}

// UpsertReport 按 (report_type, window_start) 幂等写入：同窗口重复生成时
// 更新既有行而不是新增；CreatedAt 为零时取当前时间，更新时保留原 first 值。
func (db *DB) UpsertReport(ctx context.Context, r *Report) error {
	if r.Type == "" {
		return fmt.Errorf("store.UpsertReport: Type 不能为空")
	}
	now := time.Now().UTC()
	createdAt := r.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}
	updatedAt := r.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = now
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO reports
		(report_type, window_start, window_end, status, model, attempts,
		 content_sha256, payload, error, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(report_type, window_start) DO UPDATE SET
			window_end     = excluded.window_end,
			status         = excluded.status,
			model          = excluded.model,
			attempts       = excluded.attempts,
			content_sha256 = excluded.content_sha256,
			payload        = excluded.payload,
			error          = excluded.error,
			updated_at     = excluded.updated_at`,
		r.Type, fmtTime(r.WindowStart), fmtTime(r.WindowEnd), r.Status,
		r.Model, r.Attempts, r.ContentSHA256, r.Payload, r.Error,
		fmtTime(createdAt), fmtTime(updatedAt)); err != nil {
		return fmt.Errorf("store.UpsertReport: %w", err)
	}
	if err := db.sql.QueryRowContext(ctx,
		`SELECT id FROM reports WHERE report_type = ? AND window_start = ?`,
		r.Type, fmtTime(r.WindowStart)).Scan(&r.ID); err != nil {
		return fmt.Errorf("store.UpsertReport: 回读 id: %w", err)
	}
	return nil
}

// GetReport 读取指定类型与窗口起始时间的报告；不存在返回 (nil, nil)。
func (db *DB) GetReport(ctx context.Context, typ string, windowStart time.Time) (*Report, error) {
	row := db.sql.QueryRowContext(ctx, `SELECT id, report_type, window_start,
		window_end, status, model, attempts, content_sha256, payload, error,
		created_at, updated_at FROM reports
		WHERE report_type = ? AND window_start = ?`, typ, fmtTime(windowStart))
	r, err := scanReport(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store.GetReport(%s): %w", typ, err)
	}
	return r, nil
}

// FailedReports 返回 updatedSince 之后仍处于 failed 状态的报告
// （供周期性重试），按 updated_at 升序；updatedSince 为零值时不过滤。
func (db *DB) FailedReports(ctx context.Context, updatedSince time.Time) ([]*Report, error) {
	q := `SELECT id, report_type, window_start, window_end, status, model,
		attempts, content_sha256, payload, error, created_at, updated_at
		FROM reports WHERE status = 'failed'`
	var args []any
	if !updatedSince.IsZero() {
		q += " AND updated_at >= ?"
		args = append(args, fmtTime(updatedSince))
	}
	q += " ORDER BY updated_at"
	rows, err := db.sql.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.FailedReports: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Report
	for rows.Next() {
		r, err := scanReport(rows)
		if err != nil {
			return nil, fmt.Errorf("store.FailedReports: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.FailedReports: %w", err)
	}
	return out, nil
}

// scanReport 从一行扫描出 Report。
func scanReport(sc interface{ Scan(dest ...any) error }) (*Report, error) {
	var (
		r                         Report
		windowStart, windowEnd    string
		model, sha, payload, rerr sql.NullString
		createdAt, updatedAt      string
	)
	if err := sc.Scan(&r.ID, &r.Type, &windowStart, &windowEnd, &r.Status, &model,
		&r.Attempts, &sha, &payload, &rerr, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	r.Model = model.String
	r.ContentSHA256 = sha.String
	r.Payload = payload.String
	r.Error = rerr.String
	var err error
	if r.WindowStart, err = parseTime(windowStart); err != nil {
		return nil, err
	}
	if r.WindowEnd, err = parseTime(windowEnd); err != nil {
		return nil, err
	}
	if r.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if r.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}
