package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Offset 是日志文件的采集游标。FileKey 为 "dev:ino"（unix）或
// "vol:index"（windows），轮转后同名文件对应不同 FileKey。
type Offset struct {
	FileKey, Path                    string
	Inode, Offset, FileSize, MtimeNS int64
	UpdatedAt                        time.Time
}

// SetOffset upsert 一条采集游标。
func (db *DB) SetOffset(ctx context.Context, o *Offset) error {
	if o.FileKey == "" {
		return fmt.Errorf("store.SetOffset: FileKey 不能为空")
	}
	updatedAt := o.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO collector_offsets
		(file_key, path, inode, offset, file_size, mtime_ns, updated_at)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(file_key) DO UPDATE SET
			path = excluded.path, inode = excluded.inode, offset = excluded.offset,
			file_size = excluded.file_size, mtime_ns = excluded.mtime_ns,
			updated_at = excluded.updated_at`,
		o.FileKey, o.Path, o.Inode, o.Offset, o.FileSize, o.MtimeNS, fmtTime(updatedAt)); err != nil {
		return fmt.Errorf("store.SetOffset: %w", err)
	}
	return nil
}

// GetOffset 读取指定文件游标；不存在返回 (nil, nil)。
func (db *DB) GetOffset(ctx context.Context, fileKey string) (*Offset, error) {
	var (
		o         Offset
		updatedAt string
	)
	err := db.sql.QueryRowContext(ctx, `SELECT file_key, path, inode, offset,
		file_size, mtime_ns, updated_at FROM collector_offsets WHERE file_key = ?`,
		fileKey).Scan(&o.FileKey, &o.Path, &o.Inode, &o.Offset, &o.FileSize,
		&o.MtimeNS, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store.GetOffset(%s): %w", fileKey, err)
	}
	if o.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return nil, fmt.Errorf("store.GetOffset(%s): %w", fileKey, err)
	}
	return &o, nil
}

// ListOffsets 返回全部采集游标（按 file_key 排序）。
func (db *DB) ListOffsets(ctx context.Context) ([]*Offset, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT file_key, path, inode, offset,
		file_size, mtime_ns, updated_at FROM collector_offsets ORDER BY file_key`)
	if err != nil {
		return nil, fmt.Errorf("store.ListOffsets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Offset
	for rows.Next() {
		var (
			o         Offset
			updatedAt string
		)
		if err := rows.Scan(&o.FileKey, &o.Path, &o.Inode, &o.Offset,
			&o.FileSize, &o.MtimeNS, &updatedAt); err != nil {
			return nil, fmt.Errorf("store.ListOffsets: %w", err)
		}
		if o.UpdatedAt, err = parseTime(updatedAt); err != nil {
			return nil, fmt.Errorf("store.ListOffsets: %w", err)
		}
		out = append(out, &o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListOffsets: %w", err)
	}
	return out, nil
}

// Health 是采集健康状态（单行，id=1）。LastReadAt/LastEventAt 可为空。
type Health struct {
	LastReadAt, LastEventAt *time.Time
	LastError               string
	UpdatedAt               time.Time
}

// UpdateHealth upsert 采集健康状态（单例行）。
func (db *DB) UpdateHealth(ctx context.Context, h *Health) error {
	updatedAt := h.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO collector_health
		(id, last_read_at, last_event_at, last_error, updated_at)
		VALUES (1,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			last_read_at = excluded.last_read_at,
			last_event_at = excluded.last_event_at,
			last_error = excluded.last_error,
			updated_at = excluded.updated_at`,
		fmtTimePtr(h.LastReadAt), fmtTimePtr(h.LastEventAt),
		h.LastError, fmtTime(updatedAt)); err != nil {
		return fmt.Errorf("store.UpdateHealth: %w", err)
	}
	return nil
}

// GetHealth 读取采集健康状态；尚未写入时返回 (nil, nil)。
func (db *DB) GetHealth(ctx context.Context) (*Health, error) {
	var (
		lastRead, lastEvent, lastErr, updatedAt sql.NullString
	)
	err := db.sql.QueryRowContext(ctx, `SELECT last_read_at, last_event_at,
		last_error, updated_at FROM collector_health WHERE id = 1`).
		Scan(&lastRead, &lastEvent, &lastErr, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store.GetHealth: %w", err)
	}
	h := &Health{LastError: lastErr.String}
	if h.LastReadAt, err = parseTimePtr(lastRead); err != nil {
		return nil, fmt.Errorf("store.GetHealth: %w", err)
	}
	if h.LastEventAt, err = parseTimePtr(lastEvent); err != nil {
		return nil, fmt.Errorf("store.GetHealth: %w", err)
	}
	if updatedAt.Valid {
		if h.UpdatedAt, err = parseTime(updatedAt.String); err != nil {
			return nil, fmt.Errorf("store.GetHealth: %w", err)
		}
	}
	return h, nil
}

// Gap 表示一段采集停滞造成的数据缺口。
type Gap struct {
	ID         int64
	Start, End time.Time
	Reason     string
}

// AddGap 记录一个数据缺口 [start, end)。
func (db *DB) AddGap(ctx context.Context, start, end time.Time, reason string) error {
	if _, err := db.sql.ExecContext(ctx,
		`INSERT INTO collector_gaps(gap_start, gap_end, reason) VALUES(?,?,?)`,
		fmtTime(start), fmtTime(end), reason); err != nil {
		return fmt.Errorf("store.AddGap: %w", err)
	}
	return nil
}

// GapsInRange 返回与 [since, until) 有交集的缺口（按开始时间升序）；
// since/until 为零值时不设对应边界。
func (db *DB) GapsInRange(ctx context.Context, since, until time.Time) ([]Gap, error) {
	q := `SELECT id, gap_start, gap_end, reason FROM collector_gaps`
	var conds []string
	var args []any
	if !since.IsZero() {
		conds = append(conds, "gap_end > ?")
		args = append(args, fmtTime(since))
	}
	if !until.IsZero() {
		conds = append(conds, "gap_start < ?")
		args = append(args, fmtTime(until))
	}
	if len(conds) > 0 {
		q += " WHERE " + conds[0]
		for _, c := range conds[1:] {
			q += " AND " + c
		}
	}
	q += " ORDER BY gap_start"
	rows, err := db.sql.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.GapsInRange: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Gap
	for rows.Next() {
		var (
			g    Gap
			s, e string
		)
		if err := rows.Scan(&g.ID, &s, &e, &g.Reason); err != nil {
			return nil, fmt.Errorf("store.GapsInRange: %w", err)
		}
		if g.Start, err = parseTime(s); err != nil {
			return nil, fmt.Errorf("store.GapsInRange: %w", err)
		}
		if g.End, err = parseTime(e); err != nil {
			return nil, fmt.Errorf("store.GapsInRange: %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.GapsInRange: %w", err)
	}
	return out, nil
}

// ParseErrorRecord 是无法解析的原始日志行，隔离保留，不静默丢弃。
type ParseErrorRecord struct {
	FilePath   string
	FileOffset int64
	Raw, Err   string
	At         time.Time
}

// InsertParseError 记录一条解析失败（自动计算行哈希）。
func (db *DB) InsertParseError(ctx context.Context, pe *ParseErrorRecord) error {
	at := pe.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	sum := sha256.Sum256([]byte(pe.Raw))
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO parse_errors
		(file_path, file_offset, line_sha256, raw, error, recorded_at)
		VALUES (?,?,?,?,?,?)`,
		pe.FilePath, pe.FileOffset, hex.EncodeToString(sum[:]),
		pe.Raw, pe.Err, fmtTime(at)); err != nil {
		return fmt.Errorf("store.InsertParseError: %w", err)
	}
	return nil
}

// CountParseErrors 统计 [since, until) 内记录的解析失败数；
// 零值边界不设对应条件。
func (db *DB) CountParseErrors(ctx context.Context, since, until time.Time) (int, error) {
	q := "SELECT COUNT(*) FROM parse_errors"
	var conds []string
	var args []any
	if !since.IsZero() {
		conds = append(conds, "recorded_at >= ?")
		args = append(args, fmtTime(since))
	}
	if !until.IsZero() {
		conds = append(conds, "recorded_at < ?")
		args = append(args, fmtTime(until))
	}
	if len(conds) > 0 {
		q += " WHERE " + conds[0]
		for _, c := range conds[1:] {
			q += " AND " + c
		}
	}
	var n int
	if err := db.sql.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("store.CountParseErrors: %w", err)
	}
	return n, nil
}
