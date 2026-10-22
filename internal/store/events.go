package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modenc/e3-security-analyst/internal/cowrie"
)

// Event 是入库/内存中的事件表示。原始 JSON 行在 Raw 中无损保留；
// Command、Username 等攻击者可控字段一律保持原值，不脱敏。
type Event struct {
	ID          int64
	EventID     string    // cowrie eventid
	EventTime   time.Time // 事件时间（UTC）
	CollectedAt time.Time // 采集时间（UTC）
	SrcIP       string
	SrcPort     int64
	Session     string
	Username    string
	Command     string // cowrie.command.input 的 input 字段（原值）
	Filename    string
	Shasum      string
	DurationS   float64 // cowrie.session.closed 的 duration
	Raw         string  // 原始 JSON 行，无损保留
}

// EventFilter 是事件查询条件；时间语义为 [Since, Until) 左闭右开。
// Limit/CursorID 供分页接口使用（CountEvents 忽略）。
type EventFilter struct {
	Since, Until   time.Time
	SrcIP, Session string
	EventIDs       []string
	Limit          int   // 上限由调用方钳制
	CursorID       int64 // events.id > CursorID，按 id 升序
}

const insertEventSQL = `INSERT INTO events
	(event_id, event_time, collected_at, src_ip, src_port, session, username,
	 command, filename, shasum, duration_s, raw, raw_sha256)
	VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
	ON CONFLICT(raw_sha256) DO NOTHING`

const upsertSessionSQL = `INSERT INTO sessions
	(session_id, src_ip, started_at, ended_at, duration_s, login_attempts,
	 login_successes, command_count, file_ops, first_seen, updated_at)
	VALUES (?,?,?,?,?,?,?,?,?,?,?)
	ON CONFLICT(session_id) DO UPDATE SET
		src_ip          = excluded.src_ip,
		started_at      = excluded.started_at,
		ended_at        = excluded.ended_at,
		duration_s      = excluded.duration_s,
		login_attempts  = excluded.login_attempts,
		login_successes = excluded.login_successes,
		command_count   = excluded.command_count,
		file_ops        = excluded.file_ops,
		updated_at      = excluded.updated_at`

// InsertEvents 在单个事务内幂等插入一批事件：对每条事件计算 raw 的 SHA-256
// 作为去重键（ON CONFLICT DO NOTHING），通过 RowsAffected 区分新插入与重复；
// 只对真正新插入的事件更新 sessions 聚合（batch 内先按 session 归并），
// 因此重复提交同一批事件不会使计数增长。
func (db *DB) InsertEvents(ctx context.Context, evs []*Event) (inserted, duplicates int, err error) {
	if len(evs) == 0 {
		return 0, 0, nil
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("store.InsertEvents: 开启事务失败: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	stmt, err := tx.PrepareContext(ctx, insertEventSQL)
	if err != nil {
		return 0, 0, fmt.Errorf("store.InsertEvents: 预编译插入语句失败: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	now := time.Now().UTC()
	deltas := make(map[string]*sessDelta)
	var order []string // 保持 session 首次出现顺序，写入顺序确定
	for _, ev := range evs {
		if ev == nil {
			err = fmt.Errorf("store.InsertEvents: 事件列表包含 nil 元素")
			return 0, 0, err
		}
		collected := ev.CollectedAt
		if collected.IsZero() {
			collected = now
		}
		sum := sha256.Sum256([]byte(ev.Raw))
		res, execErr := stmt.ExecContext(ctx,
			ev.EventID, fmtTime(ev.EventTime), fmtTime(collected),
			ev.SrcIP, ev.SrcPort, ev.Session, ev.Username,
			ev.Command, ev.Filename, ev.Shasum, ev.DurationS,
			ev.Raw, hex.EncodeToString(sum[:]))
		if execErr != nil {
			err = fmt.Errorf("store.InsertEvents: 插入事件失败: %w", execErr)
			return 0, 0, err
		}
		n, affErr := res.RowsAffected()
		if affErr != nil {
			err = fmt.Errorf("store.InsertEvents: 读取 RowsAffected 失败: %w", affErr)
			return 0, 0, err
		}
		if n == 0 {
			duplicates++ // raw_sha256 已存在（含 batch 内重复）
			continue
		}
		inserted++
		if ev.Session == "" {
			continue // 无会话归属的事件不参与聚合
		}
		d, ok := deltas[ev.Session]
		if !ok {
			d = &sessDelta{}
			deltas[ev.Session] = d
			order = append(order, ev.Session)
		}
		d.add(ev)
	}

	for _, sid := range order {
		if mergeErr := upsertSession(ctx, tx, sid, deltas[sid], now); mergeErr != nil {
			err = fmt.Errorf("store.InsertEvents: 更新 session 聚合失败: %w", mergeErr)
			return 0, 0, err
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("store.InsertEvents: 提交事务失败: %w", err)
	}
	return inserted, duplicates, nil
}

// sessDelta 累计一个 batch 内某 session 新插入事件的聚合增量。
type sessDelta struct {
	srcIP            string
	srcIPFromConnect bool // srcIP 是否来自 connect 事件（connect 优先）
	started, ended   time.Time
	loginAttempts    int
	loginSuccesses   int
	commands         int
	fileOps          int
	duration         float64
}

// add 按 cowrie.Kind 语义累计一个事件对 session 聚合的贡献。
func (d *sessDelta) add(ev *Event) {
	kind := cowrie.Classify(ev.EventID)
	if d.started.IsZero() || ev.EventTime.Before(d.started) {
		d.started = ev.EventTime
	}
	if ev.EventTime.After(d.ended) {
		d.ended = ev.EventTime
	}
	if ev.SrcIP != "" {
		if kind == cowrie.KindConnect {
			if !d.srcIPFromConnect { // 首个 connect 事件优先
				d.srcIP, d.srcIPFromConnect = ev.SrcIP, true
			}
		} else if d.srcIP == "" && !d.srcIPFromConnect {
			d.srcIP = ev.SrcIP // 退化为首个非空来源
		}
	}
	switch kind {
	case cowrie.KindLoginFailed, cowrie.KindLoginSuccess:
		d.loginAttempts++ // 尝试数 = 失败 + 成功
	case cowrie.KindCommand:
		d.commands++
	case cowrie.KindFileUpload, cowrie.KindFileDownload, cowrie.KindFileFailed:
		d.fileOps++
	}
	if kind == cowrie.KindLoginSuccess {
		d.loginSuccesses++
	}
	if kind == cowrie.KindSessionClosed && ev.DurationS > d.duration {
		d.duration = ev.DurationS // 会话时长取最大值
	}
}

// upsertSession 把增量合并进 sessions 表：与既有行取 started_at=最早、
// ended_at=最晚、duration_s=max，计数累加，src_ip 按 connect 优先/首个非空
// 填充；first_seen 保留首次值。调用方保证处于 InsertEvents 的同一事务内。
func upsertSession(ctx context.Context, tx *sql.Tx, sessionID string, d *sessDelta, now time.Time) error {
	var (
		srcIP    sql.NullString
		started  sql.NullString
		ended    sql.NullString
		duration sql.NullFloat64
		attempts int
		succ     int
		cmds     int
		fileOps  int
	)
	err := tx.QueryRowContext(ctx, `SELECT src_ip, started_at, ended_at, duration_s,
		login_attempts, login_successes, command_count, file_ops
		FROM sessions WHERE session_id = ?`, sessionID).
		Scan(&srcIP, &started, &ended, &duration, &attempts, &succ, &cmds, &fileOps)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// 新会话
	case err != nil:
		return fmt.Errorf("查询 session %q: %w", sessionID, err)
	}

	finalSrcIP := srcIP.String
	if d.srcIP != "" && (finalSrcIP == "" || d.srcIPFromConnect) {
		finalSrcIP = d.srcIP
	}
	finalStarted, finalEnded := d.started, d.ended
	if started.Valid && started.String != "" {
		t, perr := parseTime(started.String)
		if perr != nil {
			return fmt.Errorf("解析 session %q started_at: %w", sessionID, perr)
		}
		if finalStarted.IsZero() || t.Before(finalStarted) {
			finalStarted = t
		}
	}
	if ended.Valid && ended.String != "" {
		t, perr := parseTime(ended.String)
		if perr != nil {
			return fmt.Errorf("解析 session %q ended_at: %w", sessionID, perr)
		}
		if t.After(finalEnded) {
			finalEnded = t
		}
	}
	finalDuration := d.duration
	if duration.Valid && duration.Float64 > finalDuration {
		finalDuration = duration.Float64
	}

	var srcArg, startedArg, endedArg any
	if finalSrcIP != "" {
		srcArg = finalSrcIP
	}
	if !finalStarted.IsZero() {
		startedArg = fmtTime(finalStarted)
	}
	if !finalEnded.IsZero() {
		endedArg = fmtTime(finalEnded)
	}
	if _, err := tx.ExecContext(ctx, upsertSessionSQL,
		sessionID, srcArg, startedArg, endedArg, finalDuration,
		attempts+d.loginAttempts, succ+d.loginSuccesses,
		cmds+d.commands, fileOps+d.fileOps,
		fmtTime(now), fmtTime(now)); err != nil {
		return fmt.Errorf("写入 session %q: %w", sessionID, err)
	}
	return nil
}

// CountEvents 统计满足过滤条件的事件数（[Since, Until) 左闭右开）。
// Limit/CursorID 不影响计数。
func (db *DB) CountEvents(ctx context.Context, f EventFilter) (int, error) {
	where, args := eventWhere(f)
	row := db.sql.QueryRowContext(ctx, "SELECT COUNT(*) FROM events"+where, args...)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, fmt.Errorf("store.CountEvents: %w", err)
	}
	return n, nil
}

// eventWhere 组装事件查询共用的 WHERE 子句与参数。
func eventWhere(f EventFilter) (string, []any) {
	var conds []string
	var args []any
	if !f.Since.IsZero() {
		conds = append(conds, "event_time >= ?")
		args = append(args, fmtTime(f.Since))
	}
	if !f.Until.IsZero() {
		conds = append(conds, "event_time < ?")
		args = append(args, fmtTime(f.Until))
	}
	if f.SrcIP != "" {
		conds = append(conds, "src_ip = ?")
		args = append(args, f.SrcIP)
	}
	if f.Session != "" {
		conds = append(conds, "session = ?")
		args = append(args, f.Session)
	}
	if len(f.EventIDs) > 0 {
		ph := strings.TrimRight(strings.Repeat("?,", len(f.EventIDs)), ",")
		conds = append(conds, "event_id IN ("+ph+")")
		for _, id := range f.EventIDs {
			args = append(args, id)
		}
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}
