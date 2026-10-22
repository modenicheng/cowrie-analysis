package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Notification 是待发布的 ntfy 消息。DedupeKey 为稳定去重键（唯一约束），
// 保证重试/重启不会重复发送。
type Notification struct {
	ID                       int64
	DedupeKey                string
	Kind                     string // 如 alert.login_success / alert.login_failed / report.daily
	Topic, Title, Body, Tags string // Tags 为逗号分隔
	Priority                 int    // ntfy 1..5
	Status                   string // pending|sent|failed
	Attempts                 int
	LastError                string
	MergedCount              int // 限流时被合并的附加事件数
	CreatedAt                time.Time
	SentAt, LastAttemptAt    *time.Time
}

// EnqueueNotification 按 dedupe_key 幂等入队：已存在时返回 existed=true
// 且不覆盖既有内容；新插入时回填 n.ID。
func (db *DB) EnqueueNotification(ctx context.Context, n *Notification) (existed bool, err error) {
	if n.DedupeKey == "" {
		return false, fmt.Errorf("store.EnqueueNotification: DedupeKey 不能为空")
	}
	if n.Status == "" {
		n.Status = "pending"
	}
	if n.Priority == 0 {
		n.Priority = 3
	}
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Now().UTC()
	}
	res, err := db.sql.ExecContext(ctx, `INSERT INTO notifications
		(dedupe_key, kind, topic, title, body, priority, tags, status,
		 last_error, merged_count, created_at, sent_at, last_attempt_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(dedupe_key) DO NOTHING`,
		n.DedupeKey, n.Kind, n.Topic, n.Title, n.Body, n.Priority, n.Tags,
		n.Status, n.LastError, n.MergedCount, fmtTime(n.CreatedAt),
		fmtTimePtr(n.SentAt), fmtTimePtr(n.LastAttemptAt))
	if err != nil {
		return false, fmt.Errorf("store.EnqueueNotification: %w", err)
	}
	aff, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store.EnqueueNotification: RowsAffected: %w", err)
	}
	if aff == 0 {
		return true, nil // 已存在，内容不被覆盖
	}
	if id, lerr := res.LastInsertId(); lerr == nil {
		n.ID = id
	}
	return false, nil
}

// BumpNotification 将指定去重键的通知 merged_count 加一（限流合并计数）。
func (db *DB) BumpNotification(ctx context.Context, dedupeKey string) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE notifications SET merged_count = merged_count + 1 WHERE dedupe_key = ?`,
		dedupeKey)
	if err != nil {
		return fmt.Errorf("store.BumpNotification: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store.BumpNotification: 未找到 dedupe_key=%q 的通知", dedupeKey)
	}
	return nil
}

const notificationCols = `id, dedupe_key, kind, topic, title, body, priority, tags,
	status, attempts, last_error, merged_count, created_at, sent_at, last_attempt_at`

// PendingNotifications 按入队顺序返回 status=pending 的通知；
// limit <= 0 表示不限制条数。
func (db *DB) PendingNotifications(ctx context.Context, limit int) ([]*Notification, error) {
	q := `SELECT ` + notificationCols + ` FROM notifications
		WHERE status = 'pending' ORDER BY created_at, id`
	var args []any
	if limit > 0 {
		q += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := db.sql.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.PendingNotifications: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Notification
	for rows.Next() {
		n, err := scanNotification(rows)
		if err != nil {
			return nil, fmt.Errorf("store.PendingNotifications: %w", err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.PendingNotifications: %w", err)
	}
	return out, nil
}

// MarkNotificationSent 标记通知发送成功（status=sent，清空 last_error）。
func (db *DB) MarkNotificationSent(ctx context.Context, id int64, at time.Time) error {
	res, err := db.sql.ExecContext(ctx, `UPDATE notifications
		SET status = 'sent', sent_at = ?, last_attempt_at = ?, last_error = ''
		WHERE id = ?`, fmtTime(at), fmtTime(at), id)
	if err != nil {
		return fmt.Errorf("store.MarkNotificationSent: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store.MarkNotificationSent: 通知 id=%d 不存在", id)
	}
	return nil
}

// MarkNotificationFailed 记录一次发送失败：attempts+1；
// attempts >= maxAttempts 时置 status=failed 并返回 final=true，否则保持 pending。
func (db *DB) MarkNotificationFailed(ctx context.Context, id int64, attemptErr string, maxAttempts int) (final bool, err error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("store.MarkNotificationFailed: 开启事务: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	var attempts int
	if err = tx.QueryRowContext(ctx,
		`SELECT attempts FROM notifications WHERE id = ?`, id).Scan(&attempts); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = fmt.Errorf("通知 id=%d 不存在", id)
		} else {
			err = fmt.Errorf("查询通知 id=%d: %w", id, err)
		}
		return false, err
	}
	attempts++
	status := "pending"
	if attempts >= maxAttempts {
		status = "failed"
		final = true
	}
	if _, err = tx.ExecContext(ctx, `UPDATE notifications
		SET attempts = ?, last_error = ?, last_attempt_at = ?, status = ?
		WHERE id = ?`, attempts, attemptErr, fmtTime(time.Now().UTC()), status, id); err != nil {
		return false, fmt.Errorf("store.MarkNotificationFailed: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return false, fmt.Errorf("store.MarkNotificationFailed: 提交: %w", err)
	}
	return final, nil
}

// NotificationStats 统计 since 之后创建的通知数（按状态分组）；
// since 为零值时统计全部。
func (db *DB) NotificationStats(ctx context.Context, since time.Time) (sent, pending, failed int, err error) {
	q := `SELECT
		COALESCE(SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0)
		FROM notifications`
	var args []any
	if !since.IsZero() {
		q += " WHERE created_at >= ?"
		args = append(args, fmtTime(since))
	}
	if err = db.sql.QueryRowContext(ctx, q, args...).Scan(&sent, &pending, &failed); err != nil {
		return 0, 0, 0, fmt.Errorf("store.NotificationStats: %w", err)
	}
	return sent, pending, failed, nil
}

// scanNotification 从一行扫描出 Notification。
func scanNotification(sc interface{ Scan(dest ...any) error }) (*Notification, error) {
	var (
		n                   Notification
		tags, lastErr       sql.NullString
		createdAt           string
		sentAt, lastAttempt sql.NullString
	)
	if err := sc.Scan(&n.ID, &n.DedupeKey, &n.Kind, &n.Topic, &n.Title, &n.Body,
		&n.Priority, &tags, &n.Status, &n.Attempts, &lastErr, &n.MergedCount,
		&createdAt, &sentAt, &lastAttempt); err != nil {
		return nil, err
	}
	n.Tags = tags.String
	n.LastError = lastErr.String
	var err error
	if n.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if n.SentAt, err = parseTimePtr(sentAt); err != nil {
		return nil, err
	}
	if n.LastAttemptAt, err = parseTimePtr(lastAttempt); err != nil {
		return nil, err
	}
	return &n, nil
}
