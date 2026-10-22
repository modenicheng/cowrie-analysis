// Package query 提供面向分析层的只读事件查询与确定性统计。
//
// 本包不拥有数据：所有读取通过 store.DB 的公开 API 或 db.SQL() 完成，
// 绝不写入。时间窗口语义与 store 一致：[Since, Until) 左闭右开；
// event_time 列为 UTC RFC3339Nano 文本，SQL 中按字符串比较（与
// store.CountEvents 的语义保持一致，保证 QueryEvents/CountEvents 可对账）。
package query

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/modenc/e3-security-analyst/internal/store"
)

// defaultEventLimit 是 EventFilter.Limit <= 0 时 QueryEvents 使用的默认上限。
// 正常调用方（tools 层）会自行钳制 Limit，这里只兜底防止无界查询。
const defaultEventLimit = 1000

// fmtTime 与 store 的时间列存储格式保持一致（UTC RFC3339Nano 文本）。
// 复制自 store 的私有实现：query 包只能依赖 store 公开 API，无法引用。
func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// parseTimeCol 解析时间列文本（NOT NULL 列，空串视为零时间）。
func parseTimeCol(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("解析时间文本 %q: %w", s, err)
	}
	return t, nil
}

// QueryEvents 按过滤条件返回事件（id 升序，最多 Limit 条）。
// f.Limit <= 0 时使用 defaultEventLimit；f.CursorID > 0 时只返回 id 更大的
// 事件，供分页游标使用。字段从 events 行无损还原，Raw 保留原始 JSON。
func QueryEvents(ctx context.Context, db *store.DB, f store.EventFilter) ([]*store.Event, error) {
	if db == nil {
		return nil, fmt.Errorf("query.QueryEvents: db 为 nil")
	}
	limit := f.Limit
	if limit <= 0 {
		limit = defaultEventLimit
	}
	where, args := eventWhere(f)
	q := `SELECT id, event_id, event_time, collected_at, src_ip, src_port, session,
		username, command, filename, shasum, duration_s, raw
		FROM events` + where + ` ORDER BY id ASC LIMIT ?`
	args = append(args, limit)

	rows, err := db.SQL().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query.QueryEvents: 查询失败: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]*store.Event, 0, limit)
	for rows.Next() {
		var (
			e                         store.Event
			eventTime, collectedAt    string
			srcIP, session, username  sql.NullString
			command, filename, shasum sql.NullString
			srcPort                   sql.NullInt64
			duration                  sql.NullFloat64
		)
		if err := rows.Scan(&e.ID, &e.EventID, &eventTime, &collectedAt,
			&srcIP, &srcPort, &session, &username, &command,
			&filename, &shasum, &duration, &e.Raw); err != nil {
			return nil, fmt.Errorf("query.QueryEvents: 读取行失败: %w", err)
		}
		if e.EventTime, err = parseTimeCol(eventTime); err != nil {
			return nil, fmt.Errorf("query.QueryEvents: %w", err)
		}
		if e.CollectedAt, err = parseTimeCol(collectedAt); err != nil {
			return nil, fmt.Errorf("query.QueryEvents: %w", err)
		}
		e.SrcIP, e.SrcPort = srcIP.String, srcPort.Int64
		e.Session, e.Username = session.String, username.String
		e.Command, e.Filename, e.Shasum = command.String, filename.String, shasum.String
		e.DurationS = duration.Float64
		out = append(out, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("query.QueryEvents: 遍历结果失败: %w", err)
	}
	return out, nil
}

// CountEvents 转发 store 的计数查询（Limit/CursorID 不影响计数）。
func CountEvents(ctx context.Context, db *store.DB, f store.EventFilter) (int, error) {
	if db == nil {
		return 0, fmt.Errorf("query.CountEvents: db 为 nil")
	}
	return db.CountEvents(ctx, f)
}

// eventWhere 组装与 store.CountEvents 完全一致的 WHERE 子句与参数，
// 额外附加 id > CursorID 分页条件（仅当 CursorID > 0）。
// 时间条件沿用时间列的文本比较，保证与 CountEvents 语义对齐。
func eventWhere(f store.EventFilter) (string, []any) {
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
	if f.CursorID > 0 {
		conds = append(conds, "id > ?")
		args = append(args, f.CursorID)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}
