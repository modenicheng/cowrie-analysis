package store

import (
	"context"
	"fmt"
	"time"
)

// CleanupStats 汇报一次保留清理各表删除的行数。CheckpointErr 非空表示
// 删除全部完成后执行 PRAGMA wal_checkpoint(TRUNCATE) 失败——不 fatal，
// 删除结果不受影响，下一轮清理会再次尝试截断 WAL。
type CleanupStats struct {
	Events        int // events 删除行数（含 raw 原文，磁盘大头）
	Sessions      int // sessions 删除行数
	ParseErrors   int // parse_errors 删除行数
	Gaps          int // collector_gaps 删除行数
	Notifications int // notifications 删除行数（仅 sent）
	CheckpointErr string
}

// cleanupBatchSize 是每批 DELETE 的行数上限：分批提交避免长事务长时间
// 持有写锁，阻塞 collector 的持续写入（跨进程共用同一 SQLite 文件）。
const cleanupBatchSize = 1000

// CleanupRetention 按服务侧入库时间清理超过保留期的数据（安全审查
// High#2：raw 原文无损入库 + sha256 去重对唯一内容无效，攻击者高频灌
// 唯一事件可持续耗尽磁盘、威胁同机其他服务）。
//
// 时间基准统一为服务侧入库/写入时间（collected_at / updated_at /
// recorded_at / sent_at|created_at），绝不用攻击者可影响的 event_time：
// 伪造任意时间戳的事件也只从其真正被采集入库那一刻起计算保留期。
// 截止时间 cutoff = 清理时刻 - retentionDays，判据为 列值 < cutoff。
//
// 清理对象与判据：
//   - events：         collected_at < cutoff（raw 是磁盘占用大头）
//   - sessions：       updated_at < cutoff（老会话；updated_at 在每次聚合
//     写入时刷新为服务侧当前时间，保留期内活跃过的会话不受影响。注意：
//     会话聚合计数是入库时的事实快照，删除老事件后保留的活跃会话计数
//     不回退，可接受）
//   - parse_errors：   recorded_at < cutoff
//   - collector_gaps： collected_at < cutoff（0002 新增的服务侧入库列）
//   - notifications：  status='sent' 且 COALESCE(sent_at, created_at) <
//     cutoff（sent_at 由 MarkNotificationSent 填服务侧时间，COALESCE 兜底）；
//     pending / failed（待补发、待重试）绝不删除
//
// 不清理：reports、analysis_runs、script_runs（报告与审计记录，量小、
// 按天/周增长，保留价值高）；collector_offsets、collector_health
// （采集运行态：删游标会导致整份日志重复采集，删健康行丢失探活状态）。
//
// retentionDays <= 0 表示禁用清理（保持旧行为），直接返回零值。
// 每张表按主键子查询 LIMIT 分批循环删除，直到该批不再删满；全部完成后
// 执行 PRAGMA wal_checkpoint(TRUNCATE) 回收 WAL 磁盘空间（collector 并发
// 持有读锁时 checkpoint 可能返回 busy=1 而 partial 成功，非错误）。
func (db *DB) CleanupRetention(ctx context.Context, retentionDays int) (CleanupStats, error) {
	if retentionDays <= 0 {
		return CleanupStats{}, nil
	}
	cutoff := fmtTime(time.Now().UTC().AddDate(0, 0, -retentionDays))

	var stats CleanupStats
	type step struct {
		name string
		stmt string
		set  func(n int)
	}
	for _, s := range []step{
		{"events", `DELETE FROM events WHERE id IN
			(SELECT id FROM events WHERE collected_at < ? LIMIT ?)`,
			func(n int) { stats.Events = n }},
		{"sessions", `DELETE FROM sessions WHERE session_id IN
			(SELECT session_id FROM sessions WHERE updated_at < ? LIMIT ?)`,
			func(n int) { stats.Sessions = n }},
		{"parse_errors", `DELETE FROM parse_errors WHERE id IN
			(SELECT id FROM parse_errors WHERE recorded_at < ? LIMIT ?)`,
			func(n int) { stats.ParseErrors = n }},
		{"collector_gaps", `DELETE FROM collector_gaps WHERE id IN
			(SELECT id FROM collector_gaps WHERE collected_at < ? LIMIT ?)`,
			func(n int) { stats.Gaps = n }},
		{"notifications", `DELETE FROM notifications WHERE id IN
			(SELECT id FROM notifications
			 WHERE status = 'sent' AND COALESCE(sent_at, created_at) < ? LIMIT ?)`,
			func(n int) { stats.Notifications = n }},
	} {
		n, err := db.deleteBatched(ctx, s.stmt, cutoff)
		if err != nil {
			return stats, fmt.Errorf("store.CleanupRetention: 清理 %s 失败: %w", s.name, err)
		}
		s.set(n)
	}

	// 回收 WAL 空间：删除只是把页标记为可复用，WAL 文件不缩小；
	// TRUNCATE 截断把 WAL 缩回 0。失败不 fatal（如 collector 正持读锁导致
	// busy），记录后由调用方决定是否告警，下一轮清理重试。
	var busy, log, checkpointed int
	if err := db.sql.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).
		Scan(&busy, &log, &checkpointed); err != nil {
		stats.CheckpointErr = err.Error()
	}
	return stats, nil
}

// deleteBatched 循环执行 stmt 直到某批删除数小于 batchSize（说明已删完），
// 返回累计删除行数。stmt 必须恰好携带两个占位符：时间截止值与批大小，
// 且子查询必须按稳定的窄谓词（时间列）选出主键，保证每批删除推进。
func (db *DB) deleteBatched(ctx context.Context, stmt, cutoff string) (int, error) {
	total := 0
	for {
		res, err := db.sql.ExecContext(ctx, stmt, cutoff, cleanupBatchSize)
		if err != nil {
			return total, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, err
		}
		total += int(n)
		if int(n) < cleanupBatchSize {
			return total, nil
		}
	}
}
