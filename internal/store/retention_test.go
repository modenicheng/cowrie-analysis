package store

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"testing/fstest"
	"time"

	"github.com/modenc/e3-security-analyst/migrations"
)

// ageRows 把 table 中主键为 id 的行（sessions 表按 session_id）的时间列
// 统一改写为指定时刻——模拟"入库已久"的存量数据。
func ageRows(t *testing.T, db *DB, table, col string, at time.Time, ids ...any) {
	t.Helper()
	for _, id := range ids {
		var q string
		if table == "sessions" {
			q = "UPDATE sessions SET " + col + " = ? WHERE session_id = ?"
		} else {
			q = "UPDATE " + table + " SET " + col + " = ? WHERE id = ?"
		}
		if _, err := db.SQL().Exec(q, fmtTime(at), id); err != nil {
			t.Fatalf("老化 %s.%s 失败: %v", table, col, err)
		}
	}
}

// TestCleanupRetentionPerTable：各表按服务侧入库时间"老删新留"；
// notifications 只删 sent，pending/failed 即使过期也保留；
// WAL checkpoint 正常执行（CheckpointErr 为空）。
func TestCleanupRetentionPerTable(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.Add(-40 * 24 * time.Hour) // 40 天前：超过 30 天保留期
	fresh := now.Add(-1 * 24 * time.Hour)

	// events：老/新各一条（collected_at 为服务侧入库时间）。
	oldEv := mkEvent("cowrie.login.failed", old, "sold", "198.51.100.1", `{"old":1}`)
	oldEv.CollectedAt = old
	newEv := mkEvent("cowrie.login.failed", fresh, "snew", "198.51.100.2", `{"new":1}`)
	newEv.CollectedAt = fresh
	if _, _, err := db.InsertEvents(ctx, []*Event{oldEv, newEv}); err != nil {
		t.Fatalf("InsertEvents 失败: %v", err)
	}
	// sessions：两行入库时 updated_at=now，手动把 sold 老化，snew 保持新鲜。
	ageRows(t, db, "sessions", "updated_at", old, "sold")

	// parse_errors：recorded_at 老/新各一。
	if err := db.InsertParseError(ctx, &ParseErrorRecord{
		FilePath: "a.json", FileOffset: 1, Raw: "bad-old", Err: "x", At: old}); err != nil {
		t.Fatalf("InsertParseError(old) 失败: %v", err)
	}
	if err := db.InsertParseError(ctx, &ParseErrorRecord{
		FilePath: "a.json", FileOffset: 2, Raw: "bad-new", Err: "x", At: fresh}); err != nil {
		t.Fatalf("InsertParseError(new) 失败: %v", err)
	}

	// collector_gaps：AddGap 填 now，再把其中一行老化。
	if err := db.AddGap(ctx, old, old.Add(time.Hour), "old gap"); err != nil {
		t.Fatalf("AddGap(old) 失败: %v", err)
	}
	if err := db.AddGap(ctx, fresh, fresh.Add(time.Hour), "new gap"); err != nil {
		t.Fatalf("AddGap(new) 失败: %v", err)
	}
	var gapIDs []int64
	rows, err := db.SQL().Query(`SELECT id FROM collector_gaps ORDER BY id`)
	if err != nil {
		t.Fatalf("查询 gaps 失败: %v", err)
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("扫描 gap id 失败: %v", err)
		}
		gapIDs = append(gapIDs, id)
	}
	_ = rows.Close()
	if len(gapIDs) != 2 {
		t.Fatalf("gaps 行数 = %d, 期望 2", len(gapIDs))
	}
	ageRows(t, db, "collector_gaps", "collected_at", old, gapIDs[0])
	ageRows(t, db, "collector_gaps", "collected_at", fresh, gapIDs[1])

	// notifications：sent 老（删）、sent 新（留）、pending 老（留）、failed 老（留）。
	mkNotif := func(key, status string, createdAt, sentAt time.Time) {
		n := &Notification{
			DedupeKey: key, Kind: "alert.login_success", Topic: "t",
			Title: key, Body: "b", Status: status, CreatedAt: createdAt,
		}
		if !sentAt.IsZero() {
			n.SentAt = &sentAt
		}
		if _, err := db.EnqueueNotification(ctx, n); err != nil {
			t.Fatalf("EnqueueNotification(%s) 失败: %v", key, err)
		}
	}
	mkNotif("sent-old", "sent", old, old)
	mkNotif("sent-new", "sent", fresh, fresh)
	mkNotif("pending-old", "pending", old, time.Time{})
	mkNotif("failed-old", "failed", old, time.Time{})

	stats, err := db.CleanupRetention(ctx, 30)
	if err != nil {
		t.Fatalf("CleanupRetention 失败: %v", err)
	}
	if stats.Events != 1 || stats.Sessions != 1 || stats.ParseErrors != 1 ||
		stats.Gaps != 1 || stats.Notifications != 1 {
		t.Fatalf("stats = %+v, 期望各表均 1", stats)
	}
	if stats.CheckpointErr != "" {
		t.Errorf("WAL checkpoint 不应报错: %q", stats.CheckpointErr)
	}
	if n := countRows(t, db, "events"); n != 1 {
		t.Errorf("events 剩 %d 行, 期望 1（新事件）", n)
	}
	var raw string
	if err := db.SQL().QueryRow(`SELECT raw FROM events`).Scan(&raw); err != nil || raw != `{"new":1}` {
		t.Errorf("留存事件应为新事件, got %q err=%v", raw, err)
	}
	if n := countRows(t, db, "sessions"); n != 1 {
		t.Errorf("sessions 剩 %d 行, 期望 1（活跃会话）", n)
	}
	var sid string
	if err := db.SQL().QueryRow(`SELECT session_id FROM sessions`).Scan(&sid); err != nil || sid != "snew" {
		t.Errorf("留存会话应为 snew, got %q err=%v", sid, err)
	}
	if n := countRows(t, db, "parse_errors"); n != 1 {
		t.Errorf("parse_errors 剩 %d 行, 期望 1", n)
	}
	if n := countRows(t, db, "collector_gaps"); n != 1 {
		t.Errorf("collector_gaps 剩 %d 行, 期望 1", n)
	}
	if n := countRows(t, db, "notifications"); n != 3 {
		t.Errorf("notifications 剩 %d 行, 期望 3（sent-new/pending-old/failed-old）", n)
	}
	for _, key := range []string{"sent-new", "pending-old", "failed-old"} {
		var n int
		if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM notifications WHERE dedupe_key=?`,
			key).Scan(&n); err != nil || n != 1 {
			t.Errorf("通知 %s 应保留, got %d 行 err=%v", key, n, err)
		}
	}
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM notifications WHERE dedupe_key='sent-old'`).
		Scan(&n); err != nil || n != 0 {
		t.Errorf("已发送且过期的 sent-old 应被删除, got %d 行 err=%v", n, err)
	}

	// 幂等：重复执行不再删除任何行。
	stats2, err := db.CleanupRetention(ctx, 30)
	if err != nil {
		t.Fatalf("重复 CleanupRetention 失败: %v", err)
	}
	if stats2.Events != 0 || stats2.Sessions != 0 || stats2.ParseErrors != 0 ||
		stats2.Gaps != 0 || stats2.Notifications != 0 {
		t.Errorf("重复执行应删 0 行, got %+v", stats2)
	}
}

// TestCleanupRetentionZeroDisabled：retentionDays=0 与负值都是禁用清理，
// 过期数据一律不动、返回零值。
func TestCleanupRetentionZeroDisabled(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	old := time.Now().UTC().Add(-365 * 24 * time.Hour)
	ev := mkEvent("cowrie.login.failed", old, "s1", "198.51.100.1", `{"old":1}`)
	ev.CollectedAt = old
	if _, _, err := db.InsertEvents(ctx, []*Event{ev}); err != nil {
		t.Fatalf("InsertEvents 失败: %v", err)
	}
	if err := db.InsertParseError(ctx, &ParseErrorRecord{
		FilePath: "a.json", FileOffset: 1, Raw: "bad", Err: "x", At: old}); err != nil {
		t.Fatalf("InsertParseError 失败: %v", err)
	}
	n := &Notification{DedupeKey: "k", Kind: "k", Topic: "t", Title: "t",
		Body: "b", Status: "sent", CreatedAt: old, SentAt: &old}
	if _, err := db.EnqueueNotification(ctx, n); err != nil {
		t.Fatalf("EnqueueNotification 失败: %v", err)
	}
	if err := db.AddGap(ctx, old, old.Add(time.Hour), "disabled-era gap"); err != nil {
		t.Fatalf("AddGap 失败: %v", err)
	}

	for _, days := range []int{0, -1} {
		stats, err := db.CleanupRetention(ctx, days)
		if err != nil {
			t.Fatalf("CleanupRetention(%d) 失败: %v", days, err)
		}
		if stats != (CleanupStats{}) {
			t.Errorf("retentionDays=%d 应返回零值 stats, got %+v", days, stats)
		}
	}
	for _, table := range []string{"events", "sessions", "parse_errors", "collector_gaps", "notifications"} {
		if got := countRows(t, db, table); got == 0 {
			t.Errorf("禁用清理时 %s 不应有行被删（查询异常或表空）", table)
		}
	}
}

// TestCleanupRetentionBatching：超过单批上限（1000 行）的事件分批循环删完，
// 新数据保留。
func TestCleanupRetentionBatching(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	const oldCount = cleanupBatchSize + 500 // 1500：至少两批
	evs := make([]*Event, 0, oldCount+2)
	for i := 0; i < oldCount; i++ {
		ev := mkEvent("cowrie.login.failed", now, "", "198.51.100.1",
			`{"flood":`+strconv.Itoa(i)+`}`)
		ev.CollectedAt = now.Add(-90 * 24 * time.Hour)
		evs = append(evs, ev)
	}
	for i := 0; i < 2; i++ { // 新数据：应保留
		ev := mkEvent("cowrie.login.failed", now, "", "198.51.100.2",
			`{"fresh":`+strconv.Itoa(i)+`}`)
		ev.CollectedAt = now
		evs = append(evs, ev)
	}
	if _, _, err := db.InsertEvents(ctx, evs); err != nil {
		t.Fatalf("InsertEvents 失败: %v", err)
	}

	stats, err := db.CleanupRetention(ctx, 30)
	if err != nil {
		t.Fatalf("CleanupRetention 失败: %v", err)
	}
	if stats.Events != oldCount {
		t.Errorf("stats.Events = %d, 期望 %d（分批循环必须删完）", stats.Events, oldCount)
	}
	if n := countRows(t, db, "events"); n != 2 {
		t.Errorf("events 剩 %d 行, 期望 2", n)
	}
}

// TestMigrate0002UpgradeBackfillsGaps：0001 旧库升级到 0002 时，
// 既有 gap 行的 collected_at 被回填为迁移时刻（非空、可解析、不早于插入），
// 清理索引建立；升级后 AddGap 写入 RFC3339Nano 的服务侧时间。
func TestMigrate0002UpgradeBackfillsGaps(t *testing.T) {
	initSQL, err := os.ReadFile(filepath.Join("..", "..", "migrations", "0001_init.sql"))
	if err != nil {
		t.Fatalf("读取 0001_init.sql 失败: %v", err)
	}
	path := filepath.Join(t.TempDir(), "events.db")
	db, err := Open(path, Options{WAL: true, BusyTimeoutMs: 1500})
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	defer func() { _ = db.Close() }()
	// 先只应用 0001，构造存量 gap 行（无 collected_at 列）。
	if err := db.Migrate(fstest.MapFS{
		"0001_init.sql": &fstest.MapFile{Data: initSQL},
	}); err != nil {
		t.Fatalf("Migrate(0001) 失败: %v", err)
	}
	before := time.Now().UTC()
	if _, err := db.sql.Exec(`INSERT INTO collector_gaps(gap_start, gap_end, reason)
		VALUES('2026-01-01T00:00:00Z','2026-01-01T01:00:00Z','legacy')`); err != nil {
		t.Fatalf("插入存量 gap 失败: %v", err)
	}

	// 升级到 0002。
	if err := db.Migrate(migrations.FS); err != nil {
		t.Fatalf("Migrate(0002) 失败: %v", err)
	}
	var collected string
	if err := db.sql.QueryRow(`SELECT collected_at FROM collector_gaps`).Scan(&collected); err != nil {
		t.Fatalf("查询回填 collected_at 失败: %v", err)
	}
	got, err := parseTime(collected)
	if err != nil {
		t.Fatalf("回填值 %q 不是合法 RFC3339 时间: %v", collected, err)
	}
	// 回填值由 strftime %f 生成（毫秒精度），与 before 比较前截断到毫秒。
	if got.Before(before.Truncate(time.Millisecond)) {
		t.Errorf("回填值 %v 应为迁移执行时刻（不早于升级开始 %v）", got, before)
	}

	// 升级后 AddGap 显式写入服务侧 collected_at（RFC3339Nano 风格）。
	if err := db.AddGap(context.Background(), before, before.Add(time.Minute), "post"); err != nil {
		t.Fatalf("AddGap 失败: %v", err)
	}
	var post string
	if err := db.sql.QueryRow(`SELECT collected_at FROM collector_gaps
		WHERE reason = 'post'`).Scan(&post); err != nil {
		t.Fatalf("查询新 gap 失败: %v", err)
	}
	if post == "" {
		t.Error("AddGap 应写入 collected_at，得到空串")
	}

	// 清理索引存在（含 notifications 的 sent 部分索引）。
	for _, idx := range []string{"idx_events_collected_at", "idx_sessions_updated_at", "idx_notifications_sent_at"} {
		var n int
		if err := db.sql.QueryRow(
			`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, idx).Scan(&n); err != nil || n != 1 {
			t.Errorf("索引 %s 应存在, got %d err=%v", idx, n, err)
		}
	}
}
