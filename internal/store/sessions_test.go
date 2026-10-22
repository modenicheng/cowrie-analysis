package store

import (
	"context"
	"testing"
	"time"
)

// sessionRow 是 sessions 表的展开视图，便于断言。
type sessionRow struct {
	srcIP              string
	startedAt, endedAt time.Time
	duration           float64
	loginAttempts      int
	loginSuccesses     int
	commandCount       int
	fileOps            int
}

func getSessionRow(t *testing.T, db *DB, sessionID string) sessionRow {
	t.Helper()
	var (
		r    sessionRow
		s, e string
	)
	err := db.SQL().QueryRow(`SELECT src_ip, started_at, ended_at, duration_s,
		login_attempts, login_successes, command_count, file_ops
		FROM sessions WHERE session_id = ?`, sessionID).
		Scan(&r.srcIP, &s, &e, &r.duration, &r.loginAttempts,
			&r.loginSuccesses, &r.commandCount, &r.fileOps)
	if err != nil {
		t.Fatalf("查询 session %s 失败: %v", sessionID, err)
	}
	if r.startedAt, err = parseTime(s); err != nil {
		t.Fatalf("解析 started_at 失败: %v", err)
	}
	if r.endedAt, err = parseTime(e); err != nil {
		t.Fatalf("解析 ended_at 失败: %v", err)
	}
	return r
}

// TestSessionAggregation：混合事件批后 sessions 聚合正确；
// 重复插入同批事件后计数不变（幂等）；无 session 的事件不产生会话行。
func TestSessionAggregation(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	evs := []*Event{
		mkEvent("cowrie.session.connect", at(0, 0), "s1", "203.0.113.7", `{"ev":1}`),
		mkEvent("cowrie.login.failed", at(0, 5), "s1", "203.0.113.7", `{"ev":2}`),
		mkEvent("cowrie.login.failed", at(0, 10), "s1", "203.0.113.7", `{"ev":3}`),
		mkEvent("cowrie.login.success", at(0, 15), "s1", "203.0.113.7", `{"ev":4}`),
		mkEvent("cowrie.command.input", at(1, 0), "s1", "203.0.113.7", `{"ev":5}`),
		mkEvent("cowrie.session.file_upload", at(2, 0), "s1", "203.0.113.7", `{"ev":6}`),
		{EventID: "cowrie.session.closed", EventTime: at(3, 0), Session: "s1",
			SrcIP: "203.0.113.7", DurationS: 180, Raw: `{"ev":7}`},
		// 无 session 的事件不参与聚合
		mkEvent("cowrie.login.failed", at(0, 20), "", "198.51.100.9", `{"ev":8}`),
	}
	inserted, dup, err := db.InsertEvents(ctx, evs)
	if err != nil {
		t.Fatalf("InsertEvents 失败: %v", err)
	}
	if inserted != 8 || dup != 0 {
		t.Fatalf("inserted=%d duplicates=%d, 期望 8/0", inserted, dup)
	}

	r := getSessionRow(t, db, "s1")
	if r.srcIP != "203.0.113.7" {
		t.Errorf("src_ip = %q, 期望 203.0.113.7", r.srcIP)
	}
	if !r.startedAt.Equal(at(0, 0)) {
		t.Errorf("started_at = %v, 期望 %v", r.startedAt, at(0, 0))
	}
	if !r.endedAt.Equal(at(3, 0)) {
		t.Errorf("ended_at = %v, 期望 %v", r.endedAt, at(3, 0))
	}
	if r.loginAttempts != 3 { // 2 failed + 1 success
		t.Errorf("login_attempts = %d, 期望 3", r.loginAttempts)
	}
	if r.loginSuccesses != 1 {
		t.Errorf("login_successes = %d, 期望 1", r.loginSuccesses)
	}
	if r.commandCount != 1 {
		t.Errorf("command_count = %d, 期望 1", r.commandCount)
	}
	if r.fileOps != 1 {
		t.Errorf("file_ops = %d, 期望 1", r.fileOps)
	}
	if r.duration != 180 {
		t.Errorf("duration_s = %v, 期望 180", r.duration)
	}

	// 幂等：重复插入同批事件，sessions 计数不变。
	inserted, dup, err = db.InsertEvents(ctx, evs)
	if err != nil {
		t.Fatalf("二次 InsertEvents 失败: %v", err)
	}
	if inserted != 0 || dup != 8 {
		t.Fatalf("重复批: inserted=%d duplicates=%d, 期望 0/8", inserted, dup)
	}
	r2 := getSessionRow(t, db, "s1")
	if r2.srcIP != r.srcIP || !r2.startedAt.Equal(r.startedAt) || !r2.endedAt.Equal(r.endedAt) ||
		r2.duration != r.duration || r2.loginAttempts != r.loginAttempts ||
		r2.loginSuccesses != r.loginSuccesses || r2.commandCount != r.commandCount ||
		r2.fileOps != r.fileOps {
		t.Errorf("重复插入后 session 聚合变化: %+v → %+v", r, r2)
	}
	if n := countRows(t, db, "sessions"); n != 1 {
		t.Errorf("sessions 行数 = %d, 期望 1（空 session 不建行）", n)
	}
}

// TestSessionAggregationCrossBatch：跨批合并取最早/最晚/最大时长，
// connect 事件的 src_ip 优先于先前非 connect 来源；file_download.failed 也计入 file_ops。
func TestSessionAggregationCrossBatch(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	batch1 := []*Event{
		mkEvent("cowrie.login.failed", at(0, 30), "s2", "198.51.100.9", `{"x":1}`),
		{EventID: "cowrie.session.closed", EventTime: at(1, 0), Session: "s2",
			DurationS: 10, Raw: `{"x":2}`},
	}
	if _, _, err := db.InsertEvents(ctx, batch1); err != nil {
		t.Fatalf("batch1 失败: %v", err)
	}
	r := getSessionRow(t, db, "s2")
	if r.srcIP != "198.51.100.9" {
		t.Fatalf("batch1 后 src_ip = %q, 期望 198.51.100.9", r.srcIP)
	}

	batch2 := []*Event{
		// connect 晚到但应成为 src_ip
		mkEvent("cowrie.session.connect", at(0, 0), "s2", "192.0.2.5", `{"x":3}`),
		mkEvent("cowrie.session.file_download.failed", at(0, 45), "s2", "192.0.2.5", `{"x":4}`),
		{EventID: "cowrie.session.closed", EventTime: at(1, 30), Session: "s2",
			DurationS: 30, Raw: `{"x":5}`},
	}
	if _, _, err := db.InsertEvents(ctx, batch2); err != nil {
		t.Fatalf("batch2 失败: %v", err)
	}
	r = getSessionRow(t, db, "s2")
	if r.srcIP != "192.0.2.5" {
		t.Errorf("batch2 后 src_ip = %q, 期望 connect 的 192.0.2.5", r.srcIP)
	}
	if !r.startedAt.Equal(at(0, 0)) {
		t.Errorf("started_at = %v, 期望跨批最早的 %v", r.startedAt, at(0, 0))
	}
	if !r.endedAt.Equal(at(1, 30)) {
		t.Errorf("ended_at = %v, 期望跨批最晚的 %v", r.endedAt, at(1, 30))
	}
	if r.duration != 30 {
		t.Errorf("duration_s = %v, 期望最大值 30", r.duration)
	}
	if r.loginAttempts != 1 || r.loginSuccesses != 0 {
		t.Errorf("login 计数错误: attempts=%d successes=%d, 期望 1/0", r.loginAttempts, r.loginSuccesses)
	}
	if r.fileOps != 1 {
		t.Errorf("file_ops = %d, 期望 1（download.failed 计入）", r.fileOps)
	}
	if n := countRows(t, db, "sessions"); n != 1 {
		t.Errorf("sessions 行数 = %d, 期望 1（upsert 不新增）", n)
	}
}
