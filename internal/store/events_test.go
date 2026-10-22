package store

import (
	"context"
	"testing"
	"time"
)

var testBase = time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)

func at(min, sec int) time.Time {
	return testBase.Add(time.Duration(min)*time.Minute + time.Duration(sec)*time.Second)
}

func mkEvent(eventID string, t time.Time, session, srcIP, raw string) *Event {
	return &Event{EventID: eventID, EventTime: t, SrcIP: srcIP, Session: session, Raw: raw}
}

func countRows(t *testing.T, db *DB, table string) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("统计 %s 行数失败: %v", table, err)
	}
	return n
}

// TestInsertEventsBasic：正常插入、字段落库、零批不报错。
func TestInsertEventsBasic(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	evs := []*Event{
		{
			EventID: "cowrie.session.connect", EventTime: at(0, 0),
			SrcIP: "203.0.113.7", SrcPort: 51234, Session: "s1",
			Username: "root", Command: "", DurationS: 0,
			Raw: `{"eventid":"cowrie.session.connect","session":"s1"}`,
		},
		{
			EventID: "cowrie.command.input", EventTime: at(1, 30),
			SrcIP: "203.0.113.7", Session: "s1", Command: "cat /etc/passwd",
			Raw: `{"eventid":"cowrie.command.input","session":"s1","input":"cat /etc/passwd"}`,
		},
	}
	inserted, dup, err := db.InsertEvents(ctx, evs)
	if err != nil {
		t.Fatalf("InsertEvents 失败: %v", err)
	}
	if inserted != 2 || dup != 0 {
		t.Fatalf("inserted=%d duplicates=%d, 期望 2/0", inserted, dup)
	}

	var evID, evTime, raw, cmd string
	var port int64
	if err := db.SQL().QueryRow(`SELECT event_id, event_time, src_port, command, raw
		FROM events WHERE session = 's1' AND event_id = 'cowrie.command.input'`).
		Scan(&evID, &evTime, &port, &cmd, &raw); err != nil {
		t.Fatalf("查询事件失败: %v", err)
	}
	if cmd != "cat /etc/passwd" || raw != evs[1].Raw || port != 0 {
		t.Errorf("落库字段不一致: cmd=%q raw=%q port=%d", cmd, raw, port)
	}
	if got, _ := parseTime(evTime); !got.Equal(at(1, 30)) {
		t.Errorf("event_time = %v, 期望 %v", got, at(1, 30))
	}

	if inserted, dup, err = db.InsertEvents(ctx, nil); err != nil || inserted != 0 || dup != 0 {
		t.Errorf("空批应返回 (0,0,nil), got (%d,%d,%v)", inserted, dup, err)
	}
}

// TestInsertEventsDuplicateRaw：同一批内与跨批的重复 raw 均计入 duplicates，
// 且不产生新行；字段相同但 raw 不同的正常入库。
func TestInsertEventsDuplicateRaw(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	a := mkEvent("cowrie.login.failed", at(0, 0), "s1", "198.51.100.9", `{"n":1}`)
	b := mkEvent("cowrie.login.failed", at(0, 0), "s1", "198.51.100.9", `{"n":1}`) // 与 a 同 raw
	c := mkEvent("cowrie.login.failed", at(0, 0), "s1", "198.51.100.9", `{"n":2}`) // 同字段不同 raw

	inserted, dup, err := db.InsertEvents(ctx, []*Event{a, b, c})
	if err != nil {
		t.Fatalf("InsertEvents 失败: %v", err)
	}
	if inserted != 2 || dup != 1 {
		t.Fatalf("批内去重: inserted=%d duplicates=%d, 期望 2/1", inserted, dup)
	}
	if n := countRows(t, db, "events"); n != 2 {
		t.Fatalf("events 行数 = %d, 期望 2", n)
	}

	// 跨批重复：全部为重复。
	inserted, dup, err = db.InsertEvents(ctx, []*Event{a, c})
	if err != nil {
		t.Fatalf("二次 InsertEvents 失败: %v", err)
	}
	if inserted != 0 || dup != 2 {
		t.Fatalf("跨批去重: inserted=%d duplicates=%d, 期望 0/2", inserted, dup)
	}
	if n := countRows(t, db, "events"); n != 2 {
		t.Fatalf("重复插入后 events 行数 = %d, 期望仍为 2", n)
	}
}

// TestCountEventsBoundaries：[Since, Until) 左闭右开——等于 Since 计入，
// 等于 Until 不计入；其余过滤条件与 Limit 无关性。
func TestCountEventsBoundaries(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	t0 := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	evs := []*Event{
		{EventID: "cowrie.session.connect", EventTime: t0, Session: "a", SrcIP: "1.1.1.1", Raw: `{"a":1}`},
		{EventID: "cowrie.login.failed", EventTime: t1, Session: "b", SrcIP: "2.2.2.2", Raw: `{"b":1}`},
		{EventID: "cowrie.login.failed", EventTime: t1, Session: "b", SrcIP: "2.2.2.2", Raw: `{"b":2}`},
	}
	if _, _, err := db.InsertEvents(ctx, evs); err != nil {
		t.Fatalf("InsertEvents 失败: %v", err)
	}

	cases := []struct {
		name   string
		filter EventFilter
		want   int
	}{
		{"Since 边界计入 / Until 边界排除", EventFilter{Since: t0, Until: t1}, 1},
		{"等于 Since 计入", EventFilter{Since: t1, Until: t1.Add(time.Hour)}, 2},
		{"等于 Until 排除", EventFilter{Since: t0.Add(-time.Hour), Until: t0}, 0},
		{"全窗口", EventFilter{Since: t0, Until: t1.Add(time.Hour)}, 3},
		{"SrcIP 过滤", EventFilter{Since: t0, Until: t1.Add(time.Hour), SrcIP: "2.2.2.2"}, 2},
		{"Session 过滤", EventFilter{Session: "a"}, 1},
		{"EventIDs 过滤", EventFilter{EventIDs: []string{"cowrie.login.failed"}}, 2},
		{"Limit 不影响计数", EventFilter{Limit: 1, CursorID: 0}, 3},
		{"无条件", EventFilter{}, 3},
	}
	for _, tc := range cases {
		got, err := db.CountEvents(ctx, tc.filter)
		if err != nil {
			t.Fatalf("%s: CountEvents 失败: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}
