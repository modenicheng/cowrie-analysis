package query

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/modenc/e3-security-analyst/internal/cowrie"
	"github.com/modenc/e3-security-analyst/internal/store"
	"github.com/modenc/e3-security-analyst/migrations"
)

// openTestDB 在临时目录中打开并迁移一个全新数据库。
func openTestDB(t *testing.T) *store.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "query.db") // 子目录测试自动建目录
	db, err := store.Open(path, store.Options{WAL: true, BusyTimeoutMs: 2000})
	if err != nil {
		t.Fatalf("store.Open 失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(migrations.FS); err != nil {
		t.Fatalf("Migrate 失败: %v", err)
	}
	return db
}

// rawSeq 保证每个构造的事件 raw 唯一（InsertEvents 按 raw 哈希去重）。
var rawSeq int

// ev 构造一个事件骨架，字段可在调用处覆写。
func ev(eventID string, at time.Time) *store.Event {
	rawSeq++
	return &store.Event{
		EventID:   eventID,
		EventTime: at,
		SrcIP:     "203.0.113.1",
		Session:   "sess",
		Raw:       fmt.Sprintf(`{"eventid":%q,"seq":%d}`, eventID, rawSeq),
	}
}

// mustInsert 写入种子事件，失败即终止测试。
func mustInsert(t *testing.T, db *store.DB, evs ...*store.Event) {
	t.Helper()
	if _, _, err := db.InsertEvents(context.Background(), evs); err != nil {
		t.Fatalf("InsertEvents 失败: %v", err)
	}
}

// withIP 覆写来源 IP（链式构造种子数据用）。
func withIP(e *store.Event, ip string) *store.Event { e.SrcIP = ip; return e }

// withSession 覆写会话 ID。
func withSession(e *store.Event, s string) *store.Event { e.Session = s; return e }

// TestQueryEventsWindowBoundaries：[Since, Until) 左闭右开——等于 Since 计入，
// 等于 Until 不计入；QueryEvents 与 CountEvents 口径一致。
func TestQueryEventsWindowBoundaries(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	w0 := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	w1 := w0.Add(24 * time.Hour)

	mustInsert(t, db,
		ev(cowrie.EventLoginFailed, w0),                   // == Since：计入
		ev(cowrie.EventLoginFailed, w0.Add(12*time.Hour)), // 窗口内
		ev(cowrie.EventLoginFailed, w1),                   // == Until：排除
		ev(cowrie.EventLoginFailed, w1.Add(time.Second)),  // 窗口外
	)

	f := store.EventFilter{Since: w0, Until: w1}
	got, err := QueryEvents(ctx, db, f)
	if err != nil {
		t.Fatalf("QueryEvents 失败: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("QueryEvents 返回 %d 条, 期望 2", len(got))
	}
	if !got[0].EventTime.Equal(w0) {
		t.Errorf("首条事件时间 = %v, 期望等于 Since %v", got[0].EventTime, w0)
	}
	if got[0].ID >= got[1].ID {
		t.Errorf("结果未按 id 升序: %d >= %d", got[0].ID, got[1].ID)
	}
	n, err := CountEvents(ctx, db, f)
	if err != nil {
		t.Fatalf("CountEvents 失败: %v", err)
	}
	if n != len(got) {
		t.Errorf("CountEvents=%d 与 QueryEvents=%d 不一致", n, len(got))
	}
}

// TestQueryEventsFieldFidelity：事件字段从 events 行无损还原。
func TestQueryEventsFieldFidelity(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 21, 9, 30, 0, 0, time.UTC)

	src := ev(cowrie.EventCommandInput, at)
	src.SrcPort = 51234
	src.Username = "root"
	src.Command = "cat /etc/passwd"
	src.Filename = "kworker.sh"
	src.Shasum = "deadbeefcafe"
	src.DurationS = 12.5
	mustInsert(t, db, src)

	got, err := QueryEvents(ctx, db, store.EventFilter{Since: at.Add(-time.Minute), Until: at.Add(time.Minute)})
	if err != nil {
		t.Fatalf("QueryEvents 失败: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("返回 %d 条, 期望 1", len(got))
	}
	e := got[0]
	if e.EventID != src.EventID || !e.EventTime.Equal(at) || e.CollectedAt.IsZero() ||
		e.SrcIP != src.SrcIP || e.SrcPort != src.SrcPort || e.Session != src.Session ||
		e.Username != src.Username || e.Command != src.Command ||
		e.Filename != src.Filename || e.Shasum != src.Shasum ||
		e.DurationS != src.DurationS || e.Raw != src.Raw || e.ID == 0 {
		t.Errorf("字段往返不一致:\ngot  %+v\nwant %+v", *e, *src)
	}
}

// TestQueryEventsPaginationCursor：CursorID（id 升序）+ Limit 分页语义正确，
// 翻页总数与 CountEvents 一致。
func TestQueryEventsPaginationCursor(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)

	var seed []*store.Event
	for i := 0; i < 5; i++ {
		e := ev(cowrie.EventCommandInput, base.Add(time.Duration(i)*time.Minute))
		e.Command = fmt.Sprintf("cmd%d", i)
		seed = append(seed, e)
	}
	mustInsert(t, db, seed...)

	f := store.EventFilter{Since: base, Until: base.Add(time.Hour)}
	total, err := CountEvents(ctx, db, f)
	if err != nil {
		t.Fatalf("CountEvents 失败: %v", err)
	}
	if total != 5 {
		t.Fatalf("CountEvents=%d, 期望 5", total)
	}

	var ids []int64
	var commands []string
	var cursor int64
	pages := 0
	for {
		page, err := QueryEvents(ctx, db, store.EventFilter{
			Since: base, Until: base.Add(time.Hour), Limit: 2, CursorID: cursor,
		})
		if err != nil {
			t.Fatalf("QueryEvents 第 %d 页失败: %v", pages+1, err)
		}
		if len(page) == 0 {
			break
		}
		if len(page) > 2 {
			t.Fatalf("第 %d 页返回 %d 条, 超过 Limit 2", pages+1, len(page))
		}
		pages++
		for _, e := range page {
			ids = append(ids, e.ID)
			commands = append(commands, e.Command)
		}
		cursor = page[len(page)-1].ID
	}
	if pages != 3 { // 2 + 2 + 1
		t.Errorf("翻页页数 = %d, 期望 3", pages)
	}
	if len(ids) != 5 {
		t.Fatalf("翻页累计 %d 条, 期望 5（与 CountEvents 一致）", len(ids))
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			t.Errorf("翻页结果 id 非严格升序: %v", ids)
			break
		}
	}
	for i, want := range []string{"cmd0", "cmd1", "cmd2", "cmd3", "cmd4"} {
		if commands[i] != want {
			t.Errorf("第 %d 条命令 = %q, 期望 %q", i, commands[i], want)
		}
	}

	// 过滤条件组合：EventIDs + SrcIP。
	n, err := CountEvents(ctx, db, store.EventFilter{
		Since: base, Until: base.Add(time.Hour),
		EventIDs: []string{cowrie.EventCommandInput}, SrcIP: "203.0.113.1",
	})
	if err != nil {
		t.Fatalf("CountEvents 过滤失败: %v", err)
	}
	if n != 5 {
		t.Errorf("EventIDs+SrcIP 过滤计数 = %d, 期望 5", n)
	}
	one, err := QueryEvents(ctx, db, store.EventFilter{SrcIP: "203.0.113.1", Limit: 1})
	if err != nil || len(one) != 1 {
		t.Errorf("Limit=1 查询: got %d 条, err=%v, 期望 1 条", len(one), err)
	} else if one[0].Command != "cmd0" {
		t.Errorf("Limit=1 首条命令 = %q, 期望 cmd0", one[0].Command)
	}
}

// TestQueryEventsNilDB：nil DB 返回错误而非 panic。
func TestQueryEventsNilDB(t *testing.T) {
	if _, err := QueryEvents(context.Background(), nil, store.EventFilter{}); err == nil {
		t.Error("QueryEvents(nil) 应返回错误")
	}
	if _, err := CountEvents(context.Background(), nil, store.EventFilter{}); err == nil {
		t.Error("CountEvents(nil) 应返回错误")
	}
	if _, err := ComputeStats(context.Background(), nil, StatsQuery{}); err == nil {
		t.Error("ComputeStats(nil) 应返回错误")
	}
}
