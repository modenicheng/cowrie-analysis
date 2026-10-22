package store

import (
	"context"
	"testing"
	"time"
)

// TestOffsetRoundTrip：SetOffset/GetOffset/ListOffsets 读写往返；
// 不存在的 fileKey 返回 (nil, nil)。
func TestOffsetRoundTrip(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	if o, err := db.GetOffset(ctx, "missing"); err != nil || o != nil {
		t.Fatalf("GetOffset 不存在: got (%v, %v), 期望 (nil, nil)", o, err)
	}

	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	o1 := &Offset{
		FileKey: "8:12345", Path: "/var/log/cowrie/cowrie.json",
		Inode: 12345, Offset: 4096, FileSize: 8192, MtimeNS: 1729501200000000000,
		UpdatedAt: now,
	}
	if err := db.SetOffset(ctx, o1); err != nil {
		t.Fatalf("SetOffset 失败: %v", err)
	}
	o2 := &Offset{FileKey: "8:67890", Path: "/var/log/cowrie/cowrie.json.1", Inode: 67890, Offset: 512}
	if err := db.SetOffset(ctx, o2); err != nil {
		t.Fatalf("SetOffset 失败: %v", err)
	}

	got, err := db.GetOffset(ctx, "8:12345")
	if err != nil {
		t.Fatalf("GetOffset 失败: %v", err)
	}
	if *got != *o1 {
		t.Errorf("offset 往返不一致: got %+v want %+v", *got, *o1)
	}

	// 更新既有游标。
	o1.Offset = 9999
	if err := db.SetOffset(ctx, o1); err != nil {
		t.Fatalf("更新 SetOffset 失败: %v", err)
	}
	list, err := db.ListOffsets(ctx)
	if err != nil {
		t.Fatalf("ListOffsets 失败: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("ListOffsets 返回 %d 条, 期望 2", len(list))
	}
	if list[0].FileKey != "8:12345" || list[0].Offset != 9999 {
		t.Errorf("更新后的游标不正确: %+v", *list[0])
	}
}

// TestHealthRoundTrip：UpdateHealth/GetHealth 往返，含 nil 时间指针；
// 未写入时 GetHealth 返回 (nil, nil)。
func TestHealthRoundTrip(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	if h, err := db.GetHealth(ctx); err != nil || h != nil {
		t.Fatalf("空库 GetHealth: got (%v, %v), 期望 (nil, nil)", h, err)
	}

	readAt := time.Date(2026, 10, 21, 9, 1, 0, 0, time.UTC)
	h1 := &Health{LastReadAt: &readAt, LastError: "", UpdatedAt: readAt}
	if err := db.UpdateHealth(ctx, h1); err != nil {
		t.Fatalf("UpdateHealth 失败: %v", err)
	}
	got, err := db.GetHealth(ctx)
	if err != nil {
		t.Fatalf("GetHealth 失败: %v", err)
	}
	if got.LastReadAt == nil || !got.LastReadAt.Equal(readAt) {
		t.Errorf("LastReadAt = %v, 期望 %v", got.LastReadAt, readAt)
	}
	if got.LastEventAt != nil {
		t.Errorf("LastEventAt 应为 nil, got %v", got.LastEventAt)
	}

	// 更新：补 LastEventAt 与错误信息。
	eventAt := readAt.Add(time.Minute)
	h2 := &Health{LastReadAt: &readAt, LastEventAt: &eventAt, LastError: "boom", UpdatedAt: eventAt}
	if err := db.UpdateHealth(ctx, h2); err != nil {
		t.Fatalf("二次 UpdateHealth 失败: %v", err)
	}
	got, err = db.GetHealth(ctx)
	if err != nil {
		t.Fatalf("GetHealth 失败: %v", err)
	}
	if got.LastEventAt == nil || !got.LastEventAt.Equal(eventAt) {
		t.Errorf("LastEventAt = %v, 期望 %v", got.LastEventAt, eventAt)
	}
	if got.LastError != "boom" {
		t.Errorf("LastError = %q, 期望 boom", got.LastError)
	}
	if got.LastReadAt == nil || !got.LastReadAt.Equal(readAt) {
		t.Errorf("LastReadAt 被覆盖: %v", got.LastReadAt)
	}
	if n := countRows(t, db, "collector_health"); n != 1 {
		t.Errorf("collector_health 行数 = %d, 期望单行 1", n)
	}
}

// TestGapsInRange：AddGap + GapsInRange 的区间交集语义。
func TestGapsInRange(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	g0 := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	g1 := g0.Add(time.Hour)
	if err := db.AddGap(ctx, g0, g1, "file missing"); err != nil {
		t.Fatalf("AddGap 失败: %v", err)
	}
	g2 := g0.Add(24 * time.Hour)
	if err := db.AddGap(ctx, g2, g2.Add(30*time.Minute), "db busy"); err != nil {
		t.Fatalf("AddGap 失败: %v", err)
	}

	cases := []struct {
		name         string
		since, until time.Time
		want         int
	}{
		{"完全包含第一个", g0.Add(-time.Hour), g1.Add(time.Hour), 1},
		{"部分重叠", g0.Add(30 * time.Minute), g1.Add(time.Hour), 1},
		{"右边界恰不重叠", g1, g1.Add(time.Hour), 0}, // gap_end > since 为假
		{"左边界恰不重叠", g0.Add(-2 * time.Hour), g0, 0},
		{"跨两个缺口", g0, g2.Add(time.Hour), 2},
	}
	for _, tc := range cases {
		gaps, err := db.GapsInRange(ctx, tc.since, tc.until)
		if err != nil {
			t.Fatalf("%s: GapsInRange 失败: %v", tc.name, err)
		}
		if len(gaps) != tc.want {
			t.Errorf("%s: got %d 个缺口, want %d", tc.name, len(gaps), tc.want)
		}
	}
	all, err := db.GapsInRange(ctx, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("无界 GapsInRange 失败: %v", err)
	}
	if len(all) != 2 || all[0].ID == 0 || !all[0].Start.Equal(g0) || all[0].Reason != "file missing" {
		t.Errorf("无界查询结果不正确: %+v", all)
	}
}

// TestParseErrors：InsertParseError + CountParseErrors 时间窗口往返。
func TestParseErrors(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	t0 := time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)
	pe := &ParseErrorRecord{
		FilePath: "/var/log/cowrie/cowrie.json", FileOffset: 1234,
		Raw: `{"truncated":`, Err: "unexpected end of JSON input", At: t0,
	}
	if err := db.InsertParseError(ctx, pe); err != nil {
		t.Fatalf("InsertParseError 失败: %v", err)
	}
	pe2 := &ParseErrorRecord{
		FilePath: "/var/log/cowrie/cowrie.json", FileOffset: 5678,
		Raw: `not json`, Err: "invalid character", At: t0.Add(time.Hour),
	}
	if err := db.InsertParseError(ctx, pe2); err != nil {
		t.Fatalf("InsertParseError 失败: %v", err)
	}

	if n, err := db.CountParseErrors(ctx, t0, t0.Add(time.Hour)); err != nil || n != 1 {
		t.Errorf("[t0, t0+1h) 计数 = %d (err %v), 期望 1", n, err)
	}
	if n, err := db.CountParseErrors(ctx, t0, t0.Add(2*time.Hour)); err != nil || n != 2 {
		t.Errorf("[t0, t0+2h) 计数 = %d (err %v), 期望 2", n, err)
	}
	if n, err := db.CountParseErrors(ctx, time.Time{}, time.Time{}); err != nil || n != 2 {
		t.Errorf("无界计数 = %d (err %v), 期望 2", n, err)
	}
	var raw string
	if err := db.SQL().QueryRow(
		`SELECT raw FROM parse_errors WHERE file_offset = 1234`).Scan(&raw); err != nil {
		t.Fatalf("查询 parse_errors 失败: %v", err)
	}
	if raw != pe.Raw {
		t.Errorf("原文保留不一致: %q", raw)
	}
}
