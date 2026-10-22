package store

import (
	"context"
	"testing"
	"time"
)

var reportWindow = time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)

// TestUpsertReport：按 (type, window_start) 更新而非新增；GetReport 往返；
// 不同窗口/类型互不干扰；不存在返回 (nil, nil)。
func TestUpsertReport(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	if r, err := db.GetReport(ctx, "daily", reportWindow); err != nil || r != nil {
		t.Fatalf("空库 GetReport: got (%v, %v), 期望 (nil, nil)", r, err)
	}

	r1 := &Report{
		Type: "daily", WindowStart: reportWindow,
		WindowEnd: reportWindow.Add(24 * time.Hour),
		Status:    "validated", Model: "deepseek-chat", Attempts: 1,
		ContentSHA256: "aa1111", Payload: `{"v":1}`,
	}
	if err := db.UpsertReport(ctx, r1); err != nil {
		t.Fatalf("UpsertReport 失败: %v", err)
	}
	if r1.ID == 0 {
		t.Fatal("UpsertReport 应回填 ID")
	}
	firstID := r1.ID

	// 同 (type, window_start) 再次 upsert：更新而非新增。
	r2 := &Report{
		Type: "daily", WindowStart: reportWindow,
		WindowEnd: reportWindow.Add(24 * time.Hour),
		Status:    "published", Model: "deepseek-chat", Attempts: 2,
		ContentSHA256: "bb2222", Payload: `{"v":2}`,
	}
	if err := db.UpsertReport(ctx, r2); err != nil {
		t.Fatalf("二次 UpsertReport 失败: %v", err)
	}
	if n := countRows(t, db, "reports"); n != 1 {
		t.Fatalf("reports 行数 = %d, 期望 1（应更新而非新增）", n)
	}

	got, err := db.GetReport(ctx, "daily", reportWindow)
	if err != nil {
		t.Fatalf("GetReport 失败: %v", err)
	}
	if got.ID != firstID || got.Status != "published" || got.Payload != `{"v":2}` ||
		got.Attempts != 2 || got.ContentSHA256 != "bb2222" {
		t.Errorf("更新后的报告不正确: %+v", *got)
	}
	if !got.WindowStart.Equal(reportWindow) || !got.WindowEnd.Equal(reportWindow.Add(24*time.Hour)) {
		t.Errorf("窗口时间不正确: %v ~ %v", got.WindowStart, got.WindowEnd)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Errorf("时间戳未落库: created=%v updated=%v", got.CreatedAt, got.UpdatedAt)
	}

	// 不同窗口/类型是独立记录。
	other := &Report{
		Type: "weekly", WindowStart: reportWindow,
		WindowEnd: reportWindow.Add(7 * 24 * time.Hour),
		Status:    "failed", Error: "llm timeout",
	}
	if err := db.UpsertReport(ctx, other); err != nil {
		t.Fatalf("UpsertReport(weekly) 失败: %v", err)
	}
	if n := countRows(t, db, "reports"); n != 2 {
		t.Fatalf("reports 行数 = %d, 期望 2", n)
	}
	if r, err := db.GetReport(ctx, "weekly", reportWindow); err != nil || r == nil || r.Error != "llm timeout" {
		t.Errorf("weekly 报告读取不正确: (%v, %v)", r, err)
	}
}

// TestFailedReports：只列 failed 且 updated_at >= updatedSince。
func TestFailedReports(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	old := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	fresh := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)

	failedOld := &Report{Type: "daily", WindowStart: reportWindow,
		WindowEnd: reportWindow.Add(24 * time.Hour), Status: "failed", Error: "e1", UpdatedAt: old}
	failedFresh := &Report{Type: "daily", WindowStart: reportWindow.Add(-24 * time.Hour),
		WindowEnd: reportWindow, Status: "failed", Error: "e2", UpdatedAt: fresh}
	published := &Report{Type: "weekly", WindowStart: reportWindow,
		WindowEnd: reportWindow.Add(7 * 24 * time.Hour), Status: "published", UpdatedAt: fresh}
	for _, r := range []*Report{failedOld, failedFresh, published} {
		r.CreatedAt = r.UpdatedAt
		if err := db.UpsertReport(ctx, r); err != nil {
			t.Fatalf("UpsertReport 失败: %v", err)
		}
	}

	// updatedSince 零值：列出全部 failed。
	got, err := db.FailedReports(ctx, time.Time{})
	if err != nil {
		t.Fatalf("FailedReports 失败: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("无界 FailedReports = %d 条, 期望 2", len(got))
	}
	// 只保留 updated_at 在 since 之后的 failed。
	got, err = db.FailedReports(ctx, time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("FailedReports 失败: %v", err)
	}
	if len(got) != 1 || got[0].Error != "e2" {
		t.Fatalf("过滤后 FailedReports = %+v, 期望仅 e2", got)
	}
}
