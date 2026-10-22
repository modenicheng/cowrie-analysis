package store

import (
	"context"
	"testing"
	"time"
)

func mkNotification(key string) *Notification {
	return &Notification{
		DedupeKey: key, Kind: "alert.login_success", Topic: "alerts",
		Title: "蜜罐登录成功", Body: "src=1.2.3.4", Tags: "warning,skull",
		Priority: 4, MergedCount: 0,
	}
}

// TestEnqueueNotificationDedupe：新键插入并回填 ID；同 dedupe_key 二次入队
// existed=true 且既有内容不被覆盖。
func TestEnqueueNotificationDedupe(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	n := mkNotification("login-success:s1")
	existed, err := db.EnqueueNotification(ctx, n)
	if err != nil {
		t.Fatalf("Enqueue 失败: %v", err)
	}
	if existed {
		t.Fatal("首次入队 existed 应为 false")
	}
	if n.ID == 0 {
		t.Fatal("首次入队应回填 ID")
	}

	dupe := mkNotification("login-success:s1")
	dupe.Body = "OVERWRITTEN"
	dupe.Priority = 1
	existed, err = db.EnqueueNotification(ctx, dupe)
	if err != nil {
		t.Fatalf("二次 Enqueue 失败: %v", err)
	}
	if !existed {
		t.Fatal("同 dedupe_key 二次入队 existed 应为 true")
	}
	var body string
	var priority int
	if err := db.SQL().QueryRow(
		`SELECT body, priority FROM notifications WHERE dedupe_key = ?`, n.DedupeKey).
		Scan(&body, &priority); err != nil {
		t.Fatalf("查询通知失败: %v", err)
	}
	if body != "src=1.2.3.4" || priority != 4 {
		t.Errorf("已存在通知被覆盖: body=%q priority=%d", body, priority)
	}
	if n := countRows(t, db, "notifications"); n != 1 {
		t.Errorf("notifications 行数 = %d, 期望 1", n)
	}

	// 空键拒绝。
	if _, err := db.EnqueueNotification(ctx, &Notification{DedupeKey: ""}); err == nil {
		t.Error("空 DedupeKey 应报错")
	}
}

// TestNotificationLifecycle：Bump 计数、Pending 只列 pending、
// MarkSent 生效、MarkFailed 达到 maxAttempts 后 final=true 且 status=failed。
func TestNotificationLifecycle(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	n1 := mkNotification("login-success:s1")
	if _, err := db.EnqueueNotification(ctx, n1); err != nil {
		t.Fatalf("Enqueue n1 失败: %v", err)
	}
	n2 := mkNotification("login-failed:s2")
	n2.Kind = "alert.login_failed"
	if _, err := db.EnqueueNotification(ctx, n2); err != nil {
		t.Fatalf("Enqueue n2 失败: %v", err)
	}

	// Bump 只作用于目标键。
	if err := db.BumpNotification(ctx, n1.DedupeKey); err != nil {
		t.Fatalf("BumpNotification 失败: %v", err)
	}
	var merged int
	if err := db.SQL().QueryRow(
		`SELECT merged_count FROM notifications WHERE id = ?`, n1.ID).Scan(&merged); err != nil {
		t.Fatalf("查询 merged_count 失败: %v", err)
	}
	if merged != 1 {
		t.Errorf("merged_count = %d, 期望 1", merged)
	}
	if err := db.BumpNotification(ctx, "no-such-key"); err == nil {
		t.Error("不存在的 dedupe_key Bump 应报错")
	}

	// Pending 只列 pending。
	pending, err := db.PendingNotifications(ctx, 0)
	if err != nil {
		t.Fatalf("PendingNotifications 失败: %v", err)
	}
	if len(pending) != 2 || pending[0].DedupeKey != n1.DedupeKey || pending[0].MergedCount != 1 {
		t.Fatalf("pending 列表不正确: %+v", pending)
	}
	pending, err = db.PendingNotifications(ctx, 1)
	if err != nil || len(pending) != 1 {
		t.Fatalf("limit=1 应只返回 1 条, got %d (err %v)", len(pending), err)
	}

	// n1 发送成功。
	sentAt := time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)
	if err := db.MarkNotificationSent(ctx, n1.ID, sentAt); err != nil {
		t.Fatalf("MarkNotificationSent 失败: %v", err)
	}
	pending, _ = db.PendingNotifications(ctx, 0)
	if len(pending) != 1 || pending[0].ID != n2.ID {
		t.Fatalf("发送成功后 pending 应只剩 n2: %+v", pending)
	}

	// n2 连续失败到 maxAttempts=3：前两次保持 pending，第三次 final。
	for attempt := 1; attempt <= 3; attempt++ {
		final, err := db.MarkNotificationFailed(ctx, n2.ID, "http 503", 3)
		if err != nil {
			t.Fatalf("第 %d 次 MarkNotificationFailed 失败: %v", attempt, err)
		}
		if attempt < 3 && final {
			t.Fatalf("第 %d 次失败不应 final", attempt)
		}
		if attempt == 3 && !final {
			t.Fatal("达到 maxAttempts 应返回 final=true")
		}
	}
	var status string
	var attempts int
	var lastErr string
	if err := db.SQL().QueryRow(
		`SELECT status, attempts, last_error FROM notifications WHERE id = ?`, n2.ID).
		Scan(&status, &attempts, &lastErr); err != nil {
		t.Fatalf("查询 n2 失败: %v", err)
	}
	if status != "failed" || attempts != 3 || lastErr != "http 503" {
		t.Errorf("n2 终态: status=%q attempts=%d last_error=%q", status, attempts, lastErr)
	}
	pending, _ = db.PendingNotifications(ctx, 0)
	if len(pending) != 0 {
		t.Errorf("failed 后不应出现在 pending: %+v", pending)
	}

	sent, pendingN, failed, err := db.NotificationStats(ctx, time.Time{})
	if err != nil {
		t.Fatalf("NotificationStats 失败: %v", err)
	}
	if sent != 1 || pendingN != 0 || failed != 1 {
		t.Errorf("stats = (%d,%d,%d), 期望 (1,0,1)", sent, pendingN, failed)
	}

	// since 过滤：晚于所有创建时间的 since 应统计为 0。
	future := time.Now().UTC().Add(time.Hour)
	sent, pendingN, failed, err = db.NotificationStats(ctx, future)
	if err != nil || sent != 0 || pendingN != 0 || failed != 0 {
		t.Errorf("future since 应全为 0, got (%d,%d,%d) err %v", sent, pendingN, failed, err)
	}

	// 不存在的 ID。
	if _, err := db.MarkNotificationFailed(ctx, 99999, "x", 3); err == nil {
		t.Error("不存在的通知 MarkFailed 应报错")
	}
	if err := db.MarkNotificationSent(ctx, 99999, time.Now()); err == nil {
		t.Error("不存在的通知 MarkSent 应报错")
	}
}

// TestNotificationAttachMarkdownRoundtrip：新列 attach/markdown 入队后经
// PendingNotifications 读回一致；未设置时保持默认 ”/false（旧行为）。
func TestNotificationAttachMarkdownRoundtrip(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	attach := "https://img-host.modenc.top/e3-reports/daily/20261022-abcd.png"
	n := mkNotification("report.daily:20261022")
	n.Kind = "report.daily"
	n.Attach = attach
	n.Markdown = true
	if _, err := db.EnqueueNotification(ctx, n); err != nil {
		t.Fatalf("Enqueue 失败: %v", err)
	}

	pending, err := db.PendingNotifications(ctx, 0)
	if err != nil {
		t.Fatalf("PendingNotifications 失败: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending 行数 = %d, 期望 1", len(pending))
	}
	got := pending[0]
	if got.Attach != attach {
		t.Errorf("回读 attach = %q, 期望 %q", got.Attach, attach)
	}
	if !got.Markdown {
		t.Error("回读 markdown = false, 期望 true")
	}

	// 未设置两字段的普通通知：默认 ''/false，不携带附件与 Markdown。
	plain := mkNotification("alert.plain:s9")
	if _, err := db.EnqueueNotification(ctx, plain); err != nil {
		t.Fatalf("Enqueue plain 失败: %v", err)
	}
	pending, err = db.PendingNotifications(ctx, 0)
	if err != nil {
		t.Fatalf("PendingNotifications 失败: %v", err)
	}
	var plainGot *Notification
	for _, p := range pending {
		if p.DedupeKey == plain.DedupeKey {
			plainGot = p
		}
	}
	if plainGot == nil {
		t.Fatal("未找到 plain 通知")
	}
	if plainGot.Attach != "" || plainGot.Markdown {
		t.Errorf("plain 通知默认值异常: attach=%q markdown=%v, 期望空/false",
			plainGot.Attach, plainGot.Markdown)
	}

	// 迁移列存在性：直接 SQL 断言两列与默认值语义。
	var defAttach string
	var defMarkdown int64
	if err := db.SQL().QueryRow(
		`SELECT attach, markdown FROM notifications WHERE dedupe_key = ?`,
		plain.DedupeKey).Scan(&defAttach, &defMarkdown); err != nil {
		t.Fatalf("查询迁移列失败: %v", err)
	}
	if defAttach != "" || defMarkdown != 0 {
		t.Errorf("迁移列默认值异常: attach=%q markdown=%d", defAttach, defMarkdown)
	}
}
