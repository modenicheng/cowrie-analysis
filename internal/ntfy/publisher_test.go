package ntfy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modenc/e3-security-analyst/internal/store"
	"github.com/modenc/e3-security-analyst/migrations"
)

// pubQuietLogger 丢弃日志，保持测试输出干净。
func pubQuietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// pubOpenDB 在临时目录打开并迁移一个全新数据库。
func pubOpenDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "events.db"), store.Options{BusyTimeoutMs: 3000})
	if err != nil {
		t.Fatalf("store.Open 失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(migrations.FS); err != nil {
		t.Fatalf("Migrate 失败: %v", err)
	}
	return db
}

// scriptServer 启动按命中序号与路径决定响应状态的 mock ntfy 服务，
// 返回服务器与请求计数（并发安全）。
func scriptServer(t *testing.T, fn func(hit int, path string) (int, string)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(hits.Add(1))
		_, _ = io.Copy(io.Discard, r.Body)
		status, resp := fn(n, r.URL.Path)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, resp)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// fastBackoff 把内联退避基数调小并负责恢复（包内未导出变量，仅测试可改）。
func fastBackoff(t *testing.T) {
	t.Helper()
	old := retryBackoff
	retryBackoff = time.Millisecond
	t.Cleanup(func() { retryBackoff = old })
}

func pubNotification(key, topic string) *store.Notification {
	return &store.Notification{
		DedupeKey: key, Kind: "alert.login_success", Topic: topic,
		Title: "蜜罐登录成功", Body: "src=1.2.3.4", Priority: 4,
	}
}

func notificationStatus(t *testing.T, db *store.DB, key string) (status string, attempts int, merged int) {
	t.Helper()
	err := db.SQL().QueryRow(
		`SELECT status, attempts, merged_count FROM notifications WHERE dedupe_key = ?`, key).
		Scan(&status, &attempts, &merged)
	if err != nil {
		t.Fatalf("查询通知 %s 失败: %v", key, err)
	}
	return status, attempts, merged
}

// 1. Enqueue 补默认值：CreatedAt/Status/Priority 钳制与正文截断标记。
func TestEnqueueDefaultsClampAndTruncate(t *testing.T) {
	db := pubOpenDB(t)
	pub := NewPublisher(nil, db, 3, 4000, pubQuietLogger())
	ctx := context.Background()

	n := pubNotification("k-trunc", "alerts")
	n.Body = strings.Repeat("警", 2000) // 6000 字节 > 4000
	n.Priority = 9
	deduped, err := pub.Enqueue(ctx, n)
	if err != nil || deduped {
		t.Fatalf("Enqueue = (%v, %v), want (false, nil)", deduped, err)
	}
	if n.Priority != 5 {
		t.Errorf("Priority = %d, want 钳到 5", n.Priority)
	}
	if n.Status != "pending" {
		t.Errorf("Status = %q, want pending", n.Status)
	}
	if n.CreatedAt.IsZero() {
		t.Error("CreatedAt 未补默认值")
	}
	if len(n.Body) > 4000 {
		t.Errorf("Body %d 字节, want <= 4000", len(n.Body))
	}
	if !strings.HasSuffix(n.Body, truncationMarker) {
		t.Errorf("Body 缺少截断标记，尾部为 %q", n.Body[len(n.Body)-20:])
	}

	// Priority：0 视为未设置取 3；负数取 1；短正文不截断。
	n0 := pubNotification("k-p0", "alerts")
	n0.Priority = 0
	if _, err := pub.Enqueue(ctx, n0); err != nil {
		t.Fatalf("Enqueue k-p0: %v", err)
	}
	if n0.Priority != 3 {
		t.Errorf("Priority 0 → %d, want 3", n0.Priority)
	}
	nneg := pubNotification("k-neg", "alerts")
	nneg.Priority = -2
	if _, err := pub.Enqueue(ctx, nneg); err != nil {
		t.Fatalf("Enqueue k-neg: %v", err)
	}
	if nneg.Priority != 1 {
		t.Errorf("Priority -2 → %d, want 1", nneg.Priority)
	}
	if nneg.Body != "src=1.2.3.4" {
		t.Errorf("短正文不应截断, got %q", nneg.Body)
	}
}

// 2. Enqueue 去重：未发送时 Bump；已发送后不再 Bump。
func TestEnqueueDedupeBumpUnsentOnly(t *testing.T) {
	db := pubOpenDB(t)
	pub := NewPublisher(nil, db, 3, 4000, pubQuietLogger())
	ctx := context.Background()

	n := pubNotification("k-bump", "alerts")
	if deduped, err := pub.Enqueue(ctx, n); deduped || err != nil {
		t.Fatalf("首次 Enqueue = (%v, %v), want (false, nil)", deduped, err)
	}
	if deduped, err := pub.Enqueue(ctx, pubNotification("k-bump", "alerts")); !deduped || err != nil {
		t.Fatalf("二次 Enqueue = (%v, %v), want (true, nil)", deduped, err)
	}
	if _, _, merged := notificationStatus(t, db, "k-bump"); merged != 1 {
		t.Errorf("未发送时重复入队 merged_count = %d, want 1", merged)
	}

	// 标记 sent 后再重复入队：deduped=true 但不再 Bump。
	if err := db.MarkNotificationSent(ctx, n.ID, time.Now().UTC()); err != nil {
		t.Fatalf("MarkNotificationSent: %v", err)
	}
	if deduped, err := pub.Enqueue(ctx, pubNotification("k-bump", "alerts")); !deduped || err != nil {
		t.Fatalf("sent 后 Enqueue = (%v, %v), want (true, nil)", deduped, err)
	}
	if _, _, merged := notificationStatus(t, db, "k-bump"); merged != 1 {
		t.Errorf("sent 后重复入队 merged_count = %d, want 仍为 1（不 Bump 已发送）", merged)
	}
}

// 3. TrySend 重试与幂等：先 503 后 200 → 恰好一次成功，status=sent，
// dedupe_key 不变。
func TestTrySendRetryThenSuccess(t *testing.T) {
	fastBackoff(t)
	srv, hits := scriptServer(t, func(hit int, path string) (int, string) {
		if hit == 1 {
			return http.StatusServiceUnavailable, `{"error":"down"}`
		}
		return http.StatusOK, `{"id":"ok1"}`
	})
	db := pubOpenDB(t)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Timeout: 5 * time.Second})
	pub := NewPublisher(c, db, 3, 4000, pubQuietLogger())
	ctx := context.Background()

	n := pubNotification("k-retry", "alerts")
	if deduped, err := pub.Enqueue(ctx, n); deduped || err != nil {
		t.Fatalf("Enqueue = (%v, %v)", deduped, err)
	}
	if err := pub.TrySend(ctx, n); err != nil {
		t.Fatalf("TrySend error = %v, want nil（第二次应成功）", err)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("请求次数 = %d, want 2（1 次 503 + 1 次 200）", got)
	}
	status, attempts, _ := notificationStatus(t, db, "k-retry")
	if status != "sent" {
		t.Errorf("status = %q, want sent", status)
	}
	if attempts != 0 {
		t.Errorf("attempts = %d, want 0（成功轮不记失败）", attempts)
	}
	if n.DedupeKey != "k-retry" {
		t.Errorf("dedupe_key 变为 %q", n.DedupeKey)
	}
}

// 4. 恒 4xx 不可重试：立即终止、只发 1 次请求、当轮即 status=failed。
func TestTrySendNonRetryableFinalImmediately(t *testing.T) {
	fastBackoff(t)
	srv, hits := scriptServer(t, func(hit int, path string) (int, string) {
		return http.StatusBadRequest, `{"error":"bad request"}`
	})
	db := pubOpenDB(t)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Timeout: 5 * time.Second})
	pub := NewPublisher(c, db, 3, 4000, pubQuietLogger()) // maxAttempts=3：不可重试仍应立即终态
	ctx := context.Background()

	n := pubNotification("k-perm", "alerts")
	if _, err := pub.Enqueue(ctx, n); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := pub.TrySend(ctx, n); err == nil {
		t.Fatal("TrySend error = nil, want 非 nil（终态失败）")
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("请求次数 = %d, want 1（不可重试不重试）", got)
	}
	status, attempts, _ := notificationStatus(t, db, "k-perm")
	if status != "failed" {
		t.Errorf("status = %q, want failed", status)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1", attempts)
	}
}

// 5. 可重试失败用尽内联次数：保持 pending 且 TrySend 返回 nil；
// 下一次 FlushPending 再走一轮后达到 maxAttempts → 终态 failed。
func TestTrySendRetryableExhaustedThenFlushFails(t *testing.T) {
	fastBackoff(t)
	srv, hits := scriptServer(t, func(hit int, path string) (int, string) {
		return http.StatusServiceUnavailable, `{"error":"down"}`
	})
	db := pubOpenDB(t)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Timeout: 5 * time.Second})
	pub := NewPublisher(c, db, 2, 4000, pubQuietLogger())
	ctx := context.Background()

	n := pubNotification("k-exhaust", "alerts")
	if _, err := pub.Enqueue(ctx, n); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := pub.TrySend(ctx, n); err != nil {
		t.Fatalf("TrySend error = %v, want nil（非终态失败不报错，保持 pending）", err)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("第一轮请求次数 = %d, want 2（maxAttempts=2 内联重试）", got)
	}
	if status, attempts, _ := notificationStatus(t, db, "k-exhaust"); status != "pending" || attempts != 1 {
		t.Errorf("第一轮后 status=%q attempts=%d, want pending/1", status, attempts)
	}

	sent, failedPerm, err := pub.FlushPending(ctx)
	if err != nil {
		t.Fatalf("FlushPending error = %v", err)
	}
	if sent != 0 || failedPerm != 1 {
		t.Errorf("FlushPending = (%d, %d), want (0, 1)", sent, failedPerm)
	}
	if got := hits.Load(); got != 4 {
		t.Errorf("总请求次数 = %d, want 4（两轮各 2 次）", got)
	}
	if status, attempts, _ := notificationStatus(t, db, "k-exhaust"); status != "failed" || attempts != 2 {
		t.Errorf("第二轮后 status=%q attempts=%d, want failed/2", status, attempts)
	}
}

// 6. FlushPending：按路径路由成功/永久失败，统计正确；
// kind=alert.digest 的占位通知被跳过且保持 pending。
func TestFlushPendingCountsAndSkipsDigest(t *testing.T) {
	fastBackoff(t)
	srv, hits := scriptServer(t, func(hit int, path string) (int, string) {
		if path == "/bad" {
			return http.StatusForbidden, `{"error":"forbidden"}`
		}
		return http.StatusOK, `{"id":"x"}`
	})
	db := pubOpenDB(t)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Timeout: 5 * time.Second})
	pub := NewPublisher(c, db, 3, 4000, pubQuietLogger())
	ctx := context.Background()

	okN := pubNotification("k-ok", "ok")
	if _, err := pub.Enqueue(ctx, okN); err != nil {
		t.Fatalf("Enqueue ok: %v", err)
	}
	badN := pubNotification("k-bad", "bad")
	if _, err := pub.Enqueue(ctx, badN); err != nil {
		t.Fatalf("Enqueue bad: %v", err)
	}
	digest := pubNotification("k-digest", "ok")
	digest.Kind = "alert.digest"
	if _, err := pub.Enqueue(ctx, digest); err != nil {
		t.Fatalf("Enqueue digest: %v", err)
	}

	sent, failedPerm, err := pub.FlushPending(ctx)
	if err != nil {
		t.Fatalf("FlushPending error = %v", err)
	}
	if sent != 1 || failedPerm != 1 {
		t.Errorf("FlushPending = (%d, %d), want (1, 1)", sent, failedPerm)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("请求次数 = %d, want 2（digest 被跳过）", got)
	}
	if status, _, _ := notificationStatus(t, db, "k-ok"); status != "sent" {
		t.Errorf("k-ok status = %q, want sent", status)
	}
	if status, _, _ := notificationStatus(t, db, "k-bad"); status != "failed" {
		t.Errorf("k-bad status = %q, want failed", status)
	}
	if status, _, _ := notificationStatus(t, db, "k-digest"); status != "pending" {
		t.Errorf("k-digest status = %q, want pending（等待 FlushDigest 汇总）", status)
	}
}

// 7. 通知的 Attach/Markdown 字段经 messageFromNotification 映射到请求头：
// 入队→TrySend 全链路后 mock 服务端应看到 Attach 与 "Markdown: yes"。
func TestTrySendPropagatesAttachAndMarkdown(t *testing.T) {
	var mu sync.Mutex
	var gotAttach, gotMarkdown string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		gotAttach = r.Header.Get("Attach")
		gotMarkdown = r.Header.Get("Markdown")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"id":"img1"}`)
	}))
	t.Cleanup(srv.Close)
	db := pubOpenDB(t)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Timeout: 5 * time.Second})
	pub := NewPublisher(c, db, 2, 4000, pubQuietLogger())
	ctx := context.Background()

	n := pubNotification("k-attach", "alerts")
	n.Attach = "https://img-host.modenc.top/e3-reports/daily/20261022-abcd.png"
	n.Markdown = true
	if _, err := pub.Enqueue(ctx, n); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := pub.TrySend(ctx, n); err != nil {
		t.Fatalf("TrySend error = %v, want nil", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotAttach != n.Attach {
		t.Errorf("Attach header = %q, want %q", gotAttach, n.Attach)
	}
	if gotMarkdown != "yes" {
		t.Errorf("Markdown header = %q, want %q", gotMarkdown, "yes")
	}
}
