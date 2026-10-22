// Publisher 在 Client 之上实现持久化通知队列（SPEC §12）：入队去重、
// 消息长度截断、内联退避重试、发送状态落库（pending/sent/failed）与
// 失败补发（FlushPending）。
//
// 并发安全：Publisher 自身没有共享可变状态，全部状态保存在 SQLite
// notifications 表中，所有方法可被多个 goroutine 同时调用。
// 送达语义为至多失败重试、可能重复（HTTP 成功但落库失败时保持 pending
// 会被重发）；SPEC §12 要求以稳定 dedupe_key 保证重试/重启不会因
// "重新入队"造成重复通知，本实现通过 notifications.dedupe_key 唯一约束
// 满足该要求。日志只记录 dedupe_key/topic/HTTP 状态，绝不记录 Token。
package ntfy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/modenc/e3-security-analyst/internal/store"
)

// retryBackoff 是内联重试的退避基数：第 n 次失败后等待 base<<(n-1)，
// 封顶 retryBackoffCap。包内未导出变量，仅测试可临时调小加速用例，
// 生产代码不得修改（非并发安全地写它）。
var retryBackoff = 500 * time.Millisecond

const (
	// retryBackoffCap 是单次退避等待的上限。
	retryBackoffCap = 30 * time.Second
	// skipFlushKind 是限流合并占位通知的 kind（由 internal/rules 生成，
	// 与 rules.KindDigest 常量值保持一致）。FlushPending 跳过该类通知：
	// 它们的正文只是占位说明，必须等 rules.FlushDigest 改写为汇总后再发送。
	skipFlushKind = "alert.digest"
	// truncationMarker 追加在超长正文截断后的标记。
	truncationMarker = "\n…(截断)"
	// lastErrMaxBytes 是 last_error 列保留的最大字节数。
	lastErrMaxBytes = 300
)

// Publisher 持久化通知队列：Enqueue 幂等入队，TrySend 立即发送（含内联
// 重试），FlushPending 扫描 pending 批量补发。
type Publisher struct {
	client          *Client
	db              *store.DB
	maxAttempts     int
	maxMessageBytes int
	log             *slog.Logger
}

// NewPublisher 创建 Publisher。maxAttempts < 1 视为 1；maxMessageBytes
// <= 0 时回退到 Client 的 MaxBodyBytes；log 为 nil 时使用 slog.Default()。
func NewPublisher(client *Client, db *store.DB, maxAttempts int, maxMessageBytes int, log *slog.Logger) *Publisher {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	if maxMessageBytes <= 0 {
		maxMessageBytes = MaxBodyBytes
	}
	if log == nil {
		log = slog.Default()
	}
	return &Publisher{
		client:          client,
		db:              db,
		maxAttempts:     maxAttempts,
		maxMessageBytes: maxMessageBytes,
		log:             log,
	}
}

// Enqueue 写 notifications 表（按 dedupe_key 幂等），行为：
//
//   - 补默认值：CreatedAt=now(UTC)、Status=pending、Priority 钳到 1-5
//     （0 视为未设置取默认 3，负数取 1，>5 取 5）；
//   - Body 超过 maxMessageBytes 时按 rune 截断并追加 "\n…(截断)"；
//   - 新插入 → deduped=false；
//   - 已存在且未发送（pending/failed）→ BumpNotification 累加 merged_count
//     后返回 deduped=true；已发送 → 不再改动，直接返回 deduped=true。
func (p *Publisher) Enqueue(ctx context.Context, n *store.Notification) (deduped bool, err error) {
	if n == nil {
		return false, fmt.Errorf("ntfy.Enqueue: notification 为 nil")
	}
	if n.DedupeKey == "" {
		return false, fmt.Errorf("ntfy.Enqueue: DedupeKey 为空")
	}
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Now().UTC()
	}
	if n.Status == "" {
		n.Status = "pending"
	}
	switch {
	case n.Priority == 0:
		n.Priority = 3
	case n.Priority < 1:
		n.Priority = 1
	case n.Priority > 5:
		n.Priority = 5
	}
	n.Body = truncateBody(n.Body, p.maxMessageBytes)

	existed, err := p.db.EnqueueNotification(ctx, n)
	if err != nil {
		return false, fmt.Errorf("ntfy.Enqueue: %w", err)
	}
	if !existed {
		return false, nil
	}
	if status := p.existingStatus(ctx, n.DedupeKey); status != "sent" {
		if bumpErr := p.db.BumpNotification(ctx, n.DedupeKey); bumpErr != nil {
			return true, fmt.Errorf("ntfy.Enqueue: 累加已存在通知 merged_count: %w", bumpErr)
		}
	}
	return true, nil
}

// existingStatus 查询 dedupe_key 对应通知的当前状态；查询失败返回空串
// （调用方将其视为"非 sent"，退化为无脑 Bump，语义安全）。
func (p *Publisher) existingStatus(ctx context.Context, dedupeKey string) string {
	var status string
	if err := p.db.SQL().QueryRowContext(ctx,
		`SELECT status FROM notifications WHERE dedupe_key = ?`, dedupeKey).Scan(&status); err != nil {
		p.log.Warn("查询已存在通知状态失败", "dedupe_key", dedupeKey, "err", err)
		return ""
	}
	return status
}

// TrySend 立即尝试发送一条通知：最多 maxAttempts 次内联 Publish，
// 每次失败若 IsRetryable 且还有余量则退避后重试，不可重试错误立即终止。
//
// 返回值：发送成功 → nil；瞬态失败（已记录 attempts，通知保持 pending，
// 等待 FlushPending 重试）→ nil；最终失败（status=failed）或基础设施
// 错误 → 非 nil error（final 时为最后一次 Publish 错误本身）。
func (p *Publisher) TrySend(ctx context.Context, n *store.Notification) error {
	if n == nil {
		return fmt.Errorf("ntfy.TrySend: notification 为 nil")
	}
	// send 返回：发送成功或瞬态失败（已记录，保持 pending）→ err=nil；
	// 终态失败（status=failed，err 为最后一次 Publish 错误）或基础设施
	// 错误 → err 非 nil，如实上抛。
	if _, _, err := p.send(ctx, n); err != nil {
		return err
	}
	return nil
}

// send 是 TrySend/FlushPending 共用的发送内核，返回是否成功、是否最终
// 失败（status=failed）及错误。瞬态失败返回 (false, false, nil)。
func (p *Publisher) send(ctx context.Context, n *store.Notification) (sent, final bool, err error) {
	var lastErr error
	for attempt := 1; attempt <= p.maxAttempts; attempt++ {
		out, pubErr := p.client.Publish(ctx, messageFromNotification(n))
		if pubErr == nil {
			at := out.SentAt
			if at.IsZero() {
				at = time.Now().UTC()
			}
			if markErr := p.db.MarkNotificationSent(ctx, n.ID, at); markErr != nil {
				// HTTP 已成功但状态落库失败：保持 pending 交由 FlushPending
				// 重试（不因 HTTP 成功就永久标记完成，也不静默丢失）。
				p.log.Error("ntfy 发布成功但标记 sent 失败，通知保持 pending",
					"dedupe_key", n.DedupeKey, "http_status", out.HTTPStatus, "err", markErr)
				return false, false, fmt.Errorf("ntfy: 标记 sent 失败: %w", markErr)
			}
			// 成功日志：含 HTTP 状态与 dedupe_key，绝不包含 Token。
			p.log.Info("ntfy 发布成功", "dedupe_key", n.DedupeKey, "topic", n.Topic,
				"http_status", out.HTTPStatus, "response_id", out.ResponseID)
			return true, false, nil
		}
		lastErr = pubErr
		if IsRetryable(pubErr) && attempt < p.maxAttempts {
			delay := backoffFor(attempt)
			p.log.Warn("ntfy 发布失败，退避后重试", "dedupe_key", n.DedupeKey,
				"attempt", attempt, "backoff_ms", delay.Milliseconds(), "err", pubErr)
			select {
			case <-ctx.Done():
				p.log.Warn("ntfy 重试等待被取消，通知保持 pending",
					"dedupe_key", n.DedupeKey, "err", ctx.Err())
				return false, false, ctx.Err()
			case <-time.After(delay):
			}
			continue
		}
		break // 不可重试错误立即终止，或内联次数已用尽
	}

	// 全部尝试失败：落库。不可重试的错误（4xx/本地校验失败）不可能因
	// 重试而成功，直接判终态：向 MarkNotificationFailed 传阈值 1，
	// 强制 attempts>=1 → status=failed。
	threshold := p.maxAttempts
	if lastErr != nil && !IsRetryable(lastErr) {
		threshold = 1
	}
	final, markErr := p.db.MarkNotificationFailed(ctx, n.ID,
		previewBytes([]byte(lastErr.Error()), lastErrMaxBytes), threshold)
	if markErr != nil {
		return false, false, fmt.Errorf("ntfy: 记录发送失败状态出错: %w", markErr)
	}
	if final {
		p.log.Error("ntfy 发布最终失败，通知标记 failed",
			"dedupe_key", n.DedupeKey, "attempts_limit", threshold, "err", lastErr)
		return false, true, lastErr
	}
	p.log.Warn("ntfy 发布失败，通知保持 pending 等待 FlushPending 重试",
		"dedupe_key", n.DedupeKey, "err", lastErr)
	return false, false, nil
}

// FlushPending 扫描最多 100 条 pending 通知逐条重试，返回（成功数，
// 永久失败数）。单条失败不中断后续；kind=alert.digest 的占位通知被
// 跳过（由 rules.FlushDigest 汇总发送）。err 仅在查询 pending 列表
// 失败时非 nil。
func (p *Publisher) FlushPending(ctx context.Context) (sent int, failedPerm int, err error) {
	list, err := p.db.PendingNotifications(ctx, 100)
	if err != nil {
		return 0, 0, fmt.Errorf("ntfy.FlushPending: %w", err)
	}
	for _, n := range list {
		if n.Kind == skipFlushKind {
			continue
		}
		ok, final, sendErr := p.send(ctx, n)
		switch {
		case ok:
			sent++
		case final:
			failedPerm++
		}
		if sendErr != nil && !final {
			p.log.Warn("ntfy.FlushPending: 单条重试失败，保持 pending",
				"dedupe_key", n.DedupeKey, "err", sendErr)
		}
	}
	return sent, failedPerm, nil
}

// messageFromNotification 把存储层通知转换为 Client 消息（Tags 从逗号
// 分隔字符串还原为数组）。
func messageFromNotification(n *store.Notification) Message {
	var tags []string
	for _, t := range strings.Split(n.Tags, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	return Message{
		Topic:    n.Topic,
		Title:    n.Title,
		Body:     n.Body,
		Priority: n.Priority,
		Tags:     tags,
	}
}

// backoffFor 返回第 attempt 次失败后的退避时长：retryBackoff 指数增长，
// 封顶 retryBackoffCap；非正值兜底为 1ms（测试可能把基数调成 0）。
func backoffFor(attempt int) time.Duration {
	d := retryBackoff
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= retryBackoffCap {
			return retryBackoffCap
		}
	}
	if d <= 0 {
		return time.Millisecond
	}
	return d
}

// truncateBody 把 body 截断到不超过 maxBytes 字节（rune 安全），超长时
// 追加截断标记；maxBytes <= 0 表示不限制。
func truncateBody(body string, maxBytes int) string {
	if maxBytes <= 0 || len(body) <= maxBytes {
		return body
	}
	limit := maxBytes - len(truncationMarker)
	if limit < 0 {
		return previewBytes([]byte(truncationMarker), maxBytes)
	}
	return previewBytes([]byte(body), limit) + truncationMarker
}
