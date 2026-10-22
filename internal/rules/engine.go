// Package rules 实现确定性实时告警引擎（SPEC §10）：事件用 cowrie.Classify
// 归类后按规则去重、全局限流，再经 ntfy.Publisher 入队并立即发送。
// 规则引擎不依赖 LLM；DeepSeek 不可用不影响本包。
//
// 并发与阻塞模型（Medium#5 加固）：
//   - OnNewEvents 持锁段只做规则计算、去重/限流判定与通知持久化
//     （pub.Enqueue 仅写 SQLite、不做网络）；网络发送由单个后台发送
//     goroutine 经带界队列串行执行，不占用采集调用栈上的锁。
//   - OnNewEvents 在锁外有界等待（drainTimeout）本批通知发送完成，
//     健康网络下回调返回时本批通知已全部送达；超时则取消本批剩余
//     发送立即返回——通知已在 notifications 表持久化（pending），由
//     e3-analyst 的 FlushPending 周期补发，采集不因 ntfy 故障停摆。
//   - FlushDigest 的网络发送同样移出 e.mu，在调用方（digest 定时器）
//     goroutine 上执行，不阻塞 OnNewEvents。
//   - 生命周期：New 启动发送 goroutine，Stop 优雅停止（取消在途网络
//     请求、排空队列并等待退出）。
//
// 内存状态说明（重启丢失可接受，均以注释标注）：
//   - 登录失败聚合的"计数里程碑"状态（lf）为内存 map；
//   - 全局滑动 60s 发送窗口（sentTimes）为内存切片；
//   - 限流合并的类型分布（digestKinds）为内存计数。
//
// 事件级去重（dedupe_key）与会话命令计数全部落在 SQLite 中，
// 因此进程重启后不会重复告警（语义与重启前一致）。
package rules

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modenc/e3-security-analyst/internal/config"
	"github.com/modenc/e3-security-analyst/internal/cowrie"
	"github.com/modenc/e3-security-analyst/internal/ntfy"
	"github.com/modenc/e3-security-analyst/internal/store"
)

// 通知 kind 常量。KindDigest 同时被 internal/ntfy（FlushPending 跳过
// digest 占位通知）按字符串值引用，两边必须保持一致。
const (
	KindLoginSuccess = "alert.login_success"
	KindFileUpload   = "alert.file_upload"
	KindFileDownload = "alert.file_download"
	KindFileFailed   = "alert.file_failed"
	KindLoginFailed  = "alert.login_failed"
	KindFirstCommand = "alert.first_command"
	KindFlood        = "alert.flood"
	KindDigest       = "alert.digest"
)

// kindLabels 是 digest 汇总里的类型中文标签。
var kindLabels = map[string]string{
	KindLoginSuccess: "登录成功",
	KindFileUpload:   "文件上传",
	KindFileDownload: "文件下载",
	KindFileFailed:   "文件操作失败",
	KindLoginFailed:  "登录失败聚合",
	KindFirstCommand: "会话首条命令",
	KindFlood:        "高频连接",
}

// sendQueueCap 是即时发送队列的容量（带界）。按 alerts.max_per_minute
// 的配置校验上限（1000 条/分钟）留出余量，正常限流下不会被丢弃；
// 仅在发送端长时间挂起导致积压时溢出，溢出任务的通知已持久化，
// 保持 pending 由 FlushPending 补发。
// 包内未导出变量，仅测试可临时调小加速用例，生产代码不得修改。
var sendQueueCap = 1024

const (
	// drainTimeout 是 OnNewEvents 锁外等待本批通知发送完成的预算：
	// 覆盖健康网络下整批（≤ max_per_minute 条）的串行即时发送；
	// ntfy 挂起时采集回调的阻塞上限即该值（此前为每条最坏约 57s 的
	// 锁内同步重试，多条叠加且全程持锁）。
	drainTimeout = 2 * time.Second
	// abortDrainWait 是放弃（取消）本批剩余发送后，等待在途任务返回的
	// 收尾预算；ctx 取消会使在途 HTTP 请求立即中止，正常远小于该值。
	abortDrainWait = 500 * time.Millisecond
)

// lfState 是某 src_ip 登录失败聚合的里程碑状态（内存态，重启丢失可接受：
// 丢失后最坏情况是该 IP 在新窗口内重新满足阈值时多发一条汇总，
// dedupe_key 含窗口起点 unix，仍不会无限重复）。
type lfState struct {
	windowStart time.Time // 上次告警所用的窗口起点（dedupe_key 组成部分）
	lastRef     time.Time // 上次处理该 IP 失败事件的时间（判断是否仍在同一聚合期）
	alerted     bool      // 本聚合期是否已发过告警
	lastCount   int       // 上次告警时的窗口内计数（里程碑）
}

// sendTask 是一条待即时发送的通知任务。ctx 派生自引擎级发送基上下文与
// 批次上下文：批次超时放弃或 Engine.Stop 都会取消它，使在途 HTTP 请求
// 立即中止且不再写发送状态（通知保持 pending，交由补发路径处理）。
type sendTask struct {
	n   *store.Notification
	ctx context.Context
}

// sendBatch 汇聚一次 OnNewEvents 内产生的全部发送任务，可整体取消。
type sendBatch struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// Engine 是确定性告警引擎。OnNewEvents 串行处理事件：持锁段完成规则
// 计算、去重/聚合、全局限流与通知持久化，网络发送在锁外经后台发送
// goroutine 有界等待完成；FlushDigest 周期性发送限流合并汇总。
// New 启动发送 goroutine，调用方退出前应调用 Stop 优雅停止。
type Engine struct {
	cfg *config.Config
	db  *store.DB
	pub *ntfy.Publisher
	log *slog.Logger
	loc *time.Location

	mu          sync.Mutex
	lf          map[string]*lfState // src_ip -> 登录失败里程碑状态（内存态）
	sentTimes   []time.Time         // 全局滑动 60s 发送时间戳（内存态）
	digestKinds map[string]int      // 自上次 FlushDigest 以来被合并的告警类型计数（内存态）
	mergedTotal int                 // mergeDigestLocked 的累计总次数（FlushDigest 复位快照对比用）

	sendCh   chan *sendTask // 带界即时发送队列
	stopCh   chan struct{}  // 关闭后发送 goroutine 排空队列并退出
	stopOnce sync.Once
	senderWG sync.WaitGroup

	baseCtx    context.Context // 引擎级发送基上下文，Stop 时取消全部在途发送
	baseCancel context.CancelFunc

	enqueued atomic.Int64 // 已成功进入发送队列的任务数
	done     atomic.Int64 // 已完成的任务数（发送、跳过或放弃）
	dropped  atomic.Int64 // 队列满被放弃即时发送的任务数（通知仍持久化）
}

// New 创建规则引擎并启动后台发送 goroutine。cfg.Location() 加载失败时
// 回退 UTC 并记日志。使用完毕应调用 Stop 停止发送 goroutine。
func New(cfg *config.Config, db *store.DB, pub *ntfy.Publisher, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	loc := time.UTC
	if cfg != nil {
		if l, err := cfg.Location(); err == nil {
			loc = l
		} else {
			log.Warn("rules: 加载配置时区失败，告警时间回退 UTC", "err", err)
		}
	}
	e := &Engine{
		cfg:         cfg,
		db:          db,
		pub:         pub,
		log:         log,
		loc:         loc,
		lf:          make(map[string]*lfState),
		digestKinds: make(map[string]int),
		sendCh:      make(chan *sendTask, sendQueueCap),
		stopCh:      make(chan struct{}),
	}
	e.baseCtx, e.baseCancel = context.WithCancel(context.Background())
	e.senderWG.Add(1)
	go e.sendLoop()
	return e
}

// Stop 优雅停止引擎的后台发送 goroutine：停止接收新任务、取消全部在途
// 发送（HTTP 请求立即中止，通知保持 pending），并在 ctx 允许的范围内
// 等待 goroutine 退出。重复调用安全；ctx 为 nil 时视为不等待超时。
// 未送出的通知不会丢失——它们已在 notifications 表中持久化，由
// FlushPending 补发。调用方（cmd/collector）应在关闭数据库前调用。
func (e *Engine) Stop(ctx context.Context) {
	if e == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	e.stopOnce.Do(func() {
		close(e.stopCh)
		e.baseCancel()
	})
	done := make(chan struct{})
	go func() {
		e.senderWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		e.log.Warn("rules: Stop 等待发送 goroutine 超时，可能仍有在途网络请求（通知保持 pending 待补发）")
	}
}

// sendLoop 是唯一的网络发送 goroutine：串行消费发送队列，同一时刻至多
// 一条即时告警在发送。stopCh 关闭后快速排空剩余任务（其 ctx 已随
// baseCancel 取消，runTask 直接跳过）并退出。
func (e *Engine) sendLoop() {
	defer e.senderWG.Done()
	for {
		select {
		case <-e.stopCh:
			for {
				select {
				case t := <-e.sendCh:
					e.runTask(t)
				default:
					return
				}
			}
		case t := <-e.sendCh:
			e.runTask(t)
		}
	}
}

// runTask 执行一次即时发送；批次已放弃（ctx 取消）时直接跳过——
// 通知保持 pending，由 FlushPending 补发。
func (e *Engine) runTask(t *sendTask) {
	defer e.done.Add(1)
	if t.ctx.Err() != nil {
		return
	}
	if err := e.pub.TrySend(t.ctx, t.n); err != nil {
		e.log.Warn("rules: 告警发送失败", "kind", t.n.Kind, "dedupe_key", t.n.DedupeKey, "err", err)
	}
}

// queueSend 把已持久化的通知交给后台发送队列（调用方须持有 e.mu，
// 保证任务顺序与判定顺序一致）。队列满时放弃即时发送并计数告警：
// 通知本身已由 pub.Enqueue 持久化（pending），不会丢失。
func (e *Engine) queueSend(b *sendBatch, n *store.Notification) {
	t := &sendTask{n: n, ctx: b.ctx}
	e.enqueued.Add(1)
	select {
	case e.sendCh <- t:
	default:
		e.done.Add(1)
		d := e.dropped.Add(1)
		e.log.Warn("rules: 即时发送队列已满，放弃本条即时发送（通知保持 pending 待补发）",
			"kind", n.Kind, "dedupe_key", n.DedupeKey, "dropped_total", d)
	}
}

// drainBatch 在锁外有界等待本批任务完成：健康网络下 OnNewEvents 返回时
// 本批通知已全部送达（保持"回调返回即已发送"的可观察行为）；预算内
// 未完成则取消剩余任务立即返回。取消后的在途 HTTP 立即中止且不写
// 发送状态，通知保持 pending 由 FlushPending 补发，采集不阻塞。
func (e *Engine) drainBatch(b *sendBatch) {
	select {
	case <-e.stopCh:
		return // 引擎已停止：不再等待，剩余任务由 Stop 排空
	default:
	}
	want := e.enqueued.Load()
	if want == 0 || e.waitDone(want, drainTimeout) {
		return
	}
	e.log.Warn("rules: 本批告警发送未在预算内完成，取消剩余即时发送（通知保持 pending 待补发）",
		"pending_tasks", want-e.done.Load())
	b.cancel()
	if !e.waitDone(want, abortDrainWait) {
		e.log.Error("rules: 取消发送后队列仍未排空（网络异常或引擎已停止），剩余任务交由补发路径",
			"undone_tasks", want-e.done.Load())
	}
}

// waitDone 轮询等待完成计数达到 want 或超时；引擎停止后立即返回 false。
func (e *Engine) waitDone(want int64, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for e.done.Load() < want {
		select {
		case <-e.stopCh:
			return false
		default:
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
	return true
}

// OnNewEvents 处理一批新入库事件（collector 已调用 InsertEvents 后回调）：
// 分类 → 规则匹配 → 去重/聚合 → 全局限流 → Enqueue 持久化 → 后台即时发送。
// 持锁段不含网络操作；锁外有界等待发送完成（见 drainBatch）。
// 单条规则失败只记日志，不影响其余事件。
func (e *Engine) OnNewEvents(ctx context.Context, evs []*store.Event) {
	if e == nil || len(evs) == 0 || e.cfg == nil || e.db == nil || e.pub == nil {
		return
	}
	if !e.cfg.Alerts.Enabled {
		return
	}
	// 批次上下文派生自引擎发送基上下文（与采集 ctx 解耦）：批次超时
	// 放弃或引擎 Stop 时取消，采集 ctx 退出不中断后台发送。
	b := &sendBatch{}
	b.ctx, b.cancel = context.WithCancel(e.baseCtx)
	defer b.cancel() // 正常排空后的幂等收尾

	e.mu.Lock()
	// 预统计本批次各会话的 command 事件数：collector 以"整批已入库"的方式
	// 回调（插入先于回调），单纯用库内计数==1 判定首条命令会把批内第 2 条
	// 提前计入，导致批内首条被漏告警（§10 会话首条命令必须告警）。
	// 判定改为：库内该会话命令总数 == 本批次该会话命令数 ⇔ 本批之前无命令。
	batchCmd := make(map[string]int)
	for _, ev := range evs {
		if ev != nil && cowrie.Classify(ev.EventID) == cowrie.KindCommand {
			batchCmd[ev.Session]++
		}
	}
	seenCmd := make(map[string]bool)
	for _, ev := range evs {
		if ev == nil {
			continue
		}
		switch cowrie.Classify(ev.EventID) {
		case cowrie.KindLoginSuccess:
			e.handleLoginSuccess(ctx, b, ev)
		case cowrie.KindFileUpload, cowrie.KindFileDownload, cowrie.KindFileFailed:
			e.handleFileOp(ctx, b, ev)
		case cowrie.KindLoginFailed:
			e.handleLoginFailed(ctx, b, ev)
		case cowrie.KindCommand:
			e.handleFirstCommand(ctx, b, ev, batchCmd, seenCmd)
		case cowrie.KindConnect:
			e.handleConnect(ctx, b, ev)
		}
	}
	e.mu.Unlock()

	e.drainBatch(b)
}

// FlushDigest 查询 digest 类 pending 且 merged_count>0 的通知，改写为
// 汇总正文后发送；发送成功即复用 sent 状态标记完成。
// 类型分布来自内存计数（重启后只有总数，正文措辞自动降级为仅报数量）。
//
// Medium#5：网络发送移出 e.mu（在调用方 goroutine 上执行，不阻塞
// OnNewEvents/采集）；锁仅覆盖类型分布快照与复位。mergedTotal 快照
// 保证发送期间新到达的合并计数不会被本次复位吞掉。
func (e *Engine) FlushDigest(ctx context.Context) error {
	if e == nil || e.db == nil || e.pub == nil {
		return nil
	}
	pending, err := e.db.PendingNotifications(ctx, 0) // 0 = 不限制
	if err != nil {
		return fmt.Errorf("rules.FlushDigest: %w", err)
	}
	e.mu.Lock()
	dist := e.distributionLocked()
	merged := e.mergedTotal
	e.mu.Unlock()
	nowStr := time.Now().In(e.loc).Format("2006-01-02 15:04:05")
	flushed := false
	for _, n := range pending {
		if n.Kind != KindDigest || n.MergedCount <= 0 {
			continue
		}
		minutes := int(time.Since(n.CreatedAt).Minutes())
		if minutes < 1 {
			minutes = 1
		}
		var b strings.Builder
		fmt.Fprintf(&b, "时间：%s\n说明：过去 %d 分钟内因限流合并了 %d 条告警。", nowStr, minutes, n.MergedCount)
		if dist != "" {
			fmt.Fprintf(&b, "类型分布：%s。", dist)
		} else {
			b.WriteString("（类型分布不可用：进程可能已重启，仅报合并总数。）")
		}
		n.Title = "[E3蜜罐] 限流告警汇总"
		n.Body = b.String()
		n.Priority = 2
		if sendErr := e.pub.TrySend(ctx, n); sendErr != nil {
			e.log.Warn("rules: digest 汇总发送失败", "dedupe_key", n.DedupeKey, "err", sendErr)
			continue
		}
		flushed = true
	}
	if flushed {
		e.mu.Lock()
		if e.mergedTotal == merged {
			e.digestKinds = make(map[string]int) // 清空，下一周期重新累计
		}
		e.mu.Unlock()
	}
	return nil
}

// —— 各事件规则 ——

// handleLoginSuccess：登录成功立即高优告警。文案必须明确"蜜罐模拟登录
// 成功（非真实系统失陷）"，绝不能表述为真实主机失陷（SPEC §18）。
// 攻击者可控字段（源IP/会话/用户名）经 field 统一单行化+包裹（Medium#4）。
func (e *Engine) handleLoginSuccess(ctx context.Context, b *sendBatch, ev *store.Event) {
	var bd strings.Builder
	fmt.Fprintf(&bd, "时间：%s\n源IP：%s\n事件：%s\n会话：%s\n用户名：%s\n说明：蜜罐模拟登录成功（非真实系统失陷），攻击者以该账号进入蜜罐沙箱，请关注其后续命令与文件操作。",
		e.fmtTime(ev.EventTime), field(ev.SrcIP), ev.EventID, field(ev.Session), field(ev.Username))
	e.dispatch(ctx, b, KindLoginSuccess,
		"alert:login_success:"+ev.Session,
		"[E3蜜罐] 蜜罐模拟登录成功", bd.String(), 4, []string{"rotating_light"})
}

// handleFileOp：文件上传/下载/下载失败立即告警，dedupe 取 shasum 或
// 文件名；文案注明是蜜罐沙箱内的文件操作。文件名/哈希/会话等攻击者
// 可控字段经 field 统一单行化+包裹（Medium#4）。
func (e *Engine) handleFileOp(ctx context.Context, b *sendBatch, ev *store.Event) {
	var (
		kind     string
		title    string
		opDesc   string
		priority int
	)
	switch cowrie.Classify(ev.EventID) {
	case cowrie.KindFileUpload:
		kind, title, opDesc, priority = KindFileUpload,
			"蜜罐内文件上传", "攻击者向蜜罐沙箱上传了文件（蜜罐内文件操作，非真实系统文件）", 4
	case cowrie.KindFileDownload:
		kind, title, opDesc, priority = KindFileDownload,
			"蜜罐内文件下载", "攻击者在蜜罐沙箱内下载了文件（蜜罐内文件操作，非真实系统文件）", 4
	default: // KindFileFailed（file_download.failed / file_upload.failed）
		kind, title, opDesc, priority = KindFileFailed,
			"蜜罐内文件操作失败", "攻击者在蜜罐沙箱内尝试文件操作但失败（蜜罐内文件操作）", 3
	}
	fid := ev.Shasum
	if fid == "" {
		fid = ev.Filename
	}
	if fid == "" {
		fid = "unknown"
	}
	var bd strings.Builder
	fmt.Fprintf(&bd, "时间：%s\n源IP：%s\n事件：%s\n会话：%s\n文件名：%s\nSHA256：%s\n说明：%s。",
		e.fmtTime(ev.EventTime), field(ev.SrcIP), ev.EventID, field(ev.Session),
		field(ev.Filename), field(ev.Shasum), opDesc)
	e.dispatch(ctx, b, kind,
		"alert:file:"+ev.Session+":"+fid,
		"[E3蜜罐] "+title, bd.String(), priority, []string{"file_folder"})
}

// handleLoginFailed：同一 src_ip 滚动窗口聚合。窗口计数用 SQL
// （CountEvents，重启后语义一致）；"上次告警时的计数里程碑"用内存状态，
// 避免同窗口重复告警。达到 Threshold 发一条汇总，之后每再增加
// RepeatEvery 次再发一条（各次告警的 dedupe_key 用告警时刻的窗口起点
// unix，天然可区分且可重放）。用户名样本逐个包裹（Medium#4）。
func (e *Engine) handleLoginFailed(ctx context.Context, b *sendBatch, ev *store.Event) {
	if ev.SrcIP == "" {
		return // 无法按来源聚合（cowrie 登录失败事件通常必有 src_ip）
	}
	window := time.Duration(e.cfg.Alerts.LoginFailedWindowSec) * time.Second
	ref := ev.EventTime.UTC()
	since := ref.Add(-window)
	// 上界加 1s 余量：事件时间列以 RFC3339Nano 文本存储与比较，
	// 纳秒尾零会被格式化裁剪，紧凑上界（如 +1ns）可能把 ref 本身
	// 排除在文本比较之外；+1s 的秒位定宽递增保证文本序与时序一致，
	// 窗口语义仅放宽不足 1 秒。
	until := ref.Add(time.Second)
	cnt, err := e.db.CountEvents(ctx, store.EventFilter{
		Since: since, Until: until,
		SrcIP:    ev.SrcIP,
		EventIDs: []string{cowrie.EventLoginFailed},
	})
	if err != nil {
		e.log.Error("rules: 统计登录失败窗口计数失败", "src_ip", ev.SrcIP, "err", err)
		return
	}

	st := e.lf[ev.SrcIP]
	if st == nil || !ref.Before(st.lastRef.Add(window)) {
		// 新聚合期：距上次处理该 IP 已超过一个窗口
		st = &lfState{windowStart: since, lastRef: ref}
		e.lf[ev.SrcIP] = st
	} else {
		st.lastRef = ref
	}

	threshold := e.cfg.Alerts.LoginFailedThreshold
	repeat := e.cfg.Alerts.LoginFailedRepeatEvery
	shouldAlert := false
	if !st.alerted {
		shouldAlert = cnt >= threshold
	} else {
		shouldAlert = cnt-st.lastCount >= repeat
	}
	if !shouldAlert {
		return
	}
	st.alerted = true
	st.lastCount = cnt
	st.windowStart = since // dedupe_key 用本次告警时刻的窗口起点

	usernames := e.failedUsernames(ctx, ev.SrcIP, since, until, 5)
	var bd strings.Builder
	fmt.Fprintf(&bd, "时间：%s（窗口 %s ~ %s）\n源IP：%s\n事件：%s\n会话：%s（触发会话）\n说明：窗口内登录失败 %d 次（阈值 %d），用户名样本：%s。均为蜜罐内的失败尝试。",
		e.fmtTime(ref), e.fmtTime(since), e.fmtTime(ref), field(ev.SrcIP), ev.EventID,
		field(ev.Session), cnt, threshold, usernames)
	e.dispatch(ctx, b, KindLoginFailed,
		fmt.Sprintf("alert:login_failed:%s:%d", ev.SrcIP, st.windowStart.Unix()),
		"[E3蜜罐] 登录失败聚合告警", bd.String(), 3, []string{"warning"})
}

// handleFirstCommand：每 session 首条命令告警。判断依据：当前事件是该
// 会话在本批次中的第一条命令（seenCmd 批内去重），且 events 表中该会话
// 的 command 事件总数恰等于本批次该会话的 command 数（batchCmd）——即
// 本批之前该会话没有任何命令。查询用 CountEvents，重启后语义一致
// （内存状态无关）。命令原文先按 200 rune 截断（截断标记保留），
// 再经 field 单行化+包裹（Medium#4）。
func (e *Engine) handleFirstCommand(ctx context.Context, b *sendBatch, ev *store.Event,
	batchCmd map[string]int, seenCmd map[string]bool) {
	if seenCmd[ev.Session] {
		return // 批内第 2 条及以后的命令，不告警
	}
	seenCmd[ev.Session] = true
	cnt, err := e.db.CountEvents(ctx, store.EventFilter{
		Session:  ev.Session,
		EventIDs: []string{cowrie.EventCommandInput},
	})
	if err != nil {
		e.log.Error("rules: 统计会话命令数失败", "session", ev.Session, "err", err)
		return
	}
	if cnt != batchCmd[ev.Session] {
		return // 本批之前已有命令，非会话首条
	}
	cmd, cut := truncateRunes(ev.Command, 200)
	if cut {
		cmd += "…"
	}
	var bd strings.Builder
	fmt.Fprintf(&bd, "时间：%s\n源IP：%s\n事件：%s\n会话：%s\n命令：%s\n说明：该会话执行的首条命令，后续命令不逐条告警。",
		e.fmtTime(ev.EventTime), field(ev.SrcIP), ev.EventID, field(ev.Session), field(cmd))
	e.dispatch(ctx, b, KindFirstCommand,
		"alert:firstcmd:"+ev.Session,
		"[E3蜜罐] 会话首条命令", bd.String(), 3, []string{"computer"})
}

// handleConnect：连接事件不逐条告警；单 src_ip 一分钟内连接数超过
// MaxPerMinute*2 时发高频连接汇总（按分钟桶 dedupe）。计数用 SQL，
// 重启后同一分钟桶不会重复汇总（dedupe_key 含分钟桶 unix）。
func (e *Engine) handleConnect(ctx context.Context, b *sendBatch, ev *store.Event) {
	if ev.SrcIP == "" {
		return
	}
	bucket := ev.EventTime.UTC().Truncate(time.Minute)
	cnt, err := e.db.CountEvents(ctx, store.EventFilter{
		Since: bucket, Until: bucket.Add(time.Minute),
		SrcIP:    ev.SrcIP,
		EventIDs: []string{cowrie.EventConnect},
	})
	if err != nil {
		e.log.Error("rules: 统计分钟连接数失败", "src_ip", ev.SrcIP, "err", err)
		return
	}
	limit := e.cfg.Alerts.MaxPerMinute * 2
	if cnt <= limit {
		return
	}
	var bd strings.Builder
	fmt.Fprintf(&bd, "时间：%s\n源IP：%s\n事件：%s\n会话：（多会话聚合）\n说明：该来源一分钟内建立 %d 次连接（阈值 %d），疑似高频扫描或连接洪水；连接事件不逐条告警，仅按分钟聚合。",
		e.fmtTime(ev.EventTime), field(ev.SrcIP), ev.EventID, cnt, limit)
	e.dispatch(ctx, b, KindFlood,
		fmt.Sprintf("alert:flood:%s:%d", ev.SrcIP, bucket.Unix()),
		"[E3蜜罐] 高频连接汇总", bd.String(), 3, []string{"zap"})
}

// —— 去重 / 限流 / 合并 ——

// dispatch 是所有告警的统一出口（调用方须持有 e.mu）：先过全局滑动 60s
// 限流；被限流的告警不入队不发送，改为合并进当分钟占位通知
// （digest:minute:<unix分钟>，merged_count 计数）；通过限流的告警
// Enqueue（仅写 SQLite 不做网络；dedupe 命中则跳过发送，且不占用限流
// 额度），新入队的交给后台发送队列即时发送（Medium#5：网络已移出
// 引擎锁与采集调用栈，由 drainBatch 有界等待）。
func (e *Engine) dispatch(ctx context.Context, b *sendBatch, kind, dedupeKey, title, body string, priority int, tags []string) {
	now := time.Now().UTC()
	if !e.allowSendLocked(now) {
		e.log.Warn("rules: 告警触发全局限流，合并入分钟摘要",
			"kind", kind, "dedupe_key", dedupeKey)
		e.mergeDigestLocked(ctx, kind, now)
		return
	}
	n := &store.Notification{
		DedupeKey: dedupeKey,
		Kind:      kind,
		Topic:     e.cfg.AlertTopic(),
		Title:     title,
		Body:      body,
		Priority:  priority,
		Tags:      strings.Join(tags, ","),
		CreatedAt: now,
	}
	deduped, err := e.pub.Enqueue(ctx, n)
	if err != nil {
		// 入队失败只记日志：事件仍在 events 表中，可重放（SPEC：不得静默丢失）。
		e.log.Error("rules: 告警入队失败", "kind", kind, "dedupe_key", dedupeKey, "err", err)
		return
	}
	if deduped {
		e.log.Info("rules: 告警重复（同去重键已存在），跳过发送",
			"kind", kind, "dedupe_key", dedupeKey)
		return
	}
	e.recordSendLocked(now)
	e.queueSend(b, n)
}

// mergeDigestLocked 把一条被限流的告警合并进当分钟占位通知（调用方须
// 持有 e.mu）。首次创建 kind=alert.digest、priority=2 的占位通知且
// MergedCount=1；此后 Enqueue 命中已存在（未发送）会 Bump +1，因此
// merged_count 恰好等于被合并的告警条数。
func (e *Engine) mergeDigestLocked(ctx context.Context, kind string, now time.Time) {
	e.digestKinds[kind]++
	e.mergedTotal++
	bucket := now.Truncate(time.Minute)
	n := &store.Notification{
		DedupeKey: fmt.Sprintf("digest:minute:%d", bucket.Unix()),
		Kind:      KindDigest,
		Topic:     e.cfg.AlertTopic(),
		Title:     "[E3蜜罐] 告警限流合并",
		Body: fmt.Sprintf("时间：%s\n说明：本分钟告警数已达上限（max_per_minute=%d），超出的告警已合并，稍后以汇总形式发送。",
			now.In(e.loc).Format("2006-01-02 15:04:05"), e.cfg.Alerts.MaxPerMinute),
		Priority:    2,
		Tags:        "bookmark_tabs",
		CreatedAt:   now,
		MergedCount: 1,
	}
	if _, err := e.pub.Enqueue(ctx, n); err != nil {
		e.log.Error("rules: 限流摘要入队失败", "kind", kind, "err", err)
	}
}

// allowSendLocked 判断全局滑动 60s 窗口内是否还有发送额度（调用方须
// 持有 e.mu；sentTimes 为内存态，重启后窗口清零，影响仅为重启后第一
// 分钟可多发 max_per_minute 条，可接受）。
func (e *Engine) allowSendLocked(now time.Time) bool {
	cutoff := now.Add(-time.Minute)
	valid := e.sentTimes[:0]
	for _, t := range e.sentTimes {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	e.sentTimes = valid
	return len(e.sentTimes) < e.cfg.Alerts.MaxPerMinute
}

// recordSendLocked 记录一次实际入队发送，占用限流额度（调用方须持有 e.mu）。
func (e *Engine) recordSendLocked(now time.Time) {
	e.sentTimes = append(e.sentTimes, now)
}

// distributionLocked 生成 digest 汇总的类型分布文案；无内存计数时返回
// 空串（重启后 FlushDigest 措辞降级为仅报总数）。
func (e *Engine) distributionLocked() string {
	if len(e.digestKinds) == 0 {
		return ""
	}
	type kv struct {
		label string
		n     int
	}
	list := make([]kv, 0, len(e.digestKinds))
	for kind, n := range e.digestKinds {
		label, ok := kindLabels[kind]
		if !ok {
			label = kind
		}
		list = append(list, kv{label, n})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].label < list[j].label
	})
	parts := make([]string, 0, len(list))
	for _, it := range list {
		parts = append(parts, fmt.Sprintf("%s %d 条", it.label, it.n))
	}
	return strings.Join(parts, "、")
}

// failedUsernames 查询窗口内该 src_ip 登录失败的用户名去重样本（前 limit
// 个，按字典序保证确定性）。查询失败返回占位文案，不阻塞告警。
// 每个用户名都是攻击者可控文本，逐个经 sanitizeField 包裹（Medium#4）。
func (e *Engine) failedUsernames(ctx context.Context, srcIP string, since, until time.Time, limit int) string {
	if limit <= 0 {
		limit = 5
	}
	rows, err := e.db.SQL().QueryContext(ctx,
		`SELECT DISTINCT username FROM events
		 WHERE event_time >= ? AND event_time < ? AND src_ip = ? AND event_id = ? AND username != ''
		 ORDER BY username LIMIT ?`,
		since.UTC().Format(time.RFC3339Nano), until.UTC().Format(time.RFC3339Nano),
		srcIP, cowrie.EventLoginFailed, limit)
	if err != nil {
		e.log.Warn("rules: 查询登录失败用户名样本失败", "src_ip", srcIP, "err", err)
		return "（样本不可用）"
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil {
			names = append(names, sanitizeField(name))
		}
	}
	if len(names) == 0 {
		return "（无）"
	}
	return strings.Join(names, "、")
}

// —— 小工具 ——

// fmtTime 把 UTC 时间转为配置时区展示。
func (e *Engine) fmtTime(t time.Time) string {
	return t.In(e.loc).Format("2006-01-02 15:04:05")
}

// field 是攻击者可控字段进入告警正文的统一出口（Medium#4）：空值给
// （未知）占位，非空经 sanitizeField 单行化+包裹。标题/Tags 走 ntfy
// Client 的 headerSafe（HTTP 头注入防护），不经过这里。
func field(s string) string {
	if s == "" {
		return "（未知）"
	}
	return sanitizeField(s)
}

// sanitizeField 把攻击者可控字段安全地拼入 ntfy 正文（Medium#4）：
//
//  1. 单行化：CR/LF、其他 C0/C1 控制字符、DEL 与 Unicode 行/段分隔符
//     （U+2028/U+2029）替换为空格——字段内无法伪造换行，"说明：此告警
//     可忽略"之类的伪造排版不再能另起一行；
//  2. 防 Markdown 链接：'[' 与 '<' 前加反斜杠（CommonMark 转义），
//     渲染端不会把它们组成 [文字](url) 链接、图片或 <url> 自动链接；
//  3. 「」包裹：视觉上明确字段边界。
//
// 不做长度截断——截断由调用方 truncateRunes 与发布层负责，截断标记保留。
func sanitizeField(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	b.WriteString("「")
	for _, r := range s {
		switch {
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) ||
			r == '\u2028' || r == '\u2029':
			b.WriteRune(' ')
		case r == '[' || r == '<':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteString("」")
	return b.String()
}

// truncateRunes 按 rune 数截断字符串，返回截断结果与是否发生了截断。
func truncateRunes(s string, max int) (string, bool) {
	if max <= 0 {
		return "", s != ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s, false
	}
	return string(r[:max]), true
}
