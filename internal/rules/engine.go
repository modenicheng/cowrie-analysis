// Package rules 实现确定性实时告警引擎（SPEC §10）：事件用 cowrie.Classify
// 归类后按规则去重、全局限流，再经 ntfy.Publisher 入队并立即发送。
// 规则引擎不依赖 LLM；DeepSeek 不可用不影响本包。
//
// 内存状态说明（重启丢失可接受，均以注释标注）：
//   - 登录失败聚合的"计数里程碑"状态（lf）为内存 map；
//   - 全局滑动 60s 发送窗口（sentTimes）为内存切片；
//   - 限流合并的类型分布（digestKinds）为内存计数。
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

// lfState 是某 src_ip 登录失败聚合的里程碑状态（内存态，重启丢失可接受：
// 丢失后最坏情况是该 IP 在新窗口内重新满足阈值时多发一条汇总，
// dedupe_key 含窗口起点 unix，仍不会无限重复）。
type lfState struct {
	windowStart time.Time // 上次告警所用的窗口起点（dedupe_key 组成部分）
	lastRef     time.Time // 上次处理该 IP 失败事件的时间（判断是否仍在同一聚合期）
	alerted     bool      // 本聚合期是否已发过告警
	lastCount   int       // 上次告警时的窗口内计数（里程碑）
}

// Engine 是确定性告警引擎。OnNewEvents 串行处理事件（内部持锁，
// 包括同步发送），保证限流计数与里程碑状态的一致性；FlushDigest
// 周期性发送限流合并汇总。
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
}

// New 创建规则引擎。cfg.Location() 加载失败时回退 UTC 并记日志。
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
	return &Engine{
		cfg:         cfg,
		db:          db,
		pub:         pub,
		log:         log,
		loc:         loc,
		lf:          make(map[string]*lfState),
		digestKinds: make(map[string]int),
	}
}

// OnNewEvents 处理一批新入库事件（collector 已调用 InsertEvents 后回调）：
// 分类 → 规则匹配 → 去重/聚合 → 全局限流 → Enqueue + TrySend。
// 单条规则失败只记日志，不影响其余事件。
func (e *Engine) OnNewEvents(ctx context.Context, evs []*store.Event) {
	if e == nil || len(evs) == 0 || e.cfg == nil || e.db == nil || e.pub == nil {
		return
	}
	if !e.cfg.Alerts.Enabled {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
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
			e.handleLoginSuccess(ctx, ev)
		case cowrie.KindFileUpload, cowrie.KindFileDownload, cowrie.KindFileFailed:
			e.handleFileOp(ctx, ev)
		case cowrie.KindLoginFailed:
			e.handleLoginFailed(ctx, ev)
		case cowrie.KindCommand:
			e.handleFirstCommand(ctx, ev, batchCmd, seenCmd)
		case cowrie.KindConnect:
			e.handleConnect(ctx, ev)
		}
	}
}

// FlushDigest 查询 digest 类 pending 且 merged_count>0 的通知，改写为
// 汇总正文后用 TrySend 发送；发送成功即复用 sent 状态标记完成。
// 类型分布来自内存计数（重启后只有总数，正文措辞自动降级为仅报数量）。
func (e *Engine) FlushDigest(ctx context.Context) error {
	if e == nil || e.db == nil || e.pub == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	pending, err := e.db.PendingNotifications(ctx, 0) // 0 = 不限制
	if err != nil {
		return fmt.Errorf("rules.FlushDigest: %w", err)
	}
	dist := e.distributionLocked()
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
		e.digestKinds = make(map[string]int) // 清空，下一周期重新累计
	}
	return nil
}

// —— 各事件规则 ——

// handleLoginSuccess：登录成功立即高优告警。文案必须明确"蜜罐模拟登录
// 成功（非真实系统失陷）"，绝不能表述为真实主机失陷（SPEC §18）。
func (e *Engine) handleLoginSuccess(ctx context.Context, ev *store.Event) {
	var b strings.Builder
	fmt.Fprintf(&b, "时间：%s\n源IP：%s\n事件：%s\n会话：%s\n用户名：%s\n说明：蜜罐模拟登录成功（非真实系统失陷），攻击者以该账号进入蜜罐沙箱，请关注其后续命令与文件操作。",
		e.fmtTime(ev.EventTime), ev.SrcIP, ev.EventID, orNA(ev.Session), orNA(ev.Username))
	e.dispatch(ctx, KindLoginSuccess,
		"alert:login_success:"+ev.Session,
		"[E3蜜罐] 蜜罐模拟登录成功", b.String(), 4, []string{"rotating_light"})
}

// handleFileOp：文件上传/下载/下载失败立即告警，dedupe 取 shasum 或
// 文件名；文案注明是蜜罐沙箱内的文件操作。
func (e *Engine) handleFileOp(ctx context.Context, ev *store.Event) {
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
	var b strings.Builder
	fmt.Fprintf(&b, "时间：%s\n源IP：%s\n事件：%s\n会话：%s\n文件名：%s\nSHA256：%s\n说明：%s。",
		e.fmtTime(ev.EventTime), ev.SrcIP, ev.EventID, orNA(ev.Session),
		orNA(ev.Filename), orNA(ev.Shasum), opDesc)
	e.dispatch(ctx, kind,
		"alert:file:"+ev.Session+":"+fid,
		"[E3蜜罐] "+title, b.String(), priority, []string{"file_folder"})
}

// handleLoginFailed：同一 src_ip 滚动窗口聚合。窗口计数用 SQL
// （CountEvents，重启后语义一致）；"上次告警时的计数里程碑"用内存状态，
// 避免同窗口重复告警。达到 Threshold 发一条汇总，之后每再增加
// RepeatEvery 次再发一条（各次告警的 dedupe_key 用告警时刻的窗口起点
// unix，天然可区分且可重放）。
func (e *Engine) handleLoginFailed(ctx context.Context, ev *store.Event) {
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
	var b strings.Builder
	fmt.Fprintf(&b, "时间：%s（窗口 %s ~ %s）\n源IP：%s\n事件：%s\n会话：%s（触发会话）\n说明：窗口内登录失败 %d 次（阈值 %d），用户名样本：%s。均为蜜罐内的失败尝试。",
		e.fmtTime(ref), e.fmtTime(since), e.fmtTime(ref), ev.SrcIP, ev.EventID,
		orNA(ev.Session), cnt, threshold, usernames)
	e.dispatch(ctx, KindLoginFailed,
		fmt.Sprintf("alert:login_failed:%s:%d", ev.SrcIP, st.windowStart.Unix()),
		"[E3蜜罐] 登录失败聚合告警", b.String(), 3, []string{"warning"})
}

// handleFirstCommand：每 session 首条命令告警。判断依据：当前事件是该
// 会话在本批次中的第一条命令（seenCmd 批内去重），且 events 表中该会话
// 的 command 事件总数恰等于本批次该会话的 command 数（batchCmd）——即
// 本批之前该会话没有任何命令。查询用 CountEvents，重启后语义一致
// （内存状态无关）。
func (e *Engine) handleFirstCommand(ctx context.Context, ev *store.Event,
	batchCmd map[string]int, seenCmd map[string]bool) {
	if seenCmd[ev.Session] {
		return // 批内第 2 条及以后的命令，不告警
	}
	seenCmd[ev.Session] = true
	cnt, err := e.db.CountEvents(ctx, store.EventFilter{
		Session:   ev.Session,
		EventIDs:  []string{cowrie.EventCommandInput},
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
	var b strings.Builder
	fmt.Fprintf(&b, "时间：%s\n源IP：%s\n事件：%s\n会话：%s\n命令：%s\n说明：该会话执行的首条命令，后续命令不逐条告警。",
		e.fmtTime(ev.EventTime), ev.SrcIP, ev.EventID, orNA(ev.Session), orNA(cmd))
	e.dispatch(ctx, KindFirstCommand,
		"alert:firstcmd:"+ev.Session,
		"[E3蜜罐] 会话首条命令", b.String(), 3, []string{"computer"})
}

// handleConnect：连接事件不逐条告警；单 src_ip 一分钟内连接数超过
// MaxPerMinute*2 时发高频连接汇总（按分钟桶 dedupe）。计数用 SQL，
// 重启后同一分钟桶不会重复汇总（dedupe_key 含分钟桶 unix）。
func (e *Engine) handleConnect(ctx context.Context, ev *store.Event) {
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
	var b strings.Builder
	fmt.Fprintf(&b, "时间：%s\n源IP：%s\n事件：%s\n会话：（多会话聚合）\n说明：该来源一分钟内建立 %d 次连接（阈值 %d），疑似高频扫描或连接洪水；连接事件不逐条告警，仅按分钟聚合。",
		e.fmtTime(ev.EventTime), ev.SrcIP, ev.EventID, cnt, limit)
	e.dispatch(ctx, KindFlood,
		fmt.Sprintf("alert:flood:%s:%d", ev.SrcIP, bucket.Unix()),
		"[E3蜜罐] 高频连接汇总", b.String(), 3, []string{"zap"})
}

// —— 去重 / 限流 / 合并 ——

// dispatch 是所有告警的统一出口（调用方须持有 e.mu）：
// 先过全局滑动 60s 限流；被限流的告警不入队不发送，改为合并进当分钟
// 占位通知（digest:minute:<unix分钟>，merged_count 计数）；通过限流的
// 告警 Enqueue（dedupe 命中则跳过发送，且不占用限流额度），新入队的
// 立即 TrySend。
func (e *Engine) dispatch(ctx context.Context, kind, dedupeKey, title, body string, priority int, tags []string) {
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
	if err := e.pub.TrySend(ctx, n); err != nil {
		e.log.Warn("rules: 告警发送失败", "kind", kind, "dedupe_key", dedupeKey, "err", err)
	}
}

// mergeDigestLocked 把一条被限流的告警合并进当分钟占位通知（调用方须
// 持有 e.mu）。首次创建 kind=alert.digest、priority=2 的占位通知且
// MergedCount=1；此后 Enqueue 命中已存在（未发送）会 Bump +1，因此
// merged_count 恰好等于被合并的告警条数。
func (e *Engine) mergeDigestLocked(ctx context.Context, kind string, now time.Time) {
	e.digestKinds[kind]++
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
			names = append(names, name)
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

// orNA 空值占位。
func orNA(s string) string {
	if s == "" {
		return "（未知）"
	}
	return s
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
