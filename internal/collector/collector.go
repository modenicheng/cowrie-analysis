// Package collector 持续采集 Cowrie JSONL 日志：追加读取、部分行缓冲、
// 文件轮转追踪、按 FileKey（unix "dev:ino" / windows "vol:index"）持久化游标、
// raw sha256 幂等去重、解析错误隔离与采集缺口记录（SPEC §6.2 全覆盖）。
//
// 内存稳定性约束：不缓存全量事件（单批 ≤500 条即提交）、读取块固定 64KiB、
// 部分行缓冲上限 1MiB、单文件单次轮询最多读 4MiB。
package collector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modenc/e3-security-analyst/internal/config"
	"github.com/modenc/e3-security-analyst/internal/cowrie"
	"github.com/modenc/e3-security-analyst/internal/store"
)

const (
	readChunkSize  = 64 << 10 // 单次读取块 64KiB
	maxLineBuffer  = 1 << 20  // 部分行缓冲上限 1MiB，超限整段按解析错误落库并推进 offset
	maxBatchEvents = 500      // 单个提交批次的事件/错误条数上限
	maxReadPerPoll = 4 << 20  // 单文件单次轮询最多读取 4MiB，剩余数据下轮继续
	maxProbeHashes = 400      // filterNew 查询已存在哈希时的 IN 参数分块
	maxBackoff     = 30 * time.Second
)

// EventHandler 仅对真正新插入 store 的事件回调（去重后）；可为 nil。
// OnNewEvents 无错误返回值（契约）；实现方 panic 会被采集器捕获并记日志，
// 绝不中断采集。
type EventHandler interface {
	OnNewEvents(ctx context.Context, evs []*store.Event)
}

// Collector 按 FileKey 跟踪日志文件并尾随读取。非并发安全：Run 与 PollOnce
// 不得同时调用。
type Collector struct {
	cfg     *config.Config
	db      *store.DB
	handler EventHandler
	log     *slog.Logger

	followInterval time.Duration // Run 轮询间隔（测试可注入缩短）
	rotationGrace  time.Duration // 轮转旧文件空转多久后关闭（测试可注入缩短）

	cur     *trackedFile   // cfg.Cowrie.LogPath 当前对应的文件句柄
	retired []*trackedFile // 已轮转/上次运行遗留、仍在抽干的旧文件句柄

	bootstrapped bool
	gapOpen      bool      // 当前缺失期间是否已记录 gap（同一缺失只记一次）
	afterMissing bool      // 因路径持续缺失关闭句柄后待重现：下次路径出现时游标作废、从 0 重读
	lastGoodAt   time.Time // 最近一次路径存在或有数据的时间，作为 gap 起点

	lastEventAt time.Time
	hasEvent    bool
	lastError   string

	dupTotal      int64 // filterNew 跳过 + InsertEvents 报告的重复合计（测试可读）
	parseErrTotal int64
}

// trackedFile 是一个被跟踪的日志文件：句柄、FileKey 游标与部分行缓冲。
// 静态不变式：offset ≤ bufOffset，buf 持有文件 [bufOffset, bufOffset+len(buf))
// 中尚未形成完整行的尾部（不含 '\n'）。
type trackedFile struct {
	path  string
	file  *os.File
	key   string
	inode int64

	offset    int64 // 已提交（SetOffset 持久化）的偏移 = 最后一条完整行末尾
	bufOffset int64 // buf[0] 在文件中的偏移
	buf       []byte

	size    int64
	mtimeNS int64

	lastDataAt time.Time // 最近一次读到新数据的时间
	retiredAt  time.Time // 进入抽干阶段的时间（零值 = 活动文件）
	missingAt  time.Time // 路径探测开始缺失的时间（零值 = 路径正常）
}

// New 创建采集器。handler 可为 nil（无实时告警场景）；log 为 nil 时用
// slog.Default()。FollowInterval/RotationGraceMS 非法时回退默认值（500ms/2s）。
func New(cfg *config.Config, db *store.DB, handler EventHandler, log *slog.Logger) (*Collector, error) {
	if cfg == nil {
		return nil, errors.New("collector.New: cfg 不能为 nil")
	}
	if db == nil {
		return nil, errors.New("collector.New: db 不能为 nil")
	}
	if cfg.Cowrie.LogPath == "" {
		return nil, errors.New("collector.New: cowrie.log_path 未配置")
	}
	if log == nil {
		log = slog.Default()
	}
	c := &Collector{
		cfg:            cfg,
		db:             db,
		handler:        handler,
		log:            log,
		followInterval: time.Duration(cfg.Cowrie.FollowInterval) * time.Millisecond,
		rotationGrace:  time.Duration(cfg.Cowrie.RotationGraceMS) * time.Millisecond,
		lastGoodAt:     time.Now().UTC(),
	}
	if c.followInterval <= 0 {
		c.followInterval = 500 * time.Millisecond
	}
	if c.rotationGrace < 0 {
		c.rotationGrace = 2 * time.Second
	}
	return c, nil
}

// Run 阻塞运行直到 ctx 取消：按 followInterval 轮询 PollOnce；出错时指数退避
// （从轮询间隔翻倍，上限 30s），成功后复位。文件缺失/部分行等非错误情况
// 不触发退避。
func (c *Collector) Run(ctx context.Context) error {
	backoff := c.followInterval
	for {
		_, err := c.PollOnce(ctx)
		wait := c.followInterval
		if err != nil {
			c.log.Warn("采集轮询失败，退避后继续", "error", err, "backoff", backoff)
			wait = backoff
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		} else {
			backoff = c.followInterval
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			c.closeAll()
			return nil
		case <-timer.C:
		}
	}
}

// PollOnce 执行一轮采集：探测当前日志路径 → 处理轮转 → 抽干退役文件 →
// 读取当前文件 → 更新健康状态。返回本轮是否有进展。
//
// 错误语义：文件暂时缺失、部分行等待均不是错误（记 gap / 缓冲后平稳返回）；
// 无权限、磁盘满、数据库写入失败等真实错误返回 error，由 Run 退避重试。
func (c *Collector) PollOnce(ctx context.Context) (bool, error) {
	if !c.bootstrapped {
		if err := c.bootstrap(ctx); err != nil {
			return false, err
		}
	}
	progress := false

	// —— 探测当前路径（每 tick 打开+比较 FileKey，不能只比文件名）——
	probeTF, perr := openTracked(c.cfg.Cowrie.LogPath)
	if perr != nil && !errors.Is(perr, fs.ErrNotExist) {
		err := fmt.Errorf("打开日志文件 %s 失败: %w", c.cfg.Cowrie.LogPath, perr)
		c.failHealth(ctx, err)
		return progress, err
	}
	if probeTF != nil {
		c.gapOpen = false // 文件恢复，结束缺失标记
		switch {
		case c.cur == nil:
			if c.afterMissing {
				// 路径持续缺失关闭句柄后重现：即使 FileKey 相同也不是同一个
				// 文件对象——Linux 删除后原地重建常复用 inode，若沿用旧游标，
				// offset 相等时新内容永远读不到、offset 更小时新文件前段被
				// 静默跳过。一律从 0 重读，靠 raw sha256 去重兜底重复。
				c.afterMissing = false
				c.log.Warn("日志路径缺失后重现，旧游标作废，从头重读",
					"path", probeTF.path, "key", probeTF.key)
			} else if err := c.resumeFromCursor(ctx, probeTF); err != nil {
				_ = probeTF.file.Close()
				c.failHealth(ctx, err)
				return progress, err
			}
			c.cur = probeTF
			c.log.Info("开始跟踪日志文件", "path", probeTF.path, "key", probeTF.key, "offset", probeTF.offset)
		case probeTF.key == c.cur.key:
			_ = probeTF.file.Close() // 同一文件：复用现有句柄，避免句柄泄漏
		default:
			// 轮转：旧句柄退役进入抽干阶段，新文件从 0 或已有游标开始。
			// 两次 tick 之间写入旧文件的数据由退役句柄 drain 保证不丢。
			now := time.Now()
			if c.cur.retiredAt.IsZero() {
				c.cur.retiredAt = now
			}
			c.cur.missingAt = time.Time{}
			c.retired = append(c.retired, c.cur)
			c.log.Info("检测到日志轮转", "old_key", c.cur.key, "new_key", probeTF.key)
			if err := c.resumeFromCursor(ctx, probeTF); err != nil {
				_ = probeTF.file.Close()
				c.failHealth(ctx, err)
				return progress, err
			}
			c.cur = probeTF
		}
		c.lastGoodAt = time.Now()
		if c.cur != nil {
			c.cur.missingAt = time.Time{}
		}
	} else if c.cur != nil && c.cur.missingAt.IsZero() {
		// 路径缺失但句柄还在（rename 后新文件未创建/被删除）：
		// 继续用旧句柄抽干，空转超过 grace 后才关闭。
		c.cur.missingAt = time.Now()
		c.log.Warn("日志路径缺失，继续抽干已打开的句柄", "path", c.cfg.Cowrie.LogPath)
	}

	// —— 先抽干退役文件（更早的数据先入库），再读当前文件 ——
	var firstErr error
	keep := c.retired[:0]
	for _, tf := range c.retired {
		p, err := c.drain(ctx, tf)
		progress = progress || p
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			keep = append(keep, tf)
			continue
		}
		idle := laterOf(tf.retiredAt, tf.lastDataAt)
		if time.Since(idle) >= c.rotationGrace {
			_ = tf.file.Close()
			c.log.Info("轮转旧文件已抽干，关闭句柄", "path", tf.path, "key", tf.key)
		} else {
			keep = append(keep, tf)
		}
	}
	c.retired = keep

	if c.cur != nil {
		p, err := c.drain(ctx, c.cur)
		progress = progress || p
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// —— 路径持续缺失且旧句柄已空转超过 grace：关闭，等待新文件 ——
	if probeTF == nil && c.cur != nil && !c.cur.missingAt.IsZero() &&
		time.Since(laterOf(c.cur.missingAt, c.cur.lastDataAt)) >= c.rotationGrace {
		_ = c.cur.file.Close()
		c.log.Warn("日志路径持续缺失，关闭旧句柄", "path", c.cur.path, "key", c.cur.key)
		c.cur = nil
		c.afterMissing = true
	}

	if progress {
		c.lastGoodAt = time.Now()
	}

	// —— 完全没有数据来源：每个缺失期间只记一次 gap ——
	if probeTF == nil && c.cur == nil && len(c.retired) == 0 && !c.gapOpen {
		now := time.Now()
		reason := fmt.Sprintf("日志文件缺失: %s", c.cfg.Cowrie.LogPath)
		if err := c.db.AddGap(ctx, c.lastGoodAt, now, reason); err != nil {
			c.failHealth(ctx, err)
			return progress, err
		}
		c.gapOpen = true
		c.log.Warn("记录采集缺口", "start", c.lastGoodAt.UTC().Format(time.RFC3339), "reason", reason)
	}

	if firstErr != nil {
		c.failHealth(ctx, firstErr)
		return progress, firstErr
	}
	c.lastError = ""
	if err := c.updateHealth(ctx); err != nil {
		return progress, err
	}
	return progress, nil
}

// bootstrap 在首次 PollOnce 时执行：从 DB 恢复健康状态种子，并扫描
// glob `LogPath.*`（跳过压缩归档）补读上次运行未读完的轮转残留文件。
func (c *Collector) bootstrap(ctx context.Context) error {
	h, err := c.db.GetHealth(ctx)
	if err != nil {
		return fmt.Errorf("collector: 读取健康状态失败: %w", err)
	}
	if h != nil {
		if h.LastEventAt != nil {
			c.lastEventAt, c.hasEvent = *h.LastEventAt, true
		}
		c.lastError = h.LastError
	}
	matches, err := filepath.Glob(c.cfg.Cowrie.LogPath + ".*")
	if err != nil {
		return fmt.Errorf("collector: 扫描轮转文件 %s.* 失败: %w", c.cfg.Cowrie.LogPath, err)
	}
	for _, m := range matches {
		if isCompressed(m) {
			continue // 压缩归档无法直接补读
		}
		if st, err := os.Stat(m); err != nil || st.IsDir() {
			continue
		}
		tf, err := openTracked(m)
		if err != nil {
			c.log.Warn("打开轮转残留文件失败", "path", m, "error", err)
			continue
		}
		off, err := c.db.GetOffset(ctx, tf.key)
		if err != nil {
			_ = tf.file.Close()
			return fmt.Errorf("collector: 读取残留文件游标失败: %w", err)
		}
		if off != nil && off.Offset < tf.size {
			tf.offset, tf.bufOffset = off.Offset, off.Offset
			// 属于上一轮转周期的遗留：抽干即关，retiredAt 置于过去以越过 grace。
			tf.retiredAt = time.Now().Add(-c.rotationGrace - time.Second)
			c.retired = append(c.retired, tf)
			c.log.Info("发现未读完的轮转文件，补读", "path", m, "key", tf.key, "offset", off.Offset, "size", tf.size)
		} else {
			_ = tf.file.Close()
		}
	}
	c.bootstrapped = true
	return nil
}

// resumeFromCursor 按 FileKey 恢复游标；无游标的新文件从 0 开始。
// 游标超出文件大小 → 文件被截断/重建，从头重读并靠 raw sha256 去重兜底。
func (c *Collector) resumeFromCursor(ctx context.Context, tf *trackedFile) error {
	off, err := c.db.GetOffset(ctx, tf.key)
	if err != nil {
		return fmt.Errorf("读取游标 %s 失败: %w", tf.key, err)
	}
	if off == nil {
		return nil
	}
	if off.Offset > tf.size {
		c.log.Warn("游标超出文件大小，怀疑截断，从头重读", "key", tf.key, "offset", off.Offset, "size", tf.size)
		return nil
	}
	tf.offset = off.Offset
	tf.bufOffset = off.Offset
	return nil
}

// drain 读取 tf 的新数据并处理完整行：按 64KiB 块读入（上限 maxReadPerPoll），
// 完整行立即解析入库，行尾不完整数据保留在 buf 中等待下次（offset 不推进）。
// 返回本轮是否有进展；读错误（磁盘满等）返回 error。
func (c *Collector) drain(ctx context.Context, tf *trackedFile) (bool, error) {
	progress := false
	if st, err := tf.file.Stat(); err == nil {
		tf.size, tf.mtimeNS = st.Size(), st.ModTime().UnixNano()
	} else {
		c.log.Warn("fstat 失败，沿用旧元数据", "path", tf.path, "error", err)
	}
	budget := maxReadPerPoll
	for {
		p, err := c.processBuffer(ctx, tf)
		if err != nil {
			return progress, err
		}
		progress = progress || p

		// 不完整行超过 1MiB 缓冲上限：整段作为解析错误落库并推进 offset，
		// 防止超长无换行数据（攻击或异常）耗尽内存。
		if len(tf.buf) >= maxLineBuffer {
			rec := &store.ParseErrorRecord{
				FilePath:   tf.path,
				FileOffset: tf.bufOffset,
				Raw:        string(tf.buf),
				Err:        fmt.Sprintf("单行超过 %d 字节缓冲上限，整段按解析错误处理", maxLineBuffer),
				At:         time.Now().UTC(),
			}
			end := tf.bufOffset + int64(len(tf.buf))
			if err := c.commit(ctx, tf, nil, []*store.ParseErrorRecord{rec}, end); err != nil {
				return progress, err
			}
			tf.buf = nil
			tf.bufOffset = end
			progress = true
			continue
		}

		if budget <= 0 {
			break // 单轮读取预算用尽，剩余数据下轮 PollOnce 继续
		}
		chunk := make([]byte, readChunkSize)
		pos := tf.bufOffset + int64(len(tf.buf))
		n, rerr := tf.file.ReadAt(chunk, pos)
		if n > 0 {
			tf.buf = append(tf.buf, chunk[:n]...)
			tf.lastDataAt = time.Now()
			budget -= n
			continue
		}
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			return progress, fmt.Errorf("读取 %s 偏移 %d 失败: %w", tf.path, pos, rerr)
		}
		break // EOF：暂无新数据
	}
	return progress, nil
}

// processBuffer 消费 tf.buf 中的完整行（以 '\n' 结尾）：空行跳过；合法行解析
// 为事件、非法行生成解析错误记录；每满 500 条提交一批。尾部不完整行保留在
// buf 中。commit 的 offset 只会推进到最后一条完整行结尾。
func (c *Collector) processBuffer(ctx context.Context, tf *trackedFile) (bool, error) {
	progress := false
	base := tf.bufOffset // buf[0] 在文件中的偏移，随消费前进
	var (
		evs  []*store.Event
		errs []*store.ParseErrorRecord
		now  = time.Now().UTC()
	)
	flush := func(end int64) error {
		return c.commit(ctx, tf, evs, errs, end)
	}
	for len(tf.buf) > 0 {
		i := bytes.IndexByte(tf.buf, '\n')
		if i < 0 {
			break // 行尾不完整：等待后续数据
		}
		line := tf.buf[:i]
		lineStart, lineEnd := base, base+int64(i)+1
		if !isBlankLine(line) {
			ev, perr := cowrie.ParseEvent(line, now)
			if perr != nil {
				errs = append(errs, &store.ParseErrorRecord{
					FilePath:   tf.path,
					FileOffset: lineStart,
					Raw:        string(line),
					Err:        perr.Error(),
					At:         now,
				})
			} else {
				evs = append(evs, toStoreEvent(ev))
			}
		}
		tf.buf = tf.buf[i+1:]
		base = lineEnd
		progress = true
		if len(evs)+len(errs) >= maxBatchEvents {
			if err := flush(lineEnd); err != nil {
				return progress, err
			}
			evs, errs = nil, nil
		}
	}
	if err := flush(base); err != nil {
		return progress, err
	}
	if len(tf.buf) > 0 { // 搬移剩余尾部到新底层数组，防止随读取无限增长
		tf.buf = append([]byte(nil), tf.buf...)
	} else {
		tf.buf = nil
	}
	tf.bufOffset = base
	return progress, nil
}

// commit 是一个批次的提交语义单元，按序执行 InsertEvents → InsertParseError* →
// SetOffset。store 未提供把三者包进同一事务的组合接口：
// 若在 InsertEvents 成功后、SetOffset 前崩溃，重启会从旧 offset 重读该批行，
// events.raw_sha256 的唯一约束（ON CONFLICT DO NOTHING）保证事件不被重复
// 入库（幂等兜底）；parse_errors 无唯一约束，崩溃重放可能留下重复诊断记录，
// 属可接受的噪音。offset 只推进到 end（最后一条完整行的结尾）。
func (c *Collector) commit(ctx context.Context, tf *trackedFile, evs []*store.Event, errs []*store.ParseErrorRecord, end int64) error {
	if end <= tf.offset && len(evs) == 0 && len(errs) == 0 {
		return nil // 无新内容：不写 DB
	}
	if len(evs) > 0 {
		fresh, skipped, err := c.filterNew(ctx, evs)
		if err != nil {
			return fmt.Errorf("提交批次（%s，offset=%d）失败: %w", tf.path, end, err)
		}
		if skipped > 0 {
			c.dupTotal += int64(skipped)
			c.log.Debug("批次内/已存在的重复事件已跳过", "path", tf.path, "count", skipped)
		}
		if len(fresh) > 0 {
			inserted, dups, err := c.db.InsertEvents(ctx, fresh)
			if err != nil {
				return fmt.Errorf("写入事件批次（%s，offset=%d）失败: %w", tf.path, end, err)
			}
			if dups > 0 {
				c.dupTotal += int64(dups)
				c.log.Debug("InsertEvents 报告重复事件", "path", tf.path, "duplicates", dups)
			}
			if inserted != len(fresh) {
				c.log.Warn("插入数与预期不符", "path", tf.path, "inserted", inserted, "expected", len(fresh))
			}
			for _, ev := range fresh {
				if !c.hasEvent || ev.EventTime.After(c.lastEventAt) {
					c.lastEventAt, c.hasEvent = ev.EventTime, true
				}
			}
			if c.handler != nil {
				c.dispatch(ctx, fresh) // 仅真正新插入的事件回调 handler
			}
		}
	}
	for _, pe := range errs {
		if err := c.db.InsertParseError(ctx, pe); err != nil {
			return fmt.Errorf("写入解析错误（%s，offset=%d）失败: %w", tf.path, pe.FileOffset, err)
		}
		c.parseErrTotal++
		c.log.Info("记录解析失败行", "path", tf.path, "offset", pe.FileOffset, "error", pe.Err)
	}
	if end > tf.offset {
		off := &store.Offset{
			FileKey:   tf.key,
			Path:      tf.path,
			Inode:     tf.inode,
			Offset:    end,
			FileSize:  tf.size,
			MtimeNS:   tf.mtimeNS,
			UpdatedAt: time.Now().UTC(),
		}
		if err := c.db.SetOffset(ctx, off); err != nil {
			return fmt.Errorf("推进游标（%s，offset=%d）失败: %w", tf.key, end, err)
		}
		tf.offset = end
	}
	return nil
}

// filterNew 在批次内按 raw sha256 去重，并剔除数据库中已存在的事件，使
// InsertEvents 的入参全部为真正的新事件（handler"仅新插入事件"语义的依据）。
// 单写者模型（只有 Collector 写 events）下该预查与插入之间无竞态。
func (c *Collector) filterNew(ctx context.Context, evs []*store.Event) ([]*store.Event, int, error) {
	seen := make(map[string]struct{}, len(evs))
	var (
		uniq    []*store.Event
		hashes  []string
		skipped int
	)
	for _, ev := range evs {
		sum := sha256.Sum256([]byte(ev.Raw))
		h := hex.EncodeToString(sum[:])
		if _, dup := seen[h]; dup {
			skipped++
			continue
		}
		seen[h] = struct{}{}
		uniq = append(uniq, ev)
		hashes = append(hashes, h)
	}
	if len(hashes) == 0 {
		return nil, skipped, nil
	}
	exist := make(map[string]struct{})
	for i := 0; i < len(hashes); i += maxProbeHashes {
		j := min(i+maxProbeHashes, len(hashes))
		q := "SELECT raw_sha256 FROM events WHERE raw_sha256 IN (" +
			strings.TrimRight(strings.Repeat("?,", j-i), ",") + ")"
		args := make([]any, j-i)
		for k, h := range hashes[i:j] {
			args[k] = h
		}
		rows, err := c.db.SQL().QueryContext(ctx, q, args...)
		if err != nil {
			return nil, skipped, fmt.Errorf("查询已存在事件哈希失败: %w", err)
		}
		for rows.Next() {
			var h string
			if serr := rows.Scan(&h); serr != nil {
				rows.Close()
				return nil, skipped, fmt.Errorf("扫描已存在事件哈希失败: %w", serr)
			}
			exist[h] = struct{}{}
		}
		if rerr := rows.Err(); rerr != nil {
			rows.Close()
			return nil, skipped, fmt.Errorf("遍历已存在事件哈希失败: %w", rerr)
		}
		rows.Close()
	}
	fresh := make([]*store.Event, 0, len(uniq))
	for k, ev := range uniq {
		if _, dup := exist[hashes[k]]; dup {
			skipped++
			continue
		}
		fresh = append(fresh, ev)
	}
	return fresh, skipped, nil
}

// dispatch 回调 handler；handler 的 panic 只记日志，不中断采集。
func (c *Collector) dispatch(ctx context.Context, evs []*store.Event) {
	defer func() {
		if r := recover(); r != nil {
			c.log.Error("EventHandler 处理新事件时 panic，已忽略", "panic", r, "events", len(evs))
		}
	}()
	c.handler.OnNewEvents(ctx, evs)
}

// updateHealth 写入健康状态：LastReadAt=now；LastEventAt 取本批最新事件时间
// 或保持内存中的原值（首次 PollOnce 时已从 DB 播种）。
func (c *Collector) updateHealth(ctx context.Context) error {
	now := time.Now().UTC()
	h := &store.Health{LastReadAt: &now, LastError: c.lastError, UpdatedAt: now}
	if c.hasEvent {
		t := c.lastEventAt.UTC()
		h.LastEventAt = &t
	}
	return c.db.UpdateHealth(ctx, h)
}

// failHealth 尽力把错误写入健康状态；失败只记日志，不影响返回给调用者的错误。
func (c *Collector) failHealth(ctx context.Context, err error) {
	c.lastError = err.Error()
	if cerr := c.updateHealth(ctx); cerr != nil {
		c.log.Error("更新健康状态失败", "error", cerr)
	}
}

// closeAll 关闭全部文件句柄（Run 退出与测试模拟进程重启时使用）。
func (c *Collector) closeAll() {
	if c.cur != nil {
		_ = c.cur.file.Close()
		c.cur = nil
	}
	for _, tf := range c.retired {
		_ = tf.file.Close()
	}
	c.retired = nil
}

// openTracked 打开 path 并计算 FileKey；文件不存在时返回包装 fs.ErrNotExist
// 的错误。全程持有该句柄读取（Windows 的文件索引必须经由句柄获取；句柄以
// share-delete 方式打开，允许日志轮转方 rename/delete）。
func openTracked(path string) (*trackedFile, error) {
	f, err := openFileShared(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if st.IsDir() {
		_ = f.Close()
		return nil, fmt.Errorf("openTracked: %s 是目录", path)
	}
	key, inode, err := fileKey(f, st)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &trackedFile{
		path:    path,
		file:    f,
		key:     key,
		inode:   inode,
		size:    st.Size(),
		mtimeNS: st.ModTime().UnixNano(),
	}, nil
}

// toStoreEvent 把 cowrie.Event 映射为 store.Event（字段一一对应；见
// cowrie.Event 关于导入循环的说明）。
func toStoreEvent(ev *cowrie.Event) *store.Event {
	return &store.Event{
		EventID:     ev.EventID,
		EventTime:   ev.EventTime,
		CollectedAt: ev.CollectedAt,
		SrcIP:       ev.SrcIP,
		SrcPort:     ev.SrcPort,
		Session:     ev.Session,
		Username:    ev.Username,
		Command:     ev.Command,
		Filename:    ev.Filename,
		Shasum:      ev.Shasum,
		DurationS:   ev.DurationS,
		Raw:         ev.Raw,
	}
}

// isBlankLine 判断空行（仅 \r、空格、制表符），空行跳过不入库。
func isBlankLine(line []byte) bool {
	return len(bytes.Trim(line, "\r\t ")) == 0
}

// isCompressed 判断轮转 glob 命中的文件是否为压缩归档（无法直接补读）。
func isCompressed(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".gz", ".zip", ".bz2", ".xz", ".zst":
		return true
	}
	return false
}

func laterOf(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
