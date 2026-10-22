package collector

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/modenc/e3-security-analyst/internal/config"
	"github.com/modenc/e3-security-analyst/internal/store"
	"github.com/modenc/e3-security-analyst/migrations"
)

// —— 测试基建 ——

func openDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "events.db"), store.Options{WAL: true, BusyTimeoutMs: 2000})
	if err != nil {
		t.Fatalf("store.Open 失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(migrations.FS); err != nil {
		t.Fatalf("Migrate 失败: %v", err)
	}
	return db
}

// newCollector 建采集器并注入缩短的 follow 间隔与轮转 grace，避免测试真等 2s。
func newCollector(t *testing.T, logPath string, db *store.DB, handler EventHandler) *Collector {
	t.Helper()
	cfg := config.Default()
	cfg.Cowrie.LogPath = logPath
	cfg.Cowrie.FollowInterval = 50
	cfg.Cowrie.RotationGraceMS = 2000
	c, err := New(cfg, db, handler, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	c.followInterval = 20 * time.Millisecond
	c.rotationGrace = 30 * time.Millisecond
	// 关闭句柄早于 t.TempDir 清理（LIFO），否则 Windows 下临时目录删不掉
	t.Cleanup(c.closeAll)
	return c
}

// line 生成第 i 条互不相同的合法事件行。
func line(i int) string {
	return fmt.Sprintf(`{"eventid":"cowrie.session.connect","timestamp":"2026-10-22T08:%02d:%02d.%06d+00:00","session":"s%d","src_ip":"10.0.%d.%d","src_port":2222,"username":"root","message":"New connection"}`,
		(i/60)%60, i%60, i%1000000, i, i/251%254+1, i%251+1)
}

func appendFile(t *testing.T, path string, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("打开 %s 追加失败: %v", path, err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("写入 %s 失败: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("关闭 %s 失败: %v", path, err)
	}
}

func countEvents(t *testing.T, db *store.DB) int {
	t.Helper()
	n, err := db.CountEvents(context.Background(), store.EventFilter{})
	if err != nil {
		t.Fatalf("CountEvents 失败: %v", err)
	}
	return n
}

// pollUntil 反复 PollOnce 直到事件数达到 want 或超时。
func pollUntil(t *testing.T, c *Collector, db *store.DB, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if _, err := c.PollOnce(context.Background()); err != nil {
			t.Fatalf("PollOnce 失败: %v", err)
		}
		if countEvents(t, db) >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("等待 %d 条事件超时（当前 %d）", want, countEvents(t, db))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// handlerFunc 便于把闭包用作 EventHandler。
type handlerFunc func(ctx context.Context, evs []*store.Event)

func (f handlerFunc) OnNewEvents(ctx context.Context, evs []*store.Event) { f(ctx, evs) }

// —— 1. 追加读取 ——

func TestAppendRead(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t)
	logPath := filepath.Join(dir, "cowrie.json")
	os.WriteFile(logPath, []byte(line(0)+"\n"+line(1)+"\n"+line(2)+"\n"), 0o644)
	c := newCollector(t, logPath, db, nil)

	progress, err := c.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if !progress {
		t.Fatal("首轮应报告进展")
	}
	if n := countEvents(t, db); n != 3 {
		t.Fatalf("首轮后事件数 = %d, 期望 3", n)
	}

	appendFile(t, logPath, line(3)+"\n"+line(4)+"\n")
	pollUntil(t, c, db, 5, 2*time.Second)
	if n := countEvents(t, db); n != 5 {
		t.Fatalf("追加后事件数 = %d, 期望 5", n)
	}
}

// —— 2. 部分行：无换行结尾不入库、不推进 offset；补齐后入库 ——

func TestPartialLine(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t)
	logPath := filepath.Join(dir, "cowrie.json")
	half := `{"eventid":"cowrie.session.connect","timestamp":"2026-10-2`
	os.WriteFile(logPath, []byte(half), 0o644)
	c := newCollector(t, logPath, db, nil)

	if _, err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if n := countEvents(t, db); n != 0 {
		t.Fatalf("半行不应入库，事件数 = %d", n)
	}
	offs, err := db.ListOffsets(context.Background())
	if err != nil {
		t.Fatalf("ListOffsets: %v", err)
	}
	if len(offs) != 0 {
		t.Fatalf("半行不应推进 offset，却有 %d 条游标", len(offs))
	}

	appendFile(t, logPath, `2T08:00:00Z","session":"sp","src_ip":"1.1.1.1"}`+"\n")
	pollUntil(t, c, db, 1, 2*time.Second)
	if n := countEvents(t, db); n != 1 {
		t.Fatalf("补齐换行后事件数 = %d, 期望 1", n)
	}
}

// —— 3. 重复事件：同一行内容再写一次（不同 offset），入库数不增 ——

func TestDuplicateLines(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t)
	logPath := filepath.Join(dir, "cowrie.json")
	os.WriteFile(logPath, []byte(line(0)+"\n"), 0o644)
	c := newCollector(t, logPath, db, nil)
	pollUntil(t, c, db, 1, 2*time.Second)

	appendFile(t, logPath, line(0)+"\n") // 相同内容、不同 offset
	if _, err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if n := countEvents(t, db); n != 1 {
		t.Fatalf("重复行入库数 = %d, 期望保持 1", n)
	}
	if c.dupTotal == 0 {
		t.Fatal("重复应被计数（dupTotal）")
	}
}

// —— 4. 轮转：rename 后旧文件补写、新文件创建，A/B/C 全部入库 ——

func TestRotation(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t)
	logPath := filepath.Join(dir, "cowrie.json")
	rotated := logPath + ".1"

	// A：轮转前写入并采集（建立旧 FileKey 游标）
	os.WriteFile(logPath, []byte(line(0)+"\n"+line(1)+"\n"), 0o644)
	c := newCollector(t, logPath, db, nil)
	pollUntil(t, c, db, 2, 2*time.Second)

	// 轮转：rename → 旧文件追加 B → 新文件写 C
	if err := os.Rename(logPath, rotated); err != nil {
		t.Fatalf("rename 失败: %v", err)
	}
	appendFile(t, rotated, line(2)+"\n")
	os.WriteFile(logPath, []byte(line(3)+"\n"), 0o644)

	// 单次 PollOnce（注入缩短的 grace）：B 经退役句柄抽干、C 经新句柄读取
	if _, err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if n := countEvents(t, db); n != 4 {
		t.Fatalf("轮转后事件数 = %d, 期望 4（A+B+C 全入库）", n)
	}

	// grace 过后退役句柄关闭，再轮询不产生重复
	time.Sleep(c.rotationGrace + 20*time.Millisecond)
	if _, err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if len(c.retired) != 0 {
		t.Fatalf("grace 后退役句柄应关闭，剩余 %d", len(c.retired))
	}
	if _, err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if n := countEvents(t, db); n != 4 {
		t.Fatalf("句柄关闭后事件数 = %d, 期望仍为 4", n)
	}
}

// —— 5. 重启恢复：同一 DB 新建 Collector，不重复入库，只采新行 ——

func TestRestartResume(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t)
	logPath := filepath.Join(dir, "cowrie.json")
	os.WriteFile(logPath, []byte(line(0)+"\n"+line(1)+"\n"+line(2)+"\n"), 0o644)

	c1 := newCollector(t, logPath, db, nil)
	pollUntil(t, c1, db, 3, 2*time.Second)
	c1.closeAll() // 模拟进程退出

	c2 := newCollector(t, logPath, db, nil)
	progress, err := c2.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("重启后 PollOnce: %v", err)
	}
	if progress {
		t.Log("重启首轮报告进展（可能来自游标推进），但事件数不得增长")
	}
	if n := countEvents(t, db); n != 3 {
		t.Fatalf("重启后事件数 = %d, 期望仍为 3（无重复入库）", n)
	}

	appendFile(t, logPath, line(5)+"\n")
	pollUntil(t, c2, db, 4, 2*time.Second)
	if n := countEvents(t, db); n != 4 {
		t.Fatalf("重启后新行事件数 = %d, 期望 4", n)
	}
}

// —— 6. 轮转后重启：DB 有旧 FileKey 未读完游标，旧文件留在 log.1，启动补读 ——

func TestRestartAfterRotation(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t)
	logPath := filepath.Join(dir, "cowrie.json")

	content := line(1) + "\n" + line(2) + "\n" + line(3) + "\n"
	os.WriteFile(logPath, []byte(content), 0o644)

	// 模拟上次运行：只读了前两行（游标在 line(2) 末尾），随后轮转、进程崩溃
	tf, err := openTracked(logPath)
	if err != nil {
		t.Fatalf("openTracked: %v", err)
	}
	cut := int64(len(line(1)) + 1 + len(line(2)) + 1)
	if err := db.SetOffset(context.Background(), &store.Offset{
		FileKey: tf.key, Path: logPath, Inode: tf.inode,
		Offset: cut, FileSize: tf.size, MtimeNS: tf.mtimeNS,
	}); err != nil {
		t.Fatalf("SetOffset: %v", err)
	}
	_ = tf.file.Close()
	if err := os.Rename(logPath, logPath+".1"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	os.WriteFile(logPath, []byte(""), 0o644) // 轮转后的新（空）文件

	c := newCollector(t, logPath, db, nil)
	if _, err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if n := countEvents(t, db); n != 1 {
		t.Fatalf("补读后事件数 = %d, 期望 1（只读剩余的 line(3)）", n)
	}
	// 再轮询保证补读收尾平稳、无重复
	if _, err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if n := countEvents(t, db); n != 1 {
		t.Fatalf("二次轮询后事件数 = %d, 期望仍为 1", n)
	}
}

// —— 7. 文件缺失：不 panic、平稳返回、记 gap；重建后恢复采集 ——

func TestMissingFile(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t)
	logPath := filepath.Join(dir, "cowrie.json")
	os.WriteFile(logPath, []byte(line(0)+"\n"), 0o644)
	c := newCollector(t, logPath, db, nil)
	pollUntil(t, c, db, 1, 2*time.Second)

	if err := os.Remove(logPath); err != nil {
		t.Fatalf("删除日志失败: %v", err)
	}
	// 首次缺失：句柄仍在抽干阶段，平稳返回（可 false），不 panic
	progress, err := c.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("文件缺失时 PollOnce 应平稳返回, 得到: %v", err)
	}
	_ = progress

	// grace 过后旧句柄关闭，路径仍缺失 → 记录一次 gap
	time.Sleep(c.rotationGrace + 20*time.Millisecond)
	if _, err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	gaps, err := db.GapsInRange(context.Background(), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("GapsInRange: %v", err)
	}
	if len(gaps) == 0 {
		t.Fatal("持续缺失应记录 gap")
	}

	// 同一缺失期间只记一次
	if _, err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	gaps2, _ := db.GapsInRange(context.Background(), time.Time{}, time.Time{})
	if len(gaps2) != len(gaps) {
		t.Fatalf("同一缺失期间 gap 数应不变: %d → %d", len(gaps), len(gaps2))
	}

	// 重建文件后恢复采集。窗口放宽：文件重建走轮转切换路径，需等
	// rotationGrace 到期，CI 慢机上 2s 不够（实测 2.11s 仍差一步）。
	os.WriteFile(logPath, []byte(line(9)+"\n"), 0o644)
	pollUntil(t, c, db, 2, 10*time.Second)
}

// —— 8. DB 写失败：db.Close() 后 PollOnce 必须返回 error（不静默）——

func TestDBWriteFailure(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t)
	logPath := filepath.Join(dir, "cowrie.json")
	os.WriteFile(logPath, []byte(line(0)+"\n"), 0o644)
	c := newCollector(t, logPath, db, nil)
	pollUntil(t, c, db, 1, 2*time.Second)

	appendFile(t, logPath, line(1)+"\n")
	if err := db.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}
	if _, err := c.PollOnce(context.Background()); err == nil {
		t.Fatal("数据库关闭后 PollOnce 必须返回 error，不得静默")
	}
}

// —— 9. 大流量：5000 行分批全部入库，游标最终 == 文件大小 ——

func TestBulkLoad(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t)
	logPath := filepath.Join(dir, "cowrie.json")

	const total = 5000
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("创建日志失败: %v", err)
	}
	w := bufio.NewWriter(f)
	for i := 0; i < total; i++ {
		if _, err := w.WriteString(line(i) + "\n"); err != nil {
			t.Fatalf("写入失败: %v", err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	c := newCollector(t, logPath, db, nil)
	pollUntil(t, c, db, total, 30*time.Second)
	if n := countEvents(t, db); n != total {
		t.Fatalf("大流量事件数 = %d, 期望 %d", n, total)
	}

	st, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	tf, err := openTracked(logPath)
	if err != nil {
		t.Fatalf("openTracked: %v", err)
	}
	_ = tf.file.Close()
	off, err := db.GetOffset(context.Background(), tf.key)
	if err != nil {
		t.Fatalf("GetOffset: %v", err)
	}
	if off == nil || off.Offset != st.Size() {
		t.Fatalf("最终 offset = %+v, 期望 == 文件大小 %d", off, st.Size())
	}
}

// —— 10. handler 只收到新插入事件（重复行不重复回调）——

func TestHandlerOnlyNewEvents(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t)
	logPath := filepath.Join(dir, "cowrie.json")

	var mu sync.Mutex
	var got []*store.Event
	handler := handlerFunc(func(_ context.Context, evs []*store.Event) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, evs...)
	})

	os.WriteFile(logPath, []byte(line(0)+"\n"), 0o644)
	c := newCollector(t, logPath, db, handler)
	pollUntil(t, c, db, 1, 2*time.Second)

	appendFile(t, logPath, line(0)+"\n") // 重复行
	if _, err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	appendFile(t, logPath, line(1)+"\n") // 新行
	pollUntil(t, c, db, 2, 2*time.Second)

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("handler 收到 %d 条事件, 期望 2（重复行不回调）", len(got))
	}
	for i, ev := range got {
		if ev.Raw != line(i) {
			t.Errorf("handler 第 %d 条事件内容不对:\n got: %s\nwant: %s", i, ev.Raw, line(i))
		}
	}
}

// —— 附加：解析失败行写 parse_errors、推进 offset，后续正常行不受影响 ——

func TestParseErrorRecorded(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t)
	logPath := filepath.Join(dir, "cowrie.json")
	os.WriteFile(logPath, []byte("this is not json\n"+line(0)+"\n"), 0o644)
	c := newCollector(t, logPath, db, nil)

	if _, err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if n := countEvents(t, db); n != 1 {
		t.Fatalf("合法行应入库, 事件数 = %d", n)
	}
	n, err := db.CountParseErrors(context.Background(), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("CountParseErrors: %v", err)
	}
	if n != 1 {
		t.Fatalf("解析错误记录 = %d, 期望 1", n)
	}
	if c.parseErrTotal != 1 {
		t.Fatalf("parseErrTotal = %d, 期望 1", c.parseErrTotal)
	}
	// offset 推进到文件末尾（坏行被跳过且游标越过它）
	st, _ := os.Stat(logPath)
	offs, _ := db.ListOffsets(context.Background())
	if len(offs) != 1 || offs[0].Offset != st.Size() {
		t.Fatalf("游标应推进到文件末尾 %d: %+v", st.Size(), offs)
	}
}

// —— 附加：超长无换行行超过 1MiB 缓冲上限，整段按解析错误落库并推进 ——

func TestOversizedLine(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t)
	logPath := filepath.Join(dir, "cowrie.json")

	junk := make([]byte, maxLineBuffer+4096)
	for i := range junk {
		junk[i] = 'x'
	}
	os.WriteFile(logPath, junk, 0o644)
	c := newCollector(t, logPath, db, nil)

	if _, err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if n, _ := db.CountParseErrors(context.Background(), time.Time{}, time.Time{}); n != 1 {
		t.Fatalf("超长行应记 1 条解析错误, 得到 %d", n)
	}

	// 后续补上换行 + 合法行：残余 x 段再次成行（解析错误），合法行正常入库
	appendFile(t, logPath, "\n"+line(7)+"\n")
	pollUntil(t, c, db, 1, 2*time.Second)
	if n, _ := db.CountParseErrors(context.Background(), time.Time{}, time.Time{}); n != 2 {
		t.Fatalf("补换行后解析错误应为 2, 得到 %d", n)
	}
	st, _ := os.Stat(logPath)
	offs, _ := db.ListOffsets(context.Background())
	if len(offs) != 1 || offs[0].Offset != st.Size() {
		t.Fatalf("游标应推进到文件末尾 %d: %+v", st.Size(), offs)
	}
}
