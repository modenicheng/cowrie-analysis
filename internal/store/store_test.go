package store

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"testing/fstest"
	"time"

	"github.com/modenc/e3-security-analyst/migrations"
)

// openTestDB 在临时目录中打开并迁移一个全新数据库。
func openTestDB(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data", "events.db") // 子目录测试自动建目录
	db, err := Open(path, Options{WAL: true, BusyTimeoutMs: 2000})
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(migrations.FS); err != nil {
		t.Fatalf("Migrate 失败: %v", err)
	}
	return db
}

// TestOpenAndMigrateIdempotent 覆盖：新路径自动建库建目录；Migrate 幂等
// （同一连接执行两次 + 关闭后重开再执行均不报错）；WAL 生效。
func TestOpenAndMigrateIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "sub", "events.db")
	db, err := Open(path, Options{WAL: true, BusyTimeoutMs: 1500})
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := db.Migrate(migrations.FS); err != nil {
			t.Fatalf("第 %d 次 Migrate 失败: %v", i+1, err)
		}
	}
	var mode string
	if err := db.SQL().QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("读取 journal_mode 失败: %v", err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %q, 期望 wal", mode)
	}
	var versions int
	if err := db.SQL().QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&versions); err != nil {
		t.Fatalf("查询 schema_migrations 失败: %v", err)
	}
	if versions != 2 { // 0001_init + 0002_retention
		t.Fatalf("schema_migrations 记录数 = %d, 期望 2", versions)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}

	// 重开已有库：迁移幂等，表仍在。
	db2, err := Open(path, Options{WAL: true, BusyTimeoutMs: 1500})
	if err != nil {
		t.Fatalf("重新 Open 失败: %v", err)
	}
	defer func() { _ = db2.Close() }()
	if err := db2.Migrate(migrations.FS); err != nil {
		t.Fatalf("重开后 Migrate 失败: %v", err)
	}
	for _, table := range []string{"events", "sessions", "collector_offsets",
		"collector_health", "collector_gaps", "parse_errors", "notifications",
		"reports", "analysis_runs", "script_runs"} {
		var n int
		if err := db2.SQL().QueryRow(
			`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n); err != nil {
			t.Fatalf("查询表 %s 失败: %v", table, err)
		}
		if n != 1 {
			t.Errorf("表 %s 不存在", table)
		}
	}
}

// TestMigrateOrderingAndValidation：按版本号（而非字典序）应用、
// 后续脚本可依赖前面的对象；缺少数字前缀的脚本报错。
// 夹具版本号避开 1/2（已被 0001/0002 占用——Migrate 按版本号幂等跳过，
// 撞号会导致脚本被静默跳过）。
func TestMigrateOrderingAndValidation(t *testing.T) {
	fsys := fstest.MapFS{
		"20_b.sql": &fstest.MapFile{Data: []byte(`INSERT INTO mig_log VALUES('b');`)},
		"3_a.sql":  &fstest.MapFile{Data: []byte(`CREATE TABLE mig_log (name TEXT); INSERT INTO mig_log VALUES('a');`)},
	}
	db := openTestDB(t)
	if err := db.Migrate(fsys); err != nil {
		t.Fatalf("Migrate 失败: %v", err)
	}
	var applied int
	if err := db.SQL().QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&applied); err != nil {
		t.Fatalf("查询 schema_migrations 失败: %v", err)
	}
	if applied != 4 { // 0001 + 0002 + 3 + 20
		t.Fatalf("schema_migrations 记录数 = %d, 期望 4", applied)
	}
	// 幂等：再执行一次不重复应用。
	if err := db.Migrate(fsys); err != nil {
		t.Fatalf("重复 Migrate 失败: %v", err)
	}
	if err := db.Migrate(fstest.MapFS{
		"bad.sql": &fstest.MapFile{Data: []byte("SELECT 1;")},
	}); err == nil {
		t.Fatal("缺少数字前缀的迁移脚本应报错")
	}
}

// TestTimeHelpers 校证时间辅助的往返一致性。
func TestTimeHelpers(t *testing.T) {
	ts := []time.Time{
		time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 10, 21, 12, 34, 56, 123456789, time.UTC),
		time.Date(2026, 10, 21, 8, 0, 0, 0, time.FixedZone("CST", 8*3600)),
	}
	for _, in := range ts {
		got, err := parseTime(fmtTime(in))
		if err != nil {
			t.Fatalf("parseTime(%q) 失败: %v", fmtTime(in), err)
		}
		if !got.Equal(in) {
			t.Errorf("时间往返不一致: got %v want %v", got, in)
		}
		if got.Location() != time.UTC {
			t.Errorf("parseTime 应返回 UTC, got %v", got.Location())
		}
	}
}

// TestBuildDSN 锁定 DSN 最终形态：file: URI + 百分号编码的 _pragma 参数。
func TestBuildDSN(t *testing.T) {
	got := buildDSN("/tmp/a b/c.db", 5000, true)
	want := "file:///tmp/a%20b/c.db" +
		"?_pragma=busy_timeout%285000%29" +
		"&_pragma=foreign_keys%281%29" +
		"&_pragma=synchronous%281%29" +
		"&_pragma=journal_mode%28WAL%29"
	if got != want {
		t.Errorf("DSN 形态变化:\n got  %s\n want %s", got, want)
	}

	got = buildDSN("/tmp/x.db", 1000, false)
	want = "file:///tmp/x.db" +
		"?_pragma=busy_timeout%281000%29" +
		"&_pragma=foreign_keys%281%29" +
		"&_pragma=synchronous%281%29"
	if got != want {
		t.Errorf("无 WAL DSN 形态变化:\n got  %s\n want %s", got, want)
	}

	// Windows 盘符路径必须生成 file:///D:/...（而非 file://D:/...，后者会被
	// SQLite 判为非法 authority）；空格与非 ASCII 经百分号编码。
	if runtime.GOOS == "windows" {
		got = buildDSN(`D:\data dir\事件.db`, 2000, true)
		want = "file:///D:/data%20dir/%E4%BA%8B%E4%BB%B6.db" +
			"?_pragma=busy_timeout%282000%29" +
			"&_pragma=foreign_keys%281%29" +
			"&_pragma=synchronous%281%29" +
			"&_pragma=journal_mode%28WAL%29"
		if got != want {
			t.Errorf("Windows DSN 形态变化:\n got  %s\n want %s", got, want)
		}
	}
}

var _ fs.FS = fstest.MapFS{} // 保证 fstest 实现 fs.FS（编译期自检）

// TestOpenPragmasApplyToEveryPooledConnection 回归测试：DSN _pragma 必须作用于
// 池中每个连接，而非仅首个连接。做法：4 个 goroutine 同时持有未关闭的查询结果
// （一个连接同一时刻只能服务一个打开的 Rows），从而强制连接池创建满 4 个连接；
// 每个 goroutine 在自己独占的连接上读取 PRAGMA 并校验。
func TestOpenPragmasApplyToEveryPooledConnection(t *testing.T) {
	const busyTimeout = 2345 // 特异值：若未生效则为默认 0
	db, err := Open(filepath.Join(t.TempDir(), "events.db"),
		Options{WAL: true, BusyTimeoutMs: busyTimeout})
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Migrate(migrations.FS); err != nil {
		t.Fatalf("Migrate 失败: %v", err)
	}

	const workers = maxOpenConns // 与连接池上限一致
	started := make(chan struct{}, workers)
	release := make(chan struct{})
	type result struct {
		busyTimeout int
		foreignKeys int
		journalMode string
	}
	results := make(chan result, workers)
	errCh := make(chan error, workers)

	for i := 0; i < workers; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			rows, qerr := db.SQL().QueryContext(ctx, "PRAGMA busy_timeout")
			if qerr != nil {
				errCh <- qerr
				return
			}
			var r result
			if !rows.Next() {
				errCh <- fmt.Errorf("PRAGMA busy_timeout 无结果行")
				_ = rows.Close()
				return
			}
			if serr := rows.Scan(&r.busyTimeout); serr != nil {
				errCh <- serr
				_ = rows.Close()
				return
			}
			started <- struct{}{} // Rows 保持打开：独占一个池连接
			<-release
			_ = rows.Close()
			if serr := db.SQL().QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&r.foreignKeys); serr != nil {
				errCh <- serr
				return
			}
			if serr := db.SQL().QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&r.journalMode); serr != nil {
				errCh <- serr
				return
			}
			results <- r
		}()
	}
	for i := 0; i < workers; i++ {
		select {
		case <-started:
		case qerr := <-errCh:
			t.Fatalf("worker 查询失败: %v", qerr)
		}
	}
	close(release)
	for i := 0; i < workers; i++ {
		select {
		case r := <-results:
			if r.busyTimeout != busyTimeout {
				t.Errorf("池连接 busy_timeout=%d, 期望 %d", r.busyTimeout, busyTimeout)
			}
			if r.foreignKeys != 1 {
				t.Errorf("池连接 foreign_keys=%d, 期望 1", r.foreignKeys)
			}
			if r.journalMode != "wal" {
				t.Errorf("池连接 journal_mode=%q, 期望 wal", r.journalMode)
			}
		case qerr := <-errCh:
			t.Fatalf("worker 失败: %v", qerr)
		}
	}
}

// TestOpenPathWithSpacesAndUnicode：路径含空格与非 ASCII（中文）时，
// file: URI 的编码/解码往返正确——库文件必须落在原始路径上，
// 且建库/迁移/插入/计数全链路正常（Windows 真实场景）。
func TestOpenPathWithSpacesAndUnicode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cowrie logs 数据目录", "events 数据库.db")
	db, err := Open(path, Options{WAL: true, BusyTimeoutMs: 1500})
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Migrate(migrations.FS); err != nil {
		t.Fatalf("Migrate 失败: %v", err)
	}

	ctx := context.Background()
	evs := []*Event{
		mkEvent("cowrie.session.connect", testBase, "s1", "203.0.113.7", `{"ev":1}`),
		mkEvent("cowrie.login.failed", testBase.Add(time.Second), "s1", "203.0.113.7", `{"ev":2}`),
	}
	if inserted, _, ierr := db.InsertEvents(ctx, evs); ierr != nil || inserted != 2 {
		t.Fatalf("InsertEvents: inserted=%d err=%v", inserted, ierr)
	}
	if n, cerr := db.CountEvents(ctx, EventFilter{Since: testBase, Until: testBase.Add(time.Minute)}); cerr != nil || n != 2 {
		t.Fatalf("CountEvents = %d (err %v), 期望 2", n, cerr)
	}
	// 库文件必须创建在原始路径（URI 解码未偏离目标位置）。
	if _, serr := os.Stat(path); serr != nil {
		t.Fatalf("库文件未在预期路径 %s 创建: %v", path, serr)
	}
}
