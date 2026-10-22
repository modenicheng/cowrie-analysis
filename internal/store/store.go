// Package store 提供 SQLite 持久化层：事件索引、会话聚合、采集游标、
// 通知队列与报告/运行元数据。事件写入方为 collector；analyst 通过 SQL()
// 执行只读查询，其 daemon 另经 CleanupRetention 做保留期清理（仅删除，
// 不新增数据，见 retention.go）。
//
// 约定：时间列统一存储 UTC RFC3339Nano 文本（见 fmtTime/parseTime）；
// 所有时间范围语义为 [Since, Until) 左闭右开。
package store

import (
	"database/sql"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	// 纯 Go SQLite 驱动（无 CGO），注册驱动名 "sqlite"。
	_ "modernc.org/sqlite"
)

// DB 包装 *sql.DB。
type DB struct {
	sql *sql.DB
}

// Options 控制 SQLite 打开参数。
type Options struct {
	WAL           bool // true 时设置 journal_mode=WAL
	BusyTimeoutMs int  // busy_timeout 毫秒；<=0 时使用默认值
}

const (
	defaultBusyTimeoutMs = 5000
	maxOpenConns         = 4
)

// Open 打开（必要时创建）path 处的 SQLite 数据库：
// 确保父目录存在（0700）；DSN 以 file: URI 形式携带 per-connection PRAGMA
// （busy_timeout、foreign_keys=ON、synchronous=NORMAL，opt.WAL 时
// journal_mode=WAL）——modernc 驱动对连接池中每个新建连接逐条执行 _pragma，
// 因此这些设置对全部池连接生效，而非仅首个连接。打开后校验 PRAGMA 生效，
// 收紧库文件权限 0600，连接池上限 4。
func Open(path string, opt Options) (*DB, error) {
	if path == "" {
		return nil, fmt.Errorf("store.Open: 数据库路径为空")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("store.Open: 解析绝对路径失败: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, fmt.Errorf("store.Open: 创建目录 %s 失败: %w", filepath.Dir(abs), err)
	}

	timeout := opt.BusyTimeoutMs
	if timeout <= 0 {
		timeout = defaultBusyTimeoutMs
	}
	// DSN 采用 modernc 的 file: URI + 重复 _pragma 查询参数约定：
	// 驱动用 url.ParseQuery 解码参数值（url.Values 的百分号编码会被还原），
	// 并在每个新建连接上执行 "PRAGMA <value>"。SQLite 自身解析 URI 路径
	// （百分号解码）并忽略未知的 _pragma 查询参数。
	dsn := buildDSN(abs, timeout, opt.WAL)
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store.Open: %w", err)
	}

	// 打开后立即校验 PRAGMA 生效（同时保证连接失败尽早暴露）。
	if err := checkPragmas(sqlDB, timeout, opt.WAL); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("store.Open: %w", err)
	}
	if err := os.Chmod(abs, 0o600); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("store.Open: 收紧库文件权限 0600 失败: %w", err)
	}
	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetMaxIdleConns(maxOpenConns)
	return &DB{sql: sqlDB}, nil
}

// buildDSN 构造携带 per-connection PRAGMA 的 modernc sqlite DSN：
// file: URI + 重复的 _pragma 查询参数（url.Values 百分号编码，驱动解码后
// 在每个新建连接上执行）。busy_timeout/foreign_keys/synchronous 恒定携带，
// wal=true 时追加 journal_mode(WAL)。
func buildDSN(abs string, busyTimeout int, wal bool) string {
	q := url.Values{}
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyTimeout))
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(1)")
	if wal {
		q.Add("_pragma", "journal_mode(WAL)")
	}
	u := url.URL{
		Scheme:   "file",
		Path:     uriPath(abs),
		RawQuery: q.Encode(),
	}
	return u.String()
}

// uriPath 把绝对路径转为 file: URI 的路径段：统一正斜杠并保证以 "/" 开头。
// Windows 盘符路径必须构成 "file:///D:/..." 形式——若生成 "file://D:/..."，
// "D:" 会被 SQLite 的 URI 解析器当作非法 authority 而拒绝打开。
// 路径中的空格与非 ASCII 字符由 url.URL.String() 百分号编码，再由 SQLite 解码。
func uriPath(abs string) string {
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// checkPragmas 读取连接当前的 PRAGMA 值并校验与配置一致，
// 用于在打开阶段尽早发现 DSN _pragma 未被驱动应用的问题。
func checkPragmas(sqlDB *sql.DB, busyTimeout int, wal bool) error {
	var gotBusy int
	if err := sqlDB.QueryRow("PRAGMA busy_timeout").Scan(&gotBusy); err != nil {
		return fmt.Errorf("读取 busy_timeout 失败: %w", err)
	}
	if gotBusy != busyTimeout {
		return fmt.Errorf("busy_timeout=%d, 期望 %d（DSN _pragma 未生效）", gotBusy, busyTimeout)
	}
	var fk int
	if err := sqlDB.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil {
		return fmt.Errorf("读取 foreign_keys 失败: %w", err)
	}
	if fk != 1 {
		return fmt.Errorf("foreign_keys=%d, 期望 1（DSN _pragma 未生效）", fk)
	}
	var sync int
	if err := sqlDB.QueryRow("PRAGMA synchronous").Scan(&sync); err != nil {
		return fmt.Errorf("读取 synchronous 失败: %w", err)
	}
	if sync != 1 { // 0=OFF 1=NORMAL 2=FULL 3=EXTRA
		return fmt.Errorf("synchronous=%d, 期望 1（NORMAL）", sync)
	}
	if wal {
		var mode string
		if err := sqlDB.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
			return fmt.Errorf("读取 journal_mode 失败: %w", err)
		}
		if !strings.EqualFold(mode, "wal") {
			return fmt.Errorf("journal_mode=%q, 期望 wal", mode)
		}
	}
	return nil
}

// Close 关闭数据库。
func (db *DB) Close() error { return db.sql.Close() }

// SQL 暴露底层 *sql.DB，供 query 包执行只读查询；调用方不得借此写入。
func (db *DB) SQL() *sql.DB { return db.sql }

// Migrate 建 schema_migrations 表，并把 fsys 根目录下的 *.sql 按文件名
// 前缀数字（版本号）升序应用；每个脚本在单个事务内整体执行
// （modernc sqlite 的 Exec 支持多语句）。重复调用幂等。
func (db *DB) Migrate(fsys fs.FS) error {
	if _, err := db.sql.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		name       TEXT NOT NULL,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("store.Migrate: 创建 schema_migrations 失败: %w", err)
	}
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return fmt.Errorf("store.Migrate: 遍历迁移脚本失败: %w", err)
	}
	type migration struct {
		version int64
		name    string
	}
	migs := make([]migration, 0, len(names))
	for _, name := range names {
		v, err := migrationVersion(name)
		if err != nil {
			return fmt.Errorf("store.Migrate: %w", err)
		}
		migs = append(migs, migration{version: v, name: name})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })
	for i := 1; i < len(migs); i++ {
		if migs[i].version == migs[i-1].version {
			return fmt.Errorf("store.Migrate: 迁移脚本版本号重复: %d（%s 与 %s）",
				migs[i].version, migs[i-1].name, migs[i].name)
		}
	}
	for _, m := range migs {
		var applied int
		if err := db.sql.QueryRow(
			`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, m.version,
		).Scan(&applied); err != nil {
			return fmt.Errorf("store.Migrate: 查询版本 %d 失败: %w", m.version, err)
		}
		if applied > 0 {
			continue // 已应用，幂等跳过
		}
		script, err := fs.ReadFile(fsys, m.name)
		if err != nil {
			return fmt.Errorf("store.Migrate: 读取 %s 失败: %w", m.name, err)
		}
		if err := db.applyMigration(m.version, m.name, string(script)); err != nil {
			return fmt.Errorf("store.Migrate: %w", err)
		}
	}
	return nil
}

// applyMigration 在单个事务内执行整个迁移脚本并记录版本。
func (db *DB) applyMigration(version int64, name, script string) error {
	tx, err := db.sql.Begin()
	if err != nil {
		return fmt.Errorf("应用 %s 时开启事务失败: %w", name, err)
	}
	defer func() { _ = tx.Rollback() }() // Commit 后 Rollback 为 no-op
	if _, err := tx.Exec(script); err != nil {
		return fmt.Errorf("应用 %s 失败: %w", name, err)
	}
	if _, err := tx.Exec(
		`INSERT INTO schema_migrations(version, name, applied_at) VALUES(?,?,?)`,
		version, name, fmtTime(time.Now().UTC()),
	); err != nil {
		return fmt.Errorf("记录 %s 失败: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交 %s 失败: %w", name, err)
	}
	return nil
}

// migrationVersion 解析文件名的数字前缀作为版本号，如 "0001_init.sql" → 1。
func migrationVersion(name string) (int64, error) {
	i := 0
	for i < len(name) && name[i] >= '0' && name[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, fmt.Errorf("迁移脚本 %q 缺少数字版本前缀", name)
	}
	v, err := strconv.ParseInt(name[:i], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("迁移脚本 %q 版本号非法: %w", name, err)
	}
	return v, nil
}

// fmtTime 把时间格式化为 UTC RFC3339Nano 文本（时间列的统一存储格式）。
func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// parseTime 解析存储的时间文本，空串返回零时间。
func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("解析时间文本 %q: %w", s, err)
	}
	return t, nil
}

// fmtTimePtr 用于可空时间列：nil 或零时间写入 NULL。
func fmtTimePtr(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return fmtTime(*t)
}

// parseTimePtr 解析可空时间列；NULL 或空串返回 nil。
func parseTimePtr(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid || ns.String == "" {
		return nil, nil
	}
	t, err := parseTime(ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
