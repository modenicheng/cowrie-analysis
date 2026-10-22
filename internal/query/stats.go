package query

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/modenc/e3-security-analyst/internal/cowrie"
	"github.com/modenc/e3-security-analyst/internal/store"
)

// 统计涉及的事件 ID。常量事件沿用 internal/cowrie 契约；
// 失败变体与 cowrie.Classify 中的字面量保持一致。
const (
	eventFileDownloadFailed = "cowrie.session.file_download.failed"
	eventFileUploadFailed   = "cowrie.session.file_upload.failed"
)

const (
	defaultTopN = 10   // StatsQuery.TopN <= 0 时的默认值
	maxTopN     = 50   // TopN 钳制上限
	maxBuckets  = 1000 // Hourly/Daily 桶数量上限（防长窗口无界输出）
)

// maxValueRunes 是 TopCommands/TopUsernames 展示值的截断长度（rune 数）；
// 完整原值保留在 events.raw 中，截断以省略号标记。
const maxValueRunes = 120

// KV 是通用「值 → 计数」条目。
type KV struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// SrcIPStat 是单个来源 IP 的活动分列统计。
type SrcIPStat struct {
	IP           string `json:"ip"`
	Connections  int    `json:"connections"`
	LoginFailed  int    `json:"login_failed"`
	LoginSuccess int    `json:"login_success"`
	Commands     int    `json:"commands"`
	FileOps      int    `json:"file_ops"`
}

// FileArtifact 是窗口内观察到的文件制品（filename+shasum 聚合）。
type FileArtifact struct {
	Filename  string `json:"filename"`
	Shasum    string `json:"shasum"`
	Direction string `json:"direction"` // upload | download
	Count     int    `json:"count"`
}

// PrevDelta 是紧邻统计窗口之前的同长窗口核心指标。
type PrevDelta struct {
	Connections  int `json:"connections"`
	UniqueSrcIPs int `json:"unique_src_ips"`
	LoginSuccess int `json:"login_success"`
	LoginFailed  int `json:"login_failed"`
	Commands     int `json:"commands"`
	Window       struct {
		Since time.Time `json:"since"`
		Until time.Time `json:"until"`
	} `json:"window"`
}

// QualityInfo 汇报窗口内的数据质量：解析失败、采集缺口与采集健康状态。
type QualityInfo struct {
	ParseErrors        int         `json:"parse_errors"`
	Gaps               []store.Gap `json:"gaps"`
	LastEventAt        *time.Time  `json:"last_event_at"`
	LastReadAt         *time.Time  `json:"last_read_at"`
	LastCollectorError string      `json:"last_collector_error"`
}

// Stats 是 query_stats 返回的确定性统计结果；所有数值均来自 SQL 聚合，
// 不存在估算路径。
type Stats struct {
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`

	EventsTotal  int `json:"events_total"`
	Connections  int `json:"connections"`
	UniqueSrcIPs int `json:"unique_src_ips"`
	LoginSuccess int `json:"login_success"`
	LoginFailed  int `json:"login_failed"`

	TopSrcIPs    []SrcIPStat `json:"top_src_ips"`
	TopUsernames []KV        `json:"top_usernames"` // 登录尝试用户名（原值）
	TopCommands  []KV        `json:"top_commands"`  // 命令（原值，超长截断）
	EventKinds   []KV        `json:"event_kinds"`   // eventid 分布

	SessionsTotal        int     `json:"sessions_total"`
	SessionsWithCommands int     `json:"sessions_with_commands"`
	AvgSessionSeconds    float64 `json:"avg_session_seconds"`
	MaxSessionSeconds    float64 `json:"max_session_seconds"`

	Uploads        int `json:"uploads"`
	Downloads      int `json:"downloads"`
	DownloadFailed int `json:"download_failed"`

	Artifacts []FileArtifact `json:"artifacts"`

	Hourly []KV `json:"hourly"` // UTC 桶 "2006-01-02T15"
	Daily  []KV `json:"daily"`  // UTC 桶 "2006-01-02"

	// 分指标趋势桶（多序列折线图用），键格式同 Hourly/Daily；仅含
	// 计数 > 0 的桶，全窗口补零由展示层（chartimg）负责。
	HourlyConnections  []KV `json:"hourly_connections,omitempty"`
	HourlyLoginFailed  []KV `json:"hourly_login_failed,omitempty"`
	HourlyLoginSuccess []KV `json:"hourly_login_success,omitempty"`
	HourlyCommands     []KV `json:"hourly_commands,omitempty"`
	DailyConnections   []KV `json:"daily_connections,omitempty"`
	DailyLoginFailed   []KV `json:"daily_login_failed,omitempty"`
	DailyLoginSuccess  []KV `json:"daily_login_success,omitempty"`
	DailyCommands      []KV `json:"daily_commands,omitempty"`

	Prev    *PrevDelta  `json:"prev,omitempty"` // 紧邻前一同长窗口；不足（太早）时为 nil
	Quality QualityInfo `json:"quality"`
}

// StatsQuery 是 ComputeStats 的输入。
type StatsQuery struct {
	Since, Until time.Time
	TopN         int  // 默认 10，上限 50
	WithPrev     bool // 是否计算上一周期对比
}

// ComputeStats 对 [Since, Until) 窗口计算确定性统计。所有指标由 SQL 聚合
// 得到；窗口基于 events.event_time 文本比较（左闭右开），与 CountEvents
// 语义一致。
func ComputeStats(ctx context.Context, db *store.DB, q StatsQuery) (*Stats, error) {
	if db == nil {
		return nil, fmt.Errorf("query.ComputeStats: db 为 nil")
	}
	if q.Since.IsZero() || q.Until.IsZero() {
		return nil, fmt.Errorf("query.ComputeStats: Since/Until 不能为零值")
	}
	if !q.Until.After(q.Since) {
		return nil, fmt.Errorf("query.ComputeStats: 窗口非法（Until <= Since）")
	}
	since, until := q.Since.UTC(), q.Until.UTC()
	topN := q.TopN
	if topN <= 0 {
		topN = defaultTopN
	}
	if topN > maxTopN {
		topN = maxTopN
	}
	sdb := db.SQL()

	core, err := queryCoreCounts(ctx, sdb, since, until)
	if err != nil {
		return nil, fmt.Errorf("query.ComputeStats: 核心计数失败: %w", err)
	}
	st := &Stats{
		Since:          since,
		Until:          until,
		EventsTotal:    core.eventsTotal,
		Connections:    core.connections,
		UniqueSrcIPs:   core.uniqueSrcIPs,
		LoginSuccess:   core.loginSuccess,
		LoginFailed:    core.loginFailed,
		Uploads:        core.uploads,
		Downloads:      core.downloads,
		DownloadFailed: core.downloadFailed,
		TopSrcIPs:      []SrcIPStat{},
		TopUsernames:   []KV{},
		TopCommands:    []KV{},
		EventKinds:     []KV{},
		Artifacts:      []FileArtifact{},
		Hourly:         []KV{},
		Daily:          []KV{},
	}

	if err := computeTopSrcIPs(ctx, sdb, since, until, topN, st); err != nil {
		return nil, fmt.Errorf("query.ComputeStats: %w", err)
	}
	if err := computeTopValues(ctx, sdb, since, until, topN, st); err != nil {
		return nil, fmt.Errorf("query.ComputeStats: %w", err)
	}
	if err := computeSessions(ctx, sdb, since, until, st); err != nil {
		return nil, fmt.Errorf("query.ComputeStats: %w", err)
	}
	if err := computeArtifacts(ctx, sdb, since, until, topN, st); err != nil {
		return nil, fmt.Errorf("query.ComputeStats: %w", err)
	}
	if err := computeTrends(ctx, sdb, since, until, st); err != nil {
		return nil, fmt.Errorf("query.ComputeStats: %w", err)
	}
	if err := computePrev(ctx, sdb, since, until, q.WithPrev, st); err != nil {
		return nil, fmt.Errorf("query.ComputeStats: %w", err)
	}
	if err := computeQuality(ctx, db, since, until, st); err != nil {
		return nil, fmt.Errorf("query.ComputeStats: %w", err)
	}
	return st, nil
}

// coreCounts 汇总一个窗口内的核心计数指标，主窗口与前一窗口复用。
type coreCounts struct {
	eventsTotal, connections, uniqueSrcIPs int
	loginSuccess, loginFailed, commands    int
	uploads, downloads, downloadFailed     int
}

// queryCoreCounts 用单条聚合查询返回窗口内的全部核心计数；
// 空窗口时 SUM 为 NULL，统一 COALESCE 为 0。
func queryCoreCounts(ctx context.Context, sdb *sql.DB, since, until time.Time) (coreCounts, error) {
	row := sdb.QueryRowContext(ctx, `SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN event_id = ? THEN 1 ELSE 0 END), 0),
			COUNT(DISTINCT src_ip),
			COALESCE(SUM(CASE WHEN event_id = ? THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN event_id = ? THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN event_id = ? THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN event_id = ? THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN event_id = ? THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN event_id = ? THEN 1 ELSE 0 END), 0)
		FROM events
		WHERE event_time >= ? AND event_time < ?`,
		cowrie.EventConnect, cowrie.EventLoginSuccess, cowrie.EventLoginFailed,
		cowrie.EventCommandInput, cowrie.EventFileUpload, cowrie.EventFileDownload,
		eventFileDownloadFailed, fmtTime(since), fmtTime(until))
	var c coreCounts
	if err := row.Scan(&c.eventsTotal, &c.connections, &c.uniqueSrcIPs,
		&c.loginSuccess, &c.loginFailed, &c.commands,
		&c.uploads, &c.downloads, &c.downloadFailed); err != nil {
		return c, err
	}
	return c, nil
}

// windowConds 返回窗口 WHERE 片段与参数（左闭右开，文本比较）。
func windowConds(since, until time.Time) (string, []any) {
	return "event_time >= ? AND event_time < ?", []any{fmtTime(since), fmtTime(until)}
}

// computeTopSrcIPs 计算来源 IP 排名：GROUP BY src_ip，connections 降序、
// IP 升序决胜；分列均为 SUM CASE 计数，file_ops 含上传/下载及其失败变体
// （与 store 会话聚合的 file_ops 口径一致）。
func computeTopSrcIPs(ctx context.Context, sdb *sql.DB, since, until time.Time, topN int, st *Stats) error {
	win, winArgs := windowConds(since, until)
	rows, err := sdb.QueryContext(ctx, `SELECT src_ip,
			COALESCE(SUM(CASE WHEN event_id = ? THEN 1 ELSE 0 END), 0) AS connections,
			COALESCE(SUM(CASE WHEN event_id = ? THEN 1 ELSE 0 END), 0) AS login_failed,
			COALESCE(SUM(CASE WHEN event_id = ? THEN 1 ELSE 0 END), 0) AS login_success,
			COALESCE(SUM(CASE WHEN event_id = ? THEN 1 ELSE 0 END), 0) AS commands,
			COALESCE(SUM(CASE WHEN event_id IN (?, ?, ?, ?) THEN 1 ELSE 0 END), 0) AS file_ops
		FROM events
		WHERE `+win+` AND src_ip IS NOT NULL AND src_ip != ''
		GROUP BY src_ip
		ORDER BY connections DESC, src_ip ASC
		LIMIT ?`,
		append([]any{cowrie.EventConnect, cowrie.EventLoginFailed, cowrie.EventLoginSuccess,
			cowrie.EventCommandInput, cowrie.EventFileUpload, cowrie.EventFileDownload,
			eventFileDownloadFailed, eventFileUploadFailed}, append(winArgs, topN)...)...)
	if err != nil {
		return fmt.Errorf("TopSrcIPs 查询失败: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var s SrcIPStat
		if err := rows.Scan(&s.IP, &s.Connections, &s.LoginFailed,
			&s.LoginSuccess, &s.Commands, &s.FileOps); err != nil {
			return fmt.Errorf("TopSrcIPs 读取行失败: %w", err)
		}
		st.TopSrcIPs = append(st.TopSrcIPs, s)
	}
	return rows.Err()
}

// computeTopValues 计算 TopUsernames（登录尝试，失败+成功）、TopCommands
// 与 EventKinds（eventid 全分布）。Usernames/Commands 按 rune 截断到
// maxValueRunes 并加省略标记，完整原值保留在 events.raw。
func computeTopValues(ctx context.Context, sdb *sql.DB, since, until time.Time, topN int, st *Stats) error {
	win, winArgs := windowConds(since, until)

	kvs, err := queryKVs(ctx, sdb, `SELECT username, COUNT(*) AS n
		FROM events
		WHERE `+win+` AND event_id IN (?, ?)
		  AND username IS NOT NULL AND username != ''
		GROUP BY username ORDER BY n DESC, username ASC LIMIT ?`,
		append(winArgs, cowrie.EventLoginFailed, cowrie.EventLoginSuccess, topN)...)
	if err != nil {
		return fmt.Errorf("TopUsernames 查询失败: %w", err)
	}
	for _, kv := range kvs {
		kv.Value = truncateRunes(kv.Value)
		st.TopUsernames = append(st.TopUsernames, kv)
	}

	kvs, err = queryKVs(ctx, sdb, `SELECT command, COUNT(*) AS n
		FROM events
		WHERE `+win+` AND event_id = ?
		  AND command IS NOT NULL AND command != ''
		GROUP BY command ORDER BY n DESC, command ASC LIMIT ?`,
		append(winArgs, cowrie.EventCommandInput, topN)...)
	if err != nil {
		return fmt.Errorf("TopCommands 查询失败: %w", err)
	}
	for _, kv := range kvs {
		kv.Value = truncateRunes(kv.Value)
		st.TopCommands = append(st.TopCommands, kv)
	}

	kvs, err = queryKVs(ctx, sdb, `SELECT event_id, COUNT(*) AS n
		FROM events
		WHERE `+win+`
		GROUP BY event_id ORDER BY n DESC, event_id ASC LIMIT ?`,
		append(winArgs, topN)...)
	if err != nil {
		return fmt.Errorf("EventKinds 查询失败: %w", err)
	}
	st.EventKinds = append(st.EventKinds, kvs...)
	return nil
}

// queryKVs 执行「值, 计数」两列查询并收集为 []KV。
func queryKVs(ctx context.Context, sdb *sql.DB, q string, args ...any) ([]KV, error) {
	rows, err := sdb.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []KV
	for rows.Next() {
		var kv KV
		if err := rows.Scan(&kv.Value, &kv.Count); err != nil {
			return nil, err
		}
		out = append(out, kv)
	}
	return out, rows.Err()
}

// truncateRunes 把超长展示值截断到 maxValueRunes 个 rune 并追加省略标记；
// 未超长时原样返回。
func truncateRunes(s string) string {
	r := []rune(s)
	if len(r) <= maxValueRunes {
		return s
	}
	return string(r[:maxValueRunes]) + "…"
}

// computeSessions 计算会话指标：SessionsTotal 为窗口内有事件的去重会话数
// （基于 events）；SessionsWithCommands 经 sessions 表 join 取
// command_count > 0 的部分；时长统计来自 sessions.duration_s。
func computeSessions(ctx context.Context, sdb *sql.DB, since, until time.Time, st *Stats) error {
	win, winArgs := windowConds(since, until)
	sessCond := "session IS NOT NULL AND session != ''"

	if err := sdb.QueryRowContext(ctx, `SELECT COUNT(DISTINCT session) FROM events
			WHERE `+win+` AND `+sessCond, winArgs...).
		Scan(&st.SessionsTotal); err != nil {
		return fmt.Errorf("SessionsTotal 查询失败: %w", err)
	}

	if err := sdb.QueryRowContext(ctx, `SELECT COUNT(*) FROM (
			SELECT DISTINCT e.session FROM events e
			JOIN sessions s ON s.session_id = e.session
			WHERE e.event_time >= ? AND e.event_time < ? AND e.`+sessCond+`
			  AND s.command_count > 0)`, fmtTime(since), fmtTime(until)).
		Scan(&st.SessionsWithCommands); err != nil {
		return fmt.Errorf("SessionsWithCommands 查询失败: %w", err)
	}

	if err := sdb.QueryRowContext(ctx, `SELECT COALESCE(AVG(duration_s), 0), COALESCE(MAX(duration_s), 0)
			FROM sessions
			WHERE session_id IN (SELECT session FROM events
				WHERE `+win+` AND `+sessCond+`)`, winArgs...).
		Scan(&st.AvgSessionSeconds, &st.MaxSessionSeconds); err != nil {
		return fmt.Errorf("会话时长查询失败: %w", err)
	}
	return nil
}

// computeArtifacts 计算文件制品：成功上传/下载事件按 (filename, shasum,
// direction) 聚合；两者均非空才计入。失败变体不计入 Artifacts。
func computeArtifacts(ctx context.Context, sdb *sql.DB, since, until time.Time, topN int, st *Stats) error {
	win, winArgs := windowConds(since, until)
	rows, err := sdb.QueryContext(ctx, `SELECT filename, shasum,
			CASE WHEN event_id = ? THEN 'upload' ELSE 'download' END AS direction,
			COUNT(*) AS n
		FROM events
		WHERE `+win+` AND event_id IN (?, ?)
		  AND filename IS NOT NULL AND filename != ''
		  AND shasum IS NOT NULL AND shasum != ''
		GROUP BY filename, shasum, direction
		ORDER BY n DESC, filename ASC
		LIMIT ?`,
		append(append([]any{cowrie.EventFileUpload}, winArgs...),
			cowrie.EventFileUpload, cowrie.EventFileDownload, topN)...)
	if err != nil {
		return fmt.Errorf("Artifacts 查询失败: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var a FileArtifact
		if err := rows.Scan(&a.Filename, &a.Shasum, &a.Direction, &a.Count); err != nil {
			return fmt.Errorf("Artifacts 读取行失败: %w", err)
		}
		st.Artifacts = append(st.Artifacts, a)
	}
	return rows.Err()
}

// computeTrends 计算 UTC 小时/日桶分布：substr(event_time,1,13)/(,1,10)，
// 键即 "2006-01-02T15"/"2006-01-02"，按时间升序输出。
func computeTrends(ctx context.Context, sdb *sql.DB, since, until time.Time, st *Stats) error {
	win, winArgs := windowConds(since, until)
	hourly, err := queryKVs(ctx, sdb, `SELECT substr(event_time, 1, 13) AS bucket, COUNT(*) AS n
		FROM events WHERE `+win+`
		GROUP BY bucket ORDER BY bucket ASC LIMIT ?`,
		append(winArgs, maxBuckets)...)
	if err != nil {
		return fmt.Errorf("Hourly 查询失败: %w", err)
	}
	st.Hourly = append(st.Hourly, hourly...)

	daily, err := queryKVs(ctx, sdb, `SELECT substr(event_time, 1, 10) AS bucket, COUNT(*) AS n
		FROM events WHERE `+win+`
		GROUP BY bucket ORDER BY bucket ASC LIMIT ?`,
		append(winArgs, maxBuckets)...)
	if err != nil {
		return fmt.Errorf("Daily 查询失败: %w", err)
	}
	st.Daily = append(st.Daily, daily...)

	if err := computeMetricTrends(ctx, sdb, since, until, "substr(event_time, 1, 13)",
		&st.HourlyConnections, &st.HourlyLoginFailed, &st.HourlyLoginSuccess, &st.HourlyCommands); err != nil {
		return fmt.Errorf("Hourly 分指标查询失败: %w", err)
	}
	if err := computeMetricTrends(ctx, sdb, since, until, "substr(event_time, 1, 10)",
		&st.DailyConnections, &st.DailyLoginFailed, &st.DailyLoginSuccess, &st.DailyCommands); err != nil {
		return fmt.Errorf("Daily 分指标查询失败: %w", err)
	}
	return nil
}

// computeMetricTrends 按事件类型分列计算单粒度（小时/日）趋势桶：
// bucketExpr 为桶表达式，四列依次写入 conn/failed/success/commands；
// 某指标在该桶计数为 0 时不产生条目（省略语义，补零归展示层）。
// 事件口径与 queryCoreCounts 一致（connect/login.failed/login.success/
// command.input）。
func computeMetricTrends(ctx context.Context, sdb *sql.DB, since, until time.Time,
	bucketExpr string, conn, failed, success, commands *[]KV) error {
	win, winArgs := windowConds(since, until)
	args := append([]any{cowrie.EventConnect, cowrie.EventLoginFailed,
		cowrie.EventLoginSuccess, cowrie.EventCommandInput}, winArgs...)
	args = append(args, maxBuckets)
	rows, err := sdb.QueryContext(ctx, `SELECT `+bucketExpr+` AS bucket,
			SUM(CASE WHEN event_id = ? THEN 1 ELSE 0 END),
			SUM(CASE WHEN event_id = ? THEN 1 ELSE 0 END),
			SUM(CASE WHEN event_id = ? THEN 1 ELSE 0 END),
			SUM(CASE WHEN event_id = ? THEN 1 ELSE 0 END)
		FROM events WHERE `+win+`
		GROUP BY bucket ORDER BY bucket ASC LIMIT ?`, args...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var v string
		var c, f, s, m int
		if err := rows.Scan(&v, &c, &f, &s, &m); err != nil {
			return err
		}
		if c > 0 {
			*conn = append(*conn, KV{Value: v, Count: c})
		}
		if f > 0 {
			*failed = append(*failed, KV{Value: v, Count: f})
		}
		if s > 0 {
			*success = append(*success, KV{Value: v, Count: s})
		}
		if m > 0 {
			*commands = append(*commands, KV{Value: v, Count: m})
		}
	}
	return rows.Err()
}

// computePrev 计算紧邻 Since 之前的同长窗口对比；前窗开始时间早于
// 1970-01-01T00:00:00Z 时不计算（Prev=nil）。前窗无数据时 Prev 非 nil
// 但全 0。
func computePrev(ctx context.Context, sdb *sql.DB, since, until time.Time, withPrev bool, st *Stats) error {
	if !withPrev {
		return nil
	}
	prevSince := since.Add(-(until.Sub(since)))
	if prevSince.Before(time.Unix(0, 0)) {
		return nil // 前窗早于 Unix 纪元，无可比数据
	}
	pc, err := queryCoreCounts(ctx, sdb, prevSince, since)
	if err != nil {
		return fmt.Errorf("前窗计数失败: %w", err)
	}
	p := &PrevDelta{
		Connections:  pc.connections,
		UniqueSrcIPs: pc.uniqueSrcIPs,
		LoginSuccess: pc.loginSuccess,
		LoginFailed:  pc.loginFailed,
		Commands:     pc.commands,
	}
	p.Window.Since, p.Window.Until = prevSince, since
	st.Prev = p
	return nil
}

// computeQuality 收集窗口内数据质量：解析失败计数、采集缺口列表与
// 采集健康状态（最后事件/读取时间与最后错误）。
func computeQuality(ctx context.Context, db *store.DB, since, until time.Time, st *Stats) error {
	pe, err := db.CountParseErrors(ctx, since, until)
	if err != nil {
		return fmt.Errorf("统计解析失败失败: %w", err)
	}
	gaps, err := db.GapsInRange(ctx, since, until)
	if err != nil {
		return fmt.Errorf("查询采集缺口失败: %w", err)
	}
	if gaps == nil {
		gaps = []store.Gap{}
	}
	st.Quality = QualityInfo{ParseErrors: pe, Gaps: gaps}
	if h, err := db.GetHealth(ctx); err != nil {
		return fmt.Errorf("读取采集健康状态失败: %w", err)
	} else if h != nil {
		st.Quality.LastEventAt = h.LastEventAt
		st.Quality.LastReadAt = h.LastReadAt
		st.Quality.LastCollectorError = h.LastError
	}
	return nil
}
