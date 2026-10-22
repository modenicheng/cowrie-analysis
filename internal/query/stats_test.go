package query

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/modenc/e3-security-analyst/internal/cowrie"
	"github.com/modenc/e3-security-analyst/internal/store"
)

func mustStats(t *testing.T, db *store.DB, q StatsQuery) *Stats {
	t.Helper()
	st, err := ComputeStats(context.Background(), db, q)
	if err != nil {
		t.Fatalf("ComputeStats 失败: %v", err)
	}
	return st
}

// TestStatsWindowBoundaries：统计窗口左闭右开——等于 Since 计入、
// 等于 Until 不计入；Since/Until 原样（UTC）回填到结果。
func TestStatsWindowBoundaries(t *testing.T) {
	db := openTestDB(t)
	w0 := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	w1 := w0.Add(24 * time.Hour)

	mustInsert(t, db,
		ev(cowrie.EventConnect, w0),                  // == Since：计入
		ev(cowrie.EventConnect, w0.Add(time.Second)), // 窗口内
		ev(cowrie.EventConnect, w1),                  // == Until：排除
	)
	st := mustStats(t, db, StatsQuery{Since: w0, Until: w1})
	if st.EventsTotal != 2 || st.Connections != 2 {
		t.Errorf("EventsTotal=%d Connections=%d, 期望 2/2", st.EventsTotal, st.Connections)
	}
	if st.UniqueSrcIPs != 1 {
		t.Errorf("UniqueSrcIPs=%d, 期望 1", st.UniqueSrcIPs)
	}
	if !st.Since.Equal(w0) || !st.Until.Equal(w1) {
		t.Errorf("窗口回填错误: since=%v until=%v", st.Since, st.Until)
	}
	if st.Prev != nil {
		t.Errorf("WithPrev=false 时 Prev 应为 nil, got %+v", st.Prev)
	}
}

// TestStatsInvalidWindow：零值边界与倒置窗口返回错误。
func TestStatsInvalidWindow(t *testing.T) {
	db := openTestDB(t)
	w0 := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		q    StatsQuery
	}{
		{"Since 零值", StatsQuery{Until: w0}},
		{"Until 零值", StatsQuery{Since: w0}},
		{"倒置窗口", StatsQuery{Since: w0, Until: w0}},
	}
	for _, tc := range cases {
		if _, err := ComputeStats(context.Background(), db, tc.q); err == nil {
			t.Errorf("%s: 期望返回错误", tc.name)
		}
	}
}

// TestStatsBeijingWindow：北京时间 2026-10-21 全天窗口换算为 UTC 后，
// +08:00 边界两侧事件归属正确（16:00Z 前一天计入、次日 16:00Z 排除）。
func TestStatsBeijingWindow(t *testing.T) {
	db := openTestDB(t)
	cst := time.FixedZone("CST", 8*3600)
	since := time.Date(2026, 10, 21, 0, 0, 0, 0, cst) // = 2026-10-20T16:00:00Z
	until := time.Date(2026, 10, 22, 0, 0, 0, 0, cst) // = 2026-10-21T16:00:00Z

	mustInsert(t, db,
		withIP(ev(cowrie.EventConnect, since.Add(-time.Second)), "1.1.1.1"), // 前一秒：排除
		withIP(ev(cowrie.EventConnect, since), "1.1.1.1"),                   // == Since：计入
		withIP(ev(cowrie.EventConnect, until.Add(-time.Second)), "2.2.2.2"), // 末秒：计入
		withIP(ev(cowrie.EventConnect, until), "3.3.3.3"),                   // == Until：排除
	)
	st := mustStats(t, db, StatsQuery{Since: since, Until: until})
	if st.EventsTotal != 2 || st.Connections != 2 {
		t.Errorf("EventsTotal=%d Connections=%d, 期望 2/2", st.EventsTotal, st.Connections)
	}
	if st.UniqueSrcIPs != 2 {
		t.Errorf("UniqueSrcIPs=%d, 期望 2（1.1.1.1 与 2.2.2.2）", st.UniqueSrcIPs)
	}
	// UTC 桶归属：两个事件分别落在 2026-10-20T16 与 2026-10-21T15。
	if len(st.Hourly) != 2 || st.Hourly[0].Value != "2026-10-20T16" || st.Hourly[0].Count != 1 ||
		st.Hourly[1].Value != "2026-10-21T15" || st.Hourly[1].Count != 1 {
		t.Errorf("Hourly 桶错误: %+v", st.Hourly)
	}
	if len(st.Daily) != 2 || st.Daily[0].Value != "2026-10-20" || st.Daily[1].Value != "2026-10-21" {
		t.Errorf("Daily 桶错误: %+v", st.Daily)
	}
	if !st.Since.Equal(since) || !st.Until.Equal(until) {
		t.Errorf("窗口回填错误: since=%v until=%v", st.Since, st.Until)
	}
}

// TestStatsTopSrcIPs：3 个 IP 不同连接数——去重数、排名与分列正确；
// 同连接数按 IP 升序决胜。
func TestStatsTopSrcIPs(t *testing.T) {
	db := openTestDB(t)
	w0 := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	w1 := w0.Add(24 * time.Hour)
	ipA, ipB, ipC := "198.51.100.10", "198.51.100.11", "198.51.100.12"

	var seed []*store.Event
	at := w0.Add(time.Minute)
	for i := 0; i < 3; i++ { // A：3 连接 + 2 失败 + 1 命令 + 1 上传
		seed = append(seed, withIP(ev(cowrie.EventConnect, at.Add(time.Duration(i)*time.Second)), ipA))
	}
	for i := 0; i < 2; i++ {
		e := withIP(ev(cowrie.EventLoginFailed, at.Add(time.Duration(10+i)*time.Second)), ipA)
		e.Username = "root"
		seed = append(seed, e)
	}
	cmd := withIP(ev(cowrie.EventCommandInput, at.Add(20*time.Second)), ipA)
	cmd.Command = "uname -a"
	seed = append(seed, cmd)
	up := withIP(ev(cowrie.EventFileUpload, at.Add(21*time.Second)), ipA)
	up.Filename, up.Shasum = "a.sh", "aaa"
	seed = append(seed, up)

	for i := 0; i < 2; i++ { // B：2 连接 + 1 成功
		seed = append(seed, withIP(ev(cowrie.EventConnect, at.Add(time.Duration(30+i)*time.Second)), ipB))
	}
	ok := withIP(ev(cowrie.EventLoginSuccess, at.Add(40*time.Second)), ipB)
	ok.Username = "admin"
	seed = append(seed, ok)

	seed = append(seed, withIP(ev(cowrie.EventConnect, at.Add(50*time.Second)), ipC)) // C：1 连接
	mustInsert(t, db, seed...)

	st := mustStats(t, db, StatsQuery{Since: w0, Until: w1})
	if st.UniqueSrcIPs != 3 {
		t.Fatalf("UniqueSrcIPs=%d, 期望 3", st.UniqueSrcIPs)
	}
	if len(st.TopSrcIPs) != 3 {
		t.Fatalf("TopSrcIPs 长度 = %d, 期望 3: %+v", len(st.TopSrcIPs), st.TopSrcIPs)
	}
	want := []SrcIPStat{
		{IP: ipA, Connections: 3, LoginFailed: 2, LoginSuccess: 0, Commands: 1, FileOps: 1},
		{IP: ipB, Connections: 2, LoginFailed: 0, LoginSuccess: 1, Commands: 0, FileOps: 0},
		{IP: ipC, Connections: 1, LoginFailed: 0, LoginSuccess: 0, Commands: 0, FileOps: 0},
	}
	for i, w := range want {
		if st.TopSrcIPs[i] != w {
			t.Errorf("TopSrcIPs[%d] = %+v, 期望 %+v", i, st.TopSrcIPs[i], w)
		}
	}
}

// TestStatsLoginCountsAndUsernames：成功/失败计数与用户名排名
// （尝试次数 = 失败 + 成功，同数按用户名升序）。
func TestStatsLoginCountsAndUsernames(t *testing.T) {
	db := openTestDB(t)
	w0 := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	w1 := w0.Add(24 * time.Hour)

	login := func(ok bool, user string, at time.Time) *store.Event {
		id := cowrie.EventLoginFailed
		if ok {
			id = cowrie.EventLoginSuccess
		}
		e := ev(id, at)
		e.Username = user
		return e
	}
	var seed []*store.Event
	for i := 0; i < 3; i++ { // root：3 次失败
		seed = append(seed, login(false, "root", w0.Add(time.Duration(i)*time.Second)))
	}
	seed = append(seed, login(false, "admin", w0.Add(10*time.Second))) // admin：1 失败 + 1 成功
	seed = append(seed, login(true, "admin", w0.Add(11*time.Second)))
	seed = append(seed, login(true, "test", w0.Add(12*time.Second))) // test：2 成功
	seed = append(seed, login(true, "test", w0.Add(13*time.Second)))
	// 无用户名的登录事件不参与 TopUsernames，但计入计数。
	seed = append(seed, login(false, "", w0.Add(14*time.Second)))
	mustInsert(t, db, seed...)

	st := mustStats(t, db, StatsQuery{Since: w0, Until: w1})
	if st.LoginFailed != 5 || st.LoginSuccess != 3 {
		t.Fatalf("LoginFailed=%d LoginSuccess=%d, 期望 5/3", st.LoginFailed, st.LoginSuccess)
	}
	want := []KV{{Value: "root", Count: 3}, {Value: "admin", Count: 2}, {Value: "test", Count: 2}}
	if len(st.TopUsernames) != len(want) {
		t.Fatalf("TopUsernames = %+v, 期望 %+v", st.TopUsernames, want)
	}
	for i, w := range want {
		if st.TopUsernames[i] != w {
			t.Errorf("TopUsernames[%d] = %+v, 期望 %+v", i, st.TopUsernames[i], w)
		}
	}
}

// TestStatsSessions：窗口内会话去重、命令会话数与时长统计
// （sessions 聚合由 InsertEvents 维护）；窗口外会话不计入。
func TestStatsSessions(t *testing.T) {
	db := openTestDB(t)
	w0 := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	w1 := w0.Add(24 * time.Hour)

	closed := func(sess string, at time.Time, dur float64) *store.Event {
		e := withSession(ev(cowrie.EventSessionClosed, at), sess)
		e.DurationS = dur
		return e
	}
	cmdEv := func(sess string, at time.Time, c string) *store.Event {
		e := withSession(ev(cowrie.EventCommandInput, at), sess)
		e.Command = c
		return e
	}
	var seed []*store.Event
	// sessA：connect + command + closed(30s)
	seed = append(seed,
		withSession(ev(cowrie.EventConnect, w0.Add(time.Minute)), "sessA"),
		cmdEv("sessA", w0.Add(2*time.Minute), "ls"),
		closed("sessA", w0.Add(3*time.Minute), 30),
	)
	// sessB：connect + closed(90s)，无命令
	seed = append(seed,
		withSession(ev(cowrie.EventConnect, w0.Add(time.Hour)), "sessB"),
		closed("sessB", w0.Add(2*time.Hour), 90),
	)
	// sessC：全部事件在窗口外
	seed = append(seed,
		withSession(ev(cowrie.EventConnect, w0.Add(-time.Hour)), "sessC"),
		cmdEv("sessC", w0.Add(-50*time.Minute), "wget x"),
		closed("sessC", w0.Add(-40*time.Minute), 600),
	)
	mustInsert(t, db, seed...)

	st := mustStats(t, db, StatsQuery{Since: w0, Until: w1})
	if st.SessionsTotal != 2 {
		t.Errorf("SessionsTotal=%d, 期望 2（sessC 在窗口外）", st.SessionsTotal)
	}
	if st.SessionsWithCommands != 1 {
		t.Errorf("SessionsWithCommands=%d, 期望 1（仅 sessA）", st.SessionsWithCommands)
	}
	if st.AvgSessionSeconds != 60 || st.MaxSessionSeconds != 90 {
		t.Errorf("Avg=%v Max=%v, 期望 60/90", st.AvgSessionSeconds, st.MaxSessionSeconds)
	}
}

// TestStatsCommandTruncation：超过 120 rune 的命令截断并加省略标记
// （按 rune 而非字节截断）；未超长命令保持原值。
func TestStatsCommandTruncation(t *testing.T) {
	db := openTestDB(t)
	w0 := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	w1 := w0.Add(24 * time.Hour)

	long := strings.Repeat("安", 125) // 多字节 rune，验证按 rune 截断
	var seed []*store.Event
	for i := 0; i < 2; i++ {
		e := ev(cowrie.EventCommandInput, w0.Add(time.Duration(i)*time.Second))
		e.Command = long
		seed = append(seed, e)
	}
	for i := 0; i < 3; i++ {
		e := ev(cowrie.EventCommandInput, w0.Add(time.Duration(10+i)*time.Second))
		e.Command = "ls"
		seed = append(seed, e)
	}
	mustInsert(t, db, seed...)

	st := mustStats(t, db, StatsQuery{Since: w0, Until: w1})
	if len(st.TopCommands) != 2 {
		t.Fatalf("TopCommands = %+v, 期望 2 条", st.TopCommands)
	}
	if st.TopCommands[0].Value != "ls" || st.TopCommands[0].Count != 3 {
		t.Errorf("TopCommands[0] = %+v, 期望 {ls 3}", st.TopCommands[0])
	}
	got := st.TopCommands[1]
	want := strings.Repeat("安", maxValueRunes) + "…"
	if got.Value != want {
		t.Errorf("截断值不符: got %d rune, want %d rune", len([]rune(got.Value)), len([]rune(want)))
	}
	if got.Count != 2 {
		t.Errorf("截断命令计数 = %d, 期望 2", got.Count)
	}
	if rs := []rune(got.Value); len(rs) != maxValueRunes+1 || !strings.HasSuffix(got.Value, "…") {
		t.Errorf("截断结果应为 %d rune + 省略标记, got %d rune", maxValueRunes, len(rs))
	}
}

// TestStatsHourlyDailyBuckets：跨小时/跨日事件按 UTC 桶正确分组，键按时间升序。
func TestStatsHourlyDailyBuckets(t *testing.T) {
	db := openTestDB(t)
	d := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)

	mustInsert(t, db,
		ev(cowrie.EventConnect, d.Add(10*time.Hour+30*time.Minute)),
		ev(cowrie.EventConnect, d.Add(10*time.Hour+59*time.Minute+59*time.Second)), // 仍属 T10 桶
		ev(cowrie.EventConnect, d.Add(11*time.Hour)),                               // 恰好进入 T11 桶
		ev(cowrie.EventConnect, d.Add(24*time.Hour)),                               // 次日 00:00，属次日桶
	)
	st := mustStats(t, db, StatsQuery{Since: d, Until: d.Add(48 * time.Hour)})

	wantH := []KV{
		{Value: "2026-10-21T10", Count: 2},
		{Value: "2026-10-21T11", Count: 1},
		{Value: "2026-10-22T00", Count: 1},
	}
	if len(st.Hourly) != len(wantH) {
		t.Fatalf("Hourly = %+v, 期望 %+v", st.Hourly, wantH)
	}
	for i, w := range wantH {
		if st.Hourly[i] != w {
			t.Errorf("Hourly[%d] = %+v, 期望 %+v", i, st.Hourly[i], w)
		}
	}
	wantD := []KV{
		{Value: "2026-10-21", Count: 3},
		{Value: "2026-10-22", Count: 1},
	}
	if len(st.Daily) != len(wantD) {
		t.Fatalf("Daily = %+v, 期望 %+v", st.Daily, wantD)
	}
	for i, w := range wantD {
		if st.Daily[i] != w {
			t.Errorf("Daily[%d] = %+v, 期望 %+v", i, st.Daily[i], w)
		}
	}
}

// TestStatsMetricTrendBuckets：分指标趋势桶按事件类型分列（connect/
// login.failed/login.success/command.input），零计数的桶不产生条目；
// 全零序列序列化为空（omitempty）。
func TestStatsMetricTrendBuckets(t *testing.T) {
	db := openTestDB(t)
	d := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	mustInsert(t, db,
		ev(cowrie.EventConnect, d),
		ev(cowrie.EventConnect, d.Add(time.Hour)),
		ev(cowrie.EventLoginFailed, d),
		ev(cowrie.EventLoginFailed, d.Add(time.Minute)),
		ev(cowrie.EventCommandInput, d.Add(2*time.Hour)),
		ev(cowrie.EventFileUpload, d.Add(3*time.Hour)), // 其他类型：四个序列均不计数
	)
	st := mustStats(t, db, StatsQuery{Since: d, Until: d.Add(24 * time.Hour)})

	assertKVs := func(name string, got []KV, want []KV) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s = %+v, 期望 %+v", name, got, want)
		}
		for i, w := range want {
			if got[i] != w {
				t.Errorf("%s[%d] = %+v, 期望 %+v", name, i, got[i], w)
			}
		}
	}
	assertKVs("HourlyConnections", st.HourlyConnections,
		[]KV{{Value: "2026-10-21T00", Count: 1}, {Value: "2026-10-21T01", Count: 1}})
	assertKVs("HourlyLoginFailed", st.HourlyLoginFailed,
		[]KV{{Value: "2026-10-21T00", Count: 2}})
	assertKVs("HourlyLoginSuccess", st.HourlyLoginSuccess, nil)
	assertKVs("HourlyCommands", st.HourlyCommands,
		[]KV{{Value: "2026-10-21T02", Count: 1}})
	assertKVs("DailyConnections", st.DailyConnections,
		[]KV{{Value: "2026-10-21", Count: 2}})
	assertKVs("DailyLoginFailed", st.DailyLoginFailed,
		[]KV{{Value: "2026-10-21", Count: 2}})

	// omitempty：无成功登录 → 分指标序列键不出现在 JSON 中
	//（顶层标量 login_success 仍在）。
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("Marshal 失败: %v", err)
	}
	if strings.Contains(string(b), "hourly_login_success") ||
		strings.Contains(string(b), "daily_login_success") {
		t.Errorf("全零序列应被省略，实际 JSON:\n%s", b)
	}
}

// TestStatsFileArtifacts：上传/下载/下载失败计数与 Artifacts 聚合
// （filename+shasum+方向+次数）；失败变体不进入 Artifacts。
func TestStatsFileArtifacts(t *testing.T) {
	db := openTestDB(t)
	w0 := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	w1 := w0.Add(24 * time.Hour)

	fileEv := func(id, name, sum string, at time.Time) *store.Event {
		e := ev(id, at)
		e.Filename, e.Shasum = name, sum
		return e
	}
	var seed []*store.Event
	for i := 0; i < 2; i++ { // mal.sh 上传两次
		seed = append(seed, fileEv(cowrie.EventFileUpload, "mal.sh", "abc123",
			w0.Add(time.Duration(i)*time.Minute)))
	}
	seed = append(seed, fileEv(cowrie.EventFileDownload, "tool.tar", "def456", w0.Add(5*time.Minute)))
	// 失败下载即使带 filename+shasum 也不计入 Artifacts。
	seed = append(seed, fileEv(eventFileDownloadFailed, "bad.bin", "000", w0.Add(6*time.Minute)))
	// 缺 shasum 的上传不满足“均非空”，不计入。
	seed = append(seed, fileEv(cowrie.EventFileUpload, "nosum.sh", "", w0.Add(7*time.Minute)))
	mustInsert(t, db, seed...)

	st := mustStats(t, db, StatsQuery{Since: w0, Until: w1})
	if st.Uploads != 3 || st.Downloads != 1 || st.DownloadFailed != 1 {
		t.Fatalf("Uploads=%d Downloads=%d DownloadFailed=%d, 期望 3/1/1",
			st.Uploads, st.Downloads, st.DownloadFailed)
	}
	want := []FileArtifact{
		{Filename: "mal.sh", Shasum: "abc123", Direction: "upload", Count: 2},
		{Filename: "tool.tar", Shasum: "def456", Direction: "download", Count: 1},
	}
	if len(st.Artifacts) != len(want) {
		t.Fatalf("Artifacts = %+v, 期望 %+v", st.Artifacts, want)
	}
	for i, w := range want {
		if st.Artifacts[i] != w {
			t.Errorf("Artifacts[%d] = %+v, 期望 %+v", i, st.Artifacts[i], w)
		}
	}
}

// TestStatsPrevWindow：前一同长窗口有数据 → 数值正确；无数据 → 非 nil 全 0；
// 前窗早于 1970 → nil。
func TestStatsPrevWindow(t *testing.T) {
	db := openTestDB(t)
	d1 := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	d2 := d1.Add(24 * time.Hour)
	d3 := d2.Add(24 * time.Hour)
	d5 := d3.Add(48 * time.Hour)
	d6 := d5.Add(24 * time.Hour)

	// 前窗 [d1,d2)：2 连接（2 IP）、1 成功、3 失败、4 命令
	//（登录/命令事件同属 1.1.1.1，前窗独立 IP 共 2 个）。
	var seed []*store.Event
	seed = append(seed,
		withIP(ev(cowrie.EventConnect, d1.Add(time.Minute)), "1.1.1.1"),
		withIP(ev(cowrie.EventConnect, d1.Add(2*time.Minute)), "2.2.2.2"),
	)
	ok := ev(cowrie.EventLoginSuccess, d1.Add(3*time.Minute))
	ok.Username, ok.SrcIP = "admin", "1.1.1.1"
	seed = append(seed, ok)
	for i := 0; i < 3; i++ {
		f := ev(cowrie.EventLoginFailed, d1.Add(time.Duration(4+i)*time.Minute))
		f.Username, f.SrcIP = "root", "1.1.1.1"
		seed = append(seed, f)
	}
	for i := 0; i < 4; i++ {
		c := ev(cowrie.EventCommandInput, d1.Add(time.Duration(8+i)*time.Minute))
		c.Command, c.SrcIP = "ls", "1.1.1.1"
		seed = append(seed, c)
	}
	// 主窗 [d2,d3)：5 连接。
	for i := 0; i < 5; i++ {
		seed = append(seed, withIP(ev(cowrie.EventConnect, d2.Add(time.Duration(i)*time.Minute)), "9.9.9.9"))
	}
	mustInsert(t, db, seed...)

	st := mustStats(t, db, StatsQuery{Since: d2, Until: d3, WithPrev: true})
	if st.Prev == nil {
		t.Fatal("有前窗数据时 Prev 不应为 nil")
	}
	if st.Prev.Connections != 2 || st.Prev.UniqueSrcIPs != 2 ||
		st.Prev.LoginSuccess != 1 || st.Prev.LoginFailed != 3 || st.Prev.Commands != 4 {
		t.Errorf("Prev = %+v, 期望 {2 2 1 3 4}", *st.Prev)
	}
	if !st.Prev.Window.Since.Equal(d1) || !st.Prev.Window.Until.Equal(d2) {
		t.Errorf("Prev.Window = [%v, %v), 期望 [%v, %v)",
			st.Prev.Window.Since, st.Prev.Window.Until, d1, d2)
	}
	if st.Connections != 5 {
		t.Errorf("主窗 Connections = %d, 期望 5", st.Connections)
	}

	// 前窗无数据：Prev 非 nil 且全 0。
	empty := mustStats(t, db, StatsQuery{Since: d5, Until: d6, WithPrev: true})
	if empty.Prev == nil {
		t.Fatal("无前窗数据时 Prev 仍应为非 nil（全 0）")
	}
	if empty.Prev.Connections != 0 || empty.Prev.UniqueSrcIPs != 0 ||
		empty.Prev.LoginSuccess != 0 || empty.Prev.LoginFailed != 0 || empty.Prev.Commands != 0 {
		t.Errorf("空前窗 Prev = %+v, 期望全 0", *empty.Prev)
	}

	// 窗口太早：前窗开始时间 < 1970-01-01 → Prev = nil。
	earlySince := time.Date(1970, 1, 1, 6, 0, 0, 0, time.UTC)
	early := mustStats(t, db, StatsQuery{Since: earlySince, Until: earlySince.Add(12 * time.Hour), WithPrev: true})
	if early.Prev != nil {
		t.Errorf("前窗早于 1970 时 Prev 应为 nil, got %+v", early.Prev)
	}
}

// TestStatsQuality：窗口内 parse_error 计数、gap 列表与采集健康状态。
func TestStatsQuality(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	w0 := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	w1 := w0.Add(24 * time.Hour)

	mustInsert(t, db, ev(cowrie.EventConnect, w0.Add(time.Minute)))
	for i, raw := range []string{"bad1", "bad2"} {
		if err := db.InsertParseError(ctx, &store.ParseErrorRecord{
			FilePath: "cowrie.json", FileOffset: int64(100 + i),
			Raw: raw, Err: "invalid json", At: w0.Add(time.Duration(1+i) * time.Minute),
		}); err != nil {
			t.Fatalf("InsertParseError 失败: %v", err)
		}
	}
	if err := db.InsertParseError(ctx, &store.ParseErrorRecord{
		Raw: "bad3", Err: "invalid json", At: w1.Add(time.Minute), // 窗口外
	}); err != nil {
		t.Fatalf("InsertParseError 失败: %v", err)
	}
	if err := db.AddGap(ctx, w0.Add(-time.Hour), w0.Add(30*time.Minute), "log-missing"); err != nil {
		t.Fatalf("AddGap 失败: %v", err)
	}
	if err := db.AddGap(ctx, w1.Add(time.Hour), w1.Add(2*time.Hour), "later"); err != nil {
		t.Fatalf("AddGap 失败: %v", err) // 窗口外
	}
	lastAt := w0.Add(3 * time.Hour)
	if err := db.UpdateHealth(ctx, &store.Health{
		LastEventAt: &lastAt, LastReadAt: &lastAt, LastError: "disk slow",
	}); err != nil {
		t.Fatalf("UpdateHealth 失败: %v", err)
	}

	st := mustStats(t, db, StatsQuery{Since: w0, Until: w1})
	q := st.Quality
	if q.ParseErrors != 2 {
		t.Errorf("ParseErrors=%d, 期望 2", q.ParseErrors)
	}
	if len(q.Gaps) != 1 || q.Gaps[0].Reason != "log-missing" {
		t.Errorf("Gaps = %+v, 期望仅 log-missing 一条", q.Gaps)
	}
	if q.LastCollectorError != "disk slow" {
		t.Errorf("LastCollectorError=%q, 期望 %q", q.LastCollectorError, "disk slow")
	}
	if q.LastEventAt == nil || !q.LastEventAt.Equal(lastAt) {
		t.Errorf("LastEventAt=%v, 期望 %v", q.LastEventAt, lastAt)
	}
	if q.LastReadAt == nil || !q.LastReadAt.Equal(lastAt) {
		t.Errorf("LastReadAt=%v, 期望 %v", q.LastReadAt, lastAt)
	}
}

// TestStatsTopNClamp：TopN=100 钳制为 50；TopN<=0 使用默认 10。
func TestStatsTopNClamp(t *testing.T) {
	db := openTestDB(t)
	w0 := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	w1 := w0.Add(24 * time.Hour)

	var seed []*store.Event
	for i := 0; i < 55; i++ {
		e := ev(cowrie.EventLoginFailed, w0.Add(time.Duration(i)*time.Second))
		e.Username = fmt.Sprintf("user%02d", i)
		seed = append(seed, e)
	}
	mustInsert(t, db, seed...)

	clamped := mustStats(t, db, StatsQuery{Since: w0, Until: w1, TopN: 100})
	if len(clamped.TopUsernames) != maxTopN {
		t.Errorf("TopN=100 时条目数 = %d, 期望钳制为 %d", len(clamped.TopUsernames), maxTopN)
	}
	def := mustStats(t, db, StatsQuery{Since: w0, Until: w1, TopN: 0})
	if len(def.TopUsernames) != defaultTopN {
		t.Errorf("TopN=0 时条目数 = %d, 期望默认 %d", len(def.TopUsernames), defaultTopN)
	}
	// 钳制不影响 EventKinds 等其余指标的正确性。
	if len(clamped.EventKinds) != 1 || clamped.EventKinds[0].Value != cowrie.EventLoginFailed ||
		clamped.EventKinds[0].Count != 55 {
		t.Errorf("EventKinds = %+v, 期望 [{%s 55}]", clamped.EventKinds, cowrie.EventLoginFailed)
	}
}

// TestStatsEmptyWindow：空窗口返回全零与非 nil 空切片，不报错。
func TestStatsEmptyWindow(t *testing.T) {
	db := openTestDB(t)
	w0 := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	w1 := w0.Add(24 * time.Hour)

	st := mustStats(t, db, StatsQuery{Since: w0, Until: w1})
	if st.EventsTotal != 0 || st.Connections != 0 || st.UniqueSrcIPs != 0 ||
		st.LoginSuccess != 0 || st.LoginFailed != 0 ||
		st.SessionsTotal != 0 || st.SessionsWithCommands != 0 ||
		st.Uploads != 0 || st.Downloads != 0 || st.DownloadFailed != 0 ||
		st.AvgSessionSeconds != 0 || st.MaxSessionSeconds != 0 {
		t.Errorf("空窗口应为全零, got %+v", st)
	}
	if st.TopSrcIPs == nil || st.TopUsernames == nil || st.TopCommands == nil ||
		st.EventKinds == nil || st.Artifacts == nil || st.Hourly == nil || st.Daily == nil {
		t.Error("空窗口切片应为非 nil（JSON 序列化为 []）")
	}
	if len(st.TopSrcIPs)+len(st.TopUsernames)+len(st.TopCommands)+
		len(st.EventKinds)+len(st.Artifacts)+len(st.Hourly)+len(st.Daily) != 0 {
		t.Error("空窗口各列表应为空")
	}
	if st.Quality.Gaps == nil {
		t.Error("Quality.Gaps 应为非 nil 空切片")
	}
}

// TestStatsJSONTags：契约 JSON tag 逐字段校验（snake_case，Prev 缺省省略）。
func TestStatsJSONTags(t *testing.T) {
	db := openTestDB(t)
	w0 := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	w1 := w0.Add(24 * time.Hour)
	mustInsert(t, db,
		withIP(ev(cowrie.EventConnect, w0), "1.2.3.4"),
		withIP(ev(cowrie.EventLoginFailed, w0.Add(time.Second)), "1.2.3.4"),
	)
	st := mustStats(t, db, StatsQuery{Since: w0, Until: w1, WithPrev: true})

	b, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("Marshal 失败: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal 失败: %v", err)
	}
	for _, key := range []string{
		"since", "until", "events_total", "connections", "unique_src_ips",
		"login_success", "login_failed", "top_src_ips", "top_usernames",
		"top_commands", "event_kinds", "sessions_total", "sessions_with_commands",
		"avg_session_seconds", "max_session_seconds", "uploads", "downloads",
		"download_failed", "artifacts", "hourly", "daily", "prev", "quality",
		"hourly_connections",
	} {
		if _, ok := m[key]; !ok {
			t.Errorf("Stats JSON 缺少键 %q", key)
		}
	}
	srcIP := st.TopSrcIPs[0]
	sb, _ := json.Marshal(srcIP)
	for _, key := range []string{"ip", "connections", "login_failed", "login_success", "commands", "file_ops"} {
		if !strings.Contains(string(sb), `"`+key+`":`) {
			t.Errorf("SrcIPStat JSON 缺少键 %q: %s", key, sb)
		}
	}
	qb, _ := json.Marshal(st.Quality)
	for _, key := range []string{"parse_errors", "gaps", "last_event_at", "last_read_at", "last_collector_error"} {
		if !strings.Contains(string(qb), `"`+key+`":`) {
			t.Errorf("QualityInfo JSON 缺少键 %q: %s", key, qb)
		}
	}
	pb, _ := json.Marshal(st.Prev)
	for _, key := range []string{"connections", "unique_src_ips", "login_success", "login_failed", "commands", "window"} {
		if !strings.Contains(string(pb), `"`+key+`":`) {
			t.Errorf("PrevDelta JSON 缺少键 %q: %s", key, pb)
		}
	}
	// 空列表应序列化为 [] 而非 null（指针字段为 null 属预期）。
	for _, frag := range []string{
		`"top_usernames":[]`, `"top_commands":[]`, `"artifacts":[]`,
		`"quality":{"parse_errors":0,"gaps":[]`,
	} {
		if !strings.Contains(string(b), frag) {
			t.Errorf("空列表应序列化为 []: 缺少 %s\n%s", frag, b)
		}
	}
	// WithPrev=false 时 prev 键省略。
	noPrev := mustStats(t, db, StatsQuery{Since: w0, Until: w1})
	nb, _ := json.Marshal(noPrev)
	if strings.Contains(string(nb), `"prev"`) {
		t.Error("WithPrev=false 时不应输出 prev 键")
	}
}
