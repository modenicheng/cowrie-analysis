package scheduler

import (
	"testing"
	"time"
)

// mustLoc 加载时区，失败即终止测试。
func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatalf("加载时区 %s 失败: %v", name, err)
	}
	return loc
}

// assertWindow 断言窗口两端精确等于期望值、长度正确，且两端均为
// 自然日零点（左闭右开的边界值）。期望值用同一 loc 的 time.Date 构造，
// Equal 比较时间点，Location 比较携带的时区。
func assertWindow(t *testing.T, since, until, expSince, expUntil time.Time, wantLen time.Duration, loc *time.Location) {
	t.Helper()
	if !since.Equal(expSince) {
		t.Fatalf("since = %s，期望 %s", since, expSince)
	}
	if !until.Equal(expUntil) {
		t.Fatalf("until = %s，期望 %s", until, expUntil)
	}
	if got := until.Sub(since); got != wantLen {
		t.Fatalf("窗口长度 = %v，期望 %v", got, wantLen)
	}
	if !since.Before(until) {
		t.Fatalf("窗口非法：since %s 不早于 until %s", since, until)
	}
	for name, ts := range map[string]time.Time{"since": since, "until": until} {
		if ts.Hour() != 0 || ts.Minute() != 0 || ts.Second() != 0 || ts.Nanosecond() != 0 {
			t.Fatalf("%s（%s）不是自然日零点", name, ts)
		}
		if ts.Location() != loc {
			t.Fatalf("%s 携带时区 %v，期望 %v", name, ts.Location(), loc)
		}
	}
}

// assertWeekday 是测试日期的星期假设守卫：假设错误时给出清晰失败信息，
// 避免后续断言产生误导性输出。
func assertWeekday(t *testing.T, y int, m time.Month, d int, want time.Weekday) {
	t.Helper()
	if got := time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Weekday(); got != want {
		t.Fatalf("测试日期假设错误：%d-%02d-%02d 是 %v，不是 %v", y, m, d, got, want)
	}
}

func TestWindowForDailyShanghai(t *testing.T) {
	loc := mustLoc(t, "Asia/Shanghai")
	// 常规日：日报触发时刻 2026-10-22 08:00（周四）→ 窗口为昨日整天。
	now := time.Date(2026, 10, 22, 8, 0, 0, 0, loc)
	since, until, err := WindowFor(KindDaily, now, loc)
	if err != nil {
		t.Fatalf("WindowFor(daily) 报错: %v", err)
	}
	assertWindow(t, since, until,
		time.Date(2026, 10, 21, 0, 0, 0, 0, loc),
		time.Date(2026, 10, 22, 0, 0, 0, 0, loc),
		24*time.Hour, loc)
}

func TestWindowForDailyAtMidnight(t *testing.T) {
	loc := mustLoc(t, "Asia/Shanghai")
	// now 恰为当天零点：窗口仍为昨日整天（左端＝前一日 00:00，
	// 右端＝now 所在日 00:00，不包含 now 时刻当天的任何事件）。
	now := time.Date(2026, 10, 22, 0, 0, 0, 0, loc)
	since, until, err := WindowFor(KindDaily, now, loc)
	if err != nil {
		t.Fatalf("WindowFor(daily) 报错: %v", err)
	}
	assertWindow(t, since, until,
		time.Date(2026, 10, 21, 0, 0, 0, 0, loc),
		time.Date(2026, 10, 22, 0, 0, 0, 0, loc),
		24*time.Hour, loc)
	if !until.Equal(now) {
		t.Fatalf("零点触发时 until 应等于 now：%s != %s", until, now)
	}
}

func TestWindowForDailyMonthAndYearBoundary(t *testing.T) {
	loc := mustLoc(t, "Asia/Shanghai")
	cases := []struct {
		now                time.Time
		expSince, expUntil time.Time
	}{
		{
			// 2026-03-01（周日），前一天为 2026-02-28（2026 非闰年）。
			now:      time.Date(2026, 3, 1, 0, 30, 0, 0, loc),
			expSince: time.Date(2026, 2, 28, 0, 0, 0, 0, loc),
			expUntil: time.Date(2026, 3, 1, 0, 0, 0, 0, loc),
		},
		{
			// 跨年：2026-01-01 → [2025-12-31, 2026-01-01)。
			now:      time.Date(2026, 1, 1, 12, 0, 0, 0, loc),
			expSince: time.Date(2025, 12, 31, 0, 0, 0, 0, loc),
			expUntil: time.Date(2026, 1, 1, 0, 0, 0, 0, loc),
		},
		{
			// 一天之内的任意时刻（含毫秒）都归到同一自然日窗口。
			now:      time.Date(2026, 10, 22, 23, 59, 59, 999999999, loc),
			expSince: time.Date(2026, 10, 21, 0, 0, 0, 0, loc),
			expUntil: time.Date(2026, 10, 22, 0, 0, 0, 0, loc),
		},
	}
	for i, c := range cases {
		since, until, err := WindowFor(KindDaily, c.now, loc)
		if err != nil {
			t.Fatalf("case %d: WindowFor(daily) 报错: %v", i, err)
		}
		assertWindow(t, since, until, c.expSince, c.expUntil, 24*time.Hour, loc)
	}
}

func TestWindowForDailyUTC(t *testing.T) {
	// UTC 时区常规日。
	now := time.Date(2026, 10, 22, 3, 0, 0, 0, time.UTC)
	since, until, err := WindowFor(KindDaily, now, time.UTC)
	if err != nil {
		t.Fatalf("WindowFor(daily, UTC) 报错: %v", err)
	}
	assertWindow(t, since, until,
		time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC),
		24*time.Hour, time.UTC)
}

func TestWindowForDailyConvertsNowToLoc(t *testing.T) {
	loc := mustLoc(t, "Asia/Shanghai")
	// now 携带 UTC，但窗口必须按 loc＝上海计算：
	// 2026-10-22T02:00Z 即北京时间 2026-10-22 10:00 → 窗口为北京时间的昨日。
	now := time.Date(2026, 10, 22, 2, 0, 0, 0, time.UTC)
	since, until, err := WindowFor(KindDaily, now, loc)
	if err != nil {
		t.Fatalf("WindowFor(daily) 报错: %v", err)
	}
	assertWindow(t, since, until,
		time.Date(2026, 10, 21, 0, 0, 0, 0, loc),
		time.Date(2026, 10, 22, 0, 0, 0, 0, loc),
		24*time.Hour, loc)
}

func TestWindowForWeeklyMondayCrossYear(t *testing.T) {
	loc := mustLoc(t, "Asia/Shanghai")
	assertWeekday(t, 2026, time.January, 5, time.Monday)
	// 2026-01-05 是周一：本周一＝2026-01-05，窗口为上一整周，
	// since 落在上一年（2025-12-29 也恰为周一）。
	now := time.Date(2026, 1, 5, 8, 15, 0, 0, loc)
	since, until, err := WindowFor(KindWeekly, now, loc)
	if err != nil {
		t.Fatalf("WindowFor(weekly) 报错: %v", err)
	}
	assertWindow(t, since, until,
		time.Date(2025, 12, 29, 0, 0, 0, 0, loc),
		time.Date(2026, 1, 5, 0, 0, 0, 0, loc),
		7*24*time.Hour, loc)
}

func TestWindowForWeeklySunday(t *testing.T) {
	loc := mustLoc(t, "Asia/Shanghai")
	assertWeekday(t, 2026, time.October, 25, time.Sunday)
	// 2026-10-25 是周日：ISO 星期＝7，本周一仍为 2026-10-19，
	// 窗口＝[2026-10-12, 2026-10-19)。
	now := time.Date(2026, 10, 25, 23, 59, 59, 0, loc)
	since, until, err := WindowFor(KindWeekly, now, loc)
	if err != nil {
		t.Fatalf("WindowFor(weekly) 报错: %v", err)
	}
	assertWindow(t, since, until,
		time.Date(2026, 10, 12, 0, 0, 0, 0, loc),
		time.Date(2026, 10, 19, 0, 0, 0, 0, loc),
		7*24*time.Hour, loc)
}

func TestWindowForWeeklyWednesday(t *testing.T) {
	loc := mustLoc(t, "Asia/Shanghai")
	assertWeekday(t, 2026, time.October, 21, time.Wednesday)
	// 2026-10-21 是周三：本周一＝2026-10-19，窗口同上一自然周。
	now := time.Date(2026, 10, 21, 8, 15, 0, 0, loc)
	since, until, err := WindowFor(KindWeekly, now, loc)
	if err != nil {
		t.Fatalf("WindowFor(weekly) 报错: %v", err)
	}
	assertWindow(t, since, until,
		time.Date(2026, 10, 12, 0, 0, 0, 0, loc),
		time.Date(2026, 10, 19, 0, 0, 0, 0, loc),
		7*24*time.Hour, loc)
}

func TestWindowForWeeklyUTC(t *testing.T) {
	assertWeekday(t, 2026, time.October, 21, time.Wednesday)
	// UTC 时区：周三 00:15 → [2026-10-12T00:00Z, 2026-10-19T00:00Z)。
	now := time.Date(2026, 10, 21, 0, 15, 0, 0, time.UTC)
	since, until, err := WindowFor(KindWeekly, now, time.UTC)
	if err != nil {
		t.Fatalf("WindowFor(weekly, UTC) 报错: %v", err)
	}
	assertWindow(t, since, until,
		time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC),
		7*24*time.Hour, time.UTC)
}

func TestWindowForInvalidKind(t *testing.T) {
	for _, kind := range []string{"monthly", "", "Daily", "WEEKLY", "yearly"} {
		if _, _, err := WindowFor(kind, time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC), time.UTC); err == nil {
			t.Fatalf("kind=%q 应返回错误", kind)
		}
	}
}

func TestWindowForNilLoc(t *testing.T) {
	for _, kind := range []string{KindDaily, KindWeekly} {
		if _, _, err := WindowFor(kind, time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC), nil); err == nil {
			t.Fatalf("kind=%q 且 loc=nil 应返回错误", kind)
		}
	}
}

func TestPrevWindow(t *testing.T) {
	loc := mustLoc(t, "Asia/Shanghai")
	// 日窗口：前一窗口恰为再前一个自然日。
	since := time.Date(2026, 10, 21, 0, 0, 0, 0, loc)
	until := time.Date(2026, 10, 22, 0, 0, 0, 0, loc)
	ps, pu := PrevWindow(since, until)
	if !ps.Equal(time.Date(2026, 10, 20, 0, 0, 0, 0, loc)) || !pu.Equal(since) {
		t.Fatalf("日窗口 PrevWindow = [%s, %s)，期望 [2026-10-20 00:00, 2026-10-21 00:00)", ps, pu)
	}
	if pu.Sub(ps) != 24*time.Hour {
		t.Fatalf("日窗口 PrevWindow 长度 = %v，期望 24h", pu.Sub(ps))
	}

	// 周窗口：前一窗口为上上个自然周（周一零点对齐）。
	since = time.Date(2026, 10, 12, 0, 0, 0, 0, loc)
	until = time.Date(2026, 10, 19, 0, 0, 0, 0, loc)
	ps, pu = PrevWindow(since, until)
	if !ps.Equal(time.Date(2026, 10, 5, 0, 0, 0, 0, loc)) || !pu.Equal(since) {
		t.Fatalf("周窗口 PrevWindow = [%s, %s)，期望 [2026-10-05 00:00, 2026-10-12 00:00)", ps, pu)
	}
	if pu.Sub(ps) != 7*24*time.Hour {
		t.Fatalf("周窗口 PrevWindow 长度 = %v，期望 168h", pu.Sub(ps))
	}

	// 任意长度窗口（纯算术，不依赖自然日）：6 小时窗口前移 6 小时。
	a := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	b := a.Add(6 * time.Hour)
	ps, pu = PrevWindow(a, b)
	if !ps.Equal(a.Add(-6*time.Hour)) || !pu.Equal(a) {
		t.Fatalf("6h 窗口 PrevWindow = [%s, %s)，期望 [%s, %s)", ps, pu, a.Add(-6*time.Hour), a)
	}
}

// TestWindowForMatchesPrevWindow 验证 WindowFor 产出的窗口可直接喂给
// PrevWindow 得到紧邻前一同长窗口（趋势对比口径一致）。
func TestWindowForMatchesPrevWindow(t *testing.T) {
	loc := mustLoc(t, "Asia/Shanghai")
	now := time.Date(2026, 10, 22, 8, 0, 0, 0, loc)

	since, until, err := WindowFor(KindDaily, now, loc)
	if err != nil {
		t.Fatalf("WindowFor(daily) 报错: %v", err)
	}
	ps, pu := PrevWindow(since, until)
	if !ps.Equal(since.Add(-24*time.Hour)) || !pu.Equal(since) {
		t.Fatalf("daily 前窗 = [%s, %s)，期望 [%s, %s)", ps, pu, since.Add(-24*time.Hour), since)
	}

	ws, wu, err := WindowFor(KindWeekly, now, loc)
	if err != nil {
		t.Fatalf("WindowFor(weekly) 报错: %v", err)
	}
	ps, pu = PrevWindow(ws, wu)
	if !ps.Equal(ws.Add(-7*24*time.Hour)) || !pu.Equal(ws) {
		t.Fatalf("weekly 前窗 = [%s, %s)，期望 [%s, %s)", ps, pu, ws.Add(-7*24*time.Hour), ws)
	}
}
