package chartimg

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/modenc/e3-security-analyst/internal/query"
)

// pngMagic 是 PNG 文件头前 4 字节。
var pngMagic = []byte{0x89, 'P', 'N', 'G'}

// 常用测试时区：用 FixedZone 构造，避免依赖系统 tzdata。
var (
	shanghai = time.FixedZone("UTC+8", 8*3600)
	kolkata  = time.FixedZone("IST", 5*3600+30*60)  // 非整小时偏移 +05:30
	laPDT    = time.FixedZone("PDT", -7*3600)       // 负向整点偏移
	newfound = time.FixedZone("NST", -3*3600-30*60) // 负向非整小时偏移
)

// dailyStats 构造一个有数据的日报统计窗口（UTC 时间轴，与 ComputeStats
// 输出一致），展示时区按 loc 解释。
func dailyStats() *query.Stats {
	return &query.Stats{
		Since:       time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC),
		Until:       time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC),
		Connections: 57,
		Hourly: []query.KV{
			{Value: "2026-10-21T00", Count: 5},
			{Value: "2026-10-21T07", Count: 3},
			{Value: "2026-10-21T15", Count: 12},
			{Value: "2026-10-21T23", Count: 1},
		},
		TopSrcIPs: []query.SrcIPStat{
			{IP: "203.0.113.7", Connections: 22},
			{IP: "198.51.100.4", Connections: 15},
			{IP: "192.0.2.99", Connections: 9},
		},
	}
}

// weeklyStats 构造一个有数据的周报统计窗口。
func weeklyStats() *query.Stats {
	return &query.Stats{
		Since:       time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC),
		Until:       time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC),
		Connections: 210,
		Daily: []query.KV{
			{Value: "2026-10-13", Count: 30},
			{Value: "2026-10-15", Count: 80},
			{Value: "2026-10-19", Count: 45},
		},
		TopSrcIPs: []query.SrcIPStat{
			{IP: "203.0.113.7", Connections: 90},
			{IP: "198.51.100.4", Connections: 60},
		},
	}
}

// assertValidPNG 断言 data 是合法 PNG 且宽高 > 0。
func assertValidPNG(t *testing.T, data []byte) {
	t.Helper()
	if !bytes.HasPrefix(data, pngMagic) {
		t.Fatalf("output missing PNG magic bytes, prefix = % x", data[:min(8, len(data))])
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("png.DecodeConfig() error = %v, want nil", err)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		t.Errorf("decoded size = %dx%d, want positive", cfg.Width, cfg.Height)
	}
}

// 1. daily/weekly 均产出合法 PNG（magic bytes + 可解码 + 宽高 > 0），
// 且合成图宽度恰为 imgWidth。
func TestRenderValidPNG(t *testing.T) {
	tests := []struct {
		name  string
		stats *query.Stats
		kind  string
	}{
		{"daily", dailyStats(), KindDaily},
		{"weekly", weeklyStats(), KindWeekly},
		{"daily/UTC renderer", dailyStats(), KindDaily},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := New(shanghai)
			if tt.name == "daily/UTC renderer" {
				r = New(nil)
			}
			data, err := r.Render(tt.stats, tt.kind)
			if err != nil {
				t.Fatalf("Render() error = %v, want nil", err)
			}
			assertValidPNG(t, data)
			cfg, _ := png.DecodeConfig(bytes.NewReader(data))
			if cfg.Width != imgWidth {
				t.Errorf("width = %d, want %d", cfg.Width, imgWidth)
			}
		})
	}
}

// 2. 零事件窗口（无连接、无 Top IP、无趋势桶）仍产出合法 PNG。
func TestRenderZeroEvents(t *testing.T) {
	zero := &query.Stats{
		Since:     time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC),
		Until:     time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC),
		TopSrcIPs: []query.SrcIPStat{},
		Hourly:    []query.KV{},
		Daily:     []query.KV{},
	}
	for _, kind := range []string{KindDaily, KindWeekly} {
		data, err := New(shanghai).Render(zero, kind)
		if err != nil {
			t.Fatalf("Render(zero, %s) error = %v, want nil", kind, err)
		}
		assertValidPNG(t, data)
	}
}

// 3. TopSrcIPs 超过 10 个时截断到前 10，且含非 ASCII IP 字符串时
// 仍能成功渲染（asciiSafe 清洗生效，不 panic）。
func TestRenderTruncatesTopIPsAndSanitizes(t *testing.T) {
	st := dailyStats()
	for i := range 15 {
		st.TopSrcIPs = append(st.TopSrcIPs, query.SrcIPStat{
			IP:          fmt.Sprintf("10.0.0.%d", i),
			Connections: i + 1,
		})
	}
	st.TopSrcIPs = append(st.TopSrcIPs, query.SrcIPStat{IP: "1.2.3.4蜜罐", Connections: 3})

	data, err := New(shanghai).Render(st, KindDaily)
	if err != nil {
		t.Fatalf("Render() error = %v, want nil", err)
	}
	assertValidPNG(t, data)
}

// 4. 补零辅助函数：桶数、缺失补零、乱序输入、窗口外与解析失败忽略。
func TestHourlyBuckets(t *testing.T) {
	since := time.Date(2026, 10, 21, 0, 0, 0, 0, shanghai)
	// 输入乱序；2026-10-20T16Z = 上海 10-21T00（首桶），
	// 2026-10-21T10Z = 上海 10-21T18（第 18 桶）。
	kvs := []query.KV{
		{Value: "2026-10-21T15", Count: 12}, // 上海 10-21T23 → 第 23 桶
		{Value: "not-a-date", Count: 9},     // 解析失败 → 忽略
		{Value: "2026-10-21T10", Count: 7},  // 上海 10-21T18 → 第 18 桶
		{Value: "2026-10-21T17", Count: 40}, // 上海 10-22T01 → 窗口外忽略
		{Value: "2026-10-20T15", Count: 6},  // 上海 10-20T23 → 窗口外忽略
		{Value: "2026-10-20T16", Count: 5},  // 上海 10-21T00 → 第 0 桶
	}
	got := hourlyBuckets(kvs, since, shanghai)
	if len(got) != 24 {
		t.Fatalf("len(hourlyBuckets) = %d, want 24", len(got))
	}
	want := map[int]int{0: 5, 18: 7, 23: 12}
	for i, b := range got {
		if c, ok := want[i]; ok && b.Count != c {
			t.Errorf("bucket[%d].Count = %d, want %d", i, b.Count, c)
		} else if !ok && b.Count != 0 {
			t.Errorf("bucket[%d].Count = %d, want 0 (补零)", i, b.Count)
		}
	}
	if got[0].Label != "10-21 00" {
		t.Errorf("bucket[0].Label = %q, want %q", got[0].Label, "10-21 00")
	}
	if got[23].Label != "10-21 23" {
		t.Errorf("bucket[23].Label = %q, want %q", got[23].Label, "10-21 23")
	}
	for i := 1; i < len(got); i++ {
		if got[i].Start.Before(got[i-1].Start) {
			t.Fatalf("buckets not ascending at index %d", i)
		}
	}
}

// 5. weekly 补零：7 个日桶、缺失补零、窗口外与解析失败忽略。
func TestDailyBuckets(t *testing.T) {
	since := time.Date(2026, 10, 13, 0, 0, 0, 0, shanghai)
	kvs := []query.KV{
		{Value: "2026-10-19", Count: 4},  // 第 6 桶
		{Value: "2026-10-20", Count: 9},  // 窗口外忽略
		{Value: "2026-10-13", Count: 11}, // 第 0 桶
		{Value: "2026-10-12", Count: 1},  // 窗口外忽略
		{Value: "bad", Count: 2},         // 解析失败忽略
	}
	got := dailyBuckets(kvs, since, shanghai)
	if len(got) != 7 {
		t.Fatalf("len(dailyBuckets) = %d, want 7", len(got))
	}
	want := map[int]int{0: 11, 6: 4}
	for i, b := range got {
		if c, ok := want[i]; ok && b.Count != c {
			t.Errorf("bucket[%d].Count = %d, want %d", i, b.Count, c)
		} else if !ok && b.Count != 0 {
			t.Errorf("bucket[%d].Count = %d, want 0 (补零)", i, b.Count)
		}
	}
	if got[0].Label != "10-13" || got[6].Label != "10-19" {
		t.Errorf("labels = %q..%q, want %q..%q", got[0].Label, got[6].Label, "10-13", "10-19")
	}
}

// 6. asciiSafe：中文/非 ASCII → "?"，IP 与数字原样。
func TestASCIISafe(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"203.0.113.7", "203.0.113.7"},
		{"10-21 15", "10-21 15"},
		{"", ""},
		{"蜜罐", "??"},
		{"abc中def", "abc?def"},
		{"E3 Daily Report 2026-10-21", "E3 Daily Report 2026-10-21"},
		{"ü→é", "???"},
	}
	for _, tt := range tests {
		if got := asciiSafe(tt.in); got != tt.want {
			t.Errorf("asciiSafe(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// 7. 标题/标签全部为 ASCII：总标题与趋势面板标题在各时区下均为纯 ASCII。
func TestTitlesASCII(t *testing.T) {
	locs := []*time.Location{time.UTC, shanghai, kolkata, laPDT, newfound}
	stats := dailyStats()
	for _, loc := range locs {
		for _, kind := range []string{KindDaily, KindWeekly} {
			for _, s := range []string{reportTitle(stats, kind, loc), trendPanelTitle("hour", loc, stats.Since)} {
				for _, r := range s {
					if r > 127 {
						t.Errorf("title %q in %s contains non-ASCII rune %q", s, loc, r)
					}
				}
			}
		}
	}
}

// 8. 标题精确内容与偏移后缀。
func TestTitleContent(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"daily report", reportTitle(dailyStats(), KindDaily, shanghai), "E3 Daily Report 2026-10-21"},
		{"trend hourly", trendPanelTitle("hour", shanghai, dailyStats().Since), "Activity per hour (UTC+8)"},
		{"trend daily utc", trendPanelTitle("day", time.UTC, dailyStats().Since), "Activity per day (UTC)"},
		{"trend half offset", trendPanelTitle("hour", kolkata, dailyStats().Since), "Activity per hour (UTC+05:30)"},
		{"trend negative offset", trendPanelTitle("hour", laPDT, dailyStats().Since), "Activity per hour (UTC-7)"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.want)
		}
	}
	// weekly 标题右端 = 右开窗口最后一日。
	got := reportTitle(weeklyStats(), KindWeekly, shanghai)
	if want := "E3 Weekly Report 2026-10-13 ~ 2026-10-19"; got != want {
		t.Errorf("weekly report title = %q, want %q", got, want)
	}
}

// 9. utcOffsetSuffix 的整点/半点/负偏移格式。
func TestUTCOffsetSuffix(t *testing.T) {
	ref := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		loc  *time.Location
		want string
	}{
		{time.UTC, "UTC"},
		{shanghai, "UTC+8"},
		{laPDT, "UTC-7"},
		{kolkata, "UTC+05:30"},
		{newfound, "UTC-03:30"},
	}
	for _, tt := range tests {
		if got := utcOffsetSuffix(tt.loc, ref); got != tt.want {
			t.Errorf("utcOffsetSuffix(%s) = %q, want %q", tt.loc, got, tt.want)
		}
	}
}

// 10. 未知 kind 报错；stats 为 nil 报错。
func TestRenderErrors(t *testing.T) {
	r := New(shanghai)
	stats := dailyStats()
	for _, kind := range []string{"", "monthly", "DAILY", "Daily"} {
		if _, err := r.Render(stats, kind); err == nil {
			t.Errorf("Render(stats, %q) error = nil, want non-nil", kind)
		}
	}
	if _, err := r.Render(nil, KindDaily); err == nil {
		t.Error("Render(nil, daily) error = nil, want non-nil")
	}
}

// 11. New(nil) 使用 UTC 且渲染不 panic。
func TestNewNilUsesUTC(t *testing.T) {
	r := New(nil)
	if r.loc != time.UTC {
		t.Errorf("New(nil).loc = %v, want time.UTC", r.loc)
	}
	if r.loc.String() != "UTC" {
		t.Errorf("New(nil).loc.String() = %q, want %q", r.loc.String(), "UTC")
	}
	data, err := r.Render(dailyStats(), KindDaily)
	if err != nil {
		t.Fatalf("Render() error = %v, want nil", err)
	}
	assertValidPNG(t, data)
	if got := reportTitle(dailyStats(), KindDaily, r.loc); got != "E3 Daily Report 2026-10-21" {
		t.Errorf("UTC report title = %q, want %q", got, "E3 Daily Report 2026-10-21")
	}
}

// 12. intTicks：整数刻度、覆盖 max、全零量程。
func TestIntTicks(t *testing.T) {
	tests := []struct {
		max      int
		wantVals []float64
	}{
		{0, []float64{0, 1}},
		{3, []float64{0, 1, 2, 3}},
		{10, []float64{0, 2, 4, 6, 8, 10}},
		{23, []float64{0, 5, 10, 15, 20, 25}},
		{100, []float64{0, 20, 40, 60, 80, 100}},
	}
	for _, tt := range tests {
		ticks := intTicks(tt.max)
		if len(ticks) != len(tt.wantVals) {
			t.Errorf("intTicks(%d) len = %d, want %d (%v)", tt.max, len(ticks), len(tt.wantVals), ticks)
			continue
		}
		for i, tick := range ticks {
			if tick.Value != tt.wantVals[i] {
				t.Errorf("intTicks(%d)[%d].Value = %v, want %v", tt.max, i, tick.Value, tt.wantVals[i])
			}
			if want := strconv.Itoa(int(tt.wantVals[i])); tick.Label != want {
				t.Errorf("intTicks(%d)[%d].Label = %q, want %q", tt.max, i, tick.Label, want)
			}
			for _, r := range tick.Label {
				if r > 127 {
					t.Errorf("intTicks(%d)[%d].Label non-ASCII: %q", tt.max, i, tick.Label)
				}
			}
		}
		last := ticks[len(ticks)-1].Value
		if last < float64(tt.max) && tt.max > 1 {
			t.Errorf("intTicks(%d) top tick %v < max", tt.max, last)
		}
	}
}

// 13. trendSeriesList 按 kind 生成四条等长、索引对齐的补零序列，
// 且各序列读取对应分指标字段。
func TestTrendSeriesList(t *testing.T) {
	series := trendSeriesList(dailyStats(), KindDaily, shanghai)
	if len(series) != 4 {
		t.Fatalf("daily series 数 = %d, want 4", len(series))
	}
	for i, s := range series {
		if len(s.bkts) != dailyBucketCount {
			t.Errorf("series[%d] 桶数 = %d, want %d", i, len(s.bkts), dailyBucketCount)
		}
		if s.name == "" || s.color.A == 0 {
			t.Errorf("series[%d] 名称/颜色未设置: %q %+v", i, s.name, s.color)
		}
	}
	ws := trendSeriesList(weeklyStats(), KindWeekly, shanghai)
	if len(ws) != 4 || len(ws[0].bkts) != weeklyBucketCount {
		t.Errorf("weekly series 异常: %d 条, 首序列 %d 桶", len(ws), len(ws[0].bkts))
	}

	// 分指标字段映射：仅 HourlyLoginFailed 有数据时 failed 序列含该桶。
	st := dailyStats()
	st.HourlyLoginFailed = []query.KV{{Value: "2026-10-21T07", Count: 5}}
	failed := trendSeriesList(st, KindDaily, shanghai)[1]
	hit := 0
	for _, b := range failed.bkts {
		if b.Count == 5 {
			hit++
		} else if b.Count != 0 {
			t.Errorf("login_failed 序列出现非零桶 %+v", b)
		}
	}
	if hit != 1 {
		t.Errorf("login_failed 序列应恰含 1 个计数 5 的桶, 实际 %d", hit)
	}
}

// 14. 面板图像高度一致性：stackImages 拼接后高度等于各面板之和。
func TestStackImagesHeight(t *testing.T) {
	a := image.NewRGBA(image.Rect(0, 0, imgWidth, 10))
	b := image.NewRGBA(image.Rect(0, 0, imgWidth, 25))
	got := stackImages(a, b)
	if got.Bounds().Dy() != 35 || got.Bounds().Dx() != imgWidth {
		t.Errorf("stackImages bounds = %v, want %dx%d", got.Bounds(), imgWidth, 35)
	}
}

// 15. 并发安全：同一 Renderer 被多个 goroutine 并发使用时不出错。
func TestRenderConcurrent(t *testing.T) {
	r := New(shanghai)
	var wg sync.WaitGroup
	errCh := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := r.Render(dailyStats(), KindDaily)
			if err != nil {
				errCh <- err
				return
			}
			if !bytes.HasPrefix(data, pngMagic) {
				errCh <- fmt.Errorf("concurrent render produced invalid PNG")
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}
