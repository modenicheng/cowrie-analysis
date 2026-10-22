// 本文件实现趋势面板的补零时间桶：把 query.Stats 的 Hourly/Daily
// 聚合桶（UTC 键）映射到展示时区，并对统计窗口全区间补零——
// daily 固定 24 个小时桶、weekly 固定 7 个日桶，缺失桶计 0，
// 窗口外与解析失败的输入桶忽略。输出严格按时间升序，与输入顺序无关。
package chartimg

import (
	"time"

	"github.com/modenc/e3-security-analyst/internal/query"
)

// 趋势桶的键与标签布局、桶数量。
const (
	hourKeyLayout     = "2006-01-02T15" // stats.Hourly 桶键（UTC）
	dayKeyLayout      = "2006-01-02"    // stats.Daily 桶键与报告日期（UTC）
	hourLabelLayout   = "01-02 15"      // 小时桶 x 轴标签，如 "10-21 15"
	dayLabelLayout    = "01-02"         // 日桶 x 轴标签，如 "10-21"
	dailyBucketCount  = 24              // daily 窗口的小时桶数
	weeklyBucketCount = 7               // weekly 窗口的日桶数
)

// bucket 是趋势面板的一个补零时间桶。
type bucket struct {
	Start time.Time // 桶起始时刻（展示时区）
	Label string    // x 轴展示标签（ASCII）
	Count int       // 聚合计数，缺失补 0
}

// hourlyBuckets 对 [since, since+24h)（以 loc 的小时对齐）生成 24 个升序
// 小时桶。kvs 的键为 UTC 格式 "2006-01-02T15"，解析后换算到 loc 再匹配
// 桶；解析失败或落在窗口外的桶忽略。
func hourlyBuckets(kvs []query.KV, since time.Time, loc *time.Location) []bucket {
	counts := make(map[string]int, len(kvs))
	for _, kv := range kvs {
		t, err := time.Parse(hourKeyLayout, kv.Value)
		if err != nil {
			continue
		}
		counts[t.In(loc).Format(hourKeyLayout)] += kv.Count
	}
	start := hourStart(since.In(loc))
	out := make([]bucket, 0, dailyBucketCount)
	for i := range dailyBucketCount {
		b := start.Add(time.Duration(i) * time.Hour)
		out = append(out, bucket{
			Start: b,
			Label: b.Format(hourLabelLayout),
			Count: counts[b.Format(hourKeyLayout)],
		})
	}
	return out
}

// dailyBuckets 对 [since, since+7d)（以 loc 的日对齐）生成 7 个升序日桶。
// kvs 的键为 UTC 格式 "2006-01-02"，解析后换算到 loc 再匹配桶；
// 解析失败或落在窗口外的桶忽略。
func dailyBuckets(kvs []query.KV, since time.Time, loc *time.Location) []bucket {
	counts := make(map[string]int, len(kvs))
	for _, kv := range kvs {
		t, err := time.Parse(dayKeyLayout, kv.Value)
		if err != nil {
			continue
		}
		counts[t.In(loc).Format(dayKeyLayout)] += kv.Count
	}
	start := dayStart(since.In(loc))
	out := make([]bucket, 0, weeklyBucketCount)
	for i := range weeklyBucketCount {
		b := start.AddDate(0, 0, i)
		out = append(out, bucket{
			Start: b,
			Label: b.Format(dayLabelLayout),
			Count: counts[b.Format(dayKeyLayout)],
		})
	}
	return out
}

// hourStart 把 t（已在 loc）截断到所在小时的 0 分，避免绝对时间截断
// 在非整分钟偏移时区（如 +05:45）下产生的错位。
func hourStart(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, t.Location())
}

// dayStart 把 t（已在 loc）截断到所在日的 0 点。
func dayStart(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}
