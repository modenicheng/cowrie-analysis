// Package scheduler 计算周期报告的统计窗口（SPEC §11）。
//
// daily：前一自然日 [前一天 00:00, 当天 00:00)；
// weekly：上一自然周（周一为一周开始）[上周一 00:00, 本周一 00:00)。
// 所有窗口边界取配置时区（生产为 Asia/Shanghai）的自然日零点，语义为
// 左闭右开，与 store.EventFilter / query.ComputeStats 的窗口语义一致。
package scheduler

import (
	"fmt"
	"time"
)

// 报告类型常量（WindowFor 的 kind 取值）。
const (
	KindDaily  = "daily"
	KindWeekly = "weekly"
)

// WindowFor 计算报告统计窗口（SPEC §11）。
//
// daily 返回 loc 时区的前一自然日 [前一天 00:00, 当天 00:00)；
// weekly 返回上一自然周 [上周一 00:00, 本周一 00:00)，一周从周一开始，
// 星期采用 ISO 编号（周一＝1 … 周日＝7）。
//
// now 先转换到 loc 再取自然日边界，因此 now 自身携带的时区不影响结果；
// 返回的 since/until 均为 loc 时区的 time.Time（携带 loc）。
// kind 不是 daily/weekly，或 loc 为 nil 时返回错误。
func WindowFor(kind string, now time.Time, loc *time.Location) (since, until time.Time, err error) {
	if loc == nil {
		return time.Time{}, time.Time{}, fmt.Errorf("scheduler.WindowFor: loc 不能为 nil")
	}
	n := now.In(loc)
	switch kind {
	case KindDaily:
		// 前一自然日：日期减一天再取零点；time.Date 对越界日（如 0、-1）
		// 自动归一化，天然处理月／年边界。
		until = time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, loc)
		since = time.Date(n.Year(), n.Month(), n.Day()-1, 0, 0, 0, 0, loc)
	case KindWeekly:
		// 本周一零点：按 ISO 星期回退到周一（周日按 7 处理）。
		daysSinceMonday := (int(n.Weekday()) + 6) % 7 // 周一→0 … 周日→6
		until = time.Date(n.Year(), n.Month(), n.Day()-daysSinceMonday, 0, 0, 0, 0, loc)
		since = time.Date(n.Year(), n.Month(), n.Day()-daysSinceMonday-7, 0, 0, 0, 0, loc)
	default:
		return time.Time{}, time.Time{}, fmt.Errorf("scheduler.WindowFor: 未知报告类型 %q（仅支持 daily/weekly）", kind)
	}
	return since, until, nil
}

// PrevWindow 返回紧邻 [since, until) 之前的同长窗口 [since-d, since)，
// 其中 d＝until-since。纯时间算术，不做时区换算；供报告的趋势对比
// （query.Stats.Prev）复用同一口径。
func PrevWindow(since, until time.Time) (time.Time, time.Time) {
	d := until.Sub(since)
	return since.Add(-d), since
}
