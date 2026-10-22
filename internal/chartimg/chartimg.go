// Package chartimg 将 query.Stats 渲染为安全报告用的统计图表 PNG。
//
// 本文件实现 Renderer：对外入口 Render 接受 daily/weekly 两种图表类型，
// 输出一张宽约 1000px 的纵向合成 PNG——顶部总标题条、中部趋势柱状图
// 面板、底部 Top 来源 IP 横向条形图面板。趋势面板对统计窗口全区间补零，
// 零事件窗口也能产出合法 PNG；所有进入图表的文本经 asciiSafe 清洗，
// 保证纯 ASCII（v1 不内嵌 CJK 字体）。Renderer 无共享可变状态，
// 并发调用 Render 是安全的。
package chartimg

import (
	"bytes"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"strings"
	"time"

	"github.com/modenc/e3-security-analyst/internal/query"
	"github.com/wcharczuk/go-chart/v2/drawing"
)

// 图表类型与合成版式常量。
const (
	// KindDaily 渲染日报：24 个小时桶趋势面板 + Top IP 面板。
	KindDaily = "daily"
	// KindWeekly 渲染周报：7 个日桶趋势面板 + Top IP 面板。
	KindWeekly = "weekly"

	// imgWidth 是合成 PNG 的宽度（像素），所有面板同宽后纵向拼接。
	imgWidth = 1000
	// headerHeight 是总标题条的高度。
	headerHeight = 64
	// trendHeight 是趋势面板的高度。
	trendHeight = 380
	// topIPMaxRows 是 Top IP 面板最多展示的来源 IP 行数。
	topIPMaxRows = 10
)

// Renderer 将 query.Stats 渲染为统计图表 PNG。展示时区在 New 时固定，
// 之后不可变；并发安全。
type Renderer struct {
	loc *time.Location // 展示时区，New(nil) 时为 UTC
}

// New 创建 Renderer。loc 为展示时区，nil 时使用 UTC。
func New(loc *time.Location) *Renderer {
	if loc == nil {
		loc = time.UTC
	}
	return &Renderer{loc: loc}
}

// Render 渲染单张合成 PNG：总标题条 + 趋势面板 + Top IP 面板。
// kind 仅接受 KindDaily/KindWeekly，其他值返回错误；stats 为 nil 返回错误。
// 零事件窗口（无连接、无来源 IP、无趋势桶）仍产出合法 PNG。
func (r *Renderer) Render(stats *query.Stats, kind string) ([]byte, error) {
	if kind != KindDaily && kind != KindWeekly {
		return nil, fmt.Errorf("chartimg.Render: 未知图表类型 %q，仅支持 %q/%q", kind, KindDaily, KindWeekly)
	}
	if stats == nil {
		return nil, fmt.Errorf("chartimg.Render: stats 为 nil")
	}

	header, err := renderHeader(reportTitle(stats, kind, r.loc))
	if err != nil {
		return nil, err
	}
	trend, err := renderTrendPanel(stats, kind, r.loc)
	if err != nil {
		return nil, err
	}
	topIP, err := renderTopIPPanel(stats.TopSrcIPs)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, stackImages(header, trend, topIP)); err != nil {
		return nil, fmt.Errorf("chartimg.Render: PNG 编码失败: %w", err)
	}
	return buf.Bytes(), nil
}

// stackImages 将各面板按顺序纵向拼接为一张白底图像；各面板宽度一致
// （由 imgWidth 保证）。
func stackImages(panels ...image.Image) *image.RGBA {
	totalHeight := 0
	for _, p := range panels {
		totalHeight += p.Bounds().Dy()
	}
	canvas := image.NewRGBA(image.Rect(0, 0, imgWidth, totalHeight))
	// 先铺白底：手绘面板（标题条/Top IP）背景透明，落到底色上呈现白底。
	draw.Draw(canvas, canvas.Bounds(), image.NewUniform(drawing.ColorWhite), image.Point{}, draw.Src)
	y := 0
	for _, p := range panels {
		rect := image.Rect(0, y, imgWidth, y+p.Bounds().Dy())
		draw.Draw(canvas, rect, p, image.Point{}, draw.Over)
		y += p.Bounds().Dy()
	}
	return canvas
}

// asciiSafe 将 s 中的非 ASCII 字符（rune > 127）逐个替换为 "?"，
// 其余原样保留。图表内嵌字体不含 CJK 字形，任何进入图表的文本都
// 必须先经过本函数清洗。
func asciiSafe(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 { // UTF-8 多字节字符的字节值均 >= 0x80
			return replaceNonASCII(s)
		}
	}
	return s
}

// replaceNonASCII 是 asciiSafe 的慢路径，仅在 s 确实含非 ASCII 字节时执行。
func replaceNonASCII(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r <= 127 {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}

// utcOffsetSuffix 生成相对 UTC 的偏移后缀：整点偏移如 "UTC+8"，
// UTC 本身为 "UTC"，非整小时偏移用 ±HH:MM 如 "UTC+05:30"。
// 偏移按 ref 在 loc 中的当时规则计算（避免夏令时切换带来的歧义）。
func utcOffsetSuffix(loc *time.Location, ref time.Time) string {
	_, off := ref.In(loc).Zone()
	if off == 0 {
		return "UTC"
	}
	sign := "+"
	if off < 0 {
		sign = "-"
		off = -off
	}
	h, m := off/3600, (off%3600)/60
	if m == 0 {
		return fmt.Sprintf("UTC%s%d", sign, h)
	}
	return fmt.Sprintf("UTC%s%02d:%02d", sign, h, m)
}

// reportTitle 生成合成图总标题：
//
//	daily  → "E3 Daily Report 2026-10-21"
//	weekly → "E3 Weekly Report 2026-10-13 ~ 2026-10-19"
//
// 日期均按展示时区格式化；weekly 右端是右开窗口 [Since, Until)
// 覆盖的最后一日（Until 前一日）。
func reportTitle(stats *query.Stats, kind string, loc *time.Location) string {
	if kind == KindDaily {
		return asciiSafe("E3 Daily Report " + stats.Since.In(loc).Format(dayKeyLayout))
	}
	lastDay := stats.Until.In(loc).AddDate(0, 0, -1)
	return asciiSafe("E3 Weekly Report " + stats.Since.In(loc).Format(dayKeyLayout) +
		" ~ " + lastDay.Format(dayKeyLayout))
}
