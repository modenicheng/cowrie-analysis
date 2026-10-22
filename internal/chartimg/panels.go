// 本文件实现三个面板的绘制：顶部总标题条、趋势柱状图面板、Top 来源 IP
// 横向条形图面板。两个数据面板均基于 go-chart 的 PNG 渲染器手绘——
// 其 BarChart 会把 x 轴标签空间钳制在 DefaultVerticalTickHeight（约 5px），
// 容纳不了日期时间标签，且横向条形图不支持绝对值比较，故统一自绘。
// 视觉为深色科技风（theme.go）：卡片式面板、平色霓虹柱、弱化网格线。
// 各面板经 ImageWriter 直接取回 RGBA 图像，最终由 chartimg.go 纵向拼接。
package chartimg

import (
	"fmt"
	"image"
	"strconv"
	"time"

	"github.com/modenc/e3-security-analyst/internal/query"
	"github.com/wcharczuk/go-chart/v2"
	"github.com/wcharczuk/go-chart/v2/drawing"
)

// 面板绘制常量（像素）。
const (
	headerFontSize     = 20 // 总标题字号
	panelTitleFontSize = 15 // 面板标题字号
	axisFontSize       = 9  // 坐标轴字号
	trendLabelEvery    = 3  // daily 每 3 个小时桶标注一次 x 轴标签

	cardHInset = 12 // 面板卡片左右外边距
	cardVInset = 10 // 面板卡片上下外边距（决定卡片间隙与图像上下留白）

	trendPlotLeft     = 76 // 趋势面板绘图区左界（卡片内留 y 轴刻度文本）
	trendHMarginRight = 36 // 绘图区右界内边距
	trendPlotTop      = 60 // 绘图区顶界（面板标题之下留白）
	trendXReserve     = 56 // 底部为 x 轴刻度与标签预留的高度
	trendMaxBarWidth  = 64 // 单柱最大宽度（weekly 仅 7 柱时防止过宽）

	topIPBaseHeight  = 170            // Top IP 面板固定高度（卡片 + 标题 + 数值轴 + 留白）
	topIPRowHeight   = 32             // 每个 IP 行高
	topIPBarHeight   = 14             // 条形高度
	topIPTitleY      = 30             // 标题中心 y
	topIPPlotTop     = 68             // 首行条形中心 y
	topIPLabelRight  = 170            // IP 标签右边界（即条形起点）
	topIPPlotRight   = imgWidth - 110 // 条形区右边界（右侧留数值文本）
	topIPAxisBottomY = 58             // 底部数值轴距面板底边的高度
)

// renderHeader 渲染总标题条：透明画布上居中白色总标题 + 底部青色
// 强调线（背景由拼接层的整幅平色底提供）。
func renderHeader(title string) (image.Image, error) {
	r, err := chart.PNG(imgWidth, headerHeight)
	if err != nil {
		return nil, fmt.Errorf("chartimg: 创建标题画布失败: %w", err)
	}
	r.SetDPI(chart.DefaultDPI)
	if err := drawCenteredText(r, title, imgWidth/2, headerHeight/2-10,
		headerFontSize, titleText); err != nil {
		return nil, err
	}
	chart.Draw.Box(r, chart.Box{Left: imgWidth/2 - 36, Right: imgWidth/2 + 36,
		Top: headerHeight - 18, Bottom: headerHeight - 15}, chart.Style{FillColor: accent})
	return imageFromRenderer(r, "标题条")
}

// renderTrendPanel 手绘趋势面板：daily 用 Hourly 补零后的 24 个小时桶，
// weekly 用 Daily 补零后的 7 个日桶。左侧 y 轴整数刻度 + 弱化横向网格线，
// 平色纵向柱（峰值柱高亮并在柱顶标数值），底部 x 轴基线与稀疏刻度标签。
func renderTrendPanel(stats *query.Stats, kind string, loc *time.Location) (image.Image, error) {
	buckets, labelEvery, unit := trendBuckets(stats, kind, loc)

	r, err := chart.PNG(imgWidth, trendHeight)
	if err != nil {
		return nil, fmt.Errorf("chartimg: 创建趋势画布失败: %w", err)
	}
	r.SetDPI(chart.DefaultDPI)
	drawCard(r, chart.Box{Left: cardHInset, Top: cardVInset,
		Right: imgWidth - cardHInset, Bottom: trendHeight - cardVInset})
	if err := drawTitle(r, trendPanelTitle(unit, loc, stats.Since), cardHInset, topIPTitleY); err != nil {
		return nil, err
	}

	maxCount := 0
	for _, b := range buckets {
		if b.Count > maxCount {
			maxCount = b.Count
		}
	}
	ticks := intTicks(maxCount)
	top := int(ticks[len(ticks)-1].Value) // y 轴量程上限（整数刻度末值）

	plotLeft := trendPlotLeft
	plotRight := imgWidth - trendHMarginRight
	plotTop, plotBottom := trendPlotTop, trendHeight-trendXReserve
	plotH := plotBottom - plotTop

	tickStyle, err := textStyle(axisFontSize+1, mutedText)
	if err != nil {
		return nil, err
	}
	gridLine := chart.Style{StrokeColor: gridDark, StrokeWidth: 1}

	// 横向网格线与 y 轴刻度标签（0 刻度不画网格线，基线随后单独描亮）。
	for _, t := range ticks {
		v := int(t.Value)
		y := plotBottom - v*plotH/top
		if v > 0 {
			gridLine.WriteToRenderer(r)
			r.MoveTo(plotLeft, y)
			r.LineTo(plotRight, y)
			r.Stroke()
		}
		tb := chart.Draw.MeasureText(r, t.Label, tickStyle)
		chart.Draw.Text(r, t.Label, plotLeft-10-tb.Width(), y+tb.Height()>>1, tickStyle)
	}

	// 平色纵向柱：零计数不画（基线可见）；峰值柱用更亮色并在柱顶标数值。
	n := len(buckets) // 24 或 7，恒非空
	slot := (plotRight - plotLeft) / n
	barW := slot - 10
	if barW > trendMaxBarWidth {
		barW = trendMaxBarWidth
	}
	if barW < 2 {
		barW = 2
	}
	valueStyle, err := textStyle(axisFontSize+1, valueText)
	if err != nil {
		return nil, err
	}
	for i, b := range buckets {
		if b.Count <= 0 {
			continue
		}
		h := b.Count * plotH / top
		if h < 1 {
			h = 1
		}
		cx := plotLeft + slot*i + slot/2
		box := chart.Box{Left: cx - barW/2, Right: cx + barW/2 - 1,
			Top: plotBottom - h, Bottom: plotBottom - 1}
		if b.Count == maxCount {
			chart.Draw.Box(r, box, peakStyle)
			label := strconv.Itoa(b.Count)
			tb := chart.Draw.MeasureText(r, label, valueStyle)
			chart.Draw.Text(r, label, cx-tb.Width()>>1, box.Top-8, valueStyle)
		} else {
			chart.Draw.Box(r, box, barStyle)
		}
	}

	// x 轴基线 + 稀疏刻度与标签。
	axisLine := chart.Style{StrokeColor: axisDark, StrokeWidth: 1}
	axisLine.WriteToRenderer(r)
	r.MoveTo(plotLeft, plotBottom)
	r.LineTo(plotRight, plotBottom)
	r.Stroke()
	for i, b := range buckets {
		if i%labelEvery != 0 {
			continue
		}
		cx := plotLeft + slot*i + slot/2
		axisLine.WriteToRenderer(r)
		r.MoveTo(cx, plotBottom)
		r.LineTo(cx, plotBottom+4)
		r.Stroke()
		tb := chart.Draw.MeasureText(r, b.Label, tickStyle)
		chart.Draw.Text(r, b.Label, cx-tb.Width()>>1, plotBottom+8+tb.Height(), tickStyle)
	}
	return imageFromRenderer(r, "趋势面板")
}

// trendBuckets 按图表类型取补零后的趋势桶、x 轴标签步长与面板标题单位。
func trendBuckets(stats *query.Stats, kind string, loc *time.Location) (buckets []bucket, labelEvery int, unit string) {
	if kind == KindDaily {
		return hourlyBuckets(stats.Hourly, stats.Since, loc), trendLabelEvery, "hour"
	}
	return dailyBuckets(stats.Daily, stats.Since, loc), 1, "day"
}

// trendPanelTitle 生成趋势面板标题，如 "Connections per hour (UTC+8)"。
func trendPanelTitle(unit string, loc *time.Location, ref time.Time) string {
	return asciiSafe(fmt.Sprintf("Connections per %s (%s)", unit, utcOffsetSuffix(loc, ref)))
}

// renderTopIPPanel 手绘 Top 来源 IP 横向条形图面板：取前 topIPMaxRows 个，
// 值为 Connections、标签为 IP 字符串；榜首用紫色平色高亮，其余青色；
// 无数据时渲染占位文案。
func renderTopIPPanel(tops []query.SrcIPStat) (image.Image, error) {
	rows := tops
	if len(rows) > topIPMaxRows {
		rows = rows[:topIPMaxRows]
	}
	height := topIPBaseHeight + topIPRowHeight*len(rows)
	r, err := chart.PNG(imgWidth, height)
	if err != nil {
		return nil, fmt.Errorf("chartimg: 创建 Top IP 画布失败: %w", err)
	}
	r.SetDPI(chart.DefaultDPI)
	drawCard(r, chart.Box{Left: cardHInset, Top: cardVInset,
		Right: imgWidth - cardHInset, Bottom: height - cardVInset})
	if err := drawTitle(r, "Top source IPs by connections", cardHInset, topIPTitleY); err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		if err := drawCenteredText(r, "no source IPs in window",
			imgWidth/2, topIPBaseHeight/2+10, 13, mutedText); err != nil {
			return nil, err
		}
		return imageFromRenderer(r, "Top IP 面板")
	}

	maxConn := 0
	for _, s := range rows {
		if s.Connections > maxConn {
			maxConn = s.Connections
		}
	}
	if maxConn < 1 {
		maxConn = 1 // 全零时避免除零
	}

	ipStyle, err := textStyle(11, brightText)
	if err != nil {
		return nil, err
	}
	valueStyle, err := textStyle(11, valueText)
	if err != nil {
		return nil, err
	}
	tickStyle, err := textStyle(axisFontSize+1, mutedText)
	if err != nil {
		return nil, err
	}
	axisLine := chart.Style{StrokeColor: axisDark, StrokeWidth: 1}

	plotWidth := topIPPlotRight - topIPLabelRight
	for i, s := range rows {
		cy := topIPPlotTop + i*topIPRowHeight + topIPRowHeight/2
		ip := asciiSafe(s.IP)
		tb := chart.Draw.MeasureText(r, ip, ipStyle)
		chart.Draw.Text(r, ip, topIPLabelRight-10-tb.Width(), cy+tb.Height()>>1, ipStyle)

		if w := plotWidth * s.Connections / maxConn; w > 0 {
			box := chart.Box{
				Top:    cy - topIPBarHeight/2,
				Left:   topIPLabelRight,
				Right:  topIPLabelRight + w,
				Bottom: cy + topIPBarHeight/2 - 1,
			}
			if i == 0 {
				chart.Draw.Box(r, box, rank1Style)
			} else {
				chart.Draw.Box(r, box, barStyle)
			}
			value := strconv.Itoa(s.Connections)
			tv := chart.Draw.MeasureText(r, value, valueStyle)
			chart.Draw.Text(r, value, topIPLabelRight+w+10, cy+tv.Height()>>1, valueStyle)
		}
	}

	// 底部数值轴：横线 + 0/max 端点刻度。
	axisY := height - topIPAxisBottomY
	axisLine.WriteToRenderer(r)
	r.MoveTo(topIPLabelRight, axisY)
	r.LineTo(topIPPlotRight, axisY)
	r.Stroke()
	r.MoveTo(topIPLabelRight, axisY)
	r.LineTo(topIPLabelRight, axisY+4)
	r.Stroke()
	r.MoveTo(topIPPlotRight, axisY)
	r.LineTo(topIPPlotRight, axisY+4)
	r.Stroke()
	for v, x := range map[int]int{0: topIPLabelRight, maxConn: topIPPlotRight} {
		label := strconv.Itoa(v)
		tb := chart.Draw.MeasureText(r, label, tickStyle)
		chart.Draw.Text(r, label, x-tb.Width()>>1, axisY+8+tb.Height(), tickStyle)
	}
	return imageFromRenderer(r, "Top IP 面板")
}

// drawCenteredText 在 (cx, cy) 处绘制一行文本，水平居中、近似垂直居中
// （基线 = cy + 行高/2，与 go-chart 标题的定位方式一致）。
func drawCenteredText(r chart.Renderer, text string, cx, cy int, size float64, color drawing.Color) error {
	style, err := textStyle(size, color)
	if err != nil {
		return err
	}
	tb := chart.Draw.MeasureText(r, text, style)
	chart.Draw.Text(r, text, cx-tb.Width()>>1, cy+tb.Height()>>1, style)
	return nil
}

// textStyle 构造带内嵌字体（Roboto）的文本样式。
func textStyle(size float64, color drawing.Color) (chart.Style, error) {
	font, err := chart.GetDefaultFont()
	if err != nil {
		return chart.Style{}, fmt.Errorf("chartimg: 加载内嵌字体失败: %w", err)
	}
	return chart.Style{Font: font, FontSize: size, FontColor: color}, nil
}

// imageFromRenderer 经 ImageWriter 取回渲染器的 RGBA 图像，免去 PNG
// 编码/解码往返。
func imageFromRenderer(r chart.Renderer, panel string) (image.Image, error) {
	iw := chart.ImageWriter{}
	if err := r.Save(&iw); err != nil {
		return nil, fmt.Errorf("chartimg: %s 输出失败: %w", panel, err)
	}
	img, err := iw.Image()
	if err != nil {
		return nil, fmt.Errorf("chartimg: %s 输出图像失败: %w", panel, err)
	}
	return img, nil
}

// intTicks 生成覆盖 [0, max] 的整数刻度：步长取 1/2/5×10^k 的“整洁”值，
// 刻度数约 2..6 个；max <= 0 时退化为 0..1，保证全零数据仍有合法量程。
func intTicks(max int) []chart.Tick {
	if max < 1 {
		max = 1
	}
	step := niceStep((max + 4) / 5)
	top := ((max + step - 1) / step) * step
	ticks := make([]chart.Tick, 0, top/step+1)
	for v := 0; v <= top; v += step {
		ticks = append(ticks, chart.Tick{Value: float64(v), Label: strconv.Itoa(v)})
	}
	return ticks
}

// niceStep 返回不小于 min 的最小整洁步长（1/2/5×10^k）；min <= 1 时为 1。
func niceStep(min int) int {
	if min <= 1 {
		return 1
	}
	pow := 1
	for {
		for _, m := range [3]int{1, 2, 5} {
			if m*pow >= min {
				return m * pow
			}
		}
		pow *= 10
	}
}
