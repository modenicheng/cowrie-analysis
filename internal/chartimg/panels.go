// 本文件实现三个面板的绘制：顶部总标题条、趋势柱状图面板（go-chart
// BarChart，y 轴整数刻度）、Top 来源 IP 横向条形图面板（go-chart 的
// BarChart 不支持绝对值横向条形图，故基于其 PNG 渲染器手绘）。
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
	headerFontSize     = 20  // 总标题字号
	panelTitleFontSize = 15  // 面板标题字号
	axisFontSize       = 9   // 坐标轴字号
	trendLabelEvery    = 3   // daily 每 3 个小时桶标注一次 x 轴标签
	trendHMargin       = 220 // 趋势面板预留给 y 轴与边距的水平空间
	trendBarSpacing    = 6
	trendMinBarWidth   = 4

	topIPBaseHeight  = 150            // Top IP 面板固定高度（标题 + 数值轴 + 留白）
	topIPRowHeight   = 28             // 每个 IP 行高
	topIPBarHeight   = 16             // 条形高度
	topIPTitleY      = 26             // 标题中心 y
	topIPPlotTop     = 60             // 首行条形中心 y
	topIPLabelRight  = 170            // IP 标签右边界（即条形起点）
	topIPPlotRight   = imgWidth - 110 // 条形区右边界（右侧留数值文本）
	topIPAxisBottomY = 52             // 底部数值轴距面板底边的高度
)

// 面板配色。
var (
	barFill  = drawing.Color{R: 70, G: 130, B: 180, A: 255}  // 条形填充（钢蓝）
	barEdge  = drawing.Color{R: 45, G: 90, B: 135, A: 255}   // 条形描边
	textGray = drawing.Color{R: 110, G: 110, B: 110, A: 255} // 次要文本
	// trendBarStyle 是趋势柱状图统一的条形样式（不设置则每个柱子
	// 按序号取调色板颜色，呈彩虹色）。
	trendBarStyle = chart.Style{FillColor: barFill, StrokeColor: barEdge, StrokeWidth: 1}
	// topIPBarStyle 是 Top IP 条形样式。
	topIPBarStyle = chart.Style{FillColor: barFill, StrokeColor: barEdge, StrokeWidth: 1}
)

// renderHeader 渲染总标题条：透明画布上一行居中黑字，白底由拼接层提供。
func renderHeader(title string) (image.Image, error) {
	r, err := chart.PNG(imgWidth, headerHeight)
	if err != nil {
		return nil, fmt.Errorf("chartimg: 创建标题画布失败: %w", err)
	}
	r.SetDPI(chart.DefaultDPI)
	if err := drawCenteredText(r, title, imgWidth/2, headerHeight/2, headerFontSize, drawing.ColorBlack); err != nil {
		return nil, err
	}
	return imageFromRenderer(r, "标题条")
}

// renderTrendPanel 渲染趋势面板：daily 用 Hourly 补零后的 24 个小时桶，
// weekly 用 Daily 补零后的 7 个日桶；y 轴整数刻度，x 轴标签稀疏。
func renderTrendPanel(stats *query.Stats, kind string, loc *time.Location) (image.Image, error) {
	buckets, labelEvery, unit := trendBuckets(stats, kind, loc)

	maxCount := 0
	bars := make([]chart.Value, len(buckets))
	for i, b := range buckets {
		if b.Count > maxCount {
			maxCount = b.Count
		}
		label := ""
		if i%labelEvery == 0 {
			label = asciiSafe(b.Label)
		}
		bars[i] = chart.Value{Value: float64(b.Count), Label: label, Style: trendBarStyle}
	}

	n := len(buckets) // 24 或 7，恒非空
	barWidth := (imgWidth-trendHMargin)/n - trendBarSpacing
	if barWidth < trendMinBarWidth {
		barWidth = trendMinBarWidth
	}

	bc := chart.BarChart{
		Title:      trendPanelTitle(unit, loc, stats.Since),
		TitleStyle: chart.Style{FontSize: panelTitleFontSize},
		Background: chart.Style{
			FillColor: drawing.ColorWhite,
			// v2.1.2 的 BarChart 最多为 x 轴标签预留 DefaultVerticalTickHeight，
			// 折行后的标签会被裁掉，这里通过底部内边距显式预留标签空间。
			Padding: chart.Box{Top: 8, Left: 20, Right: 20, Bottom: 84},
		},
		Width:      imgWidth,
		Height:     trendHeight,
		Bars:       bars,
		BarWidth:   barWidth,
		BarSpacing: trendBarSpacing,
		XAxis:      chart.Style{FontSize: axisFontSize},
		YAxis: chart.YAxis{
			// 该版本 BarChart 的主 y 轴画在右侧；改用 secondary 使刻度
			// 落在左侧（常规布局）。
			AxisType: chart.YAxisSecondary,
			Style:    chart.Style{FontSize: axisFontSize},
			// 显式整数刻度同时决定了 y 轴量程，使全零数据也能渲染。
			Ticks: intTicks(maxCount),
		},
	}
	iw := chart.ImageWriter{}
	if err := bc.Render(chart.PNG, &iw); err != nil {
		return nil, fmt.Errorf("chartimg: 趋势面板渲染失败: %w", err)
	}
	img, err := iw.Image()
	if err != nil {
		return nil, fmt.Errorf("chartimg: 趋势面板输出图像失败: %w", err)
	}
	return img, nil
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

// renderTopIPPanel 渲染 Top 来源 IP 横向条形图面板：取前 topIPMaxRows 个，
// 值为 Connections、标签为 IP 字符串；无数据时渲染占位文案。
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

	if err := drawCenteredText(r, "Top source IPs by connections",
		imgWidth/2, topIPTitleY, panelTitleFontSize, drawing.ColorBlack); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		if err := drawCenteredText(r, "no source IPs in window",
			imgWidth/2, topIPBaseHeight/2+10, 13, textGray); err != nil {
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

	ipStyle, err := textStyle(11, drawing.ColorBlack)
	if err != nil {
		return nil, err
	}
	valueStyle, err := textStyle(11, textGray)
	if err != nil {
		return nil, err
	}
	tickStyle, err := textStyle(axisFontSize+1, textGray)
	if err != nil {
		return nil, err
	}
	lineStyle := chart.Style{StrokeColor: textGray, StrokeWidth: 1}

	plotWidth := topIPPlotRight - topIPLabelRight
	for i, s := range rows {
		cy := topIPPlotTop + i*topIPRowHeight + topIPRowHeight/2
		ip := asciiSafe(s.IP)
		tb := chart.Draw.MeasureText(r, ip, ipStyle)
		chart.Draw.Text(r, ip, topIPLabelRight-10-tb.Width(), cy+tb.Height()>>1, ipStyle)

		if w := plotWidth * s.Connections / maxConn; w > 0 {
			chart.Draw.Box(r, chart.Box{
				Top:    cy - topIPBarHeight/2,
				Left:   topIPLabelRight,
				Right:  topIPLabelRight + w,
				Bottom: cy + topIPBarHeight/2 - 1,
			}, topIPBarStyle)
			value := strconv.Itoa(s.Connections)
			tv := chart.Draw.MeasureText(r, value, valueStyle)
			chart.Draw.Text(r, value, topIPLabelRight+w+8, cy+tv.Height()>>1, valueStyle)
		}
	}

	// 底部数值轴：横线 + 0/max 端点刻度。
	axisY := height - topIPAxisBottomY
	lineStyle.WriteToRenderer(r)
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
