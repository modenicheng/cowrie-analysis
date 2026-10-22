// 本文件实现深色科技风主题：调色板、颜色插值与渐变/卡片绘制辅助。
// 所有渐变以 1px 条带逐行/逐列绘制（纯色插值，不依赖渲染器的透明混合）。
package chartimg

import (
	"image"
	"image/draw"

	"github.com/wcharczuk/go-chart/v2"
	"github.com/wcharczuk/go-chart/v2/drawing"
)

// 深色科技风主题配色。
var (
	bgTop    = drawing.Color{R: 10, G: 15, B: 30, A: 255} // 画布顶部 #0A0F1E
	bgBottom = drawing.Color{R: 13, G: 21, B: 38, A: 255} // 画布底部 #0D1526
	cardFill = drawing.Color{R: 17, G: 26, B: 44, A: 255} // 卡片底 #111A2C
	cardEdge = drawing.Color{R: 32, G: 43, B: 71, A: 255} // 卡片描边 #202B47
	gridDark = drawing.Color{R: 26, G: 38, B: 63, A: 255} // 网格线 #1A263F
	axisDark = drawing.Color{R: 51, G: 65, B: 85, A: 255} // 轴基线 #334155

	titleText  = drawing.Color{R: 241, G: 245, B: 249, A: 255} // 标题 #F1F5F9
	brightText = drawing.Color{R: 226, G: 232, B: 240, A: 255} // 标识文本（IP）#E2E8F0
	valueText  = drawing.Color{R: 203, G: 213, B: 225, A: 255} // 数值 #CBD5E1
	mutedText  = drawing.Color{R: 124, G: 141, B: 176, A: 255} // 轴刻度/次要 #7C8DB0

	accent = drawing.Color{R: 34, G: 211, B: 238, A: 255} // 强调青 #22D3EE

	// 趋势柱渐变（常规/峰值）。
	barGradTop  = drawing.Color{R: 103, G: 232, B: 249, A: 255} // #67E8F9
	barGradBot  = drawing.Color{R: 14, G: 116, B: 144, A: 255}  // #0E7490
	peakGradTop = drawing.Color{R: 196, G: 252, B: 255, A: 255} // #C4FCFF
	peakGradBot = drawing.Color{R: 34, G: 211, B: 238, A: 255}  // #22D3EE

	// Top IP 条形渐变（常规/榜首）。
	hbarGradA  = drawing.Color{R: 34, G: 211, B: 238, A: 255}  // #22D3EE
	hbarGradB  = drawing.Color{R: 21, G: 94, B: 117, A: 255}   // #155E75
	rank1GradA = drawing.Color{R: 232, G: 121, B: 249, A: 255} // #E879F9
	rank1GradB = drawing.Color{R: 126, G: 34, B: 206, A: 255}  // #7E22CE
)

// lerpColor 在 c1、c2 之间按 t∈[0,1] 线性插值（各自通道独立）。
func lerpColor(c1, c2 drawing.Color, t float64) drawing.Color {
	if t < 0 {
		t = 0
	}
	if t > 1 {
		t = 1
	}
	m := func(a, b uint8) uint8 { return uint8(float64(a) + (float64(b)-float64(a))*t) }
	return drawing.Color{R: m(c1.R, c2.R), G: m(c1.G, c2.G), B: m(c1.B, c2.B), A: 255}
}

// fillVGrad 在 box 内绘制垂直渐变（top→bottom 两色），逐行 1px 条带填充。
func fillVGrad(r chart.Renderer, box chart.Box, top, bottom drawing.Color) {
	h := box.Bottom - box.Top
	if h <= 0 {
		return
	}
	for y := box.Top; y < box.Bottom; y++ {
		c := lerpColor(top, bottom, float64(y-box.Top)/float64(h))
		chart.Draw.Box(r, chart.Box{Left: box.Left, Right: box.Right, Top: y, Bottom: y + 1},
			chart.Style{FillColor: c})
	}
}

// fillHGrad 在 box 内绘制水平渐变（left→right 两色），逐列 1px 条带填充。
func fillHGrad(r chart.Renderer, box chart.Box, left, right drawing.Color) {
	w := box.Right - box.Left
	if w <= 0 {
		return
	}
	for x := box.Left; x < box.Right; x++ {
		c := lerpColor(left, right, float64(x-box.Left)/float64(w))
		chart.Draw.Box(r, chart.Box{Left: x, Right: x + 1, Top: box.Top, Bottom: box.Bottom},
			chart.Style{FillColor: c})
	}
}

// drawCard 绘制面板卡片：深色填充 + 1px 描边，内容面板落在其上。
func drawCard(r chart.Renderer, box chart.Box) {
	chart.Draw.Box(r, box, chart.Style{FillColor: cardFill})
	border := chart.Style{StrokeColor: cardEdge, StrokeWidth: 1}
	border.WriteToRenderer(r)
	r.MoveTo(box.Left, box.Top)
	r.LineTo(box.Right, box.Top)
	r.LineTo(box.Right, box.Bottom)
	r.LineTo(box.Left, box.Bottom)
	r.LineTo(box.Left, box.Top)
	r.Stroke()
}

// drawTitle 在卡片内左上绘制面板标题：青色小竖条 + 左对齐标题文本，
// 返回标题文本的基线 y（供需要相对定位的调用方使用）。
func drawTitle(r chart.Renderer, text string, cardLeft, cy int) error {
	chart.Draw.Box(r, chart.Box{Left: cardLeft + 18, Right: cardLeft + 22,
		Top: cy - 7, Bottom: cy + 7}, chart.Style{FillColor: accent})
	style, err := textStyle(panelTitleFontSize, titleText)
	if err != nil {
		return err
	}
	tb := chart.Draw.MeasureText(r, text, style)
	chart.Draw.Text(r, text, cardLeft+32, cy+tb.Height()>>1, style)
	return nil
}

// bgGradient 生成整幅画布的垂直渐变背景（bgTop→bgBottom）。
func bgGradient(w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		c := lerpColor(bgTop, bgBottom, float64(y)/float64(h))
		draw.Draw(img, image.Rect(0, y, w, y+1), image.NewUniform(c), image.Point{}, draw.Src)
	}
	return img
}
