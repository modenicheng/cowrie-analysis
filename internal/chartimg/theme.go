// 本文件实现深色科技风主题：调色板与卡片/标题绘制辅助。
// 全部为纯平色（无渐变）；配色取 Tailwind 深色系基调。
package chartimg

import (
	"github.com/wcharczuk/go-chart/v2"
	"github.com/wcharczuk/go-chart/v2/drawing"
)

// 深色科技风主题配色（平色）。
var (
	bgFlat = drawing.Color{R: 13, G: 21, B: 38, A: 255} // 画布底 #0D1526
	// cardFill 是卡片底色 #111A2C。
	cardFill = drawing.Color{R: 17, G: 26, B: 44, A: 255}
	// cardEdge 是卡片描边 #202B47。
	cardEdge = drawing.Color{R: 32, G: 43, B: 71, A: 255}
	gridDark = drawing.Color{R: 26, G: 38, B: 63, A: 255} // 网格线 #1A263F
	axisDark = drawing.Color{R: 51, G: 65, B: 85, A: 255} // 轴基线 #334155

	titleText  = drawing.Color{R: 241, G: 245, B: 249, A: 255} // 标题 #F1F5F9
	brightText = drawing.Color{R: 226, G: 232, B: 240, A: 255} // 标识文本（IP）#E2E8F0
	valueText  = drawing.Color{R: 203, G: 213, B: 225, A: 255} // 数值 #CBD5E1
	mutedText  = drawing.Color{R: 124, G: 141, B: 176, A: 255} // 轴刻度/次要 #7C8DB0

	accent = drawing.Color{R: 34, G: 211, B: 238, A: 255} // 强调青 #22D3EE

	// 平色柱体与折线：常规青、Top IP 榜首紫；折线序列 connections 复用
	// barCyan，其余三色见下。
	barCyan     = drawing.Color{R: 6, G: 182, B: 212, A: 255}  // #06B6D4
	rank1Purple = drawing.Color{R: 168, G: 85, B: 247, A: 255} // #A855F7

	// 折线序列配色（平色）。
	lineAmber  = drawing.Color{R: 245, G: 158, B: 11, A: 255}  // login_failed #F59E0B
	lineRed    = drawing.Color{R: 248, G: 113, B: 113, A: 255} // login_success #F87171
	lineViolet = drawing.Color{R: 167, G: 139, B: 250, A: 255} // commands #A78BFA
)

// 面板柱体的平色样式。
var (
	barStyle   = chart.Style{FillColor: barCyan}
	rank1Style = chart.Style{FillColor: rank1Purple}
)

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

// drawTitle 在卡片内左上绘制面板标题：青色小竖条 + 左对齐标题文本。
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
