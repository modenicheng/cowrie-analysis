// ReportImager 抽象报告图表管线（渲染 → 上传 → 清理），签名见
// docs/CONTRACTS.md internal/reports 节。具体适配器由 cmd/analyst 用
// internal/chartimg.Renderer（渲染）与 internal/dogecloud.Client
// （对象 key 生成/上传/按保留期清理）组装——reports 包不直接依赖这两个包。
package reports

import (
	"context"
	"time"

	"github.com/modenc/e3-security-analyst/internal/query"
)

// ReportImager 是报告图表管线的三个环节。任一环节失败由 Generator 统一
// 降级为纯文本通知（仅 log.Warn），不得让报告失败。
type ReportImager interface {
	// Render 把窗口统计渲染为 PNG 图表字节（kind 为 daily|weekly）。
	Render(stats *query.Stats, kind string, since, until time.Time) ([]byte, error)
	// Upload 把 PNG 上传到对象存储，返回对象 key 与公网直链 URL。
	Upload(ctx context.Context, kind string, since time.Time, png []byte) (key, publicURL string, err error)
	// Prune 清理超过保留期的桶内对象（禁用时实现方应为空操作）。
	Prune(ctx context.Context) error
}

// SetImager 装配图表管线。imager 为 nil（默认，或不启用 report_image）
// 时报告不带图表，行为与历史版本一致。必须在首次 Generate 之前调用。
func (g *Generator) SetImager(imager ReportImager) {
	g.imager = imager
}

// SetNotifyMarkdown 控制带图通知是否按 Markdown 语法发送（对应 ntfy
// "Markdown: yes" 头，需服务端 >= 2.11.0；来自 cfg.Ntfy.Markdown，默认
// true）。仅在图表上传成功时生效：纯文本通知路径不受影响。必须在首次
// Generate 之前调用。
func (g *Generator) SetNotifyMarkdown(v bool) {
	g.notifyMarkdown = v
}
