// dogeImager：reports.ReportImager 的 main 包适配器——用 chartimg.Renderer
// 渲染统计图表 PNG、dogecloud.Client 生成不可猜对象 key 并上传、按保留期
// 清理桶内对象。reports 包不直接依赖这两个包（CONTRACTS internal/reports）。
package main

import (
	"context"
	"time"

	"github.com/modenc/e3-security-analyst/internal/chartimg"
	"github.com/modenc/e3-security-analyst/internal/dogecloud"
	"github.com/modenc/e3-security-analyst/internal/query"
)

// dogeImager 组合渲染器与对象存储客户端；两者均无共享可变状态，并发安全。
type dogeImager struct {
	doge   *dogecloud.Client
	render *chartimg.Renderer
}

// newDogeImager 构造适配器。
func newDogeImager(doge *dogecloud.Client, render *chartimg.Renderer) *dogeImager {
	return &dogeImager{doge: doge, render: render}
}

// Render 把窗口统计渲染为 PNG（since/until 已体现在 Stats 的桶数据中）。
func (a *dogeImager) Render(stats *query.Stats, kind string, since, until time.Time) ([]byte, error) {
	return a.render.Render(stats, kind)
}

// Upload 先用 NewKey 生成不可猜对象 key（{prefix}/{kind}/{YYYYMMDD}-{随机}.png），
// 再以 image/png 上传；返回 key 与公网直链。dogecloud 不内置重试，失败由
// reports.Generator 统一降级为纯文本通知。
func (a *dogeImager) Upload(ctx context.Context, kind string, since time.Time, png []byte) (string, string, error) {
	key := a.doge.NewKey(kind, since)
	publicURL, err := a.doge.Upload(ctx, key, png, "image/png")
	if err != nil {
		return "", "", err
	}
	return key, publicURL, nil
}

// Prune 清理超过保留期的桶内对象；删除数量对调用方无意义，仅透传错误
// （RetentionDays<=0 时 dogecloud 侧为空操作）。
func (a *dogeImager) Prune(ctx context.Context) error {
	_, err := a.doge.Prune(ctx)
	return err
}
