package reports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modenc/e3-security-analyst/internal/query"
	"github.com/modenc/e3-security-analyst/internal/store"
	"github.com/modenc/e3-security-analyst/internal/tools"
)

// stalledWarningThreshold 是采集停滞判定阈值：health.LastReadAt 早于
// 窗口终点且差距超过该值时，payload.data_quality.stalled_warning 置位。
const stalledWarningThreshold = 10 * time.Minute

// 通知文案约束。
const (
	notifySummaryRunes   = 600 // 通知正文摘要截断长度（rune）
	notifyFindingMax     = 5   // 通知正文最多列出的 finding 标题数
	notifyGapLinesMax    = 3   // 通知正文最多列出的缺口段数
	notifyMaxErrRunes    = 500 // 失败摘要截断长度（FinishAnalysisRun/UpsertReport 的 error 列）
	notifyReportPriority = 3
)

// reportPayload 是归档 JSON 文件的完整结构：窗口、生成元数据、数据质量、
// 程序统计与模型草稿（model 字段承载 submit_report 原文）。
type reportPayload struct {
	Kind        string          `json:"kind"`
	Window      payloadWindow   `json:"window"`
	GeneratedAt time.Time       `json:"generated_at"`
	ModelName   string          `json:"model_name"`
	DataQuality dataQuality     `json:"data_quality"`
	Stats       *query.Stats    `json:"stats"`
	Model       json.RawMessage `json:"model"` // 模型草稿原文（submit_report 接受的 JSON）
}

// payloadWindow 是统计窗口（since/until 为 UTC 时刻，tz 为展示时区名）。
type payloadWindow struct {
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
	TZ    string    `json:"tz"`
}

// dataQuality 是归档与提示词共用的数据完整性块；gaps 与窗口有交集时
// 逐条列出，采集停滞时置 stalled_warning——数据缺口不得被掩盖（SPEC §11）。
type dataQuality struct {
	Gaps               []store.Gap `json:"gaps"`
	ParseErrors        int         `json:"parse_errors"`
	LastEventAt        *time.Time  `json:"last_event_at"`
	LastReadAt         *time.Time  `json:"last_read_at"`
	LastCollectorError string      `json:"last_collector_error"`
	StalledWarning     string      `json:"stalled_warning,omitempty"`
}

// buildPayload 组装完整报告 payload。
func (g *Generator) buildPayload(kind string, since, until time.Time, stats *query.Stats, draft json.RawMessage) *reportPayload {
	dq := dataQuality{
		Gaps:               stats.Quality.Gaps,
		ParseErrors:        stats.Quality.ParseErrors,
		LastEventAt:        stats.Quality.LastEventAt,
		LastReadAt:         stats.Quality.LastReadAt,
		LastCollectorError: stats.Quality.LastCollectorError,
	}
	if dq.Gaps == nil {
		dq.Gaps = []store.Gap{}
	}
	// 采集停滞判定：最后读取时间早于窗口终点且差距 > 10 分钟。
	if lr := stats.Quality.LastReadAt; lr != nil && lr.Before(until) && until.Sub(*lr) > stalledWarningThreshold {
		dq.StalledWarning = "采集可能停滞"
	}
	return &reportPayload{
		Kind: kind,
		Window: payloadWindow{
			Since: since.UTC(),
			Until: until.UTC(),
			TZ:    g.cfg.App.Timezone,
		},
		GeneratedAt: time.Now().UTC(),
		ModelName:   g.cfg.LLM.Model,
		DataQuality: dq,
		Stats:       stats,
		Model:       draft,
	}
}

// archiveReport 把 payload 序列化（紧凑 JSON）、计算 sha256 并写入
// ReportsDir()/YYYY/MM/{kind}-{YYYYMMDD}.json（目录 0700、文件 0600；
// 日期取窗口起点在配置时区中的自然日）。返回 (归档字节, sha256 十六进制,
// 文件路径)；调用方落库 payload 与 content_sha256 必须与文件内容一致。
func (g *Generator) archiveReport(kind string, since time.Time, payload *reportPayload) ([]byte, string, string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, "", "", fmt.Errorf("序列化报告 payload 失败: %w", err)
	}
	sum := sha256.Sum256(data)
	localSince := since.In(g.loc)
	path := filepath.Join(g.cfg.ReportsDir(),
		localSince.Format("2006"), localSince.Format("01"),
		fmt.Sprintf("%s-%s.json", kind, localSince.Format("20060102")))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, "", "", fmt.Errorf("创建报告目录失败: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, "", "", fmt.Errorf("写入报告文件失败: %w", err)
	}
	return data, hex.EncodeToString(sum[:]), path, nil
}

// publishReport 走 ntfy 发布（SPEC §12）：
//
//   - dedupe key `report:{kind}:{windowStart.Unix()}`，topic 为 ReportTopic，
//     priority=3，tags=["chart_with_upwards_trend"]；
//   - 标题：日报 "[E3 安全日报] YYYY-MM-DD"；周报 "[E3 安全周报] A ~ B"
//     （北京时间）；
//   - 正文：summary 前 600 字 + 核心统计行 + 最多 5 条 finding 标题 +
//     （如有）"⚠ 数据缺口: ..." + 归档路径；
//   - Enqueue（notifications 表写入）失败返回 error（失败路径：不发送任何
//     报告通知）；发送失败不算生成失败——报告保持 validated，通知留
//     pending 由 daemon 重试，仅 log.Warn；
//   - 发送成功（含此前已发送的去重命中）→ 调用方将 reports.status 置为
//     published。
func (g *Generator) publishReport(ctx context.Context, kind string, since, until time.Time, draft *Draft, gaps []store.Gap, archivePath string) error {
	n := &store.Notification{
		DedupeKey: fmt.Sprintf("report:%s:%d", kind, since.Unix()),
		Kind:      "report." + kind,
		Topic:     g.cfg.ReportTopic(),
		Title:     g.reportTitle(kind, since, until),
		Body:      g.reportBody(draft, gaps, archivePath),
		Priority:  notifyReportPriority,
		Tags:      "chart_with_upwards_trend",
	}
	deduped, err := g.pub.Enqueue(ctx, n)
	if err != nil {
		return fmt.Errorf("报告通知入队失败: %w", err)
	}
	if !deduped {
		if err := g.pub.TrySend(ctx, n); err != nil {
			// 终态失败或基础设施错误：通知已按 attempts 落库（pending/failed），
			// 报告保持 validated，不算生成失败。
			g.log.Warn("报告通知发送失败，报告保持 validated，通知留待补发",
				"dedupe_key", n.DedupeKey, "err", err)
		}
	} else {
		g.log.Info("报告通知已存在（去重键命中），不重复发送", "dedupe_key", n.DedupeKey)
	}
	g.log.Info("报告通知已处理", "dedupe_key", n.DedupeKey, "topic", n.Topic)
	return nil
}

// notificationStatus 查询 dedupe_key 对应通知的当前状态；查询失败返回空串。
func (g *Generator) notificationStatus(ctx context.Context, dedupeKey string) string {
	var status string
	if err := g.db.SQL().QueryRowContext(ctx,
		`SELECT status FROM notifications WHERE dedupe_key = ?`, dedupeKey).Scan(&status); err != nil {
		g.log.Warn("查询报告通知状态失败", "dedupe_key", dedupeKey, "err", err)
		return ""
	}
	return status
}

// reportTitle 生成通知标题（北京时间）。
func (g *Generator) reportTitle(kind string, since, until time.Time) string {
	if kind == "weekly" {
		return fmt.Sprintf("[E3 安全周报] %s ~ %s",
			since.In(g.loc).Format("2006-01-02"), until.In(g.loc).Format("2006-01-02"))
	}
	return fmt.Sprintf("[E3 安全日报] %s", since.In(g.loc).Format("2006-01-02"))
}

// reportBody 组装通知正文。核心统计数字取自草稿 key_stats——草稿已被
// SubmitDraft 校验与 SQL 统计逐一相等，二者等价且无需共享生成器状态。
func (g *Generator) reportBody(draft *Draft, gaps []store.Gap, archivePath string) string {
	var b strings.Builder
	b.WriteString(tools.TruncateRunes(draft.Summary, notifySummaryRunes))
	fmt.Fprintf(&b, "\n连接 %d|独立IP %d|登录成功 %d|失败 %d",
		int(*draft.KeyStats.Connections), int(*draft.KeyStats.UniqueSrcIPs),
		int(*draft.KeyStats.LoginSuccess), int(*draft.KeyStats.LoginFailed))
	for i, f := range draft.Findings {
		if i >= notifyFindingMax {
			break
		}
		fmt.Fprintf(&b, "\n[%s] %s", f.Severity, f.Title)
	}
	if len(gaps) > 0 {
		parts := make([]string, 0, len(gaps))
		for i, gp := range gaps {
			if i >= notifyGapLinesMax {
				parts = append(parts, fmt.Sprintf("等 %d 段", len(gaps)))
				break
			}
			parts = append(parts, fmt.Sprintf("%s~%s",
				gp.Start.In(g.loc).Format("01-02 15:04"), gp.End.In(g.loc).Format("01-02 15:04")))
		}
		fmt.Fprintf(&b, "\n⚠ 数据缺口: %s", strings.Join(parts, "; "))
	}
	fmt.Fprintf(&b, "\n归档: %s", archivePath)
	return b.String()
}

// clipErr 把错误摘要截断到不超过 max 字节（回退到合法 UTF-8 边界），
// 供 analysis_runs.error / reports.error 落库。
func clipErr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := s[:max]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}
