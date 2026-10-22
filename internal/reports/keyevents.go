package reports

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modenc/e3-security-analyst/internal/cowrie"
	"github.com/modenc/e3-security-analyst/internal/query"
	"github.com/modenc/e3-security-analyst/internal/store"
	"github.com/modenc/e3-security-analyst/internal/tools"
)

// 关键事件采样约束（SPEC §8.1 步骤 3「查询重要来源、异常会话和代表性事件」）。
const (
	keyEventsMaxBytes  = 32 << 10 // __KEY_EVENTS_JSON__ 总字节预算
	keyEventMaxSession = 5        // 登录成功会话数上限
	keyEventsPerSess   = 5        // 每个会话的前 N 条事件
	keyFileEventsMax   = 10       // 文件上传/下载事件上限
	keyTopIPEventsMax  = 20       // Top1 来源 IP 最近事件数
	keyLoginScanLimit  = 100      // 登录成功事件扫描上限（足以发现 5 个会话）
)

// keyEventsDoc 是注入提示词的代表性事件样本结构。
type keyEventsDoc struct {
	LoginSuccessSessions []keySession `json:"login_success_sessions"`
	FileTransfers        []keyEvent   `json:"file_transfers"`
	TopIPRecent          []keyEvent   `json:"top_ip_recent"`
}

// keySession 是一个出现登录成功的会话及其前几条事件。
type keySession struct {
	Session string     `json:"session"`
	Events  []keyEvent `json:"events"`
}

// keyEvent 是经字段裁剪的单条事件（map 序列化按键排序，输出确定）。
type keyEvent map[string]any

// collectKeyEvents 查询并裁剪代表性事件样本，返回序列化 JSON（总字节
// 不超过 keyEventsMaxBytes）。采样口径：
//   - 登录成功的会话事件：出现 cowrie.login.success 的前 5 个会话，
//     每会话取窗口内前 5 条事件（按事件 id 升序）；
//   - 文件上传/下载事件：窗口内前 10 条；
//   - Top1 来源 IP（stats.TopSrcIPs[0]）的最近 20 条事件（按 id 降序取
//     后反转回时间升序）。
//
// 任何一类查询失败都返回 error（失败路径：不掩盖、不降级）。
func (g *Generator) collectKeyEvents(ctx context.Context, since, until time.Time, stats *query.Stats) ([]byte, error) {
	doc := keyEventsDoc{
		LoginSuccessSessions: []keySession{},
		FileTransfers:        []keyEvent{},
		TopIPRecent:          []keyEvent{},
	}

	// 1) 登录成功的会话：扫描前 100 条 login.success 事件提取去重会话。
	loginEvs, err := query.QueryEvents(ctx, g.db, store.EventFilter{
		Since: since, Until: until,
		EventIDs: []string{cowrie.EventLoginSuccess},
		Limit:    keyLoginScanLimit,
	})
	if err != nil {
		return nil, fmt.Errorf("查询登录成功事件失败: %w", err)
	}
	seen := map[string]bool{}
	for _, e := range loginEvs {
		if e.Session == "" || len(doc.LoginSuccessSessions) >= keyEventMaxSession {
			continue
		}
		if seen[e.Session] {
			continue
		}
		seen[e.Session] = true
		sessEvs, err := query.QueryEvents(ctx, g.db, store.EventFilter{
			Since: since, Until: until, Session: e.Session, Limit: keyEventsPerSess,
		})
		if err != nil {
			return nil, fmt.Errorf("查询会话 %s 事件失败: %w", e.Session, err)
		}
		sample := keySession{Session: e.Session, Events: []keyEvent{}}
		for _, se := range sessEvs {
			sample.Events = append(sample.Events, tools.TrimEvent(g.cfg, se))
		}
		doc.LoginSuccessSessions = append(doc.LoginSuccessSessions, sample)
	}

	// 2) 文件上传/下载事件。
	fileEvs, err := query.QueryEvents(ctx, g.db, store.EventFilter{
		Since: since, Until: until,
		EventIDs: []string{cowrie.EventFileUpload, cowrie.EventFileDownload},
		Limit:    keyFileEventsMax,
	})
	if err != nil {
		return nil, fmt.Errorf("查询文件上传/下载事件失败: %w", err)
	}
	for _, e := range fileEvs {
		doc.FileTransfers = append(doc.FileTransfers, tools.TrimEvent(g.cfg, e))
	}

	// 3) Top1 来源 IP 的最近 20 条事件（query.QueryEvents 仅支持 id 升序，
	//    此处用只读 SQL 直接按 id 降序取最近 N 条再反转为时间升序）。
	if len(stats.TopSrcIPs) > 0 && stats.TopSrcIPs[0].IP != "" {
		recent, err := g.recentEvents(ctx, stats.TopSrcIPs[0].IP, since, until, keyTopIPEventsMax)
		if err != nil {
			return nil, fmt.Errorf("查询 Top1 来源 IP 最近事件失败: %w", err)
		}
		for _, e := range recent {
			doc.TopIPRecent = append(doc.TopIPRecent, tools.TrimEvent(g.cfg, e))
		}
	}

	// 字节预算：超出时按 TopIPRecent → FileTransfers → 会话事件的顺序
	// 从尾部逐条丢弃，直到满足 32KiB 上限。
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("序列化关键事件样本失败: %w", err)
	}
	for len(b) > keyEventsMaxBytes {
		switch {
		case len(doc.TopIPRecent) > 0:
			doc.TopIPRecent = doc.TopIPRecent[:len(doc.TopIPRecent)-1]
		case len(doc.FileTransfers) > 0:
			doc.FileTransfers = doc.FileTransfers[:len(doc.FileTransfers)-1]
		case len(doc.LoginSuccessSessions) > 0:
			last := len(doc.LoginSuccessSessions) - 1
			s := &doc.LoginSuccessSessions[last]
			if len(s.Events) > 0 {
				s.Events = s.Events[:len(s.Events)-1]
			} else {
				doc.LoginSuccessSessions = doc.LoginSuccessSessions[:last]
			}
		default:
			return b, nil // 已全部丢弃（理论不可达：空结构远小于预算）
		}
		if b, err = json.Marshal(doc); err != nil {
			return nil, fmt.Errorf("序列化关键事件样本失败: %w", err)
		}
	}
	return b, nil
}

// recentEvents 返回指定来源 IP 在窗口内按事件 id 降序的前 n 条事件，
// 并反转为时间升序返回（只读 SQL）。
func (g *Generator) recentEvents(ctx context.Context, srcIP string, since, until time.Time, n int) ([]*store.Event, error) {
	rows, err := g.db.SQL().QueryContext(ctx, `SELECT id, event_id, event_time, collected_at,
			src_ip, src_port, session, username, command, filename, shasum, duration_s, raw
		FROM events
		WHERE event_time >= ? AND event_time < ? AND src_ip = ?
		ORDER BY id DESC LIMIT ?`,
		since.UTC().Format(time.RFC3339Nano), until.UTC().Format(time.RFC3339Nano), srcIP, n)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*store.Event
	for rows.Next() {
		var (
			e                         store.Event
			eventTime, collectedAt    string
			srcIP, session, username  sql.NullString
			command, filename, shasum sql.NullString
			srcPort                   sql.NullInt64
			duration                  sql.NullFloat64
		)
		if err := rows.Scan(&e.ID, &e.EventID, &eventTime, &collectedAt, &srcIP,
			&srcPort, &session, &username, &command, &filename, &shasum,
			&duration, &e.Raw); err != nil {
			return nil, err
		}
		if e.EventTime, err = time.Parse(time.RFC3339Nano, eventTime); err != nil {
			return nil, fmt.Errorf("解析事件时间 %q: %w", eventTime, err)
		}
		e.CollectedAt, _ = time.Parse(time.RFC3339Nano, collectedAt)
		e.SrcIP, e.SrcPort = srcIP.String, srcPort.Int64
		e.Session, e.Username = session.String, username.String
		e.Command, e.Filename, e.Shasum = command.String, filename.String, shasum.String
		e.DurationS = duration.Float64
		out = append(out, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// 反转为时间升序。
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// 事件字段的裁剪口径（§9/§13 字段矩阵）由 tools.TrimEvent 唯一实现：
// 关键事件采样与 query_events 工具输出共用，保证模型在提示词与工具
// 返回中看到的事件字段完全一致。
