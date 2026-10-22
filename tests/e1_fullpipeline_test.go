// E1 全链路端到端（SPEC §16 验收 1,3,4,5,8,13）。
//
//	验收 1：Cowrie JSONL → SQLite（含坏行进 parse_errors）；
//	验收 3：查询返回完整来源 IP、路径、命令与会话信息（原值保留）；
//	验收 4：本地代码计算确定性统计（query.ComputeStats）；
//	验收 5：LLM（mock DeepSeek）生成结构化报告并校验归档；
//	验收 8：实时告警在报告生成之前已经发出（login.success 立即高优、
//	        文案含"非真实系统失陷"；login.failed 聚合；首命令；文件操作）；
//	验收 13：报告 key_stats/payload.stats 与 events 表 SQL 统计一致。
package tests_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modenc/e3-security-analyst/internal/llm"
	"github.com/modenc/e3-security-analyst/internal/ntfy"
	"github.com/modenc/e3-security-analyst/internal/query"
	"github.com/modenc/e3-security-analyst/internal/reports"
	"github.com/modenc/e3-security-analyst/internal/rules"
	"github.com/modenc/e3-security-analyst/internal/scheduler"
	"github.com/modenc/e3-security-analyst/internal/store"
)

// e1Draft 构造与 keyStats 对齐的合法 submit_report 草稿。
func e1Draft(kind string, keyStats [4]int) string {
	d := map[string]any{
		"type":    kind,
		"title":   "E3 安全日报",
		"summary": "窗口内蜜罐攻击面概览：出现模拟登录成功、命令探测与文件上传行为，统计见核心指标。",
		"findings": []map[string]any{{
			"title":    "蜜罐内出现模拟登录成功",
			"detail":   "来源 203.0.113.10 在蜜罐内模拟登录成功（非真实系统失陷），随后执行命令探测并上传文件。",
			"severity": "high",
			"evidence": []string{"session:sess-a", "stats:login_success"},
		}},
		"key_stats": map[string]any{
			"connections":    keyStats[0],
			"unique_src_ips": keyStats[1],
			"login_success":  keyStats[2],
			"login_failed":   keyStats[3],
		},
		"confidence":       0.85,
		"data_limitations": "",
	}
	b, err := json.Marshal(d)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// TestE1FullPipeline：采集 → 规则告警 → 报告生成 → 归档/通知。
func TestE1FullPipeline(t *testing.T) {
	dir := t.TempDir()
	ntfyM := newNtfyMock(t)
	llmM := newLLMMock(t)
	cfg := integrationCfg(dir, ntfyM.srv.URL, llmM.srv.URL)
	loc := mustLoc(t, cfg)
	ctx := context.Background()

	since, until, err := scheduler.WindowFor(scheduler.KindDaily, time.Now(), loc)
	if err != nil {
		t.Fatalf("WindowFor: %v", err)
	}
	writeMixedStream(t, cfg.Cowrie.LogPath, since)

	// —— 验收 1：JSONL → SQLite，坏行隔离 ——
	db := openTestDB(t, cfg.Database.Path)
	pub := ntfy.NewPublisher(
		ntfy.NewClient(ntfy.ClientConfig{BaseURL: cfg.Ntfy.BaseURL, Timeout: 5 * time.Second}),
		db, cfg.Ntfy.MaxRetries, cfg.Ntfy.MaxMessageBytes, discardLogger())
	engine := rules.New(cfg, db, pub, discardLogger())

	runCollectorUntil(t, cfg, db, engine, func() bool {
		return countEvents(t, db) == 17 && ntfyM.countByTitle("[E3蜜罐] 蜜罐模拟登录成功") == 1
	}, "17 条事件入库 + 4 条告警", 30*time.Second)

	if n := countEvents(t, db); n != 17 {
		t.Fatalf("events = %d, 期望 17（3 connect + 10 failed + 1 success + 2 command + 1 upload）", n)
	}
	if n := countRows(t, db, "parse_errors"); n != 1 {
		t.Errorf("parse_errors = %d, 期望 1（坏 JSON 行不得静默丢弃）", n)
	}

	// —— 验收 8：实时告警独立于 LLM（此刻 LLM mock 尚未收到任何请求）——
	if n := len(llmM.requests()); n != 0 {
		t.Errorf("告警阶段不应触发任何 LLM 请求, 实际 %d", n)
	}
	alerts := ntfyM.requests()
	if len(alerts) != 4 {
		t.Fatalf("告警数 = %d, 期望 4（成功登录/失败聚合/首命令/文件上传）: %+v",
			len(alerts), alertTitles(alerts))
	}
	var successAlert, failedAlert, cmdAlert, fileAlert *ntfyReq
	for i := range alerts {
		a := &alerts[i]
		switch {
		case strings.Contains(a.Title, "蜜罐模拟登录成功"):
			successAlert = a
		case strings.Contains(a.Title, "登录失败聚合"):
			failedAlert = a
		case strings.Contains(a.Title, "会话首条命令"):
			cmdAlert = a
		case strings.Contains(a.Title, "文件上传"):
			fileAlert = a
		}
	}
	if successAlert == nil || failedAlert == nil || cmdAlert == nil || fileAlert == nil {
		t.Fatalf("四类告警不齐全: %+v", alertTitles(alerts))
	}
	// login.success：立即、priority 4、文案必须注明非真实系统失陷（§18）。
	if successAlert.Priority != "4" {
		t.Errorf("login.success 告警 priority = %q, 期望 4（立即高优）", successAlert.Priority)
	}
	if !strings.Contains(successAlert.Body, "非真实系统失陷") {
		t.Errorf("login.success 告警文案必须注明非真实系统失陷:\n%s", successAlert.Body)
	}
	if !strings.Contains(successAlert.Body, "203.0.113.10") || !strings.Contains(successAlert.Body, "sess-a") {
		t.Errorf("login.success 告警应含源 IP 与会话 ID:\n%s", successAlert.Body)
	}
	// login.failed：同 IP 10 次只聚合成一条。
	if !strings.Contains(failedAlert.Body, "10 次") || !strings.Contains(failedAlert.Body, "203.0.113.10") {
		t.Errorf("login.failed 聚合告警应含 10 次与源 IP:\n%s", failedAlert.Body)
	}
	// 首条命令：uname -a，且第二条（注入命令）不触发。
	if !strings.Contains(cmdAlert.Body, "uname -a") {
		t.Errorf("首命令告警应含命令原文:\n%s", cmdAlert.Body)
	}
	// 文件操作：文件名 + 哈希 + 会话。
	if !strings.Contains(fileAlert.Body, "payload.sh") ||
		!strings.Contains(fileAlert.Body, "cafebabecafe01") || !strings.Contains(fileAlert.Body, "sess-a") {
		t.Errorf("文件上传告警应含文件名/哈希/会话:\n%s", fileAlert.Body)
	}
	for _, a := range alerts {
		if a.Path != "/"+cfg.Ntfy.Topic {
			t.Errorf("告警 topic = %q, 期望 %q", a.Path, cfg.Ntfy.Topic)
		}
	}

	// —— 验收 4：本地确定性统计 ——
	st, err := query.ComputeStats(ctx, db, query.StatsQuery{Since: since, Until: until, TopN: 10})
	if err != nil {
		t.Fatalf("ComputeStats: %v", err)
	}
	if [4]int{st.Connections, st.UniqueSrcIPs, st.LoginSuccess, st.LoginFailed} != e1KeyStats {
		t.Errorf("SQL 统计 = %v, 期望 %v",
			[4]int{st.Connections, st.UniqueSrcIPs, st.LoginSuccess, st.LoginFailed}, e1KeyStats)
	}

	// —— 验收 3：完整来源 IP、路径、命令、会话可查询（原值保留）——
	evs, err := query.QueryEvents(ctx, db, store.EventFilter{Since: since, Until: until})
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(evs) != 17 {
		t.Fatalf("查询返回 %d 条, 期望 17", len(evs))
	}
	var injCmd, upload *store.Event
	for _, e := range evs {
		if e.Command == e1InjCommand {
			injCmd = e
		}
		if e.Filename == "payload.sh" {
			upload = e
		}
	}
	if injCmd == nil {
		t.Fatal("注入命令事件未按原值入库/可查询")
	}
	if !strings.Contains(injCmd.Raw, e1InjCommand) || injCmd.SrcIP != "203.0.113.10" || injCmd.Session != "sess-a" {
		t.Errorf("注入命令事件原值字段受损: %+v", injCmd)
	}
	if upload == nil || upload.Shasum != "cafebabecafe01" || upload.Session != "sess-a" {
		t.Errorf("文件上传事件路径/哈希/会话不完整: %+v", upload)
	}

	// —— 验收 5 + 13：LLM 结构化报告，key_stats 与 SQL 一致才发布 ——
	llmM.steps = []mockStep{
		stepTool("query_stats", "{}"),
		stepTool("submit_report", e1Draft("daily", e1KeyStats)),
		stepFinal(`{"done":true}`),
	}
	client := llm.NewClient(llm.ClientConfig{
		BaseURL: cfg.LLM.BaseURL, Model: cfg.LLM.Model, APIKey: "test-key",
		Timeout: 30 * time.Second, MaxToolRounds: cfg.LLM.MaxToolRounds, EnableTools: true,
	})
	gen, err := reports.NewGenerator(cfg, db, client, nil, pub, discardLogger())
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}
	if err := gen.Generate(ctx, "daily"); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	status, payload := reportRow(t, db)
	if status != "published" {
		t.Fatalf("reports.status = %q, 期望 published", status)
	}
	var p struct {
		Kind  string `json:"kind"`
		Stats struct {
			Connections  int `json:"connections"`
			UniqueSrcIPs int `json:"unique_src_ips"`
			LoginSuccess int `json:"login_success"`
			LoginFailed  int `json:"login_failed"`
		} `json:"stats"`
		Model struct {
			KeyStats map[string]int `json:"key_stats"`
		} `json:"model"`
	}
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		t.Fatalf("解析报告 payload: %v", err)
	}
	if [4]int{p.Stats.Connections, p.Stats.UniqueSrcIPs, p.Stats.LoginSuccess, p.Stats.LoginFailed} != e1KeyStats {
		t.Errorf("payload.stats 与 events SQL 不一致: %+v", p.Stats)
	}
	if p.Model.KeyStats["connections"] != e1KeyStats[0] || p.Model.KeyStats["login_failed"] != e1KeyStats[3] {
		t.Errorf("payload.model.key_stats 与 SQL 不一致: %v", p.Model.KeyStats)
	}

	// 归档文件存在（验收 14 的文件产物侧；窗口起点北京时间日期）。
	archive := filepath.Join(cfg.ReportsDir(),
		since.In(loc).Format("2006"), since.In(loc).Format("01"),
		"daily-"+since.In(loc).Format("20060102")+".json")
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatalf("报告归档缺失 %s: %v", archive, err)
	}
	if string(data) != payload {
		t.Errorf("归档文件与 reports.payload 不一致")
	}

	// 通知 mock 收到告警（4 条 e3alerts）+ 报告（1 条 e3reports）两类消息。
	all := ntfyM.requests()
	if len(all) != 5 {
		t.Fatalf("ntfy 总请求数 = %d, 期望 5（4 告警 + 1 报告）: %+v", len(all), alertTitles(all))
	}
	var reportMsg *ntfyReq
	for i := range all {
		if all[i].Path == "/"+cfg.Ntfy.ReportTopic {
			reportMsg = &all[i]
		}
	}
	if reportMsg == nil {
		t.Fatalf("未收到报告通知（topic %s）", cfg.Ntfy.ReportTopic)
	}
	if !strings.HasPrefix(reportMsg.Title, "[E3 安全日报]") {
		t.Errorf("报告通知标题 = %q", reportMsg.Title)
	}
	if !strings.Contains(reportMsg.Body, "连接 3|独立IP 3|登录成功 1|失败 10") {
		t.Errorf("报告通知统计行与 SQL 不一致:\n%s", reportMsg.Body)
	}
}

// alertTitles 提取标题（诊断用）。
func alertTitles(reqs []ntfyReq) []string {
	out := make([]string, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, r.Title)
	}
	return out
}
