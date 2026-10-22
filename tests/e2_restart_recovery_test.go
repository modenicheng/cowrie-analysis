// E2 重启幂等与通知恢复（SPEC §16 验收 2,10）。
//
//	验收 2：Collector 重启（新实例、同 DB）后不重复处理已提交事件，
//	        游标 == 文件大小；
//	验收 10：ntfy 故障期间通知 pending 且不丢（notifications 表），
//	        服务恢复后 FlushPending 恰好各发送一条（不重复）。
package tests_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/modenc/e3-security-analyst/internal/llm"
	"github.com/modenc/e3-security-analyst/internal/ntfy"
	"github.com/modenc/e3-security-analyst/internal/reports"
	"github.com/modenc/e3-security-analyst/internal/rules"
	"github.com/modenc/e3-security-analyst/internal/scheduler"
)

// downNtfyURL 是一个必然连接失败的回环地址（ntfy 故障注入）。
const downNtfyURL = "http://127.0.0.1:1"

func TestE2RestartIdempotencyAndNotificationRecovery(t *testing.T) {
	dir := t.TempDir()
	llmM := newLLMMock(t)
	cfg := integrationCfg(dir, downNtfyURL, llmM.srv.URL)
	loc := mustLoc(t, cfg)
	ctx := context.Background()

	since, _, err := scheduler.WindowFor(scheduler.KindDaily, time.Now(), loc)
	if err != nil {
		t.Fatalf("WindowFor: %v", err)
	}
	writeMixedStream(t, cfg.Cowrie.LogPath, since)

	db := openTestDB(t, cfg.Database.Path)
	// ntfy 故障期间：每次 TrySend 内联重试 2 次后保持 pending（不丢）。
	downPub := ntfy.NewPublisher(
		ntfy.NewClient(ntfy.ClientConfig{BaseURL: downNtfyURL, Timeout: 2 * time.Second}),
		db, cfg.Ntfy.MaxRetries, cfg.Ntfy.MaxMessageBytes, discardLogger())
	engine := rules.New(cfg, db, downPub, discardLogger())

	// —— 第一轮采集：17 条事件入库、4 条告警全部 pending ——
	runCollectorUntil(t, cfg, db, engine, func() bool {
		_, pending, _ := notificationCounts(t, db)
		return countEvents(t, db) == 17 && pending == 4
	}, "ntfy 故障期间事件入库 + 4 条告警 pending", 60*time.Second)

	if n := countEvents(t, db); n != 17 {
		t.Fatalf("events = %d, 期望 17", n)
	}
	sent, pending, failed := notificationCounts(t, db)
	if sent != 0 || failed != 0 || pending != 4 {
		t.Fatalf("故障期间通知状态 = sent:%d pending:%d failed:%d, 期望 0/4/0（不丢、不误判终态）",
			sent, pending, failed)
	}

	// —— 验收 2：Collector 重启（新实例、同 DB）不重复处理 ——
	runCollectorFor(t, cfg, db, engine, 300*time.Millisecond)
	if n := countEvents(t, db); n != 17 {
		t.Errorf("重启后 events = %d, 期望仍为 17（幂等）", n)
	}
	if n := countRows(t, db, "parse_errors"); n != 1 {
		t.Errorf("重启后 parse_errors = %d, 期望仍为 1", n)
	}
	if sent, pending, _ := notificationCounts(t, db); sent != 0 || pending != 4 {
		t.Errorf("重启后通知变化: sent=%d pending=%d, 期望 0/4（不重复入队）", sent, pending)
	}

	// 游标 == 文件大小（全部数据已消费）。
	offs, err := db.ListOffsets(ctx)
	if err != nil {
		t.Fatalf("ListOffsets: %v", err)
	}
	if len(offs) != 1 {
		t.Fatalf("collector_offsets 行数 = %d, 期望 1", len(offs))
	}
	st, err := os.Stat(cfg.Cowrie.LogPath)
	if err != nil {
		t.Fatalf("Stat 日志: %v", err)
	}
	if offs[0].Offset != st.Size() {
		t.Errorf("游标 %d != 文件大小 %d", offs[0].Offset, st.Size())
	}

	// —— 报告生成（LLM 可用，ntfy 仍故障）：报告 validated、通知 pending ——
	llmM.steps = []mockStep{
		stepTool("query_stats", "{}"),
		stepTool("submit_report", e1Draft("daily", e1KeyStats)),
		stepFinal(`{"done":true}`),
	}
	client := llm.NewClient(llm.ClientConfig{
		BaseURL: cfg.LLM.BaseURL, Model: cfg.LLM.Model, APIKey: "test-key",
		Timeout: 30 * time.Second, MaxToolRounds: cfg.LLM.MaxToolRounds, EnableTools: true,
	})
	gen, err := reports.NewGenerator(cfg, db, client, nil, downPub, discardLogger())
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}
	if err := gen.Generate(ctx, "daily"); err != nil {
		t.Fatalf("通知故障不应导致 Generate 失败: %v", err)
	}
	status, payload := reportRow(t, db)
	if status != "validated" {
		t.Fatalf("reports.status = %q, 期望 validated（通知失败不算生成失败）", status)
	}
	if payload == "" {
		t.Fatal("报告 payload 为空")
	}
	if _, pending, _ := notificationCounts(t, db); pending != 5 {
		t.Fatalf("pending = %d, 期望 5（4 告警 + 1 报告通知，均未丢）", pending)
	}

	// —— 验收 10：ntfy 恢复，FlushPending 恰好各发送一条 ——
	upM := newNtfyMock(t)
	upPub := ntfy.NewPublisher(
		ntfy.NewClient(ntfy.ClientConfig{BaseURL: upM.srv.URL, Timeout: 5 * time.Second}),
		db, cfg.Ntfy.MaxRetries, cfg.Ntfy.MaxMessageBytes, discardLogger())
	flushed, failedPerm, err := upPub.FlushPending(ctx)
	if err != nil {
		t.Fatalf("FlushPending: %v", err)
	}
	if flushed != 5 || failedPerm != 0 {
		t.Fatalf("FlushPending = sent:%d failed:%d, 期望 5/0", flushed, failedPerm)
	}

	reqs := upM.requests()
	if len(reqs) != 5 {
		t.Fatalf("恢复后 ntfy 收到 %d 条, 期望恰好 5（不重复）: %+v", len(reqs), alertTitles(reqs))
	}
	for _, want := range []struct{ title, bodyPart string }{
		{"[E3蜜罐] 蜜罐模拟登录成功", "非真实系统失陷"},
		{"[E3蜜罐] 登录失败聚合告警", "10 次"},
		{"[E3蜜罐] 会话首条命令", "uname -a"},
		{"[E3蜜罐] 蜜罐内文件上传", "payload.sh"},
	} {
		if n := upM.countByTitle(want.title); n != 1 {
			t.Errorf("标题 %q 发送 %d 次, 期望恰好 1", want.title, n)
		}
	}
	if n := upM.countByTitle("[E3 安全日报] " + since.In(loc).Format("2006-01-02")); n != 1 {
		t.Errorf("报告通知发送 %d 次, 期望恰好 1", n)
	}
	// 重复 Flush 不再重发（幂等去重）。
	if _, _, err := upPub.FlushPending(ctx); err != nil {
		t.Fatalf("第二次 FlushPending: %v", err)
	}
	if n := len(upM.requests()); n != 5 {
		t.Errorf("第二次 FlushPending 后总请求数 = %d, 期望仍为 5（已 sent 不重发）", n)
	}

	// 最终状态：5 条通知全部 sent。
	sent, pending, failed = notificationCounts(t, db)
	if sent != 5 || pending != 0 || failed != 0 {
		t.Errorf("最终通知状态 = sent:%d pending:%d failed:%d, 期望 5/0/0", sent, pending, failed)
	}
	// 通知表无重复行。
	if n := countRows(t, db, "notifications"); n != 5 {
		t.Errorf("notifications 行数 = %d, 期望 5（dedupe 唯一）", n)
	}
}
