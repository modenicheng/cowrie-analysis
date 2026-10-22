package rules

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modenc/e3-security-analyst/internal/config"
	"github.com/modenc/e3-security-analyst/internal/cowrie"
	"github.com/modenc/e3-security-analyst/internal/ntfy"
	"github.com/modenc/e3-security-analyst/internal/store"
	"github.com/modenc/e3-security-analyst/migrations"
)

// —— mock ntfy 服务：记录收到的所有请求，恒返回 200 —— //

type recordedReq struct {
	Path, Body, Title, Priority, Tags string
}

type mockNtfy struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []recordedReq
}

func newMockNtfy(t *testing.T) *mockNtfy {
	t.Helper()
	m := &mockNtfy{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec := recordedReq{
			Path:     r.URL.Path,
			Body:     string(body),
			Title:    r.Header.Get("Title"),
			Priority: r.Header.Get("Priority"),
			Tags:     r.Header.Get("Tags"),
		}
		m.mu.Lock()
		m.reqs = append(m.reqs, rec)
		m.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"id":"mock"}`)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockNtfy) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.reqs)
}

func (m *mockNtfy) all() []recordedReq {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]recordedReq(nil), m.reqs...)
}

// —— 测试环境：真实 store + mock ntfy + Publisher + Engine —— //

type testEnv struct {
	db   *store.DB
	mock *mockNtfy
	pub  *ntfy.Publisher
	cfg  *config.Config
	eng  *Engine
}

var evSeq atomic.Int64

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newTestEnv 建立共用测试环境；tune 可覆盖 Alerts 配置。
func newTestEnv(t *testing.T, maxMsgBytes int, tune func(*config.Config)) *testEnv {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "events.db"), store.Options{BusyTimeoutMs: 3000})
	if err != nil {
		t.Fatalf("store.Open 失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(migrations.FS); err != nil {
		t.Fatalf("Migrate 失败: %v", err)
	}
	mock := newMockNtfy(t)
	client := ntfy.NewClient(ntfy.ClientConfig{BaseURL: mock.srv.URL, Timeout: 5 * time.Second})
	log := quietLogger()
	pub := ntfy.NewPublisher(client, db, 3, maxMsgBytes, log)

	cfg := config.Default()
	cfg.Ntfy.Topic = "e3-alerts"
	cfg.Alerts.MaxPerMinute = 100 // 默认放宽，限流用例自行调小
	if tune != nil {
		tune(cfg)
	}
	eng := New(cfg, db, pub, log)
	return &testEnv{db: db, mock: mock, pub: pub, cfg: cfg, eng: eng}
}

// mkEvent 构造唯一 Raw 的事件；mut 可补充 Username/Command/Filename 等字段。
func mkEvent(eventID, srcIP, session string, mut ...func(*store.Event)) *store.Event {
	seq := evSeq.Add(1)
	ev := &store.Event{
		EventID:   eventID,
		EventTime: time.Now().UTC(),
		SrcIP:     srcIP,
		Session:   session,
		Raw:       fmt.Sprintf(`{"eventid":%q,"src_ip":%q,"session":%q,"seq":%d}`, eventID, srcIP, session, seq),
	}
	for _, m := range mut {
		m(ev)
	}
	return ev
}

// feed 模拟 collector：先把事件入库，再回调引擎（引擎的 SQL 计数因此
// 始终包含"当前这条"）。
func feed(t *testing.T, db *store.DB, eng *Engine, evs ...*store.Event) {
	t.Helper()
	ctx := context.Background()
	if _, _, err := db.InsertEvents(ctx, evs); err != nil {
		t.Fatalf("InsertEvents 失败: %v", err)
	}
	eng.OnNewEvents(ctx, evs)
}

func (e *testEnv) feed(t *testing.T, evs ...*store.Event) {
	t.Helper()
	feed(t, e.db, e.eng, evs...)
}

// avoidMinuteEdge 在距分钟边界过近时睡过边界，避免 digest 分钟桶被
// 测试跨边界拆分（仅限流合并用例需要）。
func avoidMinuteEdge(t *testing.T) {
	t.Helper()
	now := time.Now()
	if remain := time.Minute - now.Sub(now.Truncate(time.Minute)); remain < 2*time.Second {
		time.Sleep(remain + 100*time.Millisecond)
	}
}

// digestRow 读取（唯一的）digest 占位通知。
func digestRow(t *testing.T, db *store.DB) (status string, merged int) {
	t.Helper()
	err := db.SQL().QueryRow(
		`SELECT status, merged_count FROM notifications WHERE kind = 'alert.digest'`).
		Scan(&status, &merged)
	if err != nil {
		t.Fatalf("查询 digest 通知失败: %v", err)
	}
	return status, merged
}

// 1. login.success：立即告警（含 session/IP/"非真实系统失陷"/Priority=4/
// rotating_light 标签），同 session 重复事件去重不再发。
func TestLoginSuccessImmediateAndDedupe(t *testing.T) {
	e := newTestEnv(t, 4000, nil)

	e.feed(t, mkEvent(cowrie.EventLoginSuccess, "203.0.113.7", "sess-a", func(ev *store.Event) {
		ev.Username = "root"
	}))
	reqs := e.mock.all()
	if len(reqs) != 1 {
		t.Fatalf("请求次数 = %d, want 1", len(reqs))
	}
	r := reqs[0]
	if r.Path != "/e3-alerts" {
		t.Errorf("Path = %q, want /e3-alerts", r.Path)
	}
	if !strings.Contains(r.Title, "[E3蜜罐]") || !strings.Contains(r.Title, "登录成功") {
		t.Errorf("Title = %q, want 含 [E3蜜罐] 前缀与登录成功", r.Title)
	}
	for _, want := range []string{"sess-a", "203.0.113.7", "非真实系统失陷", "root"} {
		if !strings.Contains(r.Body, want) {
			t.Errorf("Body 缺少 %q:\n%s", want, r.Body)
		}
	}
	if r.Priority != "4" {
		t.Errorf("Priority = %q, want 4", r.Priority)
	}
	if r.Tags != "rotating_light" {
		t.Errorf("Tags = %q, want rotating_light", r.Tags)
	}

	// 同 session 第二条（新事件，但通知 dedupe 命中）→ 不再发送。
	e.feed(t, mkEvent(cowrie.EventLoginSuccess, "203.0.113.7", "sess-a", func(ev *store.Event) {
		ev.Username = "admin"
	}))
	if got := e.mock.count(); got != 1 {
		t.Errorf("重复事件后请求次数 = %d, want 仍为 1（dedupe）", got)
	}
}

// 2. 文件上传：立即告警且 body 含 filename 与 shasum；同 session 同文件
// 重复 → 去重。
func TestFileUploadAlertAndDedupe(t *testing.T) {
	e := newTestEnv(t, 4000, nil)
	mut := func(ev *store.Event) {
		ev.Filename = "malware.sh"
		ev.Shasum = "deadbeefcafe"
	}

	e.feed(t, mkEvent(cowrie.EventFileUpload, "198.51.100.9", "sess-f", mut))
	reqs := e.mock.all()
	if len(reqs) != 1 {
		t.Fatalf("请求次数 = %d, want 1", len(reqs))
	}
	for _, want := range []string{"malware.sh", "deadbeefcafe", "sess-f", "蜜罐内文件操作"} {
		if !strings.Contains(reqs[0].Body, want) {
			t.Errorf("Body 缺少 %q:\n%s", want, reqs[0].Body)
		}
	}
	if reqs[0].Priority != "4" {
		t.Errorf("Priority = %q, want 4", reqs[0].Priority)
	}

	e.feed(t, mkEvent(cowrie.EventFileUpload, "198.51.100.9", "sess-f", mut))
	if got := e.mock.count(); got != 1 {
		t.Errorf("同 session 同文件重复后请求次数 = %d, want 仍为 1", got)
	}
}

// 3. login.failed 聚合：Threshold=3 时第 3 条失败才发一条汇总（含次数与
// 用户名）；第 4 条未达 repeat_every=50 → 无新发送。
func TestLoginFailedAggregation(t *testing.T) {
	e := newTestEnv(t, 4000, func(c *config.Config) {
		c.Alerts.LoginFailedThreshold = 3
		c.Alerts.LoginFailedWindowSec = 300
		c.Alerts.LoginFailedRepeatEvery = 50
	})

	e.feed(t,
		mkEvent(cowrie.EventLoginFailed, "192.0.2.5", "s1", func(ev *store.Event) { ev.Username = "root" }),
		mkEvent(cowrie.EventLoginFailed, "192.0.2.5", "s1", func(ev *store.Event) { ev.Username = "admin" }),
	)
	if got := e.mock.count(); got != 0 {
		t.Fatalf("2 条失败后请求次数 = %d, want 0", got)
	}

	e.feed(t, mkEvent(cowrie.EventLoginFailed, "192.0.2.5", "s2", func(ev *store.Event) { ev.Username = "root" }))
	reqs := e.mock.all()
	if len(reqs) != 1 {
		t.Fatalf("第 3 条失败后请求次数 = %d, want 1", len(reqs))
	}
	for _, want := range []string{"3 次", "root", "admin", "192.0.2.5"} {
		if !strings.Contains(reqs[0].Body, want) {
			t.Errorf("Body 缺少 %q:\n%s", want, reqs[0].Body)
		}
	}
	if reqs[0].Priority != "3" {
		t.Errorf("Priority = %q, want 3", reqs[0].Priority)
	}

	e.feed(t, mkEvent(cowrie.EventLoginFailed, "192.0.2.5", "s3", func(ev *store.Event) { ev.Username = "oracle" }))
	if got := e.mock.count(); got != 1 {
		t.Errorf("第 4 条失败后请求次数 = %d, want 仍为 1（未达 repeat_every）", got)
	}
}

// 4. 首 command：session 首条命令告警且 body 含命令原文；第 2 条不发；
// 模拟重启（新建 Engine）后同 session 第 3 条命令仍不发（CountEvents 语义）。
func TestFirstCommandPerSessionAndRestart(t *testing.T) {
	e := newTestEnv(t, 4000, nil)

	e.feed(t, mkEvent(cowrie.EventCommandInput, "192.0.2.8", "sess-cmd", func(ev *store.Event) {
		ev.Command = "cat /etc/passwd"
	}))
	reqs := e.mock.all()
	if len(reqs) != 1 {
		t.Fatalf("首条命令后请求次数 = %d, want 1", len(reqs))
	}
	if !strings.Contains(reqs[0].Body, "cat /etc/passwd") {
		t.Errorf("Body 缺少命令原文:\n%s", reqs[0].Body)
	}

	e.feed(t, mkEvent(cowrie.EventCommandInput, "192.0.2.8", "sess-cmd", func(ev *store.Event) {
		ev.Command = "whoami"
	}))
	if got := e.mock.count(); got != 1 {
		t.Errorf("第 2 条命令后请求次数 = %d, want 仍为 1", got)
	}

	// 模拟重启：内存状态清零，但 events 表计数仍在。
	eng2 := New(e.cfg, e.db, e.pub, quietLogger())
	feed(t, e.db, eng2, mkEvent(cowrie.EventCommandInput, "192.0.2.8", "sess-cmd", func(ev *store.Event) {
		ev.Command = "uname -a"
	}))
	if got := e.mock.count(); got != 1 {
		t.Errorf("重启后第 3 条命令请求次数 = %d, want 仍为 1（会话命令计数重启一致）", got)
	}
}

// 4b. 批处理模式回归：同一批次内（collector 追平/重启回放的常态）一个
// 会话的多条命令只对首条告警——单纯用库内计数==1 判定会把批内第 2 条
// 提前计入导致首条漏告警（阶段 G E1 端到端暴露的缺陷）。
func TestFirstCommandBatchMode(t *testing.T) {
	e := newTestEnv(t, 4000, nil)

	// 同批两条命令 + 夹杂其他事件：仅首条命令告警一次。
	e.feed(t,
		mkEvent(cowrie.EventConnect, "192.0.2.9", "sess-batch"),
		mkEvent(cowrie.EventCommandInput, "192.0.2.9", "sess-batch", func(ev *store.Event) {
			ev.Command = "cat /etc/shadow"
		}),
		mkEvent(cowrie.EventCommandInput, "192.0.2.9", "sess-batch", func(ev *store.Event) {
			ev.Command = "whoami"
		}),
	)
	reqs := e.mock.all()
	if len(reqs) != 1 {
		t.Fatalf("批处理首命令请求次数 = %d, want 1", len(reqs))
	}
	if !strings.Contains(reqs[0].Body, "cat /etc/shadow") {
		t.Errorf("Body 应包含批内首条命令原文:\n%s", reqs[0].Body)
	}

	// 另一会话同批 3 条命令：也只告警一次。
	base := e.mock.count()
	e.feed(t,
		mkEvent(cowrie.EventCommandInput, "192.0.2.9", "sess-batch2", func(ev *store.Event) {
			ev.Command = "id"
		}),
		mkEvent(cowrie.EventCommandInput, "192.0.2.9", "sess-batch2", func(ev *store.Event) {
			ev.Command = "ls /tmp"
		}),
		mkEvent(cowrie.EventCommandInput, "192.0.2.9", "sess-batch2", func(ev *store.Event) {
			ev.Command = "ps aux"
		}),
	)
	if got := e.mock.count(); got != base+1 {
		t.Errorf("新会话批内 3 条命令后请求次数 = %d, want %d+1", got, base)
	}

	// 既有会话后续批次再来的命令：不告警。
	e.feed(t, mkEvent(cowrie.EventCommandInput, "192.0.2.9", "sess-batch", func(ev *store.Event) {
		ev.Command = "uname -r"
	}))
	if got := e.mock.count(); got != base+1 {
		t.Errorf("既有会话后续批次命令不应告警, 请求次数 = %d, want %d", got, base+1)
	}
}

// 5. connect 高频：MaxPerMinute=10 → 同 IP 21 次连接只发 1 条高频汇总。
func TestConnectFloodSummary(t *testing.T) {
	e := newTestEnv(t, 4000, func(c *config.Config) {
		c.Alerts.MaxPerMinute = 10 // 洪水阈值 = 10*2 = 20
	})
	t0 := time.Now().UTC() // 全部同分钟桶，避免跨边界
	for i := 0; i < 21; i++ {
		ev := mkEvent(cowrie.EventConnect, "203.0.113.99", "sess-conn")
		ev.EventTime = t0
		e.feed(t, ev)
	}
	reqs := e.mock.all()
	if len(reqs) != 1 {
		t.Fatalf("请求次数 = %d, want 1（高频汇总而非逐条）", len(reqs))
	}
	for _, want := range []string{"21 次", "203.0.113.99", "高频"} {
		if !strings.Contains(reqs[0].Body, want) {
			t.Errorf("Body 缺少 %q:\n%s", want, reqs[0].Body)
		}
	}
}

// 6. 全局限流 + 合并：MaxPerMinute=2，5 个不同 session 的 login.success
// → 只发 2 条；digest:minute 通知 merged_count=3；FlushDigest 后收到
// 汇总且 body 含 3，digest 复用 sent 状态。
func TestGlobalRateLimitAndDigestFlush(t *testing.T) {
	avoidMinuteEdge(t)
	e := newTestEnv(t, 4000, func(c *config.Config) {
		c.Alerts.MaxPerMinute = 2
	})
	for i := 0; i < 5; i++ {
		e.feed(t, mkEvent(cowrie.EventLoginSuccess, "203.0.113.5", fmt.Sprintf("sess-%d", i), func(ev *store.Event) {
			ev.Username = "root"
		}))
	}
	if got := e.mock.count(); got != 2 {
		t.Fatalf("限流后请求次数 = %d, want 2", got)
	}
	status, merged := digestRow(t, e.db)
	if merged != 3 {
		t.Errorf("digest merged_count = %d, want 3", merged)
	}
	if status != "pending" {
		t.Errorf("digest status = %q, want pending（FlushDigest 前）", status)
	}

	if err := e.eng.FlushDigest(context.Background()); err != nil {
		t.Fatalf("FlushDigest: %v", err)
	}
	reqs := e.mock.all()
	if len(reqs) != 3 {
		t.Fatalf("FlushDigest 后请求次数 = %d, want 3", len(reqs))
	}
	if !strings.Contains(reqs[2].Body, "合并了 3 条告警") {
		t.Errorf("汇总 Body 缺少合并计数:\n%s", reqs[2].Body)
	}
	if !strings.Contains(reqs[2].Title, "[E3蜜罐]") {
		t.Errorf("汇总 Title = %q, want 含 [E3蜜罐]", reqs[2].Title)
	}
	status, _ = digestRow(t, e.db)
	if status != "sent" {
		t.Errorf("digest status = %q, want sent（复用 sent 状态）", status)
	}
}

// 8. Body 截断：超长命令的告警经 Publisher 截断后发送 body 不超过
// maxMessageBytes 且带截断标记。
func TestBodyTruncation(t *testing.T) {
	e := newTestEnv(t, 300, nil) // maxMessageBytes=300
	e.feed(t, mkEvent(cowrie.EventCommandInput, "192.0.2.8", "sess-long", func(ev *store.Event) {
		ev.Command = strings.Repeat("A", 300) // 规则层先截到 200 rune，正文仍超 300 字节
	}))
	reqs := e.mock.all()
	if len(reqs) != 1 {
		t.Fatalf("请求次数 = %d, want 1", len(reqs))
	}
	if len(reqs[0].Body) > 300 {
		t.Errorf("Body %d 字节, want <= 300", len(reqs[0].Body))
	}
	if !strings.Contains(reqs[0].Body, "…(截断)") {
		t.Errorf("Body 缺少截断标记:\n%s", reqs[0].Body)
	}
	if !strings.Contains(reqs[0].Body, "命令：") {
		t.Errorf("Body 缺少命令字段:\n%s", reqs[0].Body)
	}
}
