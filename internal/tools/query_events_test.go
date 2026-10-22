package tools

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modenc/e3-security-analyst/internal/config"
	"github.com/modenc/e3-security-analyst/internal/cowrie"
	"github.com/modenc/e3-security-analyst/internal/store"
)

// eventsResp 是测试侧对 query_events 结果的解码目标。
type eventsResp struct {
	Events     []map[string]any `json:"events"`
	Count      int              `json:"count"`
	NextCursor *int64           `json:"next_cursor"`
	Truncated  bool             `json:"truncated"`
	Note       string           `json:"note"`
	TotalHint  *int             `json:"total_hint"`
}

func parseEvents(t *testing.T, res string) eventsResp {
	t.Helper()
	var r eventsResp
	if err := json.Unmarshal([]byte(res), &r); err != nil {
		t.Fatalf("结果不是合法 JSON: %v\n%s", err, res)
	}
	if len(r.Events) != r.Count {
		t.Fatalf("count=%d 与 events 条数 %d 不一致", r.Count, len(r.Events))
	}
	return r
}

// TestQueryEventsDefaultWindow：缺省参数时窗口取 TaskWindow；
// 恒定字段（id/event_id/time/src_port/session/username/duration_s/src_ip）
// 均输出；raw.message 输出且 password 默认不输出。
func TestQueryEventsDefaultWindow(t *testing.T) {
	db := openDB(t)
	d := NewDispatcher(testCfg(), db, nil, nil, nil)
	win := testWin()

	closed := mkEvent(cowrie.EventSessionClosed, win.Since.Add(2*time.Hour), nil)
	closed.DurationS = 12.5
	mustInsert(t, db,
		mkEvent(cowrie.EventLoginFailed, win.Since, nil),                 // == Since：计入
		mkEvent(cowrie.EventCommandInput, win.Since.Add(time.Hour), nil), // 窗口内
		closed,
		mkEvent(cowrie.EventConnect, win.Until, nil),                  // == Until：排除
		mkEvent(cowrie.EventConnect, win.Until.Add(time.Minute), nil), // 窗口外
	)

	r := parseEvents(t, mustHandle(t, d, "query_events", `{}`, win))
	if len(r.Events) != 3 {
		t.Fatalf("返回 %d 条事件，期望 3（窗口内）", len(r.Events))
	}
	if r.TotalHint == nil || *r.TotalHint != 3 {
		t.Errorf("total_hint=%v，期望 3", r.TotalHint)
	}
	if r.NextCursor != nil {
		t.Errorf("结果未取满 limit 时不应返回 next_cursor，得到 %d", *r.NextCursor)
	}
	if r.Truncated {
		t.Error("truncated 应为 false")
	}

	ev := r.Events[0]
	wantFields := []string{"id", "event_id", "time", "src_port", "session", "username", "duration_s", "src_ip", "message"}
	for _, f := range wantFields {
		if _, ok := ev[f]; !ok {
			t.Errorf("事件缺少恒定字段 %q: %v", f, ev)
		}
	}
	if _, ok := ev["password"]; ok {
		t.Errorf("IncludePasswords=false 时不应输出 password: %v", ev)
	}
	if ev["event_id"] != cowrie.EventLoginFailed {
		t.Errorf("event_id=%v，期望 %s", ev["event_id"], cowrie.EventLoginFailed)
	}
	if got := ev["time"].(string); got != win.Since.Format(time.RFC3339) {
		t.Errorf("time=%q，期望 %q", got, win.Since.Format(time.RFC3339))
	}
	if ev["src_ip"] != "203.0.113.7" {
		t.Errorf("src_ip=%v", ev["src_ip"])
	}
	if ev["username"] != "root" {
		t.Errorf("username=%v", ev["username"])
	}
	// 第三条 session.closed 带 duration。
	if got := r.Events[2]["duration_s"].(float64); got != 12.5 {
		t.Errorf("duration_s=%v，期望 12.5", got)
	}
}

// TestQueryEventsFieldTrimming：include_source_ips/commands/paths 与
// llm.include_passwords 的裁剪矩阵。
func TestQueryEventsFieldTrimming(t *testing.T) {
	db := openDB(t)
	at := testWin().Since.Add(3 * time.Hour)
	mustInsert(t, db, mkEvent(cowrie.EventCommandInput, at, map[string]any{
		"input":    "cat /etc/passwd",
		"filename": "evil.sh",
		"shasum":   "abc123",
		"outfile":  "trash/evil.sh",
		"url":      "http://example.com/worm.tar",
		"password": "toor",
	}))

	trim := func(t *testing.T, mutate func(cfg *config.Config)) map[string]any {
		t.Helper()
		cfg := testCfg()
		if mutate != nil {
			mutate(cfg)
		}
		d := NewDispatcher(cfg, db, nil, nil, nil)
		r := parseEvents(t, mustHandle(t, d, "query_events", `{}`, testWin()))
		if len(r.Events) != 1 {
			t.Fatalf("返回 %d 条事件，期望 1", len(r.Events))
		}
		return r.Events[0]
	}

	t.Run("全开", func(t *testing.T) {
		ev := trim(t, nil)
		for k, want := range map[string]any{
			"src_ip": "203.0.113.7", "command": "cat /etc/passwd",
			"filename": "evil.sh", "shasum": "abc123",
			"outfile": "trash/evil.sh", "url": "http://example.com/worm.tar",
		} {
			if ev[k] != want {
				t.Errorf("%s=%v，期望 %v", k, ev[k], want)
			}
		}
		if _, ok := ev["password"]; ok {
			t.Errorf("IncludePasswords=false 时不应输出 password")
		}
		if _, ok := ev["src_ip_omitted"]; ok {
			t.Errorf("IncludeSourceIPs=true 时不应输出 src_ip_omitted")
		}
	})

	t.Run("src_ip 省略", func(t *testing.T) {
		ev := trim(t, func(cfg *config.Config) { cfg.Reports.IncludeSourceIPs = false })
		if _, ok := ev["src_ip"]; ok {
			t.Errorf("IncludeSourceIPs=false 时不应输出 src_ip")
		}
		if v, ok := ev["src_ip_omitted"].(bool); !ok || !v {
			t.Errorf("src_ip_omitted 应为 true: %v", ev["src_ip_omitted"])
		}
	})

	t.Run("command 省略", func(t *testing.T) {
		ev := trim(t, func(cfg *config.Config) { cfg.Reports.IncludeCommands = false })
		if _, ok := ev["command"]; ok {
			t.Errorf("IncludeCommands=false 时不应输出 command")
		}
	})

	t.Run("paths 省略", func(t *testing.T) {
		ev := trim(t, func(cfg *config.Config) { cfg.Reports.IncludePaths = false })
		for _, k := range []string{"filename", "shasum", "outfile", "url"} {
			if _, ok := ev[k]; ok {
				t.Errorf("IncludePaths=false 时不应输出 %s", k)
			}
		}
	})

	t.Run("password 输出", func(t *testing.T) {
		ev := trim(t, func(cfg *config.Config) { cfg.LLM.IncludePasswords = true })
		if ev["password"] != "toor" {
			t.Errorf("password=%v，期望 toor", ev["password"])
		}
	})
}

// TestQueryEventsSpanValidation：显式窗口必须 RFC3339 合法、区间有效且
// 跨度 ≤ MaxQuerySpanDays（错误消息给出允许的最大跨度）。
func TestQueryEventsSpanValidation(t *testing.T) {
	cfg := testCfg()
	cfg.Reports.MaxQuerySpanDays = 2
	d := NewDispatcher(cfg, openDB(t), nil, nil, nil)
	win := testWin()

	cases := []struct {
		name, args, wantErr string
	}{
		{"跨度过大", `{"since":"2026-10-01T00:00:00Z","until":"2026-10-06T00:00:00Z"}`, "最大跨度 2 天"},
		{"since 非法", `{"since":"2026-10-21 00:00:00"}`, "RFC3339"},
		{"until 非法", `{"until":"not-a-time"}`, "RFC3339"},
		{"until 不晚于 since", `{"since":"2026-10-21T00:00:00Z","until":"2026-10-21T00:00:00Z"}`, "必须晚于"},
		{"limit 零", `{"limit":0}`, "limit"},
		{"cursor 负", `{"cursor":-1}`, "cursor"},
		{"未知字段", `{"srcip":"1.2.3.4"}`, "参数不合法"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := wantErr(t, d, "query_events", c.args, win)
			if !strings.Contains(got, c.wantErr) {
				t.Fatalf("错误消息 %q 应包含 %q", got, c.wantErr)
			}
		})
	}

	// 合法的窄窗口覆盖：只命中窗口内 2 条中的 1 条。
	db2 := openDB(t)
	d2 := NewDispatcher(testCfg(), db2, nil, nil, nil)
	mustInsert(t, db2,
		mkEvent(cowrie.EventConnect, win.Since.Add(time.Hour), nil),
		mkEvent(cowrie.EventConnect, win.Since.Add(5*time.Hour), nil),
	)
	args := `{"since":"` + win.Since.Add(2*time.Hour).UTC().Format(time.RFC3339) +
		`","until":"` + win.Until.Format(time.RFC3339) + `"}`
	r := parseEvents(t, mustHandle(t, d2, "query_events", args, win))
	if len(r.Events) != 1 {
		t.Fatalf("显式窗口返回 %d 条，期望 1", len(r.Events))
	}
}

// TestQueryEventsLimitClampAndCursor：limit>1000 钳制到 1000；
// 取满 limit 时返回 next_cursor，下一页拿剩余且不再重复 total_hint。
func TestQueryEventsLimitClampAndCursor(t *testing.T) {
	db := openDB(t)
	d := NewDispatcher(testCfg(), db, nil, nil, nil)
	win := testWin()

	var seed []*store.Event
	for i := 0; i < 1001; i++ {
		seed = append(seed, mkEvent(cowrie.EventCommandInput,
			win.Since.Add(time.Duration(i)*time.Second),
			map[string]any{"input": "cmd"}))
	}
	mustInsert(t, db, seed...)

	r1 := parseEvents(t, mustHandle(t, d, "query_events", `{"limit":5000}`, win))
	if len(r1.Events) != 1000 {
		t.Fatalf("limit=5000 应钳制到 1000，实际返回 %d", len(r1.Events))
	}
	if r1.Truncated {
		t.Error("条数钳制不应置 truncated")
	}
	if r1.NextCursor == nil {
		t.Fatal("取满 limit 应返回 next_cursor")
	}
	if r1.TotalHint == nil || *r1.TotalHint != 1001 {
		t.Errorf("total_hint=%v，期望 1001", r1.TotalHint)
	}
	lastID1 := int64(r1.Events[999]["id"].(float64))
	if *r1.NextCursor != lastID1 {
		t.Errorf("next_cursor=%d，期望等于最后一条事件 id=%d", *r1.NextCursor, lastID1)
	}

	args2 := `{"limit":5000,"cursor":` + jsonInt64(*r1.NextCursor) + `}`
	r2 := parseEvents(t, mustHandle(t, d, "query_events", args2, win))
	if len(r2.Events) != 1 {
		t.Fatalf("第二页应返回剩余 1 条，实际 %d", len(r2.Events))
	}
	if r2.NextCursor != nil {
		t.Errorf("最后一页不应返回 next_cursor")
	}
	if r2.TotalHint != nil {
		t.Errorf("带 cursor 的页不应重复返回 total_hint")
	}
	firstID2 := int64(r2.Events[0]["id"].(float64))
	if firstID2 <= lastID1 {
		t.Errorf("第二页首条 id=%d 应大于第一页末条 id=%d", firstID2, lastID1)
	}
}

// jsonInt64 把 int64 格式化为 JSON 数值文本。
func jsonInt64(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// TestQueryEventsByteBudget：事件累计字节超过 256KiB 时置 truncated=true
// 并返回 next_cursor；用 cursor 续查可拿到全部剩余且不重复、不重算 total。
func TestQueryEventsByteBudget(t *testing.T) {
	db := openDB(t)
	d := NewDispatcher(testCfg(), db, nil, nil, nil)
	win := testWin()

	cmd := strings.Repeat("A", 2048) // 每条裁剪后 ~2.3KiB
	var seed []*store.Event
	for i := 0; i < 300; i++ {
		seed = append(seed, mkEvent(cowrie.EventCommandInput,
			win.Since.Add(time.Duration(i)*time.Second),
			map[string]any{"input": cmd}))
	}
	mustInsert(t, db, seed...)

	seen := map[int64]bool{}
	var cursor int64
	pages := 0
	for {
		args := `{"limit":500}`
		if cursor > 0 {
			args = `{"limit":500,"cursor":` + jsonInt64(cursor) + `}`
		}
		raw := mustHandle(t, d, "query_events", args, win)
		r := parseEvents(t, raw)
		if len(r.Events) == 0 {
			t.Fatalf("第 %d 页返回 0 条事件（cursor=%d）", pages+1, cursor)
		}
		last := int64(r.Events[len(r.Events)-1]["id"].(float64))
		for _, ev := range r.Events {
			id := int64(ev["id"].(float64))
			if seen[id] {
				t.Fatalf("事件 id=%d 跨页重复", id)
			}
			seen[id] = true
		}
		pages++

		if pages == 1 {
			if len(r.Events) >= 300 {
				t.Fatal("300×2KiB 事件应在 256KiB 预算内被截断")
			}
			if !r.Truncated {
				t.Fatal("字节截断应置 truncated=true")
			}
			if r.Note == "" {
				t.Error("truncated 时应返回 note")
			}
			if r.TotalHint == nil || *r.TotalHint != 300 {
				t.Errorf("首页 total_hint=%v，期望 300", r.TotalHint)
			}
			if len(raw) > maxEventsBytes+1024 {
				t.Errorf("首页整体响应 %d 字节，超出预算过多", len(raw))
			}
		} else if r.TotalHint != nil {
			t.Errorf("第 %d 页（带 cursor）不应返回 total_hint", pages)
		}

		if r.NextCursor == nil {
			break // 最后一页
		}
		if *r.NextCursor != last {
			t.Fatalf("next_cursor=%d 与最后一条事件 id=%d 不一致", *r.NextCursor, last)
		}
		cursor = *r.NextCursor
		if pages > 10 {
			t.Fatal("页数异常，疑似游标未推进")
		}
	}
	if len(seen) != 300 {
		t.Fatalf("分页累计 %d 条事件，期望 300", len(seen))
	}
	if pages < 2 {
		t.Fatal("256KiB 预算下 300 条大事件至少应分为 2 页")
	}
}
