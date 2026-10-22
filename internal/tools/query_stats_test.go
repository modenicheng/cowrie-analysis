package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modenc/e3-security-analyst/internal/cowrie"
	"github.com/modenc/e3-security-analyst/internal/query"
	"github.com/modenc/e3-security-analyst/internal/store"
)

// TestQueryStatsPassthrough：缺省参数下结果与直接调用 query.ComputeStats
// 完全一致（JSON 逐字节对比）；核心数值与种子数据吻合；with_prev 缺省 true。
func TestQueryStatsPassthrough(t *testing.T) {
	db := openDB(t)
	d := NewDispatcher(testCfg(), db, nil, nil, nil)
	win := testWin()
	base := win.Since

	var seed []*store.Event
	add := func(ip, eventID string, off time.Duration) {
		seed = append(seed, mkEvent(eventID, base.Add(off), map[string]any{"src_ip": ip}))
	}
	add("10.0.0.1", cowrie.EventConnect, 0)
	add("10.0.0.1", cowrie.EventConnect, time.Minute)
	add("10.0.0.1", cowrie.EventLoginFailed, 2*time.Minute)
	add("10.0.0.1", cowrie.EventLoginFailed, 3*time.Minute)
	add("10.0.0.1", cowrie.EventLoginFailed, 4*time.Minute)
	add("10.0.0.1", cowrie.EventCommandInput, 5*time.Minute)
	add("10.0.0.2", cowrie.EventConnect, time.Hour)
	add("10.0.0.2", cowrie.EventLoginSuccess, time.Hour+time.Minute)
	add("10.0.0.3", cowrie.EventConnect, 2*time.Hour)
	seed = append(seed, mkEvent(cowrie.EventConnect, win.Until, map[string]any{"src_ip": "10.0.0.9"})) // 窗口外
	mustInsert(t, db, seed...)

	res := mustHandle(t, d, "query_stats", `{}`, win)

	direct, err := query.ComputeStats(context.Background(), db, query.StatsQuery{
		Since: win.Since, Until: win.Until, TopN: 10, WithPrev: true,
	})
	if err != nil {
		t.Fatalf("直接 ComputeStats 失败: %v", err)
	}
	want, _ := json.Marshal(direct)
	if res != string(want) {
		t.Fatalf("query_stats 结果与直接 ComputeStats 不一致:\n got  %s\n want %s", res, want)
	}

	var st query.Stats
	if err := json.Unmarshal([]byte(res), &st); err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if st.Connections != 4 || st.UniqueSrcIPs != 3 || st.LoginFailed != 3 || st.LoginSuccess != 1 {
		t.Errorf("核心数值不符: connections=%d unique=%d failed=%d success=%d",
			st.Connections, st.UniqueSrcIPs, st.LoginFailed, st.LoginSuccess)
	}
	if st.Prev == nil {
		t.Error("with_prev 缺省应为 true（Prev 非 nil）")
	}

	// with_prev=false 显式关闭。
	var st2 query.Stats
	if err := json.Unmarshal([]byte(mustHandle(t, d, "query_stats", `{"with_prev":false}`, win)), &st2); err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if st2.Prev != nil {
		t.Error("with_prev=false 时 Prev 应为 nil")
	}
}

// TestQueryStatsTopNClamp：top_n 缺省 10、请求超上限钳制到 50。
func TestQueryStatsTopNClamp(t *testing.T) {
	db := openDB(t)
	d := NewDispatcher(testCfg(), db, nil, nil, nil)
	win := testWin()

	var seed []*store.Event
	for i := 0; i < 60; i++ {
		ip := "10.1." + jsonInt64(int64(i/256)) + "." + jsonInt64(int64(i%256))
		seed = append(seed, mkEvent(cowrie.EventConnect, win.Since.Add(time.Duration(i)*time.Second),
			map[string]any{"src_ip": ip}))
	}
	mustInsert(t, db, seed...)

	check := func(args string, wantTop int) {
		t.Helper()
		var st query.Stats
		if err := json.Unmarshal([]byte(mustHandle(t, d, "query_stats", args, win)), &st); err != nil {
			t.Fatalf("解码失败: %v", err)
		}
		if len(st.TopSrcIPs) != wantTop {
			t.Errorf("args=%s 返回 top_src_ips %d 条，期望 %d", args, len(st.TopSrcIPs), wantTop)
		}
		if st.UniqueSrcIPs != 60 {
			t.Errorf("unique_src_ips=%d，期望 60", st.UniqueSrcIPs)
		}
	}
	check(`{}`, 10)             // 缺省 top_n=10
	check(`{"top_n":1000}`, 50) // 钳制到 50
}

// TestQueryStatsValidation：跨度校验与参数错误。
func TestQueryStatsValidation(t *testing.T) {
	cfg := testCfg()
	cfg.Reports.MaxQuerySpanDays = 2
	d := NewDispatcher(cfg, openDB(t), nil, nil, nil)
	win := testWin()

	got := wantErr(t, d, "query_stats", `{"since":"2026-10-01T00:00:00Z","until":"2026-10-10T00:00:00Z"}`, win)
	if !strings.Contains(got, "最大跨度 2 天") {
		t.Fatalf("跨度过大错误应包含允许的最大跨度，实际 %q", got)
	}
	got = wantErr(t, d, "query_stats", `{"top_n":0}`, win)
	if !strings.Contains(got, "top_n") {
		t.Fatalf("top_n=0 应报错，实际 %q", got)
	}
	got = wantErr(t, d, "query_stats", `{"unexpected":true}`, win)
	if !strings.Contains(got, "参数不合法") {
		t.Fatalf("未知字段应报错，实际 %q", got)
	}
}
