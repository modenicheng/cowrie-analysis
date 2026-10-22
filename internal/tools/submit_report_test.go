package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// fakeSubmitter 记录提交内容的假 ReportSubmitter。
type fakeSubmitter struct {
	accepted bool
	reason   string
	draft    []byte
	taskType string
	calls    int
}

func (f *fakeSubmitter) SubmitDraft(_ context.Context, draft []byte, taskType string) (bool, string) {
	f.calls++
	f.draft = append([]byte(nil), draft...)
	f.taskType = taskType
	return f.accepted, f.reason
}

// validDraft 返回一份合法的 daily 报告草稿 JSON。
func validDraft() string {
	return `{"type":"daily","title":"E3 安全日报 2026-10-21",` +
		`"summary":"过去 24 小时观测到多来源 SSH 暴力破解尝试，详见 findings 与证据引用。",` +
		`"findings":[{"title":"SSH 暴力破解","detail":"203.0.113.7 在窗口内发起多次失败登录",` +
		`"severity":"high","evidence":["event:12","session:sess-1"]}],` +
		`"key_stats":{"connections":12,"unique_src_ips":4,"login_success":0,"login_failed":9},` +
		`"confidence":0.8,"data_limitations":"无已知采集缺口"}`
}

// mutateDraft 反序列化草稿、施加修改并重新序列化。
func mutateDraft(t *testing.T, f func(m map[string]any)) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(validDraft()), &m); err != nil {
		t.Fatalf("基准草稿解码失败: %v", err)
	}
	f(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("修改后草稿序列化失败: %v", err)
	}
	return string(out)
}

// TestSubmitReportAccepted：合法 daily 草稿 + win.Type=daily + submitter 接受
// → {"accepted":true}；draft 原样传递。
func TestSubmitReportAccepted(t *testing.T) {
	fs := &fakeSubmitter{accepted: true}
	d := NewDispatcher(testCfg(), nil, nil, fs, nil)
	args := validDraft()

	res := mustHandle(t, d, "submit_report", args, testWin())
	if strings.TrimSpace(res) != `{"accepted":true}` {
		t.Fatalf("结果 %q，期望 {\"accepted\":true}", res)
	}
	if fs.calls != 1 {
		t.Fatalf("SubmitDraft 调用 %d 次，期望 1", fs.calls)
	}
	if string(fs.draft) != args {
		t.Fatalf("draft 未原样传递:\n got  %s\n want %s", fs.draft, args)
	}
	if fs.taskType != "daily" {
		t.Errorf("taskType=%q，期望 daily", fs.taskType)
	}
}

// TestSubmitReportTypeMismatch：type 与任务窗口不符 → error 且说明当前任务类型。
func TestSubmitReportTypeMismatch(t *testing.T) {
	fs := &fakeSubmitter{accepted: true}
	d := NewDispatcher(testCfg(), nil, nil, fs, nil)

	weekly := strings.Replace(validDraft(), `"type":"daily"`, `"type":"weekly"`, 1)
	got := wantErr(t, d, "submit_report", weekly, testWin())
	if !strings.Contains(got, "daily") || !strings.Contains(got, "weekly") {
		t.Fatalf("type 不匹配错误应说明当前任务类型，实际 %q", got)
	}
	if fs.calls != 0 {
		t.Errorf("校验失败不应调用 SubmitDraft，实际调用 %d 次", fs.calls)
	}
}

// TestSubmitReportValidation：各项非法输入分别返回可读错误且不触达 submitter。
func TestSubmitReportValidation(t *testing.T) {
	cases := []struct {
		name    string
		draft   string
		wantErr string
	}{
		{"summary 超长", mutateDraft0(func(m map[string]any) {
			m["summary"] = strings.Repeat("长", 4001)
		}), "summary"},
		{"summary 过短", mutateDraft0(func(m map[string]any) {
			m["summary"] = "太短"
		}), "summary"},
		{"title 为空", mutateDraft0(func(m map[string]any) {
			m["title"] = ""
		}), "title"},
		{"findings 超量", mutateDraft0(func(m map[string]any) {
			f := m["findings"].([]any)[0].(map[string]any)
			list := make([]any, 51)
			for i := range list {
				list[i] = map[string]any{"title": "t", "detail": "d", "severity": "info"}
			}
			m["findings"] = append([]any{f}, list...)
		}), "findings"},
		{"severity 非法", mutateDraft0(func(m map[string]any) {
			m["findings"].([]any)[0].(map[string]any)["severity"] = "extreme"
		}), "severity"},
		{"finding 标题超长", mutateDraft0(func(m map[string]any) {
			m["findings"].([]any)[0].(map[string]any)["title"] = strings.Repeat("题", 121)
		}), "findings[0].title"},
		{"evidence 超项", mutateDraft0(func(m map[string]any) {
			ev := make([]any, 21)
			for i := range ev {
				ev[i] = "event:1"
			}
			m["findings"].([]any)[0].(map[string]any)["evidence"] = ev
		}), "evidence"},
		{"key_stats 缺字段", mutateDraft0(func(m map[string]any) {
			delete(m["key_stats"].(map[string]any), "login_failed")
		}), "login_failed"},
		{"key_stats 整体缺失", mutateDraft0(func(m map[string]any) {
			delete(m, "key_stats")
		}), "key_stats"},
		{"key_stats 负数", mutateDraft0(func(m map[string]any) {
			m["key_stats"].(map[string]any)["connections"] = -1
		}), "非负整数"},
		{"key_stats 非整数", mutateDraft0(func(m map[string]any) {
			m["key_stats"].(map[string]any)["unique_src_ips"] = 3.5
		}), "非负整数"},
		{"confidence 缺失", mutateDraft0(func(m map[string]any) {
			delete(m, "confidence")
		}), "confidence"},
		{"confidence 超界", mutateDraft0(func(m map[string]any) {
			m["confidence"] = 1.5
		}), "confidence"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := &fakeSubmitter{accepted: true}
			d := NewDispatcher(testCfg(), nil, nil, fs, nil)
			got := wantErr(t, d, "submit_report", c.draft, testWin())
			if !strings.Contains(got, c.wantErr) {
				t.Fatalf("错误消息 %q 应包含 %q", got, c.wantErr)
			}
			if fs.calls != 0 {
				t.Errorf("校验失败不应调用 SubmitDraft")
			}
		})
	}
}

// mutateDraft0 与 mutateDraft 相同，但允许在表驱动用例中静态使用（直接
// panic 于非法基准，基准本身由单测保证合法）。
func mutateDraft0(f func(m map[string]any)) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(validDraft()), &m); err != nil {
		panic(err)
	}
	f(m)
	out, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return string(out)
}

// TestSubmitReportRejected：submitter 拒绝时返回 accepted:false + reason，
// 不返回 error（模型可读取 reason 修正重试）。
func TestSubmitReportRejected(t *testing.T) {
	reason := "key_stats.connections 与 SQL 统计不一致：期望 12，得到 15"
	fs := &fakeSubmitter{accepted: false, reason: reason}
	d := NewDispatcher(testCfg(), nil, nil, fs, nil)

	res := mustHandle(t, d, "submit_report", validDraft(), testWin())
	var got struct {
		Accepted bool   `json:"accepted"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(res), &got); err != nil {
		t.Fatalf("解码失败: %v\n%s", err, res)
	}
	if got.Accepted {
		t.Error("accepted 应为 false")
	}
	if got.Reason != reason {
		t.Errorf("reason=%q，期望 %q", got.Reason, reason)
	}
	if fs.calls != 1 {
		t.Errorf("SubmitDraft 应被调用 1 次，实际 %d", fs.calls)
	}
}

// TestSubmitReportForbiddenKeys：草稿顶层出现 url/topic/token 键 → error。
func TestSubmitReportForbiddenKeys(t *testing.T) {
	for _, key := range []string{"url", "topic", "token"} {
		t.Run(key, func(t *testing.T) {
			fs := &fakeSubmitter{accepted: true}
			d := NewDispatcher(testCfg(), nil, nil, fs, nil)
			draft := mutateDraft(t, func(m map[string]any) { m[key] = "https://attacker.example" })
			got := wantErr(t, d, "submit_report", draft, testWin())
			if !strings.Contains(got, key) {
				t.Fatalf("错误消息 %q 应包含被拒绝的字段名 %q", got, key)
			}
			if fs.calls != 0 {
				t.Errorf("携带禁止字段的草稿不应触达 submitter")
			}
		})
	}
}

// TestSubmitReportUnknownFieldTolerated：未知字段（type 之外的一般性附加
// 字段）不报错，草稿照常提交。
func TestSubmitReportUnknownFieldTolerated(t *testing.T) {
	fs := &fakeSubmitter{accepted: true}
	d := NewDispatcher(testCfg(), nil, nil, fs, nil)
	draft := mutateDraft(t, func(m map[string]any) { m["extra_note"] = "模型附加说明" })

	res := mustHandle(t, d, "submit_report", draft, testWin())
	if strings.TrimSpace(res) != `{"accepted":true}` {
		t.Fatalf("未知字段应被容忍，结果 %q", res)
	}
	if fs.calls != 1 {
		t.Errorf("SubmitDraft 应被调用 1 次，实际 %d", fs.calls)
	}
}
