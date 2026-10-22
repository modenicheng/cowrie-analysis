package cowrie

import (
	"testing"
	"time"
)

var fallback = time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)

// TestParseTimestampFormats 覆盖契约要求的三种格式 + RFC3339、时区转 UTC、失败路径。
func TestParseTimestampFormats(t *testing.T) {
	cases := []struct {
		in      string
		wantUTC string // RFC3339Nano 表示
	}{
		{"2026-10-22T12:34:56.789012345+00:00", "2026-10-22T12:34:56.789012345Z"}, // RFC3339Nano
		{"2026-10-22T12:34:56.789012+0000", "2026-10-22T12:34:56.789012Z"},        // +0000 无冒号
		{"2026-10-22 12:34:56.789012", "2026-10-22T12:34:56.789012Z"},             // 空格分隔无时区
		{"2026-10-22 12:34:56", "2026-10-22T12:34:56Z"},                           // 无小数秒
		{"2026-10-22T04:34:56Z", "2026-10-22T04:34:56Z"},                          // RFC3339
		{"2026-10-22T16:34:56+08:00", "2026-10-22T08:34:56Z"},                     // 时区归一化为 UTC
		{"2026-10-22T16:34:56.5+0800", "2026-10-22T08:34:56.5Z"},                  // 无冒号+短小数
	}
	for _, c := range cases {
		got, err := ParseTimestamp(c.in)
		if err != nil {
			t.Fatalf("ParseTimestamp(%q) 意外失败: %v", c.in, err)
		}
		if s := got.UTC().Format(time.RFC3339Nano); s != c.wantUTC {
			t.Errorf("ParseTimestamp(%q) = %s, 期望 %s", c.in, s, c.wantUTC)
		}
	}
	for _, bad := range []string{"not a time", "", "2026-10-22", "2026/10/22 12:00:00"} {
		if _, err := ParseTimestamp(bad); err == nil {
			t.Errorf("ParseTimestamp(%q) 期望失败，却成功了", bad)
		}
	}
}

// TestParseEventFull 合法完整事件：标准字段全部映射，Raw 无损保留。
func TestParseEventFull(t *testing.T) {
	line := `{"eventid":"cowrie.login.failed","timestamp":"2026-10-22T08:00:00.123456+00:00","session":"sess1","src_ip":"203.0.113.7","src_port":50123,"username":"root","password":"123456","message":"failed login b'b'"}`
	ev, err := ParseEvent([]byte(line), fallback)
	if err != nil {
		t.Fatalf("ParseEvent 失败: %v", err)
	}
	if ev.EventID != "cowrie.login.failed" {
		t.Errorf("EventID = %q", ev.EventID)
	}
	want := time.Date(2026, 10, 22, 8, 0, 0, 123456000, time.UTC)
	if !ev.EventTime.Equal(want) {
		t.Errorf("EventTime = %v, 期望 %v", ev.EventTime, want)
	}
	if ev.SrcIP != "203.0.113.7" || ev.SrcPort != 50123 || ev.Session != "sess1" || ev.Username != "root" {
		t.Errorf("字段映射错误: %+v", ev)
	}
	if ev.Command != "" {
		t.Errorf("无 input 字段时 Command 应为空，得到 %q", ev.Command)
	}
	if ev.Raw != line {
		t.Errorf("Raw 应无损保留原行\n got: %s\nwant: %s", ev.Raw, line)
	}
}

// TestParseEventCommandInput input 为字符串时映射 Command；非字符串则留空。
func TestParseEventCommandInput(t *testing.T) {
	ev, err := ParseEvent([]byte(`{"eventid":"cowrie.command.input","timestamp":"2026-10-22T08:00:00Z","session":"s","input":"cat /etc/shadow; rm -rf /"}`), fallback)
	if err != nil {
		t.Fatalf("ParseEvent 失败: %v", err)
	}
	if ev.Command != "cat /etc/shadow; rm -rf /" {
		t.Errorf("Command = %q，应为原值", ev.Command)
	}
	ev2, err := ParseEvent([]byte(`{"eventid":"cowrie.command.input","input":12345}`), fallback)
	if err != nil {
		t.Fatalf("ParseEvent 失败: %v", err)
	}
	if ev2.Command != "" {
		t.Errorf("input 非字符串时 Command 应为空，得到 %q", ev2.Command)
	}
}

// TestParseEventFilename download 用 url/filename，upload 用 outfile，优先级 filename>url>outfile。
func TestParseEventFilename(t *testing.T) {
	cases := []struct {
		name, line, want string
	}{
		{"download_url", `{"eventid":"cowrie.session.file_download","url":"http://x/y.sh","outfile":"dirty.sh"}`, "http://x/y.sh"},
		{"download_filename优先", `{"eventid":"cowrie.session.file_download","filename":"y.sh","url":"http://x/y.sh","outfile":"dirty.sh"}`, "y.sh"},
		{"download_outfile兜底", `{"eventid":"cowrie.session.file_download","outfile":"dirty.sh"}`, "dirty.sh"},
		{"upload_outfile", `{"eventid":"cowrie.session.file_upload","outfile":"/dirty/uploaded.bin","shasum":"abc123"}`, "/dirty/uploaded.bin"},
		{"都没有", `{"eventid":"cowrie.session.file_upload"}`, ""},
	}
	for _, c := range cases {
		ev, err := ParseEvent([]byte(c.line), fallback)
		if err != nil {
			t.Fatalf("%s: ParseEvent 失败: %v", c.name, err)
		}
		if ev.Filename != c.want {
			t.Errorf("%s: Filename = %q, 期望 %q", c.name, ev.Filename, c.want)
		}
		if ev.Shasum != "" && ev.Shasum != "abc123" {
			t.Errorf("%s: Shasum = %q", c.name, ev.Shasum)
		}
	}
}

// TestParseEventMissingOptional 缺可选字段不报错、不填默认假值。
func TestParseEventMissingOptional(t *testing.T) {
	ev, err := ParseEvent([]byte(`{"eventid":"cowrie.session.connect","timestamp":"2026-10-22T08:00:00Z"}`), fallback)
	if err != nil {
		t.Fatalf("ParseEvent 失败: %v", err)
	}
	if ev.SrcIP != "" || ev.SrcPort != 0 || ev.Session != "" || ev.Username != "" ||
		ev.Command != "" || ev.Filename != "" || ev.Shasum != "" || ev.DurationS != 0 {
		t.Errorf("缺失字段应留空: %+v", ev)
	}
}

// TestParseEventUnknownFields 未知额外字段不报错，Raw 原样保留。
func TestParseEventUnknownFields(t *testing.T) {
	line := `{"eventid":"cowrie.session.closed","timestamp":"2026-10-22T08:00:00Z","duration":123.4,"unknown_nested":{"a":[1,2,3]},"weird":true}`
	ev, err := ParseEvent([]byte(line), fallback)
	if err != nil {
		t.Fatalf("未知字段不得报错: %v", err)
	}
	if ev.DurationS != 123.4 {
		t.Errorf("DurationS = %v, 期望 123.4", ev.DurationS)
	}
	if ev.Raw != line {
		t.Errorf("Raw 应保留未知字段原文:\n got: %s\nwant: %s", ev.Raw, line)
	}
}

// TestParseEventBadTimestampFallback 非法/数字型 timestamp 回退 fallback 且不报错。
func TestParseEventBadTimestampFallback(t *testing.T) {
	for _, line := range []string{
		`{"eventid":"cowrie.session.connect","timestamp":"昨天"}`,
		`{"eventid":"cowrie.session.connect","timestamp":1777000000}`,
		`{"eventid":"cowrie.session.connect"}`,
	} {
		ev, err := ParseEvent([]byte(line), fallback)
		if err != nil {
			t.Fatalf("%s: 意外报错: %v", line, err)
		}
		if !ev.EventTime.Equal(fallback) {
			t.Errorf("%s: EventTime = %v, 期望 fallback %v", line, ev.EventTime, fallback)
		}
	}
}

// TestParseEventTypeCoercion 类型不符尽力转换：数字 src_ip、字符串 src_port、字符串 duration。
func TestParseEventTypeCoercion(t *testing.T) {
	ev, err := ParseEvent([]byte(`{"eventid":"e","src_ip":3232235777,"src_port":"2222","duration":"42.5"}`), fallback)
	if err != nil {
		t.Fatalf("ParseEvent 失败: %v", err)
	}
	if ev.SrcIP != "3232235777" {
		t.Errorf("数字 src_ip 应转为字符串, 得到 %q", ev.SrcIP)
	}
	if ev.SrcPort != 2222 {
		t.Errorf("字符串 src_port 应转为数字, 得到 %d", ev.SrcPort)
	}
	if ev.DurationS != 42.5 {
		t.Errorf("字符串 duration 应转为浮点, 得到 %v", ev.DurationS)
	}
}

// TestParseEventPlainText 纯文本行 → error 且不返回 Event。
func TestParseEventPlainText(t *testing.T) {
	for _, line := range []string{"hello world", "{broken json", ""} {
		ev, err := ParseEvent([]byte(line), fallback)
		if err == nil {
			t.Errorf("%q 期望报错", line)
		}
		if ev != nil {
			t.Errorf("%q 报错时不应返回 Event", line)
		}
	}
}

// TestParseEventEmptyObject 空对象 {} 不报错，EventID=""，时间回退 fallback。
func TestParseEventEmptyObject(t *testing.T) {
	ev, err := ParseEvent([]byte("{}"), fallback)
	if err != nil {
		t.Fatalf("空对象不应报错: %v", err)
	}
	if ev.EventID != "" {
		t.Errorf("EventID = %q, 期望空", ev.EventID)
	}
	if !ev.EventTime.Equal(fallback) {
		t.Errorf("EventTime = %v, 期望 fallback", ev.EventTime)
	}
	if ev.Raw != "{}" {
		t.Errorf("Raw = %q", ev.Raw)
	}
}

// TestParseEventCRLF 行尾 \r\n 应从 Raw 中剥掉，字段不受影响。
func TestParseEventCRLF(t *testing.T) {
	ev, err := ParseEvent([]byte("{\"eventid\":\"e\"}\r\n"), fallback)
	if err != nil {
		t.Fatalf("ParseEvent 失败: %v", err)
	}
	if ev.Raw != "{\"eventid\":\"e\"}" {
		t.Errorf("Raw = %q, 应去掉行尾 CR/LF", ev.Raw)
	}
}
