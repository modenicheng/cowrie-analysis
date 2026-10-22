// S2 凭据隔离（SPEC §9-3、§16 验收 11、§18 禁止清单）。
//
// 验收点：
//  1. script-runner 子进程（真实 exe）看不到宿主环境变量：API Key 与
//     ntfy Token 绝不进入脚本执行环境，typeof process/require 均为 undefined；
//  2. LLM 请求：Authorization 头携带 key，但请求 JSON 体不含 key
//     （密钥不进模型输入）；
//  3. ntfy Publisher/Client 的日志（bytes.Buffer slog writer）在发布失败
//     （mock 503）时不含 Token；
//  4. config.Redacted() 输出不含任何密钥值，只含环境变量名。
package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/modenc/e3-security-analyst/internal/config"
	"github.com/modenc/e3-security-analyst/internal/llm"
	"github.com/modenc/e3-security-analyst/internal/ntfy"
	"github.com/modenc/e3-security-analyst/internal/sandbox"
	"github.com/modenc/e3-security-analyst/internal/store"
)

// 测试用秘密值（绝不允许出现在脚本输出、日志与 Redacted 摘要中）。
const (
	secretLLMKey = "supersecret-abc"
	secretNtfy   = "tok-secret-xyz"
)

// TestS2SandboxCredentialIsolation：宿主设置了两个凭据的环境变量，
// 真实 script-runner 子进程内的脚本无法读到任何秘密。
func TestS2SandboxCredentialIsolation(t *testing.T) {
	t.Setenv("DEEPSEEK_API_KEY", secretLLMKey)
	t.Setenv("NTFY_TOKEN", secretNtfy)

	r := sandbox.NewRunner(runnerBin, sandbox.Limits{
		TimeoutMS:      5000,
		MaxInputBytes:  1 << 20,
		MaxOutputBytes: 1 << 20,
	}, 1)

	// 探测脚本：全局对象属性名清单 + process/require/fetch 类型 + 直接
	// 按环境变量名猜测的全局属性。
	code := `JSON.stringify({
		names: Object.getOwnPropertyNames(globalThis).sort(),
		process: typeof process,
		require: typeof require,
		fetch: typeof fetch,
		guessKey: String(globalThis.DEEPSEEK_API_KEY),
		guessTok: String(globalThis.NTFY_TOKEN)
	})`
	res, err := r.Execute(context.Background(), code, nil, 3000)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.OK {
		t.Fatalf("探测脚本失败: %q %q", res.ErrorType, res.ErrorMessage)
	}
	// res.Result 是脚本返回的 JSON 字符串（即被再编码一层），先解引号。
	var inner string
	if err := json.Unmarshal(res.Result, &inner); err != nil {
		t.Fatalf("解引用探测结果 %s: %v", res.Result, err)
	}
	var probe struct {
		Names    []string `json:"names"`
		Process  string   `json:"process"`
		Require  string   `json:"require"`
		Fetch    string   `json:"fetch"`
		GuessKey string   `json:"guessKey"`
		GuessTok string   `json:"guessTok"`
	}
	if err := json.Unmarshal([]byte(inner), &probe); err != nil {
		t.Fatalf("解析探测结果 %s: %v", inner, err)
	}

	// (a) 无任何宿主接口对象。
	for _, typ := range []struct{ name, got string }{
		{"typeof process", probe.Process},
		{"typeof require", probe.Require},
		{"typeof fetch", probe.Fetch},
	} {
		if typ.got != "undefined" {
			t.Errorf("沙箱内 %s = %q, 期望 undefined", typ.name, typ.got)
		}
	}
	for _, forbidden := range []string{"process", "os", "require", "fetch", "Go"} {
		for _, n := range probe.Names {
			if n == forbidden {
				t.Errorf("globalThis 暴露了宿主对象 %q（属性: %v）", forbidden, probe.Names)
			}
		}
	}

	// (b) 按环境变量名猜全局属性只能是 undefined。
	if probe.GuessKey != "undefined" || probe.GuessTok != "undefined" {
		t.Errorf("环境变量名作为全局属性可见: key=%q token=%q", probe.GuessKey, probe.GuessTok)
	}

	// (c) 整个输出（含属性名清单）不含任何秘密值。
	if out := string(res.Result); strings.Contains(out, secretLLMKey) || strings.Contains(out, secretNtfy) {
		t.Errorf("子进程输出泄露宿主凭据: %s", out)
	}
}

// TestS2LLMKeyHeaderOnly：LLM API Key 只经 Authorization 头传输，
// 绝不进入请求 JSON 体（模型输入）。
func TestS2LLMKeyHeaderOnly(t *testing.T) {
	m := newLLMMock(t)
	m.steps = []mockStep{stepFinal(`{"ok":true}`)}

	client := llm.NewClient(llm.ClientConfig{
		BaseURL: m.srv.URL,
		Model:   "mock-model",
		APIKey:  secretLLMKey,
		Timeout: 10 * time.Second,
	})
	res, err := client.Run(context.Background(), llm.RunRequest{
		SystemPrompt: "你是安全分析助手",
		UserPrompt:   "分析以下蜜罐数据（json 输出）",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Content) == 0 {
		t.Fatal("最终输出为空")
	}

	auths := m.authorizations()
	if len(auths) != 1 {
		t.Fatalf("LLM 请求数 = %d, 期望 1", len(auths))
	}
	if auths[0] != "Bearer "+secretLLMKey {
		t.Errorf("Authorization 头 = %q, 期望 Bearer <key>", auths[0])
	}
	body := m.requests()[0]
	if strings.Contains(body, secretLLMKey) {
		t.Errorf("请求 JSON 体泄露 API Key:\n%.800s", body)
	}
}

// TestS2NtfyLogsNoToken：ntfy 发布失败（mock 503）时，Publisher 日志
// （bytes.Buffer slog writer）不含 Token；Token 只出现在 HTTP 头。
func TestS2NtfyLogsNoToken(t *testing.T) {
	mock := newNtfyMock(t)
	mock.setStatus(503)

	db := openTestDB(t)
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	client := ntfy.NewClient(ntfy.ClientConfig{
		BaseURL: mock.srv.URL,
		Token:   secretNtfy,
		Timeout: 5 * time.Second,
	})
	pub := ntfy.NewPublisher(client, db, 1, 4000, logger)

	n := &store.Notification{
		DedupeKey: "sec-s2-503",
		Kind:      "alert.login_success",
		Topic:     "e3alerts",
		Title:     "[E3蜜罐] 蜜罐模拟登录成功",
		Body:      "时间：2026-10-22 10:00:00\n源IP：203.0.113.1",
		Priority:  4,
	}
	deduped, err := pub.Enqueue(context.Background(), n)
	if err != nil || deduped {
		t.Fatalf("Enqueue: deduped=%v err=%v", deduped, err)
	}
	if err := pub.TrySend(context.Background(), n); err == nil {
		t.Fatal("503 发布应失败")
	}

	logs := buf.String()
	// 日志确实记录了这次失败（避免空日志造成假阴性）。
	if !strings.Contains(logs, "dedupe_key") && !strings.Contains(logs, "sec-s2-503") {
		t.Fatalf("日志未记录发布失败，缓冲区内容:\n%s", logs)
	}
	if strings.Contains(logs, secretNtfy) {
		t.Errorf("ntfy 日志泄露 Token:\n%s", logs)
	}
	// Token 只允许出现在 HTTP Authorization 头（发往服务端的请求）。
	reqs := mock.requests()
	if len(reqs) == 0 {
		t.Fatal("mock 未收到请求")
	}
	if reqs[0].Auth != "Bearer "+secretNtfy {
		t.Errorf("Authorization 头 = %q, 期望 Bearer <token>", reqs[0].Auth)
	}
	// 503 是可重试错误，最终态为 failed 且 last_error 不含 Token。
	var status, lastErr string
	if err := db.SQL().QueryRowContext(context.Background(),
		`SELECT status, COALESCE(last_error,'') FROM notifications WHERE dedupe_key = 'sec-s2-503'`).
		Scan(&status, &lastErr); err != nil {
		t.Fatalf("查询通知状态: %v", err)
	}
	if status != "failed" {
		t.Errorf("通知状态 = %q, 期望 failed（maxAttempts=1）", status)
	}
	if strings.Contains(lastErr, secretNtfy) {
		t.Errorf("notifications.last_error 泄露 Token: %s", lastErr)
	}
}

// TestS2ConfigRedacted：Redacted 摘要只含环境变量名，不含解析值。
func TestS2ConfigRedacted(t *testing.T) {
	t.Setenv("DEEPSEEK_API_KEY", secretLLMKey)
	t.Setenv("NTFY_TOKEN", secretNtfy)

	cfg := config.Default()
	cfg.LLM.APIKeyEnv = "DEEPSEEK_API_KEY"
	cfg.Ntfy.TokenEnv = "NTFY_TOKEN"

	out := cfg.Redacted()
	for _, name := range []string{"DEEPSEEK_API_KEY", "NTFY_TOKEN"} {
		if !strings.Contains(out, name) {
			t.Errorf("Redacted 应包含环境变量名 %s: %s", name, out)
		}
	}
	if strings.Contains(out, secretLLMKey) || strings.Contains(out, secretNtfy) {
		t.Errorf("Redacted 泄露密钥值: %s", out)
	}
}

// TestS2NoAPIKeyNoRequest：LLM Key 缺失时客户端不发任何网络请求。
func TestS2NoAPIKeyNoRequest(t *testing.T) {
	m := newLLMMock(t)
	client := llm.NewClient(llm.ClientConfig{
		BaseURL: m.srv.URL, Model: "mock-model", APIKey: "", Timeout: 5 * time.Second,
	})
	_, err := client.Run(context.Background(), llm.RunRequest{UserPrompt: "x"})
	if !errors.Is(err, llm.ErrNoAPIKey) {
		t.Fatalf("空 Key 应返回 ErrNoAPIKey, 实际 %v", err)
	}
	if n := len(m.requests()); n != 0 {
		t.Errorf("空 Key 不应发出请求, 实际 %d 个", n)
	}
}
