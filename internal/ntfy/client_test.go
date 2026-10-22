package ntfy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

// recorder 记录 mock 服务端收到的请求，供测试断言（并发安全）。
type recorder struct {
	mu     sync.Mutex
	method string
	path   string
	body   string
	header http.Header
	hits   atomic.Int32
}

func (rec *recorder) record(r *http.Request, body []byte) {
	rec.hits.Add(1)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.method = r.Method
	rec.path = r.URL.Path
	rec.body = string(body)
	rec.header = r.Header.Clone()
}

func (rec *recorder) snapshot() (method, path, body string, header http.Header) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return rec.method, rec.path, rec.body, rec.header
}

// startServer 启动返回固定状态码与响应体的 mock ntfy 服务；
// delay > 0 时在响应前睡眠，用于模拟服务端超时。
func startServer(t *testing.T, status int, respBody string, delay time.Duration) (*httptest.Server, *recorder) {
	t.Helper()
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.record(r, body)
		if delay > 0 {
			time.Sleep(delay)
		}
		w.WriteHeader(status)
		fmt.Fprint(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func validMsg() Message {
	return Message{
		Topic:    "alerts",
		Title:    "蜜罐告警",
		Body:     "src=1.2.3.4 session=abc123",
		Priority: 3,
		Tags:     []string{"warning"},
	}
}

// 1. 正常发布：方法、路径、头、正文与 outcome 全部断言。
func TestPublishSuccess(t *testing.T) {
	srv, rec := startServer(t, http.StatusOK, `{"id":"zT9mY7fR2x"}`, 0)
	c := NewClient(ClientConfig{BaseURL: srv.URL + "/", Token: "tk_test_token", Timeout: 5 * time.Second})

	out, err := c.Publish(context.Background(), Message{
		Topic:    "alerts",
		Title:    "蜜罐登录成功告警",
		Body:     "src=1.2.3.4 session=abc123",
		Priority: 4,
		Tags:     []string{"warning", "skull"},
	})
	if err != nil {
		t.Fatalf("Publish() error = %v, want nil", err)
	}
	if got := rec.hits.Load(); got != 1 {
		t.Errorf("request count = %d, want 1", got)
	}
	method, path, body, hdr := rec.snapshot()
	if method != http.MethodPost {
		t.Errorf("method = %q, want POST", method)
	}
	if path != "/alerts" {
		t.Errorf("path = %q, want /alerts", path)
	}
	if body != "src=1.2.3.4 session=abc123" {
		t.Errorf("body = %q", body)
	}
	if got := hdr.Get("Title"); got != "蜜罐登录成功告警" {
		t.Errorf("Title header = %q", got)
	}
	if got := hdr.Get("Priority"); got != "4" {
		t.Errorf("Priority header = %q, want %q", got, "4")
	}
	if got := hdr.Get("Tags"); got != "warning,skull" {
		t.Errorf("Tags header = %q, want %q", got, "warning,skull")
	}
	if got := hdr.Get("Authorization"); got != "Bearer tk_test_token" {
		t.Errorf("Authorization header = %q", got)
	}
	if out.HTTPStatus != http.StatusOK {
		t.Errorf("outcome.HTTPStatus = %d, want 200", out.HTTPStatus)
	}
	if out.ResponseID != "zT9mY7fR2x" {
		t.Errorf("outcome.ResponseID = %q, want %q", out.ResponseID, "zT9mY7fR2x")
	}
	if out.SentAt.IsZero() {
		t.Error("outcome.SentAt is zero, want set on success")
	}
}

// 2. 认证失败 401/403：HTTPStatusError、不可重试、仅 1 次请求（无内置重试）。
func TestPublishAuthFailureNotRetryable(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			srv, rec := startServer(t, code, `{"code":40103,"http":401,"error":"forbidden"}`, 0)
			c := NewClient(ClientConfig{BaseURL: srv.URL, Token: "tk_bad", Timeout: 5 * time.Second})

			out, err := c.Publish(context.Background(), validMsg())
			if err == nil {
				t.Fatal("Publish() error = nil, want HTTPStatusError")
			}
			var he *HTTPStatusError
			if !errors.As(err, &he) {
				t.Fatalf("error %v (%T) is not *HTTPStatusError", err, err)
			}
			if he.Code != code {
				t.Errorf("HTTPStatusError.Code = %d, want %d", he.Code, code)
			}
			if IsRetryable(err) {
				t.Error("IsRetryable() = true, want false")
			}
			if !errors.Is(err, &HTTPStatusError{Code: code}) {
				t.Error("errors.Is by status code failed")
			}
			if got := rec.hits.Load(); got != 1 {
				t.Errorf("request count = %d, want exactly 1 (no built-in retry)", got)
			}
			if out.HTTPStatus != code {
				t.Errorf("outcome.HTTPStatus = %d, want %d", out.HTTPStatus, code)
			}
		})
	}
}

// 3. 429 限流：可重试。
func TestPublishRateLimitedRetryable(t *testing.T) {
	srv, _ := startServer(t, http.StatusTooManyRequests, `{"code":42901,"error":"too many requests"}`, 0)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Token: "tk", Timeout: 5 * time.Second})

	_, err := c.Publish(context.Background(), validMsg())
	if err == nil {
		t.Fatal("Publish() error = nil, want HTTPStatusError")
	}
	var he *HTTPStatusError
	if !errors.As(err, &he) || he.Code != http.StatusTooManyRequests {
		t.Fatalf("error = %v, want HTTPStatusError{429}", err)
	}
	if !IsRetryable(err) {
		t.Error("IsRetryable(429) = false, want true")
	}
}

// 4. 503 服务不可用：可重试。
func TestPublishServerErrorRetryable(t *testing.T) {
	srv, _ := startServer(t, http.StatusServiceUnavailable, `{"error":"service unavailable"}`, 0)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Timeout: 5 * time.Second})

	_, err := c.Publish(context.Background(), validMsg())
	if err == nil {
		t.Fatal("Publish() error = nil, want HTTPStatusError")
	}
	var he *HTTPStatusError
	if !errors.As(err, &he) || he.Code != http.StatusServiceUnavailable {
		t.Fatalf("error = %v, want HTTPStatusError{503}", err)
	}
	if !IsRetryable(err) {
		t.Error("IsRetryable(503) = false, want true")
	}
}

// 5. 服务超时（mock 睡眠 + 客户端短超时）：返回错误且可重试。
func TestPublishTimeoutRetryable(t *testing.T) {
	srv, _ := startServer(t, http.StatusOK, `{"id":"never"}`, 500*time.Millisecond)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Timeout: 50 * time.Millisecond})

	start := time.Now()
	_, err := c.Publish(context.Background(), validMsg())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Publish() error = nil, want timeout error")
	}
	if elapsed > 400*time.Millisecond {
		t.Errorf("Publish took %v, client timeout did not apply", elapsed)
	}
	if !IsRetryable(err) {
		t.Errorf("IsRetryable(timeout err) = false, want true (err=%v)", err)
	}
}

// 6. 2xx 但响应体非 JSON：仍视为成功，ResponseID 为空。
func TestPublishNonJSONBodyStillSuccess(t *testing.T) {
	srv, _ := startServer(t, http.StatusOK, `oops, not json`, 0)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Timeout: 5 * time.Second})

	out, err := c.Publish(context.Background(), validMsg())
	if err != nil {
		t.Fatalf("Publish() error = %v, want nil (non-JSON body must not fail success)", err)
	}
	if out.HTTPStatus != http.StatusOK {
		t.Errorf("outcome.HTTPStatus = %d, want 200", out.HTTPStatus)
	}
	if out.ResponseID != "" {
		t.Errorf("outcome.ResponseID = %q, want empty", out.ResponseID)
	}
}

// 7. 消息超长（>4096 字节）：本地拒绝、不发请求；恰好等于上限应放行。
func TestPublishBodyTooLargeRejectedLocally(t *testing.T) {
	srv, rec := startServer(t, http.StatusOK, `{"id":"x"}`, 0)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Timeout: 5 * time.Second})

	m := validMsg()
	m.Body = strings.Repeat("x", MaxBodyBytes+1)
	_, err := c.Publish(context.Background(), m)
	if err == nil {
		t.Fatal("Publish() error = nil, want ValidationError")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "body" {
		t.Fatalf("error = %v, want ValidationError{body}", err)
	}
	if IsRetryable(err) {
		t.Error("IsRetryable(too-large body) = true, want false")
	}
	if got := rec.hits.Load(); got != 0 {
		t.Errorf("request count = %d, want 0 (must reject before any request)", got)
	}

	// 边界：恰好 MaxBodyBytes 字节应成功。
	m.Body = strings.Repeat("x", MaxBodyBytes)
	out, err := c.Publish(context.Background(), m)
	if err != nil || out.HTTPStatus != http.StatusOK {
		t.Fatalf("exact-limit publish err=%v out=%+v, want success", err, out)
	}
}

// 8. Topic 非法（空、含 /、含空格、含非 ASCII、超长）：本地拒绝、不发请求。
func TestPublishInvalidTopicRejectedLocally(t *testing.T) {
	srv, rec := startServer(t, http.StatusOK, `{"id":"x"}`, 0)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Timeout: 5 * time.Second})

	for _, topic := range []string{"", "bad/topic", "also/bad", "has space", "中文", strings.Repeat("a", 65)} {
		m := validMsg()
		m.Topic = topic
		_, err := c.Publish(context.Background(), m)
		if err == nil {
			t.Errorf("topic %q: error = nil, want reject", topic)
			continue
		}
		var ve *ValidationError
		if !errors.As(err, &ve) || ve.Field != "topic" {
			t.Errorf("topic %q: error = %v, want ValidationError{topic}", topic, err)
		}
		if IsRetryable(err) {
			t.Errorf("topic %q: IsRetryable = true, want false", topic)
		}
	}
	if got := rec.hits.Load(); got != 0 {
		t.Errorf("request count = %d, want 0", got)
	}
}

// 9. Token 为空：匿名模式，不携带 Authorization 头。
func TestPublishAnonymousOmitsAuthorization(t *testing.T) {
	srv, rec := startServer(t, http.StatusOK, `{"id":"anon"}`, 0)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Timeout: 5 * time.Second}) // Token 留空

	if _, err := c.Publish(context.Background(), validMsg()); err != nil {
		t.Fatalf("Publish() error = %v, want nil", err)
	}
	_, _, _, hdr := rec.snapshot()
	if _, ok := hdr["Authorization"]; ok {
		t.Errorf("Authorization header present (%q), want absent in anonymous mode", hdr.Get("Authorization"))
	}
}

// 补充：空正文本地拒绝。
func TestPublishEmptyBodyRejectedLocally(t *testing.T) {
	srv, rec := startServer(t, http.StatusOK, `{"id":"x"}`, 0)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Timeout: 5 * time.Second})

	m := validMsg()
	m.Body = ""
	_, err := c.Publish(context.Background(), m)
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "body" {
		t.Fatalf("error = %v, want ValidationError{body}", err)
	}
	if got := rec.hits.Load(); got != 0 {
		t.Errorf("request count = %d, want 0", got)
	}
}

// 补充：Priority 越界本地拒绝。
func TestPublishInvalidPriorityRejectedLocally(t *testing.T) {
	srv, rec := startServer(t, http.StatusOK, `{"id":"x"}`, 0)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Timeout: 5 * time.Second})

	for _, p := range []int{0, -1, 6, 100} {
		m := validMsg()
		m.Priority = p
		_, err := c.Publish(context.Background(), m)
		var ve *ValidationError
		if !errors.As(err, &ve) || ve.Field != "priority" {
			t.Errorf("priority %d: error = %v, want ValidationError{priority}", p, err)
		}
		if IsRetryable(err) {
			t.Errorf("priority %d: IsRetryable = true, want false", p)
		}
	}
	if got := rec.hits.Load(); got != 0 {
		t.Errorf("request count = %d, want 0", got)
	}
}

// 补充：Title 按 rune 截断至 200 字节内，且移除控制字符。
func TestPublishTitleTruncatedToSafeBoundary(t *testing.T) {
	srv, rec := startServer(t, http.StatusOK, `{"id":"t"}`, 0)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Timeout: 5 * time.Second})

	m := validMsg()
	m.Title = strings.Repeat("警", 150) + "\nX" // 450 字节 + 控制字符
	if _, err := c.Publish(context.Background(), m); err != nil {
		t.Fatalf("Publish() error = %v, want nil", err)
	}
	_, _, _, hdr := rec.snapshot()
	got := hdr.Get("Title")
	if len(got) > MaxTitleBytes {
		t.Errorf("Title header is %d bytes, want <= %d", len(got), MaxTitleBytes)
	}
	if !utf8.ValidString(got) {
		t.Errorf("Title header is not valid UTF-8: %q", got)
	}
	if want := strings.Repeat("警", MaxTitleBytes/3); got != want {
		t.Errorf("Title header = %q, want %q (rune-safe truncation)", got, want)
	}
}

// 补充：ctx 取消立即返回，不等待服务端。
func TestPublishContextCanceledReturnsImmediately(t *testing.T) {
	srv, _ := startServer(t, http.StatusOK, `{"id":"never"}`, 2*time.Second)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Timeout: 5 * time.Second})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := c.Publish(ctx, validMsg())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Publish() error = nil, want context.Canceled")
	}
	if elapsed > time.Second {
		t.Errorf("Publish took %v, want immediate return on canceled ctx", elapsed)
	}
}

// 补充：Markdown=true 携带 "Markdown: yes" 头、Attach 非空携带 "Attach"
// 头（原值透传）；两者缺席时对应头不存在（与历史行为一致）。
func TestPublishMarkdownAndAttachHeaders(t *testing.T) {
	srv, rec := startServer(t, http.StatusOK, `{"id":"img"}`, 0)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Timeout: 5 * time.Second})

	attachURL := "https://img-host.modenc.top/e3-reports/daily/20261022-abcd.png"
	m := validMsg()
	m.Markdown = true
	m.Attach = attachURL
	if _, err := c.Publish(context.Background(), m); err != nil {
		t.Fatalf("Publish() error = %v, want nil", err)
	}
	_, _, _, hdr := rec.snapshot()
	if got := hdr.Get("Markdown"); got != "yes" {
		t.Errorf("Markdown header = %q, want %q", got, "yes")
	}
	if got := hdr.Get("Attach"); got != attachURL {
		t.Errorf("Attach header = %q, want %q", got, attachURL)
	}

	// 缺席：默认消息（Markdown=false、Attach=""）不携带两个头。
	if _, err := c.Publish(context.Background(), validMsg()); err != nil {
		t.Fatalf("Publish() plain error = %v, want nil", err)
	}
	_, _, _, hdr = rec.snapshot()
	for _, name := range []string{"Markdown", "Attach"} {
		if _, ok := hdr[name]; ok {
			t.Errorf("%s header present (%q), want absent", name, hdr.Get(name))
		}
	}
}

// 补充：非法 Attach（非 URL、ftp scheme、超长）本地拒绝且不发任何请求。
func TestPublishInvalidAttachRejectedLocally(t *testing.T) {
	srv, rec := startServer(t, http.StatusOK, `{"id":"x"}`, 0)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Timeout: 5 * time.Second})

	badAttaches := []string{
		"notaurl",                           // 无 scheme/host
		"ftp://files.example.com/chart.png", // 非 http(s) scheme
		"http://" + strings.Repeat("a", maxAttachBytes+1),  // 超长（2049 字节）
		"https://" + strings.Repeat("a", maxAttachBytes+2), // 超长（https 也拒）
	}
	for _, attach := range badAttaches {
		m := validMsg()
		m.Attach = attach
		_, err := c.Publish(context.Background(), m)
		if err == nil {
			t.Errorf("attach %q(...%d bytes): error = nil, want reject", attach[:16], len(attach))
			continue
		}
		var ve *ValidationError
		if !errors.As(err, &ve) || ve.Field != "attach" {
			t.Errorf("attach (%d bytes): error = %v, want ValidationError{attach}", len(attach), err)
		}
		if IsRetryable(err) {
			t.Errorf("attach (%d bytes): IsRetryable = true, want false", len(attach))
		}
	}
	if got := rec.hits.Load(); got != 0 {
		t.Errorf("request count = %d, want 0 (must reject before any request)", got)
	}

	// 边界：恰好 maxAttachBytes 字节的合法 https URL 应放行。
	m := validMsg()
	m.Attach = "https://img.example.com/" + strings.Repeat("a", maxAttachBytes-len("https://img.example.com/"))
	if len(m.Attach) != maxAttachBytes {
		t.Fatalf("构造边界附件长度失败: %d", len(m.Attach))
	}
	if _, err := c.Publish(context.Background(), m); err != nil {
		t.Errorf("exact-limit attach err = %v, want success", err)
	}
}

// 补充：SetHTTPClient 注入的客户端被实际使用。
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSetHTTPClientInjection(t *testing.T) {
	var gotMethod, gotPath string
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"id":"injected"}`)),
			Request:    r,
		}, nil
	})
	c := NewClient(ClientConfig{BaseURL: "http://ntfy.invalid", Timeout: time.Second})
	c.SetHTTPClient(&http.Client{Transport: rt})

	out, err := c.Publish(context.Background(), validMsg())
	if err != nil {
		t.Fatalf("Publish() error = %v, want nil", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/alerts" {
		t.Errorf("injected client saw %s %s, want POST /alerts", gotMethod, gotPath)
	}
	if out.ResponseID != "injected" {
		t.Errorf("outcome.ResponseID = %q, want %q", out.ResponseID, "injected")
	}
}

// 补充：IsRetryable 分类总表与 HTTPStatusError 的 errors.Is 语义。
func TestIsRetryable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"http 429", &HTTPStatusError{Code: 429}, true},
		{"http 500", &HTTPStatusError{Code: 500}, true},
		{"http 503", &HTTPStatusError{Code: 503}, true},
		{"http 400", &HTTPStatusError{Code: 400}, false},
		{"http 404", &HTTPStatusError{Code: 404}, false},
		{"wrapped http 500", fmt.Errorf("outer: %w", &HTTPStatusError{Code: 500}), true},
		{"wrapped http 403", fmt.Errorf("outer: %w", &HTTPStatusError{Code: 403}), false},
		{"validation", &ValidationError{Field: "body", Reason: "x"}, false},
		{"network", fmt.Errorf("ntfy: publish: %w", errors.New("connection reset")), true},
		{"plain error", errors.New("boom"), true},
	}
	for _, tc := range cases {
		if got := IsRetryable(tc.err); got != tc.want {
			t.Errorf("%s: IsRetryable(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
	if !errors.Is(&HTTPStatusError{Code: 403}, &HTTPStatusError{}) {
		t.Error("errors.Is with zero-code target should match any HTTPStatusError")
	}
	if errors.Is(&HTTPStatusError{Code: 403}, &HTTPStatusError{Code: 404}) {
		t.Error("errors.Is with a different code should not match")
	}
}
