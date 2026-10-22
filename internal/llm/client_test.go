package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Shorten the retry backoff so retry tests finish in milliseconds instead of
// seconds (production default is 1s).
func TestMain(m *testing.M) {
	orig := retryBackoffBase
	retryBackoffBase = 5 * time.Millisecond
	code := m.Run()
	retryBackoffBase = orig
	os.Exit(code)
}

func marshalOrPanic(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func writeChat(t *testing.T, w http.ResponseWriter, resp chatResponse) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(marshalOrPanic(resp)); err != nil {
		t.Errorf("write response: %v", err)
	}
}

func finalResp(content, finish string, prompt, completion int) chatResponse {
	return chatResponse{
		Choices: []choice{{
			Message:      message{Role: "assistant", Content: content},
			FinishReason: finish,
		}},
		Usage: usageInfo{PromptTokens: prompt, CompletionTokens: completion},
	}
}

func toolCallResp(id, name, args string, prompt, completion int) chatResponse {
	return chatResponse{
		Choices: []choice{{
			Message: message{
				Role: "assistant",
				ToolCalls: []toolCallMsg{{
					ID:       id,
					Type:     "function",
					Function: functionCall{Name: name, Arguments: args},
				}},
			},
			FinishReason: "tool_calls",
		}},
		Usage: usageInfo{PromptTokens: prompt, CompletionTokens: completion},
	}
}

func testClient(baseURL string, mutate func(*ClientConfig)) *Client {
	cfg := ClientConfig{
		BaseURL:         baseURL,
		Model:           "deepseek-test",
		APIKey:          "test-key",
		Timeout:         5 * time.Second,
		MaxToolRounds:   6,
		MaxOutputTokens: 512,
		EnableTools:     false,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return NewClient(cfg)
}

// 1. Normal single round in JSON mode (EnableTools=false).
func TestRunJSONModeSingleRound(t *testing.T) {
	var gotReq struct {
		Model          string           `json:"model"`
		Messages       []message        `json:"messages"`
		MaxTokens      int              `json:"max_tokens"`
		Stream         *bool            `json:"stream"`
		Tools          []toolDefinition `json:"tools"`
		ToolChoice     string           `json:"tool_choice"`
		ResponseFormat *responseFormat  `json:"response_format"`
	}
	var authHeader, contentType, method, path string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		authHeader = r.Header.Get("Authorization")
		contentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &gotReq); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		writeChat(t, w, finalResp(`{"summary":"ok"}`, "stop", 10, 20))
	}))
	defer srv.Close()

	// Trailing slash on purpose: the client must trim it.
	c := testClient(srv.URL+"/", nil)
	res, err := c.Run(context.Background(), RunRequest{
		SystemPrompt: "You are an analyst. Output json.",
		UserPrompt:   "analyze today",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if method != http.MethodPost {
		t.Errorf("method = %q, want POST", method)
	}
	if path != "/chat/completions" {
		t.Errorf("path = %q, want /chat/completions", path)
	}
	if authHeader != "Bearer test-key" {
		t.Errorf("Authorization = %q", authHeader)
	}
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q", contentType)
	}
	if gotReq.Model != "deepseek-test" {
		t.Errorf("model = %q", gotReq.Model)
	}
	if gotReq.Stream == nil || *gotReq.Stream {
		t.Errorf("stream = %v, want explicit false", gotReq.Stream)
	}
	if gotReq.MaxTokens != 512 {
		t.Errorf("max_tokens = %d, want 512", gotReq.MaxTokens)
	}
	if gotReq.ResponseFormat == nil || gotReq.ResponseFormat.Type != "json_object" {
		t.Errorf("response_format = %+v, want json_object", gotReq.ResponseFormat)
	}
	if len(gotReq.Tools) != 0 || gotReq.ToolChoice != "" {
		t.Errorf("json mode must not send tools/tool_choice: %+v %q", gotReq.Tools, gotReq.ToolChoice)
	}
	if len(gotReq.Messages) != 2 ||
		gotReq.Messages[0].Role != "system" || gotReq.Messages[0].Content != "You are an analyst. Output json." ||
		gotReq.Messages[1].Role != "user" || gotReq.Messages[1].Content != "analyze today" {
		t.Errorf("messages = %+v", gotReq.Messages)
	}
	if string(res.Content) != `{"summary":"ok"}` {
		t.Errorf("Content = %q", res.Content)
	}
	if res.Rounds != 1 || res.ToolCalls != 0 {
		t.Errorf("Rounds=%d ToolCalls=%d, want 1/0", res.Rounds, res.ToolCalls)
	}
	if res.PromptTokens != 10 || res.CompletionTokens != 20 {
		t.Errorf("tokens = %d/%d, want 10/20", res.PromptTokens, res.CompletionTokens)
	}
}

// 2. Normal tool loop: tool call executed, result fed back by tool_call_id.
func TestRunToolLoop(t *testing.T) {
	var n atomic.Int32
	var firstReq, secondReq chatRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch n.Add(1) {
		case 1:
			if err := json.Unmarshal(body, &firstReq); err != nil {
				t.Errorf("decode first request: %v", err)
			}
			writeChat(t, w, toolCallResp("call_1", "query_stats", `{"span":"day"}`, 3, 4))
		default:
			if err := json.Unmarshal(body, &secondReq); err != nil {
				t.Errorf("decode second request: %v", err)
			}
			writeChat(t, w, finalResp(`{"done":true}`, "stop", 5, 6))
		}
	}))
	defer srv.Close()

	var gotCall ToolCall
	c := testClient(srv.URL, func(cfg *ClientConfig) { cfg.EnableTools = true })
	res, err := c.Run(context.Background(), RunRequest{
		SystemPrompt: "sys",
		UserPrompt:   "go",
		Tools: map[string]ToolSpec{
			"query_stats": {
				Name:           "query_stats",
				Description:    "deterministic stats",
				ParametersJSON: []byte(`{"type":"object","properties":{"span":{"type":"string"}}}`),
			},
		},
		Handlers: map[string]ToolHandler{
			"query_stats": func(ctx context.Context, call ToolCall) (string, error) {
				gotCall = call
				return `{"a":1}`, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if string(res.Content) != `{"done":true}` {
		t.Errorf("Content = %q", res.Content)
	}
	if res.Rounds != 2 || res.ToolCalls != 1 {
		t.Errorf("Rounds=%d ToolCalls=%d, want 2/1", res.Rounds, res.ToolCalls)
	}
	if res.PromptTokens != 8 || res.CompletionTokens != 10 {
		t.Errorf("tokens = %d/%d, want 8/10 (accumulated usage)", res.PromptTokens, res.CompletionTokens)
	}
	if gotCall.ID != "call_1" || gotCall.Name != "query_stats" || gotCall.ArgsJSON != `{"span":"day"}` {
		t.Errorf("handler call = %+v", gotCall)
	}

	// First request advertised the tool.
	if len(firstReq.Tools) != 1 ||
		firstReq.Tools[0].Type != "function" ||
		firstReq.Tools[0].Function.Name != "query_stats" ||
		firstReq.Tools[0].Function.Description != "deterministic stats" {
		t.Errorf("first request tools = %+v", firstReq.Tools)
	}
	if tc, _ := firstReq.ToolChoice.(string); tc != "auto" {
		t.Errorf("tool_choice = %v, want auto", firstReq.ToolChoice)
	}
	if firstReq.ResponseFormat != nil {
		t.Errorf("tools mode must not set response_format, got %+v", firstReq.ResponseFormat)
	}

	// Second request echoed the assistant tool_calls and the tool result.
	msgs := secondReq.Messages
	if len(msgs) != 4 {
		t.Fatalf("second request has %d messages, want 4: %+v", len(msgs), msgs)
	}
	asst := msgs[2]
	if asst.Role != "assistant" || len(asst.ToolCalls) != 1 ||
		asst.ToolCalls[0].ID != "call_1" ||
		asst.ToolCalls[0].Type != "function" ||
		asst.ToolCalls[0].Function.Name != "query_stats" {
		t.Errorf("assistant round-trip message = %+v", asst)
	}
	toolMsg := msgs[3]
	if toolMsg.Role != "tool" || toolMsg.ToolCallID != "call_1" || toolMsg.Content != `{"a":1}` {
		t.Errorf("tool result message = %+v", toolMsg)
	}
}

// 3. Non-JSON response body.
func TestInvalidJSONResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices": [this is not json`)
	}))
	defer srv.Close()

	c := testClient(srv.URL, nil)
	_, err := c.Run(context.Background(), RunRequest{UserPrompt: "hi"})
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("err = %v, want ErrInvalidResponse", err)
	}
	if !strings.Contains(err.Error(), "choices") {
		t.Errorf("error should embed a body snippet, got: %v", err)
	}
}

// 4. One 429 then success: exactly two requests.
func TestRetryOn429(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, "rate limited")
			return
		}
		writeChat(t, w, finalResp(`{"ok":true}`, "stop", 1, 2))
	}))
	defer srv.Close()

	c := testClient(srv.URL, nil)
	res, err := c.Run(context.Background(), RunRequest{UserPrompt: "hi"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(res.Content) != `{"ok":true}` {
		t.Errorf("Content = %q", res.Content)
	}
	if got := n.Load(); got != 2 {
		t.Errorf("server saw %d requests, want 2", got)
	}
}

// 5. Persistent 500: retries, then HTTPStatusError{Code:500}, no infinite loop.
func TestHTTP500RetriesThenFails(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "upstream boom")
	}))
	defer srv.Close()

	c := testClient(srv.URL, nil)
	_, err := c.Run(context.Background(), RunRequest{UserPrompt: "hi"})
	var se *HTTPStatusError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want *HTTPStatusError", err)
	}
	if se.Code != http.StatusInternalServerError {
		t.Errorf("code = %d, want 500", se.Code)
	}
	if !strings.Contains(se.Body, "upstream boom") {
		t.Errorf("body snippet = %q", se.Body)
	}
	if got := n.Load(); got != int32(maxRetries+1) {
		t.Errorf("server saw %d requests, want %d (initial + %d retries)", got, maxRetries+1, maxRetries)
	}
}

// 6. 401 fails immediately without retrying.
func TestHTTP401NoRetry(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "bad key")
	}))
	defer srv.Close()

	c := testClient(srv.URL, nil)
	_, err := c.Run(context.Background(), RunRequest{UserPrompt: "hi"})
	var se *HTTPStatusError
	if !errors.As(err, &se) || se.Code != http.StatusUnauthorized {
		t.Fatalf("err = %v, want HTTPStatusError{401}", err)
	}
	if got := n.Load(); got != 1 {
		t.Errorf("server saw %d requests, want 1 (no retry)", got)
	}
}

// 7. Per-request timeout via injected http.Client -> ErrTimeout.
func TestRequestTimeout(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		time.Sleep(300 * time.Millisecond)
		fmt.Fprint(w, "{}")
	}))
	defer srv.Close()

	c := testClient(srv.URL, nil)
	c.SetHTTPClient(&http.Client{Timeout: 40 * time.Millisecond})
	_, err := c.Run(context.Background(), RunRequest{UserPrompt: "hi"})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("ErrTimeout should wrap context.DeadlineExceeded, got %v", err)
	}
	if got := n.Load(); got != int32(maxRetries+1) {
		t.Errorf("server saw %d requests, want %d", got, maxRetries+1)
	}
}

// 8. Invalid tool arguments: handler is skipped, model receives the error.
func TestInvalidToolArgsFeedErrorBack(t *testing.T) {
	var n atomic.Int32
	var secondReq chatRequest
	handlerCalled := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if n.Add(1) == 1 {
			writeChat(t, w, toolCallResp("call_bad", "query_stats", "{bad", 1, 1))
			return
		}
		if err := json.Unmarshal(body, &secondReq); err != nil {
			t.Errorf("decode second request: %v", err)
		}
		writeChat(t, w, finalResp(`{"recovered":true}`, "stop", 2, 2))
	}))
	defer srv.Close()

	c := testClient(srv.URL, func(cfg *ClientConfig) { cfg.EnableTools = true })
	res, err := c.Run(context.Background(), RunRequest{
		UserPrompt: "go",
		Tools: map[string]ToolSpec{
			"query_stats": {Name: "query_stats", Description: "stats"},
		},
		Handlers: map[string]ToolHandler{
			"query_stats": func(ctx context.Context, call ToolCall) (string, error) {
				handlerCalled = true
				return `{"a":1}`, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if handlerCalled {
		t.Errorf("handler must not be invoked for invalid arguments json")
	}
	if string(res.Content) != `{"recovered":true}` {
		t.Errorf("Content = %q", res.Content)
	}
	if res.ToolCalls != 1 {
		t.Errorf("ToolCalls = %d, want 1", res.ToolCalls)
	}

	msgs := secondReq.Messages
	if len(msgs) != 3 { // user + assistant(tool_calls) + tool result (no system prompt)
		t.Fatalf("second request has %d messages, want 3: %+v", len(msgs), msgs)
	}
	toolMsg := msgs[2]
	if toolMsg.Role != "tool" || toolMsg.ToolCallID != "call_bad" {
		t.Fatalf("tool message = %+v", toolMsg)
	}
	if !strings.Contains(toolMsg.Content, "invalid arguments json") {
		t.Errorf("tool result should report the json error, got %q", toolMsg.Content)
	}
	var parsed struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(toolMsg.Content), &parsed); err != nil || parsed.Error == "" {
		t.Errorf("tool result should be {\"error\":...} json, got %q", toolMsg.Content)
	}
}

// 8b. Unknown tool name and failing handler: both feed {"error":...} back.
func TestToolFailuresFeedErrorBack(t *testing.T) {
	cases := []struct {
		name       string
		toolName   string
		handler    ToolHandler
		wantSubstr string
	}{
		{
			name:       "unknown tool",
			toolName:   "no_such_tool",
			handler:    nil,
			wantSubstr: "unknown tool",
		},
		{
			name:     "handler error",
			toolName: "failing_tool",
			handler: func(ctx context.Context, call ToolCall) (string, error) {
				return "", errors.New("boom")
			},
			wantSubstr: "boom",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var n atomic.Int32
			var toolContent string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if n.Add(1) == 1 {
					writeChat(t, w, toolCallResp("c1", tc.toolName, `{}`, 1, 1))
					return
				}
				var req chatRequest
				if err := json.Unmarshal(body, &req); err != nil {
					t.Errorf("decode second request: %v", err)
				}
				if len(req.Messages) == 3 { // user + assistant(tool_calls) + tool result
					toolContent = req.Messages[2].Content
				}
				writeChat(t, w, finalResp(`{"ok":true}`, "stop", 2, 2))
			}))
			defer srv.Close()

			handlers := map[string]ToolHandler{}
			if tc.handler != nil {
				handlers[tc.toolName] = tc.handler
			}
			c := testClient(srv.URL, func(cfg *ClientConfig) { cfg.EnableTools = true })
			res, err := c.Run(context.Background(), RunRequest{
				UserPrompt: "go",
				Handlers:   handlers,
			})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if string(res.Content) != `{"ok":true}` {
				t.Errorf("Content = %q", res.Content)
			}
			if !strings.Contains(toolContent, tc.wantSubstr) {
				t.Errorf("tool result = %q, want substring %q", toolContent, tc.wantSubstr)
			}
		})
	}
}

// 9. 软/硬两档轮数控制：超出软上限后每个后续轮次注入收尾提示且工具仍
// 可用；到达硬上限触发一次不带 tools 的最终补全，任务以可解析结果结束
// 而非错误。收稿请求体：无 tools、无 tool_choice、历史 assistant 的
// reasoning_content 被剥离（主循环带 tools 的回传不受影响）、带
// response_format json_object。
func TestSoftHardToolRoundLimits(t *testing.T) {
	var mu sync.Mutex
	var reqs []chatRequest
	var bodies []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req chatRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		mu.Lock()
		reqs = append(reqs, req)
		bodies = append(bodies, string(body))
		n := len(reqs)
		mu.Unlock()
		// 带工具的请求一律继续要工具（模型固执到硬上限），且附带
		// reasoning_content 验证收稿剥离；不带工具的最终补全返回可被
		// generator 兜底解析的报告 JSON。
		if len(req.Tools) > 0 {
			writeChat(t, w, chatResponse{
				Choices: []choice{{
					Message: message{
						Role:             "assistant",
						ReasoningContent: fmt.Sprintf("reasoning round %d", n),
						ToolCalls: []toolCallMsg{{
							ID:       fmt.Sprintf("call_%d", n),
							Type:     "function",
							Function: functionCall{Name: "query_stats", Arguments: `{}`},
						}},
					},
					FinishReason: "tool_calls",
				}},
				Usage: usageInfo{PromptTokens: 1, CompletionTokens: 1},
			})
			return
		}
		writeChat(t, w, finalResp(`{"type":"daily","summary":"degraded final"}`, "stop", 9, 9))
	}))
	defer srv.Close()

	c := testClient(srv.URL, func(cfg *ClientConfig) {
		cfg.EnableTools = true
		cfg.MaxToolRounds = 2  // 软上限
		cfg.HardToolRounds = 4 // 硬上限
	})
	res, err := c.Run(context.Background(), RunRequest{
		UserPrompt: "go",
		Tools: map[string]ToolSpec{
			"query_stats": {Name: "query_stats", Description: "stats"},
		},
		Handlers: map[string]ToolHandler{
			"query_stats": func(ctx context.Context, call ToolCall) (string, error) {
				return "{}", nil
			},
		},
	})
	if err != nil {
		t.Fatalf("Run（硬限强制收稿应成功而非报错）: %v", err)
	}
	if string(res.Content) != `{"type":"daily","summary":"degraded final"}` {
		t.Errorf("Content = %q, want 强制收稿的最终报告 JSON", res.Content)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(reqs) != 6 { // 4 个带工具轮 + 1 个触发硬限的请求 + 1 次最终补全
		t.Fatalf("server saw %d requests, want 6", len(reqs))
	}
	if res.ToolCalls != 4 || res.Rounds != 6 {
		t.Errorf("ToolCalls=%d Rounds=%d, want 4/6", res.ToolCalls, res.Rounds)
	}

	// 软上限提示计数：请求 1-2（轮 1-2，未超软限）无提示；
	// 轮 3 起每执行一轮追加一条，出现在其后每个请求里。
	countHints := func(i int) int {
		n := 0
		for _, m := range reqs[i].Messages {
			if m.Role == "system" && strings.Contains(m.Content, "软上限") {
				n++
			}
		}
		return n
	}
	for i, want := range []int{0, 0, 0, 1, 2, 2} {
		if got := countHints(i); got != want {
			t.Errorf("request %d: soft-limit hints = %d, want %d", i+1, got, want)
		}
	}
	// 软限后工具仍可用：触发硬限的请求（第 5 个）依旧带 tools。
	if len(reqs[4].Tools) == 0 {
		t.Errorf("request 5 (beyond soft limit) must still advertise tools")
	}
	// 提示内容必须包含 data_limitations 引导。
	if !strings.Contains(reqs[4].Messages[len(reqs[4].Messages)-1].Content, "data_limitations") {
		t.Errorf("soft-limit hint should mention data_limitations")
	}

	// 主循环带 tools 时 reasoning_content 原样回传（第 2-5 个请求的历史
	// assistant 消息携带），证明收稿剥离针对的是收稿请求而非全局。
	for i := 1; i <= 4; i++ {
		if !strings.Contains(bodies[i], "reasoning_content") {
			t.Errorf("request %d (tools mode) must echo reasoning_content", i+1)
		}
	}

	// 最终补全：不带 tools/tool_choice/reasoning_content，带 json_object。
	finalReq := reqs[5]
	if len(finalReq.Tools) != 0 {
		t.Errorf("final completion must not carry tools, got %d", len(finalReq.Tools))
	}
	if tc, _ := finalReq.ToolChoice.(string); tc != "" {
		t.Errorf("final completion must not carry tool_choice, got %q", tc)
	}
	if strings.Contains(bodies[5], "reasoning_content") {
		t.Errorf("final completion must strip reasoning_content:\n%s", bodies[5])
	}
	if finalReq.ResponseFormat == nil || finalReq.ResponseFormat.Type != "json_object" {
		t.Errorf("final completion must set response_format json_object, got %+v", finalReq.ResponseFormat)
	}
	// 历史：user + 4×(assistant+tool) + 2 条软限提示 + 1 条硬限指令 = 12。
	if len(finalReq.Messages) != 12 {
		t.Fatalf("final completion has %d messages, want 12: %+v", len(finalReq.Messages), finalReq.Messages)
	}
	last := finalReq.Messages[len(finalReq.Messages)-1]
	if last.Role != "system" || !strings.Contains(last.Content, "不提供任何工具") {
		t.Errorf("last message of final completion = %+v, want toolless wrap-up system instruction", last)
	}
	// 历史里的 assistant 工具轮完整保留（4 条 tool_calls）。
	asst := 0
	for _, m := range finalReq.Messages {
		if m.Role == "assistant" && len(m.ToolCalls) > 0 {
			asst++
		}
	}
	if asst != 4 {
		t.Errorf("final completion preserved %d assistant tool rounds, want 4", asst)
	}
}

// 9b. 硬限收稿的最终调用本身失败（HTTP 500 重试耗尽）→ 错误同时匹配
// ErrToolRoundsExceeded 与 *HTTPStatusError。
func TestHardLimitFinalCallFails(t *testing.T) {
	var mu sync.Mutex
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req chatRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		mu.Lock()
		n++
		mu.Unlock()
		if len(req.Tools) > 0 {
			writeChat(t, w, toolCallResp(fmt.Sprintf("call_%d", n), "query_stats", `{}`, 1, 1))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "final call boom")
	}))
	defer srv.Close()

	c := testClient(srv.URL, func(cfg *ClientConfig) {
		cfg.EnableTools = true
		cfg.MaxToolRounds = 1
		cfg.HardToolRounds = 1
	})
	_, err := c.Run(context.Background(), RunRequest{
		UserPrompt: "go",
		Tools: map[string]ToolSpec{
			"query_stats": {Name: "query_stats", Description: "stats"},
		},
		Handlers: map[string]ToolHandler{
			"query_stats": func(ctx context.Context, call ToolCall) (string, error) {
				return "{}", nil
			},
		},
	})
	if !errors.Is(err, ErrToolRoundsExceeded) {
		t.Fatalf("err = %v, want ErrToolRoundsExceeded", err)
	}
	var se *HTTPStatusError
	if !errors.As(err, &se) || se.Code != http.StatusInternalServerError {
		t.Errorf("err = %v, want wrapped *HTTPStatusError{500}", err)
	}
	// 1 个工具轮 + 1 个触发硬限的请求 + 最终补全的初始尝试与 3 次重试。
	mu.Lock()
	defer mu.Unlock()
	if n != 2+maxRetries+1 {
		t.Errorf("server saw %d requests, want %d", n, 2+maxRetries+1)
	}
}

// 9c. reasoning_content 往返透传：assistant 工具轮返回的思考内容必须在
// 后续请求中随该 assistant 消息原样带回（DeepSeek 带 tools 的 400 规则）；
// 模型不返回该字段时请求不得出现该键。
func TestReasoningContentRoundTrip(t *testing.T) {
	const chain = "let me check the stats for this window..."
	for _, withReasoning := range []bool{true, false} {
		var n atomic.Int32
		var secondBody string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if n.Add(1) == 1 {
				msg := message{
					Role: "assistant",
					ToolCalls: []toolCallMsg{{ID: "call_r", Type: "function",
						Function: functionCall{Name: "query_stats", Arguments: `{}`}}},
				}
				if withReasoning {
					msg.ReasoningContent = chain
				}
				writeChat(t, w, chatResponse{
					Choices: []choice{{Message: msg, FinishReason: "tool_calls"}},
					Usage:   usageInfo{PromptTokens: 1, CompletionTokens: 1},
				})
				return
			}
			secondBody = string(body)
			writeChat(t, w, finalResp(`{"done":true}`, "stop", 2, 2))
		}))

		c := testClient(srv.URL, func(cfg *ClientConfig) { cfg.EnableTools = true })
		_, err := c.Run(context.Background(), RunRequest{
			UserPrompt: "go",
			Handlers: map[string]ToolHandler{
				"query_stats": func(ctx context.Context, call ToolCall) (string, error) {
					return "{}", nil
				},
			},
		})
		if err != nil {
			t.Fatalf("withReasoning=%v: Run: %v", withReasoning, err)
		}

		var secondReq chatRequest
		if err := json.Unmarshal([]byte(secondBody), &secondReq); err != nil {
			t.Fatalf("decode second request: %v", err)
		}
		if len(secondReq.Messages) != 3 {
			t.Fatalf("second request has %d messages, want 3", len(secondReq.Messages))
		}
		asst := secondReq.Messages[1]
		if withReasoning {
			if asst.ReasoningContent != chain {
				t.Errorf("assistant message reasoning_content = %q, want %q (echoed verbatim)",
					asst.ReasoningContent, chain)
			}
			if !strings.Contains(secondBody, `"reasoning_content"`) {
				t.Errorf("second request body must carry reasoning_content key")
			}
		} else if strings.Contains(secondBody, `"reasoning_content"`) {
			t.Errorf("non-thinking model: second request must NOT contain reasoning_content, got %s", secondBody)
		}
	}
}

// 9d. thinking / reasoning_effort 注入：默认与 auto 不发送两个键；on/off
// 分别映射 thinking.type=enabled/disabled；effort 原样透传。
func TestThinkingAndReasoningEffortParams(t *testing.T) {
	cases := []struct {
		name         string
		mutate       func(*ClientConfig)
		wantThinking string // "" = 键必须缺失
		wantEffort   string // "" = 键必须缺失
	}{
		{"default omits both", nil, "", ""},
		{"auto omits both", func(c *ClientConfig) { c.Thinking = "auto" }, "", ""},
		{"on+low", func(c *ClientConfig) { c.Thinking = "on"; c.ReasoningEffort = "low" },
			`"enabled"`, `"low"`},
		{"off+max", func(c *ClientConfig) { c.Thinking = "off"; c.ReasoningEffort = "max" },
			`"disabled"`, `"max"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var raw map[string]json.RawMessage
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if err := json.Unmarshal(body, &raw); err != nil {
					t.Errorf("decode request: %v", err)
				}
				writeChat(t, w, finalResp(`{"ok":true}`, "stop", 1, 1))
			}))
			defer srv.Close()

			c := testClient(srv.URL, tc.mutate)
			if _, err := c.Run(context.Background(), RunRequest{UserPrompt: "hi"}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			checkKey := func(key, want string) {
				got, ok := raw[key]
				if want == "" {
					if ok {
						t.Errorf("%s must be absent, got %s", key, got)
					}
					return
				}
				if !ok || string(got) != want {
					t.Errorf("%s = %s (present=%v), want %s", key, got, ok, want)
				}
			}
			// thinking 形如 {"type":"enabled"}；reasoning_effort 形如 "low"。
			var wantThinkRaw string
			if tc.wantThinking != "" {
				wantThinkRaw = `{"type":` + tc.wantThinking + `}`
			}
			var wantEffortRaw string
			if tc.wantEffort != "" {
				wantEffortRaw = tc.wantEffort
			}
			checkKey("thinking", wantThinkRaw)
			checkKey("reasoning_effort", wantEffortRaw)
		})
	}
}

// 10. Missing response fields.
func TestMissingResponseFields(t *testing.T) {
	cases := []struct{ name, body string }{
		{"empty choices", `{"choices":[],"usage":{}}`},
		{"no content field", `{"choices":[{"message":{"role":"assistant"},"finish_reason":"stop"}],"usage":{}}`},
		{"empty content", `{"choices":[{"message":{"role":"assistant","content":""},"finish_reason":"stop"}],"usage":{}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()

			c := testClient(srv.URL, nil)
			_, err := c.Run(context.Background(), RunRequest{UserPrompt: "hi"})
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("err = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

// 11. Missing API key: fail before any request.
func TestNoAPIKey(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
	}))
	defer srv.Close()

	c := testClient(srv.URL, func(cfg *ClientConfig) { cfg.APIKey = "" })
	_, err := c.Run(context.Background(), RunRequest{UserPrompt: "hi"})
	if !errors.Is(err, ErrNoAPIKey) {
		t.Fatalf("err = %v, want ErrNoAPIKey", err)
	}
	if got := n.Load(); got != 0 {
		t.Errorf("server saw %d requests, want 0", got)
	}
}

// 12. Fenced content is stripped; missing usage counts as zero tokens.
func TestRunFencedContentNoUsage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No usage block at all.
		fence := "```"
		body := `{"choices":[{"message":{"role":"assistant","content":"` + fence + `json\n{\"summary\":\"daily\"}\n` + fence + `"},"finish_reason":"stop"}]}`
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	c := testClient(srv.URL, nil)
	res, err := c.Run(context.Background(), RunRequest{UserPrompt: "hi"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(res.Content) != `{"summary":"daily"}` {
		t.Errorf("Content = %q, want fence stripped", res.Content)
	}
	if res.PromptTokens != 0 || res.CompletionTokens != 0 {
		t.Errorf("tokens = %d/%d, want 0/0 when usage is absent", res.PromptTokens, res.CompletionTokens)
	}
}

func TestStripCodeFence(t *testing.T) {
	fence := "```"
	cases := []struct{ in, want string }{
		{fence + "json\n{\"a\":1}\n" + fence, `{"a":1}`},
		{fence + "\n{\"a\":1}" + fence, `{"a":1}`},
		{"  " + fence + "json\n{\"a\":1}\n" + fence + "  ", `{"a":1}`},
		{"  {\"a\":1}  ", `{"a":1}`},
		{`{"a":1}`, `{"a":1}`},
		{"plain text", "plain text"},
	}
	for _, tc := range cases {
		if got := stripCodeFence(tc.in); got != tc.want {
			t.Errorf("stripCodeFence(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// 13a. 预算软停：累计 token 推过 MaxTotalTokens 且模型仍要工具 → 不
// abort、不报错，转而发起一次无 tools 的强制收稿，任务以内容结束。
// 收稿请求体断言：无 tools、无 tool_choice、历史 reasoning_content 被
// 剥离、带 response_format json_object；收稿 token 照常记账。
func TestBudgetOverrunTriggersToollessWrapup(t *testing.T) {
	var mu sync.Mutex
	var reqs []chatRequest
	var bodies []string
	var withToolsReqs int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req chatRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		mu.Lock()
		reqs = append(reqs, req)
		bodies = append(bodies, string(body))
		mu.Unlock()
		if len(req.Tools) > 0 {
			mu.Lock()
			withToolsReqs++
			n := withToolsReqs
			mu.Unlock()
			// 第 1 轮 50 ≤ 预算，工具照常执行；第 2 轮累计 170 > 150
			// 触发软停（模型仍要工具）。
			usage := usageInfo{PromptTokens: 40, CompletionTokens: 10}
			if n == 2 {
				usage = usageInfo{PromptTokens: 80, CompletionTokens: 40}
			}
			writeChat(t, w, chatResponse{
				Choices: []choice{{
					Message: message{
						Role:             "assistant",
						ReasoningContent: "budget round reasoning",
						ToolCalls: []toolCallMsg{{
							ID:       fmt.Sprintf("call_b%d", n),
							Type:     "function",
							Function: functionCall{Name: "query_stats", Arguments: `{}`},
						}},
					},
					FinishReason: "tool_calls",
				}},
				Usage: usage,
			})
			return
		}
		writeChat(t, w, finalResp(`{"type":"daily","summary":"budget wrap-up"}`, "stop", 10, 5))
	}))
	defer srv.Close()

	c := testClient(srv.URL, func(cfg *ClientConfig) {
		cfg.EnableTools = true
		cfg.MaxTotalTokens = 150
		cfg.MaxToolRounds = 4
		cfg.HardToolRounds = 8 // 轮数未达硬限：纯预算触发
	})
	res, err := c.Run(context.Background(), RunRequest{
		UserPrompt: "go",
		Tools: map[string]ToolSpec{
			"query_stats": {Name: "query_stats", Description: "stats"},
		},
		Handlers: map[string]ToolHandler{
			"query_stats": func(ctx context.Context, call ToolCall) (string, error) {
				return "{}", nil
			},
		},
	})
	if err != nil {
		t.Fatalf("Run（预算越限应软停收稿而非报错）: %v", err)
	}
	if string(res.Content) != `{"type":"daily","summary":"budget wrap-up"}` {
		t.Errorf("Content = %q, want 收稿报告 JSON", res.Content)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(reqs) != 3 { // 2 个带工具轮（第 2 个越限）+ 1 次无工具收稿
		t.Fatalf("server saw %d requests, want 3", len(reqs))
	}
	if res.Rounds != 3 || res.ToolCalls != 1 {
		t.Errorf("Rounds=%d ToolCalls=%d, want 3/1（软停在执行第 2 轮工具前触发）",
			res.Rounds, res.ToolCalls)
	}
	// 收稿 token 照常记账（120+50 工具轮 + 10+5 收稿）。
	if res.PromptTokens != 130 || res.CompletionTokens != 55 {
		t.Errorf("tokens = %d/%d, want 130/55", res.PromptTokens, res.CompletionTokens)
	}
	// 第 2 个请求（仍带 tools）回传 reasoning_content；收稿请求剥离。
	if !strings.Contains(bodies[1], "reasoning_content") {
		t.Errorf("tools-mode request must echo reasoning_content")
	}
	finalReq := reqs[2]
	if len(finalReq.Tools) != 0 {
		t.Errorf("收稿请求不得携带 tools, got %d", len(finalReq.Tools))
	}
	if tc, _ := finalReq.ToolChoice.(string); tc != "" {
		t.Errorf("收稿请求不得携带 tool_choice, got %q", tc)
	}
	if strings.Contains(bodies[2], "reasoning_content") {
		t.Errorf("收稿请求不得携带 reasoning_content:\n%s", bodies[2])
	}
	if finalReq.ResponseFormat == nil || finalReq.ResponseFormat.Type != "json_object" {
		t.Errorf("收稿请求应带 response_format json_object, got %+v", finalReq.ResponseFormat)
	}
	// 收稿历史保留已执行的 assistant 工具轮（剥离的只是思考内容）。
	asst := 0
	for _, m := range finalReq.Messages {
		if m.Role == "assistant" && len(m.ToolCalls) > 0 {
			asst++
		}
	}
	if asst != 1 {
		t.Errorf("收稿历史保留 %d 条 assistant 工具轮, want 1", asst)
	}
	last := finalReq.Messages[len(finalReq.Messages)-1]
	if last.Role != "system" || !strings.Contains(last.Content, "不提供任何工具") {
		t.Errorf("收稿末尾应为软停 system 指令, got %+v", last)
	}
}

// 13b. 越限后的合法最终回复不丢弃：模型给出最终非工具回复时，即使该
// 回复把累计 token 推过预算（或单发模式首回复即越限），内容照常返回，
// token 照常记账，绝不因事后越限而失败。
func TestBudgetOverrunFinalReplyStillReturned(t *testing.T) {
	cases := []struct {
		name    string
		tools   bool
		budget  int
		script  func(n int, w http.ResponseWriter)
		wantTok [2]int
	}{
		{
			name:   "tools loop final reply over budget",
			tools:  true,
			budget: 150,
			script: func(n int, w http.ResponseWriter) {
				if n == 1 {
					writeChat(t, w, toolCallResp("c1", "query_stats", `{}`, 60, 30)) // 90 ≤ 150
					return
				}
				writeChat(t, w, finalResp(`{"final":true}`, "stop", 60, 30)) // 累计 180 > 150
			},
			wantTok: [2]int{120, 60},
		},
		{
			name:   "json mode single reply over budget",
			tools:  false,
			budget: 10,
			script: func(n int, w http.ResponseWriter) {
				writeChat(t, w, finalResp(`{"summary":"ok"}`, "stop", 50, 20))
			},
			wantTok: [2]int{50, 20},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var n atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tc.script(int(n.Add(1)), w)
			}))
			defer srv.Close()

			c := testClient(srv.URL, func(cfg *ClientConfig) {
				cfg.EnableTools = tc.tools
				cfg.MaxTotalTokens = tc.budget
			})
			res, err := c.Run(context.Background(), RunRequest{
				UserPrompt: "go",
				Handlers: map[string]ToolHandler{
					"query_stats": func(ctx context.Context, call ToolCall) (string, error) {
						return "{}", nil
					},
				},
			})
			if err != nil {
				t.Fatalf("Run（越限后的最终回复必须返回内容而非报错）: %v", err)
			}
			if want := `{"final":true}`; tc.tools && string(res.Content) != want {
				t.Errorf("Content = %q, want %q", res.Content, want)
			}
			if want := `{"summary":"ok"}`; !tc.tools && string(res.Content) != want {
				t.Errorf("Content = %q, want %q", res.Content, want)
			}
			if res.PromptTokens != tc.wantTok[0] || res.CompletionTokens != tc.wantTok[1] {
				t.Errorf("tokens = %d/%d, want %d/%d (照常记账)",
					res.PromptTokens, res.CompletionTokens, tc.wantTok[0], tc.wantTok[1])
			}
		})
	}
}

// 13c. 预算触发的收稿调用本身失败（HTTP 500 重试耗尽）→ 错误匹配
// ErrToolRoundsExceeded 与 *HTTPStatusError，且错误信息说明预算触发。
func TestBudgetWrapupCallFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req chatRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if len(req.Tools) > 0 {
			writeChat(t, w, toolCallResp("c1", "query_stats", `{}`, 200, 100)) // 300 > 预算 150
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "wrap-up boom")
	}))
	defer srv.Close()

	c := testClient(srv.URL, func(cfg *ClientConfig) {
		cfg.EnableTools = true
		cfg.MaxTotalTokens = 150
		cfg.MaxToolRounds = 4
		cfg.HardToolRounds = 8
	})
	_, err := c.Run(context.Background(), RunRequest{
		UserPrompt: "go",
		Tools: map[string]ToolSpec{
			"query_stats": {Name: "query_stats", Description: "stats"},
		},
		Handlers: map[string]ToolHandler{
			"query_stats": func(ctx context.Context, call ToolCall) (string, error) {
				return "{}", nil
			},
		},
	})
	if !errors.Is(err, ErrToolRoundsExceeded) {
		t.Fatalf("err = %v, want ErrToolRoundsExceeded", err)
	}
	var se *HTTPStatusError
	if !errors.As(err, &se) || se.Code != http.StatusInternalServerError {
		t.Errorf("err = %v, want wrapped *HTTPStatusError{500}", err)
	}
	if !strings.Contains(err.Error(), "预算") {
		t.Errorf("error should name the budget trigger: %v", err)
	}
}

// Retry-After parsing: seconds, HTTP-date, garbage, negative.
func TestParseRetryAfter(t *testing.T) {
	now := time.Now()
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"0", 0},
		{"-5", 0},
		{"3", 3 * time.Second},
		{" 7 ", 7 * time.Second},
		{"garbage", 0},
	}
	for _, tc := range cases {
		if got := parseRetryAfter(tc.in, now); got != tc.want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
	future := now.Add(30 * time.Second).UTC().Format(http.TimeFormat)
	if got := parseRetryAfter(future, now); got < 25*time.Second || got > 30*time.Second {
		t.Errorf("parseRetryAfter(future date) = %v, want ~30s", got)
	}
	past := now.Add(-time.Hour).UTC().Format(http.TimeFormat)
	if got := parseRetryAfter(past, now); got != 0 {
		t.Errorf("parseRetryAfter(past date) = %v, want 0", got)
	}
}

// Backoff: Retry-After wins (capped at 60s); otherwise exponential + jitter.
func TestBackoffDelay(t *testing.T) {
	if d := backoffDelay(1, 120*time.Second); d != 60*time.Second {
		t.Errorf("Retry-After must cap at 60s, got %v", d)
	}
	if d := backoffDelay(2, 2*time.Second); d != 2*time.Second {
		t.Errorf("Retry-After must be honored exactly, got %v", d)
	}

	orig := retryBackoffBase
	retryBackoffBase = 10 * time.Millisecond
	defer func() { retryBackoffBase = orig }()
	for attempt := 1; attempt <= 3; attempt++ {
		d := backoffDelay(attempt, 0)
		want := time.Duration(10*time.Millisecond) * (1 << (attempt - 1))
		lo := time.Duration(float64(want) * 0.79)
		hi := time.Duration(float64(want) * 1.21)
		if d < lo || d > hi {
			t.Errorf("attempt %d: backoff %v outside jitter band [%v, %v]", attempt, d, lo, hi)
		}
	}
}

// Caller context cancellation during retries aborts immediately with the
// context error, not ErrTimeout.
func TestContextCancelAbortsRetry(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := testClient(srv.URL, nil)
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel while the first backoff sleep is in flight.
	go func() {
		for n.Load() == 0 {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()
	_, err := c.Run(ctx, RunRequest{UserPrompt: "hi"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if errors.Is(err, ErrTimeout) {
		t.Errorf("cancellation must not be reported as ErrTimeout")
	}
}
