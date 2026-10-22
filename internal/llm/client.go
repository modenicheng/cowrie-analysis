// Package llm implements a minimal OpenAI-compatible chat completions client
// for DeepSeek using only the standard library: a tool-calling Run loop, JSON
// output mode, retry with exponential backoff (honoring Retry-After), token
// budget guards, and structured errors that work with errors.Is / errors.As.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	defaultTimeout        = 120 * time.Second
	defaultToolRounds     = 8        // 软上限：超出后每轮注入收尾提示，但不阻断
	defaultHardToolRounds = 24       // 硬上限：到达后发起一次不带 tools 的强制收稿
	defaultFinalMaxBytes  = 64 << 10 // 64 KiB cap on the final model output
	maxResponseBody       = 8 << 20  // read cap per response body
)

// softLimitHint 是工具轮数超过软上限（llm.max_tool_rounds）后，每个后续
// 轮次追加的 system 提示（持续催促收尾，但不拒绝工具调用）。
const softLimitHintTmpl = "系统提示：工具调用轮数已超出软上限（%d 轮）。请尽快基于已有信息输出最终报告并调用 submit_report；未能详细分析的部分必须如实写入 data_limitations 字段说明，不得省略。"

// hardLimitFinalMsg 是到达硬上限（llm.hard_tool_rounds）触发强制收稿时，
// 追加在对话末尾的 system 指令：无工具、直接输出最终报告 JSON。
const hardLimitFinalMsg = "系统提示：工具调用轮数已达到硬上限，本次请求不提供任何工具。请立即基于对话中已有的信息，直接输出最终报告的 JSON（结构与 submit_report 参数一致）；因预算未能详细分析的部分，必须如实写入 data_limitations 字段说明，不得省略，也不要请求任何工具。"

// ClientConfig configures a DeepSeek (OpenAI-compatible) client. All values
// come from application configuration; nothing is hardcoded.
type ClientConfig struct {
	BaseURL, Model, APIKey string
	Timeout                time.Duration // per-request total timeout; <=0 => 120s
	MaxToolRounds          int           // 软上限：超过后每轮注入收尾提示；<=0 => 8
	HardToolRounds         int           // 硬上限：到达后强制无工具收稿；<=0 => max(24, 软上限)
	MaxOutputTokens        int           // max_tokens per request; 0 => omit
	MaxTotalTokens         int           // task-level cumulative budget; 0 => unlimited
	EnableTools            bool          // false => single-shot json_object mode
	// Thinking controls the DeepSeek thinking switch: ""/"auto" => 不发送该
	// 字段（沿用服务端默认，思考模型默认开启）；"on" => thinking.type=
	// enabled；"off" => thinking.type=disabled。
	Thinking string
	// ReasoningEffort controls DeepSeek thinking effort ("low"|"medium"|
	// "high"|"max"); "" => 不发送该字段。medium 由服务端映射为 high。
	ReasoningEffort string
}

// Client is a reusable chat completions client.
type Client struct {
	cfg  ClientConfig
	http *http.Client
}

// NewClient applies defaults (Timeout, MaxToolRounds, HardToolRounds) and
// returns a client with its own http.Client{Timeout: cfg.Timeout}.
func NewClient(cfg ClientConfig) *Client {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.MaxToolRounds <= 0 {
		cfg.MaxToolRounds = defaultToolRounds
	}
	if cfg.HardToolRounds <= 0 {
		// 配置层已校验 hard >= soft；客户端兜底保证不变式成立。
		cfg.HardToolRounds = defaultHardToolRounds
		if cfg.MaxToolRounds > cfg.HardToolRounds {
			cfg.HardToolRounds = cfg.MaxToolRounds
		}
	}
	return &Client{cfg: cfg, http: &http.Client{Timeout: cfg.Timeout}}
}

// SetHTTPClient replaces the internally created http.Client, e.g. to inject a
// client with a shared Transport (connection pooling) or, in tests, a client
// with a very short Timeout.
func (c *Client) SetHTTPClient(hc *http.Client) {
	if hc != nil {
		c.http = hc
	}
}

// ToolSpec describes one function tool exposed to the model.
type ToolSpec struct {
	Name, Description string
	ParametersJSON    []byte // JSON Schema; empty defaults to {"type":"object"}
}

// ToolCall is a single tool invocation requested by the model.
type ToolCall struct {
	ID, Name, ArgsJSON string
}

// ToolHandler executes a tool call and returns a JSON string result.
type ToolHandler func(ctx context.Context, call ToolCall) (resultJSON string, err error)

// RunRequest is one analysis task.
type RunRequest struct {
	SystemPrompt, UserPrompt string
	Tools                    map[string]ToolSpec // ignored when EnableTools is false
	Handlers                 map[string]ToolHandler
	FinalMaxBytes            int // cap on the final model output; 0 => 64 KiB
}

// RunResult reports the final output and the accounting of a successful Run.
type RunResult struct {
	Content                        []byte // final model output, fences stripped, raw JSON text
	Rounds, ToolCalls              int
	PromptTokens, CompletionTokens int
}

// Run drives the chat completion loop:
//
//  1. ErrNoAPIKey when the configured API key is empty (no request is sent).
//  2. Each completion goes through POST {BaseURL}/chat/completions with
//     retry/backoff for network errors, 429 and 500/502/503/504; other 4xx
//     fail fast as *HTTPStatusError.
//  3. finish_reason tool_calls (or legacy function_call) executes every tool
//     call and feeds results back as tool messages; handler failures become
//     {"error":...} tool results instead of aborting. Assistant messages are
//     echoed back with their reasoning_content intact (DeepSeek requires it
//     when the request carries tools).
//  4. Soft limit (MaxToolRounds): once exceeded, every further round gets a
//     system hint urging the model to wrap up — tool calls remain allowed.
//  5. Hard limit (HardToolRounds): when the model still requests tools, one
//     final toolless completion is issued with the full history preserved;
//     its output returns through the normal final-content path. Only if that
//     call itself fails does Run return ErrToolRoundsExceeded.
//  6. The loop ends with a normal message whose content is fence-stripped and
//     size-checked, or with ErrTokenBudgetExceeded.
func (c *Client) Run(ctx context.Context, req RunRequest) (RunResult, error) {
	var res RunResult
	if c.cfg.APIKey == "" {
		return res, ErrNoAPIKey
	}

	msgs := make([]message, 0, 2)
	if req.SystemPrompt != "" {
		msgs = append(msgs, message{Role: "system", Content: req.SystemPrompt})
	}
	msgs = append(msgs, message{Role: "user", Content: req.UserPrompt})

	var toolDefs []toolDefinition
	if c.cfg.EnableTools && len(req.Tools) > 0 {
		names := make([]string, 0, len(req.Tools))
		for name := range req.Tools {
			names = append(names, name)
		}
		sort.Strings(names) // deterministic request bodies
		for _, name := range names {
			spec := req.Tools[name]
			params := json.RawMessage(spec.ParametersJSON)
			if len(params) == 0 {
				params = json.RawMessage(`{"type":"object"}`)
			}
			toolDefs = append(toolDefs, toolDefinition{
				Type: "function",
				Function: functionDef{
					Name:        name,
					Description: spec.Description,
					Parameters:  params,
				},
			})
		}
	}

	finalMax := req.FinalMaxBytes
	if finalMax <= 0 {
		finalMax = defaultFinalMaxBytes
	}

	toolRounds := 0
	for {
		res.Rounds++
		resp, err := c.postChat(ctx, msgs, toolDefs)
		if err != nil {
			return res, err
		}

		res.PromptTokens += resp.Usage.PromptTokens
		res.CompletionTokens += resp.Usage.CompletionTokens
		if c.cfg.MaxTotalTokens > 0 &&
			res.PromptTokens+res.CompletionTokens > c.cfg.MaxTotalTokens {
			return res, fmt.Errorf("%w: %d tokens used, budget %d",
				ErrTokenBudgetExceeded,
				res.PromptTokens+res.CompletionTokens, c.cfg.MaxTotalTokens)
		}

		ch := resp.Choices[0]
		if isToolRound(ch.FinishReason) && len(ch.Message.ToolCalls) > 0 {
			if toolRounds >= c.cfg.HardToolRounds {
				// 硬上限：强制收稿——一次不带 tools 的最终补全。
				return c.finalWithoutTools(ctx, res, msgs, finalMax)
			}
			toolRounds++
			msgs = append(msgs, message{
				Role:             "assistant",
				Content:          ch.Message.Content,
				ReasoningContent: ch.Message.ReasoningContent, // 原样回传（DeepSeek 400 规则）
				ToolCalls:        ch.Message.ToolCalls,
			})
			for _, tc := range ch.Message.ToolCalls {
				content := c.execTool(ctx, req, tc)
				msgs = append(msgs, message{
					Role:       "tool",
					ToolCallID: tc.ID,
					Content:    content,
				})
				res.ToolCalls++
			}
			// 软上限：超出后每个后续轮次注入一条收尾提示（不阻断工具）。
			if len(toolDefs) > 0 && toolRounds > c.cfg.MaxToolRounds {
				msgs = append(msgs, message{
					Role:    "system",
					Content: fmt.Sprintf(softLimitHintTmpl, c.cfg.MaxToolRounds),
				})
			}
			continue
		}

		content := stripCodeFence(ch.Message.Content)
		if content == "" {
			return res, fmt.Errorf("%w: empty final content (finish_reason=%q)",
				ErrInvalidResponse, ch.FinishReason)
		}
		if len(content) > finalMax {
			return res, fmt.Errorf("%w: final content is %d bytes, limit %d",
				ErrInvalidResponse, len(content), finalMax)
		}
		res.Content = []byte(content)
		return res, nil
	}
}

// finalWithoutTools 是硬上限触发的强制收稿：保留全部对话历史（system、
// user、历次 assistant 工具轮与 tool 结果），追加一条无工具收尾的 system
// 指令，发起一次不带 tools 的最终补全。成功则与正常最终输出走同一条
// 路径（剥围栏、限长，写入 res.Content）——与 generator「无 submit_report
// 被接受时把最终输出当草稿解析」的兜底天然兼容。仅当这次调用本身失败
// （HTTP/超时/响应无效）才返回错误；ErrToolRoundsExceeded 只保留给该场景。
func (c *Client) finalWithoutTools(ctx context.Context, res RunResult, msgs []message, finalMax int) (RunResult, error) {
	final := make([]message, 0, len(msgs)+1)
	final = append(final, msgs...)
	final = append(final, message{Role: "system", Content: hardLimitFinalMsg})

	resp, err := c.postChat(ctx, final, nil)
	if err != nil {
		return res, fmt.Errorf("%w: 已达硬上限 %d 轮，最终补全调用失败: %w",
			ErrToolRoundsExceeded, c.cfg.HardToolRounds, err)
	}

	res.Rounds++
	res.PromptTokens += resp.Usage.PromptTokens
	res.CompletionTokens += resp.Usage.CompletionTokens
	if c.cfg.MaxTotalTokens > 0 &&
		res.PromptTokens+res.CompletionTokens > c.cfg.MaxTotalTokens {
		return res, fmt.Errorf("%w: %d tokens used, budget %d",
			ErrTokenBudgetExceeded,
			res.PromptTokens+res.CompletionTokens, c.cfg.MaxTotalTokens)
	}

	ch := resp.Choices[0]
	content := stripCodeFence(ch.Message.Content)
	if content == "" {
		return res, fmt.Errorf("%w: 硬上限收稿的最终输出为空 (finish_reason=%q)",
			ErrInvalidResponse, ch.FinishReason)
	}
	if len(content) > finalMax {
		return res, fmt.Errorf("%w: final content is %d bytes, limit %d",
			ErrInvalidResponse, len(content), finalMax)
	}
	res.Content = []byte(content)
	return res, nil
}

// execTool runs one tool call and always returns the JSON content for the tool
// result message. Bad arguments, an unregistered tool, a handler error or a
// handler panic become {"error":...} results so the conversation continues.
func (c *Client) execTool(ctx context.Context, req RunRequest, tc toolCallMsg) (result string) {
	name := tc.Function.Name
	call := ToolCall{ID: tc.ID, Name: name, ArgsJSON: tc.Function.Arguments}

	defer func() {
		if r := recover(); r != nil {
			result = (&ToolError{ToolName: name, Reason: fmt.Sprintf("handler panicked: %v", r)}).ToJSON()
		}
	}()

	args := strings.TrimSpace(call.ArgsJSON)
	if args == "" {
		args = "{}" // some models emit arguments:"" for no-arg calls
	}
	var raw json.RawMessage
	if err := json.Unmarshal([]byte(args), &raw); err != nil {
		return (&ToolError{
			ToolName: name,
			Reason:   "invalid arguments json: " + err.Error(),
		}).ToJSON()
	}
	call.ArgsJSON = args

	handler, ok := req.Handlers[name]
	if !ok || handler == nil {
		return (&ToolError{ToolName: name, Reason: "unknown tool"}).ToJSON()
	}
	out, err := handler(ctx, call)
	if err != nil {
		return (&ToolError{ToolName: name, Reason: err.Error()}).ToJSON()
	}
	if strings.TrimSpace(out) == "" {
		return "{}"
	}
	return out
}

// isToolRound reports whether a finish reason asks the host to run tools.
// "function_call" is the legacy OpenAI spelling kept for compatibility.
func isToolRound(finishReason string) bool {
	return finishReason == "tool_calls" || finishReason == "function_call"
}

// postChat performs one chat/completions request, retrying transient failures
// (network errors, 429, 500, 502, 503, 504) with exponential backoff and
// jitter, honoring a capped Retry-After header. It returns as soon as the
// caller's context is done.
func (c *Client) postChat(ctx context.Context, msgs []message, toolDefs []toolDefinition) (*chatResponse, error) {
	toolChoice := any(nil)
	if len(toolDefs) > 0 {
		toolChoice = "auto"
	}
	var respFormat *responseFormat
	if !c.cfg.EnableTools {
		respFormat = &responseFormat{Type: "json_object"}
	}
	// thinking：on → enabled，off → disabled；""/auto → 不发送（服务端
	// 默认：思考模型开启思考，强度 high）。
	var thinking *thinkingParam
	switch c.cfg.Thinking {
	case "on":
		thinking = &thinkingParam{Type: "enabled"}
	case "off":
		thinking = &thinkingParam{Type: "disabled"}
	}
	payload, err := json.Marshal(chatRequest{
		Model:           c.cfg.Model,
		Messages:        msgs,
		MaxTokens:       c.cfg.MaxOutputTokens,
		Stream:          false,
		Tools:           toolDefs,
		ToolChoice:      toolChoice,
		ResponseFormat:  respFormat,
		Thinking:        thinking,
		ReasoningEffort: c.cfg.ReasoningEffort, // "" => omit
	})
	if err != nil {
		return nil, fmt.Errorf("llm: marshal request: %w", err)
	}
	url := strings.TrimSuffix(c.cfg.BaseURL, "/") + "/chat/completions"

	var lastErr error
	var retryAfter time.Duration
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoffDelay(attempt, retryAfter)):
			}
			retryAfter = 0
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("llm: build request: %w", err)
		}
		httpReq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
		httpReq.Header.Set("Content-Type", "application/json")

		resp, err := c.http.Do(httpReq)
		if err != nil {
			lastErr = err
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr // caller context done: stop retrying
			}
			continue // transient network error: retry
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var parsed chatResponse
			if err := json.Unmarshal(body, &parsed); err != nil {
				return nil, fmt.Errorf("%w: body is not valid JSON: %s",
					ErrInvalidResponse, snippet(body))
			}
			if len(parsed.Choices) == 0 {
				return nil, fmt.Errorf("%w: choices is empty: %s",
					ErrInvalidResponse, snippet(body))
			}
			return &parsed, nil
		}

		statusErr := &HTTPStatusError{
			Code:       resp.StatusCode,
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()),
			Body:       snippet(body),
		}
		if retryableStatus(resp.StatusCode) {
			lastErr = statusErr
			retryAfter = statusErr.RetryAfter
			continue
		}
		return nil, statusErr // e.g. 400/401/403/404: fail fast
	}

	// Retry budget exhausted.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if isTimeoutError(lastErr) {
		return nil, fmt.Errorf("%w: %v", ErrTimeout, lastErr)
	}
	return nil, fmt.Errorf("llm: request failed after %d attempts: %w", maxRetries+1, lastErr)
}

// isTimeoutError reports whether err is a per-request timeout (client timeout
// or request context deadline), as opposed to the caller's context being done.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

// stripCodeFence removes a surrounding markdown code fence (``` or ```json)
// from model output and trims surrounding whitespace.
func stripCodeFence(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[i+1:] // drop the "```json" opening line
	}
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "```") {
		s = strings.TrimSuffix(s, "```")
	}
	return strings.TrimSpace(s)
}

// snippet returns up to 500 bytes of a raw response body for error messages.
func snippet(b []byte) string {
	const max = 500
	if len(b) > max {
		return string(b[:max]) + "...(truncated)"
	}
	return string(b)
}
