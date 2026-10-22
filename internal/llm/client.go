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
	defaultTimeout       = 120 * time.Second
	defaultToolRounds    = 6
	defaultFinalMaxBytes = 64 << 10 // 64 KiB cap on the final model output
	maxResponseBody      = 8 << 20  // read cap per response body
)

// ClientConfig configures a DeepSeek (OpenAI-compatible) client. All values
// come from application configuration; nothing is hardcoded.
type ClientConfig struct {
	BaseURL, Model, APIKey string
	Timeout         time.Duration // per-request total timeout; <=0 => 120s
	MaxToolRounds   int           // max rounds with tool execution; <=0 => 6
	MaxOutputTokens int           // max_tokens per request; 0 => omit
	MaxTotalTokens  int           // task-level cumulative budget; 0 => unlimited
	EnableTools     bool          // false => single-shot json_object mode
}

// Client is a reusable chat completions client.
type Client struct {
	cfg  ClientConfig
	http *http.Client
}

// NewClient applies defaults (Timeout, MaxToolRounds) and returns a client
// with its own http.Client{Timeout: cfg.Timeout}.
func NewClient(cfg ClientConfig) *Client {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.MaxToolRounds <= 0 {
		cfg.MaxToolRounds = defaultToolRounds
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
	Tools    map[string]ToolSpec   // ignored when EnableTools is false
	Handlers map[string]ToolHandler
	FinalMaxBytes int // cap on the final model output; 0 => 64 KiB
}

// RunResult reports the final output and the accounting of a successful Run.
type RunResult struct {
	Content        []byte // final model output, fences stripped, raw JSON text
	Rounds, ToolCalls int
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
//     {"error":...} tool results instead of aborting.
//  4. The loop ends with a normal message whose content is fence-stripped and
//     size-checked, or with ErrToolRoundsExceeded / ErrTokenBudgetExceeded.
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
			if toolRounds >= c.cfg.MaxToolRounds {
				return res, fmt.Errorf("%w: limit is %d",
					ErrToolRoundsExceeded, c.cfg.MaxToolRounds)
			}
			toolRounds++
			msgs = append(msgs, message{
				Role:      "assistant",
				Content:   ch.Message.Content,
				ToolCalls: ch.Message.ToolCalls,
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
	payload, err := json.Marshal(chatRequest{
		Model:          c.cfg.Model,
		Messages:       msgs,
		MaxTokens:      c.cfg.MaxOutputTokens,
		Stream:         false,
		Tools:          toolDefs,
		ToolChoice:     toolChoice,
		ResponseFormat: respFormat,
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
