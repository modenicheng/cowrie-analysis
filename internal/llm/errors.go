package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Sentinel errors returned (wrapped) by Run. All are usable with errors.Is.
var (
	// ErrNoAPIKey is returned when ClientConfig.APIKey is empty; no request
	// is sent in that case.
	ErrNoAPIKey = errors.New("llm: API key is empty")

	// ErrTimeout is returned when the retry budget is exhausted and the last
	// failure was a per-request timeout (http.Client.Timeout or a context
	// deadline on the request itself). It wraps context.DeadlineExceeded so
	// callers can match either sentinel.
	ErrTimeout = fmt.Errorf("llm: request timed out: %w", context.DeadlineExceeded)

	// ErrInvalidResponse covers non-JSON response bodies, empty choices,
	// and empty or oversized final model content.
	ErrInvalidResponse = errors.New("llm: invalid response from model")

	// ErrToolRoundsExceeded is returned when the model still requests tools
	// after MaxToolRounds tool rounds have already been executed.
	ErrToolRoundsExceeded = errors.New("llm: maximum tool call rounds exceeded")

	// ErrTokenBudgetExceeded is returned when accumulated prompt+completion
	// tokens exceed ClientConfig.MaxTotalTokens.
	ErrTokenBudgetExceeded = errors.New("llm: token budget exceeded")
)

// HTTPStatusError reports a non-success HTTP status from the completions API.
// Non-retryable statuses (400/401/403/404 and any other non-retryable 4xx) are
// returned immediately; retryable statuses (429/500/502/503/504) surface as
// this error only after the retry budget is exhausted. Inspect it with
// errors.As.
type HTTPStatusError struct {
	Code       int           // HTTP status code
	RetryAfter time.Duration // parsed Retry-After header, 0 when absent
	Body       string        // truncated response body for diagnostics
}

func (e *HTTPStatusError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("llm: HTTP %d (retry after %s): %s", e.Code, e.RetryAfter, e.Body)
	}
	return fmt.Sprintf("llm: HTTP %d: %s", e.Code, e.Body)
}

// ToolError describes why a single tool invocation failed. Run never aborts a
// conversation because of a ToolError: the reason is serialized as
// {"error":...} and fed back to the model as the tool result so the model can
// correct itself; Run therefore does not return ToolError directly. The type
// exists for callers that invoke tool handlers outside the Run loop.
type ToolError struct {
	ToolName string
	Reason   string
}

func (e *ToolError) Error() string {
	return fmt.Sprintf("llm: tool %q failed: %s", e.ToolName, e.Reason)
}

// ToJSON renders the error as the tool message content sent back to the model.
func (e *ToolError) ToJSON() string {
	b, err := json.Marshal(map[string]string{"error": e.Reason})
	if err != nil {
		return `{"error":"tool invocation failed"}`
	}
	return string(b)
}
