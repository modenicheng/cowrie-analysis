package llm

import (
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// maxRetryAfterDelay caps any server-provided Retry-After wait.
const maxRetryAfterDelay = 60 * time.Second

// maxRetries is the number of retries after the initial attempt
// (3 retries => up to 4 requests per completion).
var maxRetries = 3

// retryBackoffBase is the base delay of the exponential backoff (1s, 2s, 4s
// with the production default of 1s). It is deliberately unexported so tests
// can shorten it instead of sleeping seconds between retry attempts.
var retryBackoffBase = 1 * time.Second

// retryableStatus reports whether an HTTP status code is worth retrying:
// 429, 500, 502, 503, 504. Everything else (including other 4xx and 5xx)
// fails fast.
func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout:      // 504
		return true
	}
	return false
}

// parseRetryAfter parses a Retry-After header value, accepting either delay
// seconds ("120") or an HTTP-date. Missing, invalid, zero or negative values
// yield 0.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if at, err := http.ParseTime(v); err == nil {
		if d := at.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// backoffDelay computes the wait before retry number `attempt` (1-based).
// A server-provided retryAfter takes precedence over the computed backoff and
// is capped at maxRetryAfterDelay; otherwise the delay is retryBackoffBase
// doubled per attempt (1s, 2s, 4s with the default base) with +/-20% jitter.
func backoffDelay(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		if retryAfter > maxRetryAfterDelay {
			return maxRetryAfterDelay
		}
		return retryAfter
	}
	d := retryBackoffBase
	for i := 1; i < attempt && d > 0; i++ {
		d <<= 1
	}
	jitter := 1 + (rand.Float64()*2-1)*0.2 // 0.8 .. 1.2
	return time.Duration(float64(d) * jitter)
}
