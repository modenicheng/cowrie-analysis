// Package ntfy 实现与 ntfy 通知服务的交互。
//
// 本文件实现 Client：单次 HTTP 发布，包括本地消息校验、请求构造、
// 状态码分类与可重试判定。Client 不内置重试（单次发布），重试、去重
// 与限流由 Publisher 编排（另行实现，见 publisher.go）。
package ntfy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// 与 ntfy 服务端约定的大小限制与内部读取上限。
const (
	// MaxBodyBytes 是消息正文上限（字节）。超出时本地直接拒绝，
	// 截断策略由调用方决定，Client 不得静默截断正文。
	MaxBodyBytes = 4096
	// MaxTitleBytes 是 Title 请求头的字节安全边界，超长按 rune 截断。
	MaxTitleBytes = 200
	// statusPreviewBytes 是 HTTPStatusError.Body 保留的最大字节数。
	statusPreviewBytes = 500
	// respReadLimit 限制读取的响应体字节数，防止异常响应占用过多内存。
	respReadLimit = 8 << 10
	// defaultTimeout 是 cfg.Timeout 未设置（<=0）时使用的默认 HTTP 超时。
	defaultTimeout = 10 * time.Second
)

// topicRe 定义合法主题名：字母、数字、下划线、连字符，长度 1..64。
var topicRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ClientConfig 配置 ntfy 客户端。BaseURL 必须已由上层配置校验
// （合法的 http/https URL），Client 不重复校验 URL 语法。
type ClientConfig struct {
	BaseURL string
	Token   string        // 可为空（匿名模式）；非空时以 Bearer 方式携带
	Timeout time.Duration // 单次 HTTP 请求总超时；<=0 时使用默认值
}

// Client 向 ntfy 服务发布单条消息。并发安全；单次发布，不内置重试。
type Client struct {
	baseURL string // 已去除尾斜杠
	token   string
	hc      *http.Client
}

// NewClient 创建 Client。cfg.Timeout <= 0 时使用 defaultTimeout。
func NewClient(cfg ClientConfig) *Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		token:   strings.TrimSpace(cfg.Token),
		hc:      &http.Client{Timeout: timeout},
	}
}

// SetHTTPClient 替换内部 http.Client，用于测试注入；hc 为 nil 时忽略。
func (c *Client) SetHTTPClient(hc *http.Client) {
	if hc != nil {
		c.hc = hc
	}
}

// Message 是一条待发布的 ntfy 消息。
type Message struct {
	Topic    string   // 目标主题，须匹配 ^[A-Za-z0-9_-]{1,64}$
	Title    string   // 可选标题，发送前截断至 MaxTitleBytes 字节内（按 rune）
	Body     string   // 消息正文，非空且不超过 MaxBodyBytes 字节
	Priority int      // 1..5
	Tags     []string // 可选标签，以逗号连接
}

// PublishOutcome 记录一次发布的结果，供发布状态持久化使用。
type PublishOutcome struct {
	HTTPStatus int       // 服务端响应状态码（本地校验失败时为 0）
	ResponseID string    // 2xx 响应体 JSON 中的 id；解析失败或非 JSON 时为空
	SentAt     time.Time // 仅在 2xx 成功时设置（UTC）
}

// Publish 向 {BaseURL 去尾斜杠}/{Topic} 发送一次 POST。行为约定：
//
//   - Topic/Body/Priority 不合法时本地直接返回错误，不发出任何请求；
//   - 2xx 视为成功；响应体尝试解析 {"id":"..."}，解析失败不影响成功（ResponseID 为空）；
//   - 429 与 5xx 返回 HTTPStatusError（IsRetryable=true）；
//   - 其余非 2xx 返回 HTTPStatusError（IsRetryable=false），Body 截断至 500 字节；
//   - 网络错误/超时/ctx 取消返回包装后的原始错误（IsRetryable=true）。
func (c *Client) Publish(ctx context.Context, m Message) (PublishOutcome, error) {
	if err := validateMessage(m); err != nil {
		return PublishOutcome{}, err
	}
	if c.baseURL == "" {
		return PublishOutcome{}, &ValidationError{Field: "base_url", Reason: "empty base URL"}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/"+m.Topic, strings.NewReader(m.Body))
	if err != nil {
		return PublishOutcome{}, &ValidationError{Field: "base_url", Reason: err.Error()}
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("Priority", strconv.Itoa(m.Priority))
	if title := headerSafe(m.Title, MaxTitleBytes); title != "" {
		req.Header.Set("Title", title)
	}
	if tags := joinTags(m.Tags); tags != "" {
		req.Header.Set("Tags", tags)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		// 网络错误、超时与 ctx 取消都在此返回；包装原始错误，
		// 保留 errors.Is/As 对底层原因（如 context.DeadlineExceeded）的判定。
		return PublishOutcome{}, fmt.Errorf("ntfy: publish to topic %q: %w", m.Topic, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, respReadLimit))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		out := PublishOutcome{HTTPStatus: resp.StatusCode, SentAt: time.Now().UTC()}
		var parsed struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(body, &parsed) == nil {
			out.ResponseID = parsed.ID
		}
		return out, nil
	}

	// 429/5xx 与其余 4xx 统一返回 HTTPStatusError；是否可重试由 IsRetryable 按状态码判定。
	return PublishOutcome{HTTPStatus: resp.StatusCode}, &HTTPStatusError{
		Code: resp.StatusCode,
		Body: previewBytes(body, statusPreviewBytes),
	}
}

// HTTPStatusError 表示 ntfy 服务端返回了非 2xx 响应。
type HTTPStatusError struct {
	Code int    // HTTP 状态码
	Body string // 响应体预览，截断至 500 字节
}

// Error 实现 error 接口。
func (e *HTTPStatusError) Error() string {
	preview := previewBytes([]byte(e.Body), 160)
	if preview == "" {
		return fmt.Sprintf("ntfy: HTTP %d", e.Code)
	}
	return fmt.Sprintf("ntfy: HTTP %d: %s", e.Code, preview)
}

// Is 支持 errors.Is(err, &HTTPStatusError{Code: 401}) 的按状态码匹配；
// target 的 Code 为 0 时匹配任意 HTTPStatusError。
func (e *HTTPStatusError) Is(target error) bool {
	t, ok := target.(*HTTPStatusError)
	if !ok {
		return false
	}
	return t.Code == 0 || t.Code == e.Code
}

// ValidationError 表示消息未通过本地校验（或 BaseURL 未配置），
// 未发出任何网络请求。不可重试。
type ValidationError struct {
	Field  string // topic|body|priority|base_url
	Reason string
}

// Error 实现 error 接口。
func (e *ValidationError) Error() string {
	return fmt.Sprintf("ntfy: invalid %s: %s", e.Field, e.Reason)
}

// IsRetryable 判断 Publish 返回的错误是否值得重试：
//
//   - nil → false；
//   - *HTTPStatusError：429 或 5xx → true，其余（其他 4xx、3xx）→ false；
//   - *ValidationError（本地校验/配置错误）→ false；
//   - 其他非 nil 错误（网络错误、超时、包装的 ctx 错误）→ true。
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	var se *HTTPStatusError
	if errors.As(err, &se) {
		return se.Code == http.StatusTooManyRequests || se.Code >= 500
	}
	var ve *ValidationError
	if errors.As(err, &ve) {
		return false
	}
	return true
}

// validateMessage 在发出请求前校验消息，全部通过返回 nil。
func validateMessage(m Message) error {
	if !topicRe.MatchString(m.Topic) {
		return &ValidationError{Field: "topic", Reason: "must match " + topicRe.String()}
	}
	if m.Body == "" {
		return &ValidationError{Field: "body", Reason: "must not be empty"}
	}
	if len(m.Body) > MaxBodyBytes {
		return &ValidationError{Field: "body", Reason: fmt.Sprintf("length %d bytes exceeds limit %d", len(m.Body), MaxBodyBytes)}
	}
	if m.Priority < 1 || m.Priority > 5 {
		return &ValidationError{Field: "priority", Reason: fmt.Sprintf("must be within 1-5, got %d", m.Priority)}
	}
	return nil
}

// joinTags 过滤空标签与控制字符后以逗号连接；结果为空表示不发送 Tags 头。
func joinTags(tags []string) string {
	cleaned := make([]string, 0, len(tags))
	for _, tag := range tags {
		if tag = headerSafe(tag, len(tag)); tag != "" {
			cleaned = append(cleaned, tag)
		}
	}
	return strings.Join(cleaned, ",")
}

// headerSafe 移除对 HTTP 头非法的控制字符（防止标题注入破坏请求），
// 并按 rune 截断至不超过 maxBytes 字节。
func headerSafe(s string, maxBytes int) string {
	var b strings.Builder
	b.Grow(min(len(s), maxBytes))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > maxBytes {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// previewBytes 将 b 截断至不超过 max 字节，并回退到 UTF-8 字符边界，
// 避免在错误信息中切断多字节字符。
func previewBytes(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(b[cut]) {
		cut--
	}
	return string(b[:cut])
}
