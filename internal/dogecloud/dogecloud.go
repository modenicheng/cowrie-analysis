// Package dogecloud 实现多吉云（DogeCloud）对象存储的上传与过期清理。
//
// 工作方式：先用 AccessKey/SecretKey 通过多吉云开放 API 换取一次性 S3
// 临时密钥（channel=OSS_UPLOAD，作用域限定到单个桶），再用临时密钥以
// S3 Signature V4（virtual-host 风格、region "auto"）直连对象存储读写。
// 临时密钥有效期不超过 2 小时，因此 Upload/Prune 每次调用都现换新密钥，
// 不做缓存；本包也不内置重试（调用方自行决定重试策略）。
//
// 全部实现仅依赖标准库。错误信息面向运维排障（包含 HTTP 状态码、桶名/
// 对象 key、endpoint 主机名），绝不包含 SecretKey 或临时凭据值；包内也
// 不引入日志库。
package dogecloud

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// 包内常量集中声明：默认地址/超时、临时密钥协议参数、S3 SigV4 参数、
// 错误预览与响应体读取上限、NewKey 随机段参数。
const (
	// defaultAPIBaseURL 是 cfg.APIBaseURL 留空时使用的多吉云开放 API 地址。
	defaultAPIBaseURL = "https://api.dogecloud.com"
	// defaultTimeout 是 cfg.Timeout 未设置（<=0）时使用的默认 HTTP 超时。
	defaultTimeout = 10 * time.Second
	// tmpTokenPath 是换取临时密钥的 API 路径，同时参与 HMAC-SHA1 签名。
	tmpTokenPath = "/auth/tmp_token.json"
	// tmpTokenChannel 是临时密钥的用途标识（对象存储上传专用通道）。
	tmpTokenChannel = "OSS_UPLOAD"
	// tmpTokenOKCode 是多吉云 API 业务成功码。
	tmpTokenOKCode = 200
	// tmpTokenRespLimit 限制读取的临时密钥响应体字节数，防止异常响应占用过多内存。
	tmpTokenRespLimit = 64 << 10

	// s3Region / s3Service 是多吉云 S3 兼容端点的 SigV4 签名参数。
	s3Region  = "auto"
	s3Service = "s3"
	// amzDateLayout 是 SigV4 的 x-amz-date / 日期范围时间格式（UTC）。
	amzDateLayout = "20060102T150405Z"
	// s3ListMaxKeys 是 LIST 请求单页最大对象数（S3 ListObjectsV2 上限 1000）。
	s3ListMaxKeys = "1000"
	// s3ErrorPreviewBytes 是 S3 错误响应体进入错误信息的最大字节数。
	s3ErrorPreviewBytes = 4 << 10
	// s3ListRespLimit 限制读取的单页 LIST 响应体字节数。
	s3ListRespLimit = 1 << 20
	// maxListPages 是 LIST 分页页数上限，防止服务端异常令牌导致死循环。
	maxListPages = 1000

	// keyRandBytes 是 NewKey 随机段使用的 crypto/rand 字节数（hex 后 16 字符）。
	keyRandBytes = 8
	// keyDateLayout 是 NewKey 日期段的时间格式（UTC 语义由调用方保证）。
	keyDateLayout = "20060102"
)

// nowFn 是可注入的时钟（SigV4 时间戳与 Prune 保留期计算都依赖它），
// 仅测试替换使用；生产代码不得修改（非并发安全地写它）。
var nowFn func() time.Time = time.Now

// Config 配置多吉云对象存储客户端。AccessKey/SecretKey/Bucket 必填
// （运行时从环境变量解析后的值），方法调用前缺失会返回明确错误。
type Config struct {
	AccessKey, SecretKey string        // 多吉云 AccessKey / SecretKey
	Bucket               string        // 标准型存储桶名
	PublicBaseURL        string        // 公网访问基址，如 https://img-host.modenc.top
	KeyPrefix            string        // 对象 key 前缀，如 "e3-reports/"（NewKey 会规范化为以 / 结尾）
	APIBaseURL           string        // 多吉云 API 基址；留空则 https://api.dogecloud.com（测试可注入 httptest 地址）
	RetentionDays        int           // 桶内对象保留期（天）；<=0 禁用清理
	Timeout              time.Duration // 单次 HTTP 请求超时；<=0 时使用 10s
}

// Client 是多吉云对象存储客户端：上传（Upload）、生成对象 key（NewKey）
// 与按保留期清理（Prune）。方法每次调用独立换临时密钥，无共享可变状态，
// 可被多个 goroutine 同时调用（hc 须并发安全，*http.Client 满足）。
type Client struct {
	cfg Config
	hc  *http.Client
}

// New 创建 Client：cfg.APIBaseURL 留空时使用官方地址，Timeout <=0 时
// 使用 10s；hc 为 nil 时使用带该超时的默认 http.Client，否则原样使用
// （测试可注入自定义 Transport）。
func New(cfg Config, hc *http.Client) *Client {
	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = defaultAPIBaseURL
	}
	cfg.APIBaseURL = strings.TrimRight(cfg.APIBaseURL, "/")
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if hc == nil {
		hc = &http.Client{Timeout: cfg.Timeout}
	}
	return &Client{cfg: cfg, hc: hc}
}

// NewKey 生成一个对象 key：
//
//	{KeyPrefix 规范化为以 / 结尾}{kind}/{since.Format("20060102")}-{hex(8 字节随机数)}.png
//
// 随机段来自 crypto/rand（失败在实践中不可达，兜底用时间熵避免 panic）。
func (c *Client) NewKey(kind string, since time.Time) string {
	rnd := make([]byte, keyRandBytes)
	if _, err := rand.Read(rnd); err != nil {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d", c.cfg.KeyPrefix, kind, nowFn().UnixNano())))
		copy(rnd, sum[:keyRandBytes])
	}
	return normalizeKeyPrefix(c.cfg.KeyPrefix) + kind + "/" +
		since.Format(keyDateLayout) + "-" + hex.EncodeToString(rnd) + ".png"
}

// Upload 把 data 以 key 上传到桶（每次调用现换临时密钥，不缓存、不重试）：
//
//   - key 为空、含 "?"、"#" 或非 ASCII 字符时本地直接返回错误，不发出任何请求；
//   - SigV4 PUT 成功（2xx）返回 PublicBaseURL（去尾斜杠）+ "/" + key；
//   - 非 2xx 时读取响应体（不超过 4KB）进入错误信息。
func (c *Client) Upload(ctx context.Context, key string, data []byte, contentType string) (publicURL string, err error) {
	if err := c.validateConfig(); err != nil {
		return "", err
	}
	if err := validateKey(key); err != nil {
		return "", err
	}
	creds, err := c.fetchTmpToken(ctx)
	if err != nil {
		return "", err
	}
	resp, err := c.s3Perform(ctx, creds, http.MethodPut, "/"+uriEscape(key, true), "", data, contentType)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := readLimited(resp.Body, s3ErrorPreviewBytes)
		return "", fmt.Errorf("dogecloud: 上传对象 %q 到存储桶 %s 失败: HTTP %d: %s",
			key, creds.target.bucket, resp.StatusCode, previewText(body))
	}
	return strings.TrimRight(c.cfg.PublicBaseURL, "/") + "/" + key, nil
}

// Prune 清理桶内 KeyPrefix 前缀下超过保留期的对象：
//
//   - RetentionDays <= 0 时禁用清理，直接返回 (0, nil)；
//   - LastModified 早于 now-保留期 的对象逐个 DELETE；单对象删除失败
//     记录后继续下一个，返回成功删除数；err 返回首个遇到的删除错误
//     （全部成功则 nil）；
//   - LIST 本身失败 → (0, err)；LastModified 无法解析的对象视为时间
//     未知，保守跳过不删。
func (c *Client) Prune(ctx context.Context) (deleted int, err error) {
	if err := c.validateConfig(); err != nil {
		return 0, err
	}
	if c.cfg.RetentionDays <= 0 {
		return 0, nil
	}
	creds, err := c.fetchTmpToken(ctx)
	if err != nil {
		return 0, err
	}
	objects, err := c.listAllObjects(ctx, creds)
	if err != nil {
		return 0, err
	}
	cutoff := nowFn().Add(-time.Duration(c.cfg.RetentionDays) * 24 * time.Hour)
	var firstErr error
	for _, obj := range objects {
		if !obj.modTimeOK || !obj.LastModified.Before(cutoff) {
			continue
		}
		resp, delErr := c.s3Perform(ctx, creds, http.MethodDelete, "/"+uriEscape(obj.Key, true), "", nil, "")
		if delErr != nil {
			if firstErr == nil {
				firstErr = delErr
			}
			continue
		}
		ok := resp.StatusCode >= 200 && resp.StatusCode <= 299
		if !ok {
			body, _ := readLimited(resp.Body, s3ErrorPreviewBytes)
			if firstErr == nil {
				firstErr = fmt.Errorf("dogecloud: 删除对象 %q 失败: HTTP %d: %s",
					obj.Key, resp.StatusCode, previewText(body))
			}
		}
		resp.Body.Close()
		if ok {
			deleted++
		}
	}
	return deleted, firstErr
}

// validateConfig 校验必填配置，全部通过返回 nil（错误列出全部缺失字段，便于一次改完）。
func (c *Client) validateConfig() error {
	var missing []string
	if c.cfg.AccessKey == "" {
		missing = append(missing, "AccessKey")
	}
	if c.cfg.SecretKey == "" {
		missing = append(missing, "SecretKey")
	}
	if c.cfg.Bucket == "" {
		missing = append(missing, "Bucket")
	}
	if len(missing) > 0 {
		return fmt.Errorf("dogecloud: 配置不完整，缺少 %s", strings.Join(missing, "、"))
	}
	return nil
}

// validateKey 校验对象 key：非空、不含 "?" 与 "#"（会被截断成查询串/锚点）、
// 全 ASCII（签名与 URL 编码路径只按字节处理）。通过返回 nil。
func validateKey(key string) error {
	if key == "" {
		return fmt.Errorf("dogecloud: 对象 key 为空")
	}
	if strings.ContainsAny(key, "?#") {
		return fmt.Errorf("dogecloud: 对象 key %q 含有 \"?\" 或 \"#\"", key)
	}
	for i := 0; i < len(key); i++ {
		if key[i] > 0x7f {
			return fmt.Errorf("dogecloud: 对象 key %q 含有非 ASCII 字符", key)
		}
	}
	return nil
}

// normalizeKeyPrefix 把 KeyPrefix 规范化为以 / 结尾（空前缀保持为空）。
func normalizeKeyPrefix(prefix string) string {
	if prefix == "" || strings.HasSuffix(prefix, "/") {
		return prefix
	}
	return prefix + "/"
}
