// S3 Signature V4 全手写实现（仅标准库 crypto/hmac、crypto/sha256）与
// S3 请求执行：virtual-host 风格 PUT/DELETE/LIST（ListObjectsV2）。
// 签名头固定为 host;x-amz-content-sha256;x-amz-date（持有会话令牌时
// 追加 x-amz-security-token），Content-Type 不参与签名。
package dogecloud

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// sigHeader 是一个参与签名的请求头（名称小写，值已去除首尾空白）。
type sigHeader struct {
	name  string
	value string
}

// sigv4Sign 按 SigV4 计算完整 Authorization 头的值。headers 必须已按
// 名称升序排列（S3 场景由 sigv4Authorization 组装）；签名链：
// HMAC("AWS4"+SK,date) → HMAC(,region) → HMAC(,service) → HMAC(,"aws4_request")。
func sigv4Sign(secretKey, accessKey, region, service, method, canonicalURI, canonicalQuery string,
	headers []sigHeader, payloadHash, amzDate string) string {
	date := amzDate[:8]
	var ch strings.Builder
	names := make([]string, 0, len(headers))
	for _, h := range headers {
		names = append(names, h.name)
		ch.WriteString(h.name)
		ch.WriteByte(':')
		ch.WriteString(h.value)
		ch.WriteByte('\n')
	}
	signedHeaders := strings.Join(names, ";")
	canonicalRequest := strings.Join([]string{
		method, canonicalURI, canonicalQuery, ch.String(), signedHeaders, payloadHash,
	}, "\n")
	scope := date + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, sha256Hex([]byte(canonicalRequest)),
	}, "\n")
	kSigning := hmacSHA256(hmacSHA256(hmacSHA256(hmacSHA256(
		[]byte("AWS4"+secretKey), date), region), service), "aws4_request")
	return "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + scope +
		", SignedHeaders=" + signedHeaders +
		", Signature=" + hex.EncodeToString(hmacSHA256(kSigning, stringToSign))
}

// sigv4Authorization 组装 S3 场景的标准签名头集（host、x-amz-content-sha256、
// x-amz-date，持有会话令牌时追加 x-amz-security-token，天然按名升序）并签名。
func sigv4Authorization(creds ossCredentials, region, service, method, canonicalURI,
	canonicalQuery, host, payloadHash, amzDate string) string {
	headers := []sigHeader{
		{"host", host},
		{"x-amz-content-sha256", payloadHash},
		{"x-amz-date", amzDate},
	}
	if creds.sessionToken != "" {
		headers = append(headers, sigHeader{"x-amz-security-token", creds.sessionToken})
	}
	return sigv4Sign(creds.secretKey, creds.accessKey, region, service,
		method, canonicalURI, canonicalQuery, headers, payloadHash, amzDate)
}

// uriEscape 按 RFC 3986 做 percent-encoding（非保留字符 A-Za-z0-9-._~ 之外
// 全部转义，空格为 %20）；keepSlash 为 true 时保留 '/'（对象 key 的
// canonical URI 按 S3 规范不二次 encode、不折叠斜杠），false 用于查询参数值。
func uriEscape(s string, keepSlash bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '-' || c == '.' || c == '_' || c == '~' || (keepSlash && c == '/') {
			b.WriteByte(c)
			continue
		}
		const hexDigits = "0123456789ABCDEF"
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&0xf])
	}
	return b.String()
}

// sha256Hex 返回 hex(SHA-256(b))；b 为 nil 时空体哈希，与空串一致。
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// hmacSHA256 返回 HMAC-SHA256(key, s)。
func hmacSHA256(key []byte, s string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(s))
	return mac.Sum(nil)
}

// s3VirtualHost 返回 virtual-host 风格的主机名：{s3Bucket}.{endpoint host}。
func s3VirtualHost(creds ossCredentials) string {
	return creds.target.bucket + "." + creds.target.host
}

// s3Perform 构造并发送一个带 SigV4 签名的 S3 请求，返回未关闭的响应。
// path 须为已编码的 canonical URI（以 / 开头），query 须为已按参数名排序、
// 已编码的 canonical query string（无参数传空串）；payload 为请求体
// （GET/DELETE 传 nil，按空体参与签名）。contentType 为空时不设置该头。
func (c *Client) s3Perform(ctx context.Context, creds ossCredentials, method, path, query string,
	payload []byte, contentType string) (*http.Response, error) {
	amzDate := nowFn().UTC().Format(amzDateLayout)
	payloadHash := sha256Hex(payload)
	vhost := s3VirtualHost(creds)
	authorization := sigv4Authorization(creds, s3Region, s3Service, method, path, query, vhost, payloadHash, amzDate)

	urlStr := creds.target.scheme + "://" + vhost + path
	if query != "" {
		urlStr += "?" + query
	}
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, fmt.Errorf("dogecloud: 构造 S3 请求失败: %w", err)
	}
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	if creds.sessionToken != "" {
		req.Header.Set("x-amz-security-token", creds.sessionToken)
	}
	req.Header.Set("Authorization", authorization)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dogecloud: S3 %s %s 请求失败: %w", method, path, err)
	}
	return resp, nil
}

// s3Object 是 LIST 结果中的一项。LastModified 无法解析时 modTimeOK 为
// false（Prune 保守跳过该对象，不删时间未知的对象）。
type s3Object struct {
	Key          string
	LastModified time.Time
	modTimeOK    bool
}

// listBucketXML 对应 S3 ListObjectsV2 的 ListBucketResult 响应。
type listBucketXML struct {
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
	Contents              []struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
	} `xml:"Contents"`
}

// parseListXML 解析一页 ListObjectsV2 响应。LastModified 按 RFC3339 解析
// （S3 带毫秒的小数秒仍可解析）；解析失败的对象保留 Key、modTimeOK=false。
func parseListXML(data []byte) (objects []s3Object, truncated bool, nextToken string, err error) {
	var lx listBucketXML
	if err := xml.Unmarshal(data, &lx); err != nil {
		return nil, false, "", fmt.Errorf("dogecloud: 解析 LIST 响应 XML 失败: %w", err)
	}
	objects = make([]s3Object, 0, len(lx.Contents))
	for _, item := range lx.Contents {
		obj := s3Object{Key: item.Key}
		if t, terr := time.Parse(time.RFC3339, item.LastModified); terr == nil {
			obj.LastModified, obj.modTimeOK = t, true
		}
		objects = append(objects, obj)
	}
	return objects, lx.IsTruncated, lx.NextContinuationToken, nil
}

// listAllObjects 以 ListObjectsV2 分页遍历 KeyPrefix 前缀下全部对象。
// 请求 GET /?list-type=2&max-keys=1000&prefix={KeyPrefix 编码}[&continuation-token=...]，
// canonical query string 始终按参数名排序。
func (c *Client) listAllObjects(ctx context.Context, creds ossCredentials) ([]s3Object, error) {
	var all []s3Object
	token := ""
	for page := 0; ; page++ {
		if page >= maxListPages {
			return nil, fmt.Errorf("dogecloud: LIST 分页超过 %d 页，疑似异常响应，已中止", maxListPages)
		}
		params := []string{
			"list-type=2",
			"max-keys=" + s3ListMaxKeys,
			"prefix=" + uriEscape(c.cfg.KeyPrefix, false),
		}
		if token != "" {
			params = append(params, "continuation-token="+uriEscape(token, false))
		}
		sort.Strings(params)

		resp, err := c.s3Perform(ctx, creds, http.MethodGet, "/", strings.Join(params, "&"), nil, "")
		if err != nil {
			return nil, err
		}
		body, readErr := readLimited(resp.Body, s3ListRespLimit)
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, fmt.Errorf("dogecloud: 列举对象失败: HTTP %d: %s",
				resp.StatusCode, previewText(body))
		}
		if readErr != nil {
			return nil, fmt.Errorf("dogecloud: 读取 LIST 响应失败: %w", readErr)
		}
		objs, truncated, next, perr := parseListXML(body)
		if perr != nil {
			return nil, perr
		}
		all = append(all, objs...)
		if !truncated || next == "" {
			return all, nil
		}
		token = next
	}
}
