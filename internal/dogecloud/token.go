// 临时密钥（tmp_token）：POST /auth/tmp_token.json，HMAC-SHA1 请求签名、
// 响应解析（兼容 AWS STS 大写与小写两种字段风格）、S3 endpoint 解析。
// 安全约定：本文件所有错误信息只包含状态码/业务码/msg/桶名/endpoint，
// 绝不包含 SecretKey、Authorization 头或临时凭据值。
package dogecloud

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// FetchTmpToken 换取并校验一次临时密钥（自检用，零副作用），不做任何
// S3 操作。Upload/Prune 每次调用也会自行换取新临时密钥，不经过这里缓存。
func (c *Client) FetchTmpToken(ctx context.Context) error {
	_, err := c.fetchTmpToken(ctx)
	return err
}

// ossTarget 是临时密钥换回的 S3 访问目标（virtual-host 风格拼 URL 用）。
type ossTarget struct {
	bucket string // s3Bucket（以 API 返回为准）
	scheme string // "https"（endpoint 为 http 时为 "http"，供测试注入）
	host   string // endpoint 主机名（可含端口）
}

// ossCredentials 是一次性的 S3 临时凭据及其访问目标。有效时间不超过 2
// 小时，用完即弃，不得缓存、不得写入日志或错误信息。
type ossCredentials struct {
	accessKey    string
	secretKey    string
	sessionToken string // 可为空（部分渠道不下发会话令牌）
	target       ossTarget
}

// tmpTokenRequest 是 /auth/tmp_token.json 的请求体；字段顺序即 JSON 字节
// 序（参与签名），Channel 固定 OSS_UPLOAD，作用域限定到单个桶。
type tmpTokenRequest struct {
	Channel string   `json:"channel"`
	Scopes  []string `json:"scopes"`
}

// tmpTokenBucket 是响应 data.Buckets 的一项。
type tmpTokenBucket struct {
	S3Bucket   string `json:"s3Bucket"`
	S3Endpoint string `json:"s3Endpoint"`
}

// tmpTokenResponse 是 /auth/tmp_token.json 的响应外层结构。
type tmpTokenResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Credentials tmpTokenCredentials `json:"Credentials"`
		Buckets     []tmpTokenBucket    `json:"Buckets"`
	} `json:"data"`
}

// tmpTokenCredentials 兼容两种字段风格：AWS STS 大写开头
// （AccessKeyId/SecretAccessKey/SessionToken）与小写开头
// （accessKeyId/secretAccessKey/sessionToken）。
type tmpTokenCredentials struct {
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
}

// UnmarshalJSON 先按 AWS STS 大写字段风格解析，全空时回退小写开头风格。
func (tc *tmpTokenCredentials) UnmarshalJSON(data []byte) error {
	var upper struct {
		AccessKeyId     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		SessionToken    string `json:"SessionToken"`
	}
	if err := json.Unmarshal(data, &upper); err != nil {
		return err
	}
	if upper.AccessKeyId != "" || upper.SecretAccessKey != "" || upper.SessionToken != "" {
		tc.AccessKeyId, tc.SecretAccessKey, tc.SessionToken =
			upper.AccessKeyId, upper.SecretAccessKey, upper.SessionToken
		return nil
	}
	var lower struct {
		AccessKeyId     string `json:"accessKeyId"`
		SecretAccessKey string `json:"secretAccessKey"`
		SessionToken    string `json:"sessionToken"`
	}
	if err := json.Unmarshal(data, &lower); err != nil {
		return err
	}
	tc.AccessKeyId, tc.SecretAccessKey, tc.SessionToken =
		lower.AccessKeyId, lower.SecretAccessKey, lower.SessionToken
	return nil
}

// fetchTmpToken 换取一次临时密钥：POST {APIBaseURL}/auth/tmp_token.json，
// 请求体 {"channel":"OSS_UPLOAD","scopes":["<Bucket>:*"]}，头
// Authorization: TOKEN AccessKey:hex(HMAC-SHA1(SecretKey, path+"\n"+body))。
// code != 200 或 HTTP 非 2xx、凭据/桶信息缺失均返回明确错误。
func (c *Client) fetchTmpToken(ctx context.Context) (ossCredentials, error) {
	if err := c.validateConfig(); err != nil {
		return ossCredentials{}, err
	}
	payload, err := json.Marshal(tmpTokenRequest{
		Channel: tmpTokenChannel,
		Scopes:  []string{c.cfg.Bucket + ":*"},
	})
	if err != nil {
		return ossCredentials{}, fmt.Errorf("dogecloud: 构造临时密钥请求体失败: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.APIBaseURL+tmpTokenPath, bytes.NewReader(payload))
	if err != nil {
		return ossCredentials{}, fmt.Errorf("dogecloud: 构造临时密钥请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "TOKEN "+c.cfg.AccessKey+":"+
		hex.EncodeToString(hmacSHA1Hex([]byte(c.cfg.SecretKey), tmpTokenPath+"\n"+string(payload))))

	resp, err := c.hc.Do(req)
	if err != nil {
		return ossCredentials{}, fmt.Errorf("dogecloud: 请求临时密钥失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := readLimited(resp.Body, tmpTokenRespLimit)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// 尽力提取业务 code/msg 供运维排障；解析失败不影响按 HTTP 状态码报错。
		var biz struct {
			Code int    `json:"code"`
			Msg  string `json:"msg"`
		}
		_ = json.Unmarshal(body, &biz)
		if biz.Code != 0 || biz.Msg != "" {
			return ossCredentials{}, fmt.Errorf("dogecloud: 获取临时密钥失败: HTTP %d, code=%d, msg=%q",
				resp.StatusCode, biz.Code, biz.Msg)
		}
		return ossCredentials{}, fmt.Errorf("dogecloud: 获取临时密钥失败: HTTP %d", resp.StatusCode)
	}

	var parsed tmpTokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ossCredentials{}, fmt.Errorf("dogecloud: 解析临时密钥响应失败: %w", err)
	}
	if parsed.Code != tmpTokenOKCode {
		return ossCredentials{}, fmt.Errorf("dogecloud: 获取临时密钥失败: code=%d, msg=%q", parsed.Code, parsed.Msg)
	}
	creds := parsed.Data.Credentials
	if creds.AccessKeyId == "" || creds.SecretAccessKey == "" {
		return ossCredentials{}, fmt.Errorf("dogecloud: 临时密钥响应缺少 AccessKeyId/SecretAccessKey")
	}
	if len(parsed.Data.Buckets) == 0 {
		return ossCredentials{}, fmt.Errorf("dogecloud: 临时密钥响应未返回任何存储桶（Buckets 为空）")
	}
	bucket := parsed.Data.Buckets[0]
	if bucket.S3Bucket == "" || bucket.S3Endpoint == "" {
		return ossCredentials{}, fmt.Errorf("dogecloud: 临时密钥响应的 Buckets[0] 缺少 s3Bucket/s3Endpoint")
	}
	scheme, host, err := parseS3Endpoint(bucket.S3Endpoint)
	if err != nil {
		return ossCredentials{}, err
	}
	return ossCredentials{
		accessKey:    creds.AccessKeyId,
		secretKey:    creds.SecretAccessKey,
		sessionToken: creds.SessionToken,
		target:       ossTarget{bucket: bucket.S3Bucket, scheme: scheme, host: host},
	}, nil
}

// parseS3Endpoint 解析 s3Endpoint 为 (scheme, host)。无协议前缀时按
// https 处理；仅接受 http/https，其余协议拒绝。
func parseS3Endpoint(endpoint string) (scheme, host string, err error) {
	ep := strings.TrimSpace(endpoint)
	if ep == "" {
		return "", "", fmt.Errorf("dogecloud: s3Endpoint 为空")
	}
	if !strings.Contains(ep, "://") {
		ep = "https://" + ep
	}
	u, perr := url.Parse(ep)
	if perr != nil || u.Host == "" {
		return "", "", fmt.Errorf("dogecloud: 解析 s3Endpoint %q 失败", endpoint)
	}
	scheme = "https"
	if u.Scheme == "http" {
		scheme = "http"
	}
	return scheme, u.Host, nil
}

// hmacSHA1Hex 返回 hex(HMAC-SHA1(key, s))，多吉云 API 请求签名专用。
func hmacSHA1Hex(key []byte, s string) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write([]byte(s))
	return mac.Sum(nil)
}

// readLimited 最多读取 max 字节（读取错误时返回已读部分）。
func readLimited(r io.Reader, max int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, max))
}

// previewText 把错误响应体预览转为字符串并去除首尾空白。
func previewText(b []byte) string {
	return strings.TrimSpace(string(b))
}
