package dogecloud

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 测试固定凭据与配置。
const (
	testAK        = "ak-test-123"
	testSK        = "sk-test-456"
	testBucket    = "e3-reports-bucket"
	testPrefix    = "e3-reports/"
	testPublicB   = "https://img-host.modenc.top"
	testPayload   = "PNGDATA-test-body"
	testTokenBody = `{"channel":"OSS_UPLOAD","scopes":["e3-reports-bucket:*"]}`
)

// golden 期望值：按算法独立手算（Go/Python 双实现交叉验证）后写死。
const (
	// wantTokenAuthorization = "TOKEN " + AK + ":" + hex(HMAC-SHA1(SK, "/auth/tmp_token.json\n"+body))
	wantTokenAuthorization = "TOKEN ak-test-123:554daa25c07ad9f928fb7b6703036c4c1a89eebb"
	// wantPayloadHash = hex(SHA-256(testPayload))
	wantPayloadHash = "f5c85c8ca81a6305e33bafed3a849471f7371982c45bc4aa3841557560f4ca68"
	// SigV4 PUT golden：固定临时凭据 + amzDate 20261022T080910Z + host
	// e3-bucket.s3.example.test + key e3-reports/daily/20261022-00ff00ff00ff00ff.png。
	wantPutAuthWithToken = "AWS4-HMAC-SHA256 Credential=STS_TEST_AK/20261022/auto/s3/aws4_request, " +
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, " +
		"Signature=c9e8d43ce37b9488a258492fca4a4befdbe3ab9b659e024f04436df14c002f8b"
	wantPutAuthNoToken = "AWS4-HMAC-SHA256 Credential=STS_TEST_AK/20261022/auto/s3/aws4_request, " +
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date, " +
		"Signature=8538e6bc974a9d42f30d5551bd6d36c350aa88806471253f486fd7cc02433a1d"
	// AWS 官方文档（SigV4 签名示例：GET iam.amazonaws.com）的完整
	// Authorization 期望值，作为签名链的公开权威向量。
	wantAWSVectorAuth = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-date, " +
		"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
)

var fixedTestNow = time.Date(2026, 10, 22, 8, 9, 10, 0, time.UTC)

// fixClock 固定时钟（nowFn 注入），测试结束自动恢复；本包测试不并行。
func fixClock(t *testing.T, tv time.Time) {
	t.Helper()
	old := nowFn
	nowFn = func() time.Time { return tv }
	t.Cleanup(func() { nowFn = old })
}

// --- 测试用假服务端与 transport ---

// fakeAPI 记录多吉云 API 侧收到的请求（Authorization 与请求体逐条保存）。
type fakeAPI struct {
	*httptest.Server
	hits atomic.Int32
	mu   sync.Mutex
	auth []string
	body []string
}

func startFakeAPI(t *testing.T, status int, respBody string) *fakeAPI {
	t.Helper()
	api := &fakeAPI{}
	api.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		api.hits.Add(1)
		api.mu.Lock()
		api.auth = append(api.auth, r.Header.Get("Authorization"))
		api.body = append(api.body, string(b))
		api.mu.Unlock()
		w.WriteHeader(status)
		fmt.Fprint(w, respBody)
	}))
	t.Cleanup(api.Close)
	return api
}

func (api *fakeAPI) snapshot() (auth, body []string) {
	api.mu.Lock()
	defer api.mu.Unlock()
	outA, outB := make([]string, len(api.auth)), make([]string, len(api.body))
	copy(outA, api.auth)
	copy(outB, api.body)
	return outA, outB
}

// tokenRespUpper/Lower 构造两种字段风格的成功临时密钥响应，s3Endpoint 指向 s3。
func tokenRespUpper(s3Endpoint string) string {
	return fmt.Sprintf(`{"code":200,"msg":"ok","data":{"Credentials":{"AccessKeyId":"STS_AK_UP",`+
		`"SecretAccessKey":"STS_SK_UP","SessionToken":"STS_TK_UP"},`+
		`"Buckets":[{"s3Bucket":%q,"s3Endpoint":%q}]}}`, testBucket, s3Endpoint)
}

func tokenRespLower(s3Endpoint string) string {
	return fmt.Sprintf(`{"code":200,"msg":"ok","data":{"Credentials":{"accessKeyId":"STS_AK_LOW",`+
		`"secretAccessKey":"STS_SK_LOW","sessionToken":"STS_TK_LOW"},`+
		`"Buckets":[{"s3Bucket":%q,"s3Endpoint":%q}]}}`, testBucket, s3Endpoint)
}

// s3Record 记录一次 S3 请求的关键字段（含签名字段）。
type s3Record struct {
	method, host, path, rawQuery string
	auth, amzDate, contentSHA    string
	contentType, securityToken   string
	body                         []byte
}

// fakeS3 记录 S3 侧收到的全部请求，behavior 决定响应。
type fakeS3 struct {
	*httptest.Server
	mu       sync.Mutex
	requests []s3Record
}

func startFakeS3(t *testing.T, behavior func(rec s3Record) (int, string)) *fakeS3 {
	t.Helper()
	s3 := &fakeS3{}
	s3.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rec := s3Record{
			method:        r.Method,
			host:          r.Host,
			path:          r.URL.EscapedPath(),
			rawQuery:      r.URL.RawQuery,
			auth:          r.Header.Get("Authorization"),
			amzDate:       r.Header.Get("x-amz-date"),
			contentSHA:    r.Header.Get("x-amz-content-sha256"),
			contentType:   r.Header.Get("Content-Type"),
			securityToken: r.Header.Get("x-amz-security-token"),
			body:          b,
		}
		s3.mu.Lock()
		s3.requests = append(s3.requests, rec)
		s3.mu.Unlock()
		status, respBody := behavior(rec)
		w.WriteHeader(status)
		fmt.Fprint(w, respBody)
	}))
	t.Cleanup(s3.Close)
	return s3
}

func (s3 *fakeS3) snapshot() []s3Record {
	s3.mu.Lock()
	defer s3.mu.Unlock()
	out := make([]s3Record, len(s3.requests))
	copy(out, s3.requests)
	return out
}

// vhostTransport 把 virtual-host 风格（{bucket}.{s3host}）的请求重定向到
// 假 S3 服务器，同时保留原 Host 头；其余请求（如假 API）原样放行。
type vhostTransport struct{ target *url.URL }

func (vt vhostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Host, "."+vt.target.Host) {
		u := *req.URL
		u.Scheme = vt.target.Scheme
		u.Host = vt.target.Host
		r2 := req.Clone(req.Context())
		r2.URL = &u
		r2.Host = req.URL.Host
		return http.DefaultTransport.RoundTrip(r2)
	}
	return http.DefaultTransport.RoundTrip(req)
}

func hostOf(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	return u.Host
}

// newTestClient 构造指向假 API 与假 S3 的客户端；mutate 允许微调 Config。
func newTestClient(t *testing.T, apiURL string, s3 *fakeS3, mutate func(*Config)) *Client {
	t.Helper()
	cfg := Config{
		AccessKey:     testAK,
		SecretKey:     testSK,
		Bucket:        testBucket,
		PublicBaseURL: testPublicB + "/", // 故意带尾斜杠，验证 TrimRight
		KeyPrefix:     testPrefix,
		APIBaseURL:    apiURL,
		RetentionDays: 30,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	target, err := url.Parse(s3.URL)
	if err != nil {
		t.Fatalf("parse s3 url: %v", err)
	}
	return New(cfg, &http.Client{Transport: vhostTransport{target: target}})
}

// --- 1. HMAC-SHA1 临时密钥签名 golden ---

func TestTokenAuthorizationGolden(t *testing.T) {
	api := startFakeAPI(t, http.StatusOK, tokenRespUpper("https://s3.example.test"))
	c := New(Config{AccessKey: testAK, SecretKey: testSK, Bucket: testBucket, APIBaseURL: api.URL}, nil)

	if err := c.FetchTmpToken(context.Background()); err != nil {
		t.Fatalf("FetchTmpToken() error = %v, want nil", err)
	}
	auth, bodies := api.snapshot()
	if got := api.hits.Load(); got != 1 {
		t.Fatalf("API request count = %d, want 1", got)
	}
	if len(auth) != 1 || auth[0] != wantTokenAuthorization {
		t.Errorf("Authorization = %v, want [%s]", auth, wantTokenAuthorization)
	}
	if len(bodies) != 1 || bodies[0] != testTokenBody {
		t.Errorf("request body = %q, want %q", bodies, testTokenBody)
	}
}

// --- 2. tmp_token 解析：两种字段风格与各类失败 ---

func TestFetchTmpTokenParsesBothCredentialStyles(t *testing.T) {
	cases := []struct {
		name      string
		resp      string
		wantAK    string
		wantSK    string
		wantToken string
	}{
		{"upper-aws-sts-style", tokenRespUpper("https://s3.example.test"), "STS_AK_UP", "STS_SK_UP", "STS_TK_UP"},
		{"lower-camel-style", tokenRespLower("https://s3.example.test"), "STS_AK_LOW", "STS_SK_LOW", "STS_TK_LOW"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := startFakeAPI(t, http.StatusOK, tc.resp)
			c := New(Config{AccessKey: testAK, SecretKey: testSK, Bucket: testBucket, APIBaseURL: api.URL}, nil)

			creds, err := c.fetchTmpToken(context.Background())
			if err != nil {
				t.Fatalf("fetchTmpToken() error = %v, want nil", err)
			}
			if creds.accessKey != tc.wantAK || creds.secretKey != tc.wantSK || creds.sessionToken != tc.wantToken {
				t.Errorf("credentials = (%q, %q, %q), want (%q, %q, %q)",
					creds.accessKey, creds.secretKey, creds.sessionToken, tc.wantAK, tc.wantSK, tc.wantToken)
			}
			if creds.target.bucket != testBucket {
				t.Errorf("target.bucket = %q, want %q", creds.target.bucket, testBucket)
			}
			if creds.target.host != "s3.example.test" || creds.target.scheme != "https" {
				t.Errorf("target = (%q, %q), want (s3.example.test, https)", creds.target.scheme, creds.target.host)
			}
		})
	}
}

func TestFetchTmpTokenErrors(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		resp      string
		wantParts []string
	}{
		{"biz-code-not-200", http.StatusOK,
			`{"code":401,"msg":"invalid credential"}`,
			[]string{"code=401", "invalid credential"}},
		{"http-500", http.StatusInternalServerError,
			`{"code":500,"msg":"internal error"}`,
			[]string{"HTTP 500", "code=500"}},
		{"buckets-empty", http.StatusOK,
			`{"code":200,"data":{"Credentials":{"AccessKeyId":"a","SecretAccessKey":"s"},"Buckets":[]}}`,
			[]string{"Buckets"}},
		{"bucket-missing-endpoint", http.StatusOK,
			`{"code":200,"data":{"Credentials":{"AccessKeyId":"a","SecretAccessKey":"s"},"Buckets":[{"s3Bucket":"x"}]}}`,
			[]string{"s3Bucket/s3Endpoint"}},
		{"missing-credentials", http.StatusOK,
			`{"code":200,"data":{"Credentials":{},"Buckets":[{"s3Bucket":"x","s3Endpoint":"https://s3"}]}}`,
			[]string{"AccessKeyId/SecretAccessKey"}},
		{"bad-json", http.StatusOK, `not-json`, []string{"解析临时密钥响应"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := startFakeAPI(t, tc.status, tc.resp)
			c := New(Config{AccessKey: testAK, SecretKey: testSK, Bucket: testBucket, APIBaseURL: api.URL}, nil)

			_, err := c.fetchTmpToken(context.Background())
			if err == nil {
				t.Fatal("fetchTmpToken() error = nil, want error")
			}
			for _, part := range tc.wantParts {
				if !strings.Contains(err.Error(), part) {
					t.Errorf("error %q does not contain %q", err, part)
				}
			}
			if strings.Contains(err.Error(), testSK) {
				t.Errorf("error %q leaks SecretKey", err)
			}
		})
	}
}

func TestParseS3Endpoint(t *testing.T) {
	cases := []struct {
		endpoint   string
		wantScheme string
		wantHost   string
		wantErr    bool
	}{
		{"https://s3.dogecloud.com", "https", "s3.dogecloud.com", false},
		{"http://127.0.0.1:9000", "http", "127.0.0.1:9000", false},
		{"s3.example.test", "https", "s3.example.test", false},
		{"https://s3.dogecloud.com/path", "https", "s3.dogecloud.com", false},
		{"", "", "", true},
	}
	for _, tc := range cases {
		scheme, host, err := parseS3Endpoint(tc.endpoint)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseS3Endpoint(%q) error = nil, want error", tc.endpoint)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseS3Endpoint(%q) error = %v", tc.endpoint, err)
			continue
		}
		if scheme != tc.wantScheme || host != tc.wantHost {
			t.Errorf("parseS3Endpoint(%q) = (%q, %q), want (%q, %q)",
				tc.endpoint, scheme, host, tc.wantScheme, tc.wantHost)
		}
	}
}

// --- 3. SigV4 golden：AWS 官方公开向量 + 本包 S3 PUT 场景 ---

func TestSigV4AWSDocumentedVector(t *testing.T) {
	auth := sigv4Sign(
		"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "AKIDEXAMPLE",
		"us-east-1", "iam", "GET", "/", "Action=ListUsers&Version=2010-05-08",
		[]sigHeader{
			{"content-type", "application/x-www-form-urlencoded; charset=utf-8"},
			{"host", "iam.amazonaws.com"},
			{"x-amz-date", "20150830T123600Z"},
		},
		sha256Hex(nil), "20150830T123600Z")
	if auth != wantAWSVectorAuth {
		t.Errorf("Authorization =\n%s\nwant\n%s", auth, wantAWSVectorAuth)
	}
}

func TestSigV4PutGolden(t *testing.T) {
	payloadHash := sha256Hex([]byte(testPayload))
	if payloadHash != wantPayloadHash {
		t.Fatalf("sha256Hex(payload) = %s, want golden %s", payloadHash, wantPayloadHash)
	}
	const (
		amzDate = "20261022T080910Z"
		host    = "e3-bucket.s3.example.test"
		keyPath = "/e3-reports/daily/20261022-00ff00ff00ff00ff.png"
	)
	withToken := ossCredentials{accessKey: "STS_TEST_AK", secretKey: "STS_TEST_SK", sessionToken: "STS_TEST_TOKEN"}
	if got := sigv4Authorization(withToken, s3Region, s3Service, "PUT", keyPath, "", host, payloadHash, amzDate); got != wantPutAuthWithToken {
		t.Errorf("with-token Authorization =\n%s\nwant\n%s", got, wantPutAuthWithToken)
	}
	noToken := ossCredentials{accessKey: "STS_TEST_AK", secretKey: "STS_TEST_SK"}
	if got := sigv4Authorization(noToken, s3Region, s3Service, "PUT", keyPath, "", host, payloadHash, amzDate); got != wantPutAuthNoToken {
		t.Errorf("no-token Authorization =\n%s\nwant\n%s", got, wantPutAuthNoToken)
	}
}

// --- 4. 假 API + 假 S3 全链路 Upload ---

func TestUploadFullChainSuccess(t *testing.T) {
	fixClock(t, fixedTestNow)
	s3 := startFakeS3(t, func(rec s3Record) (int, string) { return http.StatusOK, "" })
	api := startFakeAPI(t, http.StatusOK, tokenRespUpper(s3.URL))
	c := newTestClient(t, api.URL, s3, nil)

	key := "e3-reports/daily/20260101-aabbccdd.png"
	publicURL, err := c.Upload(context.Background(), key, []byte(testPayload), "image/png")
	if err != nil {
		t.Fatalf("Upload() error = %v, want nil", err)
	}
	if want := testPublicB + "/" + key; publicURL != want {
		t.Errorf("publicURL = %q, want %q", publicURL, want)
	}

	// API 侧：Authorization golden（token 签名与时间无关）与请求体字节。
	auth, bodies := api.snapshot()
	if got := api.hits.Load(); got != 1 {
		t.Fatalf("API request count = %d, want 1", got)
	}
	if len(auth) != 1 || auth[0] != wantTokenAuthorization {
		t.Errorf("API Authorization = %v, want [%s]", auth, wantTokenAuthorization)
	}
	if len(bodies) != 1 || bodies[0] != testTokenBody {
		t.Errorf("API body = %q, want %q", bodies, testTokenBody)
	}

	// S3 侧：virtual-host、path、签名字段、Content-Type 与正文。
	reqs := s3.snapshot()
	if len(reqs) != 1 {
		t.Fatalf("S3 request count = %d, want 1", len(reqs))
	}
	rec := reqs[0]
	if rec.method != http.MethodPut {
		t.Errorf("S3 method = %q, want PUT", rec.method)
	}
	if wantHost := testBucket + "." + hostOf(t, s3.URL); rec.host != wantHost {
		t.Errorf("S3 Host = %q, want %q (virtual-host style)", rec.host, wantHost)
	}
	if rec.path != "/"+key {
		t.Errorf("S3 path = %q, want %q", rec.path, "/"+key)
	}
	wantAuthPrefix := "AWS4-HMAC-SHA256 Credential=STS_AK_UP/20261022/auto/s3/aws4_request, " +
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature="
	if !strings.HasPrefix(rec.auth, wantAuthPrefix) {
		t.Errorf("S3 Authorization = %q, want prefix %q", rec.auth, wantAuthPrefix)
	} else if sig := strings.TrimPrefix(rec.auth, wantAuthPrefix); !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(sig) {
		t.Errorf("S3 signature = %q, want 64 lowercase hex chars", sig)
	}
	if rec.amzDate != "20261022T080910Z" {
		t.Errorf("x-amz-date = %q, want 20261022T080910Z (UTC)", rec.amzDate)
	}
	if rec.contentSHA != wantPayloadHash {
		t.Errorf("x-amz-content-sha256 = %q, want %q", rec.contentSHA, wantPayloadHash)
	}
	if rec.securityToken != "STS_TK_UP" {
		t.Errorf("x-amz-security-token = %q, want STS_TK_UP", rec.securityToken)
	}
	if rec.contentType != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", rec.contentType)
	}
	if string(rec.body) != testPayload {
		t.Errorf("S3 body = %q, want %q", rec.body, testPayload)
	}

	// 每次调用现换临时密钥：第二次 Upload 应再次请求 tmp_token。
	if _, err := c.Upload(context.Background(), key, []byte(testPayload), "image/png"); err != nil {
		t.Fatalf("second Upload() error = %v, want nil", err)
	}
	if got := api.hits.Load(); got != 2 {
		t.Errorf("API request count after 2 uploads = %d, want 2 (no credential caching)", got)
	}
	if got := len(s3.snapshot()); got != 2 {
		t.Errorf("S3 request count after 2 uploads = %d, want 2", got)
	}
}

func TestUploadAPIError(t *testing.T) {
	s3 := startFakeS3(t, func(rec s3Record) (int, string) { return http.StatusOK, "" })
	api := startFakeAPI(t, http.StatusInternalServerError, `{"code":500,"msg":"internal error"}`)
	c := newTestClient(t, api.URL, s3, nil)

	publicURL, err := c.Upload(context.Background(), "e3-reports/daily/x.png", []byte("d"), "image/png")
	if err == nil {
		t.Fatal("Upload() error = nil, want error")
	}
	for _, part := range []string{"HTTP 500", "code=500"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("error %q does not contain %q", err, part)
		}
	}
	if publicURL != "" {
		t.Errorf("publicURL = %q, want empty", publicURL)
	}
	if got := len(s3.snapshot()); got != 0 {
		t.Errorf("S3 request count = %d, want 0", got)
	}
}

func TestUploadS3Forbidden(t *testing.T) {
	s3 := startFakeS3(t, func(rec s3Record) (int, string) {
		return http.StatusForbidden, "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"
	})
	api := startFakeAPI(t, http.StatusOK, tokenRespLower(s3.URL))
	c := newTestClient(t, api.URL, s3, nil)

	publicURL, err := c.Upload(context.Background(), "e3-reports/daily/x.png", []byte("d"), "image/png")
	if err == nil {
		t.Fatal("Upload() error = nil, want error")
	}
	for _, part := range []string{"403", "AccessDenied"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("error %q does not contain %q", err, part)
		}
	}
	if publicURL != "" {
		t.Errorf("publicURL = %q, want empty", publicURL)
	}
}

// --- 5. LIST XML 解析与 Prune ---

const listPage1XML = `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult Name="e3-reports-bucket" Prefix="e3-reports/">
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>tok-2</NextContinuationToken>
  <Contents>
    <Key>e3-reports/old/a.png</Key>
    <LastModified>2026-09-01T00:00:00Z</LastModified>
  </Contents>
  <Contents>
    <Key>e3-reports/new/b.png</Key>
    <LastModified>2026-10-21T00:00:00.000Z</LastModified>
  </Contents>
  <Contents>
    <Key>e3-reports/weird/x.png</Key>
    <LastModified>not-a-timestamp</LastModified>
  </Contents>
</ListBucketResult>`

const listPage2XML = `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult Name="e3-reports-bucket" Prefix="e3-reports/">
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>e3-reports/old/c.png</Key>
    <LastModified>2026-08-15T00:00:00Z</LastModified>
  </Contents>
  <Contents>
    <Key>e3-reports/deny/d.png</Key>
    <LastModified>2026-09-10T00:00:00Z</LastModified>
  </Contents>
  <Contents>
    <Key>e3-reports/old/e.png</Key>
    <LastModified>2026-08-20T00:00:00Z</LastModified>
  </Contents>
</ListBucketResult>`

func TestParseListXML(t *testing.T) {
	objs, truncated, next, err := parseListXML([]byte(listPage1XML))
	if err != nil {
		t.Fatalf("parseListXML() error = %v", err)
	}
	if !truncated || next != "tok-2" {
		t.Errorf("truncated=%v next=%q, want true tok-2", truncated, next)
	}
	if len(objs) != 3 {
		t.Fatalf("objects = %d, want 3", len(objs))
	}
	wantTimes := []struct {
		key    string
		want   time.Time
		wantOK bool
	}{
		{"e3-reports/old/a.png", time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), true},
		{"e3-reports/new/b.png", time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC), true}, // 带毫秒仍可解析
		{"e3-reports/weird/x.png", time.Time{}, false},
	}
	for i, w := range wantTimes {
		if objs[i].Key != w.key {
			t.Errorf("objs[%d].Key = %q, want %q", i, objs[i].Key, w.key)
		}
		if objs[i].modTimeOK != w.wantOK {
			t.Errorf("objs[%d].modTimeOK = %v, want %v", i, objs[i].modTimeOK, w.wantOK)
		}
		if w.wantOK && !objs[i].LastModified.Equal(w.want) {
			t.Errorf("objs[%d].LastModified = %v, want %v", i, objs[i].LastModified, w.want)
		}
	}

	if _, _, _, err := parseListXML([]byte("not-xml")); err == nil {
		t.Error("parseListXML(bad xml) error = nil, want error")
	}
}

func TestPruneDeletesExpiredKeepsFresh(t *testing.T) {
	fixClock(t, fixedTestNow) // now=2026-10-22T08:09:10Z，RetentionDays=30 → cutoff=2026-09-22
	s3 := startFakeS3(t, func(rec s3Record) (int, string) {
		switch rec.method {
		case http.MethodGet:
			switch continuationTokenOf(rec.rawQuery) {
			case "":
				return http.StatusOK, listPage1XML
			case "tok-2":
				return http.StatusOK, listPage2XML
			}
			return http.StatusInternalServerError, "unexpected continuation token"
		case http.MethodDelete:
			if strings.Contains(rec.path, "/deny/") {
				return http.StatusForbidden, "<Error><Code>AccessDenied</Code></Error>"
			}
			return http.StatusNoContent, ""
		}
		return http.StatusMethodNotAllowed, ""
	})
	api := startFakeAPI(t, http.StatusOK, tokenRespLower(s3.URL))
	c := newTestClient(t, api.URL, s3, nil)

	deleted, err := c.Prune(context.Background())
	if deleted != 3 {
		t.Errorf("Prune() deleted = %d, want 3 (a/c/e)", deleted)
	}
	if err == nil {
		t.Fatal("Prune() err = nil, want first delete error (deny/d.png)")
	}
	for _, part := range []string{"deny/d.png", "403"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("error %q does not contain %q", err, part)
		}
	}

	reqs := s3.snapshot()
	var gets, deletes []s3Record
	for _, rec := range reqs {
		switch rec.method {
		case http.MethodGet:
			gets = append(gets, rec)
		case http.MethodDelete:
			deletes = append(deletes, rec)
		}
	}
	// 分页两页合并：两次 LIST，canonical query 按参数名排序、prefix 编码。
	wantQueries := []string{
		"list-type=2&max-keys=1000&prefix=e3-reports%2F",
		"continuation-token=tok-2&list-type=2&max-keys=1000&prefix=e3-reports%2F",
	}
	if len(gets) != len(wantQueries) {
		t.Fatalf("LIST count = %d, want %d", len(gets), len(wantQueries))
	}
	for i, want := range wantQueries {
		if gets[i].rawQuery != want {
			t.Errorf("LIST[%d] query = %q, want %q", i, gets[i].rawQuery, want)
		}
		if gets[i].path != "/" {
			t.Errorf("LIST[%d] path = %q, want /", i, gets[i].path)
		}
	}
	// 删除顺序即 LIST 顺序：跳过未过期(b)与时间未知(weird/x)的对象，
	// deny/d.png 失败后继续删 e.png。
	wantDeletes := []string{
		"/e3-reports/old/a.png",
		"/e3-reports/old/c.png",
		"/e3-reports/deny/d.png",
		"/e3-reports/old/e.png",
	}
	if len(deletes) != len(wantDeletes) {
		t.Fatalf("DELETE count = %d, want %d", len(deletes), len(wantDeletes))
	}
	emptyHash := func() string { sum := sha256.Sum256(nil); return hex.EncodeToString(sum[:]) }()
	for i, want := range wantDeletes {
		if deletes[i].path != want {
			t.Errorf("DELETE[%d] path = %q, want %q", i, deletes[i].path, want)
		}
		if deletes[i].contentSHA != emptyHash {
			t.Errorf("DELETE[%d] x-amz-content-sha256 = %q, want empty-body hash", i, deletes[i].contentSHA)
		}
		if !strings.HasPrefix(deletes[i].auth, "AWS4-HMAC-SHA256 Credential=STS_AK_LOW/") {
			t.Errorf("DELETE[%d] Authorization = %q, want lower-style temp credentials", i, deletes[i].auth)
		}
	}
	// 单次 Prune 只换取一次临时密钥。
	if got := api.hits.Load(); got != 1 {
		t.Errorf("API request count = %d, want 1", got)
	}
}

// continuationTokenOf 从原始查询串提取 continuation-token；解析失败按首页
// 语义返回空串（假服务端处理器运行在非测试 goroutine，不得调用 t.Fatal*，
// 异常最终会体现在断言上）。
func continuationTokenOf(rawQuery string) string {
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return ""
	}
	return q.Get("continuation-token")
}

func TestPruneDisabledNoOp(t *testing.T) {
	s3 := startFakeS3(t, func(rec s3Record) (int, string) { return http.StatusOK, listPage1XML })
	api := startFakeAPI(t, http.StatusOK, tokenRespUpper(s3.URL))
	c := newTestClient(t, api.URL, s3, func(cfg *Config) { cfg.RetentionDays = 0 })

	deleted, err := c.Prune(context.Background())
	if deleted != 0 || err != nil {
		t.Errorf("Prune() = (%d, %v), want (0, nil) when retention disabled", deleted, err)
	}
	if got := api.hits.Load(); got != 0 {
		t.Errorf("API request count = %d, want 0", got)
	}
	if got := len(s3.snapshot()); got != 0 {
		t.Errorf("S3 request count = %d, want 0", got)
	}
}

func TestPruneListFailure(t *testing.T) {
	s3 := startFakeS3(t, func(rec s3Record) (int, string) {
		return http.StatusInternalServerError, "list boom"
	})
	api := startFakeAPI(t, http.StatusOK, tokenRespUpper(s3.URL))
	c := newTestClient(t, api.URL, s3, nil)

	deleted, err := c.Prune(context.Background())
	if deleted != 0 || err == nil {
		t.Fatalf("Prune() = (%d, %v), want (0, error)", deleted, err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q does not contain HTTP status", err)
	}
	if got := len(s3.snapshot()); got != 1 {
		t.Errorf("S3 request count = %d, want 1 (only LIST attempted)", got)
	}
}

// --- 6. NewKey 格式 ---

func TestNewKeyFormat(t *testing.T) {
	since := fixedTestNow
	pattern := regexp.MustCompile(`^e3-reports/daily/20261022-[0-9a-f]{16}\.png$`)
	c := New(Config{KeyPrefix: "e3-reports/"}, nil)
	first := c.NewKey("daily", since)
	if !pattern.MatchString(first) {
		t.Errorf("NewKey() = %q, want match %s", first, pattern)
	}
	second := c.NewKey("daily", since)
	if first == second {
		t.Error("two NewKey() calls returned the same key, random segment must differ")
	}
	// 前缀规范化：无尾斜杠自动补齐；空前缀保持为空。
	if got := New(Config{KeyPrefix: "e3-reports"}, nil).NewKey("daily", since); !strings.HasPrefix(got, "e3-reports/daily/") {
		t.Errorf("NewKey() = %q, want prefix e3-reports/daily/", got)
	}
	if got := New(Config{}, nil).NewKey("daily", since); !strings.HasPrefix(got, "daily/") {
		t.Errorf("NewKey() = %q, want prefix daily/ (empty KeyPrefix)", got)
	}
}

// --- 7. 前置校验与安全红线 ---

func TestConfigValidationErrors(t *testing.T) {
	s3 := startFakeS3(t, func(rec s3Record) (int, string) { return http.StatusOK, "" })
	api := startFakeAPI(t, http.StatusOK, tokenRespUpper(s3.URL))
	c := New(Config{APIBaseURL: api.URL, RetentionDays: 30}, nil)

	ctx := context.Background()
	ops := map[string]func() error{
		"FetchTmpToken": func() error { return c.FetchTmpToken(ctx) },
		"Upload":        func() error { _, err := c.Upload(ctx, "k.png", []byte("d"), ""); return err },
		"Prune":         func() error { _, err := c.Prune(ctx); return err },
	}
	for name, op := range ops {
		err := op()
		if err == nil {
			t.Errorf("%s: error = nil, want validation error", name)
			continue
		}
		for _, field := range []string{"AccessKey", "SecretKey", "Bucket"} {
			if !strings.Contains(err.Error(), field) {
				t.Errorf("%s: error %q does not mention %s", name, err, field)
			}
		}
	}
	if got := api.hits.Load(); got != 0 {
		t.Errorf("API request count = %d, want 0 (reject before any request)", got)
	}
	if got := len(s3.snapshot()); got != 0 {
		t.Errorf("S3 request count = %d, want 0", got)
	}
}

func TestUploadInvalidKeyRejected(t *testing.T) {
	s3 := startFakeS3(t, func(rec s3Record) (int, string) { return http.StatusOK, "" })
	api := startFakeAPI(t, http.StatusOK, tokenRespUpper(s3.URL))
	c := newTestClient(t, api.URL, s3, nil)

	for _, key := range []string{"", "a?b", "a#b", "e3-reports/日报.png"} {
		_, err := c.Upload(context.Background(), key, []byte("d"), "image/png")
		if err == nil {
			t.Errorf("key %q: error = nil, want reject", key)
		}
	}
	if got := api.hits.Load(); got != 0 {
		t.Errorf("API request count = %d, want 0 (key rejected before token fetch)", got)
	}
	if got := len(s3.snapshot()); got != 0 {
		t.Errorf("S3 request count = %d, want 0", got)
	}
}

func TestValidateKey(t *testing.T) {
	cases := []struct {
		key     string
		wantErr bool
	}{
		{"e3-reports/daily/20260101-0011223344556677.png", false},
		{"a.png", false},
		{"a b.png", false}, // 空格为 ASCII，放行（URL 编码处理）
		{"", true},
		{"?a", true},
		{"a#b", true},
		{"e3-reports/图表.png", true},
	}
	for _, tc := range cases {
		err := validateKey(tc.key)
		if tc.wantErr && err == nil {
			t.Errorf("validateKey(%q) = nil, want error", tc.key)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("validateKey(%q) = %v, want nil", tc.key, err)
		}
	}
}

// TestErrorsDoNotLeakSecrets 汇总各错误路径，断言任何错误文本不出现
// SecretKey、临时凭据密钥/令牌值或 Authorization 头内容。
func TestErrorsDoNotLeakSecrets(t *testing.T) {
	fixClock(t, fixedTestNow)
	s3Forbid := startFakeS3(t, func(rec s3Record) (int, string) {
		if rec.method == http.MethodPut || rec.method == http.MethodDelete {
			return http.StatusForbidden, "<Error><Code>AccessDenied</Code></Error>"
		}
		return http.StatusOK, listPage1XML
	})
	apiOK := startFakeAPI(t, http.StatusOK, tokenRespUpper(s3Forbid.URL))
	apiBizErr := startFakeAPI(t, http.StatusOK, `{"code":401,"msg":"invalid credential"}`)
	apiHTTPErr := startFakeAPI(t, http.StatusInternalServerError, `{"code":500,"msg":"boom"}`)

	ctx := context.Background()
	var errs []error
	if _, err := New(Config{AccessKey: testAK, SecretKey: testSK, Bucket: testBucket,
		APIBaseURL: apiBizErr.URL}, nil).Upload(ctx, "k.png", []byte("d"), ""); err != nil {
		errs = append(errs, err)
	}
	if _, err := New(Config{AccessKey: testAK, SecretKey: testSK, Bucket: testBucket,
		APIBaseURL: apiHTTPErr.URL}, nil).Upload(ctx, "k.png", []byte("d"), ""); err != nil {
		errs = append(errs, err)
	}
	if _, err := newTestClient(t, apiOK.URL, s3Forbid, nil).Upload(ctx, "k.png", []byte("d"), ""); err != nil {
		errs = append(errs, err)
	}
	if _, err := newTestClient(t, apiOK.URL, s3Forbid, nil).Prune(ctx); err != nil {
		errs = append(errs, err)
	}

	forbidden := []string{
		testSK,
		"STS_SK_UP", "STS_TK_UP", // 临时凭据值
		"ak-test-123:", "TOKEN ak-test-123", // API Authorization 头
		"AWS4-HMAC-SHA256 Credential=", // S3 Authorization 头
	}
	if len(errs) == 0 {
		t.Fatal("no errors collected, fixture broken")
	}
	for _, err := range errs {
		for _, secret := range forbidden {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error text leaks %q: %q", secret, err)
			}
		}
	}
}
