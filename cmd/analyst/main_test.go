package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/modenc/e3-security-analyst/internal/chartimg"
	"github.com/modenc/e3-security-analyst/internal/config"
	"github.com/modenc/e3-security-analyst/internal/dogecloud"
	"github.com/modenc/e3-security-analyst/internal/query"
	"github.com/modenc/e3-security-analyst/internal/reports"
	"github.com/modenc/e3-security-analyst/internal/store"

	"github.com/modenc/e3-security-analyst/migrations"
)

// analystBin 是 TestMain 构建的一次性 e3-analyst 二进制（verify 冒烟测试用）。
var analystBin string

// TestMain 构建本包二进制，供子进程冒烟测试（与 internal/tools 相同方式）。
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "e3-analyst-test")
	if err != nil {
		fmt.Fprintf(os.Stderr, "MkdirTemp: %v\n", err)
		os.Exit(1)
	}
	bin := filepath.Join(dir, "e3-analyst")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Abs: %v\n", err)
		os.Exit(1)
	}
	build := exec.Command("go", "build", "-o", bin, "./cmd/analyst")
	build.Dir = root
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building e3-analyst failed: %v\n%s\n", err, out)
		os.Exit(1)
	}
	analystBin = bin

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// TestVerifySmokeMissingEnv：临时配置 + 缺失 NTFY_TOKEN / 日志文件 →
// 退出码 1，输出含 ✗，且绝不包含已设置环境变量的值。
func TestVerifySmokeMissingEnv(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgYAML := fmt.Sprintf(`app:
  timezone: UTC
  state_dir: %s
  log_level: info
cowrie:
  log_path: %s
database:
  path: %s
llm:
  base_url: https://api.deepseek.com
  model: deepseek-chat
  api_key_env: DEEPSEEK_API_KEY
ntfy:
  base_url: https://notify.example.com
  topic: e3verify
  token_env: NTFY_TOKEN
script_runner:
  enabled: false
`,
		filepath.ToSlash(dir),
		filepath.ToSlash(filepath.Join(dir, "cowrie", "cowrie.json")),
		filepath.ToSlash(filepath.Join(dir, "db", "events.db")))
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("写入配置失败: %v", err)
	}

	const secret = "sk-verify-secret-do-not-print-9f8e7d6c"
	cmd := exec.Command(analystBin, "verify", "--config", cfgPath)
	// 过滤可能干扰的环境变量，再注入带密值的 DEEPSEEK_API_KEY：
	// 验证输出只允许出现变量名，绝不允许出现其值。
	env := []string{}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "NTFY_TOKEN=") || strings.HasPrefix(kv, "DEEPSEEK_API_KEY=") ||
			strings.HasPrefix(kv, "E3_ANALYST_CONFIG=") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "DEEPSEEK_API_KEY="+secret)
	cmd.Env = env

	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("verify 应以退出码 1 失败，实际成功。输出:\n%s", output)
	}
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
		t.Fatalf("verify 退出码异常: %v（输出:\n%s）", err, output)
	}
	if !strings.Contains(output, "✗") {
		t.Errorf("输出应包含 ✗ 项:\n%s", output)
	}
	if !strings.Contains(output, "NTFY_TOKEN") {
		t.Errorf("输出应指出 NTFY_TOKEN 未设置:\n%s", output)
	}
	if strings.Contains(output, secret) {
		t.Errorf("输出泄露了环境变量值:\n%s", output)
	}
	// cowrie.log_path 不存在必须被点名。
	if !strings.Contains(output, "cowrie.log_path") && !strings.Contains(output, "cowrie.json") {
		t.Errorf("输出应指出日志路径不可读:\n%s", output)
	}
}

// TestRetentionSweep：daemon 保留清理 sweep 的最小端到端验证——
// retention_days=0 时不动任何数据；>0 时按服务侧入库时间老删新留。
// （24h ticker 的循环接线本身不可单测，靠该函数覆盖清理路径。）
func TestRetentionSweep(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "events.db"),
		store.Options{WAL: true, BusyTimeoutMs: 2000})
	if err != nil {
		t.Fatalf("store.Open 失败: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Migrate(migrations.FS); err != nil {
		t.Fatalf("Migrate 失败: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.Add(-100 * 24 * time.Hour)
	mk := func(raw string, at time.Time) *store.Event {
		ev := &store.Event{
			EventID: "cowrie.login.failed", EventTime: at,
			CollectedAt: at, Session: "s1", SrcIP: "198.51.100.9", Raw: raw,
		}
		return ev
	}
	if _, _, err := db.InsertEvents(ctx, []*store.Event{
		mk(`{"old":1}`, old), mk(`{"new":1}`, now),
	}); err != nil {
		t.Fatalf("InsertEvents 失败: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Default()
	env := &analystEnv{cfg: cfg, db: db}

	// 0 = 禁用：两行都在。
	cfg.App.RetentionDays = 0
	env.retentionSweep(ctx, log)
	if n, err := db.CountEvents(ctx, store.EventFilter{}); err != nil || n != 2 {
		t.Fatalf("禁用清理后 events = %d (err %v), 期望 2", n, err)
	}

	// 90 天：入库 100 天的老事件删除，新事件保留。
	cfg.App.RetentionDays = 90
	env.retentionSweep(ctx, log)
	filter := store.EventFilter{Since: now.Add(-time.Minute), Until: now.Add(time.Minute)}
	if n, err := db.CountEvents(ctx, filter); err != nil || n != 1 {
		t.Fatalf("清理后新事件应剩 1, got %d (err %v)", n, err)
	}
	oldFilter := store.EventFilter{Since: old.Add(-time.Minute), Until: old.Add(time.Minute)}
	if n, err := db.CountEvents(ctx, oldFilter); err != nil || n != 0 {
		t.Fatalf("老事件应已删除, got %d (err %v)", n, err)
	}
}

// TestArchivesSweep：daemon 报告归档轮转的最小端到端验证——
// reports.retention_days=0 时不动任何文件；>0 时按文件名日期老删新留。
// （24h ticker 的循环接线本身不可单测，靠该函数覆盖清理路径。）
func TestArchivesSweep(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default()
	cfg.Reports.Dir = root
	env := &analystEnv{cfg: cfg}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sweepNow := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	oldRel := filepath.Join("2025", "09", "daily-20250901.json")
	newRel := filepath.Join("2026", "10", "daily-20261021.json")
	for _, rel := range []string{oldRel, newRel} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	// 0 = 禁用：两份归档都在。
	cfg.Reports.RetentionDays = 0
	env.archivesSweep(log) // 内部 time.Now()：retention=0 直接短路，与时钟无关
	for _, rel := range []string{oldRel, newRel} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Fatalf("禁用轮转后 %s 不应缺失: %v", rel, err)
		}
	}

	// 90 天：老归档删除、新归档保留（经 reports.CleanupArchives 固定时钟验证）。
	if err := reports.CleanupArchives(root, 90, sweepNow); err != nil {
		t.Fatalf("CleanupArchives: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, oldRel)); !os.IsNotExist(err) {
		t.Errorf("老归档应已删除 (stat err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(root, newRel)); err != nil {
		t.Errorf("新归档不应删除: %v", err)
	}
}

// —— dogeImager 适配器：Render/Upload/Prune 到 chartimg/dogecloud 的映射 ——

// dogeTestTransport 把多吉云 API 请求与 virtual-host 风格（{bucket}.{host}）
// 的 S3 请求都路由到同一个 httptest 服务，其余原样放行。
type dogeTestTransport struct {
	handler http.HandlerFunc
}

func (t dogeTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.handler(rec, req)
	resp := rec.Result()
	return resp, nil
}

// newFakeDogeServer 启动假多吉云服务：/auth/tmp_token.json 发临时密钥
// （s3Endpoint 指回自身），PUT /{key} 记录请求体并返回 200；LIST 返回空集。
func newFakeDogeServer(t *testing.T) (*httptest.Server, *[]byte, *[]string) {
	t.Helper()
	var putBody []byte
	var putPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/tmp_token.json":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"code":200,"msg":"ok","data":{"Credentials":{"AccessKeyId":"STS_AK","SecretAccessKey":"STS_SK","SessionToken":"STS_TK"},"Buckets":[{"s3Bucket":"e3-test-bucket","s3Endpoint":%q}]}}`,
				"http://"+r.Host)
		case r.Method == http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			putBody = b
			putPaths = append(putPaths, r.URL.EscapedPath())
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet: // ListObjectsV2：空结果
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>`)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &putBody, &putPaths
}

// TestDogeImagerRenderUploadPruneMapping：Render 委托 chartimg 产出 PNG；
// Upload 用 NewKey 生成 key（含 kind/日期/前缀与 .png 后缀）并上传原始字节、
// 返回 PublicBaseURL+key 直链；Prune 走 LIST 空集成功返回。
func TestDogeImagerRenderUploadPruneMapping(t *testing.T) {
	srv, putBody, putPaths := newFakeDogeServer(t)
	doge := dogecloud.New(dogecloud.Config{
		AccessKey:     "ak-test",
		SecretKey:     "sk-test",
		Bucket:        "e3-test-bucket",
		PublicBaseURL: "https://img-host.example.top/",
		KeyPrefix:     "e3-reports/",
		APIBaseURL:    srv.URL,
		RetentionDays: 30,
	}, &http.Client{Transport: dogeTestTransport{handler: func(w http.ResponseWriter, r *http.Request) {
		// 统一改写 host 后交给同一假服务（virtual-host 风格的 S3 请求
		// 目标是 {bucket}.{api host}，测试 transport 直接按路径处理）。
		srv.Config.Handler.ServeHTTP(w, r)
	}}})
	adapter := newDogeImager(doge, chartimg.New(time.UTC))

	// Render：委托 chartimg（零事件窗口仍产出合法 PNG）。
	stats := &query.Stats{
		Since: time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC),
		Until: time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC),
	}
	png, err := adapter.Render(stats, "daily", stats.Since, stats.Until)
	if err != nil {
		t.Fatalf("Render 失败: %v", err)
	}
	if len(png) < 8 || string(png[:4]) != "\x89PNG" {
		t.Fatalf("Render 产物不是 PNG: 前 8 字节 %x", png[:8])
	}

	// Upload：key 布局 + 直链 + 上传字节一致。
	since := time.Date(2026, 10, 21, 16, 0, 0, 0, time.UTC)
	key, publicURL, err := adapter.Upload(context.Background(), "daily", since, png)
	if err != nil {
		t.Fatalf("Upload 失败: %v", err)
	}
	wantKeyPrefix := "e3-reports/daily/20261021-"
	if !strings.HasPrefix(key, wantKeyPrefix) || !strings.HasSuffix(key, ".png") {
		t.Errorf("key = %q, 期望前缀 %q 且 .png 结尾", key, wantKeyPrefix)
	}
	if want := "https://img-host.example.top/" + key; publicURL != want {
		t.Errorf("publicURL = %q, 期望 %q", publicURL, want)
	}
	if !bytes.Equal(*putBody, png) {
		t.Errorf("上传字节与 Render 产物不一致: %d vs %d 字节", len(*putBody), len(png))
	}
	if len(*putPaths) != 1 || (*putPaths)[0] != "/"+key {
		t.Errorf("PUT 路径 = %v, 期望 [/%s]", *putPaths, key)
	}

	// Prune：LIST 空集 → (0, nil)，适配器透传为 nil。
	if err := adapter.Prune(context.Background()); err != nil {
		t.Errorf("Prune 失败（空桶应无错误）: %v", err)
	}
}

// TestDogeImagerUploadFailurePropagates：多吉云侧错误原样透传（key 为空），
// 由 reports.Generator 统一降级。
func TestDogeImagerUploadFailurePropagates(t *testing.T) {
	// 直接对不可达端口构造客户端：网络错误即透传。
	doge := dogecloud.New(dogecloud.Config{
		AccessKey:     "ak-test",
		SecretKey:     "sk-test",
		Bucket:        "e3-test-bucket",
		PublicBaseURL: "https://img-host.example.top",
		KeyPrefix:     "e3-reports/",
		APIBaseURL:    "http://127.0.0.1:1", // 不可达
		Timeout:       500 * time.Millisecond,
	}, nil)
	adapter := newDogeImager(doge, chartimg.New(time.UTC))
	key, publicURL, err := adapter.Upload(context.Background(), "daily", time.Now().UTC(), []byte("png"))
	if err == nil {
		t.Fatal("Upload 应失败（API 不可达）")
	}
	if key != "" || publicURL != "" {
		t.Errorf("失败时 key/publicURL 应为空: %q/%q", key, publicURL)
	}
	if strings.Contains(err.Error(), "sk-test") {
		t.Errorf("错误信息不得包含密钥: %v", err)
	}
}
