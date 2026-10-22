// ReportImager 管线测试：假 imager 覆盖成功路径（payload.image 块、通知
// Attach+Markdown、归档 .png 副本、Prune 被调用）与降级路径（Render/Upload
// 失败 → 纯文本正文与历史格式逐字节一致、报告照常 published）。
package reports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modenc/e3-security-analyst/internal/query"
)

// fakeImager 是可控失败的假图表管线：renderErr/uploadErr/pruneErr 非空时
// 对应环节返回错误；成功路径返回固定 PNG 字节与直链。
type fakeImager struct {
	renderErr error
	uploadErr error
	pruneErr  error

	renderCalled bool
	pruneCalled  bool
	lastPNG      []byte
	lastKind     string
	lastSince    time.Time
}

const (
	fakePNGBytes = "FAKE-PNG-BYTES-FOR-E3-REPORTS-TEST"
	fakeKey      = "e3-reports/daily/20261022-00ff00ff00ff00ff.png"
	fakeURL      = "https://img-host.modenc.top/e3-reports/daily/20261022-00ff00ff00ff00ff.png"
)

func (f *fakeImager) Render(stats *query.Stats, kind string, since, until time.Time) ([]byte, error) {
	f.renderCalled = true
	if f.renderErr != nil {
		return nil, f.renderErr
	}
	return []byte(fakePNGBytes), nil
}

func (f *fakeImager) Upload(ctx context.Context, kind string, since time.Time, png []byte) (string, string, error) {
	f.lastPNG = png
	f.lastKind = kind
	f.lastSince = since
	if f.uploadErr != nil {
		return "", "", f.uploadErr
	}
	return fakeKey, fakeURL, nil
}

func (f *fakeImager) Prune(ctx context.Context) error {
	f.pruneCalled = true
	return f.pruneErr
}

// wantPlainBody 按历史格式构造期望的纯文本通知正文（与 draftFor/种子数据
// 对齐），用于降级路径的逐字节断言。
func wantPlainBody(t *testing.T, archivedJSON []byte, ks [4]int, archivePath string) string {
	t.Helper()
	var p archivePayload
	if err := json.Unmarshal(archivedJSON, &p); err != nil {
		t.Fatalf("解析归档 payload 失败: %v", err)
	}
	summary, _ := p.Model["summary"].(string)
	return summary +
		fmt.Sprintf("\n连接 %d|独立IP %d|登录成功 %d|失败 %d", ks[0], ks[1], ks[2], ks[3]) +
		"\n[high] 蜜罐内出现模拟登录成功" +
		"\n归档: " + archivePath
}

// —— 成功路径：payload.image 块、Attach+Markdown 头、.png 副本、Prune ——

func TestGenerateWithImageSuccess(t *testing.T) {
	te := newTestEnv(t, nil)
	fi := &fakeImager{}
	te.gen.SetImager(fi)
	_, ks := seedDailyWindow(t, te.db, te.loc)
	te.llm.steps = successSteps("daily", ks)

	if err := te.gen.Generate(context.Background(), "daily"); err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}

	// 报告照常 published；归档 .json 落盘且 payload.image 字段齐全。
	rep, err := te.db.GetReport(context.Background(), "daily", mustWindow(t, te.loc))
	if err != nil || rep == nil {
		t.Fatalf("GetReport 失败: %v %v", rep, err)
	}
	if rep.Status != "published" {
		t.Errorf("reports.status = %q, 期望 published", rep.Status)
	}
	jsonPath := archivePathFor(te.cfg, te.loc, "daily", mustWindow(t, te.loc))
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("读取归档 JSON 失败: %v", err)
	}
	var p archivePayload
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("解析归档 payload 失败: %v", err)
	}
	if p.Image == nil {
		t.Fatalf("payload.image 缺失:\n%s", data)
	}
	sum := sha256.Sum256([]byte(fakePNGBytes))
	if p.Image.URL != fakeURL || p.Image.Key != fakeKey ||
		p.Image.SHA256 != hex.EncodeToString(sum[:]) || p.Image.Bytes != len(fakePNGBytes) {
		t.Errorf("payload.image 字段异常: %+v", p.Image)
	}
	if p.Image.GeneratedAt.IsZero() {
		t.Error("payload.image.generated_at 为零值")
	}

	// 归档 .png 副本：同目录同基名，字节即 Render 产物。
	pngPath := strings.TrimSuffix(jsonPath, ".json") + ".png"
	pngData, err := os.ReadFile(pngPath)
	if err != nil {
		t.Fatalf("读取归档 PNG 失败: %v", err)
	}
	if string(pngData) != fakePNGBytes {
		t.Errorf("归档 PNG 字节与 Render 产物不一致: %q", pngData)
	}

	// 通知：Attach=直链、Markdown=yes、正文为 Markdown 变体。
	reqs := te.ntfy.requests()
	if len(reqs) != 1 {
		t.Fatalf("ntfy 收到 %d 条, 期望 1", len(reqs))
	}
	r := reqs[0]
	if r.Attach != fakeURL {
		t.Errorf("Attach header = %q, 期望 %q", r.Attach, fakeURL)
	}
	if r.Markdown != "yes" {
		t.Errorf("Markdown header = %q, 期望 yes", r.Markdown)
	}
	for _, sub := range []string{
		fmt.Sprintf("**连接 %d|独立IP %d|登录成功 %d|失败 %d**", ks[0], ks[1], ks[2], ks[3]),
		"- [high] 蜜罐内出现模拟登录成功",
		"![chart](" + fakeURL + ")",
		"归档: ",
	} {
		if !strings.Contains(r.Body, sub) {
			t.Errorf("ntfy body 缺少 %q, 实际:\n%s", sub, r.Body)
		}
	}

	// Prune 被调用；Upload 收到的字节与 kind 来自流程。
	if !fi.pruneCalled {
		t.Error("Prune 未被调用")
	}
	if string(fi.lastPNG) != fakePNGBytes || fi.lastKind != "daily" {
		t.Errorf("Upload 参数异常: kind=%q png=%q", fi.lastKind, fi.lastPNG)
	}
}

// —— Render 失败：img=nil，正文纯文本与历史格式逐字节一致，报告照常发布 ——

func TestGenerateImageRenderFailureDegrades(t *testing.T) {
	te := newTestEnv(t, nil)
	fi := &fakeImager{renderErr: fmt.Errorf("boom: 渲染失败")}
	te.gen.SetImager(fi)
	_, ks := seedDailyWindow(t, te.db, te.loc)
	te.llm.steps = successSteps("daily", ks)

	if err := te.gen.Generate(context.Background(), "daily"); err != nil {
		t.Fatalf("Render 失败不应导致 Generate 失败: %v", err)
	}

	rep, err := te.db.GetReport(context.Background(), "daily", mustWindow(t, te.loc))
	if err != nil || rep == nil {
		t.Fatalf("GetReport 失败: %v %v", rep, err)
	}
	if rep.Status != "published" {
		t.Errorf("reports.status = %q, 期望 published（降级不阻断）", rep.Status)
	}

	jsonPath := archivePathFor(te.cfg, te.loc, "daily", mustWindow(t, te.loc))
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("读取归档 JSON 失败: %v", err)
	}
	if strings.Contains(string(data), `"image"`) {
		t.Errorf("降级路径 payload 不应包含 image 块:\n%s", data)
	}

	// .png 不落盘。
	pngPath := strings.TrimSuffix(jsonPath, ".json") + ".png"
	if _, err := os.Stat(pngPath); !os.IsNotExist(err) {
		t.Errorf("降级路径不应写 .png 副本 (stat err=%v)", err)
	}

	// 通知：无 Attach/Markdown 头，正文与历史纯文本格式逐字节一致。
	reqs := te.ntfy.requests()
	if len(reqs) != 1 {
		t.Fatalf("ntfy 收到 %d 条, 期望 1", len(reqs))
	}
	r := reqs[0]
	if r.Attach != "" || r.Markdown != "" {
		t.Errorf("降级通知不应携带 Attach/Markdown 头: %q/%q", r.Attach, r.Markdown)
	}
	if want := wantPlainBody(t, data, ks, jsonPath); r.Body != want {
		t.Errorf("降级正文与历史格式不一致:\n got: %q\nwant: %q", r.Body, want)
	}

	// Upload/Prune 不被调用。
	if fi.pruneCalled {
		t.Error("Render 失败后 Prune 不应被调用")
	}
	if fi.lastKind != "" {
		t.Error("Render 失败后 Upload 不应被调用")
	}
}

// —— Upload 失败：与 Render 失败同样降级 ——

func TestGenerateImageUploadFailureDegrades(t *testing.T) {
	te := newTestEnv(t, nil)
	fi := &fakeImager{uploadErr: fmt.Errorf("boom: 上传失败")}
	te.gen.SetImager(fi)
	_, ks := seedDailyWindow(t, te.db, te.loc)
	te.llm.steps = successSteps("daily", ks)

	if err := te.gen.Generate(context.Background(), "daily"); err != nil {
		t.Fatalf("Upload 失败不应导致 Generate 失败: %v", err)
	}

	rep, err := te.db.GetReport(context.Background(), "daily", mustWindow(t, te.loc))
	if err != nil || rep == nil {
		t.Fatalf("GetReport 失败: %v %v", rep, err)
	}
	if rep.Status != "published" {
		t.Errorf("reports.status = %q, 期望 published（降级不阻断）", rep.Status)
	}

	jsonPath := archivePathFor(te.cfg, te.loc, "daily", mustWindow(t, te.loc))
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("读取归档 JSON 失败: %v", err)
	}
	if strings.Contains(string(data), `"image"`) {
		t.Errorf("降级路径 payload 不应包含 image 块:\n%s", data)
	}
	pngPath := strings.TrimSuffix(jsonPath, ".json") + ".png"
	if _, err := os.Stat(pngPath); !os.IsNotExist(err) {
		t.Errorf("降级路径不应写 .png 副本 (stat err=%v)", err)
	}

	reqs := te.ntfy.requests()
	if len(reqs) != 1 {
		t.Fatalf("ntfy 收到 %d 条, 期望 1", len(reqs))
	}
	r := reqs[0]
	if r.Attach != "" || r.Markdown != "" {
		t.Errorf("降级通知不应携带 Attach/Markdown 头: %q/%q", r.Attach, r.Markdown)
	}
	if want := wantPlainBody(t, data, ks, jsonPath); r.Body != want {
		t.Errorf("降级正文与历史格式不一致:\n got: %q\nwant: %q", r.Body, want)
	}
	if !fi.renderCalled {
		t.Error("Upload 失败前 Render 应已被调用")
	}
	if fi.pruneCalled {
		t.Error("Upload 失败后 Prune 不应被调用")
	}
}

// —— Prune 失败：仅告警，不影响报告与通知 ——

func TestGenerateImagePruneFailureNonFatal(t *testing.T) {
	te := newTestEnv(t, nil)
	fi := &fakeImager{pruneErr: fmt.Errorf("boom: 清理失败")}
	te.gen.SetImager(fi)
	_, ks := seedDailyWindow(t, te.db, te.loc)
	te.llm.steps = successSteps("daily", ks)

	if err := te.gen.Generate(context.Background(), "daily"); err != nil {
		t.Fatalf("Prune 失败不应导致 Generate 失败: %v", err)
	}
	rep, err := te.db.GetReport(context.Background(), "daily", mustWindow(t, te.loc))
	if err != nil || rep == nil {
		t.Fatalf("GetReport 失败: %v %v", rep, err)
	}
	if rep.Status != "published" {
		t.Errorf("reports.status = %q, 期望 published", rep.Status)
	}
	reqs := te.ntfy.requests()
	if len(reqs) != 1 || reqs[0].Attach != fakeURL {
		t.Fatalf("Prune 失败不应影响带图通知: %+v", reqs)
	}
}

// —— notifyMarkdown=false：正文保持现格式并追加 "图表: URL"，Attach 仍携带 ——

func TestGenerateImageNotifyMarkdownOff(t *testing.T) {
	te := newTestEnv(t, nil)
	fi := &fakeImager{}
	te.gen.SetImager(fi)
	te.gen.SetNotifyMarkdown(false)
	_, ks := seedDailyWindow(t, te.db, te.loc)
	te.llm.steps = successSteps("daily", ks)

	if err := te.gen.Generate(context.Background(), "daily"); err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}

	jsonPath := archivePathFor(te.cfg, te.loc, "daily", mustWindow(t, te.loc))
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("读取归档 JSON 失败: %v", err)
	}

	reqs := te.ntfy.requests()
	if len(reqs) != 1 {
		t.Fatalf("ntfy 收到 %d 条, 期望 1", len(reqs))
	}
	r := reqs[0]
	if r.Attach != fakeURL {
		t.Errorf("Attach header = %q, 期望 %q（直链照常携带）", r.Attach, fakeURL)
	}
	if r.Markdown != "" {
		t.Errorf("Markdown header = %q, 期望缺席", r.Markdown)
	}
	want := wantPlainBody(t, data, ks, jsonPath) + "\n图表: " + fakeURL
	if r.Body != want {
		t.Errorf("关闭 Markdown 的正文应为纯文本+图表行:\n got: %q\nwant: %q", r.Body, want)
	}
	if strings.Contains(r.Body, "![chart]") || strings.Contains(r.Body, "**连接") {
		t.Errorf("关闭 Markdown 的正文不应含 Markdown 语法:\n%s", r.Body)
	}

	// 归档 .png 副本照常落盘。
	pngPath := strings.TrimSuffix(jsonPath, ".json") + ".png"
	if pngData, err := os.ReadFile(pngPath); err != nil || string(pngData) != fakePNGBytes {
		t.Errorf("归档 PNG 异常: err=%v data=%q", err, pngData)
	}
}
