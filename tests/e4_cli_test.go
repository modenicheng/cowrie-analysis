// E4 命令行冒烟与部署可达性（SPEC §16 验收 9,12）。
//
//	验收 9（可达性）：deploy/ 中日报/周报 systemd timer → service →
//	  `e3-analyst report --type daily|weekly` 链路完整；
//	验收 12（可达性）：全部 *.service 以非 root 专用用户运行；
//	附加：`analyst verify --config` 全通过时输出 ✓ 清单且退出码 0，
//	  绝不打印环境变量值（凭据不进普通输出）。
package tests_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestE4AnalystVerifySmoke：构建出的真实 e3-analyst 二进制对临时全绿
// 配置执行 verify：退出码 0、含 ✓ 清单、不含 env 值。
func TestE4AnalystVerifySmoke(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "cowrie")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("创建日志目录: %v", err)
	}
	logPath := filepath.Join(logDir, "cowrie.json")
	if err := os.WriteFile(logPath, []byte("{\"eventid\":\"cowrie.session.connect\"}\n"), 0o644); err != nil {
		t.Fatalf("写入日志文件: %v", err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgYAML := "app:\n" +
		"  timezone: Asia/Shanghai\n" +
		"  state_dir: " + filepath.ToSlash(filepath.Join(dir, "state")) + "\n" +
		"  log_level: info\n" +
		"cowrie:\n" +
		"  log_path: " + filepath.ToSlash(logPath) + "\n" +
		"database:\n" +
		"  path: " + filepath.ToSlash(filepath.Join(dir, "db", "events.db")) + "\n" +
		"llm:\n" +
		"  base_url: https://api.deepseek.com\n" +
		"  model: deepseek-chat\n" +
		"  api_key_env: DEEPSEEK_API_KEY\n" +
		"ntfy:\n" +
		"  base_url: https://notify.example.com\n" +
		"  topic: e3verify\n" +
		"  token_env: NTFY_TOKEN\n" +
		"script_runner:\n" +
		"  enabled: false\n"
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("写入配置: %v", err)
	}

	const llmSecret = "sk-e4-secret-llm-do-not-print"
	const ntfySecret = "tok-e4-secret-ntfy-do-not-print"
	env := []string{}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "DEEPSEEK_API_KEY=") || strings.HasPrefix(kv, "NTFY_TOKEN=") ||
			strings.HasPrefix(kv, "E3_ANALYST_CONFIG=") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "DEEPSEEK_API_KEY="+llmSecret, "NTFY_TOKEN="+ntfySecret)

	cmd := exec.Command(analystBin, "verify", "--config", cfgPath)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		t.Fatalf("verify 应以退出码 0 成功: %v\n输出:\n%s", err, output)
	}
	if !strings.Contains(output, "✓") {
		t.Errorf("verify 输出应包含 ✓ 清单:\n%s", output)
	}
	if strings.Contains(output, llmSecret) || strings.Contains(output, ntfySecret) {
		t.Errorf("verify 输出泄露环境变量值:\n%s", output)
	}
	// 环境变量只以名字出现，并明示"值不显示"。
	if !strings.Contains(output, "DEEPSEEK_API_KEY") || !strings.Contains(output, "NTFY_TOKEN") {
		t.Errorf("verify 输出应点名两个凭据环境变量（仅名字）:\n%s", output)
	}
	if !strings.Contains(output, "全部通过") {
		t.Errorf("verify 应报告全部通过:\n%s", output)
	}
}

// TestE4DeployWiring：systemd timer/service 部署链路可达（验收 9,12）。
func TestE4DeployWiring(t *testing.T) {
	deploy := filepath.Join(repoRoot(t), "deploy")
	readFile := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(deploy, name))
		if err != nil {
			t.Fatalf("读取 deploy/%s 失败: %v", name, err)
		}
		return string(b)
	}

	// 验收 9：日报/周报由 timer 触发，service 调用 report 子命令。
	for _, d := range []struct{ timer, service, typ string }{
		{"e3-daily-report.timer", "e3-daily-report.service", "daily"},
		{"e3-weekly-report.timer", "e3-weekly-report.service", "weekly"},
	} {
		timer := readFile(d.timer)
		if !strings.Contains(timer, "OnCalendar=") {
			t.Errorf("%s 缺少 OnCalendar 触发时间", d.timer)
		}
		if !strings.Contains(timer, "Unit="+d.service) {
			t.Errorf("%s 未指向 %s", d.timer, d.service)
		}
		svc := readFile(d.service)
		if !strings.Contains(svc, "report --type "+d.typ) {
			t.Errorf("%s 未调用 report --type %s", d.service, d.typ)
		}
	}

	// 验收 12：所有 service 均以非 root 专用用户运行。
	services, err := filepath.Glob(filepath.Join(deploy, "*.service"))
	if err != nil {
		t.Fatalf("Glob service 文件: %v", err)
	}
	if len(services) < 4 {
		t.Fatalf("deploy 下 service 文件数 = %d, 期望 ≥4（collector/analyst/daily/weekly）", len(services))
	}
	for _, svcPath := range services {
		svc := readFile(filepath.Base(svcPath))
		idx := strings.Index(svc, "User=")
		if idx < 0 {
			t.Errorf("%s 缺少 User=（必须非 root 运行）", filepath.Base(svcPath))
			continue
		}
		user := svc[idx+len("User="):]
		if nl := strings.IndexAny(user, "\r\n"); nl >= 0 {
			user = user[:nl]
		}
		if strings.TrimSpace(user) == "" || strings.TrimSpace(user) == "root" {
			t.Errorf("%s User=%q 不允许（须专用非 root 用户）", filepath.Base(svcPath), user)
		}
	}
}
