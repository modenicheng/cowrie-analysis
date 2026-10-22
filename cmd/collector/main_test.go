package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/modenc/e3-security-analyst/internal/config"
)

// TestExampleConfigLoads 保证 configs/config.example.yaml 与
// internal/config.Config 逐字段一一对应（config.Load 开启 KnownFields，
// 任何未知字段都会失败）且全部值通过校验（越界值也会失败）。
// 这能防止任一侧新增字段后另一侧被遗漏。
func TestExampleConfigLoads(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "config.example.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("示例配置不存在（%s）: %v", path, err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("加载示例配置失败: %v", err)
	}
	if cfg.Ntfy.BaseURL != "https://notify.modenc.top" {
		t.Errorf("ntfy.base_url = %q，期望示例值 https://notify.modenc.top", cfg.Ntfy.BaseURL)
	}
	if cfg.ScriptRunner.RunnerPath != "/usr/local/bin/e3-script-runner" {
		t.Errorf("script_runner.runner_path = %q，期望 /usr/local/bin/e3-script-runner", cfg.ScriptRunner.RunnerPath)
	}
}

// TestDefaultConfigPath 验证 E3_ANALYST_CONFIG 覆盖默认配置路径的优先级。
func TestDefaultConfigPath(t *testing.T) {
	t.Setenv(configEnvVar, "")
	if got := defaultConfigPath(); got != "/etc/e3-security-analyst/config.yaml" {
		t.Errorf("默认路径 = %q", got)
	}
	t.Setenv(configEnvVar, "  /tmp/e3-test.yaml  ")
	if got := defaultConfigPath(); got != "/tmp/e3-test.yaml" {
		t.Errorf("环境变量覆盖后 = %q，期望去除首尾空白", got)
	}
}
