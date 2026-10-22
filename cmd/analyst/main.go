// Command e3-analyst 是安全分析 Agent 的入口（CONTRACTS "cmd 二进制"）。
//
// 子命令：
//
//	report --type daily|weekly   一次性生成报告（systemd timer 触发）
//	daemon                       常驻：每 30s 补发 pending 通知 +
//	                             每 10min 重试 72h 内 attempts<3 的失败报告
//	verify                       配置/环境自检（✓/✗ 清单，值绝不打印）
//
// 公共约定：--config <path>（默认 /etc/e3-security-analyst/config.yaml，
// 环境变量 E3_ANALYST_CONFIG 可覆盖）；凭据只经环境变量注入（llm.api_key_env
// → DEEPSEEK_API_KEY，ntfy.token_env → NTFY_TOKEN），日志绝不输出其值。
//
// 退出码：0 正常；1 运行期错误（含 verify 发现 ✗）；2 配置/用法错误；
// 3 report 子命令缺少 LLM API Key。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/modenc/e3-security-analyst/internal/config"
	"github.com/modenc/e3-security-analyst/internal/llm"
	"github.com/modenc/e3-security-analyst/internal/logging"
	"github.com/modenc/e3-security-analyst/internal/ntfy"
	"github.com/modenc/e3-security-analyst/internal/reports"
	"github.com/modenc/e3-security-analyst/internal/sandbox"
	"github.com/modenc/e3-security-analyst/internal/store"

	"github.com/modenc/e3-security-analyst/migrations"
)

// errLLMKeyMissing 表示 LLM API Key 缺失（report 子命令退出码 3 的判定依据）。
var errLLMKeyMissing = errors.New("LLM API Key 未设置")

// configEnvVar 覆盖默认配置路径（优先级：--config > 环境变量 > 内置默认）。
const configEnvVar = "E3_ANALYST_CONFIG"

// daemon 循环节奏。
const (
	daemonFlushInterval = 30 * time.Second // 通知补发周期
	daemonRetryInterval = 10 * time.Minute // 失败报告重试周期
	daemonRetryWindow   = 72 * time.Hour   // 只重试该窗口内失败的报告
	daemonMaxAttempts   = 3                // 重试的报告最大 attempts
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		return 2
	}
	switch os.Args[1] {
	case "report":
		return cmdReport(os.Args[2:])
	case "daemon":
		return cmdDaemon(os.Args[2:])
	case "verify":
		return cmdVerify(os.Args[2:])
	case "-h", "--help", "help":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "e3-analyst: 未知子命令 %q\n\n", os.Args[1])
		usage(os.Stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `用法：e3-analyst <子命令> [参数]

子命令：
  report --type daily|weekly [--config <path>]   生成日报/周报（oneshot）
  daemon [--config <path>]                       常驻：通知补发 + 失败报告重试
  verify [--config <path>]                       配置/环境自检

公共参数：
  --config <path>   配置文件路径（默认 /etc/e3-security-analyst/config.yaml，
                    环境变量 %s 可覆盖）
`, configEnvVar)
}

// loadConfigFile 加载配置文件；失败时以兜底 stderr 日志记录后返回退出码
// 2（与 cmd/collector 一致的风格）。
func loadConfigFile(path string) (*config.Config, int) {
	cfg, err := config.Load(path)
	if err != nil {
		boot, bootErr := logging.New("info", os.Stderr)
		if bootErr != nil {
			fmt.Fprintf(os.Stderr, "e3-analyst: 加载配置 %s 失败: %v\n", path, err)
			return nil, 2
		}
		boot.Error("加载配置失败", "path", path, "error", err)
		return nil, 2
	}
	return cfg, 0
}

// loadConfig 解析子命令的 --config 并加载配置；失败时以退出码 2 结束。
func loadConfig(args []string, name string) (*config.Config, *string, int) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", defaultConfigPath(), "配置文件路径")
	if err := fs.Parse(args); err != nil {
		return nil, nil, 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "e3-analyst %s: 未知位置参数 %v\n", name, fs.Args())
		return nil, nil, 2
	}
	cfg, code := loadConfigFile(*configPath)
	if code != 0 {
		return nil, nil, code
	}
	return cfg, configPath, 0
}

// defaultConfigPath 返回默认配置路径：E3_ANALYST_CONFIG 环境变量优先。
func defaultConfigPath() string {
	if p := strings.TrimSpace(os.Getenv(configEnvVar)); p != "" {
		return p
	}
	return "/etc/e3-security-analyst/config.yaml"
}

// analystEnv 是 report/daemon 共用的装配结果。
type analystEnv struct {
	cfg       *config.Config
	db        *store.DB
	gen       *reports.Generator
	publisher *ntfy.Publisher
	llmKey    string // LLM API Key（绝不出现在日志）
	llmReady  bool   // Key 已配置
}

// assemble 完成公共装配：日志、数据库、LLM 客户端、Runner（可选降级）、
// ntfy Publisher 与报告生成器。requireKey=true 时 Key 缺失返回错误
// （由调用方决定退出码 3）；false 时仅告警（daemon 主要做通知补发）。
func assemble(cfg *config.Config, requireKey bool, log *slog.Logger) (*analystEnv, error) {
	db, err := store.Open(cfg.Database.Path, store.Options{
		WAL:           cfg.Database.WAL,
		BusyTimeoutMs: cfg.Database.BusyTimeoutMs,
	})
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}
	if err := db.Migrate(migrations.FS); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("数据库迁移失败: %w", err)
	}

	llmKey := os.Getenv(cfg.LLM.APIKeyEnv)
	if llmKey == "" {
		if requireKey {
			_ = db.Close()
			return nil, fmt.Errorf("%w（环境变量 %s）", errLLMKeyMissing, cfg.LLM.APIKeyEnv)
		}
		log.Warn("LLM API Key 未设置，报告生成不可用（通知补发不受影响）",
			"api_key_env", cfg.LLM.APIKeyEnv)
	}
	client := llm.NewClient(llm.ClientConfig{
		BaseURL:         cfg.LLM.BaseURL,
		Model:           cfg.LLM.Model,
		APIKey:          llmKey,
		Timeout:         time.Duration(cfg.LLM.TimeoutSeconds) * time.Second,
		MaxToolRounds:   cfg.LLM.MaxToolRounds,
		MaxOutputTokens: cfg.LLM.MaxOutputTokens,
		MaxTotalTokens:  cfg.LLM.MaxTotalTokens,
		EnableTools:     cfg.LLM.EnableTools,
	})

	// Runner：启用且二进制存在才装配，否则降级 nil（execute_js 不可用）。
	var runner *sandbox.Runner
	if cfg.ScriptRunner.Enabled {
		if _, err := os.Stat(cfg.ScriptRunner.RunnerPath); err == nil {
			runner = sandbox.NewRunner(cfg.ScriptRunner.RunnerPath, sandbox.Limits{
				TimeoutMS:      cfg.ScriptRunner.TimeoutMS,
				MaxInputBytes:  cfg.ScriptRunner.MaxInputBytes,
				MaxOutputBytes: cfg.ScriptRunner.MaxOutputBytes,
			}, cfg.ScriptRunner.MaxConcurrency)
		} else {
			log.Warn("script-runner 二进制不存在，execute_js 降级禁用",
				"runner_path", cfg.ScriptRunner.RunnerPath)
		}
	}

	// ntfy：Token 缺失 → 匿名模式（仅告警，不阻断）。
	token := os.Getenv(cfg.Ntfy.TokenEnv)
	if token == "" {
		log.Warn("ntfy Token 未设置，以匿名模式继续（通知可能被服务端拒绝）",
			"token_env", cfg.Ntfy.TokenEnv)
	}
	nc := ntfy.NewClient(ntfy.ClientConfig{
		BaseURL: cfg.Ntfy.BaseURL,
		Token:   token,
		Timeout: time.Duration(cfg.Ntfy.TimeoutSeconds) * time.Second,
	})
	publisher := ntfy.NewPublisher(nc, db, cfg.Ntfy.MaxRetries, cfg.Ntfy.MaxMessageBytes, log)

	gen, err := reports.NewGenerator(cfg, db, client, runner, publisher, log)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("创建报告生成器失败: %w", err)
	}
	return &analystEnv{
		cfg: cfg, db: db, gen: gen, publisher: publisher,
		llmKey: llmKey, llmReady: llmKey != "",
	}, nil
}

func (e *analystEnv) close() {
	if e.db != nil {
		_ = e.db.Close()
	}
}

// —— report ——

func cmdReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", defaultConfigPath(), "配置文件路径")
	typ := fs.String("type", "", "报告类型：daily 或 weekly")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *typ != "daily" && *typ != "weekly" {
		fmt.Fprintf(os.Stderr, "e3-analyst report: --type 必须为 daily 或 weekly（当前 %q）\n", *typ)
		return 2
	}

	cfg, code := loadConfigFile(*configPath)
	if code != 0 {
		return code
	}
	log, err := logging.New(cfg.App.LogLevel, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "e3-analyst: 初始化日志失败: %v\n", err)
		return 2
	}
	log.Info("e3-analyst report 启动", "config", *configPath, "type", *typ, "summary", cfg.Redacted())

	env, err := assemble(cfg, true, log)
	if err != nil {
		if errors.Is(err, errLLMKeyMissing) {
			log.Error("LLM API Key 未设置，无法生成报告", "api_key_env", cfg.LLM.APIKeyEnv)
			return 3
		}
		log.Error("装配失败", "error", err)
		return 1
	}
	defer env.close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := env.gen.Generate(ctx, *typ); err != nil {
		log.Error("报告生成失败", "type", *typ, "error", err)
		return 1
	}
	log.Info("报告生成完成", "type", *typ)
	return 0
}

// —— daemon ——

func cmdDaemon(args []string) int {
	cfg, _, code := loadConfig(args, "daemon")
	if code != 0 {
		return code
	}
	log, err := logging.New(cfg.App.LogLevel, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "e3-analyst: 初始化日志失败: %v\n", err)
		return 2
	}
	log.Info("e3-analyst daemon 启动", "summary", cfg.Redacted())

	env, err := assemble(cfg, false, log)
	if err != nil {
		log.Error("装配失败", "error", err)
		return 1
	}
	defer env.close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	flushTick := time.NewTicker(daemonFlushInterval)
	defer flushTick.Stop()
	retryTick := time.NewTicker(daemonRetryInterval)
	defer retryTick.Stop()

	// 启动即补发一次积压通知。
	if sent, failedPerm, ferr := env.publisher.FlushPending(ctx); ferr != nil {
		log.Warn("补发通知失败", "error", ferr)
	} else if sent > 0 || failedPerm > 0 {
		log.Info("启动补发完成", "sent", sent, "failed_permanent", failedPerm)
	}

	for {
		select {
		case <-ctx.Done():
			log.Info("e3-analyst daemon 退出")
			return 0
		case <-flushTick.C:
			sent, failedPerm, ferr := env.publisher.FlushPending(ctx)
			if ferr != nil {
				log.Warn("补发通知失败", "error", ferr)
				continue
			}
			if sent > 0 || failedPerm > 0 {
				log.Info("通知补发完成", "sent", sent, "failed_permanent", failedPerm)
			}
		case <-retryTick.C:
			env.retryFailedReports(ctx, log)
		}
	}
}

// retryFailedReports 重试 72h 内 attempts<3 的失败报告；LLM 不可用（Key
// 缺失）时只记日志跳过——daemon 的首要职责是通知补发，不因缺 Key 退出。
func (e *analystEnv) retryFailedReports(ctx context.Context, log *slog.Logger) {
	failed, err := e.db.FailedReports(ctx, time.Now().Add(-daemonRetryWindow))
	if err != nil {
		log.Warn("查询失败报告出错", "error", err)
		return
	}
	for _, r := range failed {
		if r.Attempts >= daemonMaxAttempts {
			continue
		}
		if !e.llmReady {
			log.Warn("LLM 不可用，跳过失败报告重试",
				"type", r.Type, "attempts", r.Attempts, "api_key_env", e.cfg.LLM.APIKeyEnv)
			continue
		}
		log.Info("重试失败报告", "type", r.Type, "attempts", r.Attempts,
			"window_start", r.WindowStart.UTC().Format(time.RFC3339))
		if err := e.gen.Generate(ctx, r.Type); err != nil {
			log.Warn("失败报告重试未成功", "type", r.Type, "error", err)
		}
	}
}

// —— verify ——

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", defaultConfigPath(), "配置文件路径")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "e3-analyst verify: 未知位置参数 %v\n", fs.Args())
		return 2
	}
	cfg, err := config.Load(*configPath)
	ok := true
	check := func(passed bool, format string, a ...any) {
		mark := "✓"
		if !passed {
			mark = "✗"
			ok = false
		}
		fmt.Printf(mark+" "+format+"\n", a...)
	}
	fmt.Printf("e3-analyst verify — 配置 %s\n", *configPath)
	check(err == nil, "配置加载: %v", errOrOK(err))
	if err != nil {
		return 1
	}

	_, locErr := cfg.Location()
	check(locErr == nil, "时区 %s: %v", cfg.App.Timezone, errOrOK(locErr))

	llmKeySet := strings.TrimSpace(os.Getenv(cfg.LLM.APIKeyEnv)) != ""
	check(llmKeySet, "环境变量 %s 已设置（值不显示）", cfg.LLM.APIKeyEnv)

	ntfyTokenSet := strings.TrimSpace(os.Getenv(cfg.Ntfy.TokenEnv)) != ""
	check(ntfyTokenSet, "环境变量 %s 已设置（值不显示）", cfg.Ntfy.TokenEnv)

	check(fileReadable(cfg.Cowrie.LogPath), "cowrie.log_path 存在且可读: %s", cfg.Cowrie.LogPath)

	check(dirWritable(filepath.Dir(cfg.Database.Path)), "database.path 父目录可写: %s",
		filepath.Dir(cfg.Database.Path))

	check(dirWritable(cfg.ReportsDir()), "reports 目录可写: %s", cfg.ReportsDir())

	if cfg.ScriptRunner.Enabled {
		_, statErr := os.Stat(cfg.ScriptRunner.RunnerPath)
		check(statErr == nil, "script-runner 二进制存在: %s（%v）",
			cfg.ScriptRunner.RunnerPath, errOrOK(statErr))
	} else {
		check(true, "script-runner 已禁用（无需二进制）")
	}

	check(schemeHTTPS(cfg.LLM.BaseURL), "llm.base_url 为 https: %s", cfg.LLM.BaseURL)
	check(schemeHTTPS(cfg.Ntfy.BaseURL), "ntfy.base_url 为 https: %s", cfg.Ntfy.BaseURL)

	if !ok {
		fmt.Println("verify：存在 ✗ 项，请修复后再运行")
		return 1
	}
	fmt.Println("verify：全部通过")
	return 0
}

// errOrOK 把 nil 错误渲染为 "OK"。
func errOrOK(err error) any {
	if err == nil {
		return "OK"
	}
	return err
}

// fileReadable 检查路径存在且以只读方式可打开。
func fileReadable(path string) bool {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return false
	}
	return f.Close() == nil
}

// dirWritable 检查目录存在（不存在则按 0700 创建）且可写（探针文件）。
func dirWritable(dir string) bool {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false
	}
	f, err := os.CreateTemp(dir, ".e3-verify-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name) == nil
}

// schemeHTTPS 要求 https；仅回环地址允许 http（与 config 校验口径一致）。
func schemeHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}
	return false
}
