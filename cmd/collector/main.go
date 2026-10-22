// Command e3-collector 持续采集 Cowrie JSONL 日志并驱动确定性实时告警
// （SPEC §2/§6/§10/§14；CONTRACTS "cmd 二进制"）。
//
// 启动流程：
//
//	--config <path>（默认 /etc/e3-security-analyst/config.yaml，
//	  环境变量 E3_ANALYST_CONFIG 可覆盖默认值）
//	  → config.Load（失败 → stderr 记录错误并以退出码 2 退出）
//	  → logging.New(cfg.App.LogLevel, stdout)，启动日志含 cfg.Redacted() 脱敏摘要
//	  → store.Open({WAL, BusyTimeoutMs}) + db.Migrate(migrations.FS)
//	  → ntfy Client/Publisher：Token 取自 cfg.Ntfy.TokenEnv 指向的环境变量；
//	    为空时仅告警并以匿名模式继续（保证采集可以先跑通）
//	  → alerts.enabled 时挂载 rules.Engine 为 collector.EventHandler，
//	    并按 alerts.digest_interval_seconds 周期 FlushDigest（错误只记日志）
//	  → signal.NotifyContext(SIGINT, SIGTERM) → collector.Run(ctx)
//
// 所有路径/间隔/限额均读自配置文件；实时告警不依赖 LLM，DeepSeek 不可用
// 不影响本进程。退出码：0 正常（收到退出信号）；1 运行期错误；2 配置加载失败。
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modenc/e3-security-analyst/internal/collector"
	"github.com/modenc/e3-security-analyst/internal/config"
	"github.com/modenc/e3-security-analyst/internal/logging"
	"github.com/modenc/e3-security-analyst/internal/ntfy"
	"github.com/modenc/e3-security-analyst/internal/rules"
	"github.com/modenc/e3-security-analyst/internal/store"

	"github.com/modenc/e3-security-analyst/migrations"
)

// configEnvVar 覆盖默认配置路径（优先级：--config > 环境变量 > 内置默认）。
const configEnvVar = "E3_ANALYST_CONFIG"

func main() {
	os.Exit(run())
}

func run() int {
	configPath := flag.String("config", defaultConfigPath(), "配置文件路径")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		// 配置加载失败：stdout logger 尚不可用（日志级别未知），
		// 用 stderr 上的兜底 logger 记录后退出。
		boot, bootErr := logging.New("info", os.Stderr)
		if bootErr != nil {
			fmt.Fprintf(os.Stderr, "e3-collector: 加载配置 %s 失败: %v\n", *configPath, err)
			return 2
		}
		boot.Error("加载配置失败", "path", *configPath, "error", err)
		return 2
	}

	log, err := logging.New(cfg.App.LogLevel, os.Stdout)
	if err != nil {
		// cfg.Validate 已校验 log_level，此处不应到达；兜底按配置错误处理。
		fmt.Fprintf(os.Stderr, "e3-collector: 初始化日志失败: %v\n", err)
		return 2
	}
	log.Info("e3-collector 启动", "config", *configPath, "summary", cfg.Redacted())

	db, err := store.Open(cfg.Database.Path, store.Options{
		WAL:           cfg.Database.WAL,
		BusyTimeoutMs: cfg.Database.BusyTimeoutMs,
	})
	if err != nil {
		log.Error("打开数据库失败", "path", cfg.Database.Path, "error", err)
		return 1
	}
	defer func() { _ = db.Close() }()
	if err := db.Migrate(migrations.FS); err != nil {
		log.Error("数据库迁移失败", "path", cfg.Database.Path, "error", err)
		return 1
	}

	// ntfy：凭据只经环境变量注入（SPEC §12/§18），日志绝不输出其值。
	token := os.Getenv(cfg.Ntfy.TokenEnv)
	if token == "" {
		log.Warn("ntfy Token 未设置，以匿名模式继续（采集与入库不受影响，通知可能被服务端拒绝）",
			"token_env", cfg.Ntfy.TokenEnv)
	}
	client := ntfy.NewClient(ntfy.ClientConfig{
		BaseURL: cfg.Ntfy.BaseURL,
		Token:   token,
		Timeout: time.Duration(cfg.Ntfy.TimeoutSeconds) * time.Second,
	})
	publisher := ntfy.NewPublisher(client, db, cfg.Ntfy.MaxRetries, cfg.Ntfy.MaxMessageBytes, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var handler collector.EventHandler
	var digestDone chan struct{} // 非 nil 表示 digest goroutine 在运行
	if cfg.Alerts.Enabled {
		engine := rules.New(cfg, db, publisher, log)
		handler = engine
		digestDone = make(chan struct{})
		go runDigestLoop(ctx, engine,
			time.Duration(cfg.Alerts.DigestIntervalSec)*time.Second, log, digestDone)
		log.Info("实时告警已启用", "digest_interval_seconds", cfg.Alerts.DigestIntervalSec,
			"max_per_minute", cfg.Alerts.MaxPerMinute)
	} else {
		log.Info("实时告警未启用（alerts.enabled=false），仅采集入库")
	}
	// waitDigest 等待 digest goroutine 退出，避免其在 db.Close() 后仍访问数据库。
	waitDigest := func() {
		if digestDone != nil {
			stop() // 触发 ctx 取消
			<-digestDone
		}
	}

	col, err := collector.New(cfg, db, handler, log)
	if err != nil {
		waitDigest()
		log.Error("创建采集器失败", "error", err)
		return 1
	}
	log.Info("开始采集 Cowrie 日志", "log_path", cfg.Cowrie.LogPath,
		"follow_interval_ms", cfg.Cowrie.FollowInterval, "rotation_grace_ms", cfg.Cowrie.RotationGraceMS)

	runErr := col.Run(ctx)
	waitDigest()
	if runErr != nil {
		log.Error("采集器异常退出", "error", runErr)
		return 1
	}
	log.Info("e3-collector 正常退出")
	return 0
}

// defaultConfigPath 返回默认配置路径：E3_ANALYST_CONFIG 环境变量优先。
func defaultConfigPath() string {
	if p := strings.TrimSpace(os.Getenv(configEnvVar)); p != "" {
		return p
	}
	return "/etc/e3-security-analyst/config.yaml"
}

// runDigestLoop 按 interval 周期发送限流合并的告警汇总；错误只记日志，
// 不中断采集。ctx 取消时退出并关闭 done，保证与主流程的关库顺序安全。
func runDigestLoop(ctx context.Context, engine *rules.Engine, interval time.Duration, log *slog.Logger, done chan<- struct{}) {
	defer close(done)
	if interval <= 0 {
		interval = 15 * time.Minute // 配置已校验 [30,86400]s，此处仅为防御性兜底
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := engine.FlushDigest(ctx); err != nil {
				log.Warn("限流告警汇总发送失败，下个周期重试", "error", err)
			}
		}
	}
}
