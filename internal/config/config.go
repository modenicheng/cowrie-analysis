// Package config 加载并校验 YAML 配置。
// 安全约束：密钥只通过 *_env 字段引用环境变量名，配置文件中不出现真实凭据；
// 日志中不得输出任何环境变量的解析值。
package config

import (
	_ "embed"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	_ "time/tzdata"

	"gopkg.in/yaml.v3"

	"github.com/modenc/e3-security-analyst/internal/logging"
)

// Config 全量配置。字段与 configs/config.example.yaml 一一对应。
type Config struct {
	App struct {
		Timezone string `yaml:"timezone"`
		StateDir string `yaml:"state_dir"`
		LogLevel string `yaml:"log_level"`
		// RetentionDays 是数据保留期（天）：analyst daemon 启动时与每 24h
		// 按服务侧入库时间清理超过保留期的 events（含 raw 原文）、sessions、
		// parse_errors、collector_gaps 与已发送的 notifications，防止攻击者
		// 高频灌唯一事件耗尽磁盘。0 = 禁用清理（保持旧行为）。
		RetentionDays int `yaml:"retention_days"`
	} `yaml:"app"`

	Cowrie struct {
		LogPath         string `yaml:"log_path"`
		Follow          bool   `yaml:"follow"`
		PreserveRaw     bool   `yaml:"preserve_raw"`
		FollowInterval  int    `yaml:"follow_interval_ms"`
		RotationGraceMS int    `yaml:"rotation_grace_ms"`
	} `yaml:"cowrie"`

	Database struct {
		Path          string `yaml:"path"`
		WAL           bool   `yaml:"wal"`
		BusyTimeoutMs int    `yaml:"busy_timeout_ms"`
	} `yaml:"database"`

	LLM struct {
		BaseURL        string `yaml:"base_url"`
		Model          string `yaml:"model"`
		APIKeyEnv      string `yaml:"api_key_env"`
		TimeoutSeconds int    `yaml:"timeout_seconds"`
		// MaxToolRounds 是工具调用轮数软上限：超出后每个后续轮次向模型
		// 注入收尾提示（尽快 submit_report），但不阻断工具调用。
		MaxToolRounds int `yaml:"max_tool_rounds"`
		// HardToolRounds 是工具调用轮数硬上限：到达后由 LLM 客户端发起
		// 一次不带 tools 的最终补全强制收稿。必须 >= MaxToolRounds。
		HardToolRounds  int    `yaml:"hard_tool_rounds"`
		MaxOutputTokens int    `yaml:"max_output_tokens"`
		MaxTotalTokens  int    `yaml:"max_total_tokens"`
		EnableTools     bool   `yaml:"enable_tools"`
		Thinking        string `yaml:"thinking"`         // auto|on|off，auto=不干预
		ReasoningEffort string `yaml:"reasoning_effort"` // ""|low|medium|high|max，""=不干预
		// IncludePasswords 控制是否把登录尝试中的 password 字段提交给模型（§9）。
		IncludePasswords bool `yaml:"include_passwords"`
	} `yaml:"llm"`

	ScriptRunner struct {
		Enabled        bool   `yaml:"enabled"`
		RunnerPath     string `yaml:"runner_path"`
		TimeoutMS      int    `yaml:"timeout_ms"`
		MaxInputBytes  int64  `yaml:"max_input_bytes"`
		MaxOutputBytes int64  `yaml:"max_output_bytes"`
		MaxConcurrency int    `yaml:"max_concurrency"`
	} `yaml:"script_runner"`

	Ntfy struct {
		BaseURL         string `yaml:"base_url"`
		Topic           string `yaml:"topic"`
		AlertTopic      string `yaml:"alert_topic"`
		ReportTopic     string `yaml:"report_topic"`
		TokenEnv        string `yaml:"token_env"`
		TimeoutSeconds  int    `yaml:"timeout_seconds"`
		MaxRetries      int    `yaml:"max_retries"`
		MaxMessageBytes int    `yaml:"max_message_bytes"`
	} `yaml:"ntfy"`

	Alerts struct {
		Enabled                bool `yaml:"enabled"`
		MaxPerMinute           int  `yaml:"max_per_minute"`
		LoginFailedWindowSec   int  `yaml:"login_failed_window_seconds"`
		LoginFailedThreshold   int  `yaml:"login_failed_threshold"`
		LoginFailedRepeatEvery int  `yaml:"login_failed_repeat_every"`
		DigestIntervalSec      int  `yaml:"digest_interval_seconds"`
	} `yaml:"alerts"`

	Reports struct {
		DailyEnabled     bool   `yaml:"daily_enabled"`
		WeeklyEnabled    bool   `yaml:"weekly_enabled"`
		IncludeSourceIPs bool   `yaml:"include_source_ips"`
		IncludePaths     bool   `yaml:"include_paths"`
		IncludeCommands  bool   `yaml:"include_commands"`
		Dir              string `yaml:"dir"`
		MaxQuerySpanDays int    `yaml:"max_query_span_days"`
	} `yaml:"reports"`
}

var (
	topicRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	envNameRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

// Default 返回填好默认值的配置。
func Default() *Config {
	c := &Config{}
	c.App.Timezone = "Asia/Shanghai"
	c.App.StateDir = "/var/lib/e3-security-analyst"
	c.App.LogLevel = "info"
	c.App.RetentionDays = 90

	c.Cowrie.LogPath = "/var/log/cowrie/cowrie.json"
	c.Cowrie.Follow = true
	c.Cowrie.PreserveRaw = true
	c.Cowrie.FollowInterval = 500
	c.Cowrie.RotationGraceMS = 2000

	c.Database.Path = "/var/lib/e3-security-analyst/events.db"
	c.Database.WAL = true
	c.Database.BusyTimeoutMs = 5000

	c.LLM.BaseURL = "https://api.deepseek.com"
	c.LLM.Model = "deepseek-chat"
	c.LLM.APIKeyEnv = "DEEPSEEK_API_KEY"
	c.LLM.TimeoutSeconds = 90
	c.LLM.MaxToolRounds = 8
	c.LLM.HardToolRounds = 24
	c.LLM.MaxOutputTokens = 65536
	c.LLM.MaxTotalTokens = 200000
	c.LLM.EnableTools = true
	c.LLM.Thinking = "auto"
	c.LLM.ReasoningEffort = ""
	c.LLM.IncludePasswords = false

	c.ScriptRunner.Enabled = true
	c.ScriptRunner.RunnerPath = "/usr/local/bin/e3-script-runner"
	c.ScriptRunner.TimeoutMS = 2000
	c.ScriptRunner.MaxInputBytes = 1 << 20
	c.ScriptRunner.MaxOutputBytes = 256 << 10
	c.ScriptRunner.MaxConcurrency = 1

	c.Ntfy.BaseURL = "https://notify.modenc.top"
	c.Ntfy.Topic = "change-me"
	c.Ntfy.TokenEnv = "NTFY_TOKEN"
	c.Ntfy.TimeoutSeconds = 10
	c.Ntfy.MaxRetries = 5
	c.Ntfy.MaxMessageBytes = 4000

	c.Alerts.Enabled = true
	c.Alerts.MaxPerMinute = 10
	c.Alerts.LoginFailedWindowSec = 300
	c.Alerts.LoginFailedThreshold = 10
	c.Alerts.LoginFailedRepeatEvery = 50
	c.Alerts.DigestIntervalSec = 900

	c.Reports.DailyEnabled = true
	c.Reports.WeeklyEnabled = true
	c.Reports.IncludeSourceIPs = true
	c.Reports.IncludePaths = true
	c.Reports.IncludeCommands = true
	c.Reports.MaxQuerySpanDays = 31
	return c
}

// Load 读取 YAML 配置文件。未知字段视为错误；文件值覆盖默认值后统一校验。
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件: %w", err)
	}
	c := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("解析配置文件 %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("配置校验失败: %w", err)
	}
	return c, nil
}

func inRange(v, lo, hi int, name string) error {
	if v < lo || v > hi {
		return fmt.Errorf("%s=%d 超出允许范围 [%d,%d]", name, v, lo, hi)
	}
	return nil
}

// checkHTTPURL 要求 https；仅允许回环地址使用 http（便于本地测试）。
func checkHTTPURL(raw, name string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s 不是合法 URL: %w", name, err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("%s 使用 http 但主机 %s 不是回环地址，必须使用 https", name, host)
	default:
		return fmt.Errorf("%s 必须是 http(s) URL，当前 scheme=%s", name, u.Scheme)
	}
}

func checkEnvName(name, field string) error {
	if !envNameRe.MatchString(name) {
		return fmt.Errorf("%s=%q 不是合法的环境变量名（大写字母开头，仅含大写字母/数字/下划线）", field, name)
	}
	return nil
}

// Validate 校验必填字段、URL、时间范围和资源限制。
func (c *Config) Validate() error {
	if c.App.Timezone == "" {
		return fmt.Errorf("app.timezone 不能为空")
	}
	if _, err := time.LoadLocation(c.App.Timezone); err != nil {
		return fmt.Errorf("app.timezone=%q 无法加载: %w", c.App.Timezone, err)
	}
	if c.App.StateDir == "" {
		return fmt.Errorf("app.state_dir 不能为空")
	}
	if _, err := logging.ParseLevel(c.App.LogLevel); err != nil {
		return err
	}
	if err := inRange(c.App.RetentionDays, 0, 3650, "app.retention_days"); err != nil {
		return err
	}

	if c.Cowrie.LogPath == "" {
		return fmt.Errorf("cowrie.log_path 不能为空（需按实际部署调整 Cowrie JSONL 路径）")
	}
	if err := inRange(c.Cowrie.FollowInterval, 50, 60000, "cowrie.follow_interval_ms"); err != nil {
		return err
	}
	if err := inRange(c.Cowrie.RotationGraceMS, 0, 60000, "cowrie.rotation_grace_ms"); err != nil {
		return err
	}

	if c.Database.Path == "" {
		return fmt.Errorf("database.path 不能为空")
	}
	if err := inRange(c.Database.BusyTimeoutMs, 100, 60000, "database.busy_timeout_ms"); err != nil {
		return err
	}

	if err := checkHTTPURL(c.LLM.BaseURL, "llm.base_url"); err != nil {
		return err
	}
	if c.LLM.Model == "" {
		return fmt.Errorf("llm.model 不能为空")
	}
	if err := checkEnvName(c.LLM.APIKeyEnv, "llm.api_key_env"); err != nil {
		return err
	}
	if err := inRange(c.LLM.TimeoutSeconds, 5, 600, "llm.timeout_seconds"); err != nil {
		return err
	}
	if err := inRange(c.LLM.MaxToolRounds, 1, 64, "llm.max_tool_rounds"); err != nil {
		return err
	}
	if err := inRange(c.LLM.HardToolRounds, 1, 64, "llm.hard_tool_rounds"); err != nil {
		return err
	}
	if c.LLM.HardToolRounds < c.LLM.MaxToolRounds {
		return fmt.Errorf("llm.hard_tool_rounds=%d 必须 >= llm.max_tool_rounds=%d（硬上限不能低于软上限）",
			c.LLM.HardToolRounds, c.LLM.MaxToolRounds)
	}
	if err := inRange(c.LLM.MaxOutputTokens, 256, 131072, "llm.max_output_tokens"); err != nil {
		return err
	}
	if err := inRange(c.LLM.MaxTotalTokens, 10000, 10000000, "llm.max_total_tokens"); err != nil {
		return err
	}
	switch c.LLM.Thinking {
	case "auto", "on", "off":
	default:
		return fmt.Errorf("llm.thinking=%q 不合法，允许值：auto（默认，不发送该字段）|on（thinking.type=enabled）|off（thinking.type=disabled）",
			c.LLM.Thinking)
	}
	switch c.LLM.ReasoningEffort {
	case "", "low", "medium", "high", "max":
	default:
		return fmt.Errorf("llm.reasoning_effort=%q 不合法，允许值：留空（默认，不发送该字段）|low|medium|high|max",
			c.LLM.ReasoningEffort)
	}

	if c.ScriptRunner.Enabled {
		if c.ScriptRunner.RunnerPath == "" {
			return fmt.Errorf("script_runner.runner_path 不能为空")
		}
		if err := inRange(c.ScriptRunner.TimeoutMS, 100, 30000, "script_runner.timeout_ms"); err != nil {
			return err
		}
		if c.ScriptRunner.MaxInputBytes <= 0 || c.ScriptRunner.MaxInputBytes > 8<<20 {
			return fmt.Errorf("script_runner.max_input_bytes=%d 超出范围 (0, 8MiB]", c.ScriptRunner.MaxInputBytes)
		}
		if c.ScriptRunner.MaxOutputBytes <= 0 || c.ScriptRunner.MaxOutputBytes > 2<<20 {
			return fmt.Errorf("script_runner.max_output_bytes=%d 超出范围 (0, 2MiB]", c.ScriptRunner.MaxOutputBytes)
		}
		if err := inRange(c.ScriptRunner.MaxConcurrency, 1, 8, "script_runner.max_concurrency"); err != nil {
			return err
		}
	}

	if err := checkHTTPURL(c.Ntfy.BaseURL, "ntfy.base_url"); err != nil {
		return err
	}
	if !topicRe.MatchString(c.Ntfy.Topic) {
		return fmt.Errorf("ntfy.topic=%q 不合法（仅允许字母/数字/下划线/连字符，长度 1-64）", c.Ntfy.Topic)
	}
	for topic, name := range map[string]string{
		c.Ntfy.AlertTopic: "ntfy.alert_topic", c.Ntfy.ReportTopic: "ntfy.report_topic",
	} {
		if topic != "" && !topicRe.MatchString(topic) {
			return fmt.Errorf("%s=%q 不合法", name, topic)
		}
	}
	if err := checkEnvName(c.Ntfy.TokenEnv, "ntfy.token_env"); err != nil {
		return err
	}
	if err := inRange(c.Ntfy.TimeoutSeconds, 1, 120, "ntfy.timeout_seconds"); err != nil {
		return err
	}
	if err := inRange(c.Ntfy.MaxRetries, 0, 20, "ntfy.max_retries"); err != nil {
		return err
	}
	if c.Ntfy.MaxMessageBytes < 500 || c.Ntfy.MaxMessageBytes > 4096 {
		return fmt.Errorf("ntfy.max_message_bytes=%d 超出范围 [500,4096]", c.Ntfy.MaxMessageBytes)
	}

	if c.Alerts.Enabled {
		if err := inRange(c.Alerts.MaxPerMinute, 1, 1000, "alerts.max_per_minute"); err != nil {
			return err
		}
		if err := inRange(c.Alerts.LoginFailedWindowSec, 10, 86400, "alerts.login_failed_window_seconds"); err != nil {
			return err
		}
		if err := inRange(c.Alerts.LoginFailedThreshold, 1, 100000, "alerts.login_failed_threshold"); err != nil {
			return err
		}
		if err := inRange(c.Alerts.LoginFailedRepeatEvery, 1, 100000, "alerts.login_failed_repeat_every"); err != nil {
			return err
		}
		if err := inRange(c.Alerts.DigestIntervalSec, 30, 86400, "alerts.digest_interval_seconds"); err != nil {
			return err
		}
	}

	if err := inRange(c.Reports.MaxQuerySpanDays, 1, 366, "reports.max_query_span_days"); err != nil {
		return err
	}
	return nil
}

// Location 返回配置时区。
func (c *Config) Location() (*time.Location, error) {
	return time.LoadLocation(c.App.Timezone)
}

// ReportsDir 报告归档目录，默认 state_dir/reports。
func (c *Config) ReportsDir() string {
	if c.Reports.Dir != "" {
		return c.Reports.Dir
	}
	return c.App.StateDir + string(os.PathSeparator) + "reports"
}

// AlertTopic 实时告警主题，未配置时退回主主题。
func (c *Config) AlertTopic() string {
	if c.Ntfy.AlertTopic != "" {
		return c.Ntfy.AlertTopic
	}
	return c.Ntfy.Topic
}

// ReportTopic 报告主题，未配置时退回主主题。
func (c *Config) ReportTopic() string {
	if c.Ntfy.ReportTopic != "" {
		return c.Ntfy.ReportTopic
	}
	return c.Ntfy.Topic
}

// redactURL 剥离 URL 中的 userinfo（https://user:pass@host → https://host），
// 防止嵌入 base_url 的凭据随 Redacted 摘要进入 journald；解析失败时原样返回。
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = nil
	return u.String()
}

// Redacted 返回用于日志的脱敏摘要：只展示密钥的环境变量名，绝不展示解析值；
// llm/ntfy base_url 打印前剥离 URL userinfo。
func (c *Config) Redacted() string {
	return fmt.Sprintf("config{timezone=%s state_dir=%s db=%s llm=%s model=%s key_env=%s ntfy=%s token_env=%s topic=%s}",
		c.App.Timezone, c.App.StateDir, c.Database.Path, redactURL(c.LLM.BaseURL), c.LLM.Model,
		c.LLM.APIKeyEnv, redactURL(c.Ntfy.BaseURL), c.Ntfy.TokenEnv, c.Ntfy.Topic)
}
