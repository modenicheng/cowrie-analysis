# e3-security-analyst 包间接口契约

所有子代理实现必须严格遵守本文件中的签名与语义。修改契约需 orchestrator 批准。
时间约定：所有入库时间为 **UTC**，`time.Time` 之间传递；展示层转换为配置时区。

## internal/store （持久化层，唯一写入方为 collector；analyst 只读）

```go
type DB struct{ /* wraps *sql.DB */ }
type Options struct{ WAL bool; BusyTimeoutMs int }
func Open(path string, opt Options) (*DB, error)   // 建目录 0700、文件 0600、pragmas: journal_mode(WAL 可选), busy_timeout, foreign_keys, synchronous(NORMAL)
func (db *DB) Migrate(fsys fs.FS) error            // schema_migrations 表 + 按 .sql 文件名版本号顺序应用
func (db *DB) Close() error
func (db *DB) SQL() *sql.DB                        // 供 query 包使用

// —— 事件 ——
type Event struct {
    ID          int64
    EventID     string      // cowrie eventid
    EventTime   time.Time   // 事件时间（UTC）
    CollectedAt time.Time
    SrcIP       string
    SrcPort     int64
    Session     string
    Username    string
    Command     string      // cowrie.command.input 的 input 字段（原值，不脱敏）
    Filename    string
    Shasum      string
    DurationS   float64     // session.closed 的 duration
    Raw         string      // 原始 JSON 行，无损保留
}
type EventFilter struct {   // 查询条件；时间语义为 [Since, Until) 左闭右开
    Since, Until time.Time
    SrcIP, Session string
    EventIDs    []string
    Limit       int         // 上限由调用方钳制
    CursorID    int64       // events.id > CursorID，按 id 升序
}
func (db *DB) InsertEvents(ctx context.Context, evs []*Event) (inserted, duplicates int, err error)
// 事务内：按 raw 的 sha256 幂等插入（ON CONFLICT DO NOTHING）；
// 仅对真正新插入的事件更新 sessions 聚合（started_at 取最早、ended_at 最晚、
// login_attempts/successes、command_count、file_ops、duration_s 取 max）。
func (db *DB) CountEvents(ctx context.Context, f EventFilter) (int, error)

// —— 采集游标 / 健康 / 缺口 / 解析错误 ——
type Offset struct {
    FileKey, Path string   // FileKey = "dev:ino"（unix）/ "vol:index"（windows）
    Inode, Offset, FileSize, MtimeNS int64
    UpdatedAt time.Time
}
func (db *DB) SetOffset(ctx context.Context, o *Offset) error
func (db *DB) GetOffset(ctx context.Context, fileKey string) (*Offset, error) // 不存在返回 (nil, nil)
func (db *DB) ListOffsets(ctx context.Context) ([]*Offset, error)
type Health struct {
    LastReadAt, LastEventAt *time.Time
    LastError   string
    UpdatedAt   time.Time
}
func (db *DB) UpdateHealth(ctx context.Context, h *Health) error
func (db *DB) GetHealth(ctx context.Context) (*Health, error)
type Gap struct{ ID int64; Start, End time.Time; Reason string }
func (db *DB) AddGap(ctx context.Context, start, end time.Time, reason string) error
func (db *DB) GapsInRange(ctx context.Context, since, until time.Time) ([]Gap, error)
type ParseErrorRecord struct{ FilePath string; FileOffset int64; Raw, Err string; At time.Time }
func (db *DB) InsertParseError(ctx context.Context, pe *ParseErrorRecord) error
func (db *DB) CountParseErrors(ctx context.Context, since, until time.Time) (int, error)

// —— 通知 ——
type Notification struct {
    ID          int64
    DedupeKey   string // 稳定去重键（唯一约束），重试/重启不重复发送
    Kind        string // 如 alert.login_success / alert.login_failed / report.daily
    Topic, Title, Body, Tags string // Tags 为逗号分隔
    Attach      string // 外链附件 URL（X-Attach）；空则不携带（迁移 0003 新列）
    Markdown    bool   // 正文是否按 Markdown 发送（迁移 0003 新列）
    Priority    int    // ntfy 1..5
    Status      string // pending|sent|failed
    Attempts    int
    LastError   string
    MergedCount int    // 限流时被合并的附加事件数
    CreatedAt   time.Time
    SentAt, LastAttemptAt *time.Time
}
func (db *DB) EnqueueNotification(ctx context.Context, n *Notification) (existed bool, err error)
// 按 dedupe_key INSERT OR IGNORE；已存在时返回 existed=true 且不覆盖
func (db *DB) BumpNotification(ctx context.Context, dedupeKey string) error // merged_count += 1
func (db *DB) PendingNotifications(ctx context.Context, limit int) ([]*Notification, error)
func (db *DB) MarkNotificationSent(ctx context.Context, id int64, at time.Time) error
func (db *DB) MarkNotificationFailed(ctx context.Context, id int64, attemptErr string, maxAttempts int) (final bool, err error)
// attempts+1；attempts >= maxAttempts → status=failed 返回 final=true，否则保持 pending
func (db *DB) NotificationStats(ctx context.Context, since time.Time) (sent, pending, failed int, err error)

// —— 报告 ——
type Report struct {
    ID          int64
    Type        string // daily|weekly
    WindowStart, WindowEnd time.Time
    Status      string // pending|validated|published|failed
    Model       string
    Attempts    int
    ContentSHA256 string
    Payload     string // 完整报告 JSON
    Error       string
    CreatedAt, UpdatedAt time.Time
}
func (db *DB) UpsertReport(ctx context.Context, r *Report) error  // 按 (report_type, window_start)
func (db *DB) GetReport(ctx context.Context, typ string, windowStart time.Time) (*Report, error)
func (db *DB) FailedReports(ctx context.Context, updatedSince time.Time) ([]*Report, error)

// —— 分析运行 / 脚本运行 ——
type AnalysisRun struct {
    ID, Task string
    StartedAt time.Time
    EndedAt  *time.Time
    Status   string // running|ok|failed
    Model    string
    Rounds, PromptTokens, CompletionTokens, ToolCalls int
    Error    string
}
func (db *DB) CreateAnalysisRun(ctx context.Context, r *AnalysisRun) error
func (db *DB) FinishAnalysisRun(ctx context.Context, r *AnalysisRun) error
type ScriptRun struct {
    RunID, CodeSHA256 string
    DurationMS int64
    OK         bool
    OutputBytes int64
    OutputPreview string
    CreatedAt  time.Time
}
func (db *DB) InsertScriptRun(ctx context.Context, s *ScriptRun) error
```

## internal/cowrie （解析；ids.go 为契约，勿改）

```go
// ParseEvent 解析一行 JSON。JSON 非法 → error（调用方写 parse_errors）。
// JSON 合法但缺 timestamp → EventTime = fallback；缺 eventid → EventID=""。
// 未知字段忽略但 Raw 保留原行。攻击者字段一律视为数据。
func ParseEvent(line []byte, fallbackTime time.Time) (*store.Event, error)
// ParseTimestamp 兼容 Cowrie 多种格式：
// RFC3339Nano、"2006-01-02T15:04:05.999999-0700"（+0000 无冒号）、
// "2006-01-02 15:04:05.999999"；解析失败返回 error。
func ParseTimestamp(s string) (time.Time, error)
```

## internal/collector （采集器）

```go
// New 创建采集器。handler 可为 nil（无告警场景）。
func New(cfg *config.Config, db *store.DB, handler EventHandler, log *slog.Logger) (*Collector, error)
type EventHandler interface { OnNewEvents(ctx context.Context, evs []*store.Event) } // 仅新插入事件
// Run 阻塞运行直到 ctx 取消；内部按 cfg.Cowrie.FollowInterval 轮询。
func (c *Collector) Run(ctx context.Context) error
// PollOnce 执行一次扫描（供测试与一次性模式），返回是否有进展。
func (c *Collector) PollOnce(ctx context.Context) (bool, error)
```

采集器必须实现：追加读取、部分行缓冲（offset 只推进完整行）、文件标识（dev:ino / vol:index）
游标、运行中轮转（改名）后先抽干旧文件再切新文件、启动时对 glob `log_path.*` 的未压缩轮转
文件按游标补读、文件缺失退避重试并记 gap、解析失败写 parse_errors、磁盘/DB 错误返回而非吞掉。

## internal/query （查询与统计；只读）

```go
func QueryEvents(ctx context.Context, db *store.DB, f store.EventFilter) ([]*store.Event, error) // id 升序，最多 Limit 条
func CountEvents(ctx context.Context, db *store.DB, f store.EventFilter) (int, error)

type KV struct{ Value string `json:"value"`; Count int `json:"count"` }
type SrcIPStat struct {
    IP string `json:"ip"`
    Connections, LoginFailed, LoginSuccess, Commands, FileOps int
}
type FileArtifact struct{ Filename, Shasum, Direction string; Count int }
type PrevDelta struct {
    Connections, UniqueSrcIPs, LoginSuccess, LoginFailed, Commands int
    Window struct{ Since, Until time.Time }
}
type QualityInfo struct {
    ParseErrors int
    Gaps        []store.Gap
    LastEventAt, LastReadAt *time.Time
    LastCollectorError string
}
type Stats struct {
    Since, Until time.Time
    EventsTotal, Connections, UniqueSrcIPs, LoginSuccess, LoginFailed int
    TopSrcIPs    []SrcIPStat
    TopUsernames []KV   // 登录尝试用户名（原值）
    TopCommands  []KV   // 命令（原值）
    EventKinds   []KV   // eventid 分布
    SessionsTotal, SessionsWithCommands int
    AvgSessionSeconds, MaxSessionSeconds float64
    Uploads, Downloads, DownloadFailed int
    Artifacts   []FileArtifact
    Hourly, Daily []KV  // UTC 桶："2006-01-02T15" / "2006-01-02"
    // 分指标趋势桶（多序列折线图用），仅含计数>0 的桶，补零归展示层：
    HourlyConnections/HourlyLoginFailed/HourlyLoginSuccess/HourlyCommands []KV
    DailyConnections/DailyLoginFailed/DailyLoginSuccess/DailyCommands     []KV
    Prev  *PrevDelta    // 与紧邻前一个同长窗口比较；不足时为 nil
    Quality QualityInfo
}
func ComputeStats(ctx context.Context, db *store.DB, q StatsQuery) (*Stats, error)
type StatsQuery struct {
    Since, Until time.Time
    TopN        int  // 默认 10，上限 50
    WithPrev    bool // 是否计算上一周期对比
}
```

## internal/ntfy （客户端 + 发布队列）

```go
// Client 单次发布；重试策略由 Publisher 编排。
type ClientConfig struct{ BaseURL, Token string; Timeout time.Duration }
func NewClient(cfg ClientConfig) *Client
type Message struct{ Topic, Title, Body string; Priority int; Tags []string; Attach string; Markdown bool }
type PublishOutcome struct{ HTTPStatus int; ResponseID string; SentAt time.Time }
func (c *Client) Publish(ctx context.Context, m Message) (PublishOutcome, error)
// 2xx → nil error。4xx（除 429）不可重试；429/5xx/网络错误可重试。
// Attach 非空 → 发 X-Attach（须合法 http(s) URL、≤2048 字节，否则本地
// ValidationError）；Markdown=true → 发 "Markdown: yes"。两者缺席时行为不变。
func IsRetryable(err error) bool

// Publisher 持久化队列：入队去重、立即发送、失败留待重试。
func NewPublisher(client *Client, db *store.DB, maxAttempts int, maxMessageBytes int, log *slog.Logger) *Publisher
// Enqueue 写 notifications 表（dedupe）；若已存在且未发送 → BumpNotification 计数后返回 deduped。
func (p *Publisher) Enqueue(ctx context.Context, n *store.Notification) (deduped bool, err error)
// TrySend 立即尝试发送一条（含最多 maxAttempts 次内联重试与退避）。
func (p *Publisher) TrySend(ctx context.Context, n *store.Notification) error
// FlushPending 扫描 pending 并重试，返回 (sent, failedPermanent)。
func (p *Publisher) FlushPending(ctx context.Context) (int, int, error)
```

## internal/dogecloud （多吉云对象存储上传/清理；仅标准库）

```go
type Config struct {
    AccessKey, SecretKey string // 运行时从 doge.env 解析；绝不出现在日志/错误
    Bucket        string        // 标准型存储桶（低频型不支持 API 上传）
    PublicBaseURL string        // 直链域名，如 https://img-host.modenc.top
    KeyPrefix     string        // 如 "e3-reports/"
    APIBaseURL    string        // 留空 → https://api.dogecloud.com（测试注入用）
    RetentionDays int           // 桶内对象保留期；<=0 禁用清理
    Timeout       time.Duration // <=0 → 10s
}
func New(cfg Config, hc *http.Client) *Client
// FetchTmpToken 仅换取临时密钥（verify 自检，零副作用）：
// POST /auth/tmp_token.json，body {"channel":"OSS_UPLOAD","scopes":["<bucket>:*"]}，
// Authorization: TOKEN <AK>:<hex HMAC-SHA1(SK, path+"\n"+bodyJSON)>；
// 响应 data.Credentials（AccessKeyId/SecretAccessKey/SessionToken，兼容小写变体）
// + data.Buckets[0].s3Bucket/s3Endpoint。临时密钥 ≤2h，每次现换不缓存。
func (c *Client) FetchTmpToken(ctx context.Context) error
// NewKey 生成不可猜对象键：{KeyPrefix 规范尾斜杠}{kind}/{YYYYMMDD}-{crypto/rand 8 字节 hex}.png
func (c *Client) NewKey(kind string, since time.Time) string
// Upload：换临时密钥 → 对 s3Endpoint 发 SigV4 PUT（virtual-host 风格 bucket.host、
// region "auto"、签名头 host;x-amz-content-sha256;x-amz-date[;x-amz-security-token]）
// → 返回 PublicBaseURL 去尾斜杠 + "/" + key。不内置重试，失败即由调用方降级。
func (c *Client) Upload(ctx context.Context, key string, data []byte, contentType string) (publicURL string, err error)
// Prune：配置校验通过且 RetentionDays<=0 → (0, nil)（配置缺失时仍报错，不以禁用
// 掩盖）。LIST prefix=KeyPrefix 分页遍历，Last-Modified 早于 now-保留期 的对象逐个
// SigV4 DELETE；单对象失败记录后继续，返回成功删除数与首个遇到的删除错误。
// LIST 本身失败 → (0, err)。Last-Modified 无法解析的对象跳过不删（保守防误删）。
func (c *Client) Prune(ctx context.Context) (deleted int, err error)
```

约束：任何错误文本与包装链不得包含 SecretKey 或临时凭据值（可含 bucket/key/HTTP 状态码/endpoint host）。

## internal/chartimg （报告图表 PNG 渲染；新增依赖 wcharczuk/go-chart/v2，间接仅 golang/freetype 与 golang.org/x/image）

```go
func New(loc *time.Location) *Renderer // loc 为展示时区；nil → UTC
func (r *Renderer) Render(stats *query.Stats, kind string) ([]byte, error)
```

kind 仅接受 daily|weekly。输出单张合成 PNG（约 1000px 宽，双面板以 stdlib
image/draw 纵向拼接）：面板 A 多序列活动折线（connections/login_failed/
login_success/commands 四序列同框，来自 Hourly*/Daily* 分指标序列并
[Since,Until) 全区间补零；标题下列图例，全局峰值点标注数值）；面板 B
TopSrcIPs 前 10 横向条形图（值=Connections，为空时渲染 no-data 占位）。
图表文本全 ASCII（asciiSafe 清洗；v1 不内嵌 CJK 字体）。深色平色主题
（theme.go）。零事件窗口仍产出合法 PNG。

## internal/llm （OpenAI 兼容客户端，DeepSeek）

```go
type ClientConfig struct {
    BaseURL, Model, APIKey string
    Timeout       time.Duration // 单次 HTTP 总超时
    MaxToolRounds int           // 默认 6
    MaxOutputTokens int
    MaxTotalTokens  int         // 任务级累计 token 预算
    EnableTools   bool
}
func NewClient(cfg ClientConfig) *Client

type ToolSpec struct {
    Name, Description string
    ParametersJSON    []byte // JSON Schema
}
type ToolCall struct{ ID, Name, ArgsJSON string }
type ToolHandler func(ctx context.Context, call ToolCall) (resultJSON string, err error)

type RunRequest struct {
    SystemPrompt, UserPrompt string
    Tools    map[string]ToolSpec   // EnableTools=false 时忽略
    Handlers map[string]ToolHandler
    FinalMaxBytes int              // 最终输出字节上限（0=默认 64KiB）
}
type RunResult struct {
    Content        []byte // 最终模型输出（已剥 markdown 代码栅栏的 JSON 文本）
    Rounds, ToolCalls int
    PromptTokens, CompletionTokens int
}
// 错误类型（errors.Is 判定）：
//   ErrNoAPIKey / ErrTimeout / ErrInvalidResponse / ErrToolRoundsExceeded /
//   ErrTokenBudgetExceeded / HTTPStatusError{Code int, RetryAfter time.Duration} / ToolError
func (c *Client) Run(ctx context.Context, req RunRequest) (RunResult, error)
```

Run 行为：429/5xx/网络错误按指数退避重试（默认 3 次，尊重 Retry-After）；
工具调用循环直到 finish_reason != tool_calls 或超过 MaxToolRounds（返回
ErrToolRoundsExceeded，不无限循环）；工具 handler 错误以 JSON 结果回传模型而非中断；
EnableTools=false 时单轮请求 + response_format json_object（提示词需含 "json" 字样）。

## internal/sandbox （Goja 受限执行）+ cmd/script-runner

```go
type Limits struct{ TimeoutMS int; MaxInputBytes, MaxOutputBytes int64 }
// RunCode 在当前进程内受限执行（script-runner 二进制复用）。
// 全局环境只暴露 input 与 JS 标准内建；不注册任何宿主函数。
// 超时用 vm.Interrupt 中断；recover panic；输出序列化后超限报错。
func RunCode(code string, input any, timeoutMS int, maxOutputBytes int64) (out []byte, errType, errMsg string, durationMS int64)

// Runner 通过独立子进程执行 cmd/script-runner（隔离进程边界）。
type Runner struct{ /* path, limits, 并发信号量 */ }
func NewRunner(path string, limits Limits, maxConcurrency int) *Runner
// Execute：子进程 Env 置空（绝不继承任何凭据），stdin 传任务 JSON，
// stdout 收结果；超时（timeout+2s 宽限）杀进程。结果超限报结构化错误。
func (r *Runner) Execute(ctx context.Context, code string, input any, timeoutMS int) (*Result, error)
type Result struct {
    OK        bool
    Result    json.RawMessage
    ErrorType, ErrorMessage string
    DurationMS int64
}
// 任务 JSON（stdin）：{"code":string,"input":any,"timeout_ms":int}
// 结果 JSON（stdout）：{"ok":bool,"result":any|null,"error":{"type","message"}|null,"duration_ms":int}
// 子进程 exit 0 表示任务被执行（含脚本错误）；exit 2 表示输入超限等基础设施错误。
```

## internal/rules （确定性告警引擎，不依赖 LLM）

```go
func New(cfg *config.Config, db *store.DB, pub *ntfy.Publisher, log *slog.Logger) *Engine
func (e *Engine) OnNewEvents(ctx context.Context, evs []*store.Event) // 分类→去重→限流→Enqueue+TrySend
func (e *Engine) FlushDigest(ctx context.Context) error               // 周期性合并汇总
```

规则（§10）：login.success 立即高优（dedupe: session）；file_upload/download 立即
（dedupe: session+shasum/filename）；login.failed 按 src_ip 时间窗聚合（阈值触发，
之后按 repeat_every 递进）；command 每会话首条告警（依据 sessions.command_count==0）；
connect 只计数，超阈值发高频汇总。全局每分钟上限 max_per_minute，超出部分 Bump 合并，
由 FlushDigest 按 digest_interval 汇总发送。所有消息含时间/源IP/事件类型/会话ID/说明，
且 login.success 文案必须注明"蜜罐模拟登录成功，非真实系统失陷"。

## internal/tools （模型工具调度）

```go
type TaskWindow struct{ Since, Until time.Time; Type, RunID string } // Type: daily|weekly; RunID: analysis_runs.id，供 script_runs 审计关联
type ReportSubmitter interface {
    // 校验通过收下草稿（返回 accepted=true）；否则给出模型可读的拒绝原因。
    SubmitDraft(ctx context.Context, draft []byte, taskType string) (bool, string)
}
func NewDispatcher(cfg *config.Config, db *store.DB, runner *sandbox.Runner, submitter ReportSubmitter, log *slog.Logger) *Dispatcher
func (d *Dispatcher) Specs() []llm.ToolSpec                  // query_events/query_stats/execute_js/submit_report
func (d *Dispatcher) Handle(ctx context.Context, call llm.ToolCall, win TaskWindow) (string, error)
func TrimEvent(cfg *config.Config, e *store.Event) map[string]any // §9/§13 字段裁剪矩阵的唯一实现，query_events 输出与 reports 关键事件注入共用
func TruncateRunes(s string, max int) string               // rune 截断（不补省略号），query_events message 与 reports 通知摘要共用
```

query_events：强制 since/until（默认任务窗口）、跨度 ≤ cfg.Reports.MaxQuerySpanDays、
limit ≤ 1000、序列化后字节 ≤ 256KiB（超出截断并置 truncated=true + next_cursor）；
按 include_source_ips/paths/commands/llm.include_passwords 剪裁字段。
query_stats：调用 query.ComputeStats，数值必须来自 SQL。
execute_js：runner 不为 nil 时可用；记录 script_runs；并发受信号量限制。
submit_report：仅接受固定字段，type 必须等于任务窗口 Type，长度受校验，交 ReportSubmitter。

## internal/reports （报告生成）

```go
func WindowFor(kind string, now time.Time, loc *time.Location) (since, until time.Time, err error)
// ↑ 已由 internal/scheduler 实现（scheduler.WindowFor / scheduler.PrevWindow）

type Generator struct{ /* cfg, db, llm, dispatcher, pub, imager, log */ }
// NewGenerator 内部自行创建 tools.Dispatcher（submitter 为 Generator 自身的草稿校验器）。
// runner 为 nil 或 cfg.ScriptRunner.Enabled=false 时 execute_js 不可用。
// runner 由调用方传入；二进制缺失或禁用时由 cmd/analyst 先降级为 nil 并 Warn 再构造。
// imager 为 nil 时无图表（现行为）；具体适配器由 cmd/analyst 用 dogecloud.Client +
// chartimg.Renderer 组装——reports 包不直接依赖这两个包。SetImager/SetNotifyMarkdown
// 必须在首次 Generate 前调用（NotifyMarkdown 默认 true，来自 cfg.Ntfy.Markdown）。
type ReportImager interface {
    Render(stats *query.Stats, kind string, since, until time.Time) ([]byte, error)
    Upload(ctx context.Context, kind string, since time.Time, png []byte) (key, publicURL string, err error)
    Prune(ctx context.Context) error
}
func NewGenerator(cfg *config.Config, db *store.DB, client *llm.Client,
    runner *sandbox.Runner, pub *ntfy.Publisher, log *slog.Logger) (*Generator, error)
func (g *Generator) SetImager(imager ReportImager)
func (g *Generator) SetNotifyMarkdown(v bool)
func (g *Generator) Generate(ctx context.Context, kind string) error
// 图表步骤（imager 非 nil 且 report_image.enabled）：草稿校验后 render→upload→prune，
// 任一失败仅 log.Warn 并降级为纯文本通知，不影响报告状态机；payload 增可选 image 块
// {url,key,sha256,bytes,generated_at}；归档目录写 {kind}-{YYYYMMDD}.png 副本（0600）；
// 通知 Attach=直链、Markdown 按 cfg.Ntfy.Markdown。纯文本正文路径保持逐字节不变。
// Markdown 变体的 summary/finding 标题经 escapeCommonMark 转义（先 \ 后 [、<，
// severity 已枚举校验不转义）——回显的攻击者内容无法组成链接/图片/自动链接。
// CleanupArchives 按文件名内嵌日期轮转归档目录 .json/.png（0 禁用），由 daemon 每日调用。
func CleanupArchives(dir string, retentionDays int, now time.Time) error
// 流程（§8.1）：算窗口→SQL统计→关键事件→LLM（带工具）→submit_report 校验
// （key_stats 必须与 SQL 统计一致，否则拒绝并让模型修正一轮）→归档
// state_dir/reports/YYYY/MM/daily-20060102.json（紧凑日期，周报 weekly-YYYYMMDD.json）+ reports 表 + ntfy 发布。
// 数据缺口（gaps/停滞）必须写入报告 data_quality，不得掩盖。
// 失败：reports.status=failed + analysis_runs 记录错误，不发送报告通知。
```

## cmd 二进制

- `cmd/collector`：加载配置 → store.Open+Migrate → rules engine（alerts.enabled）→ collector.Run。
- `cmd/analyst`：子命令 `report --type daily|weekly`（oneshot，systemd timer 触发）、
  `daemon`（常驻：每 30s FlushPending 通知 + 每 10min 重试失败报告 + 每日
  CleanupArchives 归档轮转）、`verify`（配置/环境自检；report_image.enabled 时
  含多吉云临时密钥换取检查）。report_image.enabled 且密钥 env 缺失时启动即报错。
- `cmd/script-runner`：stdin 任务 JSON → sandbox.RunCode → stdout 结果 JSON（见 internal/sandbox）。
