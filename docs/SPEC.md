# E3 Security Analyst — 安全分析 Agent 开发规格（v0.1）

目标平台：Ubuntu 24.04 LTS；开发语言：Go；脚本运行时：Goja（JavaScript）；
数据存储：SQLite + 原始 JSONL 日志；LLM：DeepSeek API；通知：自建 ntfy 服务；
部署方式：原生 systemd + 独立受限脚本运行容器。

## 1. 项目目标

开发一个面向 Cowrie 蜜罐的轻量级安全分析 Agent，运行在 E3 服务器上。该程序负责读取 Cowrie 日志、分析攻击行为、生成安全日报和周报，并通过现有 ntfy 服务发送通知。

项目不仅是定时调用 LLM 生成摘要的脚本，还应提供受控的脚本执行能力，让 Agent 根据任务编写 JavaScript，查询日志、统计指标、关联会话并形成分析结论。

系统应满足以下要求：

1. 支持持续读取 Cowrie JSONL 日志，正确处理追加写入、文件轮转、重复事件和进程重启。
2. 保留原始日志，完整保留源 IP、时间戳、命令、路径、用户名、会话 ID、文件名等分析字段，不做统一脱敏。
3. 提供结构化事件查询和统计接口，支持按时间、来源 IP、会话、事件类型等条件检索。
4. 接入 DeepSeek API，支持多轮工具调用及结构化输出；模型接口和模型名称均可配置。
5. 提供 Goja JavaScript 执行环境，支持基于查询结果编写自定义分析逻辑。
6. 支持实时告警、每日安全日报、每周安全周报。
7. 通过 ntfy 发送消息，支持认证、失败重试、去重和限流。
8. 原始数据、模型调用、脚本执行、报告发送彼此隔离，避免模型生成的代码直接获得宿主机权限。
9. 任何任务失败都应留下可诊断的日志，不得静默丢失事件或重复发送报告。

本项目只实现分析 Agent，不负责 Cowrie 本身的安装、SSH 端口切换或宿主机防火墙配置。

## 2. 当前运行环境

目标主机为 E3，运行 Ubuntu 24.04 LTS，具备 Go/Python 开发环境所需的基础条件，当前已安装 Docker，且可以通过 HTTPS 访问公网 ntfy 服务。

现有服务包括 SSH、Nginx、PostgreSQL、Redis 及其他业务。Agent 不得修改这些服务的配置，也不得默认以 root 身份运行。

现有 ntfy 地址：`https://notify.modenc.top`

所有服务地址、主题、Token、API Key 和日志路径必须由配置文件或环境变量提供，禁止硬编码凭据。

## 3. 总体架构

```text
Cowrie JSONL 日志
        |
        v
  Log Collector
        |
        +----> 原始日志归档
        |
        v
   Event Store
   SQLite 数据库
        |
        +---------------------+
        |                     |
        v                     v
 Realtime Alert          Report Scheduler
        |                     |
        |                     v
        |                Security Analyst
        |                     |
        |                 DeepSeek API
        |                     |
        |                 Tool Dispatcher
        |                     |
        |                JavaScript Runner
        |                     |
        +----------+----------+
                   |
                   v
             Report Validator
                   |
                   v
              ntfy Publisher
```

各组件职责必须明确：

- Collector：读取日志、校验事件格式、记录采集位置、写入数据库。
- Event Store：提供持久化事件数据、查询和统计。
- Alert Engine：基于确定性规则识别需要即时通知的事件。
- Analyst：调用 DeepSeek，组织分析任务和工具调用。
- Script Runner：运行受限 JavaScript，只能使用明确提供的数据与接口。
- Scheduler：触发日报和周报。
- Publisher：负责消息格式校验、去重、重试及 ntfy 发布。

实时告警不依赖 LLM。即使 DeepSeek API 不可用，采集、确定性规则和本地事件存储仍须正常工作。

## 4. 推荐项目结构

```text
e3-security-analyst/
├── cmd/
│   ├── analyst/
│   │   └── main.go
│   ├── collector/
│   │   └── main.go
│   └── script-runner/
│       └── main.go
├── internal/
│   ├── config/
│   ├── cowrie/
│   ├── collector/
│   ├── store/
│   ├── query/
│   ├── rules/
│   ├── llm/
│   ├── tools/
│   ├── sandbox/
│   ├── scheduler/
│   ├── reports/
│   ├── ntfy/
│   ├── security/
│   └── logging/
├── prompts/
│   ├── analyst.md
│   ├── daily-report.md
│   └── weekly-report.md
├── migrations/
├── deploy/
│   ├── analyst.service
│   ├── collector.service
│   ├── daily-report.service
│   ├── daily-report.timer
│   ├── weekly-report.service
│   └── weekly-report.timer
├── configs/
│   └── config.example.yaml
├── scripts/
├── tests/
├── go.mod
├── go.sum
└── README.md
```

可将 `collector` 和 `analyst` 合并为同一个程序，但应保留清晰的模块边界。生产环境优先使用独立进程，避免一次模型调用阻塞日志采集。

## 5. 技术选型

### 5.1 Go

Go 负责：systemd 服务入口与调度、HTTP API 调用、JSONL 日志读取、SQLite 事务及查询、事件规则匹配、LLM 工具调用循环、报告生成和 ntfy 发布、超时、重试、日志和错误处理。

优先使用标准库，依赖应少而明确。SQLite 可采用 `modernc.org/sqlite`，避免强制依赖 CGO。Goja 及 SQLite 依赖必须固定版本，并记录在 `go.mod` 中。

### 5.2 Goja

Goja 用于运行由 Agent 生成或选择的 JavaScript 分析代码。

脚本可以完成：分组统计和趋势计算、跨会话行为关联、对给定事件集合进行模式匹配、对预定义指标进行二次计算、生成结构化分析结果。

脚本不得直接访问文件系统、环境变量、网络、系统命令或 Go 运行时内部对象。

重要：Goja 不是完整安全沙箱。JavaScript 运行时必须放在独立低权限进程或受限容器内，配置 CPU 时间、内存、进程数及输出大小限制。不能仅依靠隐藏 `os` 或 `fs` 对象来宣称安全。

### 5.3 SQLite

SQLite 是事件索引、统计结果、采集游标、告警状态和报告元数据的存储层。

建议开启 WAL，配置合理的 busy timeout。数据库应存放在独立目录，限制文件权限。只有 Collector 拥有事件写入权限，报告分析使用只读查询接口。

## 6. 日志采集与事件模型

### 6.1 输入格式

输入是 Cowrie 生成的 JSONL 文件，每行一条 JSON 事件。

日志路径由 `cowrie.log_path` 配置，不得假设所有 Cowrie 镜像都采用同一个路径。上线时应根据实际容器挂载目录确认文件位置。

至少支持以下字段（具体事件可能缺少其中部分字段）：`eventid`、`timestamp`、`session`、`src_ip`、`src_port`、`username`、`password`、`input`、`message`、`outfile`、`shasum`。

必须兼容额外字段。未知字段不能导致事件被丢弃。

事件 ID 和字段语义应以实际运行的 Cowrie 版本为准。不要为了匹配预设结构而丢弃原始 JSON。

### 6.2 采集要求

Collector 必须处理：

1. 文件持续追加。
2. 文件暂时不存在。
3. JSON 行尚未写完整。
4. 文件轮转和重命名。
5. 程序异常退出及重启。
6. 重复事件。
7. 磁盘空间不足。
8. 无权限读取日志。
9. SQLite 写入失败。

使用文件设备号/inode 与读取偏移量记录采集位置，必要时结合事件哈希实现幂等去重。文件轮转后必须继续追踪旧文件剩余数据并发现新文件。

不能仅使用文件名作为游标，因为轮转后同名文件可能对应新的 inode。

每个原始事件应保留原始 JSON 文本或等价的无损数据，另行解析标准字段。原始日志不得由 Agent 修改。

对于无法解析的 JSON 行，将原文写入隔离错误记录，保留文件名、偏移量、时间及错误原因；不要静默跳过。

### 6.3 SQLite 表

至少实现以下表：`events`、`sessions`、`collector_offsets`、`notifications`、`reports`、`analysis_runs`、`script_runs`。

对 `events.timestamp`、`events.src_ip`、`events.eventid`、`events.session` 建立适合查询模式的索引。

不要将所有事件一次性载入内存。分页查询并对结果条数和时间跨度设置上限。

## 7. Agent 工具接口

模型不能直接操作 SQLite、文件系统或 HTTP。它只能通过 Agent Host 提供的工具访问数据。

### 7.1 `query_events`

参数：

```json
{
  "since": "2026-10-21T00:00:00+08:00",
  "until": "2026-10-22T00:00:00+08:00",
  "src_ip": null,
  "session": null,
  "event_types": [],
  "limit": 500
}
```

返回匹配事件及其必要原始字段。

必须限制最大时间跨度、单次记录数、总查询量及返回字节数。超出限制时明确返回分页游标或限制错误，不能静默截断后声称数据完整。

### 7.2 `query_stats`

提供确定性统计，例如：连接次数及独立来源 IP 数、登录成功与失败次数、来源 IP 排名、常见用户名、命令类型与出现频率、会话时长、文件上传/下载次数及哈希、小时/日/周趋势、与前一统计周期的变化。

聚合数值由程序计算，不允许模型自行编造或估算实际事件总数。

### 7.3 `execute_js`

输入：

```json
{
  "code": "/* JavaScript source */",
  "input": {
    "events": [],
    "stats": {}
  },
  "timeout_ms": 2000
}
```

输出：

```json
{
  "ok": true,
  "result": {},
  "duration_ms": 12
}
```

执行要求：

- 使用 Goja。
- 输入只能包含 Host 明确授权的数据。
- 不提供通用 `readFile`、`exec`、`fetch`、`require` 或动态模块加载接口。
- 通过独立 Runner 执行脚本。
- 限制执行时间、输入大小、输出大小及并发任务数。
- 脚本错误必须作为结构化结果返回。
- 禁止脚本直接发送 ntfy 消息或调用 DeepSeek。
- 每次执行记录任务 ID、代码哈希、执行结果和耗时。

如果模型需要更多数据，必须重新调用 `query_events` 或 `query_stats`，而不是直接读取任意宿主机文件。

### 7.4 `submit_report`

参数：

```json
{
  "type": "daily",
  "title": "E3 安全日报",
  "summary": "报告摘要",
  "findings": []
}
```

此工具只接受报告数据，不允许指定任意 URL、ntfy 主题或 Token。

Host 必须校验报告类型、字段长度、数据来源、统计窗口及必要指标，再决定是否发布。模型输出不能直接覆盖报告归档或系统配置。

## 8. DeepSeek 接入

使用可配置的 OpenAI 兼容 HTTP API 接口。API Base URL、模型名、密钥和超时都从配置读取。

需要实现：连接超时和总请求超时、HTTP 状态码处理、429 和可重试 5xx 错误的退避重试、最大工具调用轮数、最大输入输出 Token 预算、单任务最大执行时长、模型输出 JSON Schema 校验、失败任务记录与后续重试、对工具调用参数执行严格校验。

建议默认每个任务最多 6 轮工具调用。达到上限后返回部分分析或明确失败状态，不得无限循环。

LLM 接口必须支持配置关闭工具调用，降级为一次性结构化分析。

### 8.1 分析流程

1. 根据任务计算统计窗口。
2. 使用本地 SQL 生成基础指标。
3. 查询重要来源、异常会话和代表性事件。
4. 将必要数据提交给 DeepSeek。
5. 如需额外关联，模型请求 `query_events` 或 `query_stats`。
6. 如需复杂计算，模型请求 `execute_js`。
7. 将工具结果返回模型继续分析。
8. 模型生成结构化报告。
9. 校验统计值、字段、时间范围和内容。
10. 如启用报告图表（`report_image.enabled`）：由 Host 基于 SQL 统计（不经 LLM）确定性渲染 PNG，上传对象存储获取公网直链，并按保留期清理桶内旧对象；渲染或上传失败仅降级为纯文本通知，不影响报告状态机。
11. 归档报告并通过 ntfy 发布。

所有工具调用都由 Host 调度。不得允许模型自行拼接 Shell 命令执行。

## 9. 数据完整性与提示词注入

攻击日志完全不可信，但不应因此统一脱敏。

以下字段必须保持原值：来源 IP 和端口、完整时间戳、会话 ID、用户名、路径和文件名、攻击命令及其参数、事件原文、文件哈希、Cowrie 额外事件字段。

不对 IP、目录、命令做匿名化或模糊化。允许对事件进行分类、摘要和结构化，但原始证据必须保持不变。

攻击者可能在终端命令、文件名或其他字段中植入提示词注入内容。Agent 必须将这些字段视为待分析数据，而不是执行指令。

必须满足：

1. 系统提示词与攻击数据在逻辑上明确分离。
2. 数据中的指令不能修改系统策略或工具权限。
3. 脚本执行环境不能获取任何 API Key、ntfy Token 或宿主机秘密。
4. 脚本不能访问网络和任意文件。
5. 报告发布由 Host 执行，不由脚本自行请求 HTTP。
6. 重要结论附带事件 ID、会话 ID 或统计依据，方便人工复查。

原始日志可以完整保留在 E3。是否将凭据字段提交给外部模型应由显式配置控制；无论选择如何，均不得把 Agent 自身的 API Key、ntfy Token 或系统凭据混入模型输入。

## 10. 实时告警

实时告警首先由本地规则引擎实现，不等待 LLM。

初始规则：

- `cowrie.session.connect`：连接事件，聚合统计。
- `cowrie.login.failed`：登录失败，同一来源短时间内合并。
- `cowrie.login.success`：立即发送高优先级通知。
- `cowrie.command.input`：会话首次执行命令时告警，后续按规则聚合。
- 文件上传或下载事件：立即告警，附带文件名、哈希及会话 ID。

事件名称以实际 Cowrie 版本为准。

告警必须包含时间、源 IP、事件类型、会话 ID 和简短说明。支持按来源、会话及事件类型去重，并配置每分钟消息上限。

不能因为一台来源主机频繁连接就无条件发送大量通知。限流时应记录被合并事件数量，并定期发送汇总消息。

## 11. 日报和周报

所有周期使用 `Asia/Shanghai`。内部时间存储统一使用 UTC，展示时转换为北京时间。

### 日报

每天 08:00 执行，分析前一个自然日：`[前一天 00:00, 当天 00:00)`

内容包括：统计窗口和数据完整性；连接总量及独立来源 IP 数；登录成功/失败情况；来源 IP 排名及其活动；高频用户名、命令和会话；可疑目录探测、系统信息探测和文件操作；与前一天相比的显著变化；值得人工复查的事件及其引用；模型分析置信度和证据不足之处。

### 周报

每周一 08:15 执行，分析上一自然周：`[上周一 00:00, 本周一 00:00)`

额外包括：每日连接趋势；持续出现的来源 IP；跨天、跨会话的行为关联；高频攻击模式变化；新出现的命令和文件哈希；与前一周的差异；值得调整的检测规则；数据缺口、模型失败及统计限制。

### 报告约束

报告必须区分：直接观察到的事实、程序计算得到的统计、模型推断、尚待人工确认的假设。

Cowrie 中的模拟登录成功不得表述为真实主机登录成功。

缺失数据、采集停滞或日志轮转异常必须明确标记，不能生成看似完整的报告掩盖数据缺口。

报告应归档到本地，并记录统计窗口、模型名称、生成时间、输入数据范围和内容哈希。启用图表时，归档 payload 增加可选 `image` 块（url/key/sha256/bytes），并在归档目录写同名 `.png` 副本。

### 存储轮转

所有随时间累积的远端文件必须受保留期约束：

- 本地归档目录（`YYYY/MM/{kind}-{YYYYMMDD}.json` 及同名 `.png` 图表副本）按 `reports.retention_days` 轮转（默认 90 天，0 禁用），由 daemon 每日清理循环按文件名内嵌日期执行。
- 对象存储桶内的报告图表对象按 `report_image.retention_days` 轮转（默认 90 天，0 禁用），每次上传后以 LIST+DELETE 清理；清理失败仅告警，不阻塞报告。
- ntfy 发布使用外部 URL 附件（X-Attach），图片不落在 ntfy 服务端存储，零新增存储压力。
- 报告 payload 中的图表 URL 在桶内对象过期后失效，属轮转的固有语义。

## 12. ntfy 发布

ntfy 服务地址：`https://notify.modenc.top`

主题名和 Token 必须可配置。Token 通过权限为 0600 的环境文件或受控凭据机制注入，不写入源码、日志和报告。

实现功能：HTTPS 请求、Bearer Token 认证、标题/正文/优先级和标签、超时与退避重试、消息长度限制、发布状态记录、幂等去重、失败消息的持久化重试、固定发布目标禁止模型自定义 URL。

可选增强（`ntfy.markdown`，默认开启）：正文以 Markdown 发送（`X-Markdown` 头，含 `![](url)` 内联图，需服务端 ≥2.11.0，旧版本仅显示原始语法文本，可配置关闭）；报告通知携带外链图片附件（`X-Attach`，指向对象存储直链）。附件 URL 由 Host 程序以随机不可猜的对象键生成，模型不得自定义。外部 URL 附件不占 ntfy 服务端存储与配额。附件地址与 Markdown 标志随 notifications 行持久化，daemon 补发时不丢失。报告正文中的 summary 与 finding 标题回显攻击者可控内容，进入 Markdown 前必须转义链接构成字符（先 `\` 后 `[`、`<`——防自带反斜杠转义拆解重组链接，参照告警侧 sanitizeField 并堵其绕过），渲染端不得出现攻击者构造的可点击链接。

建议实时告警与周期报告使用不同主题或不同消息标签，便于客户端区分。

不能仅因 HTTP 返回成功就永久标记任务完成；需要记录响应状态、请求时间和消息标识。对于不确定是否成功的请求，使用稳定去重键避免重试造成重复通知。

## 13. 配置文件

提供 `configs/config.example.yaml`（结构见仓库内实际文件；所有地址/主题/密钥均为占位或环境变量引用，不得包含真实 Token 或 API Key）。配置加载时必须验证必填字段、URL、时间范围和资源限制。日志中不得输出密钥。

## 14. systemd 部署

实现独立服务：`e3-collector.service`、`e3-analyst.service`、`e3-daily-report.service`、`e3-daily-report.timer`、`e3-weekly-report.service`、`e3-weekly-report.timer`。

Collector 常驻运行。日报和周报由 systemd timer 触发，不使用无限循环模拟定时器。

服务默认以专用低权限用户运行，启用适用的 systemd 加固选项。脚本 Runner 使用独立身份和受限容器，不能挂载 Docker Socket 或宿主机根目录。

LLM 与 ntfy 凭据仅注入确实需要使用它们的进程。Runner 不得继承这些凭据。对象存储密钥（`doge.env`，含多吉云 AccessKey/SecretKey）仅注入 analyst 相关 unit（daemon 与两个 report oneshot）；collector 不需要、不加载。

## 15. 测试要求

必须提供自动化测试。

### 日志采集

合法 JSON 事件；缺少可选字段；未知字段；不完整 JSON 行；重复事件；文件轮转；Collector 重启恢复；SQLite 暂时不可写；大量事件流下的内存稳定性。

### 查询与统计

时间窗口左闭右开；跨日事件；时区转换；来源 IP 去重；登录事件计数；会话关联；分页与上限；不完整采集情况下的统计标记。

### Goja Runner

合法脚本；语法错误；无限循环；超时中断；超大输出；超大输入；恶意字符串及提示词注入；尝试访问不存在的文件、网络和系统接口；尝试访问环境变量或获取宿主对象。

测试必须证明脚本无法调用任意 Shell、任意 HTTP 或任意文件访问接口。测试失败时不得发布报告。

### DeepSeek

正常响应；无效 JSON；HTTP 429；HTTP 5xx；请求超时；非法工具参数；超出工具调用轮数；模型输出字段缺失；API Key 缺失。

### ntfy

正常发布；认证失败；超时；服务不可用；重试与幂等；限流和消息合并；Markdown/附件头的存在与缺席；非法附件 URL 本地拒绝。

测试应默认使用 Mock HTTP Server，不得依赖真实 API Key。

### 报告图表与对象存储上传

临时密钥 HMAC 签名（golden）；S3 SigV4 PUT/LIST/DELETE 签名（golden，固定凭据与时钟）；上传全链路（Mock API + Mock S3，断言请求头/路径/字节）；桶内清理按 Last-Modified 删旧留新与分页合并；图表 PNG 合法性（magic bytes、尺寸）与零事件窗口；小时/日桶补零；渲染或上传失败降级为纯文本且不阻塞报告状态机；归档目录轮转按文件名日期删旧留新。

## 16. 验收标准

第一版交付必须满足：

1. 可以从 Cowrie JSONL 读取事件并存入 SQLite。
2. Collector 重启后不重复处理已经提交的事件。
3. 可以查询指定时间段的完整来源 IP、路径、命令及会话信息。
4. 可以使用本地代码计算确定性统计。
5. 可以通过 DeepSeek 生成结构化安全分析结果。
6. 可以运行受限 JavaScript 并返回 JSON。
7. JavaScript 无法任意读取文件、访问网络或执行系统命令。
8. 实时告警能够独立于 LLM 工作。
9. 日报和周报能够由 systemd timer 触发。
10. ntfy 发布失败后可以恢复，且不会无条件重复发送。
11. 所有 API Key、Token 均不进入脚本执行环境。
12. 服务以非 root 用户运行，日志、数据库和报告权限符合最小权限原则。
13. 生成的报告可以追溯到实际事件和统计结果。
14. 有完整 README、配置示例、systemd 文件、数据库迁移、自动化测试和故障排查说明。

## 17. 开发顺序

按以下阶段实现，每个阶段均应编译、测试后再继续。

- 阶段 A：基础框架（Go 模块、配置加载、结构化日志、SQLite 初始化、迁移和测试框架）。
- 阶段 B：Collector（JSONL 读取、轮转、偏移量恢复、原始数据保留、事件索引及基础查询）。
- 阶段 C：规则告警（事件分类、去重、限流、ntfy 发布和失败重试）。
- 阶段 D：DeepSeek（API 客户端、结构化输出、工具调用循环、超时和错误处理）。
- 阶段 E：Goja Runner（独立运行环境、受控输入、资源限制、超时中断及安全测试）。
- 阶段 F：报告（日报、周报、趋势比较、事件引用、归档和 systemd timer）。
- 阶段 G：安全验收（测试权限隔离、提示词注入、资源耗尽、日志轮转、网络故障和凭据隔离）。

每阶段必须提交可运行代码和测试结果。不要一次性生成大量未经验证的代码，也不要在测试未通过时继续叠加功能。

## 18. 明确禁止的设计

- 不允许 LLM 直接执行 Shell 命令。
- 不允许将 Docker Socket 暴露给 Agent。
- 不允许脚本自行构造任意 HTTP 请求。
- 不允许脚本直接修改 Cowrie 原始日志。
- 不允许通过删除、匿名化来源 IP 或路径来简化数据处理。
- 不允许模型自行决定绕过资源限制或提升权限。
- 不允许无上限地读取日志、调用工具或执行脚本。
- 不允许将模拟 SSH 登录成功描述成真实系统失陷。
- 不允许在没有数据完整性依据时输出确定性攻击结论。
- 不允许将真实凭据、API Key 或 ntfy Token 写入模型提示词、脚本输入和普通日志。

最终目标是一个轻量、可审计、能扩展的安全分析系统：程序负责采集与事实，JavaScript 负责受控计算，DeepSeek 负责行为解释，ntfy 负责通知。任何一个组件失效，都不应让其他组件获得额外权限。
