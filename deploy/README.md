# e3-security-analyst 部署指南（Ubuntu 24.04，systemd）

本目录包含在 E3 服务器上部署 e3-security-analyst 所需的全部文件：
systemd units、凭据环境文件模板、幂等安装脚本。

部署不修改现有 SSH / Nginx / PostgreSQL / Redis 等任何服务的配置，
不以 root 运行业务进程，不触碰防火墙规则。

## 文件清单

| 文件 | 用途 |
| --- | --- |
| `e3-collector.service` | 常驻 Cowrie 日志采集器（含实时告警），`Restart=always` |
| `e3-analyst.service` | 常驻分析守护进程（每 30s FlushPending 重试失败通知、周期重试失败报告），`Restart=always` |
| `e3-daily-report.service` | 日报生成（oneshot，由 timer 触发），窗口 `[前一天 00:00, 当天 00:00)` |
| `e3-daily-report.timer` | 每天 `08:00:00 Asia/Shanghai` 触发日报，`Persistent=true` |
| `e3-weekly-report.service` | 周报生成（oneshot，由 timer 触发），窗口 `[上周一 00:00, 本周一 00:00)` |
| `e3-weekly-report.timer` | 每周一 `08:15:00 Asia/Shanghai` 触发周报，`Persistent=true` |
| `env.example` | `llm.env` / `ntfy.env` 凭据文件模板（0600 e3sec:e3sec） |
| `install.sh` | 幂等安装脚本（root 执行） |

## 部署步骤

```bash
# 0. 构建 linux/amd64 二进制（输出到 bin/linux-amd64/）
bash scripts/build.sh            # 或 bash scripts/build.sh --tests 先跑测试

# 1. 安装（root；创建 e3sec 用户/目录，装二进制与 units，enable 不 start）
sudo bash deploy/install.sh

# 2. 放置配置（0640 root:e3sec），按实际容器挂载修改 cowrie.log_path
sudo install -m 0640 -o root -g e3sec configs/config.example.yaml \
     /etc/e3-security-analyst/config.yaml
sudoedit /etc/e3-security-analyst/config.yaml

# 3. 放置凭据（0600 e3sec:e3sec，内容见 deploy/env.example）
sudo install -m 0600 -o e3sec -g e3sec /dev/null /etc/e3-security-analyst/ntfy.env
sudo install -m 0600 -o e3sec -g e3sec /dev/null /etc/e3-security-analyst/llm.env
#   分别写入 NTFY_TOKEN=... 与 DEEPSEEK_API_KEY=...

# 4. 确认 e3sec 可读 Cowrie 日志（只读即可；授权方式由管理员决定，
#    例如 setfacl -m u:e3sec:r /var/log/cowrie/cowrie.json）
sudo -u e3sec test -r /var/log/cowrie/cowrie.json && echo ok

# 5. 启动
sudo systemctl start e3-collector.service e3-analyst.service
sudo systemctl start e3-daily-report.timer e3-weekly-report.timer

# 6. 验证
journalctl -u e3-collector -f               # 启动日志含脱敏配置摘要
systemctl list-timers 'e3-*'                # 两个 timer 的下次触发时间
```

## 权限矩阵（哪个进程拿哪些凭据）

| 进程 | systemd unit | 凭据（环境） | 数据访问 |
| --- | --- | --- | --- |
| e3-collector | `e3-collector.service` | 仅 `NTFY_TOKEN`（ntfy.env） | 写 `/var/lib/e3-security-analyst`（SQLite/游标/通知队列）；只读 `/var/log/cowrie` |
| e3-analyst daemon | `e3-analyst.service` | `DEEPSEEK_API_KEY`（llm.env）+ `NTFY_TOKEN`（ntfy.env） | 写 `/var/lib/e3-security-analyst`（报告/通知补发） |
| e3-analyst report | `e3-daily-report.service` / `e3-weekly-report.service` | 同上 | 同上 |
| e3-script-runner | 无独立 unit（由 analyst 以子进程拉起） | **无任何凭据**（空环境启动，不继承任何 env 文件） | 无文件系统/网络访问需求，只读 stdin 写 stdout |

要点：

- 三个 env 文件均 `0600 e3sec:e3sec`，由 systemd（PID 1）在降权前读取，
  进程自身无法改写。
- **collector 只加载 `ntfy.env`**——即使它被攻破也没有 LLM 凭据。
- 所有 unit 均以专用低权限用户 `e3sec` 运行，`CapabilityBoundingSet=`（空），
  非 root，无 sudo。
- 日志（journald）与报告中绝不出现 Token / API Key 的值。

## script-runner 的隔离说明

- runner（Goja JavaScript 执行）是 **独立子进程**：analyst 通过
  `internal/sandbox.Runner` 以 `Env` 置空的子进程启动
  `/usr/local/bin/e3-script-runner`，**不继承任何环境变量**（含
  `DEEPSEEK_API_KEY`、`NTFY_TOKEN`）。
- 子进程受超时（`script_runner.timeout_ms` + 2s 宽限后强杀）、输入/输出
  字节限额与并发信号量约束；脚本错误以结构化 JSON 返回，不 panic 外泄。
- 脚本运行环境不提供 `readFile`/`exec`/`fetch`/`require` 等宿主接口，
  也不能自行发送 ntfy 或调用 DeepSeek（SPEC §7.3/§18）。
- 如需更强隔离，可由管理员把 `/usr/local/bin/e3-script-runner` 包进
  gVisor 或 Docker 容器（`--network none --read-only --memory ...`，
  仅挂只读 stdin/stdout）——**禁止挂载 Docker Socket 或宿主机根目录**。
  注意 `MemoryDenyWriteExecute=true` 与 Goja 解释执行兼容（无 JIT）。

## systemd 加固清单（所有 unit 生效）

`NoNewPrivileges` / `ProtectSystem=strict` / `ProtectHome` / `PrivateTmp` /
`ProtectKernelTunables` / `ProtectKernelModules` / `ProtectKernelLogs` /
`ProtectClock` / `ProtectControlGroups` / `ProtectHostname` /
`RestrictNamespaces` / `RestrictRealtime` / `RestrictSUIDSGID` /
`LockPersonality` / `MemoryDenyWriteExecute` /
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` /
`SystemCallArchitectures=native` / `SystemCallFilter=@system-service` /
`CapabilityBoundingSet=`（空）；写权限仅限 `ReadWritePaths=/var/lib/e3-security-analyst`
（collector 额外 `ReadOnlyPaths=/var/log/cowrie`）。

## 定时任务

- 日报：每天 `08:00:00 Asia/Shanghai`，分析前一自然日；错过补跑（`Persistent=true`）。
- 周报：每周一 `08:15:00 Asia/Shanghai`，分析上一自然周；错过补跑。
- 由 systemd timer 触发，不使用进程内无限循环模拟定时器（SPEC §14）。

## 故障排查

```bash
journalctl -u e3-collector -n 200 --no-pager   # 采集/告警日志（JSON）
journalctl -u e3-analyst -n 200 --no-pager     # 分析守护进程
journalctl -u e3-daily-report -n 200 --no-pager
systemctl status e3-collector
systemctl list-timers 'e3-*'
sudo -u e3sec sqlite3 /var/lib/e3-security-analyst/events.db \
  'SELECT status, COUNT(*) FROM notifications GROUP BY status;'
```

常见问题：

- 启动即退出码 2：配置文件缺失/含未知字段/字段越界，看 stderr 与 journald 的错误行。
- 无通知发出：`NTFY_TOKEN` 为空（匿名模式仅告警）、topic 仍是 `change-me`、
  或 pending 通知在等 FlushPending（analyst daemon 每 30s 重试）。
- 采集 gap：`/var/log/cowrie` 不可读或路径错误；collector 会在数据库记录 gap。

## 卸载

```bash
sudo systemctl disable --now \
  e3-collector.service e3-analyst.service \
  e3-daily-report.timer e3-weekly-report.timer
sudo systemctl stop e3-daily-report.service e3-weekly-report.service 2>/dev/null || true
sudo rm -f /etc/systemd/system/e3-{collector,analyst,daily-report.service,daily-report.timer,weekly-report.service,weekly-report.timer}
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/e3-{collector,analyst,script-runner}
# 数据与凭据（确认不再需要后删除；含 Token，务必最后处理）
sudo rm -rf /var/lib/e3-security-analyst
sudo rm -rf /etc/e3-security-analyst
sudo userdel e3sec; sudo groupdel e3sec   # 可选
```

卸载同样不影响 SSH / Nginx / PostgreSQL / Redis 等现有服务。
