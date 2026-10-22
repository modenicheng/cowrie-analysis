-- e3-security-analyst 初始 schema
-- 时间列统一存储 UTC RFC3339Nano 文本，展示层再转换为配置时区。

CREATE TABLE events (
    id            INTEGER PRIMARY KEY,
    event_id      TEXT NOT NULL,             -- cowrie eventid，如 cowrie.login.success
    event_time    TEXT NOT NULL,             -- 事件时间（UTC）
    collected_at  TEXT NOT NULL,             -- 采集时间（UTC）
    src_ip        TEXT,
    src_port      INTEGER,
    session       TEXT,
    username      TEXT,
    command       TEXT,                      -- cowrie.command.input 的 input 字段
    filename      TEXT,                      -- 文件上传/下载相关文件名
    shasum        TEXT,
    duration_s    REAL,                      -- cowrie.session.closed 的 duration
    raw           TEXT NOT NULL,             -- 原始 JSON 行，无损保留
    raw_sha256    TEXT NOT NULL UNIQUE       -- 幂等去重键
);

CREATE INDEX idx_events_event_time ON events(event_time);
CREATE INDEX idx_events_src_ip     ON events(src_ip);
CREATE INDEX idx_events_event_id   ON events(event_id);
CREATE INDEX idx_events_session    ON events(session);

CREATE TABLE sessions (
    session_id      TEXT PRIMARY KEY,
    src_ip          TEXT,
    started_at      TEXT,
    ended_at        TEXT,
    duration_s      REAL NOT NULL DEFAULT 0,
    login_attempts  INTEGER NOT NULL DEFAULT 0,
    login_successes INTEGER NOT NULL DEFAULT 0,
    command_count   INTEGER NOT NULL DEFAULT 0,
    file_ops        INTEGER NOT NULL DEFAULT 0,
    first_seen      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX idx_sessions_src_ip ON sessions(src_ip);

CREATE TABLE collector_offsets (
    file_key   TEXT PRIMARY KEY,            -- 设备号/inode（Windows 为卷序列号+文件索引）
    path       TEXT NOT NULL,
    inode      INTEGER NOT NULL,
    offset     INTEGER NOT NULL,
    file_size  INTEGER NOT NULL DEFAULT 0,
    mtime_ns   INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE TABLE collector_health (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    last_read_at TEXT,
    last_event_at TEXT,
    last_error   TEXT,
    updated_at   TEXT NOT NULL
);

-- 采集停滞（日志缺失、进程停机、轮转异常等）造成的数据缺口
CREATE TABLE collector_gaps (
    id        INTEGER PRIMARY KEY,
    gap_start TEXT NOT NULL,
    gap_end   TEXT NOT NULL,
    reason    TEXT NOT NULL
);

-- 无法解析的日志行，隔离保留，不静默丢弃
CREATE TABLE parse_errors (
    id          INTEGER PRIMARY KEY,
    file_path   TEXT NOT NULL,
    file_offset INTEGER NOT NULL,
    line_sha256 TEXT NOT NULL,
    raw         TEXT NOT NULL,
    error       TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

-- 报告数据质量窗口统计（CountParseErrors）按 recorded_at 范围过滤
CREATE INDEX idx_parse_errors_recorded_at ON parse_errors(recorded_at);

CREATE TABLE notifications (
    id             INTEGER PRIMARY KEY,
    dedupe_key     TEXT NOT NULL UNIQUE,    -- 稳定去重键，重试不会重复发送
    kind           TEXT NOT NULL,
    topic          TEXT NOT NULL,
    title          TEXT NOT NULL,
    body           TEXT NOT NULL,
    priority       INTEGER NOT NULL DEFAULT 3,
    tags           TEXT,
    status         TEXT NOT NULL DEFAULT 'pending',  -- pending|sent|failed
    attempts       INTEGER NOT NULL DEFAULT 0,
    last_error     TEXT,
    merged_count   INTEGER NOT NULL DEFAULT 0,       -- 限流时被合并的事件数
    created_at     TEXT NOT NULL,
    sent_at        TEXT,
    last_attempt_at TEXT
);

CREATE INDEX idx_notifications_status ON notifications(status);

CREATE TABLE reports (
    id             INTEGER PRIMARY KEY,
    report_type    TEXT NOT NULL,
    window_start   TEXT NOT NULL,
    window_end     TEXT NOT NULL,
    status         TEXT NOT NULL,           -- pending|validated|published|failed
    model          TEXT,
    attempts       INTEGER NOT NULL DEFAULT 0,
    content_sha256 TEXT,
    payload        TEXT,                    -- 完整报告 JSON（程序统计 + 模型分析）
    error          TEXT,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    UNIQUE(report_type, window_start)
);

CREATE TABLE analysis_runs (
    id                TEXT PRIMARY KEY,
    task              TEXT NOT NULL,
    started_at        TEXT NOT NULL,
    ended_at          TEXT,
    status            TEXT NOT NULL,
    model             TEXT,
    rounds            INTEGER NOT NULL DEFAULT 0,
    prompt_tokens     INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    tool_calls        INTEGER NOT NULL DEFAULT 0,
    error             TEXT
);

CREATE TABLE script_runs (
    id            INTEGER PRIMARY KEY,
    run_id        TEXT,                     -- 关联 analysis_runs.id
    code_sha256   TEXT NOT NULL,
    duration_ms   INTEGER NOT NULL,
    ok            INTEGER NOT NULL,
    output_bytes  INTEGER NOT NULL,
    output_preview TEXT,
    created_at    TEXT NOT NULL
);
