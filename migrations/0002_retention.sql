-- 0002：数据保留清理支持（安全审查 High#2：防攻击者高频灌唯一事件耗尽磁盘）。
--
-- 清理判据必须用服务侧入库时间，绝不能用攻击者可伪造的 event_time。
-- 各表现状：
--   events.collected_at / sessions.updated_at / parse_errors.recorded_at /
--   notifications.created_at|sent_at 均为服务侧时间列，直接复用；
--   collector_gaps 只有缺口边界（gap_start/gap_end），缺少入库时间列，本迁移补上。

-- 1) collector_gaps 增加服务侧入库时间列。存量行回填为迁移执行时刻：
--    旧行据此获得全新的保留期（默认 90 天），可接受——gap 行是采集停滞的
--    咨询性记录，量极小（每个缺失期间一行），多保留一轮无害。
--    注意：SQLite 的 ALTER TABLE ADD COLUMN 不允许表达式 DEFAULT，
--    故先以 '' 为默认加列，再显式回填（毫秒精度，RFC3339 兼容）。
--    新行由 store.AddGap 在 Go 侧统一填 time.Now().UTC()（RFC3339Nano）。
--    空串残留只可能来自部署交叠期的旧 collector 二进制插入的行，这类行
--    按字典序最小会在首次清理时被删除，属可接受的咨询性数据损失。
ALTER TABLE collector_gaps ADD COLUMN collected_at TEXT NOT NULL DEFAULT '';
UPDATE collector_gaps SET collected_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
 WHERE collected_at = '';

-- 2) 清理路径索引：按入库时间分批 DELETE 时避免全表扫描。
--    events 是磁盘大头（raw 原文无损保留），必须索引；
--    sessions 按 updated_at 判老会话；notifications 只删已发送（部分索引，
--    pending/failed 行不进索引）。
CREATE INDEX idx_events_collected_at    ON events(collected_at);
CREATE INDEX idx_sessions_updated_at    ON sessions(updated_at);
CREATE INDEX idx_notifications_sent_at  ON notifications(sent_at) WHERE status = 'sent';
