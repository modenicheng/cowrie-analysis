-- 0003：通知附件与 Markdown 支持（报告图表→多吉云上传→ntfy 带图通知）。
--
-- notifications 新增两列，仅带图报告通知使用：
--   attach   外链附件 URL（报告图表直链；空串 = 不携带，历史行为不变）；
--   markdown 正文是否按 Markdown 语法发送（ntfy "Markdown: yes" 头，
--            需服务端 >= 2.11.0；0 = 纯文本，历史行为不变）。
-- 存量行由 NOT NULL DEFAULT 直接获得 ''/0，天然兼容：旧二进制读新库
-- 按列名取数不受影响；新二进制读旧迁移库亦不出现空值。
ALTER TABLE notifications ADD COLUMN attach TEXT NOT NULL DEFAULT '';
ALTER TABLE notifications ADD COLUMN markdown INTEGER NOT NULL DEFAULT 0;
