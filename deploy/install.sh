#!/usr/bin/env bash
# =============================================================================
# install.sh — e3-security-analyst 幂等安装脚本（Ubuntu 24.04）
#
# 用途：
#   1. 创建专用低权限系统用户/组 e3sec（nologin，无 home 内容）；
#   2. 创建目录：/etc/e3-security-analyst (0750 root:e3sec)、
#      /var/lib/e3-security-analyst (0700 e3sec:e3sec) 及 reports 子目录；
#   3. 安装 bin/linux-amd64 下的二进制到 /usr/local/bin（需 root）；
#   4. 安装 systemd units 并 daemon-reload；
#   5. enable（不 start）collector、analyst 与两个 report timer。
#
# 权限：必须以 root 执行（sudo bash deploy/install.sh）。
#
# 安全承诺：本脚本不修改现有 SSH / Nginx / PostgreSQL / Redis 等任何服务的
# 配置，不触碰防火墙规则；只创建与 e3-security-analyst 相关的用户、目录、
# 二进制和 systemd units。重复执行安全（幂等）。
# =============================================================================
set -euo pipefail

E3_USER=e3sec
E3_GROUP=e3sec
CONF_DIR=/etc/e3-security-analyst
STATE_DIR=/var/lib/e3-security-analyst
BIN_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin/linux-amd64"
UNIT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNITS=(
  e3-collector.service
  e3-analyst.service
  e3-daily-report.service
  e3-daily-report.timer
  e3-weekly-report.service
  e3-weekly-report.timer
)

if [[ ${EUID} -ne 0 ]]; then
  echo "错误：请以 root 执行（sudo bash deploy/install.sh）" >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "错误：未找到 systemctl，本脚本仅支持 systemd（Ubuntu 24.04）" >&2
  exit 1
fi

# —— 1. 专用低权限用户/组（幂等）——
if ! getent group "${E3_GROUP}" >/dev/null; then
  groupadd --system "${E3_GROUP}"
  echo "[ok] 已创建系统组 ${E3_GROUP}"
else
  echo "[skip] 组 ${E3_GROUP} 已存在"
fi
if ! getent passwd "${E3_USER}" >/dev/null; then
  useradd --system --gid "${E3_GROUP}" --home-dir "${STATE_DIR}" \
    --shell /usr/sbin/nologin --no-create-home "${E3_USER}"
  echo "[ok] 已创建系统用户 ${E3_USER}（nologin，非 root，无 sudo）"
else
  echo "[skip] 用户 ${E3_USER} 已存在"
fi

# —— 2. 目录与权限（幂等：install -d 会纠正权限/属主）——
install -d -m 0750 -o root  -g "${E3_GROUP}" "${CONF_DIR}"
install -d -m 0700 -o "${E3_USER}" -g "${E3_GROUP}" "${STATE_DIR}"
install -d -m 0700 -o "${E3_USER}" -g "${E3_GROUP}" "${STATE_DIR}/reports"
echo "[ok] 目录就绪：${CONF_DIR} (0750 root:${E3_GROUP})、${STATE_DIR} (0700 ${E3_USER}:${E3_GROUP})"

# —— 3. 二进制（缺失则提示先构建，不阻断 units 安装）——
for bin in e3-collector e3-analyst e3-script-runner; do
  if [[ -f "${BIN_SRC}/${bin}" ]]; then
    install -m 0755 "${BIN_SRC}/${bin}" "/usr/local/bin/${bin}"
    echo "[ok] 已安装 /usr/local/bin/${bin}"
  else
    echo "[warn] 缺少 ${BIN_SRC}/${bin}（先运行 scripts/build.sh），本次跳过"
  fi
done

# —— 4. systemd units ——
for unit in "${UNITS[@]}"; do
  if [[ ! -f "${UNIT_SRC}/${unit}" ]]; then
    echo "错误：缺少 unit 文件 ${UNIT_SRC}/${unit}" >&2
    exit 1
  fi
  install -m 0644 "${UNIT_SRC}/${unit}" "/etc/systemd/system/${unit}"
done
systemctl daemon-reload
echo "[ok] 已安装 ${#UNITS[@]} 个 unit 并 daemon-reload"

# —— 5. enable（不 start：配置与凭据就位后由管理员启动）——
systemctl enable \
  e3-collector.service \
  e3-analyst.service \
  e3-daily-report.timer \
  e3-weekly-report.timer >/dev/null
echo "[ok] 已 enable：e3-collector e3-analyst e3-daily-report.timer e3-weekly-report.timer"

echo
echo "===================================================================="
echo " 安装完成。手动收尾步骤（按顺序）："
echo " 1. 构建并安装二进制（若上一步有 warn）："
echo "      bash scripts/build.sh && sudo bash deploy/install.sh"
echo " 2. 放置配置文件并核对 cowrie.log_path（按实际容器挂载调整）："
echo "      sudo install -m 0640 -o root -g ${E3_GROUP} \\"
echo "           configs/config.example.yaml ${CONF_DIR}/config.yaml"
echo "      sudoedit ${CONF_DIR}/config.yaml"
echo " 3. 放置凭据文件（0600 e3sec:e3sec，内容见 deploy/env.example）："
echo "      sudo install -m 0600 -o ${E3_USER} -g ${E3_GROUP} /dev/null ${CONF_DIR}/ntfy.env"
echo "      sudo install -m 0600 -o ${E3_USER} -g ${E3_GROUP} /dev/null ${CONF_DIR}/llm.env"
echo "      （然后分别写入 NTFY_TOKEN、DEEPSEEK_API_KEY；collector 只需要 ntfy.env）"
echo " 4. 确认 e3sec 能读 Cowrie 日志（只读即可，不修改现有服务）："
echo "      sudo -u ${E3_USER} test -r /var/log/cowrie/cowrie.json && echo ok"
echo "    若不可读，由管理员决定授权方式（如 setfacl -m u:${E3_USER}:r 或只读组），"
echo "    本脚本不代做任何授权决定。"
echo " 5. 启动："
echo "      sudo systemctl start e3-collector.service e3-analyst.service"
echo "      sudo systemctl start e3-daily-report.timer e3-weekly-report.timer"
echo " 6. 验证：journalctl -u e3-collector -f 与 systemctl list-timers 'e3-*'"
echo "===================================================================="
