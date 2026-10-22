#!/usr/bin/env bash
# =============================================================================
# build.sh — 构建 linux/amd64 发布二进制到 bin/linux-amd64/
#
# 用法：
#   bash scripts/build.sh            # 仅构建
#   bash scripts/build.sh --tests    # 先运行 go test ./... 再构建
#
# 输出：bin/linux-amd64/e3-collector、e3-analyst、e3-script-runner
#（-trimpath -ldflags "-s -w"，CGO_ENABLED=0，纯 Go SQLite 无 CGO 依赖）。
# cmd/analyst 暂未实现时自动跳过并提示（不报错）。
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

if [[ "${1:-}" == "--tests" ]]; then
  echo "[run] go test ./..."
  go test ./...
elif [[ -n "${1:-}" ]]; then
  echo "用法：bash scripts/build.sh [--tests]" >&2
  exit 64
fi

OUT="${ROOT}/bin/linux-amd64"
mkdir -p "${OUT}"

export GOOS=linux GOARCH=amd64 CGO_ENABLED=0
LDFLAGS="-s -w"

failed=0
for cmd in collector analyst script-runner; do
  bin="e3-${cmd}"
  if [[ -d "cmd/${cmd}" ]]; then
    if go build -trimpath -ldflags "${LDFLAGS}" -o "${OUT}/${bin}" "./cmd/${cmd}"; then
      echo "[ok] ${OUT}/${bin} (${GOOS}/${GOARCH})"
    else
      echo "[fail] 构建 ./cmd/${cmd} 失败" >&2
      failed=1
    fi
  else
    echo "[skip] cmd/${cmd} 不存在（尚未实现），跳过 ${bin}"
  fi
done

if [[ ${failed} -ne 0 ]]; then
  exit 1
fi
echo "[done] 构建完成：${OUT}"
