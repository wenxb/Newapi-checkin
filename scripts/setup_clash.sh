#!/usr/bin/env bash
set -euo pipefail

PROXY_SUBSCRIPTION_URL="${PROXY_SUBSCRIPTION_URL:-}"

if [[ -z "${PROXY_SUBSCRIPTION_URL}" ]]; then
    echo "[INFO] 未配置 PROXY_SUBSCRIPTION_URL，跳过代理启动，使用直连模式"
    exit 0
fi

PROXY_DIR="${RUNNER_TEMP:-/tmp}/clash-proxy"
mkdir -p "${PROXY_DIR}"
cd "${PROXY_DIR}"

PROXY_PORT="${PROXY_PORT:-7890}"
MIHOMO_VERSION="${MIHOMO_VERSION:-v1.19.0}"

echo "[INFO] 正在下载 mihomo (${MIHOMO_VERSION})..."
ARCHIVE="mihomo-linux-amd64-compatible-${MIHOMO_VERSION}.gz"
BIN_NAME="mihomo-linux-amd64-compatible-${MIHOMO_VERSION}"
if ! curl --retry 3 --retry-delay 3 -fsSL -o "${ARCHIVE}" \
    "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VERSION}/${ARCHIVE}"; then
    echo "[WARN] 下载 mihomo 失败，继续使用直连模式"
    exit 0
fi

gunzip -f "${ARCHIVE}"
chmod +x "${BIN_NAME}"
MIHOMO_BIN="${PROXY_DIR}/${BIN_NAME}"

echo "[INFO] 正在拉取 Clash 节点配置..."
if ! curl --retry 3 --retry-delay 3 -fsSLk -o config.yaml "${PROXY_SUBSCRIPTION_URL}"; then
    echo "[WARN] 拉取订阅失败，继续使用直连模式"
    exit 0
fi

# 确保配置包含 mixed-port 和 allow-lan
sed -i '/^mixed-port:/d' config.yaml
sed -i '/^port:/d' config.yaml
sed -i '/^socks-port:/d' config.yaml
sed -i '/^allow-lan:/d' config.yaml
sed -i '/^log-level:/d' config.yaml
sed -i "1i mixed-port: ${PROXY_PORT}\nallow-lan: false\nlog-level: warning\n" config.yaml

echo "[INFO] 启动 mihomo 代理 (127.0.0.1:${PROXY_PORT})..."
nohup "${MIHOMO_BIN}" -d "${PROXY_DIR}" -f config.yaml > mihomo.log 2>&1 &
MIHOMO_PID=$!
echo "${MIHOMO_PID}" > mihomo.pid
disown "${MIHOMO_PID}"

PROXY_URL="http://127.0.0.1:${PROXY_PORT}"
READY=false
for attempt in $(seq 1 30); do
    if curl -fsS -k -x "${PROXY_URL}" --max-time 10 "https://www.gstatic.com/generate_204" -o /dev/null 2>/dev/null || \
       curl -fsS -k -x "${PROXY_URL}" --max-time 10 "https://www.google.com/generate_204" -o /dev/null 2>/dev/null; then
        READY=true
        break
    fi
    echo "[INFO] 等待代理节点连通 (${attempt}/30)..."
    sleep 2
done

if [[ "${READY}" != "true" ]]; then
    echo "[WARN] 代理健康检查超时，可能节点未就绪，继续执行"
    if [[ -f mihomo.pid ]]; then
        kill "$(cat mihomo.pid)" 2>/dev/null || true
    fi
    exit 0
fi

echo "[SUCCESS] Clash 代理已就绪: ${PROXY_URL}"

# 验证出口节点国家
TRACE="$(curl -fsS -k -x "${PROXY_URL}" --max-time 15 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)"
if [[ -n "${TRACE}" ]]; then
    EXIT_LOC="$(printf '%s\n' "${TRACE}" | sed -n 's/^loc=//p' | head -n1)"
    echo "[INFO] 代理出口地区: loc=${EXIT_LOC:-unknown}"
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
    echo "CHECKIN_PROXY_URL=${PROXY_URL}" >> "${GITHUB_ENV}"
    echo "HTTP_PROXY=${PROXY_URL}" >> "${GITHUB_ENV}"
    echo "HTTPS_PROXY=${PROXY_URL}" >> "${GITHUB_ENV}"
fi
