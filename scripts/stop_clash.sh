#!/usr/bin/env bash
PROXY_DIR="${RUNNER_TEMP:-/tmp}/clash-proxy"
if [[ -f "${PROXY_DIR}/mihomo.pid" ]]; then
    PID="$(cat "${PROXY_DIR}/mihomo.pid" 2>/dev/null || true)"
    if [[ -n "${PID}" ]]; then
        kill "${PID}" 2>/dev/null || true
        echo "[INFO] Clash 代理进程已停止 (PID: ${PID})"
    fi
fi
