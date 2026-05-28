#!/usr/bin/env bash
# teardown.sh — Clean up all artifacts left by the uv security audit exploits.
#
# Removes:
#   - /tmp/exfiltrated.txt       (exploit 01 output)
#   - /tmp/github_api_requests.txt (exploit 02 output)
#   - /tmp/audit_shared_venv     (shared test venv from setup.sh)
#   - Any leftover mock_server.py processes
#
# Exit codes: 0 always (cleanup is best-effort)

set -uo pipefail

echo "[teardown] Cleaning up audit artifacts..."

# ---------------------------------------------------------------------------
# Remove exploit output files
# ---------------------------------------------------------------------------
if [[ -f "/tmp/exfiltrated.txt" ]]; then
    rm -f "/tmp/exfiltrated.txt"
    echo "[teardown] Removed /tmp/exfiltrated.txt"
fi

if [[ -f "/tmp/github_api_requests.txt" ]]; then
    rm -f "/tmp/github_api_requests.txt"
    echo "[teardown] Removed /tmp/github_api_requests.txt"
fi

# ---------------------------------------------------------------------------
# Kill any leftover mock_server.py processes
# ---------------------------------------------------------------------------
MOCK_PIDS="$(pgrep -f "mock_server.py" 2>/dev/null || true)"
if [[ -n "${MOCK_PIDS}" ]]; then
    echo "[teardown] Killing mock_server.py processes: ${MOCK_PIDS}"
    # shellcheck disable=SC2086
    kill ${MOCK_PIDS} 2>/dev/null || true
else
    echo "[teardown] No mock_server.py processes found."
fi

# ---------------------------------------------------------------------------
# Remove shared test venv
# ---------------------------------------------------------------------------
if [[ -d "/tmp/audit_shared_venv" ]]; then
    rm -rf "/tmp/audit_shared_venv"
    echo "[teardown] Removed /tmp/audit_shared_venv"
fi

echo "[teardown] Teardown complete."
exit 0
