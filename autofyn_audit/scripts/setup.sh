#!/usr/bin/env bash
# setup.sh — Prepare the local environment for running uv security audit exploits.
#
# Checks for required tooling (Docker, uv) and creates a shared test venv
# at /tmp/audit_shared_venv if one does not already exist.
#
# Exit codes: 0 = success, 1 = missing prerequisite

set -euo pipefail

AUDIT_VENV="/tmp/audit_shared_venv"

# ---------------------------------------------------------------------------
# Resolve uv
# ---------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ -x "/home/agentuser/repo/target/release/uv" ]]; then
    UV_BIN="/home/agentuser/repo/target/release/uv"
elif [[ -x "${REPO_ROOT}/target/release/uv" ]]; then
    UV_BIN="${REPO_ROOT}/target/release/uv"
elif [[ -x "${REPO_ROOT}/target/debug/uv" ]]; then
    UV_BIN="${REPO_ROOT}/target/debug/uv"
elif command -v uv &>/dev/null; then
    UV_BIN="$(command -v uv)"
else
    echo "ERROR: uv is not available." >&2
    echo "  Install via: curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
    echo "  Or build from source:" >&2
    echo "    git clone https://github.com/astral-sh/uv" >&2
    echo "    cd uv && git checkout da5f6a6967b41423fb2a61bf094adff4e403367c" >&2
    echo "    cargo build --release --bin uv" >&2
    exit 1
fi

echo "[setup] uv found: ${UV_BIN} ($(${UV_BIN} --version))"

# ---------------------------------------------------------------------------
# Check Docker
# ---------------------------------------------------------------------------
if command -v docker &>/dev/null; then
    echo "[setup] docker found: $(docker --version)"
else
    echo "[setup] WARNING: docker not found — Dockerfile-based reproduction will not work." >&2
    echo "[setup]   Install Docker: https://docs.docker.com/get-docker/" >&2
    # Not a hard failure — exploits run locally without Docker.
fi

# ---------------------------------------------------------------------------
# Create shared test venv (used by exploits that need one)
# ---------------------------------------------------------------------------
if [[ -d "${AUDIT_VENV}" ]]; then
    echo "[setup] Shared venv already exists at ${AUDIT_VENV} — skipping creation."
else
    echo "[setup] Creating shared test venv at ${AUDIT_VENV}..."
    "${UV_BIN}" venv "${AUDIT_VENV}"
    echo "[setup] Shared venv created."
fi

echo ""
echo "[setup] Setup complete. Run exploits with:"
echo "  bash autofyn_audit/scripts/run_all_exploits.sh"
