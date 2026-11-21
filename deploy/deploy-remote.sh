#!/usr/bin/env bash
set -euo pipefail

# NetProfiler — Remote Deployment Helper (run from a workstation on the same LAN)
# Usage: ./deploy/deploy-remote.sh [user@host] [port]
# Example: ./deploy/deploy-remote.sh debian@192.168.55.115 8000

TARGET="${1:-root@192.168.55.115}"
PORT="${2:-8000}"
REMOTE_STAGE="/tmp/netprofiler-deploy"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "Uploading NetProfiler to ${TARGET}:${REMOTE_STAGE}..."
ssh "${TARGET}" "mkdir -p ${REMOTE_STAGE}"
rsync -az --delete \
    --exclude '.git' \
    --exclude '.venv' \
    --exclude '__pycache__' \
    --exclude '*.db' \
    "${REPO_DIR}/" "${TARGET}:${REMOTE_STAGE}/"

echo "Running Debian installer on ${TARGET} (port ${PORT})..."
ssh -t "${TARGET}" "sudo NETPROFILER_PORT=${PORT} bash ${REMOTE_STAGE}/deploy/install-debian.sh && rm -rf ${REMOTE_STAGE}"
