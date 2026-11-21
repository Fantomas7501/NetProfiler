#!/usr/bin/env bash
set -euo pipefail

# NetProfiler — Idempotent Debian Installer & Systemd Setup
# Run as root (or via sudo) on the target Debian server (e.g. 192.168.55.115).

APP_DIR="/opt/netprofiler"
DATA_DIR="/var/lib/netprofiler"
ENV_FILE="/etc/netprofiler.env"
SERVICE_NAME="netprofiler"
PORT="${NETPROFILER_PORT:-8000}"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: please run as root (e.g. sudo $0)." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "[1/6] Installing system prerequisites (python3, python3-venv, python3-pip)..."
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip rsync

echo "[2/6] Ensuring system user '${SERVICE_NAME}' and directories exist..."
if ! id -u "${SERVICE_NAME}" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_NAME}"
fi
mkdir -p "${APP_DIR}" "${DATA_DIR}"

echo "[3/6] Syncing application files to ${APP_DIR}..."
if [[ "$(realpath "${SRC_DIR}")" != "$(realpath "${APP_DIR}")" ]]; then
    rsync -a --delete \
        --exclude '.git' \
        --exclude '.venv' \
        --exclude '__pycache__' \
        --exclude '*.db' \
        "${SRC_DIR}/" "${APP_DIR}/"
fi

echo "[4/6] Creating Python virtual environment and installing dependencies..."
if [[ ! -d "${APP_DIR}/.venv" ]]; then
    python3 -m venv "${APP_DIR}/.venv"
fi
"${APP_DIR}/.venv/bin/pip" install --quiet --upgrade pip
"${APP_DIR}/.venv/bin/pip" install --quiet -r "${APP_DIR}/requirements.txt"

echo "[5/6] Configuring environment file (${ENV_FILE})..."
if [[ ! -f "${ENV_FILE}" ]]; then
    cat > "${ENV_FILE}" <<EOF
NETPROFILER_PORT=${PORT}
NETPROFILER_DB=${DATA_DIR}/netprofiler.db
NETPROFILER_ADMIN_USER=admin
# Uncomment to set a custom initial password before first start:
# NETPROFILER_ADMIN_PASSWORD=ChangeMeStrong!2026
NETPROFILER_SESSION_TTL_HOURS=24
NETPROFILER_COOKIE_SECURE=false
EOF
    chmod 600 "${ENV_FILE}"
fi

chown -R "${SERVICE_NAME}:${SERVICE_NAME}" "${APP_DIR}" "${DATA_DIR}"
chown root:"${SERVICE_NAME}" "${ENV_FILE}"
chmod 640 "${ENV_FILE}"

echo "[6/6] Installing and starting systemd service (${SERVICE_NAME}.service)..."
install -m 644 "${APP_DIR}/deploy/netprofiler.service" "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}.service"
systemctl restart "${SERVICE_NAME}.service"

sleep 1
systemctl --no-pager --lines=10 status "${SERVICE_NAME}.service" || true

echo ""
echo "=================================================================="
echo " NetProfiler deployed successfully!"
echo " URL: http://$(hostname -I | awk '{print $1}'):${PORT}"
echo " Default initial login (if DB was new): admin / NetProfiler!2026"
echo " Config file: ${ENV_FILE}"
echo " Logs: journalctl -u ${SERVICE_NAME} -f"
echo "=================================================================="
