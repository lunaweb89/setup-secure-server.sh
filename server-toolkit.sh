#!/usr/bin/env bash
#
# server-toolkit.sh
#
# Unified toolkit menu for:
#   1) Full secure server setup      (setup-secure-server.sh)
#   2) Backup module only            (setup-backup-module.sh)
#   3) Restore from backups          (restore-backup.sh)
#
# Usage (from GitHub):
#   bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/server-toolkit.sh)
#
# Adjust the URL above if you place this file somewhere else.

set -u
set -o pipefail

# ------------- Config: GitHub raw URLs for the modules ------------- #

BASE_URL="https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main"

SECURE_SERVER_URL="${BASE_URL}/setup-secure-server.sh"
BACKUP_MODULE_URL="${BASE_URL}/setup-backup-module.sh"
RESTORE_BACKUP_URL="${BASE_URL}/restore-backup.sh"

# ------------- Helpers ------------- #

log() {
  echo "[+] $*"
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "[-] ERROR: This toolkit must be run as root (sudo)." >&2
    exit 1
  fi
}

require_curl() {
  if ! command -v curl >/dev/null 2>&1; then
    echo "[-] ERROR: 'curl' is required but not installed." >&2
    echo "    Install it with: apt-get update && apt-get install -y curl" >&2
    exit 1
  fi
}

run_remote_script() {
  local name="$1"
  local url="$2"

  echo
  log "Running ${name} from:"
  echo "    ${url}"
  echo

  # Use a subshell to avoid polluting toolkit's shell environment
  if ! bash <(curl -fsSL "$url"); then
    echo
    echo "[-] ${name} encountered an error or exited with a non-zero status."
    echo "    Check the logs / output above for details."
    echo
  else
    echo
    echo "[OK] ${name} finished successfully."
    echo
  fi

  read -r -p "Press ENTER to return to the toolkit menu..." _
}

# ------------- Main Menu ------------- #

require_root
require_curl

while true; do
  clear
  cat <<'EOF'
============================================================
              LunaServers – Server Toolkit Menu
============================================================

  1) Full Secure Server Setup
     - Runs setup-secure-server.sh
     - Hardens SSH (port 2808), UFW, Fail2Ban
     - Sets up auto security updates, ClamAV, Maldet
     - Optionally runs Backup + Storage Box module from inside

  2) Run Backup Module Only
     - Runs setup-backup-module.sh
     - Sets up Borg + Hetzner Storage Box backups
     - Creates daily backup cronjob and helper scripts

  3) Run Restore Module Only
     - Runs restore-backup.sh
     - Restores selected sites from Borg backups
     - For disaster recovery / migrations

  4) Exit Toolkit

============================================================
EOF

  read -r -p "Select an option [1-4]: " CHOICE
  echo

  case "$CHOICE" in
    1)
      run_remote_script "Secure Server Setup (setup-secure-server.sh)" "$SECURE_SERVER_URL"
      ;;
    2)
      run_remote_script "Backup Module (setup-backup-module.sh)" "$BACKUP_MODULE_URL"
      ;;
    3)
      run_remote_script "Restore Module (restore-backup.sh)" "$RESTORE_BACKUP_URL"
      ;;
    4)
      echo "Exiting toolkit. Bye."
      exit 0
      ;;
    *)
      echo "Invalid option: '$CHOICE'"
      read -r -p "Press ENTER to try again..." _
      ;;
  esac
done
