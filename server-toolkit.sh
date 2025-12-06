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

# ------------- Idempotency / marker files ------------- #

# These marker files are created AFTER a module completes successfully,
# so the toolkit can warn you before re-running heavy “one-time” modules.
MODULE_SECURE_MARKER="/root/.toolkit-setup-secure-server.done"
MODULE_BACKUP_MARKER="/root/.toolkit-setup-backup-module.done"

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

confirm_if_marker_exists() {
  # $1 = marker path
  # $2 = human-friendly module name
  local marker="$1"
  local name="$2"

  if [[ -f "$marker" ]]; then
    echo
    echo "------------------------------------------------------------"
    echo " NOTICE: ${name} appears to have been run before."
    echo "         Running it again will REAPPLY its baseline config."
    echo "         (It should not 'break' the server, but can override"
    echo "          manual changes you made to SSH/UFW/etc.)"
    echo "------------------------------------------------------------"
    read -r -p "Run ${name} again anyway? [y/N]: " RECONFIRM
    case "$RECONFIRM" in
      [Yy]*) return 0 ;;
      *)     echo "Skipping ${name}."; return 1 ;;
    esac
  fi

  return 0
}

run_remote_script() {
  # $1 = short name
  # $2 = URL
  # $3 = optional marker path ("" if none)
  local name="$1"
  local url="$2"
  local marker="${3:-}"

  # If marker exists, confirm before re-running
  if [[ -n "$marker" ]]; then
    if ! confirm_if_marker_exists "$marker" "$name"; then
      read -r -p "Press ENTER to return to the toolkit menu..." _
      return 0
    fi
  fi

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

    # If module completed OK, create marker file (idempotency hint)
    if [[ -n "$marker" ]]; then
      touch "$marker" 2>/dev/null || true
    fi
  fi

  read -r -p "Press ENTER to return to the toolkit menu..." _
}

# ------------- Main Menu ------------- #

require_root
require_curl

while true; do
  clear
  cat <<EOF
============================================================
              LunaServers – Server Toolkit Menu
============================================================

  1) Full Secure Server Setup
     - Runs setup-secure-server.sh
     - Hardens SSH (port 2808), UFW, Fail2Ban
     - Sets up auto security updates, ClamAV, Maldet
     - Optionally runs Backup + Storage Box module from inside
$( [[ -f "$MODULE_SECURE_MARKER" ]] && echo "     [STATUS] Already run at least once (marker present)" )

  2) Run Backup Module Only
     - Runs setup-backup-module.sh
     - Sets up Borg + Hetzner Storage Box backups
     - Creates daily backup cronjob and helper scripts
$( [[ -f "$MODULE_BACKUP_MARKER" ]] && echo "     [STATUS] Already run at least once (marker present)" )

  3) Run Restore Module Only
     - Runs restore-backup.sh
     - Restores selected sites from Borg backups
     - For disaster recovery / migrations
     NOTE: Running this repeatedly will NOT 'break' the OS,
           but CAN overwrite site files/databases each time.

  4) Exit Toolkit

============================================================
EOF

  read -r -p "Select an option [1-4]: " CHOICE
  echo

  case "$CHOICE" in
    1)
      run_remote_script \
        "Secure Server Setup (setup-secure-server.sh)" \
        "$SECURE_SERVER_URL" \
        "$MODULE_SECURE_MARKER"
      ;;
    2)
      run_remote_script \
        "Backup Module (setup-backup-module.sh)" \
        "$BACKUP_MODULE_URL" \
        "$MODULE_BACKUP_MARKER"
      ;;
    3)
      echo "------------------------------------------------------------"
      echo " WARNING: Restore Module (restore-backup.sh)"
      echo "------------------------------------------------------------"
      echo " This will let you restore sites/databases from Borg backups."
      echo " Re-running restores will re-sync data to the selected target"
      echo " paths. This won't break Ubuntu itself, but it CAN overwrite"
      echo " existing site files/databases for the sites you choose."
      echo "------------------------------------------------------------"
      read -r -p "Continue to Restore Module? [y/N]: " REST_CONFIRM
      case "$REST_CONFIRM" in
        [Yy]*)
          run_remote_script \
            "Restore Module (restore-backup.sh)" \
            "$RESTORE_BACKUP_URL" \
            ""   # no marker for restore; always available
          ;;
        *)
          echo "Skipping Restore Module."
          read -r -p "Press ENTER to return to the toolkit menu..." _
          ;;
      esac
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
