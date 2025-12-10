#!/usr/bin/env bash
#
# server-toolkit.sh
#
# Simple menu wrapper for:
#   - setup-secure-server.sh      (full hardening)
#   - setup-backup-module.sh      (backup + storage box)
#   - restore-backup.sh           (disaster recovery)
#   - server-optimizer.sh         (performance tuning)
#

set -euo pipefail

BASE_URL="https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main"

log() { echo "[+] $*"; }

run_full_secure_setup() {
  log "Starting full secure server setup..."
  bash <(curl -fsSL "${BASE_URL}/setup-secure-server.sh")
}

run_backup_setup_only() {
  log "Starting backup module setup..."
  bash <(curl -fsSL "${BASE_URL}/setup-backup-module.sh")
}

run_restore_module_only() {
  log "Starting restore module..."
  bash <(curl -fsSL "${BASE_URL}/restore-backup.sh")
}

run_optimizer_only() {
  log "Starting performance optimizer..."
  bash <(curl -fsSL "${BASE_URL}/server-optimizer.sh")
}

show_status() {
  echo "============================================================"
  echo "                 LunaServers – Status"
  echo "============================================================"

  # Markers (optional – adapt if you use different marker files)
  for f in \
    /root/.secure_server_setup_done \
    /root/.backup_module_setup_done \
    /root/.restore_module_last_run \
    /root/.server_optimizer_last_run
  do
    if [[ -f "$f" ]]; then
      echo "  [OK]  Marker present: $f"
    else
      echo "  [--]  Marker missing: $f"
    fi
  done

  echo
  echo "UFW status (if installed):"
  if command -v ufw >/dev/null 2>&1; then
    ufw status verbose || true
  else
    echo "  UFW not installed."
  fi

  echo
  echo "Fail2Ban status (if installed):"
  if systemctl list-unit-files | grep -q '^fail2ban\.service'; then
    systemctl status fail2ban --no-pager || true
  else
    echo "  Fail2Ban not installed."
  fi

  echo
  read -r -p "Press ENTER to return to menu..." _
}

while :; do
  cat <<'MENU'

============================================================
              LunaServers – Server Toolkit Menu
============================================================

  1) Full Secure Server Setup
     - Runs setup-secure-server.sh
     - Hardens SSH (custom port), UFW, Fail2Ban
     - Sets up auto security updates, ClamAV, Maldet
     - Optionally runs Backup + Storage Box module from inside
     - Optionally runs Performance Optimizer from inside

  2) Run Auto Backup Setup Only
     - Runs setup-backup-module.sh for automated backup
     - Sets up Borg + Hetzner Storage Box backups
     - Creates daily backup cronjob and helper scripts

  3) Run Restore Module Only
     - Runs restore-backup.sh
     - Restores selected sites from Borg backups
     - For disaster recovery / migrations
     NOTE: Running this repeatedly will NOT 'break' the OS,
           but CAN overwrite site files/databases each time.

  4) Run Performance Optimizer Only
     - Runs server-optimizer.sh
     - Auto-tunes sysctl, limits, OpenLiteSpeed, PHP LSAPI
     - Auto-tunes MariaDB (60% RAM) & Redis (15% RAM, capped at 2GB)

  5) View Status
     - Shows markers, Borg repo & connectivity, cronjob presence

  6) Exit Toolkit
============================================================
MENU

  read -r -p "Select an option [1-6]: " choice

  case "$choice" in
    1) run_full_secure_setup ;;
    2) run_backup_setup_only ;;
    3) run_restore_module_only ;;
    4) run_optimizer_only ;;
    5) show_status ;;
    6) exit 0 ;;
    *) echo "Invalid choice. Please enter 1–6." ;;
  esac
done
