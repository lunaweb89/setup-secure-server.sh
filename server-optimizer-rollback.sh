#!/usr/bin/env bash
#
# server-optimizer-rollback.sh
#
# Roll back configs changed by server-optimizer.sh using the most recent
# *.bak-YYYYMMDD-HHMMSS backups and restart services.
#

set -euo pipefail

log() { echo "[+] $*"; }
warn() { echo "[-] $*"; }
err() { echo "[ERROR] $*" >&2; }

if [[ "$EUID" -ne 0 ]]; then
  err "This script must be run as root (sudo)."
  exit 1
fi

timestamp="$(date +%Y%m%d-%H%M%S)"

restore_latest() {
  local target="$1"
  local pattern="$2"

  local latest
  latest=$(ls -1t $pattern 2>/dev/null | head -n1 || true)

  if [[ -z "$latest" ]]; then
    warn "No backup found for $target matching pattern: $pattern"
    return 0
  fi

  log "Restoring $target from $latest"
  cp "$latest" "$target"
}

log "Starting rollback of server-optimizer.sh changes..."

###############################################
# 1. Sysctl tuning rollback (optional)
###############################################

SYSCTL_FILE="/etc/sysctl.d/99-ols-optimized.conf"
if [[ -f "$SYSCTL_FILE" ]]; then
  restore_latest "$SYSCTL_FILE" "${SYSCTL_FILE}.bak-*"
else
  warn "Sysctl file $SYSCTL_FILE not found; nothing to restore."
fi

###############################################
# 2. OpenLiteSpeed config rollback
###############################################

OLS_CONF="/usr/local/lsws/conf/httpd_config.conf"
if [[ -f "$OLS_CONF" ]]; then
  restore_latest "$OLS_CONF" "${OLS_CONF}.bak-*"
else
  warn "OpenLiteSpeed config $OLS_CONF not found; skipping."
fi

###############################################
# 3. PHP LSAPI php.ini rollback (all versions)
###############################################

for PHPINI in /usr/local/lsws/lsphp*/etc/php.ini; do
  [[ -f "$PHPINI" ]] || continue
  restore_latest "$PHPINI" "${PHPINI}.bak-*"
done

###############################################
# 4. Redis config rollback
###############################################

REDIS_CONF="/etc/redis/redis.conf"
if [[ -f "$REDIS_CONF" ]]; then
  restore_latest "$REDIS_CONF" "${REDIS_CONF}.bak-*"
else
  warn "Redis config $REDIS_CONF not found; skipping."
fi

###############################################
# 5. MariaDB optimized cnf rollback
###############################################

MARIADB_CONF="/etc/mysql/mariadb.conf.d/99-optimized.cnf"
if [[ -f "$MARIADB_CONF" ]]; then
  restore_latest "$MARIADB_CONF" "${MARIADB_CONF}.bak-*"
else
  warn "MariaDB config $MARIADB_CONF not found; skipping."
fi

###############################################
# 6. Limits rollback (manual notice)
###############################################

if [[ -f /etc/security/limits.conf ]]; then
  warn "NOTE: /etc/security/limits.conf was overwritten by server-optimizer.sh"
  warn "      No automatic backup was created by default. If you have your own"
  warn "      backup, restore it manually and then re-login."
fi

###############################################
# 7. Apply sysctl and restart services
###############################################

log "Re-applying sysctl settings..."
sysctl --system >/dev/null || warn "sysctl --system returned a warning."

log "Restarting Redis..."
systemctl restart redis-server || warn "Redis restart failed; please check logs."

log "Restarting MariaDB..."
systemctl restart mariadb || warn "MariaDB restart failed; please check logs."

if systemctl status lsws >/dev/null 2>&1; then
  log "Restarting OpenLiteSpeed..."
  systemctl restart lsws || warn "OpenLiteSpeed restart failed; please check logs."
fi

touch /root/.server_optimizer_rollback_last_run 2>/dev/null || true

log "Rollback completed. Please test your sites & services."
