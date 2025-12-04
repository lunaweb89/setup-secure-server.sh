#!/usr/bin/env bash
#
# wp-core-restore.sh
#
# Auto-restore WordPress core files for sites that show signs of malware.
#
# Logic:
#   - Detect WordPress installs under /home (CyberPanel layout)
#   - Check logs from wp-malware-scan.sh:
#       /var/log/wp-malware-maldet.log
#       /var/log/wp-malware-suspicious.log
#   - If a site's path appears in either log, treat it as infected
#   - Use WP-CLI to re-download WordPress core with --force --skip-content
#
# Requirements:
#   - Run secure-server script first (for maldet/clamav)
#   - Recommended: run wp-malware-scan.sh first
#
# Usage (direct from GitHub):
#   bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server.sh/main/wp-core-restore.sh)

set -euo pipefail

# ----------------- Config ----------------- #

WP_BASE_DIR="/home"

MALDET_LOG="/var/log/wp-malware-maldet.log"
SUSPICIOUS_LOG="/var/log/wp-malware-suspicious.log"

LOG_RESTORE="/var/log/wp-core-restore.log"

# ----------------- Helpers ----------------- #

log() { echo "[+] $*"; }

require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    echo "[-] ERROR: This script must run as root (sudo)." >&2
    exit 1
  fi
}

check_or_install_wp_cli() {
  if command -v wp >/dev/null 2>&1; then
    log "WP-CLI already installed: $(command -v wp)"
    return
  fi

  log "WP-CLI not found, installing to /usr/local/bin/wp ..."
  # Ensure dependencies
  apt-get update -qq
  apt-get install -y -qq php-cli curl

  curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o /usr/local/bin/wp
  chmod +x /usr/local/bin/wp

  if command -v wp >/dev/null 2>&1; then
    log "WP-CLI installed successfully at /usr/local/bin/wp"
  else
    echo "[-] Failed to install WP-CLI. Aborting." >&2
    exit 1
  fi
}

site_has_malware() {
  local docroot="$1"
  # Simple heuristic: if docroot path appears in maldet or suspicious logs
  if [[ -f "$MALDET_LOG" ]] && grep -q "$docroot" "$MALDET_LOG"; then
    return 0
  fi
  if [[ -f "$SUSPICIOUS_LOG" ]] && grep -q "$docroot" "$SUSPICIOUS_LOG"; then
    return 0
  fi
  return 1
}

# ----------------- Start ----------------- #

require_root

mkdir -p "$(dirname "$LOG_RESTORE")"
: > "$LOG_RESTORE"

log "Looking for WordPress installations under ${WP_BASE_DIR}..."
mapfile -t WP_CONFIGS < <(find "$WP_BASE_DIR" -maxdepth 6 -type f -name "wp-config.php" 2>/dev/null || true)

if [[ "${#WP_CONFIGS[@]}" -eq 0 ]]; then
  echo "[-] No WordPress installations found under ${WP_BASE_DIR} (no wp-config.php files)." >&2
  exit 1
fi

log "Found ${#WP_CONFIGS[@]} WordPress install(s):"
for cfg in "${WP_CONFIGS[@]}"; do
  echo "    - $(dirname "$cfg")"
done

log "Checking WP-CLI..."
check_or_install_wp_cli

if [[ ! -f "$MALDET_LOG" && ! -f "$SUSPICIOUS_LOG" ]]; then
  echo "[-] Warning: Neither $MALDET_LOG nor $SUSPICIOUS_LOG exist." >&2
  echo "   It is recommended to run wp-malware-scan.sh first." >&2
fi

echo ""
log "Starting WordPress core restore process..."
echo "Restore log: $LOG_RESTORE"
echo ""

SITE_NUM=0
RESTORED=0
SKIPPED=0

for cfg in "${WP_CONFIGS[@]}"; do
  SITE_NUM=$((SITE_NUM + 1))
  DOCROOT="$(dirname "$cfg")"

  log "[$SITE_NUM] Checking site at: ${DOCROOT}"

  if site_has_malware "$DOCROOT"; then
    log "[$SITE_NUM] Malware indicators found for this site (based on logs)."
    echo "[$(date +'%F %T')] [$SITE_NUM] ${DOCROOT} -> flagged for core restore" >> "$LOG_RESTORE"

    # Try to detect current core version
    VERSION="$(wp core version --path="$DOCROOT" --allow-root 2>/dev/null || echo "")"

    if [[ -n "$VERSION" ]]; then
      log "[$SITE_NUM] Detected WordPress version: ${VERSION}"
      echo "[$(date +'%F %T')] [$SITE_NUM] Detected version: ${VERSION}" >> "$LOG_RESTORE"

      log "[$SITE_NUM] Re-downloading WordPress core (same version, force, skip-content)..."
      wp core download \
        --path="$DOCROOT" \
        --version="$VERSION" \
        --force \
        --skip-content \
        --allow-root >> "$LOG_RESTORE" 2>&1 || {
          echo "[-] [$SITE_NUM] wp core download failed for ${DOCROOT}. See $LOG_RESTORE." >&2
          continue
        }

    else
      log "[$SITE_NUM] Could not detect WordPress version, using latest stable."
      echo "[$(date +'%F %T')] [$SITE_NUM] Version unknown, downloading latest" >> "$LOG_RESTORE"

      wp core download \
        --path="$DOCROOT" \
        --force \
        --skip-content \
        --allow-root >> "$LOG_RESTORE" 2>&1 || {
          echo "[-] [$SITE_NUM] wp core download (latest) failed for ${DOCROOT}. See $LOG_RESTORE." >&2
          continue
        }
    fi

    log "[$SITE_NUM] Core files restored for: ${DOCROOT}"
    echo "[$(date +'%F %T')] [$SITE_NUM] Core restore completed" >> "$LOG_RESTORE"
    RESTORED=$((RESTORED + 1))
  else
    log "[$SITE_NUM] No malware indicators for this site in logs; skipping core_]()
