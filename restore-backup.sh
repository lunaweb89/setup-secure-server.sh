#!/usr/bin/env bash
#
# restore-backup.sh
#
# Helper to restore from Borg backups on Hetzner Storage Box.
#
# Modes:
#   1) Full restore (entire snapshot into /restore/...)
#   2) WordPress + MySQL + mail/LSWS/CyberPanel configs for selected sites:
#      - Auto-detect WP sites under home/<domain>/...
#      - Restore into /restore/... via Borg
#      - Automatically:
#          * rsync WP to /home/<domain>/public_html
#          * restore matching MySQL dump (var/backups/mysql/<DB_NAME>.sql)
#          * rsync mail configs (postfix/dovecot/opendkim)
#          * rsync LSWS + CyberPanel configs
#          * restart services
#

set -euo pipefail

log()  { echo "[+] $*"; }
err()  { echo "[-] $*" >&2; }
info() { echo "[*] $*"; }

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "This script must be run as root (sudo)."
    exit 1
  fi
}

require_root

BORG_PASSFILE="/root/.borg-passphrase"
REPO_FILE="/root/.borg-repository"

if [[ ! -f "$BORG_PASSFILE" ]]; then
  err "Borg passphrase file not found at $BORG_PASSFILE"
  exit 1
fi

if [[ ! -f "$REPO_FILE" ]]; then
  err "Repository file not found at $REPO_FILE"
  exit 1
fi

export BORG_PASSPHRASE
BORG_PASSPHRASE="$(<"$BORG_PASSFILE")"

REPOSITORY="$(<"$REPO_FILE")"
BORG_BIN="$(command -v borg || echo borg)"

echo "============================================"
echo " Borg Restore Helper"
echo "============================================"
echo "Repository: $REPOSITORY"
echo

# -------------------------------------------------------------
# SELECT ARCHIVE
# -------------------------------------------------------------

log "Fetching archive list..."
mapfile -t ARCHIVES < <("$BORG_BIN" list "$REPOSITORY" --format '{archive}{NEWLINE}')
if (( ${#ARCHIVES[@]} == 0 )); then
  err "No archives found in repository."
  exit 1
fi

echo "Available archives:"
for i in "${!ARCHIVES[@]}"; do
  printf "   %d) %s\n" "$((i+1))" "${ARCHIVES[i]}"
done
echo

read -rp "Select archive number (or q to quit): " ARCH_SEL
if [[ "$ARCH_SEL" == "q" || "$ARCH_SEL" == "Q" ]]; then
  info "Aborted by user."
  exit 0
fi

if ! [[ "$ARCH_SEL" =~ ^[0-9]+$ ]] || (( ARCH_SEL < 1 || ARCH_SEL > ${#ARCHIVES[@]} )); then
  err "Invalid selection."
  exit 1
fi

ARCHIVE="${ARCHIVES[ARCH_SEL-1]}"
log "Selected archive: $ARCHIVE"
echo

# -------------------------------------------------------------
# BASE RESTORE DIRECTORY + UNIQUE TARGET
# -------------------------------------------------------------

read -rp "Base restore directory [/restore]: " BASE_DIR
BASE_DIR="${BASE_DIR:-/restore}"

mkdir -p "$BASE_DIR"

# Normalised archive name for filesystem
ARCH_SAFE="${ARCHIVE//:/-}"
ARCH_SAFE="${ARCH_SAFE// /_}"

TARGET="$BASE_DIR/$ARCH_SAFE"
BASE_TARGET="$TARGET"
suffix=1
while [[ -e "$TARGET" ]]; do
  TARGET="${BASE_TARGET}-${suffix}"
  suffix=$((suffix+1))
done

log "Restore target: $TARGET"
mkdir -p "$TARGET"

# -------------------------------------------------------------
# RESTORE MODE SELECTION
# -------------------------------------------------------------

echo "Choose restore mode:"
echo "  1) Full restore (entire snapshot; slower, manual apply)"
echo "  2) WordPress + MySQL + mail/LSWS/CyberPanel configs for selected sites (faster, automatic)"
read -rp "Enter 1 or 2 [2]: " MODE
MODE="${MODE:-2}"

# -------------------------------------------------------------
# HELPER: MYSQL ROOT ACCESS
# -------------------------------------------------------------

build_mysql_cmd() {
  local pw_file="/etc/cyberpanel/mysqlPassword"
  if [[ -f "$pw_file" ]]; then
    local pw
    pw="$(<"$pw_file")"
    echo "mysql -u root -p$pw"
  else
    # fallback: socket auth root
    echo "mysql"
  fi
}

MYSQL_CMD="$(build_mysql_cmd)"

# -------------------------------------------------------------
# MODE 1: FULL RESTORE
# -------------------------------------------------------------

if [[ "$MODE" == "1" ]]; then
  log "Mode 1 selected: full restore."

  log "Starting full borg extract into: $TARGET"
  echo "This may take a while depending on archive size."
  (
    cd "$TARGET"
    "$BORG_BIN" extract --list "$REPOSITORY::$ARCHIVE"
  )

  echo
  log "Full restore completed into: $TARGET"
  echo "You can now manually rsync from this directory into / as needed."
  exit 0
fi

# -------------------------------------------------------------
# MODE 2: WORDPRESS + MYSQL + CONFIGS (AUTOMATIC)
# -------------------------------------------------------------

log "Mode 2 selected: WordPress + MySQL + mail/LSWS/CyberPanel configs for selected sites."

TMP_PATHS="$(mktemp)"
log "Listing archive paths for detection..."
if ! "$BORG_BIN" list "$REPOSITORY::$ARCHIVE" --format '{path}{NEWLINE}' > "$TMP_PATHS"; then
  rm -f "$TMP_PATHS"
  err "Failed to list archive contents."
  exit 1
fi

log "Scanning archive for WordPress sites (any wp-config.php under home/<domain>/...)..."
mapfile -t WP_CONFIGS < <(grep -E '^home/[^/]+/.*/wp-config\.php$' "$TMP_PATHS" || true)

if (( ${#WP_CONFIGS[@]} == 0 )); then
  rm -f "$TMP_PATHS"
  err "No WordPress installations (wp-config.php) found in this archive."
  exit 1
fi

declare -A SEEN
DOMAINS=()

for p in "${WP_CONFIGS[@]}"; do
  # home/<domain>/.../wp-config.php
  domain="$(echo "$p" | cut -d'/' -f2)"
  if [[ -n "$domain" && -z "${SEEN[$domain]+x}" ]]; then
    SEEN["$domain"]=1
    DOMAINS+=("$domain")
  fi
done

if (( ${#DOMAINS[@]} == 0 )); then
  rm -f "$TMP_PATHS"
  err "No domains detected from wp-config.php paths."
  exit 1
fi

echo
echo "Detected WordPress sites:"
for i in "${!DOMAINS[@]}"; do
  printf "  %2d) %s\n" "$((i+1))" "${DOMAINS[i]}"
done
echo

read -rp "Enter site numbers to restore (e.g. 1,3 or 'all') [all]: " SITE_SEL
SITE_SEL="${SITE_SEL:-all}"

SELECTED_DOMAINS=()

if [[ "$SITE_SEL" == "all" ]]; then
  SELECTED_DOMAINS=("${DOMAINS[@]}")
else
  IFS=',' read -r -a IDXES <<< "$SITE_SEL"
  for idx in "${IDXES[@]}"; do
    idx_trimmed="${idx//[[:space:]]/}"
    if ! [[ "$idx_trimmed" =~ ^[0-9]+$ ]]; then
      err "Invalid index: $idx_trimmed"
      rm -f "$TMP_PATHS"
      exit 1
    fi
    i_num=$((idx_trimmed-1))
    if (( i_num < 0 || i_num >= ${#DOMAINS[@]} )); then
      err "Index out of range: $idx_trimmed"
      rm -f "$TMP_PATHS"
      exit 1
    fi
    SELECTED_DOMAINS+=("${DOMAINS[i_num]}")
  done
fi

echo
log "You chose to restore these domains:"
for d in "${SELECTED_DOMAINS[@]}"; do
  echo "  - $d"
done

# -------------------------------------------------------------
# BUILD PATH LIST FOR PARTIAL EXTRACT
# -------------------------------------------------------------

INCLUDE_PATHS=()

for domain in "${SELECTED_DOMAINS[@]}"; do
  # WordPress + related stuff under home/<domain>
  INCLUDE_PATHS+=("home/$domain")
done

# Global things we always restore (if present in archive)
GLOBAL_PATHS=(
  "var/backups/mysql"
  "etc/postfix"
  "etc/dovecot"
  "etc/opendkim"
  "etc/cyberpanel"
  "usr/local/lsws"
  "usr/local/CyberCP"
)

for gp in "${GLOBAL_PATHS[@]}"; do
  if grep -qx "$gp" "$TMP_PATHS" || grep -q "^$gp/" "$TMP_PATHS"; then
    INCLUDE_PATHS+=("$gp")
  fi
done

rm -f "$TMP_PATHS"

echo
log "Will extract the following paths from the archive:"
for p in "${INCLUDE_PATHS[@]}"; do
  echo "  - $p"
done
echo

log "Starting partial borg extract into: $TARGET"
echo "This may take a few minutes depending on archive size."

(
  cd "$TARGET"
  "$BORG_BIN" extract --progress "$REPOSITORY::$ARCHIVE" "${INCLUDE_PATHS[@]}"
)

log "Partial extract completed into $TARGET"
echo

# -------------------------------------------------------------
# AUTOMATIC APPLY: FOR EACH SELECTED DOMAIN
# -------------------------------------------------------------

log "Applying restore automatically for selected domains..."

for domain in "${SELECTED_DOMAINS[@]}"; do
  echo
  echo "============================================"
  echo " Restoring domain: $domain"
  echo "============================================"

  RESTORED_HOME="$TARGET/home/$domain"
  LIVE_HOME="/home/$domain"

  if [[ ! -d "$RESTORED_HOME/public_html" ]]; then
    err "No public_html found for $domain in $RESTORED_HOME. Skipping this domain."
    continue
  fi

  mkdir -p "$LIVE_HOME/public_html"

  # 1) Rsync WordPress files
  log "Rsyncing WordPress files to $LIVE_HOME/public_html ..."
  rsync -aHAX --delete "$RESTORED_HOME/public_html/" "$LIVE_HOME/public_html/"

  # 2) Database restore (auto from wp-config.php)
  WP_CONFIG="$RESTORED_HOME/public_html/wp-config.php"
  if [[ ! -f "$WP_CONFIG" ]]; then
    err "wp-config.php not found for $domain at $WP_CONFIG; skipping DB restore for this domain."
    continue
  fi

  log "Parsing DB credentials from $WP_CONFIG ..."

  DB_NAME="$(grep -E "DB_NAME" "$WP_CONFIG" | head -n1 | sed "s/.*DB_NAME', *'\(.*\)'.*/\1/")" || DB_NAME=""
  DB_USER="$(grep -E "DB_USER" "$WP_CONFIG" | head -n1 | sed "s/.*DB_USER', *'\(.*\)'.*/\1/")" || DB_USER=""
  DB_PASS="$(grep -E "DB_PASSWORD" "$WP_CONFIG" | head -n1 | sed "s/.*DB_PASSWORD', *'\(.*\)'.*/\1/")" || DB_PASS=""

  if [[ -z "$DB_NAME" || -z "$DB_USER" || -z "$DB_PASS" ]]; then
    err "Failed to parse DB credentials from wp-config.php for $domain; skipping DB restore."
    continue
  fi

  log "DB_NAME = $DB_NAME"
  log "DB_USER = $DB_USER"
  # Not logging DB_PASS for security

  DUMPFILE="$TARGET/var/backups/mysql/$DB_NAME.sql"
  if [[ ! -f "$DUMPFILE" ]]; then
    err "MySQL dump $DUMPFILE not found; skipping DB import for $domain."
    continue
  fi

  log "Ensuring database & user exist for $DB_NAME ..."

  $MYSQL_CMD <<EOF || err "Warning: could not create DB/user for $DB_NAME (continuing)."
CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
EOF

  log "Importing dump $DUMPFILE into $DB_NAME ..."
  $MYSQL_CMD "$DB_NAME" < "$DUMPFILE" || err "MySQL import failed for $DB_NAME (check manually)."

  log "Domain $domain: WordPress files + DB restored."
done

# -------------------------------------------------------------
# APPLY GLOBAL CONFIGS (MAIL, LSWS, CYBERPANEL)
# -------------------------------------------------------------

echo
log "Applying global configs (if present in restore tree)..."

if [[ -d "$TARGET/etc/postfix" ]]; then
  log "Rsyncing /etc/postfix ..."
  rsync -aHAX "$TARGET/etc/postfix/" /etc/postfix/
fi

if [[ -d "$TARGET/etc/dovecot" ]]; then
  log "Rsyncing /etc/dovecot ..."
  rsync -aHAX "$TARGET/etc/dovecot/" /etc/dovecot/
fi

if [[ -d "$TARGET/etc/opendkim" ]]; then
  log "Rsyncing /etc/opendkim ..."
  rsync -aHAX "$TARGET/etc/opendkim/" /etc/opendkim/
fi

if [[ -d "$TARGET/etc/cyberpanel" ]]; then
  log "Rsyncing /etc/cyberpanel ..."
  rsync -aHAX "$TARGET/etc/cyberpanel/" /etc/cyberpanel/
fi

if [[ -d "$TARGET/usr/local/lsws" ]]; then
  log "Rsyncing /usr/local/lsws ..."
  rsync -aHAX "$TARGET/usr/local/lsws/" /usr/local/lsws/
fi

if [[ -d "$TARGET/usr/local/CyberCP" ]]; then
  log "Rsyncing /usr/local/CyberCP ..."
  rsync -aHAX "$TARGET/usr/local/CyberCP/" /usr/local/CyberCP/
fi

# -------------------------------------------------------------
# RESTART SERVICES
# -------------------------------------------------------------

echo
log "Restarting services (Postfix, Dovecot, LSWS, CyberPanel)..."

systemctl restart postfix  || err "Failed to restart postfix (check manually)."
systemctl restart dovecot  || err "Failed to restart dovecot (check manually)."
systemctl restart lsws     || err "Failed to restart lsws (check manually)."
systemctl restart lscpd    || err "Failed to restart lscpd (check manually)."

echo
log "Automatic restore completed."

echo
echo "Summary:"
echo "  - Selected archive: $ARCHIVE"
echo "  - Restore target:   $TARGET"
echo "  - Domains restored: ${SELECTED_DOMAINS[*]}"
echo
echo "Each selected domain had:"
echo "  - WordPress files rsynced to /home/<domain>/public_html"
echo "  - Matching DB imported from var/backups/mysql/<DB_NAME>.sql"
echo "  - Mail + LSWS + CyberPanel configs rsynced (if present)"
echo
echo "If anything looks off, you can still inspect: $TARGET"
echo "and manually adjust or re-rsync specific paths."
echo

exit 0
