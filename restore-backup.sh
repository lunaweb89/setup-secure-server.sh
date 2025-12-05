#!/usr/bin/env bash
#
# restore-backup.sh
#
# Helper to restore from Borg backups created by setup-backup-module.sh
# Modes:
#   1) Full restore (entire filesystem snapshot)
#   2) WordPress + Email + MySQL + mail/LSWS configs for selected sites
#
# Non-destructive: everything is restored under /restore/... by default.
#

set -euo pipefail

log() { echo "[+] $*"; }
err() { echo "[-] $*" >&2; }

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
  err "Expected repository URL to be stored there by setup-backup-module.sh"
  exit 1
fi

export BORG_PASSPHRASE="$(<"$BORG_PASSFILE")"
REPOSITORY="$(<"$REPO_FILE")"
BORG_BIN="$(command -v borg || echo /usr/bin/borg)"

echo "============================================"
echo " Borg Restore Helper"
echo "============================================"
echo "Repository: $REPOSITORY"
echo

# -------------------------------------------------------------
# LIST ARCHIVES
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
  echo "[*] Aborted by user."
  exit 0
fi

if ! [[ "$ARCH_SEL" =~ ^[0-9]+$ ]] || (( ARCH_SEL < 1 || ARCH_SEL > ${#ARCHIVES[@]} )); then
  err "Invalid archive selection."
  exit 1
fi

ARCHIVE="${ARCHIVES[ARCH_SEL-1]}"
log "Selected archive: $ARCHIVE"
echo

# -------------------------------------------------------------
# RESTORE BASE DIRECTORY
# -------------------------------------------------------------

read -rp "Base restore directory [/restore]: " BASE_DIR
BASE_DIR="${BASE_DIR:-/restore}"

mkdir -p "$BASE_DIR"

# Sanitize archive name into a folder-safe name
ARCHIVE_SAFE="${ARCHIVE//:/-}"
ARCHIVE_SAFE="${ARCHIVE_SAFE// /-}"

TARGET="$BASE_DIR/$ARCHIVE_SAFE"

# If target exists, append -1, -2, ...
if [[ -e "$TARGET" ]]; then
  suffix=1
  while [[ -e "${TARGET}-${suffix}" ]]; do
    ((suffix++))
  done
  TARGET="${TARGET}-${suffix}"
fi

log "Restore target: $TARGET"
mkdir -p "$TARGET"

# -------------------------------------------------------------
# RESTORE MODE
# -------------------------------------------------------------

echo "Choose restore mode:"
echo "  1) Full restore (entire snapshot; slower)"
echo "  2) WordPress + Email + MySQL dumps + mail/LSWS configs for selected sites (faster)"
read -rp "Enter 1 or 2 [2]: " MODE
MODE="${MODE:-2}"

# Helper: check if a path exists in archive path listing
path_exists_in_archive() {
  local p="$1"
  local tmp_file="$2"
  # Match directory or file prefix
  grep -q "^${p}\(/.*\)\?$" "$tmp_file"
}

# -------------------------------------------------------------
# MODE 1: FULL RESTORE
# -------------------------------------------------------------

if [[ "$MODE" == "1" ]]; then
  echo
  log "Mode 1 selected: full restore of entire snapshot."
  echo "This will restore EVERYTHING from the archive into:"
  echo "  $TARGET"
  echo
  read -rp "Proceed with full restore? [y/N]: " CONFIRM
  CONFIRM="${CONFIRM:-N}"
  if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "[*] Aborted by user."
    exit 0
  fi

  log "Starting full borg extract (this may take a while)..."
  (
    cd "$TARGET"
    # ARCHIVE must be first positional argument
    "$BORG_BIN" extract --progress "$REPOSITORY::$ARCHIVE"
  )
  log "Full restore completed successfully into $TARGET"
  exit 0
fi

# -------------------------------------------------------------
# MODE 2: PARTIAL RESTORE FOR SELECTED SITES
# -------------------------------------------------------------

echo
log "Mode 2 selected: WordPress + email + MySQL dumps + mail/LSWS config for selected sites."

TMP_PATHS="$(mktemp)"
trap 'rm -f "$TMP_PATHS"' EXIT

log "Listing archive paths for detection..."
if ! "$BORG_BIN" list "$REPOSITORY::$ARCHIVE" --format '{path}{NEWLINE}' > "$TMP_PATHS"; then
  err "Failed to list archive contents for detection."
  exit 1
fi

log "Scanning archive for WordPress sites (any wp-config.php under home/<domain>/...)..."
mapfile -t WP_CONFIGS < <(
  grep -E '^home/[^/]+/.*/wp-config\.php$' "$TMP_PATHS" || true
)

if (( ${#WP_CONFIGS[@]} == 0 )); then
  err "No WordPress installations (wp-config.php) found in this archive."
  exit 1
fi

DOMAINS=()
declare -A SEEN

for p in "${WP_CONFIGS[@]}"; do
  # path pattern: home/<domain>/.../wp-config.php
  domain="$(echo "$p" | cut -d'/' -f2)"
  if [[ -n "$domain" && -z "${SEEN[$domain]+x}" ]]; then
    SEEN["$domain"]=1
    DOMAINS+=("$domain")
  fi
done

if (( ${#DOMAINS[@]} == 0 )); then
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

if [[ "$SITE_SEL" == "all" || "$SITE_SEL" == "ALL" ]]; then
  SELECTED_DOMAINS=("${DOMAINS[@]}")
else
  IFS=',' read -r -a TOKENS <<< "$SITE_SEL"
  for t in "${TOKENS[@]}"; do
    t="$(echo "$t" | xargs)"  # trim
    if ! [[ "$t" =~ ^[0-9]+$ ]]; then
      err "Invalid selection token: $t"
      exit 1
    fi
    idx=$((t-1))
    if (( idx < 0 || idx >= ${#DOMAINS[@]} )); then
      err "Site index out of range: $t"
      exit 1
    fi
    SELECTED_DOMAINS+=("${DOMAINS[idx]}")
  done
fi

if (( ${#SELECTED_DOMAINS[@]} == 0 )); then
  err "No domains selected."
  exit 1
fi

echo
log "You chose to restore these domains:"
for d in "${SELECTED_DOMAINS[@]}"; do
  echo "  - $d"
done
echo

# -------------------------------------------------------------
# BUILD PATH LIST TO RESTORE (ONLY EXISTING PATHS)
# -------------------------------------------------------------

PATHS=()

# Per-site paths
for domain in "${SELECTED_DOMAINS[@]}"; do
  wp_dir="home/${domain}/public_html"
  mail_dir="home/${domain}/mail"

  if path_exists_in_archive "$wp_dir" "$TMP_PATHS"; then
    log "Will restore WordPress files for $domain from $wp_dir"
    PATHS+=("$wp_dir")
  else
    err "WordPress base directory not found in archive for $domain at $wp_dir"
  fi

  if path_exists_in_archive "$mail_dir" "$TMP_PATHS"; then
    log "Will restore mailboxes for $domain from $mail_dir"
    PATHS+=("$mail_dir")
  else
    log "No mail directory stored for $domain (skipping mail restore for this domain)."
  fi
done

# Global / shared paths (configs & MySQL dumps)
GLOBAL_PATHS=(
  "var/backups/mysql"
  "etc/postfix"
  "etc/dovecot"
  "etc/opendkim"
  "etc/cyberpanel"
  "usr/local/lsws"
  "usr/local/CyberCP"
)

for g in "${GLOBAL_PATHS[@]}"; do
  if path_exists_in_archive "$g" "$TMP_PATHS"; then
    log "Will also restore: $g"
    PATHS+=("$g")
  else
    log "Path not found in archive (skipping): $g"
  fi
done

if (( ${#PATHS[@]} == 0 )); then
  err "No matching paths found in archive for selected sites/configs."
  exit 1
fi

# -------------------------------------------------------------
# PARTIAL EXTRACT
# -------------------------------------------------------------

echo
log "Starting partial borg extract into: $TARGET"
echo "This may take a few minutes depending on archive size."
echo

(
  cd "$TARGET"
  # ARCHIVE must be the first positional argument
  "$BORG_BIN" extract --progress "$REPOSITORY::$ARCHIVE" "${PATHS[@]}"
)

log "Partial restore completed successfully into $TARGET"
echo
echo "Contents include (for selected sites):"
echo "  - home/<domain>/public_html   (WordPress files)"
echo "  - home/<domain>/mail          (if existed in archive)"
echo "  - var/backups/mysql/*.sql     (database dumps)"
echo "  - etc/postfix, etc/dovecot, etc/opendkim"
echo "  - etc/cyberpanel, usr/local/lsws, usr/local/CyberCP"
echo
echo "Next steps (on a rebuilt server) typically are:"
echo "  - rsync public_html into /home/<domain>/public_html"
echo "  - import the correct MySQL dump into a new DB"
echo "  - rsync mail/ if you want to restore mailboxes"
echo "  - compare/merge configs from etc/ and usr/local/lsws"
