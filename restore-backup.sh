#!/usr/bin/env bash
#
# restore-backup.sh
#
# Safe Borg restore helper with two modes:
#   1) Full restore (entire snapshot into a restore dir)
#   2) WordPress + email + MySQL dumps + mail/webserver configs for selected sites
#
#   - Reads repo + passphrase from:
#       /root/.borg-repository
#       /root/.borg-passphrase
#   - Restores into /restore/... by default (non-destructive)
#

set -euo pipefail

err() { echo "[-] $*" >&2; }
log() { echo "[+] $*"; }

BORG_PASSFILE="/root/.borg-passphrase"
REPO_FILE="/root/.borg-repository"
KEEP_RESTORES=3   # number of restore dirs per prefix to keep under base dir

# -------------------------------------------------------------
# Validation
# -------------------------------------------------------------

if [[ ! -f "$BORG_PASSFILE" ]]; then
  err "Passphrase file missing: $BORG_PASSFILE"
  exit 1
fi

if [[ ! -f "$REPO_FILE" ]]; then
  err "Repository file missing: $REPO_FILE"
  exit 1
fi

export BORG_PASSPHRASE="$(<"$BORG_PASSFILE")"
REPOSITORY="$(<"$REPO_FILE")"

echo "============================================"
echo " Borg Restore Helper"
echo "============================================"
echo "Repository: $REPOSITORY"
echo

# -------------------------------------------------------------
# Fetch archive list
# -------------------------------------------------------------

log "Fetching archive list..."
if ! borg list --short "$REPOSITORY" > /tmp/borg-archives.$$; then
  err "Cannot list archives. Incorrect passphrase or connectivity issue."
  rm -f /tmp/borg-archives.$$
  exit 1
fi

mapfile -t ARCHIVES < /tmp/borg-archives.$$
rm -f /tmp/borg-archives.$$

if (( ${#ARCHIVES[@]} == 0 )); then
  err "No archives found."
  exit 1
fi

echo "Available archives:"
for i in "${!ARCHIVES[@]}"; do
  printf "  %2d) %s\n" "$((i+1))" "${ARCHIVES[i]}"
done
echo

read -rp "Select archive number (or q to quit): " CHOICE
if [[ "$CHOICE" =~ ^[Qq]$ ]]; then
  echo "[*] Aborted by user."
  exit 0
fi
if ! [[ "$CHOICE" =~ ^[0-9]+$ ]]; then
  err "Invalid choice."
  exit 1
fi

INDEX=$((CHOICE - 1))
if (( INDEX < 0 || INDEX >= ${#ARCHIVES[@]} )); then
  err "Selection out of range."
  exit 1
fi

ARCHIVE="${ARCHIVES[$INDEX]}"
ARCHIVE_PREFIX="$(basename "$ARCHIVE")"

log "Selected archive: $ARCHIVE"
echo

# -------------------------------------------------------------
# Base restore directory
# -------------------------------------------------------------

read -rp "Base restore directory [/restore]: " BASE
BASE="${BASE:-/restore}"
BASE="${BASE%/}"

mkdir -p "$BASE"

# -------------------------------------------------------------
# Choose restore mode
# -------------------------------------------------------------

echo "Choose restore mode:"
echo "  1) Full restore (entire snapshot; slower)"
echo "  2) WordPress + email + MySQL dumps + mail/LSWS configs for selected sites (faster)"
read -rp "Enter 1 or 2 [2]: " MODE
MODE="${MODE:-2}"

if [[ "$MODE" != "1" && "$MODE" != "2" ]]; then
  err "Invalid mode selection."
  exit 1
fi

# -------------------------------------------------------------
# Helper: auto-clean old restore dirs and choose new target
# -------------------------------------------------------------

choose_target_dir() {
  local base="$1"
  local prefix="$2"
  local target="${base}/${prefix}"

  # Cleanup old dirs for this prefix
  if [[ -d "$base" ]]; then
    mapfile -t OLD_DIRS < <(
      find "$base" -maxdepth 1 -mindepth 1 -type d -name "${prefix}*" -printf '%T@ %p\n' \
        | sort -nr \
        | awk '{ $1=""; sub(/^ /, ""); print }'
    )

    if (( ${#OLD_DIRS[@]} > KEEP_RESTORES )); then
      local to_delete=$(( ${#OLD_DIRS[@]} - KEEP_RESTORES ))
      log "Found ${#OLD_DIRS[@]} existing restore dirs for '${prefix}'. Keeping newest ${KEEP_RESTORES}, deleting ${to_delete} older."

      local i
      for ((i=KEEP_RESTORES; i<${#OLD_DIRS[@]}; i++)); do
        local d="${OLD_DIRS[i]}"
        if [[ -d "$d" ]]; then
          log "Deleting old restore dir: $d"
          rm -rf -- "$d"
        fi
      done
    fi
  fi

  # Auto-increment if target exists
  if [[ -e "$target" ]]; then
    log "Base target exists, choosing next available suffix..."
    local n=1
    local new_target="${target}-${n}"
    while [[ -e "$new_target" ]]; do
      n=$((n+1))
      new_target="${target}-${n}"
    done
    target="$new_target"
  fi

  echo "$target"
}

# -------------------------------------------------------------
# MODE 1: FULL RESTORE
# -------------------------------------------------------------

if [[ "$MODE" == "1" ]]; then
  TARGET="$(choose_target_dir "$BASE" "$ARCHIVE_PREFIX")"
  log "Full restore into: $TARGET"
  mkdir -p "$TARGET"

  cd "$TARGET"
  START=$(date +%s)

  if borg extract --list "$REPOSITORY::$ARCHIVE"; then
    END=$(date +%s)
    DUR=$((END - START))
    MIN=$((DUR / 60))
    SEC=$((DUR % 60))

    echo
    log "Full restore completed."
    log "Restored to: $TARGET"
    echo "[INFO] Time taken: ${MIN}m ${SEC}s"
    exit 0
  else
    err "borg extract failed."
    exit 1
  fi
fi

# -------------------------------------------------------------
# MODE 2: WORDPRESS + EMAIL + MYSQL DUMPS + MAIL/LSWS CONFIG
# -------------------------------------------------------------

log "Mode 2 selected: WordPress + email + MySQL dumps + mail/LSWS config for selected sites."

# List all paths in archive once (for WP detection + config presence)
TMP_PATHS="/tmp/borg-paths-$$.txt"
log "Pre-listing archive paths (for site detection & config selection)..."
borg list --format '{path}{NL}' "$REPOSITORY::$ARCHIVE" > "$TMP_PATHS"

log "Scanning archive for WordPress sites (wp-config.php under home/*/public_html)..."
mapfile -t WP_CONFIGS < <(
  grep -E '^home/[^/]+/public_html/wp-config\.php$' "$TMP_PATHS" || true
)

if (( ${#WP_CONFIGS[@]} == 0 )); then
  rm -f "$TMP_PATHS"
  err "No WordPress installations (wp-config.php) found in this archive."
  exit 1
fi

DOMAINS=()
declare -A SEEN

for p in "${WP_CONFIGS[@]}"; do
  # path form: home/example.com/public_html/wp-config.php
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

read -rp "Enter site numbers to restore (e.g. 1,3 or 'all') [all]: " SEL
SEL="${SEL:-all}"
SEL=$(echo "$SEL" | tr 'A-Z' 'a-z' | tr -d ' ')

SELECTED_DOMAINS=()
if [[ "$SEL" == "all" ]]; then
  SELECTED_DOMAINS=("${DOMAINS[@]}")
else
  IFS=',' read -r -a IDX_ARR <<< "$SEL"
  for idx in "${IDX_ARR[@]}"; do
    if ! [[ "$idx" =~ ^[0-9]+$ ]]; then
      rm -f "$TMP_PATHS"
      err "Invalid index in selection: $idx"
      exit 1
    fi
    j=$((idx - 1))
    if (( j < 0 || j >= ${#DOMAINS[@]} )); then
      rm -f "$TMP_PATHS"
      err "Index out of range: $idx"
      exit 1
    fi
    SELECTED_DOMAINS+=("${DOMAINS[j]}")
  done
fi

echo
log "Sites selected:"
for d in "${SELECTED_DOMAINS[@]}"; do
  echo "  - $d"
done
echo

TARGET_PREFIX="${ARCHIVE_PREFIX}-wp-stack"
TARGET="$(choose_target_dir "$BASE" "$TARGET_PREFIX")"
log "Partial restore (sites + email + MySQL dumps + mail/LSWS configs) into: $TARGET"
mkdir -p "$TARGET"
cd "$TARGET"

# Build list of paths to extract from archive
PATHS_TO_EXTRACT=()

# Per-site data: WordPress + per-domain mail
for d in "${SELECTED_DOMAINS[@]}"; do
  PATHS_TO_EXTRACT+=( "home/${d}/public_html" )
  PATHS_TO_EXTRACT+=( "home/${d}/mail" )
done

# Always include MySQL dumps folder if present in archive
if grep -q '^var/backups/mysql\(/.*\)\?$' "$TMP_PATHS"; then
  PATHS_TO_EXTRACT+=( "var/backups/mysql" )
fi

# Global mailserver + LSWS/CyberPanel configs (restored into restore dir, not live)
GLOBAL_CFG_CANDIDATES=(
  "etc/postfix"
  "etc/dovecot"
  "etc/opendkim"
  "etc/pure-ftpd"
  "usr/local/lsws"
  "etc/cyberpanel"
  "usr/local/CyberCP"
)

for cfg in "${GLOBAL_CFG_CANDIDATES[@]}"; do
  if grep -q "^${cfg}\(/.*\)\?$" "$TMP_PATHS"; then
    PATHS_TO_EXTRACT+=( "$cfg" )
  fi
done

rm -f "$TMP_PATHS"

log "Paths to extract from archive:"
for p in "${PATHS_TO_EXTRACT[@]}"; do
  echo "  - $p"
done
echo

START=$(date +%s)

if borg extract --list "$REPOSITORY::$ARCHIVE" "${PATHS_TO_EXTRACT[@]}"; then
  END=$(date +%s)
  DUR=$((END - START))
  MIN=$((DUR / 60))
  SEC=$((DUR % 60))

  echo
  log "Partial restore completed."
  log "Restored to: $TARGET"
  echo "[INFO] Time taken: ${MIN}m ${SEC}s"
  echo
  echo "Contents now available under:"
  echo "  - $TARGET/home/<domain>/public_html        (WordPress files)"
  echo "  - $TARGET/home/<domain>/mail               (per-domain mailboxes)"
  echo "  - $TARGET/var/backups/mysql/*.sql          (MySQL dumps, if present)"
  echo "  - $TARGET/etc/postfix, /etc/dovecot, etc.  (mailserver configs, if present)"
  echo "  - $TARGET/usr/local/lsws, /etc/cyberpanel  (LSWS/CyberPanel configs, if present)"
  echo
  echo "You can now selectively sync these back onto the live server and import the DBs."
  exit 0
else
  err "Partial borg extract failed."
  exit 1
fi
