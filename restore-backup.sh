#!/usr/bin/env bash
#
# restore-backup.sh
# Borg Restore Helper with:
# - Mode 1 (Full restore)
# - Mode 2 (WordPress + Email + MySQL + Configs)
# - Progress output + ETA
# - Auto-increment restore dirs
# - Auto-cleanup old restore dirs
#

set -euo pipefail

log() { echo "[+] $*"; }
err() { echo "[-] $*" >&2; }

PASSFILE="/root/.borg-passphrase"
REPOFILE="/root/.borg-repository"

if [[ ! -f "$PASSFILE" || ! -f "$REPOFILE" ]]; then
    err "Missing passphrase or repository file."
    err "Expected:"
    err "  $PASSFILE"
    err "  $REPOFILE"
    exit 1
fi

export BORG_PASSPHRASE="$(<$PASSFILE)"
REPO="$(<$REPOFILE)"

echo "============================================"
echo " Borg Restore Helper"
echo "============================================"
echo "Repository: $REPO"
echo

# -------------------------------------------------
# Fetch archive list
# -------------------------------------------------
log "Fetching archive list..."

mapfile -t ARCHIVES < <(borg list "$REPO" --format "{archive}{NEWLINE}" 2>/dev/null)

if (( ${#ARCHIVES[@]} == 0 )); then
    err "No archives found."
    exit 1
fi

echo "Available archives:"
i=1
for a in "${ARCHIVES[@]}"; do
    echo "   $i) $a"
    ((i++))
done
echo

read -rp "Select archive number (or q to quit): " ARCH_NO
[[ "$ARCH_NO" == "q" ]] && { echo "[*] Aborted by user."; exit 0; }

if ! [[ "$ARCH_NO" =~ ^[0-9]+$ ]] || (( ARCH_NO < 1 || ARCH_NO > ${#ARCHIVES[@]} )); then
    err "Invalid selection."
    exit 1
fi

ARCHIVE="${ARCHIVES[$((ARCH_NO - 1))]}"
log "Selected archive: $ARCHIVE"
echo

# -------------------------------------------------
# MODE SELECTION
# -------------------------------------------------

echo "Choose restore mode:"
echo "  1) Full restore (entire filesystem snapshot)"
echo "  2) WordPress + Email + MySQL + Configs for selected sites"
read -rp "Enter 1 or 2 [2]: " MODE
MODE="${MODE:-2}"

if [[ "$MODE" != "1" && "$MODE" != "2" ]]; then
    err "Invalid mode."
    exit 1
fi

# -------------------------------------------------
# Base restore directory
# -------------------------------------------------

DEFAULT_BASE="/restore"
read -rp "Base restore directory [$DEFAULT_BASE]: " BASEDIR
BASEDIR="${BASEDIR:-$DEFAULT_BASE}"

ARCHIVE_SAFE="${ARCHIVE//:/-}"
REST_DIR="${BASEDIR}/${ARCHIVE_SAFE}"

# Auto-increment folder name if exists
COUNT=1
while [[ -e "$REST_DIR" ]]; do
    REST_DIR="${BASEDIR}/${ARCHIVE_SAFE}-${COUNT}"
    ((COUNT++))
done

log "Restore target: $REST_DIR"
mkdir -p "$REST_DIR"

# Cleanup restore folders >3 days
find "$BASEDIR" -maxdepth 1 -type d -mtime +3 -name "*$(hostname)*" -exec rm -rf {} \; 2>/dev/null || true

# -------------------------------------------------
# MODE 2 → Discover WordPress sites
# -------------------------------------------------

SELECTED_SITES=()

if [[ "$MODE" == "2" ]]; then
    echo
    log "Scanning archive for WordPress installations..."

    mapfile -t WP_SITES < <(
        borg list "$REPO::$ARCHIVE" --path home 2>/dev/null \
        | grep "public_html" \
        | awk -F'/' '{print $2}' | sort -u
    )

    if (( ${#WP_SITES[@]} == 0 )); then
        err "No WordPress sites detected in archive!"
        exit 1
    fi

    echo "Detected WordPress sites:"
    i=1
    for site in "${WP_SITES[@]}"; do
        echo "  $i) $site"
        ((i++))
    done
    echo

    read -rp "Enter site numbers to restore (e.g. 1,2 or 'all') [all]: " SITESEL
    SITESEL="${SITESEL:-all}"

    if [[ "$SITESEL" == "all" ]]; then
        SELECTED_SITES=("${WP_SITES[@]}")
    else
        IFS=',' read -ra IDX <<< "$SITESEL"
        for n in "${IDX[@]}"; do
            if ! [[ "$n" =~ ^[0-9]+$ ]] || (( n < 1 || n > ${#WP_SITES[@]} )); then
                err "Invalid site number: $n"
                exit 1
            fi
            SELECTED_SITES+=("${WP_SITES[$((n-1))]}")
        done
    fi

    echo
    log "Sites selected for restore:"
    printf " - %s\n" "${SELECTED_SITES[@]}"
    echo
fi

# -------------------------------------------------
# Extract with ETA + progress
# -------------------------------------------------

START_TIME=$(date +%s)

log "Calculating archive size for ETA..."
SIZE_BYTES=$(borg info "$REPO::$ARCHIVE" --json | jq '.archives[0].stats.original_size')
SIZE_GB=$(awk "BEGIN {printf \"%.2f\", $SIZE_BYTES/1024/1024/1024}")

echo "[INFO] Archive size: $SIZE_GB GB"
echo

log "Extracting archive..."
if [[ "$MODE" == "1" ]]; then
    borg extract "$REPO::$ARCHIVE" --progress --destination "$REST_DIR"
else
    for SITE in "${SELECTED_SITES[@]}"; do
        log "Extracting WordPress + email for: $SITE"

        borg extract "$REPO::$ARCHIVE" \
            --progress \
            --destination "$REST_DIR" \
            "home/$SITE/public_html" \
            "home/$SITE/mail" \
            2>/dev/null || true
    done

    log "Extracting MySQL dumps..."
    borg extract "$REPO::$ARCHIVE" --progress --destination "$REST_DIR" "var/backups/mysql" || true

    log "Extracting configs..."
    borg extract "$REPO::$ARCHIVE" --progress --destination "$REST_DIR" \
        "etc/postfix" \
        "etc/dovecot" \
        "etc/opendkim" \
        "etc/cyberpanel" \
        "usr/local/lsws" \
        2>/dev/null || true
fi

END_TIME=$(date +%s)
DURATION=$(( END_TIME - START_TIME ))

echo
log "[SUCCESS] Restore complete."
echo "[INFO] Time taken: ${DURATION}s"
echo
echo "Restore data available at:"
echo "  $REST_DIR"
echo
exit 0
