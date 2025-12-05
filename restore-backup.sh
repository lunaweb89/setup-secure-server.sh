#!/usr/bin/env bash
#
# restore-backup.sh
#
# Safely restore a Borg archive from your Hetzner Storage Box.
# - Reads repo + passphrase from:
#     /root/.borg-repository
#     /root/.borg-passphrase
# - Lists archives and lets you pick one by number
# - Restores into /restore/<archive-name> (non-destructive)
# - Shows archive info, progress, and a rough estimated restore time
#

set -euo pipefail

err() { echo "[-] $*" >&2; }
log() { echo "[+] $*"; }

BORG_PASSFILE="/root/.borg-passphrase"
REPO_FILE="/root/.borg-repository"

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

log "Fetching archive list from repository..."
if ! borg list --short "$REPOSITORY" > /tmp/borg-archives.$$; then
  err "Failed to list archives. Check passphrase or connectivity."
  rm -f /tmp/borg-archives.$$
  exit 1
fi

mapfile -t ARCHIVES < /tmp/borg-archives.$$
rm -f /tmp/borg-archives.$$

if (( ${#ARCHIVES[@]} == 0 )); then
  err "No archives found in repository."
  exit 1
fi

echo "Available archives:"
for i in "${!ARCHIVES[@]}"; do
  printf "  %2d) %s\n" "$((i+1))" "${ARCHIVES[i]}"
done
echo

# -------------------------------------------------------------
# Select archive
# -------------------------------------------------------------

read -rp "Select archive number to restore (or 'q' to quit): " CHOICE

if [[ "$CHOICE" =~ ^[Qq]$ ]]; then
  echo "[*] Aborted by user."
  exit 0
fi

if ! [[ "$CHOICE" =~ ^[0-9]+$ ]]; then
  err "Invalid selection."
  exit 1
fi

INDEX=$((CHOICE-1))

if (( INDEX < 0 || INDEX >= ${#ARCHIVES[@]} )); then
  err "Selection out of range."
  exit 1
fi

ARCHIVE="${ARCHIVES[INDEX]}"
echo
log "Selected archive: $ARCHIVE"
echo

# -------------------------------------------------------------
# Show archive info + estimate restore time (if possible)
# -------------------------------------------------------------

EST_SIZE_BYTES=""
EST_SPEED_MB=40   # assumed effective throughput (MB/s) for rough ETA

echo "[*] Getting archive info (size, dates)..."
if borg info --json "$REPOSITORY::$ARCHIVE" > /tmp/borg-archive-info.$$ 2>/dev/null; then
  if command -v python3 >/dev/null 2>&1; then
    EST_SIZE_BYTES="$(python3 - "$EST_SPEED_MB" << 'PYEOF'
import sys, json
data = json.load(open("/tmp/borg-archive-info.$$"))
arch = data.get("archives", [{}])[0]
size = arch.get("stats", {}).get("compressed_size") or arch.get("stats", {}).get("original_size")
if size is not None:
    print(size)
PYEOF
)"
  fi

  echo
  echo "Archive info:"
  borg info "$REPOSITORY::$ARCHIVE" || true
  echo
else
  echo "[!] borg info --json not available or failed; skipping detailed info."
fi

rm -f /tmp/borg-archive-info.$$ 2>/dev/null || true

if [[ -n "${EST_SIZE_BYTES:-}" && "$EST_SIZE_BYTES" =~ ^[0-9]+$ ]]; then
  # size in MB (decimal)
  EST_SIZE_MB=$((EST_SIZE_BYTES / 1024 / 1024))
  # estimated seconds at EST_SPEED_MB MB/s
  if (( EST_SIZE_MB > 0 )); then
    EST_SECONDS=$((EST_SIZE_MB / EST_SPEED_MB + 1))
    EST_MIN=$((EST_SECONDS / 60))
    EST_SEC=$((EST_SECONDS % 60))
    echo "[*] Approx archive compressed size: ~${EST_SIZE_MB} MB"
    echo "[*] Rough restore time estimate at ${EST_SPEED_MB} MB/s: ~${EST_MIN} min ${EST_SEC} s"
  fi
fi

echo

# -------------------------------------------------------------
# Choose restore path
# -------------------------------------------------------------

read -rp "Base restore directory [/restore]: " BASE_RESTORE
BASE_RESTORE="${BASE_RESTORE:-/restore}"

# normalize
BASE_RESTORE="${BASE_RESTORE%/}"

RESTORE_DIR="${BASE_RESTORE}/${ARCHIVE}"

log "Restore target: $RESTORE_DIR"
if [[ -e "$RESTORE_DIR" ]]; then
  err "Target path already exists: $RESTORE_DIR"
  err "Remove it or choose a different base directory and try again."
  exit 1
fi

mkdir -p "$BASE_RESTORE"
mkdir "$RESTORE_DIR"

# -------------------------------------------------------------
# Extract archive (with progress)
# -------------------------------------------------------------

echo
log "Starting restore into: $RESTORE_DIR"
echo "[*] This may take a while. Showing file-level progress (--list)..."
echo

START_TS=$(date +%s)

# Extract into restore dir by changing into it first
cd "$RESTORE_DIR"

if borg extract --list "$REPOSITORY::$ARCHIVE"; then
  END_TS=$(date +%s)
  DURATION=$((END_TS - START_TS))
  MIN=$((DURATION / 60))
  SEC=$((DURATION % 60))

  echo
  echo "[SUCCESS] Archive restored to: $RESTORE_DIR"
  echo "[INFO] Actual restore time: ${MIN} min ${SEC} s"
  echo "You can safely inspect files there without touching the live system."
else
  err "borg extract failed."
  exit 1
fi

exit 0
