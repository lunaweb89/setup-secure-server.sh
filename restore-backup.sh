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
#

set -euo pipefail

err() { echo "[-] $*" >&2; }

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

echo "[+] Fetching archive list from repository..."
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
echo "[+] Selected archive: $ARCHIVE"
echo

# -------------------------------------------------------------
# Choose restore path
# -------------------------------------------------------------

read -rp "Base restore directory [/restore]: " BASE_RESTORE
BASE_RESTORE="${BASE_RESTORE:-/restore}"

# normalize
BASE_RESTORE="${BASE_RESTORE%/}"

RESTORE_DIR="${BASE_RESTORE}/${ARCHIVE}"

echo "[+] Restore target: $RESTORE_DIR"
if [[ -e "$RESTORE_DIR" ]]; then
  err "Target path already exists: $RESTORE_DIR"
  err "Remove it or choose a different base directory and try again."
  exit 1
fi

mkdir -p "$BASE_RESTORE"
mkdir "$RESTORE_DIR"

# -------------------------------------------------------------
# Extract archive
# -------------------------------------------------------------

echo
echo "[+] Running Borg extract (this may take a while)..."
echo "    Command: borg extract --destination \"$RESTORE_DIR\" \"$REPOSITORY::$ARCHIVE\""
echo

if borg extract --destination "$RESTORE_DIR" "$REPOSITORY::$ARCHIVE"; then
  echo
  echo "[SUCCESS] Archive restored to: $RESTORE_DIR"
  echo "You can safely inspect files there without touching the live system."
else
  err "borg extract failed."
  exit 1
fi

exit 0
