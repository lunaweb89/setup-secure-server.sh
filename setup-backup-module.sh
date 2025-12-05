#!/usr/bin/env bash
#
# setup-backup-module.sh
#
# Adds BorgBackup + Hetzner Storage Box weekly backups,
# weekly safe-upgrades, and simple safety logic.
#
# Usage:
#   sudo bash setup-backup-module.sh
#

set -euo pipefail

log() { echo "[+] $*"; }
err() { echo "[-] $*" >&2; }

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "This script must be run as root (use sudo)."
    exit 1
  fi
}

require_root

# -------------------------------------------------------------
# PROMPT FOR STORAGE BOX DETAILS
# -------------------------------------------------------------

echo "===== Hetzner Storage Box Backup Setup (Borg) ====="
read -rp "Storage Box username (e.g. u123456): " BOXUSER
read -rp "Storage Box hostname (e.g. u123456.your-storagebox.de): " BOXHOST
read -rp "Storage Box SSH port (default 23): " BOXPORT
BOXPORT="${BOXPORT:-23}"

DEFAULT_REPO_DIR="server-$(hostname)"
read -rp "Repository directory under /backups/ [${DEFAULT_REPO_DIR}]: " REPO_DIR
REPO_DIR="${REPO_DIR:-$DEFAULT_REPO_DIR}"

if [[ -z "${BOXUSER}" || -z "${BOXHOST}" ]]; then
  err "Storage Box username and hostname are required."
  exit 1
fi

REPOSITORY="ssh://${BOXUSER}@${BOXHOST}:${BOXPORT}/./backups/${REPO_DIR}"
log "Borg repository will be: ${REPOSITORY}"

# -------------------------------------------------------------
# BORG PASSPHRASE HANDLING (NOT IN GIT)
# -------------------------------------------------------------

# Passphrase file will live only on the server
BORG_PASSFILE="/root/.borg-passphrase"

if [[ -f "${BORG_PASSFILE}" ]]; then
  log "Existing Borg passphrase file found at ${BORG_PASSFILE}, reusing."
else
  echo
  echo "Borg will use encryption=repokey (recommended)."
  echo "Passphrase will be stored locally at ${BORG_PASSFILE} (root-only)."
  echo "Do NOT use spaces or quotes to keep things simple."
  read -rsp "Enter Borg repository passphrase: " BORG_PASSPHRASE
  echo
  if [[ -z "${BORG_PASSPHRASE}" ]]; then
    err "Borg passphrase cannot be empty."
    exit 1
  fi

  echo "${BORG_PASSPHRASE}" > "${BORG_PASSFILE}"
  chmod 600 "${BORG_PASSFILE}"
  log "Saved Borg passphrase to ${BORG_PASSFILE} (root-only)."
fi

# Always load it into env when needed
BORG_PASSPHRASE="$(<"${BORG_PASSFILE}")"

# -------------------------------------------------------------
# INSTALL REQUIRED PACKAGES
# -------------------------------------------------------------

log "Installing BorgBackup and unattended-upgrades (if not present)..."
apt-get update -qq
apt-get install -y -qq borgbackup unattended-upgrades

BORG_BIN="$(command -v borg || echo /usr/bin/borg)"

# -------------------------------------------------------------
# SSH KEY SETUP
# -------------------------------------------------------------

if [[ ! -f /root/.ssh/id_rsa ]]; then
  log "Generating SSH key for root..."
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh
  ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N "" >/dev/null
else
  log "Existing SSH key found at /root/.ssh/id_rsa, reusing."
fi

log "Copying SSH key to Storage Box (may prompt for password)..."
ssh-copy-id -p "${BOXPORT}" "${BOXUSER}@${BOXHOST}"

# -------------------------------------------------------------
# INIT BORG REPO (idempotent, encryption=repokey)
# -------------------------------------------------------------

log "Initializing (or verifying) Borg repository on Storage Box..."

export BORG_PASSPHRASE
if ! "${BORG_BIN}" init --encryption=repokey "${REPOSITORY}" 2>/tmp/borg-init.log; then
  if grep -qi "already exists" /tmp/borg-init.log 2>/dev/null; then
    log "Borg repository already exists, continuing."
  else
    err "borg init failed. Check /tmp/borg-init.log"
    exit 1
  fi
fi
rm -f /tmp/borg-init.log || true
unset BORG_PASSPHRASE

# -------------------------------------------------------------
# CREATE BACKUP SCRIPT (Hetzner-style)
# -------------------------------------------------------------

log "Creating /usr/local/bin/pre-upgrade-backup.sh ..."

mkdir -p /var/log/borg

cat > /usr/local/bin/pre-upgrade-backup.sh <<EOF
#!/usr/bin/env bash
set -euo pipefail

BORG_PASSFILE="/root/.borg-passphrase"
if [[ ! -f "\$BORG_PASSFILE" ]]; then
  echo "[\$(date -Is)] Borg passphrase file \$BORG_PASSFILE not found, aborting." >&2
  exit 1
fi

export BORG_PASSPHRASE="\$(<"\$BORG_PASSFILE")"
REPOSITORY="${REPOSITORY}"
LOG='/var/log/borg/backup.log'
BORG_BIN="\$(command -v borg || echo /usr/bin/borg)"

mkdir -p /var/log/borg
touch "\$LOG"
chmod 600 "\$LOG"

exec >> "\$LOG" 2>&1

echo "###### Backup started: \$(date -Is) ######"

echo "Transfer files with Borg..."

"\$BORG_BIN" create -v --stats \\
    "\$REPOSITORY::\{now:%Y-%m-%d_%H:%M\}" \\
    / \\
    --exclude /dev \\
    --exclude /proc \\
    --exclude /sys \\
    --exclude /var/run \\
    --exclude /run \\
    --exclude /lost+found \\
    --exclude /mnt \\
    --exclude /var/lib/lxcfs

echo "Borg create finished at \$(date -Is)"

"\$BORG_BIN" prune -v --list --keep-daily=30 "\$REPOSITORY"
"\$BORG_BIN" compact "\$REPOSITORY" || true

mkdir -p /var/run
touch /var/run/backup-ok

echo "###### Backup ended: \$(date -Is) ######"
EOF

chmod 700 /usr/local/bin/pre-upgrade-backup.sh

# -------------------------------------------------------------
# CREATE WEEKLY SAFE-UPGRADE WRAPPER
# -------------------------------------------------------------

log "Creating /usr/local/bin/weekly-safe-upgrade.sh ..."

cat > /usr/local/bin/weekly-safe-upgrade.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

LOG=/var/log/auto-security-updates.log
mkdir -p /var/log
touch "$LOG"
chmod 600 "$LOG"

if [[ ! -f /var/run/backup-ok ]]; then
  echo "[$(date -Is)] weekly-safe-upgrade: backup-ok flag missing, aborting." >> "$LOG"
  exit 0
fi

if ! command -v unattended-upgrade >/dev/null 2>&1; then
  echo "[$(date -Is)] weekly-safe-upgrade: unattended-upgrade not installed, aborting." >> "$LOG"
  exit 0
fi

echo "===== Weekly unattended-upgrade started at $(date -Is) =====" >> "$LOG"
if unattended-upgrade -v >> "$LOG" 2>&1; then
  echo "===== Weekly unattended-upgrade finished SUCCESSFULLY at $(date -Is) =====" >> "$LOG"
  rm -f /var/run/backup-ok
else
  echo "===== Weekly unattended-upgrade FAILED at $(date -Is) =====" >> "$LOG"
fi
EOF

chmod 700 /usr/local/bin/weekly-safe-upgrade.sh

# -------------------------------------------------------------
# WEEKLY BACKUP + WEEKLY SAFE UPGRADE CRONS
# -------------------------------------------------------------

log "Configuring weekly Sunday backup and upgrade cronjobs..."

cat > /etc/cron.d/weekly-backup <<EOF
# Weekly full-system Borg backup to Hetzner Storage Box
0 12 * * 0 root /usr/local/bin/pre-upgrade-backup.sh
EOF

cat > /etc/cron.d/weekly-upgrade <<EOF
# Weekly unattended-upgrade, only if backup succeeded
0 14 * * 0 root /usr/local/bin/weekly-safe-upgrade.sh
EOF

chmod 644 /etc/cron.d/weekly-backup /etc/cron.d/weekly-upgrade

# -------------------------------------------------------------
# SIMPLE HETZNER-STYLE REMOTE TEST
# -------------------------------------------------------------

log "Testing Borg remote access on Storage Box (borg --version)..."

if ssh -p "${BOXPORT}" "${BOXUSER}@${BOXHOST}" "borg --version" >/dev/null 2>&1; then
  log "Borg remote test SUCCESSFUL (borg --version)."
else
  err "Borg remote test FAILED. Check that Borg is enabled on the Storage Box and SSH support is active."
fi

# -------------------------------------------------------------
# COMPLETION
# -------------------------------------------------------------

log "Backup module installation finished."

exit 0
