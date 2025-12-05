#!/usr/bin/env bash
#
# setup-backup-module.sh
#
# Adds BorgBackup + Hetzner Storage Box daily backups.
# - Full-system backup of "/" with sensible excludes
# - MySQL dumps of all non-system DBs to /var/backups/mysql/*.sql
# - Excludes raw MySQL data directory (/var/lib/mysql) from Borg
# - Auto-generates encryption passphrase and prints it at the end
# - Stores repo URL + passphrase for restore helpers
# - Daily backups at 08:30
# - Retention: 7 daily, 4 weekly, 3 monthly
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
export DEBIAN_FRONTEND=noninteractive

# -------------------------------------------------------------
# PROMPT FOR STORAGE BOX DETAILS
# -------------------------------------------------------------

echo "===== Hetzner Storage Box Backup Setup (Borg) ====="
read -rp "Storage Box server (e.g. u515286.your-storagebox.de): " BOXHOST
read -rp "Storage Box username (e.g. u515286): " BOXUSER
read -srp "Storage Box password (used once to install SSH key, not stored): " BOXPASS
echo
read -rp "Storage Box SSH port (default 23): " BOXPORT
BOXPORT="${BOXPORT:-23}"

DEFAULT_REPO_DIR="server-$(hostname)"
read -rp "Repository directory under /backup/ [${DEFAULT_REPO_DIR}]: " REPO_DIR
REPO_DIR="${REPO_DIR:-$DEFAULT_REPO_DIR}"

if [[ -z "${BOXUSER}" || -z "${BOXHOST}" ]]; then
  err "Storage Box username and server are required."
  exit 1
fi

# Hetzner standard path is /backup (no "s")
REPOSITORY="ssh://${BOXUSER}@${BOXHOST}:${BOXPORT}/./backup/${REPO_DIR}"
log "Borg repository will be: ${REPOSITORY}"

BORG_PASSFILE="/root/.borg-passphrase"
REPO_FILE="/root/.borg-repository"

# -------------------------------------------------------------
# AUTO-GENERATE / LOAD PASSPHRASE
# -------------------------------------------------------------

if [[ -f "${BORG_PASSFILE}" ]]; then
  log "Existing Borg passphrase found at ${BORG_PASSFILE}, reusing."
else
  log "Generating secure Borg passphrase..."
  # 32-char random string, safe characters, C locale
  GENERATED_PASSPHRASE="$(LC_ALL=C tr -dc 'A-Za-z0-9!@#$%^&*_\-+=' </dev/urandom | head -c 32 || true)"

  if [[ -z "${GENERATED_PASSPHRASE}" ]]; then
    err "Failed to generate random passphrase."
    exit 1
  fi

  echo "${GENERATED_PASSPHRASE}" > "${BORG_PASSFILE}"
  chmod 600 "${BORG_PASSFILE}"
fi

BORG_PASSPHRASE="$(<"${BORG_PASSFILE}")"

# Store repo URL for restore helpers
echo "${REPOSITORY}" > "${REPO_FILE}"
chmod 600 "${REPO_FILE}"

# -------------------------------------------------------------
# INSTALL BORG + SSHPASS
# -------------------------------------------------------------

log "Installing BorgBackup + sshpass..."
apt-get update -qq
apt-get install -y -qq borgbackup sshpass

BORG_BIN="$(command -v borg || echo /usr/bin/borg)"

# -------------------------------------------------------------
# PRE-ACCEPT STORAGE BOX HOST KEY (AVOID yes/no PROMPT)
# -------------------------------------------------------------

log "Adding Storage Box host key to known_hosts (if not present)..."
mkdir -p /root/.ssh
chmod 700 /root/.ssh
ssh-keyscan -p "${BOXPORT}" "${BOXHOST}" >> /root/.ssh/known_hosts 2>/dev/null || true

# -------------------------------------------------------------
# SSH KEY SETUP (HETZNER: USE -s, PASSWORD ONLY USED ONCE)
# -------------------------------------------------------------

if [[ ! -f /root/.ssh/id_rsa ]]; then
  log "Generating SSH key for root..."
  ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N "" >/dev/null
else
  log "Existing SSH key found at /root/.ssh/id_rsa, reusing."
fi

log "Copying SSH key to Storage Box with sshpass (Hetzner requires -s)..."
sshpass -p "${BOXPASS}" ssh-copy-id -s -p "${BOXPORT}" "${BOXUSER}@${BOXHOST}" || true

# -------------------------------------------------------------
# STORAGE BOX CONNECTION TEST - UPLOAD TEMP FILE (WITH SSHPASS)
# -------------------------------------------------------------

log "Testing Storage Box connectivity by uploading a test file..."

TESTFILE_LOCAL="/tmp/storagebox-test-$(date +%s).txt"
TESTFILE_REMOTE="test-upload-$(hostname)-$(date +%s).txt"

echo "Storage Box test file created at $(date -Is)" > "${TESTFILE_LOCAL}"

if sshpass -p "${BOXPASS}" scp -P "${BOXPORT}" "${TESTFILE_LOCAL}" "${BOXUSER}@${BOXHOST}:${TESTFILE_REMOTE}" >/dev/null 2>&1; then
  log "Test file upload SUCCESSFUL: ${TESTFILE_REMOTE}"
else
  err "Test upload FAILED — cannot write to Storage Box!"
  err "Check:"
  err " - Credentials"
  err " - SSH port (${BOXPORT})"
  err " - Network firewall rules"
  err " - Storage Box SSH access enabled"
  exit 1
fi

sshpass -p "${BOXPASS}" ssh -p "${BOXPORT}" "${BOXUSER}@${BOXHOST}" "rm -f ${TESTFILE_REMOTE}" >/dev/null 2>&1 || true
rm -f "${TESTFILE_LOCAL}" || true

log "Storage Box connectivity OK."

# -------------------------------------------------------------
# INIT BORG REPO (IDEMPOTENT, USING SSHPASS FOR FIRST RUN)
# -------------------------------------------------------------

log "Initializing (or verifying) Borg repository on Storage Box..."

export BORG_PASSPHRASE
# Use sshpass for this initial init so no extra password prompts
BORG_RSH_CMD="sshpass -p ${BOXPASS} ssh -p ${BOXPORT} -o StrictHostKeyChecking=no"
if ! BORG_RSH="${BORG_RSH_CMD}" "${BORG_BIN}" init --encryption=repokey --make-parent-dirs "${REPOSITORY}" 2>/tmp/borg-init.log; then
  if grep -qi "already exists" /tmp/borg-init.log 2>/dev/null; then
    log "Borg repository already exists, continuing."
  else
    err "borg init failed. Check /tmp/borg-init.log"
    exit 1
  fi
fi
rm -f /tmp/borg-init.log || true
# Do NOT unset BORG_PASSPHRASE here, we still want to print it at the end

# -------------------------------------------------------------
# CREATE DAILY BACKUP SCRIPT (WITH MYSQL DUMPS)
# -------------------------------------------------------------

log "Creating /usr/local/bin/pre-upgrade-backup.sh ..."

mkdir -p /var/log/borg

cat > /usr/local/bin/pre-upgrade-backup.sh << 'EOF'
#!/usr/bin/env bash
#
# pre-upgrade-backup.sh
#
# - Dumps all non-system MySQL/MariaDB databases to /var/backups/mysql/*.sql
# - Runs Borg full-system backup of "/" with sensible excludes
# - Prunes old archives and compacts the repo
#

set -euo pipefail

BORG_PASSFILE="/root/.borg-passphrase"
REPO_FILE="/root/.borg-repository"
LOG="/var/log/borg/backup.log"
MYSQL_DUMP_DIR="/var/backups/mysql"
MYSQL_DUMP_LOG="/var/log/mysql-dumps.log"
BORG_BIN="$(command -v borg || echo /usr/bin/borg)"

if [[ ! -f "$BORG_PASSFILE" ]]; then
  echo "[ERROR] Borg passphrase file missing at $BORG_PASSFILE" >&2
  exit 1
fi

if [[ ! -f "$REPO_FILE" ]]; then
  echo "[ERROR] Borg repository file missing at $REPO_FILE" >&2
  exit 1
fi

export BORG_PASSPHRASE="$(<"$BORG_PASSFILE")"
REPOSITORY="$(<"$REPO_FILE")"

mkdir -p "$(dirname "$LOG")"
touch "$LOG"
chmod 600 "$LOG"

mkdir -p "$(dirname "$MYSQL_DUMP_LOG")"
touch "$MYSQL_DUMP_LOG"
chmod 600 "$MYSQL_DUMP_LOG"

# ---------------------------------------------------------
# Function: dump all non-system DBs to /var/backups/mysql
# ---------------------------------------------------------
do_mysql_dumps() {
  echo "===== MySQL dump started at $(date -Is) =====" >> "$MYSQL_DUMP_LOG"

  mkdir -p "$MYSQL_DUMP_DIR"
  chmod 700 "$MYSQL_DUMP_DIR"

  if ! command -v mysql >/dev/null 2>&1 || ! command -v mysqldump >/dev/null 2>&1; then
    echo "[WARN] mysql or mysqldump not found, skipping DB dumps." >> "$MYSQL_DUMP_LOG"
    echo "===== MySQL dump finished (skipped) at $(date -Is) =====" >> "$MYSQL_DUMP_LOG"
    return 0
  fi

  set +e
  DBS="$(mysql -N -B -e 'SHOW DATABASES;' 2>>"$MYSQL_DUMP_LOG")"
  if [[ -z "$DBS" ]]; then
    echo "[WARN] No databases returned by SHOW DATABASES; skipping DB dumps." >> "$MYSQL_DUMP_LOG"
    echo "===== MySQL dump finished (no DBs) at $(date -Is) =====" >> "$MYSQL_DUMP_LOG"
    set -e
    return 0
  fi

  for db in $DBS; do
    case "$db" in
      information_schema|performance_schema|mysql|sys)
        continue
        ;;
    esac
    echo "[INFO] Dumping database: $db" >> "$MYSQL_DUMP_LOG"
    mysqldump --single-transaction --quick --routines --events "$db" > "${MYSQL_DUMP_DIR}/${db}.sql" 2>>"$MYSQL_DUMP_LOG"
    if [[ $? -ne 0 ]]; then
      echo "[WARN] Failed to dump database: $db" >> "$MYSQL_DUMP_LOG"
    fi
  done
  set -e

  echo "===== MySQL dump finished at $(date -Is) =====" >> "$MYSQL_DUMP_LOG"
}

exec >> "$LOG" 2>&1

echo "###### Backup started: $(date -Is) ######"

# Step 1: DB dumps
do_mysql_dumps

# Step 2: Borg backup of "/" with excludes and MySQL data dir excluded
"$BORG_BIN" create -v --stats \
  "$REPOSITORY::$(hostname)-{now:%Y-%m-%d_%H:%M}" \
  / \
  --exclude /dev \
  --exclude /proc \
  --exclude /sys \
  --exclude /run \
  --exclude /var/run \
  --exclude /tmp \
  --exclude /var/tmp \
  --exclude /var/cache \
  --exclude /var/log/journal \
  --exclude /var/lib/lxcfs \
  --exclude /var/lib/mysql \
  --exclude /mnt \
  --exclude /media \
  --exclude /lost+found \
  --exclude /swapfile

# Step 3: prune & compact
"$BORG_BIN" prune -v --list \
  --keep-daily=7 \
  --keep-weekly=4 \
  --keep-monthly=3 \
  "$REPOSITORY"

"$BORG_BIN" compact "$REPOSITORY" || true

mkdir -p /var/run
touch /var/run/backup-ok

echo "###### Backup ended: $(date -Is) ######"
EOF

chmod 700 /usr/local/bin/pre-upgrade-backup.sh

# -------------------------------------------------------------
# CREATE PASSPHRASE / REPO VERIFICATION HELPER
# -------------------------------------------------------------

log "Creating /usr/local/bin/borg-passphrase-test.sh ..."

cat > /usr/local/bin/borg-passphrase-test.sh << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

BORG_PASSFILE="/root/.borg-passphrase"
REPO_FILE="/root/.borg-repository"

if [[ ! -f "$BORG_PASSFILE" ]]; then
  echo "[ERROR] Passphrase file missing: $BORG_PASSFILE" >&2
  exit 1
fi

if [[ ! -f "$REPO_FILE" ]]; then
  echo "[ERROR] Repository file missing: $REPO_FILE" >&2
  exit 1
fi

export BORG_PASSPHRASE="$(<"$BORG_PASSFILE")"
REPOSITORY="$(<"$REPO_FILE")"

echo "--------------------------------------------"
echo " Testing Borg passphrase & repository access"
echo "--------------------------------------------"
echo "Repository: $REPOSITORY"
echo

if borg list "$REPOSITORY"; then
  echo
  echo "[SUCCESS] Passphrase is correct and archive decryption works."
  echo "[SUCCESS] Repository is readable over SSH."
else
  echo
  echo "[FAILED] Borg could not read the repository."
  echo "Check passphrase or connectivity."
  exit 1
fi

echo "--------------------------------------------"
echo "Test complete."
EOF

chmod 755 /usr/local/bin/borg-passphrase-test.sh

# -------------------------------------------------------------
# DAILY BACKUP CRON (08:30)
# -------------------------------------------------------------

log "Creating daily backup cronjob..."

CRON_BACKUP="/etc/cron.d/daily-borg-backup"

cat > "$CRON_BACKUP" << 'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Daily full-system Borg backup (08:30 every day)
30 8 * * * root /usr/local/bin/pre-upgrade-backup.sh
EOF

chmod 644 "$CRON_BACKUP"

# -------------------------------------------------------------
# COMPLETION & PASSPHRASE DISPLAY + VERIFICATION
# -------------------------------------------------------------

echo
log "Backup module installation finished successfully."

echo "------------------------------------------------------------"
echo " IMPORTANT: SAVE YOUR BORG PASSPHRASE"
echo "------------------------------------------------------------"
echo "${BORG_PASSPHRASE}"
echo "------------------------------------------------------------"
echo "The passphrase is stored locally at: /root/.borg-passphrase"
echo "The repository URL is stored at:    /root/.borg-repository"
echo "You must save the above passphrase somewhere safe."
echo

log "Running borg-passphrase-test.sh to verify access (using ssh key; may prompt if key not working)..."
# First verification run: prefer key auth; if it still prompts for password, you can fix SSH key later.
 /usr/local/bin/borg-passphrase-test.sh || err "Verification failed – check output above."

# Now we are done with the password; clear it from memory
unset BOXPASS || true

exit 0
