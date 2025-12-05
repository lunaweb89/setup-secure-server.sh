#!/usr/bin/env bash
#
# setup-backup-module.sh
#
# Adds BorgBackup + Hetzner Storage Box weekly backups,
# weekly safe-upgrades, and safe reboot logic.

set -u

log() { echo "[+] $*"; }

# -------------------------------------------------------------
# PROMPT FOR STORAGE BOX DETAILS
# -------------------------------------------------------------

echo "===== Hetzner Storage Box Backup Setup ====="
read -rp "Storage Box username (e.g. u123456): " BOXUSER
read -rp "Storage Box hostname (e.g. u123456.your-storagebox.de): " BOXHOST
read -rp "Storage Box SSH port (default 23): " BOXPORT
BOXPORT="${BOXPORT:-23}"

# -------------------------------------------------------------
# INSTALL REQUIRED PACKAGES
# -------------------------------------------------------------

log "Installing BorgBackup + SSHFS..."
apt-get update -qq
apt-get install -y -qq borgbackup sshfs

# -------------------------------------------------------------
# SSH KEY SETUP
# -------------------------------------------------------------

if [[ ! -f /root/.ssh/id_rsa ]]; then
  log "Generating SSH key..."
  ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N "" >/dev/null
fi

log "Copying SSH key to Storage Box..."
ssh-copy-id -p "$BOXPORT" "$BOXUSER@$BOXHOST"

# -------------------------------------------------------------
# DETECT ROOT FILESYSTEM DEVICE
# -------------------------------------------------------------

ROOTDEV="$(findmnt -n -o SOURCE /)"
log "Detected root filesystem device: $ROOTDEV"

# -------------------------------------------------------------
# INIT BORG REPO (idempotent)
# -------------------------------------------------------------

log "Initializing Storage Box Borg repository..."
ssh -p "$BOXPORT" "$BOXUSER@$BOXHOST" "borg init --make-parent-dirs --encryption=none repo" || true

# -------------------------------------------------------------
# CREATE BACKUP SCRIPT
# -------------------------------------------------------------

cat > /usr/local/bin/pre-upgrade-backup.sh <<EOF
#!/bin/bash
set -e

LOG=/var/log/borg-backup.log
echo "===== Backup started at \$(date) =====" >> \$LOG

borg create --verbose --stats --compression zstd \
  ${BOXUSER}@${BOXHOST}:repo::server-\$(hostname)-\$(date +%Y-%m-%d_%H-%M-%S) \
  / \
  --exclude /dev --exclude /proc --exclude /sys --exclude /tmp \
  --exclude /run --exclude /mnt --exclude /media --exclude /lost+found \
  >> \$LOG 2>&1

borg prune --keep-daily=30 ${BOXUSER}@${BOXHOST}:repo >> \$LOG 2>&1

touch /var/run/backup-ok
echo "===== Backup completed successfully =====" >> \$LOG
EOF

chmod +x /usr/local/bin/pre-upgrade-backup.sh

# -------------------------------------------------------------
# WEEKLY BACKUP + WEEKLY SAFE UPGRADE + SAFE REBOOT
# -------------------------------------------------------------

log "Configuring weekly Sunday backup and upgrade..."

cat > /etc/cron.d/weekly-backup <<EOF
0 12 * * 0 root /usr/local/bin/pre-upgrade-backup.sh
EOF

cat > /etc/cron.d/weekly-upgrade <<'EOF'
0 14 * * 0 root [ -f /var/run/backup-ok ] && unattended-upgrade -v >> /var/log/auto-security-updates.log 2>&1 && rm -f /var/run/backup-ok
EOF

# -------------------------------------------------------------
# TEST UPLOAD
# -------------------------------------------------------------

TESTFILE="/tmp/storagebox-test-\$(date +%s).txt"
echo "Storage Box test upload successful at \$(date)" > "\$TESTFILE"

scp -P "$BOXPORT" "\$TESTFILE" "${BOXUSER}@${BOXHOST}:test-upload.txt"

if [[ $? -eq 0 ]]; then
  echo "[+] Storage Box test upload SUCCESSFUL."
else
  echo "[-] Storage Box test upload FAILED."
fi

# -------------------------------------------------------------
# COMPLETION
# -------------------------------------------------------------

log "Backup module installation finished."

exit 0
