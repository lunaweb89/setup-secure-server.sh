#!/usr/bin/env bash
#
# setup-secure-server.sh
#
# One-time full-security setup for fresh Ubuntu:
#   - Install required base packages
#   - Enable security-only automatic updates
#   - Configure daily cron job for updates
#   - Harden SSH configuration
#   - Install + configure fail2ban
#   - Configure + enable UFW firewall
#   - Install ClamAV + Maldet (Linux Malware Detect)
#   - Run weekly malware scans via cron
#
# Designed to be executed directly from GitHub:
#   bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server.sh/main/setup-secure-server.sh)
#
# Safe to run once on a fresh Ubuntu server.

set -euo pipefail

# ----------------- Helpers ----------------- #

log() { echo "[+] $*"; }

require_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "[-] ERROR: This script must run as root (sudo)." >&2
        exit 1
    fi
}

backup() {
    local f="$1"
    [[ -f "$f" ]] && cp "$f" "$f.bak.$(date +%s)" && log "Backup saved: $f.bak.*"
}

get_codename() {
    if command -v lsb_release >/dev/null 2>&1; then
        lsb_release -sc
    else
        # shellcheck disable=SC1091
        source /etc/os-release
        echo "${VERSION_CODENAME:-}"
    fi
}

# ----------------- Start ----------------- #

require_root
export DEBIAN_FRONTEND=noninteractive

log "Updating package lists..."
apt-get update -qq

log "Installing required base packages (may already be installed)..."
apt-get install -y -qq \
    lsb-release \
    ca-certificates \
    openssh-server \
    cron \
    ufw \
    fail2ban \
    unattended-upgrades \
    curl \
    wget \
    tar

log "Ensuring SSH service is running..."
systemctl enable ssh >/dev/null 2>&1 || systemctl enable sshd >/dev/null 2>&1 || true
systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true

CODENAME="$(get_codename)"
if [[ -z "$CODENAME" ]]; then
    echo "[-] Unable to detect Ubuntu codename."
    exit 1
fi
log "Ubuntu codename detected: $CODENAME"

# ----------------- Automated Security Updates ----------------- #

UU="/etc/apt/apt.conf.d/50unattended-upgrades"
AU="/etc/apt/apt.conf.d/20auto-upgrades"
CRON_UPDATES="/etc/cron.d/auto-security-updates"

backup "$UU"
backup "$AU"

log "Configuring unattended security upgrades..."

cat > "$UU" <<EOF
Unattended-Upgrade::Origins-Pattern {
    "origin=Ubuntu,codename=${CODENAME},label=Ubuntu-Security";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
Unattended-Upgrade::MailOnlyOnError "true";
EOF

cat > "$AU" <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

log "Creating cron job for unattended-upgrade..."

cat > "$CRON_UPDATES" <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

0 4 * * * root unattended-upgrade -v >> /var/log/auto-security-updates.log 2>&1
EOF

chmod 644 "$CRON_UPDATES"

# ----------------- SSH Hardening ----------------- #

SSH_HARDEN="/etc/ssh/sshd_config.d/99-hardening.conf"
mkdir -p /etc/ssh/sshd_config.d
backup "$SSH_HARDEN"

log "Applying SSH hardening..."

cat > "$SSH_HARDEN" <<'EOF'
# SSH Hardening
Port 22
Protocol 2

PermitRootLogin prohibit-password
PasswordAuthentication yes
ChallengeResponseAuthentication no
PermitEmptyPasswords no
UsePAM yes

X11Forwarding no
AllowTcpForwarding yes
AllowAgentForwarding yes

LoginGraceTime 30
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

log "Testing SSH configuration..."
if command -v sshd >/dev/null 2>&1; then
    if sshd -t; then
        systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || true
        log "SSHD reloaded with hardened config."
    else
        echo "[-] SSH config test failed — not reloading."
    fi
else
    echo "[-] sshd binary not found. Please verify openssh-server installation." >&2
fi

# ----------------- Fail2Ban ----------------- #

FAIL_JAIL="/etc/fail2ban/jail.local"
backup "$FAIL_JAIL"

log "Configuring fail2ban..."

cat > "$FAIL_JAIL" <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = systemd
EOF

systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban >/dev/null 2>&1 || true

# ----------------- UFW Firewall ----------------- #

log "Configuring UFW firewall..."

ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp >/dev/null 2>&1
ufw limit OpenSSH >/dev/null 2>&1 || true
ufw allow 80/tcp >/dev/null 2>&1 || true
ufw allow 443/tcp >/dev/null 2>&1 || true

ufw default deny incoming >/dev/null 2>&1 || true
ufw default allow outgoing >/dev/null 2>&1 || true

log "Enabling firewall..."
ufw --force enable >/dev/null 2>&1 || true

# ----------------- ClamAV Installation ----------------- #

log "Installing ClamAV antivirus..."
apt-get install -y -qq clamav clamav-daemon

log "Updating ClamAV virus database (freshclam)..."
systemctl stop clamav-freshclam >/dev/null 2>&1 || true
freshclam || true
systemctl enable clamav-freshclam >/dev/null 2>&1 || true
systemctl restart clamav-freshclam >/dev/null 2>&1 || true

systemctl enable clamav-daemon >/dev/null 2>&1 || true
systemctl restart clamav-daemon >/dev/null 2>&1 || true

# ----------------- Maldet (Linux Malware Detect) ----------------- #

log "Installing Linux Malware Detect (Maldet)..."

TMP_DIR="/tmp/maldet-install"
mkdir -p "$TMP_DIR"

MALDET_URL="https://www.rfxn.com/downloads/maldetect-current.tar.gz"
MALDET_TGZ="${TMP_DIR}/maldetect-current.tar.gz"

wget -q -O "$MALDET_TGZ" "$MALDET_URL" || {
    echo "[-] Failed to download Maldet from $MALDET_URL" >&2
}

if [[ -f "$MALDET_TGZ" ]]; then
    tar -xzf "$MALDET_TGZ" -C "$TMP_DIR"
    MALDET_SRC_DIR="$(find "$TMP_DIR" -maxdepth 1 -type d -name 'maldetect-*' | head -n1)"

    if [[ -n "$MALDET_SRC_DIR" ]]; then
        (cd "$MALDET_SRC_DIR" && bash install.sh) || echo "[-] Maldet install script failed." >&2
    else
        echo "[-] Could not locate Maldet source directory after extraction." >&2
    fi
else
    echo "[-] Maldet tarball not found, skipping Maldet install." >&2
fi

# Configure Maldet to use ClamAV engine if available
MALDET_CONF="/usr/local/maldetect/conf.maldet"
if [[ -f "$MALDET_CONF" ]]; then
    backup "$MALDET_CONF"
    sed -i 's/^scan_clamscan=.*/scan_clamscan="1"/' "$MALDET_CONF" || true
    sed -i 's/^scan_clamd=.*/scan_clamd="1"/' "$MALDET_CONF" || true
    log "Configured Maldet to use ClamAV engine."
fi

# ----------------- Weekly Malware Scan via Cron ----------------- #

log "Creating weekly malware scan cron job..."

CRON_MALWARE="/etc/cron.d/weekly-malware-scan"

cat > "$CRON_MALWARE" <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Weekly malware scan every Sunday at 03:30
30 3 * * 0 root /usr/local/maldetect/maldet -b -r /home,/var/www 1 >> /var/log/weekly-malware-scan.log 2>&1
EOF

chmod 644 "$CRON_MALWARE"

# ----------------- Initial Security Patch Run ----------------- #

log "Running initial security upgrade (unattended-upgrade)..."
unattended-upgrade -v >> /var/log/auto-security-updates.log 2>&1 || true

# ----------------- DONE ----------------- #

log "SECURE SERVER + ANTIVIRUS SETUP COMPLETE!"
log ""
log "Installed & enabled:"
log " - Security-only automatic updates (unattended-upgrades)"
log " - SSH hardening"
log " - Fail2Ban (SSH protection)"
log " - UFW firewall (SSH/HTTP/HTTPS allowed)"
log " - ClamAV + clamav-daemon (with freshclam auto-updates)"
log " - Maldet (Linux Malware Detect) integrated with ClamAV"
log " - Weekly malware scan cron: /etc/cron.d/weekly-malware-scan"
log ""
log "Scan log:   /var/log/weekly-malware-scan.log"
log "Update log: /var/log/auto-security-updates.log"
log ""
log "Optional next step: After adding your SSH key,"
log "  edit /etc/ssh/sshd_config.d/99-hardening.conf and set:"
log "      PasswordAuthentication no"
log "  then: systemctl reload ssh"
