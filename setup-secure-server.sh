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
#   - Run weekly malware scans via cron on /home
#
# Run directly from GitHub:
#   bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server.sh/main/setup-secure-server.sh)

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
  if [[ -f "$f" ]]; then
    # Store backups under /root/config-backups to avoid APT warnings
    local rel="${f#/}"
    local dir="/root/config-backups/$(dirname "$rel")"
    mkdir -p "$dir"
    cp "$f" "$dir/$(basename "$f").bak.$(date +%s)"
    log "Backup saved: $dir/$(basename "$f").bak.*"
  fi
}

get_codename() {
  if command -v lsb_release >/dev/null 2>&1; then
    lsb_release -sc
  else
    # shellcheck disable=SC1091
    . /etc/os-release
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
  echo "[-] Unable to detect Ubuntu codename." >&2
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

cat > "$AU" <<'EOF'
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

# Listen on BOTH ports:
Port 22
Port 2808
Protocol 2

# Enable root login with password
PermitRootLogin yes

# Enable password authentication
PasswordAuthentication yes

ChallengeResponseAuthentication no
PermitEmptyPasswords no
UsePAM yes

# Security options
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
    echo "[-] SSH config test failed; not reloading." >&2
  fi
else
  echo "[-] sshd binary not found; please verify openssh-server installation." >&2
fi


# ----------------- Fail2Ban ----------------- #

FAIL_JAIL="/etc/fail2ban/jail.local"
backup "$FAIL_JAIL"

log "Configuring fail2ban..."

cat > "$FAIL_JAIL" <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled  = true
port     = 22,2808
logpath  = %(sshd_log)s
backend  = systemd
EOF

systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban >/dev/null 2>&1 || true

# ----------------- UFW Firewall ----------------- #

log "Configuring UFW firewall..."

# --- SSH (primary + fallback) ---
ufw allow 22/tcp    >/dev/null 2>&1 || true
ufw limit 22/tcp    >/dev/null 2>&1 || true

ufw allow 2808/tcp  >/dev/null 2>&1 || true
ufw limit 2808/tcp  >/dev/null 2>&1 || true

# --- Core Web + Panel Ports ---

# HTTP / HTTPS
ufw allow 80/tcp    >/dev/null 2>&1 || true
ufw allow 443/tcp   >/dev/null 2>&1 || true

# CyberPanel panel
ufw allow 8090/tcp  >/dev/null 2>&1 || true

# OpenLiteSpeed WebAdmin
ufw allow 7080/tcp  >/dev/null 2>&1 || true

# --- DNS (for nameserver / resolver if used) ---
ufw allow 53/tcp    >/dev/null 2>&1 || true
ufw allow 53/udp    >/dev/null 2>&1 || true

# --- Mail Services ---
ufw allow 25/tcp    >/dev/null 2>&1 || true
ufw allow 465/tcp   >/dev/null 2>&1 || true
ufw allow 587/tcp   >/dev/null 2>&1 || true
ufw allow 110/tcp   >/dev/null 2>&1 || true
ufw allow 995/tcp   >/dev/null 2>&1 || true
ufw allow 143/tcp   >/dev/null 2>&1 || true
ufw allow 993/tcp   >/dev/null 2>&1 || true

# --- FTP + Passive FTP ---
ufw allow 21/tcp           >/dev/null 2>&1 || true
ufw allow 40110:40210/tcp  >/dev/null 2>&1 || true

# --- Default Policies ---
ufw default deny incoming  >/dev/null 2>&1 || true
ufw default allow outgoing >/dev/null 2>&1 || true

log "Enabling firewall..."
ufw --force enable >/dev/null 2>&1 || true

# --- Mail Services ---

# SMTP
ufw allow 25/tcp   >/dev/null 2>&1 || true   # outbound often enough; inbound if you're receiving mail directly
ufw allow 465/tcp  >/dev/null 2>&1 || true   # SMTPS
ufw allow 587/tcp  >/dev/null 2>&1 || true   # Submission

# POP3 / IMAP
ufw allow 110/tcp  >/dev/null 2>&1 || true   # POP3
ufw allow 995/tcp  >/dev/null 2>&1 || true   # POP3S
ufw allow 143/tcp  >/dev/null 2>&1 || true   # IMAP
ufw allow 993/tcp  >/dev/null 2>&1 || true   # IMAPS

# --- FTP + Passive FTP ---

ufw allow 21/tcp        >/dev/null 2>&1 || true           # FTP control
ufw allow 40110:40210/tcp >/dev/null 2>&1 || true         # Passive FTP range (must match FTP config)

# --- Default Policies ---

ufw default deny incoming  >/dev/null 2>&1 || true
ufw default allow outgoing >/dev/null 2>&1 || true

log "Enabling firewall..."
ufw --force enable >/dev/null 2>&1 || true



# ----------------- ClamAV ----------------- #

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

if wget -q -O "$MALDET_TGZ" "$MALDET_URL"; then
  tar -xzf "$MALDET_TGZ" -C "$TMP_DIR"
  MALDET_SRC_DIR="$(find "$TMP_DIR" -maxdepth 1 -type d -name 'maldetect-*' | head -n1)"
  if [[ -n "$MALDET_SRC_DIR" ]]; then
    (cd "$MALDET_SRC_DIR" && bash install.sh) || echo "[-] Maldet install script failed." >&2
  else
    echo "[-] Could not locate Maldet source directory after extraction." >&2
  fi
else
  echo "[-] Failed to download Maldet from $MALDET_URL" >&2
fi

MALDET_CONF="/usr/local/maldetect/conf.maldet"
if [[ -f "$MALDET_CONF" ]]; then
  backup "$MALDET_CONF"
  sed -i 's/^scan_clamscan=.*/scan_clamscan="1"/' "$MALDET_CONF" || true
  sed -i 's/^scan_clamd=.*/scan_clamd="1"/' "$MALDET_CONF" || true
  log "Configured Maldet to use ClamAV engine."
else
  echo "[-] Maldet config not found at $MALDET_CONF" >&2
fi

# ----------------- Weekly Malware Scan via Cron ----------------- #

log "Creating weekly malware scan cron job..."

CRON_MALWARE="/etc/cron.d/weekly-malware-scan"

cat > "$CRON_MALWARE" <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Weekly malware scan every Sunday at 03:30
# Scans all sites/data under /home (CyberPanel layout)
30 3 * * 0 root /usr/local/maldetect/maldet -b -r /home 1 >> /var/log/weekly-malware-scan.log 2>&1
EOF

chmod 644 "$CRON_MALWARE"

# ----------------- Initial Security Patch Run ----------------- #

log "Running initial security upgrade (unattended-upgrade)..."
unattended-upgrade -v >> /var/log/auto-security-updates.log 2>&1 || true

log "Secure server + antivirus setup complete."
log "Security auto-updates enabled; firewall, fail2ban, ClamAV, Maldet all configured."
