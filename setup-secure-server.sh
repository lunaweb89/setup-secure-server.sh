#!/usr/bin/env bash
#
# setup-secure-server.sh
#
# One-time full-security setup for fresh Ubuntu:
#   - Repair dpkg/APT if broken
#   - Install required base packages
#   - Enable security-only automatic updates
#   - Configure daily cron job for updates
#   - Harden SSH configuration (root login allowed, ports 22 + 2808)
#   - Install + configure Fail2Ban (maxretry=5)
#   - Configure + enable UFW firewall (SSH, web, CyberPanel, mail, FTP, DNS)
#   - Install ClamAV + Maldet (Linux Malware Detect)
#   - Run weekly malware scans via cron on /home
#
# Run directly (example):
#   bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server.sh/main/setup-secure-server.sh)

set -u   # strict on unset vars, but we handle errors manually (no set -e)

# ----------------- Step Status ----------------- #
STEP_update_base_packages="FAILED"
STEP_auto_security_updates="FAILED"
STEP_ssh_hardening="FAILED"
STEP_fail2ban_config="FAILED"
STEP_ufw_firewall="FAILED"
STEP_clamav_install="FAILED"
STEP_maldet_install="FAILED"
STEP_weekly_malware_cron="FAILED"
STEP_initial_unattended_upgrade="FAILED"

# ----------------- Helpers ----------------- #

log() { echo "[+] $*"; }

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "[-] ERROR: This script must run as root (sudo)." >&2
    exit 1
  fi
}

backup() {
  local f="$1"
  if [[ -f "$f" ]]; then
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

apt_update_retry() {
  local tries=0 max_tries=3
  while (( tries < max_tries )); do
    if apt-get update -qq; then
      return 0
    fi
    tries=$((tries + 1))
    log "apt-get update failed (attempt $tries/$max_tries), retrying in 5s..."
    sleep 5
  done
  return 1
}

apt_install_retry() {
  local tries=0 max_tries=3
  local pkgs=("$@")
  while (( tries < max_tries )); do
    if apt-get install -y -qq "${pkgs[@]}"; then
      return 0
    fi
    log "apt-get install ${pkgs[*]} failed (attempt $((tries+1))/$max_tries), trying apt-get -f install..."
    apt-get -f install -y || true
    tries=$((tries + 1))
    sleep 5
  done
  return 1
}

# ----------------- Start ----------------- #

require_root
export DEBIAN_FRONTEND=noninteractive

# ----------------- Repair dpkg / APT if broken ----------------- #
log "Checking dpkg / APT health..."

if dpkg --audit | grep -q .; then
  log "dpkg is in a broken state — repairing with dpkg --configure -a ..."
  dpkg --configure -a || log "WARNING: dpkg --configure -a did not complete cleanly."
fi

apt-get -f install -y || true

log "Running apt-get update with retry..."
if apt_update_retry; then
  log "APT update completed."
else
  log "ERROR: apt-get update failed after retries. Continuing, but later installs may fail."
fi

log "Installing required base packages (may already be installed)..."
if apt_install_retry \
  lsb-release \
  ca-certificates \
  openssh-server \
  cron \
  ufw \
  fail2ban \
  unattended-upgrades \
  curl \
  wget \
  tar; then
  STEP_update_base_packages="OK"
else
  log "ERROR: Base package installation failed after retries."
fi

log "Ensuring SSH service is enabled and running..."
systemctl enable ssh >/dev/null 2>&1 || systemctl enable sshd >/dev/null 2>&1 || true
systemctl restart ssh  >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true

CODENAME="$(get_codename)"
if [[ -z "$CODENAME" ]]; then
  echo "[-] Unable to detect Ubuntu codename." >&2
  # We continue but unattended-upgrades config may be suboptimal
fi
log "Ubuntu codename detected: ${CODENAME:-unknown}"

# ----------------- Automated Security Updates ----------------- #

UU="/etc/apt/apt.conf.d/50unattended-upgrades"
AU="/etc/apt/apt.conf.d/20auto-upgrades"
CRON_UPDATES="/etc/cron.d/auto-security-updates"

backup "$UU"
backup "$AU"

log "Configuring unattended security-only upgrades..."

{
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

  cat > "$CRON_UPDATES" <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

0 4 * * * root unattended-upgrade -v >> /var/log/auto-security-updates.log 2>&1
EOF

  chmod 644 "$CRON_UPDATES"
  STEP_auto_security_updates="OK"
} || {
  log "ERROR: Failed to configure unattended upgrades."
}

# ----------------- SSH Hardening ----------------- #

SSH_HARDEN="/etc/ssh/sshd_config.d/99-hardening.conf"
mkdir -p /etc/ssh/sshd_config.d
backup "$SSH_HARDEN"

log "Applying SSH hardening (root login allowed, ports 22 & 2808, 5 attempts)..."

if cat > "$SSH_HARDEN" <<'EOF'
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
MaxAuthTries 5
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
then
  log "Testing SSH configuration..."
  if command -v sshd >/dev/null 2>&1; then
    if sshd -t; then
      systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || true
      log "SSHD reloaded with hardened config."
      STEP_ssh_hardening="OK"
    else
      echo "[-] SSH config test failed; not reloading." >&2
    fi
  else
    echo "[-] sshd binary not found; please verify openssh-server installation." >&2
  fi
else
  log "ERROR: Failed to write $SSH_HARDEN"
fi

# ----------------- Fail2Ban ----------------- #

FAIL_JAIL="/etc/fail2ban/jail.local"
mkdir -p /etc/fail2ban
backup "$FAIL_JAIL"

log "Configuring Fail2Ban for SSH (maxretry = 5)..."

if cat > "$FAIL_JAIL" <<'EOF'
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
then
  systemctl enable fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban >/dev/null 2>&1 || true
  STEP_fail2ban_config="OK"
else
  log "ERROR: Failed to write $FAIL_JAIL"
fi

# ----------------- UFW Firewall ----------------- #

log "Configuring UFW firewall (SSH, web, CyberPanel, mail, FTP, DNS)..."

UFW_OK=1

# SSH (primary + fallback)
ufw allow 22/tcp    >/dev/null 2>&1 || UFW_OK=0
ufw limit 22/tcp    >/dev/null 2>&1 || true

ufw allow 2808/tcp  >/dev/null 2>&1 || UFW_OK=0
ufw limit 2808/tcp  >/dev/null 2>&1 || true

# HTTP / HTTPS
ufw allow 80/tcp    >/dev/null 2>&1 || UFW_OK=0
ufw allow 443/tcp   >/dev/null 2>&1 || UFW_OK=0

# CyberPanel panel
ufw allow 8090/tcp  >/dev/null 2>&1 || UFW_OK=0

# OpenLiteSpeed WebAdmin
ufw allow 7080/tcp  >/dev/null 2>&1 || UFW_OK=0

# DNS
ufw allow 53/tcp    >/dev/null 2>&1 || UFW_OK=0
ufw allow 53/udp    >/dev/null 2>&1 || UFW_OK=0

# Mail Services
ufw allow 25/tcp    >/dev/null 2>&1 || UFW_OK=0
ufw allow 465/tcp   >/dev/null 2>&1 || UFW_OK=0
ufw allow 587/tcp   >/dev/null 2>&1 || UFW_OK=0
ufw allow 110/tcp   >/dev/null 2>&1 || UFW_OK=0
ufw allow 995/tcp   >/dev/null 2>&1 || UFW_OK=0
ufw allow 143/tcp   >/dev/null 2>&1 || UFW_OK=0
ufw allow 993/tcp   >/dev/null 2>&1 || UFW_OK=0

# FTP + Passive FTP
ufw allow 21/tcp           >/dev/null 2>&1 || UFW_OK=0
ufw allow 40110:40210/tcp  >/dev/null 2>&1 || UFW_OK=0

# Default policies
ufw default deny incoming  >/dev/null 2>&1 || UFW_OK=0
ufw default allow outgoing >/dev/null 2>&1 || UFW_OK=0

log "Enabling UFW firewall..."
if ufw --force enable >/dev/null 2>&1; then
  if (( UFW_OK == 1 )); then
    STEP_ufw_firewall="OK"
  else
    log "WARNING: Some UFW rules may have failed; check 'ufw status verbose'."
  fi
else
  log "ERROR: UFW enable failed. Check iptables/nftables support."
fi

# ----------------- ClamAV ----------------- #

log "Installing ClamAV antivirus..."

if apt_install_retry clamav clamav-daemon; then
  log "Configuring ClamAV (freshclam + clamd)..."
  systemctl stop clamav-freshclam >/dev/null 2>&1 || true
  if command -v freshclam >/dev/null 2>&1; then
    freshclam || log "WARNING: freshclam failed (check network or mirrors)."
  else
    log "ERROR: freshclam command not found after installation."
  fi
  systemctl enable clamav-freshclam >/dev/null 2>&1 || true
  systemctl restart clamav-freshclam >/dev/null 2>&1 || true

  systemctl enable clamav-daemon >/dev/null 2>&1 || true
  systemctl restart clamav-daemon >/dev/null 2>&1 || true

  STEP_clamav_install="OK"
else
  log "ERROR: ClamAV installation failed after retries."
fi

# ----------------- Maldet (Linux Malware Detect) ----------------- #

log "Installing Linux Malware Detect (Maldet)..."

TMP_DIR="/tmp/maldet-install"
mkdir -p "$TMP_DIR"

MALDET_URL="https://www.rfxn.com/downloads/maldetect-current.tar.gz"
MALDET_TGZ="${TMP_DIR}/maldetect-current.tar.gz"
MALDET_INST_OK=0

if wget -q -O "$MALDET_TGZ" "$MALDET_URL"; then
  if tar -xzf "$MALDET_TGZ" -C "$TMP_DIR"; then
    MALDET_SRC_DIR="$(find "$TMP_DIR" -maxdepth 1 -type d -name 'maldetect-*' | head -n1)"
    if [[ -n "$MALDET_SRC_DIR" ]]; then
      if (cd "$MALDET_SRC_DIR" && bash install.sh); then
        MALDET_INST_OK=1
      else
        log "ERROR: Maldet install.sh failed."
      fi
    else
      log "ERROR: Could not locate Maldet source directory after extraction."
    fi
  else
    log "ERROR: Failed to extract Maldet tarball."
  fi
else
  log "ERROR: Failed to download Maldet from $MALDET_URL"
fi

MALDET_CONF="/usr/local/maldetect/conf.maldet"
if [[ -f "$MALDET_CONF" ]]; then
  backup "$MALDET_CONF"
  sed -i 's/^scan_clamscan=.*/scan_clamscan="1"/' "$MALDET_CONF" || true
  sed -i 's/^scan_clamd=.*/scan_clamd="1"/' "$MALDET_CONF" || true
  log "Configured Maldet to use ClamAV engine."
fi

if [[ $MALDET_INST_OK -eq 1 ]]; then
  STEP_maldet_install="OK"
fi

# ----------------- Weekly Malware Scan via Cron ----------------- #

log "Creating weekly malware scan cron job (/home)..."

CRON_MALWARE="/etc/cron.d/weekly-malware-scan"

if cat > "$CRON_MALWARE" <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Weekly malware scan every Sunday at 03:30
# Scans all sites/data under /home (CyberPanel layout)
30 3 * * 0 root /usr/local/maldetect/maldet -b -r /home 1 >> /var/log/weekly-malware-scan.log 2>&1
EOF
then
  chmod 644 "$CRON_MALWARE"
  STEP_weekly_malware_cron="OK"
else
  log "ERROR: Failed to write $CRON_MALWARE"
fi

# ----------------- Initial Security Patch Run ----------------- #

log "Running initial security upgrade (unattended-upgrade)..."
if unattended-upgrade -v >> /var/log/auto-security-updates.log 2>&1; then
  STEP_initial_unattended_upgrade="OK"
else
  log "WARNING: unattended-upgrade returned an error; check /var/log/auto-security-updates.log"
fi

# ----------------- Summary ----------------- #

echo
echo "========================================================"
echo " Secure Server Setup Summary"
echo "========================================================"
printf "update_base_packages           : %s\n" "$STEP_update_base_packages"
printf "auto_security_updates          : %s\n" "$STEP_auto_security_updates"
printf "ssh_hardening                  : %s\n" "$STEP_ssh_hardening"
printf "fail2ban_config                : %s\n" "$STEP_fail2ban_config"
printf "ufw_firewall                   : %s\n" "$STEP_ufw_firewall"
printf "clamav_install                 : %s\n" "$STEP_clamav_install"
printf "maldet_install                 : %s\n" "$STEP_maldet_install"
printf "weekly_malware_cron            : %s\n" "$STEP_weekly_malware_cron"
printf "initial_unattended_upgrade     : %s\n" "$STEP_initial_unattended_upgrade"
echo "========================================================"
echo "[INFO] Any step marked 'FAILED' should be investigated."
echo "[INFO] Check /var/log/auto-security-updates.log and /var/log/weekly-malware-scan.log for details."
echo

exit 0
