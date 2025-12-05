#!/usr/bin/env bash
#
# setup-secure-server.sh
#
# One-time full-security setup for fresh Ubuntu:
#   - Repair dpkg/APT if broken
#   - Install base packages
#   - Enable kernel Livepatch (optional)
#   - Enable security-only automatic updates
#   - Configure monthly cron job for updates
#   - Harden SSH config (root login allowed, ports 22 + 2808)
#   - Install & configure Fail2Ban
#   - Configure & enable UFW firewall
#   - Install ClamAV + Maldet
#   - Create weekly malware scan cron job
#
# Run directly:
#   bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/setup-secure-server.sh)

set -u   # strict on unset vars
set -o pipefail

# ----------------- Step Status ----------------- #
STEP_update_base_packages="FAILED"
STEP_livepatch="SKIPPED"
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
    . /etc/os-release
    echo "${VERSION_CODENAME:-}"
  fi
}

apt_update_retry() {
  local tries=0 max_tries=3
  while (( tries < max_tries )); do
    if apt-get update -qq; then return 0; fi
    log "apt-get update failed (attempt $((tries+1))/$max_tries), retrying in 5s..."
    tries=$((tries + 1))
    sleep 5
  done
  return 1
}

apt_install_retry() {
  local tries=0 max_tries=3 pkgs=("$@")
  while (( tries < max_tries )); do
    if apt-get install -y -qq "${pkgs[@]}"; then return 0; fi
    log "apt-get install ${pkgs[*]} failed — running apt-get -f install..."
    apt-get -f install -y || true
    tries=$((tries + 1))
    sleep 5
  done
  return 1
}

# ----------------- Start ----------------- #

require_root
export DEBIAN_FRONTEND=noninteractive

# ----------------- Prompt for Livepatch Token ----------------- #
echo "============================================================"
echo " Ubuntu Kernel Livepatch Setup (Optional)"
echo "============================================================"
echo "Livepatch applies kernel security updates WITHOUT rebooting."
echo "Get a FREE token from: https://auth.livepatch.canonical.com/"
echo
read -r -p "Enter your Livepatch token (leave blank to skip): " LIVEPATCH_TOKEN
echo

if [[ -n "$LIVEPATCH_TOKEN" ]]; then
  log "Installing Canonical Livepatch..."

  if ! command -v snap >/dev/null 2>&1; then
    log "Snapd missing — installing..."
    apt-get update -qq
    apt-get install -y -qq snapd || {
      log "ERROR: snapd install failed — cannot use Livepatch."
      LIVEPATCH_TOKEN=""
    }
  fi

  if [[ -n "$LIVEPATCH_TOKEN" ]]; then
    snap install canonical-livepatch >/dev/null 2>&1 && \
    canonical-livepatch enable "$LIVEPATCH_TOKEN" >/dev/null 2>&1

    if canonical-livepatch status 2>/dev/null | grep -q "kernel"; then
      log "Livepatch enabled successfully."
      STEP_livepatch="OK"
    else
      log "WARNING: Livepatch activation failed."
      STEP_livepatch="FAILED"
    fi
  fi
else
  log "Livepatch skipped."
fi

# ----------------- Repair dpkg / APT ----------------- #

log "Checking dpkg / APT health..."

if dpkg --audit | grep -q .; then
  log "dpkg broken — repairing..."
  dpkg --configure -a || log "WARNING: dpkg configure did not finish cleanly."
fi

apt-get -f install -y || true

log "Running apt-get update..."
apt_update_retry || log "ERROR: apt-get update failed."

log "Installing required base packages..."
if apt_install_retry lsb-release ca-certificates openssh-server cron ufw fail2ban unattended-upgrades curl wget tar; then
  STEP_update_base_packages="OK"
fi

# ----------------- SSH ensure service exists ----------------- #

systemctl enable ssh >/dev/null 2>&1 || systemctl enable sshd >/dev/null 2>&1
systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1

CODENAME="$(get_codename)"
log "Ubuntu codename detected: ${CODENAME:-unknown}"

# ----------------- Automated Security Updates ----------------- #

UU="/etc/apt/apt.conf.d/50unattended-upgrades"
AU="/etc/apt/apt.conf.d/20auto-upgrades"
CRON_UPDATES="/etc/cron.d/auto-security-updates"

backup "$UU"
backup "$AU"

log "Configuring unattended security upgrades..."

{
  if [[ -n "$CODENAME" ]]; then
    ORIGIN_PATTERN="origin=Ubuntu,codename=${CODENAME},label=Ubuntu-Security"
  else
    ORIGIN_PATTERN="origin=Ubuntu,label=Ubuntu-Security"
  fi

  cat > "$UU" <<EOF
Unattended-Upgrade::Origins-Pattern {
  "${ORIGIN_PATTERN}";
};

Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "14:00";
Unattended-Upgrade::MailOnlyOnError "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
EOF

  cat > "$AU" <<EOF
APT::Periodic::Update-Package-Lists "7";
APT::Periodic::Unattended-Upgrade "7";
EOF

  # Monthly updates on 1st at 13:30
  cat > "$CRON_UPDATES" <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
30 13 1 * * root unattended-upgrade -v >> /var/log/auto-security-updates.log 2>&1
EOF

  chmod 644 "$CRON_UPDATES"
  STEP_auto_security_updates="OK"
} || log "ERROR: Failed to configure unattended-upgrades."

# ----------------- SSH Hardening ----------------- #

SSH_HARDEN="/etc/ssh/sshd_config.d/99-hardening.conf"
mkdir -p /etc/ssh/sshd_config.d
backup "$SSH_HARDEN"

log "Applying SSH hardening..."

if cat > "$SSH_HARDEN" <<'EOF'
# SSH Hardening
Port 22
Port 2808
Protocol 2
PermitRootLogin yes
PasswordAuthentication yes
ChallengeResponseAuthentication no
PermitEmptyPasswords no
UsePAM yes
X11Forwarding no
AllowTcpForwarding yes
AllowAgentForwarding yes
LoginGraceTime 30
MaxAuthTries 5
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
then
  if sshd -t 2>/dev/null; then
    systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1
    STEP_ssh_hardening="OK"
  else
    log "ERROR: SSH config test failed."
  fi
fi

# ----------------- Fail2Ban ----------------- #

FAIL_JAIL="/etc/fail2ban/jail.local"
mkdir -p /etc/fail2ban
backup "$FAIL_JAIL"

log "Configuring Fail2Ban..."

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
  systemctl enable fail2ban >/dev/null
  systemctl restart fail2ban >/dev/null
  STEP_fail2ban_config="OK"
fi

# ----------------- UFW Firewall ----------------- #

log "Configuring UFW firewall..."

UFW_OK=1

# SSH ports
ufw allow 22/tcp    >/dev/null || UFW_OK=0
ufw limit 22/tcp    >/dev/null || true
ufw allow 2808/tcp  >/dev/null || UFW_OK=0
ufw limit 2808/tcp  >/dev/null || true

# HTTP/HTTPS
ufw allow 80/tcp    >/dev/null || UFW_OK=0
ufw allow 443/tcp   >/dev/null || UFW_OK=0

# App ports
ufw allow 8090/tcp  >/dev/null || UFW_OK=0
ufw allow 7080/tcp  >/dev/null || UFW_OK=0

# DNS
ufw allow 53/tcp    >/dev/null || UFW_OK=0
ufw allow 53/udp    >/dev/null || UFW_OK=0
ufw allow out 53/tcp >/dev/null || UFW_OK=0
ufw allow out 53/udp >/dev/null || UFW_OK=0

# Email ports
ufw allow 25/tcp    >/dev/null || UFW_OK=0
ufw allow 465/tcp   >/dev/null || UFW_OK=0
ufw allow 587/tcp   >/dev/null || UFW_OK=0
ufw allow 110/tcp   >/dev/null || UFW_OK=0
ufw allow 995/tcp   >/dev/null || UFW_OK=0
ufw allow 143/tcp   >/dev/null || UFW_OK=0
ufw allow 993/tcp   >/dev/null || UFW_OK=0

# FTP
ufw allow 21/tcp          >/dev/null || UFW_OK=0
ufw allow 40110:40210/tcp >/dev/null || UFW_OK=0

# Livepatch + Snapd traffic
ufw allow out 443/tcp >/dev/null || UFW_OK=0

ufw default deny incoming >/dev/null || UFW_OK=0
ufw default allow outgoing >/dev/null || UFW_OK=0

ufw --force enable >/dev/null && STEP_ufw_firewall="OK"

# ----------------- ClamAV ----------------- #

log "Installing ClamAV..."

if apt_install_retry clamav clamav-daemon; then
  systemctl stop clamav-freshclam >/dev/null 2>&1 || true
  freshclam || log "WARNING: freshclam failed."
  systemctl enable clamav-freshclam >/dev/null
  systemctl restart clamav-freshclam >/dev/null
  systemctl restart clamav-daemon >/dev/null
  STEP_clamav_install="OK"
fi

# ----------------- Maldet ----------------- #

log "Installing Maldet..."

TMP_DIR="/tmp/maldet-install"
mkdir -p "$TMP_DIR"

MALDET_TGZ="$TMP_DIR/maldetect-current.tar.gz"
MALDET_URL="https://www.rfxn.com/downloads/maldetect-current.tar.gz"

MALDET_INST_OK=0

if wget -q -O "$MALDET_TGZ" "$MALDET_URL"; then
  tar -xzf "$MALDET_TGZ" -C "$TMP_DIR"
  MALDET_SRC_DIR="$(find "$TMP_DIR" -maxdepth 1 -type d -name 'maldetect-*' | head -n1)"
  if [[ -n "$MALDET_SRC_DIR" ]]; then
    (cd "$MALDET_SRC_DIR" && bash install.sh) && MALDET_INST_OK=1
  fi
fi

if [[ -f /usr/local/maldetect/conf.maldet ]]; then
  sed -i 's/^scan_clamscan=.*/scan_clamscan="1"/' /usr/local/maldetect/conf.maldet
  sed -i 's/^scan_clamd=.*/scan_clamd="1"/' /usr/local/maldetect/conf.maldet
  STEP_maldet_install="OK"
fi

# ----------------- Weekly Malware Scan ----------------- #

CRON_MALWARE="/etc/cron.d/weekly-malware-scan"

log "Creating weekly malware scan cron job..."

cat > "$CRON_MALWARE" <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
30 3 * * 0 root /usr/local/maldetect/maldet -b -r /home 1 >> /var/log/weekly-malware-scan.log 2>&1
EOF

chmod 644 "$CRON_MALWARE"
STEP_weekly_malware_cron="OK"

# ----------------- Initial Upgrade ----------------- #

log "Running initial unattended security upgrade..."

if unattended-upgrade -v >> /var/log/auto-security-updates.log 2>&1; then
  STEP_initial_unattended_upgrade="OK"
fi

# ----------------- Reboot Notification ----------------- #

if [[ -f /var/run/reboot-required ]]; then
  echo "--------------------------------------------------------"
  echo "[INFO] A system reboot is required."
  echo "[INFO] Automatic reboot is DISABLED — reboot manually when convenient."
  echo "--------------------------------------------------------"
fi

# ----------------- Summary ----------------- #

echo
echo "================ Secure Server Setup Summary ================"
printf "update_base_packages           : %s\n" "$STEP_update_base_packages"
printf "livepatch                      : %s\n" "$STEP_livepatch"
printf "auto_security_updates          : %s\n" "$STEP_auto_security_updates"
printf "ssh_hardening                  : %s\n" "$STEP_ssh_hardening"
printf "fail2ban_config                : %s\n" "$STEP_fail2ban_config"
printf "ufw_firewall                   : %s\n" "$STEP_ufw_firewall"
printf "clamav_install                 : %s\n" "$STEP_clamav_install"
printf "maldet_install                 : %s\n" "$STEP_maldet_install"
printf "weekly_malware_cron            : %s\n" "$STEP_weekly_malware_cron"
printf "initial_unattended_upgrade     : %s\n" "$STEP_initial_unattended_upgrade"
echo "=============================================================="
echo "[INFO] Logs:"
echo " - /var/log/auto-security-updates.log"
echo " - /var/log/weekly-malware-scan.log"
echo
# -------------------------------------------------------------
# Run external backup module (GitHub-hosted)
# -------------------------------------------------------------
log "Running Backup + Storage Box module..."

bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server.sh/main/setup-backup-module.sh)

if [[ $? -eq 0 ]]; then
  log "Backup module completed successfully."
else
  log "ERROR: Backup module failed. Check above logs."
fi

exit 0
