#!/usr/bin/env bash
#
# setup-secure-server.sh
#
# One-time full-security setup for fresh Ubuntu:
#   - Repair dpkg/APT if broken
#   - Install base packages
#   - Enable kernel Livepatch via Ubuntu Pro (optional)
#   - Enable security-only automatic updates
#   - Configure monthly cron job for updates
#   - Harden SSH config (root login allowed, custom SSH port)
#   - Install & configure Fail2Ban
#   - Configure & enable UFW firewall
#   - Install ClamAV + Maldet
#   - Create weekly malware scan cron job
#
# Run directly:
#   bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/setup-secure-server.sh)

set -u   # strict on unset vars
set -o pipefail

# ----------------- Configurable SSH Port ----------------- #
# Single custom SSH port used everywhere (SSH, UFW, Fail2Ban)
SSH_PORT=2808

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

SSH_CONFIG_OK=0   # internal flag: SSH config validated but not yet reloaded

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

# ----------------- Ubuntu Pro / Livepatch (Optional) ----------------- #
echo "============================================================"
echo " Ubuntu Pro Livepatch Setup (Optional)"
echo "============================================================"
echo "Livepatch applies kernel security updates WITHOUT rebooting."
echo "Requires an Ubuntu Pro token (not the old Livepatch token)."
echo "Get one from: https://ubuntu.com/pro/subscribe"
echo
read -r -p "Enter your Ubuntu Pro token (leave blank to skip Livepatch): " UBUNTU_PRO_TOKEN
echo

if [[ -n "$UBUNTU_PRO_TOKEN" ]]; then
  log "Setting up Ubuntu Pro + Livepatch..."

  # Ensure 'pro' CLI is available
  if ! command -v pro >/dev/null 2>&1; then
    log "ubuntu-advantage-tools (pro CLI) missing — installing..."
    if ! apt_install_retry ubuntu-advantage-tools; then
      log "ERROR: ubuntu-advantage-tools install failed — cannot enable Livepatch."
      UBUNTU_PRO_TOKEN=""
    fi
  fi

  if [[ -n "$UBUNTU_PRO_TOKEN" ]] && command -v pro >/dev/null 2>&1; then
    # Attach if needed
    if pro status 2>&1 | grep -qi "not attached"; then
      log "Machine is NOT attached to Ubuntu Pro — attaching now..."
      if pro attach "$UBUNTU_PRO_TOKEN"; then
        log "Ubuntu Pro attached successfully."
      else
        log "WARNING: 'pro attach' failed — Livepatch may not be available."
      fi
    else
      log "Ubuntu Pro already attached; skipping 'pro attach'."
    fi

    is_livepatch_enabled() {
      pro status 2>/dev/null | awk '/livepatch/ {print tolower($0)}' | grep -q 'enabled'
    }

    if is_livepatch_enabled; then
      log "Livepatch already enabled via Ubuntu Pro."
      STEP_livepatch="OK"
    else
      log "Enabling Livepatch via 'pro enable livepatch' (ignore errors if already enabled)..."
      pro enable livepatch >/tmp/pro-livepatch.log 2>&1 || true

      if is_livepatch_enabled; then
        log "Livepatch enabled (or already enabled) according to 'pro status'."
        STEP_livepatch="OK"
      else
        log "WARNING: Livepatch still not reported as enabled after 'pro enable livepatch'."
        log "         See /tmp/pro-livepatch.log for details."
        STEP_livepatch="FAILED"
      fi
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

  # Monthly updates on 1st at 13:30 (cron in system time)
  cat > "$CRON_UPDATES" <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
30 13 1 * * root unattended-upgrade -v >> /var/log/auto-security-updates.log 2>&1
EOF

  chmod 644 "$CRON_UPDATES"
  STEP_auto_security_updates="OK"
} || log "ERROR: Failed to configure unattended-upgrades."

# ----------------- SSH Hardening (config only, reload later) ----------------- #

SSH_HARDEN="/etc/ssh/sshd_config.d/99-hardening.conf"
mkdir -p /etc/ssh/sshd_config.d
backup "$SSH_HARDEN"

log "Applying SSH hardening (port ${SSH_PORT}, root+password allowed)..."

if cat > "$SSH_HARDEN" <<EOF
# SSH Hardening
Port ${SSH_PORT}
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
    log "SSH configuration syntax OK. Reload will be done AFTER firewall check."
    SSH_CONFIG_OK=1
  else
    log "ERROR: SSH config test (sshd -t) failed. Not reloading sshd."
    SSH_CONFIG_OK=0
  fi
fi

# ----------------- Fail2Ban ----------------- #

FAIL_JAIL="/etc/fail2ban/jail.local"
mkdir -p /etc/fail2ban
backup "$FAIL_JAIL"

log "Configuring Fail2Ban..."

if cat > "$FAIL_JAIL" <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled  = true
port     = ${SSH_PORT}
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

# SSH port (custom only, no port 22)
ufw allow "${SSH_PORT}/tcp"    >/dev/null || UFW_OK=0
ufw limit "${SSH_PORT}/tcp"    >/dev/null || true

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

# Livepatch + Snapd traffic (HTTPS out)
ufw allow out 443/tcp >/dev/null || UFW_OK=0

ufw default deny incoming  >/dev/null || UFW_OK=0
ufw default allow outgoing >/dev/null || UFW_OK=0

ufw --force enable >/dev/null && STEP_ufw_firewall="OK"

# ----------------- SSH Pre-Check + Safe Reload ----------------- #

# ----------------- SSH Pre-Check + Safe Reload ----------------- #

log "Pre-check: ensuring firewall allows SSH port ${SSH_PORT} before reloading sshd..."

FIREWALL_ALLOWS_SSH=0
UFW_STATUS="$(ufw status 2>/dev/null || true)"

if echo "$UFW_STATUS" | grep -q "Status: active"; then
  # Match lines like:
  #   2808/tcp                  ALLOW       Anywhere
  #   2808                      ALLOW       Anywhere
  if echo "$UFW_STATUS" | grep -E "^[[:space:]]*${SSH_PORT}(/tcp)?[[:space:]]+ALLOW" >/dev/null; then
    FIREWALL_ALLOWS_SSH=1
  fi
else
  # If UFW is not active, we do NOT auto-reload SSH
  FIREWALL_ALLOWS_SSH=0
fi

if [[ "$SSH_CONFIG_OK" -eq 1 && "$FIREWALL_ALLOWS_SSH" -eq 1 ]]; then
  log "Firewall appears to allow port ${SSH_PORT}/tcp. Reloading sshd to apply new port..."
  if systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1; then
    STEP_ssh_hardening="OK"
    log "SSH is now configured to use ONLY port ${SSH_PORT}. Port 22 is not opened by this script."
    log "Use: ssh -p ${SSH_PORT} root@YOUR_SERVER_IP"
  else
    log "ERROR: Failed to reload sshd. SSH is still using the old configuration."
  fi
else
  log "WARNING: Skipping SSH reload because either:"
  log "  - SSH config did not validate, or"
  log "  - UFW does NOT clearly show an ALLOW rule for port ${SSH_PORT}/tcp."
  log "SSH is still running with its previous port configuration."
  log "Check:"
  log "  - /etc/ssh/sshd_config.d/99-hardening.conf"
  log "  - 'ufw status' for port ${SSH_PORT}"
  log "Then manually run: systemctl reload ssh"
fi

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
# Optional: Run external backup module (GitHub-hosted)
# -------------------------------------------------------------
read -r -p "Run Backup + Storage Box module now? [y/N]: " RUN_BACKUP
if [[ "$RUN_BACKUP" =~ ^[Yy]$ ]]; then
  log "Running Backup + Storage Box module..."
  if bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/setup-backup-module.sh); then
    log "Backup module completed successfully."
  else
    log "ERROR: Backup module failed. Check above logs."
  fi
else
  log "Skipping Backup + Storage Box module."
fi

exit 0
