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
#   - Harden SSH config (move SSH to port 2808 ONLY, root+password allowed)
#   - Install & configure Fail2Ban
#   - Configure & enable UFW firewall (SSH ONLY on 2808, not 22)
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
    # Attach if needed (pro status exits 0 even when not attached, so check text)
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

    # Helper: check if Livepatch is reported enabled
    is_livepatch_enabled() {
      pro status 2>/dev/null | awk '/livepatch/ {print tolower($0)}' | grep -q 'enabled'
    }

    # If already enabled, don't even try to enable again
    if is_livepatch_enabled; then
      log "Livepatch already enabled via Ubuntu Pro."
      STEP_livepatch="OK"
    else
      log "Enabling Livepatch via 'pro enable livepatch' (ignore errors if already enabled)..."
      # Do NOT trust the exit code; some versions return non-zero even when it works
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

log "Checking required base packages (lsb-release, ufw, fail2ban, etc.)..."

BASE_PKGS=(lsb-release ca-certificates openssh-server cron ufw fail2ban unattended-upgrades curl wget tar)
NEED_INSTALL=()

for pkg in "${BASE_PKGS[@]}"; do
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    continue
  else
    NEED_INSTALL+=("$pkg")
  fi
done

if ((${#NEED_INSTALL[@]} > 0)); then
  log "Installing required base packages: ${NEED_INSTALL[*]}"
  if apt_install_retry "${NEED_INSTALL[@]}"; then
    STEP_update_base_packages="OK"
  else
    log "ERROR: Failed to install some base packages."
  fi
else
  log "All required base packages already installed; skipping apt-get install."
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

# ----------------- SSH Hardening (port 2808 only) ----------------- #

SSH_HARDEN="/etc/ssh/sshd_config.d/99-hardening.conf"
mkdir -p /etc/ssh/sshd_config.d
backup "$SSH_HARDEN"

log "Applying SSH hardening (SSH on port 2808 only, root+password allowed)..."

SSH_CONFIG_OK=0

if cat > "$SSH_HARDEN" <<'EOF'
# SSH Hardening
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
    log "SSH configuration syntax OK. Reload will be done AFTER firewall check."
    SSH_CONFIG_OK=1
  else
    log "ERROR: SSH config test failed. Not reloading sshd."
  fi
fi

# NOTE: We set STEP_ssh_hardening to OK only AFTER sshd is reloaded safely
# once UFW is confirmed to allow port 2808.

# ----------------- Update SSH Configuration ----------------- #

# Update /etc/ssh/sshd_config to uncomment PasswordAuthentication yes
SSH_CONFIG_FILE="/etc/ssh/sshd_config"

echo "Ensuring PasswordAuthentication is enabled and Port is correct..."

# Uncomment PasswordAuthentication yes and set Port to 2808
sudo sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' "$SSH_CONFIG_FILE"
sudo sed -i 's/^Port .*/Port 2808/' "$SSH_CONFIG_FILE"

# Reload SSH service to apply changes
sudo systemctl reload sshd

echo "[INFO] SSH configuration updated successfully."

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
port     = 2808
logpath  = %(sshd_log)s
backend  = systemd
EOF
then
  systemctl enable fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban >/dev/null 2>&1 || true
  STEP_fail2ban_config="OK"
fi

# ----------------- UFW Firewall ----------------- #

log "Configuring UFW firewall..."

UFW_OK=1

# Remove any existing OpenSSH / 22 rules so SSH is ONLY on 2808
ufw delete allow OpenSSH  >/dev/null 2>&1 || true
ufw delete limit OpenSSH  >/dev/null 2>&1 || true
ufw delete allow 22/tcp   >/dev/null 2>&1 || true
ufw delete limit 22/tcp   >/dev/null 2>&1 || true

# SSH custom port (2808) with rate-limiting
ufw limit 2808/tcp        >/dev/null || UFW_OK=0

# HTTP/HTTPS
ufw allow 80/tcp          >/dev/null || UFW_OK=0
ufw allow 443/tcp         >/dev/null || UFW_OK=0

# App ports
ufw allow 8090/tcp        >/dev/null || UFW_OK=0
ufw allow 7080/tcp        >/dev/null || UFW_OK=0

# DNS
ufw allow 53/tcp          >/dev/null || UFW_OK=0
ufw allow 53/udp          >/dev/null || UFW_OK=0
ufw allow out 53/tcp      >/dev/null || UFW_OK=0
ufw allow out 53/udp      >/dev/null || UFW_OK=0

# Email ports
ufw allow 25/tcp          >/dev/null || UFW_OK=0
ufw allow 465/tcp         >/dev/null || UFW_OK=0
ufw allow 587/tcp         >/dev/null || UFW_OK=0
ufw allow 110/tcp         >/dev/null || UFW_OK=0
ufw allow 995/tcp         >/dev/null || UFW_OK=0
ufw allow 143/tcp         >/dev/null || UFW_OK=0
ufw allow 993/tcp         >/dev/null || UFW_OK=0

# FTP
ufw allow 21/tcp          >/dev/null || UFW_OK=0
ufw allow 40110:40210/tcp >/dev/null || UFW_OK=0

# Livepatch + Snapd traffic (HTTPS out)
ufw allow out 443/tcp     >/dev/null || UFW_OK=0

ufw default deny incoming  >/dev/null || UFW_OK=0
ufw default allow outgoing >/dev/null || UFW_OK=0

ufw --force enable >/dev/null && STEP_ufw_firewall="OK"

# ---- Pre-check: ensure 2808 is allowed/limited before reloading SSH ---- #

if [[ "$SSH_CONFIG_OK" -eq 1 ]]; then
  log "[Pre-check] Ensuring firewall allows SSH port 2808 before reloading sshd..."

  if ufw status | grep -E '2808/tcp' | grep -E 'ALLOW|LIMIT' >/dev/null 2>&1; then
    if systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1; then
      log "SSH reloaded successfully. SSH now listens ONLY on port 2808."
      STEP_ssh_hardening="OK"
    else
      log "WARNING: Failed to reload sshd. Check 'systemctl status ssh' and logs."
    fi
  else
    log "[WARNING] UFW does not show an ALLOW/LIMIT rule for 2808/tcp."
    log "[WARNING] Not reloading sshd to avoid locking you out."
    log "[INFO] After fixing firewall, run: systemctl reload ssh"
  fi
else
  log "[WARNING] SSH hardening not fully applied because sshd -t failed earlier."
fi

# ----------------- ClamAV ----------------- #

log "Checking ClamAV installation..."

if command -v clamscan >/dev/null 2>&1 && dpkg -s clamav-daemon >/dev/null 2>&1; then
  log "ClamAV already installed; skipping package installation."
  # Make sure services are enabled/running
  systemctl enable clamav-freshclam >/dev/null 2>&1 || true
  systemctl restart clamav-freshclam >/dev/null 2>&1 || true
  systemctl restart clamav-daemon >/dev/null 2>&1 || true
  STEP_clamav_install="OK"
else
  log "Installing ClamAV..."
  if apt_install_retry clamav clamav-daemon; then
    systemctl stop clamav-freshclam >/dev/null 2>&1 || true
    freshclam || log "WARNING: freshclam failed."
    systemctl enable clamav-freshclam >/dev/null 2>&1 || true
    systemctl restart clamav-freshclam >/dev/null 2>&1 || true
    systemctl restart clamav-daemon >/dev/null 2>&1 || true
    STEP_clamav_install="OK"
  else
    log "ERROR: Failed to install ClamAV packages."
  fi
fi

# ----------------- Maldet ----------------- #

log "Checking Maldet installation..."

MALDET_CONF="/usr/local/maldetect/conf.maldet"

if [[ -x /usr/local/maldetect/maldet || -x /usr/local/sbin/maldet || -x /usr/local/sbin/lmd ]]; then
  log "Maldet already installed; skipping re-install."
else
  log "Installing Maldet..."

  TMP_DIR="/tmp/maldet-install"
  mkdir -p "$TMP_DIR"

  MALDET_TGZ="$TMP_DIR/maldetect-current.tar.gz"
  MALDET_URL="https://www.rfxn.com/downloads/maldetect-current.tar.gz"

  if wget -q -O "$MALDET_TGZ" "$MALDET_URL"; then
    tar -xzf "$MALDET_TGZ" -C "$TMP_DIR"
    MALDET_SRC_DIR="$(find "$TMP_DIR" -maxdepth 1 -type d -name 'maldetect-*' | head -n1)"
    if [[ -n "$MALDET_SRC_DIR" ]]; then
      (cd "$MALDET_SRC_DIR" && bash install.sh) || log "WARNING: Maldet install.sh returned a non-zero exit."
    else
      log "WARNING: Could not find extracted Maldet source directory."
    fi
  else
    log "WARNING: Failed to download Maldet tarball."
  fi
fi

# Configure Maldet if config exists (whether newly installed or already present)
if [[ -f "$MALDET_CONF" ]]; then
  sed -i 's/^scan_clamscan=.*/scan_clamscan="1"/' "$MALDET_CONF"
  sed -i 's/^scan_clamd=.*/scan_clamd="1"/' "$MALDET_CONF"
  STEP_maldet_install="OK"
else
  log "WARNING: Maldet config file not found at $MALDET_CONF"
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

# ----------------- SSH Connectivity Test (Port 2808) ----------------- #

echo "================ SSH Connectivity Test (port 2808) ================"

# Best-effort guess of primary server IP (for info only)
SERVER_IP_GUESS="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [[ -z "${SERVER_IP_GUESS:-}" ]]; then
  SERVER_IP_GUESS="127.0.0.1"
fi

read -r -p "Enter server IP/hostname to test TCP on port 2808 [${SERVER_IP_GUESS}]: " SSH_TEST_HOST
SSH_TEST_HOST="${SSH_TEST_HOST:-$SERVER_IP_GUESS}"

# Test TCP connection first (without SSH login)
TCP_TEST_OK=0
if command -v nc >/dev/null 2>&1; then
  if nc -zw5 "$SSH_TEST_HOST" 2808 >/dev/null 2>&1; then
    echo "[OK] TCP connection to ${SSH_TEST_HOST}:2808 succeeded (port is open)."
    TCP_TEST_OK=1
  else
    echo "[-] WARNING: TCP connection to ${SSH_TEST_HOST}:2808 FAILED."
    echo "    Check that sshd is listening on port 2808 and that UFW allows it."
  fi
else
  echo "[-] WARNING: netcat (nc) not found — skipping TCP test."
  TCP_TEST_OK=0
fi

# If TCP test is successful, attempt SSH login to the server
if [[ "$TCP_TEST_OK" -eq 1 ]]; then
  echo "[INFO] Attempting SSH login on port 2808..."

  # Set the default username as root (no prompt needed)
  SSH_USER="root"

  # Prompt for SSH password for the specified user
  read -s -r -p "Enter SSH password for $SSH_USER@$SSH_TEST_HOST: " SSH_PASSWORD
  echo

  # Test SSH login using the provided username, password, and port 2808
  SSH_TEST_OK=0
  if sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no -p 2808 "$SSH_USER@$SSH_TEST_HOST" 'exit' >/dev/null 2>&1; then
    echo "[OK] SSH login successful on ${SSH_TEST_HOST}:2808."
    SSH_TEST_OK=1
  else
    echo "[-] WARNING: SSH login to ${SSH_TEST_HOST}:2808 FAILED."
    echo "    Check SSH server configuration and ensure the correct port is open."
  fi
fi

if [[ "$SSH_TEST_OK" -eq 1 ]]; then
  echo "[INFO] SSH on port 2808 appears to be working correctly."
else
  echo "[INFO] Please verify SSH access from your own machine before closing this session."
fi

echo "=================================================================="

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
