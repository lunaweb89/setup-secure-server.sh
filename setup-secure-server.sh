#!/usr/bin/env bash
#
# setup-secure-server.sh
#
# One-time full-security setup for fresh Ubuntu:
#   - Repair dpkg/APT if broken
#   - Install required base packages
#   - Enable security-only automatic updates
#   - Configure monthly cron job for updates
#   - Harden SSH configuration (root login allowed, ports 22 + 2808)
#   - Install + configure Fail2Ban (maxretry=5)
#   - Configure + enable UFW firewall (SSH, web, CyberPanel, mail, FTP, DNS)
#   - Install ClamAV + Maldet (Linux Malware Detect)
#   - Run weekly malware scans via cron on /home
#
# Run directly:
#   bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server.sh/main/setup-secure-server.sh)

set -u   # strict on unset vars

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
    log "apt-get install ${pkgs[*]} failed, retrying..."
    apt-get -f install -y || true
    tries=$((tries + 1))
    sleep 5
  done
  return 1
}

# ----------------- Start ----------------- #

require_root
export DEBIAN_FRONTEND=noninteractive

# ----------------- Repair dpkg / APT ----------------- #
log "Checking dpkg / APT health..."

if dpkg --audit | grep -q .; then
  log "dpkg broken — repairing..."
  dpkg --configure -a || log "WARNING: dpkg configure did not fully succeed."
fi

apt-get -f install -y || true

log "Running apt-get update with retry..."
apt_update_retry || log "ERROR: apt-get update failed after retries."

log "Installing required base packages..."
if apt_install_retry lsb-release ca-certificates openssh-server cron ufw fail2ban unattended-upgrades curl wget tar; then
  STEP_update_base_packages="OK"
fi

log "Ensuring SSH service is running..."
systemctl enable ssh >/dev/null 2>&1 || systemctl enable sshd >/dev/null 2>&1
systemctl restart ssh  >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1

CODENAME="$(get_codename)"
log "Ubuntu codename detected: ${CODENAME:-unknown}"

# ----------------- Automated Security Updates ----------------- #

UU="/etc/apt/apt.conf.d/50unattended-upgrades"
AU="/etc/apt/apt.conf.d/20auto-upgrades"
CRON_UPDATES="/etc/cron.d/auto-security-updates"

backup "$UU"
backup "$AU"

log "Configuring unattended security-only upgrades..."

{
  # NEW: fallback if CODENAME is empty
  if [[ -n "$CODENAME" ]]; then
    ORIGIN_PATTERN="origin=Ubuntu,codename=${CODENAME},label=Ubuntu-Security"
  else
    ORIGIN_PATTERN="origin=Ubuntu,label=Ubuntu-Security"
  fi

  cat > "$UU" <<EOF
Unattended-Upgrade::Origins-Pattern {
  "${ORIGIN_PATTERN}";
};

Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "14:00";
Unattended-Upgrade::MailOnlyOnError "true";

# NEW Quality-of-life improvements
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
EOF

  # Periodic (still required even when using cron)
  cat > "$AU" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

  # UPDATED: monthly updates (1st of month at 13:30)
  cat > "$CRON_UPDATES" <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Run unattended-upgrade monthly on the 1st at 13:30
30 13 1 * * root unattended-upgrade -v >> /var/log/auto-security-updates.log 2>&1
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
    echo "[-] SSH config test failed; NOT reloading."
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

ufw allow 22/tcp    >/dev/null || UFW_OK=0
ufw limit 22/tcp    >/dev/null || true
ufw allow 2808/tcp  >/dev/null || UFW_OK=0
ufw limit 2808/tcp  >/dev/null || true

ufw allow 80/tcp    >/dev/null || UFW_OK=0
ufw allow 443/tcp   >/dev/null || UFW_OK=0
ufw allow 8090/tcp  >/dev/null || UFW_OK=0
ufw allow 7080/tcp  >/dev/null || UFW_OK=0
ufw allow 53/tcp    >/dev/null || UFW_OK=0
ufw allow 53/udp    >/dev/null || UFW_OK=0

ufw allow 25/tcp    >/dev/null || UFW_OK=0
ufw allow 465/tcp   >/dev/null || UFW_OK=0
ufw allow 587/tcp   >/dev/null || UFW_OK=0
ufw allow 110/tcp   >/dev/null || UFW_OK=0
ufw allow 995/tcp   >/dev/null || UFW_OK=0
ufw allow 143/tcp   >/dev/null || UFW_OK=0
ufw allow 993/tcp   >/dev/null || UFW_OK=0

ufw allow 21/tcp           >/dev/null || UFW_OK=0
ufw allow 40110:40210/tcp  >/dev/null || UFW_OK=0

ufw default deny incoming  >/dev/null || UFW_OK=0
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

MALDET_URL="https://www.rfxn.com/downloads/maldetect-current.tar.gz"
MALDET_TGZ="$TMP_DIR/maldetect-current.tar.gz"
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
fi

[[ $MALDET_INST_OK -eq 1 ]] && STEP_maldet_install="OK"

# ----------------- Weekly Malware Scan ----------------- #

CRON_MALWARE="/etc/cron.d/weekly-malware-scan"

log "Creating weekly malware scan cron..."

cat > "$CRON_MALWARE" <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

30 3 * * 0 root /usr/local/maldetect/maldet -b -r /home 1 >> /var/log/weekly-malware-scan.log 2>&1
EOF

chmod 644 "$CRON_MALWARE"
STEP_weekly_malware_cron="OK"

# ----------------- Initial Security Update ----------------- #

log "Running initial unattended security upgrade..."
if unattended-upgrade -v >> /var/log/auto-security-updates.log 2>&1; then
  STEP_initial_unattended_upgrade="OK"
fi

# ----------------- Reboot Notification (NEW) ----------------- #

if [[ -f /var/run/reboot-required ]]; then
  echo "--------------------------------------------------------"
  echo "[INFO] A system reboot is required to complete updates."
  echo "[INFO] It will automatically occur at the next window:"
  echo "       → 14:00"
  echo "--------------------------------------------------------"
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
echo "[INFO] Logs:"
echo " - /var/log/auto-security-updates.log"
echo " - /var/log/weekly-malware-scan.log"
echo
exit 0
