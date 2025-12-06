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
#   - Harden SSH config (move SSH to custom port, root+password allowed)
#   - Install & configure Fail2Ban
#   - Configure & enable UFW firewall (SSH ONLY on custom port, not 22)
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

# ----------------- Custom Port Configuration ----------------- #
# Prompt the user to enter the custom SSH port before applying hardening
read -r -p "Enter custom SSH port (e.g., 2228) [Default:22]: " CUSTOM_SSH_PORT

# Use port 22 as the default if the user presses enter without typing anything
CUSTOM_SSH_PORT="${CUSTOM_SSH_PORT:-22}"
LOGGED_PORT="Custom port"  # Masked output for SSH port

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

# ----------------- SSH Hardening (custom port) ----------------- #

SSH_HARDEN="/etc/ssh/sshd_config.d/99-hardening.conf"
mkdir -p /etc/ssh/sshd_config.d
backup "$SSH_HARDEN"

log "Applying SSH hardening (SSH on $CUSTOM_SSH_PORT only, root+password allowed)..."

# Overwrite the existing Port line with the custom port if it exists in sshd_config
if grep -q "^Port" /etc/ssh/sshd_config; then
  # Replace the existing Port line with the custom port
  sed -i "s/^Port.*/Port $CUSTOM_SSH_PORT/" /etc/ssh/sshd_config
else
  # If no Port line exists, add the custom port at the end
  echo "Port $CUSTOM_SSH_PORT" >> /etc/ssh/sshd_config
fi

# Restart SSH service immediately to apply changes
sudo systemctl restart sshd

# Create or update SSH hardening file
SSH_CONFIG_OK=0
if cat > "$SSH_HARDEN" <<EOF
# SSH Hardening
Port $CUSTOM_SSH_PORT
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
  # Test the SSH configuration
  if sshd -t 2>/dev/null; then
    log "SSH configuration syntax OK. Reload will be done AFTER firewall check."
    SSH_CONFIG_OK=1
  else
    log "ERROR: SSH config test failed. Not reloading sshd."
  fi
fi

# Reload SSH service to apply changes if SSH config is OK
if [[ "$SSH_CONFIG_OK" -eq 1 ]]; then
  log "Reloading SSH service to apply custom port..."
  systemctl restart sshd

  # Check if the SSH service is listening on the custom port
  ss -tuln | grep "$CUSTOM_SSH_PORT" && log "SSH is now listening on port $CUSTOM_SSH_PORT"
  STEP_ssh_hardening="OK"
else
  log "SSH hardening failed, configuration not reloaded."
  STEP_ssh_hardening="FAILED"
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
port     = $CUSTOM_SSH_PORT
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

ufw delete allow OpenSSH  >/dev/null 2>&1 || true
ufw delete limit OpenSSH  >/dev/null 2>&1 || true
ufw delete allow 22/tcp   >/dev/null 2>&1 || true
ufw delete limit 22/tcp   >/dev/null 2>&1 || true

# Ensure custom port is allowed
ufw allow $CUSTOM_SSH_PORT/tcp        >/dev/null || UFW_OK=0

ufw default deny incoming  >/dev/null || UFW_OK=0
ufw default allow outgoing >/dev/null || UFW_OK=0

ufw --force enable >/dev/null && STEP_ufw_firewall="OK"

# ----------------- Firewalld Configuration ----------------- #

log "Configuring Firewalld..."

FIREWALLD_SERVICE="/etc/firewalld/services/SSHCustom.xml"
FIREWALLD_ZONE="/etc/firewalld/zones/public.xml"

# Backup existing files
backup "$FIREWALLD_SERVICE"
backup "$FIREWALLD_ZONE"

# Create or update the SSHCustom.xml service for the custom SSH port
cat > "$FIREWALLD_SERVICE" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<service>
  <port port="$CUSTOM_SSH_PORT" protocol="tcp"/>
</service>
EOF

# Check if the custom port exists in the public zone and add if not
if ! grep -q "port=\"$CUSTOM_SSH_PORT\"" "$FIREWALLD_ZONE"; then
  # Adding custom port rule for both IPv4 and IPv6
  sed -i "/<\/zone>/i \
  <rule family=\"ipv4\">\n\
    <source address=\"0.0.0.0/0\"/>\n\
    <port port=\"$CUSTOM_SSH_PORT\" protocol=\"tcp\"/>\n\
    <accept/>\n\
  </rule>\n\
  <rule family=\"ipv6\">\n\
    <source address=\"::/0\"/>\n\
    <port port=\"$CUSTOM_SSH_PORT\" protocol=\"tcp\"/>\n\
    <accept/>\n\
  </rule>" "$FIREWALLD_ZONE"

  # Reload firewalld to apply changes to public zone and service
  firewall-cmd --reload
  log "Custom port $CUSTOM_SSH_PORT added to Firewalld public zone."
else
  log "Custom port $CUSTOM_SSH_PORT already present in the Firewalld public zone."
fi

# Add the custom SSH port to firewalld permanently
firewall-cmd --zone=public --add-port=$CUSTOM_SSH_PORT/tcp --permanent

# Reload firewalld to apply the new port configuration
firewall-cmd --reload

# Check if the new custom SSH port is active in firewalld
if firewall-cmd --list-ports | grep -q "$CUSTOM_SSH_PORT/tcp"; then
  log "Custom SSH port $CUSTOM_SSH_PORT added to Firewalld successfully."
else
  log "Failed to add custom SSH port $CUSTOM_SSH_PORT to Firewalld."
fi

# ----------------- ClamAV ----------------- #

log "Checking ClamAV installation..."

if command -v clamscan >/dev/null 2>&1 && dpkg -s clamav-daemon >/dev/null 2>&1; then
  log "ClamAV already installed; skipping package installation."
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
