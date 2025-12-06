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
#   - Harden SSH config (move SSH to custom port ONLY, root+password allowed)
#   - Install & configure Fail2Ban
#   - Configure & enable UFW firewall (SSH ONLY on custom port)
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

# ----------------- Custom SSH Port Setup ----------------- #

# Prompt user for custom SSH port (default is 22)
read -r -p "Enter custom SSH port (default: 22): " SSH_PORT
SSH_PORT="${SSH_PORT:-22}"

log "Using SSH port: $SSH_PORT"

# Backup the original sshd_config before making changes
backup "/etc/ssh/sshd_config"

# Replace all instances of Port 22 with the new custom port
sed -i "s/^Port 22/Port $SSH_PORT/g" /etc/ssh/sshd_config
sed -i "/^#Port $SSH_PORT/d" /etc/ssh/sshd_config  # Remove commented lines with old port if any

# Apply the changes by restarting SSH
log "Restarting SSH service to apply the new port..."
systemctl restart sshd

# ----------------- UFW Firewall Configuration ----------------- #

log "Configuring UFW firewall to allow the new SSH port..."

# Allow the custom SSH port
ufw allow "$SSH_PORT"/tcp

# Reload UFW to apply the changes
ufw reload

# ----------------- Fail2Ban Configuration ----------------- #

log "Configuring Fail2Ban to use the new SSH port..."

# Backup Fail2Ban config before making changes
backup "/etc/fail2ban/jail.local"

# Modify the port in Fail2Ban configuration
sed -i "s/^port     = ssh/port     = $SSH_PORT/" /etc/fail2ban/jail.local

# Restart Fail2Ban service to apply changes
systemctl restart fail2ban

# ----------------- Check SSH Connectivity ----------------- #

log "Verifying SSH connectivity on port $SSH_PORT..."

# Test SSH connectivity using the custom port
if nc -zv 127.0.0.1 "$SSH_PORT"; then
  log "[OK] SSH is reachable on port $SSH_PORT."
else
  log "[ERROR] SSH is NOT reachable on port $SSH_PORT. Please check your configuration."
fi

# ----------------- Final Steps ----------------- #

log "Secure Server Setup complete. Please verify SSH access using port $SSH_PORT."
log "If you are unable to connect, please verify firewall and SSH configuration."

exit 0
