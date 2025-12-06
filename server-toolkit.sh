#!/usr/bin/env bash

# Server Toolkit Menu
#
# This menu provides easy access to the various server setup, backup, and restore functions.
# You can also view the status of your server's security setup, backups, and SSH configuration.

clear
echo "============================================================"
echo "              LunaServers – Server Toolkit Menu             "
echo "============================================================"
echo ""
echo "  1) Full Secure Server Setup"
echo "     - Runs setup-secure-server.sh"
echo "     - Hardens SSH (custom port), UFW, Fail2Ban"
echo "     - Sets up auto security updates, ClamAV, Maldet"
echo "     - Optionally runs Backup + Storage Box module from inside"
echo "     [STATUS] Already run at least once (marker present)"
echo ""
echo "  2) Run Auto Backup Setup Only"
echo "     - Runs setup-backup-module.sh for automated backup"
echo "     - Sets up Borg + Hetzner Storage Box backups"
echo "     - Creates daily backup cronjob and helper scripts"
echo ""
echo "  3) Run Restore Module Only"
echo "     - Runs restore-backup.sh"
echo "     - Restores selected sites from Borg backups"
echo "     - For disaster recovery / migrations"
echo "     NOTE: Running this repeatedly will NOT 'break' the OS,"
echo "           but CAN overwrite site files/databases each time."
echo ""
echo "  4) View Status"
echo "     - Shows markers, Borg repo & connectivity, cronjob presence"
echo ""
echo "  5) Exit Toolkit"
echo "============================================================"
echo ""
read -p "Select an option [1-5]: " choice

case "$choice" in
  1) 
    # Full Secure Server Setup
    bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/setup-secure-server.sh)
    ;;
  2) 
    # Auto Backup Module
    bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/setup-backup-module.sh)
    ;;
  3) 
    # Restore Backup Module
    bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/restore-backup.sh)
    ;;
  4) 
    # View Status
    echo "============================================================"
    echo "                    Viewing Server Status                  "
    echo "============================================================"
    # Call status-checking functions (or a script that handles this)
    bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/status-check.sh)
    ;;
  5) 
    echo "Exiting toolkit. Bye."
    exit 0
    ;;
  *)
    echo "Invalid option. Please choose between 1-5."
    ;;
esac
