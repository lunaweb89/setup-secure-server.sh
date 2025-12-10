## LunaServers – Secure Setup & Performance Toolkit

This repository provides a complete, opinionated toolkit to:

- Secure a fresh Ubuntu server (SSH hardening, UFW, Fail2Ban, auto security updates, malware scanners)
- Configure automated Borg backups to Hetzner Storage Box (or similar)
- Restore sites quickly in a disaster or migration scenario
- Optimize performance for OpenLiteSpeed + CyberPanel + MariaDB + Redis
- Roll back optimizer changes safely if needed

Supported stack (tested and targeted):
- Ubuntu 20.04 / 22.04 / 24.04
- OpenLiteSpeed (OLS) + CyberPanel
- MariaDB
- Redis
- WordPress / WooCommerce workloads

---

### 1. Quick Start: Server Toolkit Menu

Run everything through the toolkit menu (recommended):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/server-toolkit.sh)
You will see:

Full Secure Server Setup

Runs setup-secure-server.sh

Hardens SSH (custom port), UFW, Fail2Ban

Sets up auto security updates, ClamAV, Maldet

Optionally runs:

Backup module (Borg + Storage Box)

Performance Optimizer (server-optimizer.sh)

Run Auto Backup Setup Only

Runs setup-backup-module.sh

Configures Borg + Storage Box

Creates daily backup cronjob and helper scripts

Run Restore Module Only

Runs restore-backup.sh

Lets you select and restore sites from Borg backups

For disaster recovery or server migrations

Run Performance Optimizer Only

Runs server-optimizer.sh

Auto-detects CPU/RAM

Tunes:

sysctl & limits

OpenLiteSpeed & PHP LSAPI (all installed lsphp versions)

MariaDB (uses ~60% of RAM for buffer pool)

Redis (uses ~15% of RAM, capped at 2 GB)

Leaves ~25% RAM free for OS, backups, malware scans, and spikes

Only prompts if something is unsafe or fails (e.g. low disk, bad config)

Run Performance Optimizer Rollback

Runs server-optimizer-rollback.sh

Restores most recent backups of:

/etc/sysctl.d/99-ols-optimized.conf

/usr/local/lsws/conf/httpd_config.conf

/usr/local/lsws/lsphp*/etc/php.ini

/etc/redis/redis.conf

/etc/mysql/mariadb.conf.d/99-optimized.cnf

Re-applies sysctl and restarts Redis, MariaDB, and OpenLiteSpeed

Lets you test and revert optimizer changes if needed

View Status

Shows presence of marker files:

/root/.secure_server_setup_done

/root/.backup_module_setup_done

/root/.restore_module_last_run

/root/.server_optimizer_last_run

/root/.server_optimizer_rollback_last_run

Displays UFW and Fail2Ban status (if installed)

Exit Toolkit

2. Recommended Run Order for a New Server
For a fresh Ubuntu + CyberPanel + OLS server, the recommended flow is:

Secure the server first

From the toolkit:

Choose 1) Full Secure Server Setup

Follow prompts to:

Harden SSH (custom port, disable password login if you use keys)

Enable UFW and Fail2Ban

Set up automatic security updates

Install and configure malware scanners

At the end, the script will optionally offer to:

Run the backup module

Run the performance optimizer

Set up backups

You can either:

Run the backup module from inside the secure-setup script when prompted; or

Later, from the toolkit choose 2) Run Auto Backup Setup Only.

Make sure:

Borg repository and Storage Box are working

At least one full backup completes successfully before going to production

Optimize performance

When your stack is installed (OpenLiteSpeed, CyberPanel, MariaDB, Redis, WordPress):

From the toolkit, choose 4) Run Performance Optimizer Only

Or run directly:

bash
Copy code
bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/server-optimizer.sh)
The optimizer will:

Detect total RAM and CPU cores

Allocate RAM approximately as:

~60% to MariaDB

~15% to Redis (max 2 GB)

~25% reserved for the OS and spikes

Tune sysctl, limits, OpenLiteSpeed, PHP LSAPI, MariaDB, Redis

Restart services safely, with checks

Rollback if needed

If after optimization you see unexpected behavior, you can roll back:

From the toolkit, choose 5) Run Performance Optimizer Rollback

Or run directly:

bash
Copy code
bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/server-optimizer-rollback.sh)
Then re-test your sites and services.

3. Idempotency & Safety
The secure setup, backup module, and optimizer are safe to run multiple times.

Restore module can overwrite files/databases—use with care.

Optimizer:

Creates timestamped backups of every config it touches

Writes a marker file /root/.server_optimizer_last_run

Rollback:

Restores the most recent backups

Writes /root/.server_optimizer_rollback_last_run

Always test changes on a staging server, or ensure you have working backups before running on critical production servers.
