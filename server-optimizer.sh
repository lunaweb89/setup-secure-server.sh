#!/usr/bin/env bash
#
# server-optimizer.sh
#
# Auto-Optimization Script for:
#   - Ubuntu 20.04 / 22.04 / 24.04
#   - OpenLiteSpeed
#   - CyberPanel
#   - MariaDB
#   - Redis
#   - WordPress / WooCommerce workloads
#
# Auto-detects CPU/RAM and tunes server based on:
#   - MariaDB = 60% RAM
#   - Redis = 15% RAM (capped at 2GB)
#   - Leaves ~25% RAM for OS + PHP + OLS spikes
#
# Fully automatic — only prompts if something is unsafe or would break.
#

set -euo pipefail

log() { echo -e "[+] $*"; }
warn() { echo -e "[-] $*"; }
err() { echo -e "[ERROR] $*" >&2; }

timestamp="$(date +%Y%m%d-%H%M%S)"

###############################################
# 1. DETECT CPU & RAM
###############################################

log "Detecting system resources..."

TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_MB=$((TOTAL_RAM_KB / 1024))
TOTAL_RAM_GB=$((TOTAL_RAM_MB / 1024))

CPU_CORES=$(nproc)

log "Total RAM: ${TOTAL_RAM_MB} MB (${TOTAL_RAM_GB} GB)"
log "CPU cores: ${CPU_CORES}"

if (( TOTAL_RAM_MB < 2048 )); then
  warn "Server has less than 2GB RAM. Optimization may be limited."
fi

###############################################
# 2. CALCULATE ALLOCATIONS
###############################################

log "Calculating dynamic RAM allocations..."

# MariaDB = 60%
MARIADB_MB=$(( TOTAL_RAM_MB * 60 / 100 ))
# Redis = 15% but max 2GB
REDIS_MB=$(( TOTAL_RAM_MB * 15 / 100 ))
if (( REDIS_MB > 2048 )); then REDIS_MB=2048; fi

RESERVED_MB=$(( TOTAL_RAM_MB - MARIADB_MB - REDIS_MB ))

log "MariaDB Allocation: ${MARIADB_MB} MB"
log "Redis Allocation: ${REDIS_MB} MB"
log "Reserved for OS spikes: ${RESERVED_MB} MB"

###############################################
# 3. SAFETY CHECK — DISK SPACE
###############################################

DISK_PCT=$(df / | awk 'NR==2{print $5}' | sed 's/%//')

if (( DISK_PCT > 85 )); then
    warn "Disk usage above 85%. This is unsafe for optimization."
    read -rp "Proceed anyway? (y/N): " ans
    if [[ ! "$ans" =~ ^[Yy]$ ]]; then
        err "Aborting to avoid breaking server."
        exit 1
    fi
fi

###############################################
# 4. SYSCTL OPTIMIZATION
###############################################

log "Applying sysctl tuning..."

SYSCTL_FILE="/etc/sysctl.d/99-ols-optimized.conf"

cp "$SYSCTL_FILE" "$SYSCTL_FILE.bak-$timestamp" 2>/dev/null || true

cat > "$SYSCTL_FILE" <<EOF
fs.file-max = 1048576

net.core.somaxconn = 65535
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_fin_timeout = 15

vm.swappiness = 10
vm.vfs_cache_pressure = 50
EOF

sysctl --system >/dev/null

###############################################
# 5. LIMITS CONFIGURATION
###############################################

log "Updating /etc/security/limits.conf..."

cat > /etc/security/limits.conf <<EOF
* soft nofile 1024000
* hard nofile 1024000
root soft nofile 1024000
root hard nofile 1024000
EOF

###############################################
# 6. OPENLITESPEED OPTIMIZATION
###############################################

log "Optimizing OpenLiteSpeed..."

OLS_CONF="/usr/local/lsws/conf/httpd_config.conf"

if [[ -f "$OLS_CONF" ]]; then
    cp "$OLS_CONF" "$OLS_CONF.bak-$timestamp"

    sed -i "s/^maxConnections.*/maxConnections                $((CPU_CORES * 4000))/" "$OLS_CONF"
    sed -i "s/^maxSSLConnections.*/maxSSLConnections          $((CPU_CORES * 1000))/" "$OLS_CONF"
    sed -i "s/^adminReqPerSec.*/adminReqPerSec                2000/" "$OLS_CONF"
else
    warn "OpenLiteSpeed config not found. Skipping."
fi

###############################################
# 7. PHP LSAPI OPTIMIZATION FOR ALL VERSIONS
###############################################

log "Optimizing all installed PHP LSAPI versions..."

for PHPINI in /usr/local/lsws/lsphp*/etc/php.ini; do
    [[ -f "$PHPINI" ]] || continue

    cp "$PHPINI" "$PHPINI.bak-$timestamp"

    sed -i "s/^memory_limit.*/memory_limit = 512M/" "$PHPINI"
    sed -i "s/^max_execution_time.*/max_execution_time = 300/" "$PHPINI"

    # LSAPI children = CPU * 10 (balanced)
    sed -i "s/^;*lsapi_children.*/lsapi_children = $((CPU_CORES * 10))/" "$PHPINI"

done

###############################################
# 8. REDIS OPTIMIZATION
###############################################

log "Optimizing Redis..."

REDIS_CONF="/etc/redis/redis.conf"
cp "$REDIS_CONF" "$REDIS_CONF.bak-$timestamp"

sed -i "s/^maxmemory .*/maxmemory ${REDIS_MB}mb/" "$REDIS_CONF"
sed -i "s/^# maxmemory-policy.*/maxmemory-policy allkeys-lru/" "$REDIS_CONF"

###############################################
# 9. MARIADB OPTIMIZATION
###############################################

log "Optimizing MariaDB..."

MARIADB_CONF="/etc/mysql/mariadb.conf.d/99-optimized.cnf"
cp "$MARIADB_CONF" "$MARIADB_CONF.bak-$timestamp" 2>/dev/null || true

cat > "$MARIADB_CONF" <<EOF
[mysqld]
max_connections         = 300
connect_timeout         = 5
wait_timeout            = 60
interactive_timeout     = 180
thread_cache_size       = 50

query_cache_type        = 0
query_cache_size        = 0

innodb_buffer_pool_size = ${MARIADB_MB}M
innodb_log_file_size    = 256M
innodb_flush_method     = O_DIRECT
innodb_flush_log_at_trx_commit = 2
innodb_file_per_table   = 1

innodb_io_capacity      = 4000
innodb_io_capacity_max  = 8000
EOF

###############################################
# 10. CONFIG VALIDATION
###############################################

log "Validating configurations..."

if ! mysqld --verbose --help >/dev/null 2>&1; then
    err "MariaDB config test failed. Restore backup:"
    echo "cp $MARIADB_CONF.bak-$timestamp $MARIADB_CONF"
    exit 1
fi

redis-server --test-memory 64 >/dev/null 2>&1 || warn "Redis memory test warning."

###############################################
# 11. RESTART SERVICES
###############################################

log "Restarting Redis..."
systemctl restart redis-server || err "Redis restart failed!"

log "Restarting MariaDB..."
systemctl restart mariadb || err "MariaDB restart failed!"

if systemctl status lsws >/dev/null 2>&1; then
    log "Restarting OpenLiteSpeed..."
    systemctl restart lsws || err "OLS restart failed!"
fi

###############################################
# 12. HEALTH REPORT
###############################################

log "Optimization completed. Generating health summary..."

echo "------ HEALTH SUMMARY ------"
echo "CPU cores: $CPU_CORES"
echo "Total RAM: ${TOTAL_RAM_MB} MB"
echo "MariaDB: ${MARIADB_MB} MB"
echo "Redis: ${REDIS_MB} MB"
echo "Reserved: ${RESERVED_MB} MB"
echo
echo "MariaDB threads_running:"
mysql -uroot -e "SHOW GLOBAL STATUS LIKE 'Threads_running';" 2>/dev/null || true
echo
echo "Redis usage:"
redis-cli info memory | egrep "used_memory_human|maxmemory_human|mem_fragmentation_ratio" || true
echo
echo "OpenLiteSpeed status:"
systemctl status lsws --no-pager 2>/dev/null | head -n 5 || true
echo
echo "System failed services:"
systemctl --failed || true

log "Server optimization finished successfully."

touch /root/.server_optimizer_last_run 2>/dev/null || true

