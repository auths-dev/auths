#!/bin/bash
# Restore Redis from AOF backup (point-in-time recovery)
# Usage: ./restore-redis-aof.sh <backup-source> [redis-host] [redis-port] [backup-date]
#
# Examples:
#   ./restore-redis-aof.sh s3://my-bucket/redis-aof-20260329_020000.aof.gz
#   ./restore-redis-aof.sh /local/redis-aof-20260329_020000.aof.gz localhost 6379
#   ./restore-redis-aof.sh latest localhost 6379 2026-03-28  # Restore backup from specific date

set -e

# Configuration
BACKUP_SOURCE=$1
REDIS_HOST=${2:-localhost}
REDIS_PORT=${3:-6379}
BACKUP_DATE=${4:-}
S3_BUCKET="${S3_BUCKET:-auths-redis-backups}"
AWS_REGION=${AWS_REGION:-us-east-1}
WORK_DIR="/tmp/redis-restore-$(date +%s)"
REDIS_DIR=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" config get dir 2>/dev/null | tail -1 || echo "/var/lib/redis")
REDIS_AOF_NAME=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" config get appendfilename 2>/dev/null | tail -1 || echo "appendonly.aof")

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# === Validation ===
if [[ -z "$BACKUP_SOURCE" ]]; then
  log_error "Usage: $0 <backup-source> [redis-host] [redis-port] [backup-date]"
fi

if ! command -v redis-cli >/dev/null; then
  log_error "redis-cli not found. Install redis-tools."
fi

# === Step 1: Find backup file ===
log_info "Locating backup file..."

BACKUP_FILE=""
if [[ "$BACKUP_SOURCE" == "latest" ]]; then
  # Find latest backup from optional date
  if [[ -n "$BACKUP_DATE" ]]; then
    log_info "Finding latest backup from $BACKUP_DATE..."
    BACKUP_FILE=$(aws s3api list-objects-v2 \
      --bucket "$S3_BUCKET" \
      --prefix "backups/redis-aof-${BACKUP_DATE}" \
      --region "$AWS_REGION" \
      --query 'Contents | sort_by(@, &LastModified) | [-1].Key' \
      --output text 2>/dev/null || echo "")
  else
    log_info "Finding latest backup..."
    BACKUP_FILE=$(aws s3api list-objects-v2 \
      --bucket "$S3_BUCKET" \
      --prefix "backups/" \
      --region "$AWS_REGION" \
      --query 'Contents | sort_by(@, &LastModified) | [-1].Key' \
      --output text 2>/dev/null || echo "")
  fi

  if [[ -z "$BACKUP_FILE" || "$BACKUP_FILE" == "None" ]]; then
    log_error "No backup found in S3"
  fi
  BACKUP_SOURCE="s3://${S3_BUCKET}/${BACKUP_FILE}"
  log_info "Using: $BACKUP_SOURCE"
elif [[ "$BACKUP_SOURCE" =~ ^s3:// ]]; then
  log_info "Using S3 backup: $BACKUP_SOURCE"
elif [[ -f "$BACKUP_SOURCE" ]]; then
  log_info "Using local backup: $BACKUP_SOURCE"
else
  log_error "Backup not found: $BACKUP_SOURCE"
fi

# === Step 2: Download backup ===
mkdir -p "$WORK_DIR"
log_info "Downloading backup..."

LOCAL_BACKUP="${WORK_DIR}/backup.aof.gz"
if [[ "$BACKUP_SOURCE" =~ ^s3:// ]]; then
  if ! aws s3 cp "$BACKUP_SOURCE" "$LOCAL_BACKUP" --region "$AWS_REGION"; then
    log_error "Failed to download $BACKUP_SOURCE"
  fi
else
  cp "$BACKUP_SOURCE" "$LOCAL_BACKUP"
fi

log_info "✓ Backup downloaded"

# === Step 3: Decompress ===
log_info "Decompressing..."
if ! gunzip -f "$LOCAL_BACKUP"; then
  log_error "Failed to decompress backup"
fi

LOCAL_AOF="${LOCAL_BACKUP%.gz}"
log_info "✓ Decompressed to $LOCAL_AOF"

# === Step 4: Validate AOF ===
log_info "Validating AOF integrity..."

# Redis can validate by trying to load it
if ! timeout 30 redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" --pipe < "$LOCAL_AOF" >/dev/null 2>&1; then
  # Check for obvious corruption markers
  if head -c 10 "$LOCAL_AOF" | grep -q "REDIS"; then
    log_info "AOF header present (RDB format, may be snapshot)"
  fi
fi

# Count entries (rough validation)
ENTRY_COUNT=$(grep -c "^\*" "$LOCAL_AOF" || echo "unknown")
log_info "AOF entries: ~$ENTRY_COUNT"

if [[ $ENTRY_COUNT -eq 0 ]]; then
  log_warn "Warning: AOF appears empty or corrupted"
fi

# === Step 5: Backup current AOF ===
log_info "Backing up current AOF..."
if [[ -f "${REDIS_DIR}/${REDIS_AOF_NAME}" ]]; then
  CURRENT_BACKUP="${WORK_DIR}/appendonly.aof.backup"
  cp "${REDIS_DIR}/${REDIS_AOF_NAME}" "$CURRENT_BACKUP"
  log_info "✓ Current AOF backed up to $CURRENT_BACKUP"
fi

# === Step 6: Stop Redis ===
log_info "Stopping Redis ($REDIS_HOST:$REDIS_PORT)..."
if ! redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" shutdown >/dev/null 2>&1; then
  log_warn "Redis already stopped"
fi

sleep 2
if redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping >/dev/null 2>&1; then
  log_error "Failed to stop Redis"
fi
log_info "✓ Redis stopped"

# === Step 7: Replace AOF ===
log_info "Replacing AOF file..."
if [[ ! -d "$REDIS_DIR" ]]; then
  log_error "Redis directory not found: $REDIS_DIR"
fi

cp "$LOCAL_AOF" "${REDIS_DIR}/${REDIS_AOF_NAME}"
log_info "✓ AOF replaced"

# === Step 8: Start Redis ===
log_info "Starting Redis..."
# This is environment-specific; assuming systemd
if command -v systemctl >/dev/null; then
  if ! systemctl start redis-server 2>/dev/null; then
    log_warn "Could not start Redis via systemctl (may be docker-compose or manual)"
  fi
else
  log_warn "systemctl not found. Manually start Redis and verify."
fi

sleep 3

# === Step 9: Verify recovery ===
log_info "Verifying recovery..."
if ! redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping >/dev/null 2>&1; then
  log_error "Redis not responding after restore. Check logs."
fi
log_info "✓ Redis responding"

# Get stats
DBSIZE=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" dbsize | grep -oE '[0-9]+' || echo "0")
MEMORY=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" info memory | grep used_memory_human | cut -d: -f2 || echo "unknown")

log_info "Database size: $DBSIZE keys"
log_info "Memory usage: $MEMORY"

# === Step 10: Cleanup ===
log_info "Cleaning up temporary files..."
rm -rf "$WORK_DIR"

log_info "✓ Recovery completed successfully"
log_info ""
log_info "Summary:"
log_info "  Backup source: $BACKUP_SOURCE"
log_info "  Redis: $REDIS_HOST:$REDIS_PORT"
log_info "  Keys restored: $DBSIZE"
log_info "  Memory: $MEMORY"
log_info ""
log_info "Next steps:"
log_info "  1. Verify data integrity in application"
log_info "  2. Check for replication lag if using replicas"
log_info "  3. Resume monitoring/alerting"

exit 0
