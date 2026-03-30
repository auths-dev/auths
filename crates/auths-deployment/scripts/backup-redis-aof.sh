#!/bin/bash
# Automated Redis AOF backup to S3
# Usage: AWS_REGION=us-east-1 ./backup-redis-aof.sh [redis-host] [redis-port]
#
# Cron job (2am UTC daily):
#   0 2 * * * cd /app && AWS_REGION=us-east-1 ./backup-redis-aof.sh localhost 6379 >> /var/log/redis-backup.log 2>&1

set -e

# Configuration
REDIS_HOST=${1:-localhost}
REDIS_PORT=${2:-6379}
AWS_REGION=${AWS_REGION:-us-east-1}
S3_BUCKET="${S3_BUCKET:-auths-redis-backups}"
BACKUP_RETENTION_DAYS=30
MAX_BACKUP_SIZE_MB=1000  # Alert if > 1GB

# Derived variables
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="redis-aof-${TIMESTAMP}.aof.gz"
LOCAL_AOF_PATH="/tmp/redis-aof-${TIMESTAMP}.aof"
COMPRESSED_AOF_PATH="${LOCAL_AOF_PATH}.gz"
S3_KEY="backups/${BACKUP_NAME}"
S3_URI="s3://${S3_BUCKET}/${S3_KEY}"
LOG_PREFIX="[$(date '+%Y-%m-%d %H:%M:%S')]"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}${LOG_PREFIX}${NC} $*"; }
log_warn() { echo -e "${YELLOW}${LOG_PREFIX}${NC} $*"; }
log_error() { echo -e "${RED}${LOG_PREFIX}${NC} $*"; exit 1; }

# === Step 1: Verify Redis connectivity ===
log_info "Verifying Redis connectivity ($REDIS_HOST:$REDIS_PORT)..."
if ! redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping >/dev/null 2>&1; then
  log_error "Redis not reachable at $REDIS_HOST:$REDIS_PORT"
fi
log_info "Redis reachable ✓"

# === Step 2: Trigger AOF rewrite ===
log_info "Triggering AOF rewrite (compaction)..."
if ! redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" BGREWRITEAOF >/dev/null 2>&1; then
  log_warn "AOF rewrite failed (may already be in progress)"
fi

# Wait for rewrite to complete (max 30s)
sleep 2
log_info "Waiting for AOF rewrite..."
for i in {1..15}; do
  if redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" info persistence | grep -q "aof_rewrite_in_progress:0"; then
    log_info "AOF rewrite completed"
    break
  fi
  sleep 2
done

# === Step 3: Get AOF file location ===
log_info "Locating AOF file..."
REDIS_AOF_PATH=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" config get appendfilename | tail -1)
REDIS_DIR=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" config get dir | tail -1)
FULL_AOF_PATH="${REDIS_DIR}/${REDIS_AOF_PATH}"

log_info "AOF file: $FULL_AOF_PATH"
if [[ ! -f "$FULL_AOF_PATH" ]]; then
  log_error "AOF file not found at $FULL_AOF_PATH"
fi

# === Step 4: Copy and compress AOF ===
log_info "Copying AOF to temporary location..."
cp "$FULL_AOF_PATH" "$LOCAL_AOF_PATH"

log_info "Compressing AOF..."
gzip -f "$LOCAL_AOF_PATH"

# Check backup size
BACKUP_SIZE_MB=$(($(stat -f%z "$COMPRESSED_AOF_PATH" 2>/dev/null || stat -c%s "$COMPRESSED_AOF_PATH") / 1024 / 1024))
log_info "Compressed AOF size: ${BACKUP_SIZE_MB}MB"

if [[ $BACKUP_SIZE_MB -gt $MAX_BACKUP_SIZE_MB ]]; then
  log_warn "ALERT: Backup size (${BACKUP_SIZE_MB}MB) exceeds threshold (${MAX_BACKUP_SIZE_MB}MB)"
fi

# === Step 5: Upload to S3 ===
log_info "Uploading to S3: $S3_URI"
if ! aws s3 cp "$COMPRESSED_AOF_PATH" "$S3_URI" \
    --region "$AWS_REGION" \
    --storage-class STANDARD_IA \
    --metadata "timestamp=${TIMESTAMP},redis-host=${REDIS_HOST},backup-size=${BACKUP_SIZE_MB}MB" \
    2>&1; then
  log_error "S3 upload failed for $S3_URI"
fi
log_info "✓ Backup uploaded to S3"

# === Step 6: Cleanup old local backups ===
log_info "Cleaning up temporary files..."
rm -f "$COMPRESSED_AOF_PATH"

# === Step 7: Cleanup old S3 backups (retention policy) ===
log_info "Applying retention policy (keeping ${BACKUP_RETENTION_DAYS} days)..."
CUTOFF_DATE=$(date -u -d "${BACKUP_RETENTION_DAYS} days ago" +%Y-%m-%d 2>/dev/null || date -u -v-${BACKUP_RETENTION_DAYS}d +%Y-%m-%d)

# List and delete old backups
OLD_BACKUPS=$(aws s3api list-objects-v2 \
  --bucket "$S3_BUCKET" \
  --prefix "backups/" \
  --region "$AWS_REGION" \
  --query "Contents[?LastModified<'${CUTOFF_DATE}T00:00:00Z'].Key" \
  --output text 2>/dev/null || echo "")

if [[ -n "$OLD_BACKUPS" ]]; then
  log_info "Deleting old backups..."
  for key in $OLD_BACKUPS; do
    log_info "  Deleting: $key"
    aws s3 rm "s3://${S3_BUCKET}/${key}" --region "$AWS_REGION" 2>/dev/null || true
  done
fi

# === Step 8: Log success ===
log_info "✓ Backup completed successfully"
log_info "Summary:"
log_info "  Timestamp: $TIMESTAMP"
log_info "  Size: ${BACKUP_SIZE_MB}MB"
log_info "  Location: $S3_URI"
log_info "  Redis: $REDIS_HOST:$REDIS_PORT"

# === Step 9: CloudWatch metric (optional) ===
if command -v aws >/dev/null 2>&1; then
  log_info "Publishing CloudWatch metrics..."
  aws cloudwatch put-metric-data \
    --namespace "auths/redis" \
    --metric-name "backup-size-mb" \
    --value "$BACKUP_SIZE_MB" \
    --region "$AWS_REGION" \
    2>/dev/null || log_warn "Failed to publish metrics"

  aws cloudwatch put-metric-data \
    --namespace "auths/redis" \
    --metric-name "backup-success" \
    --value 1 \
    --region "$AWS_REGION" \
    2>/dev/null || true
fi

exit 0
