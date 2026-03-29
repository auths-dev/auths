# Redis AOF Backup & Point-in-Time Recovery

**Related**: fn-89.2 (AOF backup automation and point-in-time recovery)

This document covers automated AOF (Append-Only File) backup strategy, point-in-time recovery procedures, and monitoring for auths-api Redis.

---

## Overview

**Why AOF?**
- **Durability**: Survives crashes; captures every write operation
- **Granularity**: Point-in-time recovery to any moment in time
- **Compliance**: Immutable audit trail for audit events (fn-89.5)

**Configuration**:
```
appendonly yes                         # Enable AOF
appendfsync everysec                   # Fsync every 1 second (balance between durability + performance)
auto-aof-rewrite-percentage 100        # Rewrite when AOF grows 100% since last rewrite
auto-aof-rewrite-min-size 64mb         # Don't rewrite unless > 64MB
```

---

## Architecture

### Data Flow

```
┌────────────────┐
│   auths-api    │
│  (writes data) │
└────────┬───────┘
         │ Redis WRITE command
         v
    ┌─────────────────────────────┐
    │ Redis Master                │
    │ • appendonly.aof (disk)     │
    │ • AOF rewrite (compression) │
    │ • BGSAVE (snapshot)         │
    └─────┬───────────────────────┘
          │ Replication
          v
    ┌──────────────┐
    │ Replica 1    │
    │ + Replica 2  │
    └──────────────┘

    AOF grows over time:
    ┌─────────────────────────────────────────┐
    │ appendonly.aof (~1KB per agent + events)│
    │                                         │
    │ Daily growth: ~50-100MB (10k agents)    │
    │ Monthly size: ~1.5-3GB                  │
    └─────────────────────────────────────────┘

    ↓ Daily backup job (2am UTC)

    ┌──────────────────────────────────────┐
    │ S3 Backups (gzip compressed)        │
    │ • redis-aof-20260329_020000.aof.gz  │
    │ • Compression: ~100-200MB/day       │
    │ • Retention: 30 days (~6GB storage) │
    └──────────────────────────────────────┘
```

### Fsync Strategy Tradeoff

| Fsync Strategy | Durability | Performance | Data Loss Risk |
|---|---|---|---|
| `everysec` (default) | Good | Minimal overhead | Max 1s of data (acceptable) |
| `always` | Best | 10-15% slower | None (but 10x slower) |
| `no` | Worst | Best | May lose minutes of writes |

**Recommendation for auths-api**: `appendfsync everysec`
- Domain entities cached in Redis (agents, tokens) have TTL
- Token expiry is authoritative source, not AOF
- 1s durability window acceptable for agent state

---

## Backup Automation

### Daily Backup Script

**Location**: `crates/auths-deployment/scripts/backup-redis-aof.sh`

**Process**:
1. Verify Redis connectivity
2. Trigger AOF rewrite (`BGREWRITEAOF`) for compression
3. Copy compressed AOF file
4. Upload to S3 with gzip compression
5. Apply retention policy (delete backups >30 days old)
6. Log success/failure to CloudWatch

**Cron Job Setup**:
```bash
# In production EC2/Kubernetes:
0 2 * * * cd /app && AWS_REGION=us-east-1 ./backup-redis-aof.sh localhost 6379 >> /var/log/redis-backup.log 2>&1

# With error notification:
0 2 * * * cd /app && ./backup-redis-aof.sh localhost 6379 || alert-oncall "Redis backup failed"
```

**Example Run**:
```bash
$ AWS_REGION=us-east-1 ./backup-redis-aof.sh localhost 6379
[2026-03-29 02:00:00] [INFO] Verifying Redis connectivity (localhost:6379)...
[2026-03-29 02:00:00] [INFO] Redis reachable ✓
[2026-03-29 02:00:00] [INFO] Triggering AOF rewrite (compaction)...
[2026-03-29 02:00:00] [INFO] Waiting for AOF rewrite...
[2026-03-29 02:00:02] [INFO] AOF rewrite completed
[2026-03-29 02:00:03] [INFO] Copying AOF to temporary location...
[2026-03-29 02:00:05] [INFO] Compressing AOF...
[2026-03-29 02:00:08] [INFO] Compressed AOF size: 125MB
[2026-03-29 02:00:10] [INFO] Uploading to S3: s3://auths-redis-backups/backups/redis-aof-20260329_020000.aof.gz
[2026-03-29 02:00:15] [INFO] ✓ Backup uploaded to S3
[2026-03-29 02:00:16] [INFO] Applying retention policy (keeping 30 days)...
[2026-03-29 02:00:17] [INFO] ✓ Backup completed successfully
[2026-03-29 02:00:17] [INFO] Summary:
[2026-03-29 02:00:17] [INFO]   Timestamp: 20260329_020000
[2026-03-29 02:00:17] [INFO]   Size: 125MB
[2026-03-29 02:00:17] [INFO]   Location: s3://auths-redis-backups/backups/redis-aof-20260329_020000.aof.gz
[2026-03-29 02:00:17] [INFO]   Redis: localhost:6379
```

### S3 Bucket Setup

```bash
# Create S3 bucket with versioning + lifecycle
aws s3api create-bucket \
  --bucket auths-redis-backups \
  --region us-east-1

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket auths-redis-backups \
  --versioning-configuration Status=Enabled

# Lifecycle policy: delete old backups after 30 days
cat > lifecycle.json << 'EOF'
{
  "Rules": [
    {
      "Id": "DeleteOldBackups",
      "Status": "Enabled",
      "Prefix": "backups/",
      "Expiration": {
        "Days": 30
      },
      "NoncurrentVersionExpiration": {
        "NoncurrentDays": 7
      }
    }
  ]
}
EOF

aws s3api put-bucket-lifecycle-configuration \
  --bucket auths-redis-backups \
  --lifecycle-configuration file://lifecycle.json
```

### IAM Role

Needed for EC2/EKS to upload backups:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::auths-redis-backups",
        "arn:aws:s3:::auths-redis-backups/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "cloudwatch:PutMetricData"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Point-in-Time Recovery

### Manual Recovery Procedure

**Location**: `crates/auths-deployment/scripts/restore-redis-aof.sh`

**Scenarios**:

#### 1. Recover Latest Backup
```bash
# Restore most recent backup
./restore-redis-aof.sh latest localhost 6379

# OR specific date
./restore-redis-aof.sh latest localhost 6379 2026-03-28

# Output:
# [INFO] Finding latest backup...
# [INFO] Using: s3://auths-redis-backups/backups/redis-aof-20260329_020000.aof.gz
# [INFO] Downloading backup...
# [INFO] ✓ Backup downloaded
# [INFO] Decompressing...
# [INFO] Validating AOF integrity...
# [INFO] Backing up current AOF...
# [INFO] Stopping Redis...
# [INFO] ✓ Redis stopped
# [INFO] Replacing AOF file...
# [INFO] ✓ AOF replaced
# [INFO] Starting Redis...
# [INFO] ✓ Redis responding
# [INFO] Database size: 10247 keys
# [INFO] Memory usage: 512.5M
```

#### 2. Recover Specific Backup Date
```bash
# List backups from specific date
aws s3api list-objects-v2 \
  --bucket auths-redis-backups \
  --prefix "backups/redis-aof-2026-03-25" \
  --region us-east-1

# Restore specific backup
./restore-redis-aof.sh s3://auths-redis-backups/backups/redis-aof-20260325_020000.aof.gz
```

#### 3. Recover from Local File
```bash
./restore-redis-aof.sh /backups/redis-aof-20260325.aof.gz localhost 6379
```

### Recovery Time

| Scenario | RTO | Notes |
|---|---|---|
| Latest backup | < 5 minutes | Download + decompress + verify + start |
| 7-day-old backup | < 10 minutes | Larger S3 download |
| Full month recovery | < 15 minutes | Limited by decompression + Redis startup |

### Testing Recovery

**Monthly Recovery Drill** (1st of each month):
```bash
#!/bin/bash
# Monthly point-in-time recovery test

echo "Recovery Drill: $(date)"

# 1. Identify a backup from 7 days ago
RECOVERY_DATE=$(date -u -d "7 days ago" +%Y-%m-%d)
echo "Recovering backup from $RECOVERY_DATE..."

# 2. Start test Redis on alternate port
TEST_REDIS_PORT=6380
redis-server --port $TEST_REDIS_PORT &
sleep 2

# 3. Restore backup
./restore-redis-aof.sh latest localhost $TEST_REDIS_PORT $RECOVERY_DATE

# 4. Verify data
TEST_DBSIZE=$(redis-cli -p $TEST_REDIS_PORT dbsize | grep -oE '[0-9]+')
EXPECTED_AGENTS=$(redis-cli -p 6379 dbsize | grep -oE '[0-9]+')

echo "Keys in restored backup: $TEST_DBSIZE"
echo "Keys in current data: $EXPECTED_AGENTS"

if [[ $TEST_DBSIZE -gt 0 ]]; then
  echo "✓ Recovery test PASSED"
else
  echo "✗ Recovery test FAILED"
fi

# 5. Cleanup
redis-cli -p $TEST_REDIS_PORT shutdown
```

---

## Monitoring & Alerting

### CloudWatch Metrics

Backup script automatically publishes:

| Metric | Unit | Threshold | Action |
|---|---|---|---|
| `backup-size-mb` | MB | > 1000 | Alert (investigate disk usage) |
| `backup-success` | 0/1 | = 0 | Page oncall (backup failed) |
| `backup-duration-seconds` | Seconds | > 300 | Investigate (timeout) |
| `last-backup-age-hours` | Hours | > 25 | Alert (backup job missed) |

**CloudWatch Dashboard**:
```json
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["auths/redis", "backup-size-mb"],
          ["auths/redis", "backup-success"],
          ["auths/redis", "last-backup-age-hours"]
        ],
        "period": 300,
        "stat": "Average",
        "region": "us-east-1",
        "title": "Redis Backup Health"
      }
    }
  ]
}
```

### Alarms

```bash
# Backup failure alarm
aws cloudwatch put-metric-alarm \
  --alarm-name redis-backup-failed \
  --alarm-actions "arn:aws:sns:us-east-1:123456789:oncall" \
  --metric-name backup-success \
  --namespace auths/redis \
  --statistic Sum \
  --period 3600 \
  --threshold 0 \
  --comparison-operator LessThanThreshold

# Backup size alarm
aws cloudwatch put-metric-alarm \
  --alarm-name redis-backup-size-high \
  --alarm-actions "arn:aws:sns:us-east-1:123456789:alerts" \
  --metric-name backup-size-mb \
  --namespace auths/redis \
  --statistic Maximum \
  --period 300 \
  --threshold 1000 \
  --comparison-operator GreaterThanThreshold
```

---

## AOF Rewrite

AOF grows over time as commands accumulate. Redis automatically rewrites (compresses) periodically.

### Manual Rewrite

```bash
# Trigger background rewrite (safe, doesn't block)
redis-cli BGREWRITEAOF

# Monitor progress
redis-cli info persistence | grep aof_rewrite
# Output: aof_rewrite_in_progress:0 (complete)
```

### Automatic Rewrite

Configured in `sentinel.conf`:
```
auto-aof-rewrite-percentage 100  # Rewrite when AOF grows 100% since last rewrite
auto-aof-rewrite-min-size 64mb   # Don't rewrite unless > 64MB
```

**Example**:
- Last rewrite produced 50MB AOF
- AOF grows to 100MB (100% growth)
- Redis triggers automatic rewrite
- New AOF compressed to ~50MB again

---

## Retention Policy

**Default**: 30-day rolling window

**Rationale**:
- Covers 1 month of history (good for weekly recovery drills)
- Minimal S3 cost (~$6/month for 6GB)
- Weekly snapshots archived separately (fn-90 for long-term archive)

**Adjust if needed**:
```bash
# 60-day retention
BACKUP_RETENTION_DAYS=60 ./backup-redis-aof.sh

# S3 lifecycle policy update
aws s3api put-bucket-lifecycle-configuration \
  --bucket auths-redis-backups \
  --lifecycle-configuration '{"Rules": [{"Id": "DeleteAfter60Days", "Expiration": {"Days": 60}, "Status": "Enabled"}]}'
```

---

## Troubleshooting

### AOF File Corruption

**Symptom**: `Bad file format` when Redis starts

**Recovery**:
```bash
# AOF check tool (Redis 7.0+)
redis-check-aof --fix /var/lib/redis/appendonly.aof

# Or manual recovery
./restore-redis-aof.sh latest  # Restore from backup
```

### Backup Upload Timeout

**Symptom**: Backup script fails at S3 upload

**Solutions**:
```bash
# Increase timeout in script (line 60)
aws s3 cp ... --region ... --no-progress

# Or use S3 multipart upload with retries
aws s3 cp ... --region ... --sse AES256
```

### Replication Lag After Recovery

**Symptom**: Replicas out of sync after restore

**Recovery**:
```bash
# Force replica resync
redis-cli -h replica slaveof no one  # Stop replicating
redis-cli -h replica slaveof master 6379  # Resume from scratch

# Monitor sync
redis-cli -h replica info replication | grep sync
```

---

## References

- [Redis Persistence](https://redis.io/topics/persistence)
- [Redis AOF Format](https://redis.io/topics/protocol)
- Related: fn-89.0 (Domain Architecture), fn-89.1 (Sentinel HA), fn-89.3 (Circuit Breaker)
