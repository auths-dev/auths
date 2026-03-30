# Production Redis HA Setup Guide

**Related**: fn-89.1 (Redis Sentinel + failover configuration and docs)

Redis high availability is **critical** for auths-api. This document covers four deployment patterns with increasing operational overhead vs. cost.

---

## Quick Comparison

| Platform | Failover | Backups | Cost | Operational Load |
|----------|----------|---------|------|------------------|
| **Managed (Upstash/ElastiCache/Memorystore)** | Automatic | Automatic | $$$ | Minimal |
| **Self-Hosted EC2 + Sentinel** | Automatic | Manual (fn-89.2) | $ | Medium |
| **Self-Hosted Docker + Sentinel** | Automatic | Manual | $ | Low (testing) |
| **Single Master (NOT recommended for production)** | None | Manual | $ | None (risky) |

**Recommendation**: Start with managed (Upstash or AWS ElastiCache) for production. Self-host Sentinel only if you need cost control + accept operational complexity.

---

## Architecture Overview

### Managed Services (Upstash, ElastiCache, Memorystore)

```
┌─────────────────────────────────┐
│      auths-api (replicas)       │
│  (multiple availability zones)  │
└────────────┬────────────────────┘
             │ Connect to service endpoint
             │ (auto-discovers master)
             v
    ┌────────────────────┐
    │ Managed Redis HA   │
    │ (Master + Replicas)│
    │ - Auto-failover    │
    │ - Auto-backups     │
    │ - Monitoring       │
    └────────────────────┘
```

### Self-Hosted (EC2/Kubernetes + Sentinel)

```
┌──────────────────────────────────────────────────┐
│       auths-api (multiple pods/instances)        │
│  (Kubernetes or EC2 Auto Scaling Group)          │
└────────────┬─────────────────────────────────────┘
             │ Connect to Sentinel (quorum)
             │
     ┌───────┴────────────┐
     │                    │
     v                    v
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Sentinel 1 │     │  Sentinel 2 │     │  Sentinel 3 │
│  (port 26379)      │  (port 26379)      │  (port 26379)
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │ monitors         │ monitors         │ monitors
       │                  │                  │
       └──────────────────┼──────────────────┘
                          │ quorum (2 of 3)
             ┌────────────┴────────────┐
             │                         │
             v                         v
        ┌─────────────┐           ┌──────────────┐
        │ Redis       │ replicates│  Redis       │
        │ Master      │to         │  Replica 1   │
        └─────────────┘           └──────────────┘
             │ replicates to
             v
        ┌──────────────┐
        │  Redis       │
        │  Replica 2   │
        └──────────────┘
```

---

## Platform 1: AWS ElastiCache (Recommended for AWS)

### Setup

1. **Create Redis Cluster with Multi-AZ Failover**:
   ```bash
   aws elasticache create-replication-group \
     --replication-group-description "auths-api-cache" \
     --engine redis \
     --engine-version 7.0 \
     --cache-node-type cache.r6g.xlarge \
     --num-cache-clusters 3 \
     --automatic-failover-enabled \
     --multi-az-enabled \
     --at-rest-encryption-enabled \
     --transit-encryption-enabled \
     --auth-token "your-secure-token-here"
   ```

2. **Retrieve Endpoint**:
   ```bash
   aws elasticache describe-replication-groups \
     --replication-group-id auths-api-cache \
     --query 'ReplicationGroups[0].ConfigurationEndpoint'
   ```
   Returns: `auths-api-cache.abc123.ng.0001.use1.cache.amazonaws.com:6379`

3. **Security Group**: Allow inbound on port 6379 from auths-api security group.

### Configuration

In auths-api config (e.g., `config/redis.toml`):
```toml
[redis]
endpoint = "redis://<auth-token>@auths-api-cache.abc123.ng.0001.use1.cache.amazonaws.com:6379"
# ElastiCache handles replication + failover automatically
# Connection string directly points to cluster endpoint
```

### Failover Behavior

- **Detection Time**: ~15-30s (AWS-managed)
- **RTO** (Recovery Time Objective): < 1 minute
- **Automatic**: No manual intervention needed
- **Transparency**: Connection string remains valid during failover

### Backups

```bash
# Automatic snapshots (can configure retention)
aws elasticache create-snapshot \
  --replication-group-id auths-api-cache \
  --snapshot-name auths-api-backup-$(date +%Y%m%d)

# Point-in-time recovery via automated snapshots
# (See fn-89.2 for AOF backup strategy)
```

### Cost

- `cache.r6g.xlarge` (8GB): ~$0.35/hour (~$250/month) × 3 nodes = **~$750/month**
- Multi-AZ: +10% cost
- Data transfer: varies (typically $0.01/GB out)
- **Total**: ~$800-1000/month for typical workload

---

## Platform 2: Upstash (Recommended for Cost-Conscious / Serverless)

### Setup

1. **Create Redis Database**:
   - Go to https://console.upstash.com/redis
   - Click "Create Database"
   - Region: Select closest to app (US-East, EU-West, etc.)
   - Eviction Policy: `allkeys-lru` (for cache, safe to evict)
   - Enable "Max Retries" for client resilience

2. **Copy Connection String**:
   ```
   redis://default:your-auth-token@your-region-xxxxx.upstash.io:xxxxx
   ```

### Configuration

In auths-api config:
```toml
[redis]
endpoint = "redis://default:your-auth-token@your-region-xxxxx.upstash.io:xxxxx"
# Upstash provides automatic failover via managed infrastructure
```

### Failover Behavior

- **Detection Time**: ~5-10s (Upstash-managed)
- **RTO**: < 30s
- **Automatic**: Fully managed, no intervention
- **Transparency**: Connection string remains valid

### Backups

Upstash provides:
- Automatic 24-hour retention snapshots
- Point-in-time recovery (with premium tier)
- Daily backups (backup tier)

```bash
# No manual backups needed; configure via Upstash console
# Premium: Enable backup for point-in-time recovery
```

### Cost

- **Free Tier**: 10,000 commands/day, 256MB, single replica
- **Starter**: $9/month (1GB, Infra Multi-Master Replication)
- **Pro**: $199/month (16GB)
- **Enterprise**: Contact sales
- **Recommended for auths-api**: Pro or Enterprise

---

## Platform 3: GCP Memorystore (Recommended for Google Cloud)

### Setup

1. **Create Redis Instance**:
   ```bash
   gcloud redis instances create auths-api-cache \
     --size=4 \
     --region=us-central1 \
     --tier=standard \
     --redis-version=7.0 \
     --enable-auth \
     --region-zone=us-central1-a
   ```

2. **Retrieve Connection Info**:
   ```bash
   gcloud redis instances describe auths-api-cache \
     --region=us-central1
   ```
   Returns: `host` (IP only, no DNS) and `port`

3. **Network**: Redis is private to VPC; auths-api must be in same VPC.

### Configuration

In auths-api config:
```toml
[redis]
endpoint = "redis://default:your-auth-password@10.0.0.3:6379"
# Note: Memorystore uses IP addresses, not DNS names
```

### Failover Behavior

- **Detection Time**: ~30s (automatic)
- **RTO**: < 1 minute
- **Automatic**: Standard tier provides automatic failover
- **Transparency**: Connection via private IP

### Backups

```bash
# Manual snapshots
gcloud redis instances snapshot create \
  --instance=auths-api-cache \
  --region=us-central1

# Scheduled backups (backup tier)
# Set retention in GCP console
```

### Cost

- **Standard (no HA)**: $0.11/GB/month × 4GB = ~$44/month
- **HA (multi-region)**: +100% cost = ~$88/month
- **Data transfer**: Free within GCP, $0.12/GB out to internet
- **Recommended for auths-api**: HA tier (~$88/month)

---

## Platform 4: Self-Hosted (EC2 + Sentinel)

Use this **only** if:
- You must minimize cloud costs
- You have ops expertise for Redis + Sentinel management
- Your organization already manages self-hosted Redis

### Prerequisites

- 3 EC2 instances (t3.large) in different availability zones
  - One for Redis Master
  - Two for Redis Replicas
  - Plus 3 Sentinel instances (can co-locate on replicas)
- Redis 7.0+ installed
- Sentinel config from `crates/auths-deployment/config/sentinel.conf`

### Setup

1. **Install Redis on all 3 instances**:
   ```bash
   # On all instances:
   sudo yum install redis -y
   sudo systemctl enable redis
   sudo systemctl start redis
   ```

2. **Configure Master** (first instance):
   - Edit `/etc/redis.conf`:
     ```
     port 6379
     bind 0.0.0.0
     appendonly yes
     requirepass your-redis-password
     ```

3. **Configure Replicas** (second and third instances):
   ```
   port 6379
   bind 0.0.0.0
   replicaof <master-ip> 6379
   requirepass your-redis-password
   masterauth your-redis-password
   appendonly yes
   ```

4. **Deploy Sentinel** (all 3 instances):
   ```bash
   # Copy sentinel.conf from crates/auths-deployment/config/sentinel.conf
   sudo cp sentinel.conf /etc/redis-sentinel.conf
   sudo chown redis:redis /etc/redis-sentinel.conf

   # Edit /etc/redis-sentinel.conf:
   # - Change bind to specific IP or 0.0.0.0
   # - Set down_after_milliseconds 30000 (30s)
   # - Set parallel_syncs 1

   sudo redis-sentinel /etc/redis-sentinel.conf
   ```

5. **Test Failover**:
   ```bash
   # Run test script (see fn-89.1)
   ./crates/auths-deployment/scripts/test-sentinel-failover.sh
   ```

### Configuration

In auths-api config:
```toml
[redis]
# Sentinel discovery (client resolves master dynamically)
endpoint = "redis-sentinel://user:password@sentinel1:26379,sentinel2:26379,sentinel3:26379?service_name=mymaster"
```

### Failover Behavior

- **Detection Time**: ~30s (configurable)
- **RTO**: ~1 minute
- **Manual Intervention**: Monitor Sentinel; no auto-healing for failed machines
- **Operational Overhead**: 2-4 hours/month (monitoring, updates, troubleshooting)

### Backups

Manual via `redis-cli` or AOF (see fn-89.2):
```bash
# Manual snapshot
redis-cli BGSAVE

# AOF (automatic incremental backups)
# Enable in redis.conf: appendonly yes
# See fn-89.2 for point-in-time recovery
```

### Cost

- **EC2 (3 × t3.large)**: $0.10/hour × 3 = **$215/month**
- **Elastic IPs (3)**: ~$1/month
- **EBS storage (3 × 100GB)**: ~$15/month
- **Ops burden**: 2-4 hours/month
- **Total**: ~$230/month + ops time

---

## Connection Resilience

### Client-Side Retry Logic

All auths-api clients must implement exponential backoff on Redis connection failures:

```rust
// Pseudocode for auths-api client
const MAX_RETRIES: usize = 3;
const INITIAL_BACKOFF: Duration = Duration::from_millis(100);

async fn connect_with_retry() -> Result<RedisClient> {
    for attempt in 0..MAX_RETRIES {
        match redis_client.connect().await {
            Ok(client) => return Ok(client),
            Err(e) => {
                let backoff = INITIAL_BACKOFF * 2u32.pow(attempt as u32);
                log::warn!("Redis connect failed (attempt {}): {}, retry in {:?}",
                    attempt, e, backoff);
                sleep(backoff).await;
            }
        }
    }
    Err(anyhow::anyhow!("Failed to connect after {} attempts", MAX_RETRIES))
}
```

### Domain Entity Resilience (fn-89.0)

Redis caches these auths-api entities:
- `agents:{namespace}:{agent_id}` (agent state, TTL = agent.expires_at)
- `tokens:{token_hash}` (token metadata, TTL = token.expires_at)
- `device_keys:*` (device keys, TTL = agent expiry)

**On Redis unavailability** (fn-89.3 circuit breaker):
- **Authorization queries** (token validation): Return 503 Service Unavailable
- **Cache miss on agent lookup**: 503 (can't validate without cache)
- **Reads from replicas**: Fail over to secondary cache if available

---

## Monitoring & Alerting

### Key Metrics (fn-89.12)

For any platform, monitor:
- **Replication lag**: < 1 second (normal), > 5s (alert)
- **Master failover count**: Should be 0-1/month (normal), > 3/month (investigate)
- **Connection pool health**: % connections alive (target: > 95%)
- **Cache hit ratio**: Should be > 90% for auths agents/tokens
- **Memory usage**: < 80% of allocated (auto-eviction at 100%)

### Alerting

Example Prometheus rules (fn-89.12):
```yaml
- alert: RedisMasterDown
  expr: redis_up{role="master"} == 0
  for: 30s
  action: page oncall

- alert: RedisReplicationLag
  expr: redis_replication_lag_bytes > 5242880  # 5MB
  for: 2m
  action: alert (not page)

- alert: RedisMemoryHigh
  expr: redis_memory_usage_percent > 80
  for: 5m
  action: alert (check if cache needs size increase)
```

---

## Disaster Recovery

### Recovery Time Objectives (RTO)

| Failure Scenario | Managed | Self-Hosted |
|---|---|---|
| Master crashes | 1-2 minutes | 30 seconds (Sentinel) + manual failover |
| Entire region down | 5-10 minutes | Data loss (replicate to backup region) |
| Corrupted data | 24 hours (backup restore) | 24+ hours (manual restore from AOF) |

### Backup Strategy (fn-89.2)

- **Managed services**: Automatic daily snapshots (retention: 30 days)
- **Self-hosted**: AOF (append-only file) + daily snapshots to S3/GCS
- **Testing**: Monthly restore from backup to validation environment

---

## Decision Tree: Which Platform?

```
┌─ AWS User?
│  └─→ Use AWS ElastiCache
│      (most integrated, auto-failover, managed backups)
│
├─ Google Cloud User?
│  └─→ Use GCP Memorystore (Standard + HA)
│      (best for Kubernetes on GKE)
│
├─ Serverless / Multi-cloud?
│  └─→ Use Upstash
│      (cheapest managed option, no infra)
│
└─ On-premises / Self-hosted required?
   └─→ Use EC2 + Sentinel
       (cheapest, highest ops burden)
```

---

## Testing & Validation

### Local Testing (Docker Compose)

```bash
# Start Sentinel cluster
./crates/auths-deployment/scripts/start-sentinel.sh local

# Run failover tests
./crates/auths-deployment/scripts/test-sentinel-failover.sh

# Verify client retries on master kill
# (see test output)
```

### Production Validation (Chaos Engineering)

For self-hosted:
1. Kill master in off-hours
2. Verify failover time < 30s
3. Verify client reconnects without request loss
4. Verify new master has all data
5. Document incident in runbook

---

## References

- [AWS ElastiCache User Guide](https://docs.aws.amazon.com/elasticache/)
- [Upstash Documentation](https://upstash.com/docs)
- [GCP Memorystore User Guide](https://cloud.google.com/memorystore/docs)
- [Redis Sentinel Documentation](https://redis.io/docs/management/sentinel/)
- Related: fn-89.0 (Domain Architecture), fn-89.2 (AOF Backups), fn-89.12 (Monitoring)
