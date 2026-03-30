#!/bin/bash
# Start Redis Sentinel instances for auths-api HA
# Usage: ./start-sentinel.sh [mode: local|cloud]
#
# Local mode: starts 3 Sentinels + master + 2 replicas via docker-compose (testing)
# Cloud mode: generates configs for managed deployment

set -e

MODE=${1:-local}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/../config"

# === Local Mode: Docker Compose Test Setup ===
if [[ "$MODE" == "local" ]]; then
  echo "Starting local Sentinel cluster (docker-compose)..."

  # Create docker-compose.yml for 3 Sentinels + master + 2 replicas
  cat > "${SCRIPT_DIR}/docker-compose-sentinel.yml" << 'EOF'
version: '3.8'
services:
  redis-master:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes --dir /data
    volumes:
      - redis-master-data:/data
    networks:
      - sentinel-net
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 3

  redis-replica-1:
    image: redis:7-alpine
    ports:
      - "6380:6379"
    command: redis-server --port 6379 --replicaof redis-master 6379 --appendonly yes --dir /data
    volumes:
      - redis-replica-1-data:/data
    depends_on:
      redis-master:
        condition: service_healthy
    networks:
      - sentinel-net
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 3

  redis-replica-2:
    image: redis:7-alpine
    ports:
      - "6381:6379"
    command: redis-server --port 6379 --replicaof redis-master 6379 --appendonly yes --dir /data
    volumes:
      - redis-replica-2-data:/data
    depends_on:
      redis-master:
        condition: service_healthy
    networks:
      - sentinel-net
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 3

  sentinel-1:
    image: redis:7-alpine
    ports:
      - "26379:26379"
    command: redis-sentinel /etc/sentinel/sentinel.conf --port 26379
    volumes:
      - ./config/sentinel.conf:/etc/sentinel/sentinel.conf:ro
      - sentinel-1-data:/data
    depends_on:
      - redis-master
      - redis-replica-1
      - redis-replica-2
    networks:
      - sentinel-net
    healthcheck:
      test: ["CMD", "redis-cli", "-p", "26379", "ping"]
      interval: 5s
      timeout: 3s
      retries: 3

  sentinel-2:
    image: redis:7-alpine
    ports:
      - "26380:26379"
    command: redis-sentinel /etc/sentinel/sentinel.conf --port 26379
    volumes:
      - ./config/sentinel.conf:/etc/sentinel/sentinel.conf:ro
      - sentinel-2-data:/data
    depends_on:
      - redis-master
      - redis-replica-1
      - redis-replica-2
    networks:
      - sentinel-net
    healthcheck:
      test: ["CMD", "redis-cli", "-p", "26379", "ping"]
      interval: 5s
      timeout: 3s
      retries: 3

  sentinel-3:
    image: redis:7-alpine
    ports:
      - "26381:26379"
    command: redis-sentinel /etc/sentinel/sentinel.conf --port 26379
    volumes:
      - ./config/sentinel.conf:/etc/sentinel/sentinel.conf:ro
      - sentinel-3-data:/data
    depends_on:
      - redis-master
      - redis-replica-1
      - redis-replica-2
    networks:
      - sentinel-net
    healthcheck:
      test: ["CMD", "redis-cli", "-p", "26379", "ping"]
      interval: 5s
      timeout: 3s
      retries: 3

volumes:
  redis-master-data:
  redis-replica-1-data:
  redis-replica-2-data:
  sentinel-1-data:
  sentinel-2-data:
  sentinel-3-data:

networks:
  sentinel-net:
    driver: bridge
EOF

  cd "${SCRIPT_DIR}"

  # Start services
  docker-compose -f docker-compose-sentinel.yml up -d

  # Wait for cluster to stabilize
  echo "Waiting for cluster to stabilize (10s)..."
  sleep 10

  echo "✓ Sentinel cluster started"
  echo ""
  echo "Cluster Status:"
  docker exec "$(docker-compose -f docker-compose-sentinel.yml ps -q sentinel-1)" \
    redis-cli -p 26379 sentinel masters | grep -E "name|role|status"

  echo ""
  echo "Connection String: redis-sentinel://localhost:26379,localhost:26380,localhost:26381?service_name=mymaster"
  echo "Test with: redis-cli -h localhost -p 26379 sentinel masters"

# === Cloud Mode: Generate configs for managed deployments ===
elif [[ "$MODE" == "cloud" ]]; then
  echo "Generating configs for cloud deployment..."
  echo "See docs/PRODUCTION_REDIS_HA.md for platform-specific setup:"
  echo "  - Self-hosted EC2 (deploy sentinel cluster separately)"
  echo "  - AWS ElastiCache (managed failover, skip Sentinel)"
  echo "  - Upstash (managed failover, skip Sentinel)"
  echo "  - GCP Memorystore (managed failover, skip Sentinel)"

else
  echo "Usage: $0 [local|cloud]"
  exit 1
fi
