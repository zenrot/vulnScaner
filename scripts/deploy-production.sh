#!/usr/bin/env bash
# Server-side deployment script.
# Called by .github/workflows/deploy.yml after the archive is extracted.
# Working directory must be the project root.
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
SAST_API_PORT="${SAST_API_PORT:-10000}"
SAST_UI_PORT="${SAST_UI_PORT:-10001}"
HEALTH_URL="${HEALTH_URL:-http://localhost:${SAST_API_PORT}/healthz}"
HEALTH_RETRIES="${HEALTH_RETRIES:-24}"
HEALTH_INTERVAL="${HEALTH_INTERVAL:-5}"

echo "=== Pulling latest images ==="
docker compose -f "$COMPOSE_FILE" pull --ignore-pull-failures 2>/dev/null || true

echo "=== Preparing Ollama model (${SAST_OLLAMA_MODEL:-qwen2.5:7b-instruct}) ==="
docker compose -f "$COMPOSE_FILE" up -d ollama
docker compose -f "$COMPOSE_FILE" rm -sf ollama-init >/dev/null 2>&1 || true
docker compose -f "$COMPOSE_FILE" run --rm ollama-init

echo "=== Restarting services ==="
docker compose -f "$COMPOSE_FILE" up -d --build --remove-orphans

echo "=== Waiting for health check (up to $((HEALTH_RETRIES * HEALTH_INTERVAL))s) ==="
for i in $(seq 1 "$HEALTH_RETRIES"); do
  if curl -sf "$HEALTH_URL" > /dev/null 2>&1; then
    echo "✅ Healthy after $((i * HEALTH_INTERVAL))s"
    docker compose -f "$COMPOSE_FILE" ps
    exit 0
  fi
  echo "  [$i/$HEALTH_RETRIES] not ready yet…"
  sleep "$HEALTH_INTERVAL"
done

echo "❌ Service did not become healthy in time"
docker compose -f "$COMPOSE_FILE" logs --tail=50
exit 1
