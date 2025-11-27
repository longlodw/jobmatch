#!/bin/sh
set -eu

# JobMatch Pod creation script using podman.
# Creates pod 'jobmatch-pod' and launches containers: pgvector, minio,
# nginx-jobfetcher-cache, and the app. Only the app port is exposed to host.

REPO_DIR="$(cd "$(dirname "$0")"/.. && pwd)"
SCRIPT_DIR="${REPO_DIR}/scripts"
HELPERS_FILE="${SCRIPT_DIR}/pod_helpers.sh"
APP_ENV_FILE="${REPO_DIR}/.env.app"
POSTGRES_ENV_FILE="${REPO_DIR}/.env.postgres"
MINIO_ENV_FILE="${REPO_DIR}/.env.minio"
POD_NAME="jobmatch-pod"
APP_IMAGE="localhost/jobmatch:latest"
POSTGRES_IMAGE="docker.io/ankane/pgvector:latest"
MINIO_IMAGE="quay.io/minio/minio:latest"
EMBEDDINGS_IMAGE="ghcr.io/substratusai/stapi:latest"

APP_PORT="${APP_PORT:-8080}"
RECREATE_POD="${RECREATE_POD:-}"

# Source helpers
if [ ! -f "$HELPERS_FILE" ]; then
  echo "Missing helpers file: $HELPERS_FILE" >&2
  exit 1
fi
. "$HELPERS_FILE"

# Ensure per-service env files exist
for f in "$APP_ENV_FILE" "$POSTGRES_ENV_FILE" "$MINIO_ENV_FILE"; do
  if [ ! -f "$f" ]; then
    echo "Missing env file: $f" >&2
    exit 1
  fi
done

# Load app env to validate required vars
while IFS='=' read -r key value; do
  [ -z "$key" ] && continue
  case "$key" in \#*) continue ;; esac
  value="${value%\"}"; value="${value#\"}"
  export "$key=$value"
done < "$APP_ENV_FILE"

required_vars="GOOGLE_CLIENT_ID GOOGLE_CLIENT_SECRET WEB_REDIRECT_URL API_REDIRECT_URL PG_CONN_STR PG_SECRET MINIO_ENDPOINT MINIO_ACCESS_KEY MINIO_SECRET_KEY MINIO_BUCKET JOB_FETCHER_URL JOB_FETCHER_TOKEN OPENAI_BASE_URL OPENAI_API_KEY"
missing=""
for v in $required_vars; do
  eval val="\${$v:-}"
  [ -z "$val" ] && missing="$missing $v"
done
if [ -n "$missing" ]; then
  echo "Missing required env vars:$missing" >&2
  exit 1
fi

echo "Creating pod ${POD_NAME} exposing only app port ${APP_PORT}"
podman pod create --name "$POD_NAME" -p "${APP_PORT}:8080"

# Host data dirs
HOST_BASE="${REPO_DIR}/.pod_data"
mkdir -p "${HOST_BASE}/pgvector" "${HOST_BASE}/minio" "${HOST_BASE}/nginx/cache" "${HOST_BASE}/nginx/conf"

# Start services using helpers
start_pgvector "$POD_NAME" "$POSTGRES_ENV_FILE" "$HOST_BASE" "$POSTGRES_IMAGE"
start_minio    "$POD_NAME" "$MINIO_ENV_FILE"    "$HOST_BASE" "$MINIO_IMAGE" ""
start_openai_embeddings "$POD_NAME" "$HOST_BASE" "$EMBEDDINGS_IMAGE"

# Ensure app image present (auto-build if absent)
if ! podman image exists "$APP_IMAGE"; then
  echo "App image ${APP_IMAGE} not found. Building..." >&2
  podman build -t "$APP_IMAGE" "$REPO_DIR"
fi

# Launch application
if [ "$(podman container exists jobmatch-app && podman inspect -f '{{.State.Running}}' jobmatch-app 2>/dev/null || echo false)" != "true" ]; then
  echo "(Re)starting jobmatch app container"
  if podman container exists jobmatch-app; then podman rm -f jobmatch-app >/dev/null 2>&1 || true; fi
  podman run -d --restart=always --pod "$POD_NAME" \
    --name jobmatch-app \
    --env-file "$APP_ENV_FILE" \
    "$APP_IMAGE"
else
  echo "jobmatch-app container already running"
fi

echo "Pod setup complete. Containers status (shared pod ports appear on each row):"
podman ps --filter "pod=${POD_NAME}" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
