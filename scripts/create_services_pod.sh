#!/bin/sh
set -eu

# JobMatch Services Pod script (no app container).
# Creates a pod with Postgres (pgvector), MinIO (API + Console), and
# Nginx job fetcher cache proxy, exposing all service ports directly
# to the host. Does NOT start the Go application and does NOT
# generate any local env file.

REPO_DIR="$(cd "$(dirname "$0")"/.. && pwd)"
SCRIPT_DIR="${REPO_DIR}/scripts"
HELPERS_FILE="${SCRIPT_DIR}/pod_helpers.sh"
POSTGRES_ENV_FILE="${REPO_DIR}/.env.postgres"
MINIO_ENV_FILE="${REPO_DIR}/.env.minio"
POD_NAME="jobmatch-services-pod"
POSTGRES_IMAGE="docker.io/ankane/pgvector:latest"
MINIO_IMAGE="quay.io/minio/minio:latest"
EMBEDDINGS_IMAGE="ghcr.io/substratusai/stapi:latest"
RECREATE_POD="${RECREATE_POD:-}"

# Source helpers
if [ ! -f "$HELPERS_FILE" ]; then
  echo "Missing helpers file: $HELPERS_FILE" >&2
  exit 1
fi
. "$HELPERS_FILE"

# Ensure env files exist
for f in "$POSTGRES_ENV_FILE" "$MINIO_ENV_FILE"; do
  if [ ! -f "$f" ]; then
    echo "Missing env file: $f" >&2
    exit 1
  fi
done

# Create / recreate pod with service ports exposed
if podman pod exists "$POD_NAME"; then
  existing_ports="$(podman port "$POD_NAME" 2>/dev/null || true)"
  normalized_ports="$(echo "$existing_ports" | grep -v '^$' | sed '/\[::\]/d' | sort)"
  expected_ports="5432/tcp -> 0.0.0.0:5432\n9000/tcp -> 0.0.0.0:9000\n8080/tcp -> 0.0.0.0:9080"
  expected_sorted="$(echo "$expected_ports" | sort)"
  needs_recreate=0
  if [ "$RECREATE_POD" = "1" ]; then
    needs_recreate=1
  else
    [ "$normalized_ports" != "$expected_sorted" ] && needs_recreate=1
  fi
  if [ "$needs_recreate" -eq 1 ]; then
    echo "Recreating pod ${POD_NAME} with service port mappings"
    podman pod rm -f "$POD_NAME" >/dev/null 2>&1 || true
    podman pod create --name "$POD_NAME" -p 5432:5432 -p 9000:9000 -p 9080:8080
  else
    echo "Pod ${POD_NAME} already exists with expected service ports (set RECREATE_POD=1 to force)"
  fi
else
  echo "Creating pod ${POD_NAME} exposing service ports (5432,9000)"
  podman pod create --name "$POD_NAME" -p 5432:5432 -p 9000:9000 -p 9080:8080
fi

# Data directories
HOST_BASE="${REPO_DIR}/.pod_data_services"
mkdir -p "${HOST_BASE}/pgvector" "${HOST_BASE}/minio" "${HOST_BASE}/nginx/cache" "${HOST_BASE}/nginx/conf"

# Start services using helpers
start_pgvector "$POD_NAME" "$POSTGRES_ENV_FILE" "$HOST_BASE" "$POSTGRES_IMAGE"
start_minio    "$POD_NAME" "$MINIO_ENV_FILE"    "$HOST_BASE" "$MINIO_IMAGE" ":9090"
start_openai_embeddings "$POD_NAME" "$HOST_BASE" "$EMBEDDINGS_IMAGE"

# Summary
echo "Services pod setup complete. Containers:"
podman ps --filter "pod=${POD_NAME}" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
