#!/bin/sh
set -eu

# JobMatch Pod creation script using podman.
# Loads environment variables from .env (key=value) file in repo root.
# Creates pod 'jobmatch-pod' if it does not already exist, then launches
# containers: pgvector, minio, nginx-jobfetcher-cache, app.
# Idempotent: skips creating containers if they already exist.

REPO_DIR="$(cd "$(dirname "$0")"/.. && pwd)"
APP_ENV_FILE="${REPO_DIR}/.env.app"
POSTGRES_ENV_FILE="${REPO_DIR}/.env.postgres"
MINIO_ENV_FILE="${REPO_DIR}/.env.minio"
NGINX_ENV_FILE="${REPO_DIR}/.env.nginx"
POD_NAME="jobmatch-pod"
APP_IMAGE="localhost/jobmatch:latest"
POSTGRES_IMAGE="docker.io/ankane/pgvector:latest"
MINIO_IMAGE="quay.io/minio/minio:latest"
NGINX_IMAGE="docker.io/library/nginx:latest"

# Ensure per-service env files exist
for f in "$APP_ENV_FILE" "$POSTGRES_ENV_FILE" "$MINIO_ENV_FILE" "$NGINX_ENV_FILE"; do
  if [ ! -f "$f" ]; then
    echo "Missing env file: $f" >&2
    exit 1
  fi
done

# Export variables from app env to validate required vars (ignore comments / blank lines)
# Load app env file into current shell
# shellcheck disable=SC2163
while IFS='=' read -r key value; do
  [ -z "$key" ] && continue
  case "$key" in \#*) continue ;; esac
  case "$key" in [A-Z0-9_]*) ;; *) echo "Invalid var: $key" >&2; exit 1 ;; esac
  # Strip optional surrounding double quotes
  value="${value%\"}"
  value="${value#\"}"
  export "$key=$value"
done < "$APP_ENV_FILE"

# Required variables (fail fast if empty)
required_vars="GOOGLE_CLIENT_ID GOOGLE_CLIENT_SECRET WEB_LOGIN_REDIRECT_URL API_LOGIN_REDIRECT_URL API_DRIVE_REDIRECT_URL WEB_DRIVE_REDIRECT_URL PG_CONN_STR PG_SECRET MINIO_ENDPOINT MINIO_ACCESS_KEY MINIO_SECRET_KEY MINIO_BUCKET JOB_FETCHER_URL JOB_FETCHER_TOKEN OPENAI_BASE_URL OPENAI_API_KEY"
missing=""
for v in $required_vars; do
  eval val="\${$v:-}"
  if [ -z "$val" ]; then
    missing="$missing $v"
  fi
done
if [ -n "$missing" ]; then
  echo "Missing required env vars:$missing" >&2
  exit 1
fi

# Define app host port (only external exposure)
APP_PORT="${APP_PORT:-8080}"
RECREATE_POD="${RECREATE_POD:-}" # set to 1 to force pod recreation

# Create or recreate pod ensuring ONLY app port is exposed externally
if podman pod exists "$POD_NAME"; then
  existing_ports="$(podman port "$POD_NAME" 2>/dev/null || true)"
  # Normalize by removing IPv6 duplicate lines
  normalized_ports="$(echo "$existing_ports" | grep -v '^$' | sed '/\[::\]/d')"
  expected_line="8080/tcp -> 0.0.0.0:${APP_PORT}"
  needs_recreate=0
  # RECREATE_POD override always forces recreation
  if [ "$RECREATE_POD" = "1" ]; then
    needs_recreate=1
  else
    # If any port other than 8080/tcp is published OR host port differs, recreate
    if echo "$normalized_ports" | grep -qv '^8080/tcp'; then
      needs_recreate=1
    elif ! echo "$normalized_ports" | grep -q "$expected_line"; then
      needs_recreate=1
    fi
    # If multiple lines remain after normalization, recreate
    count_lines="$(echo "$normalized_ports" | wc -l | tr -d ' ')"
    if [ "$count_lines" -gt 1 ]; then
      needs_recreate=1
    fi
  fi
  if [ "$needs_recreate" -eq 1 ]; then
    echo "Recreating pod ${POD_NAME} to enforce single exposed app port ${APP_PORT}"
    podman pod rm -f "$POD_NAME" >/dev/null 2>&1 || true
    podman pod create --name "${POD_NAME}" -p "${APP_PORT}:8080"
  else
    echo "Pod ${POD_NAME} already exists with only app port exposed (set RECREATE_POD=1 to force)"
  fi
else
  echo "Creating pod ${POD_NAME} exposing only app port ${APP_PORT}"
  podman pod create --name "${POD_NAME}" -p "${APP_PORT}:8080"
fi

# Create volumes directories (host paths) if not present
HOST_BASE="${REPO_DIR}/pod_data"
mkdir -p "${HOST_BASE}/pgvector" "${HOST_BASE}/minio" "${HOST_BASE}/nginx/cache"

# Launch Postgres (restart if existing but stopped)
if [ "$(podman container exists pgvector && podman inspect -f '{{.State.Running}}' pgvector 2>/dev/null || echo false)" != "true" ]; then
  echo "(Re)starting pgvector container"
  if podman container exists pgvector; then
    podman rm -f pgvector >/dev/null 2>&1 || true
  fi
  podman run -d --restart=always --pod "${POD_NAME}" \
    --name pgvector \
    --env-file "${POSTGRES_ENV_FILE}" \
    -v "${HOST_BASE}/pgvector:/var/lib/postgresql/data" \
    "${POSTGRES_IMAGE}"
else
  echo "pgvector container already running"
fi

# Launch MinIO (restart if existing but stopped)
if [ "$(podman container exists minio && podman inspect -f '{{.State.Running}}' minio 2>/dev/null || echo false)" != "true" ]; then
  echo "(Re)starting minio container"
  if podman container exists minio; then
    podman rm -f minio >/dev/null 2>&1 || true
  fi
  podman run -d --restart=always --pod "${POD_NAME}" \
    --name minio \
    --env-file "${MINIO_ENV_FILE}" \
    -v "${HOST_BASE}/minio:/data" \
    "${MINIO_IMAGE}" server /data
else
  echo "minio container already running"
fi

# Prepare nginx config (cache reverse proxy) in temp dir mapped into container
NGINX_CONF_DIR="${HOST_BASE}/nginx/conf"
mkdir -p "${NGINX_CONF_DIR}" "${HOST_BASE}/nginx/cache"
NGINX_CONF_FILE="${NGINX_CONF_DIR}/nginx.conf"
if [ ! -f "$NGINX_CONF_FILE" ]; then
  cat > "${NGINX_CONF_FILE}" <<'EOF'
# Nginx reverse proxy + cache for remote job fetcher
user  nginx;
worker_processes  auto;
error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

events { worker_connections 1024; }

http {
  proxy_cache_path /cache levels=1:2 keys_zone=jobfetcher_cache:10m max_size=500m inactive=30m use_temp_path=off;
  server {
    listen 8081;
    # Adjust upstream origin below to the real job fetcher endpoint if not local
    set $jobfetcher_origin https://api.apify.com/v2/acts/curious_coder~linkedin-jobs-scraper/run-sync-get-dataset-items;
    location / {
      proxy_pass $jobfetcher_origin;
      proxy_set_header Host api.apify.com;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_cache jobfetcher_cache;
      proxy_cache_valid 200 10m;
      proxy_cache_valid 404 1m;
      proxy_cache_bypass $http_cache_control;
      add_header X-Cache-Status $upstream_cache_status;
    }
  }
}
EOF
fi

# Launch Nginx cache proxy (restart if existing but stopped)
if [ "$(podman container exists nginx-jobfetcher-cache && podman inspect -f '{{.State.Running}}' nginx-jobfetcher-cache 2>/dev/null || echo false)" != "true" ]; then
  echo "(Re)starting nginx-jobfetcher-cache container"
  if podman container exists nginx-jobfetcher-cache; then
    podman rm -f nginx-jobfetcher-cache >/dev/null 2>&1 || true
  fi
  podman run -d --restart=always --pod "${POD_NAME}" \
    --name nginx-jobfetcher-cache \
    --env-file "${NGINX_ENV_FILE}" \
    -v "${NGINX_CONF_DIR}:/etc/nginx" \
    -v "${HOST_BASE}/nginx/cache:/cache" \
    "${NGINX_IMAGE}"
else
  echo "nginx-jobfetcher-cache container already running"
fi

# Ensure app image present (auto-build if absent)
if ! podman image exists "$APP_IMAGE"; then
  echo "App image ${APP_IMAGE} not found. Building..." >&2
  if ! podman build -t "${APP_IMAGE}" "${REPO_DIR}"; then
    echo "Failed to build image ${APP_IMAGE}" >&2
    exit 1
  fi
fi

# Launch application (restart if existing but stopped)
if [ "$(podman container exists jobmatch-app && podman inspect -f '{{.State.Running}}' jobmatch-app 2>/dev/null || echo false)" != "true" ]; then
  echo "(Re)starting jobmatch app container"
  if podman container exists jobmatch-app; then
    podman rm -f jobmatch-app >/dev/null 2>&1 || true
  fi
  podman run -d --restart=always --pod "${POD_NAME}" \
    --name jobmatch-app \
    --env-file "${APP_ENV_FILE}" \
    "${APP_IMAGE}"
else
  echo "jobmatch-app container already running"
fi

echo "Pod setup complete. Containers status (shared pod ports appear on each row):" 
podman ps --filter "pod=${POD_NAME}" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
