#!/bin/sh
set -eu

# JobMatch Pod creation script using podman.
# Loads environment variables from .env (key=value) file in repo root.
# Creates pod 'jobmatch-pod' if it does not already exist, then launches
# containers: postgres, minio, nginx-jobfetcher-cache, app.
# Idempotent: skips creating containers if they already exist.

REPO_DIR="$(cd "$(dirname "$0")"/.. && pwd)"
APP_ENV_FILE="${REPO_DIR}/.env.app"
POSTGRES_ENV_FILE="${REPO_DIR}/.env.postgres"
MINIO_ENV_FILE="${REPO_DIR}/.env.minio"
NGINX_ENV_FILE="${REPO_DIR}/.env.nginx"
POD_NAME="jobmatch-pod"
APP_IMAGE="localhost/jobmatch:latest"
POSTGRES_IMAGE="docker.io/library/postgres:latest"
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
required_vars="GOOGLE_CLIENT_ID GOOGLE_CLIENT_SECRET WEB_LOGIN_REDIRECT_URL API_LOGIN_REDIRECT_URL DRIVE_REDIRECT_URL PG_CONN_STR PG_SECRET MINIO_ENDPOINT MINIO_ACCESS_KEY MINIO_SECRET_KEY MINIO_BUCKET JOB_FETCHER_URL JOB_FETCHER_TOKEN OPENAI_BASE_URL OPENAI_API_KEY"
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

# Create or recreate pod with only app port exposed
if podman pod exists "$POD_NAME"; then
  if [ "$RECREATE_POD" = "1" ]; then
    echo "Recreating pod ${POD_NAME} exposing app port ${APP_PORT}"
    podman pod rm -f "$POD_NAME" >/dev/null 2>&1 || true
    podman pod create --name "${POD_NAME}" -p "${APP_PORT}:8080"
  else
    echo "Pod ${POD_NAME} already exists (set RECREATE_POD=1 to rebuild with new app port)"
  fi
else
  echo "Creating pod ${POD_NAME} exposing app port ${APP_PORT}"
  podman pod create --name "${POD_NAME}" -p "${APP_PORT}:8080"
fi

# Create volumes directories (host paths) if not present
HOST_BASE="${REPO_DIR}/pod_data"
mkdir -p "${HOST_BASE}/postgres" "${HOST_BASE}/minio" "${HOST_BASE}/nginx/cache"

# Launch Postgres (restart if existing but stopped)
if [ "$(podman container exists postgres && podman inspect -f '{{.State.Running}}' postgres 2>/dev/null || echo false)" != "true" ]; then
  echo "(Re)starting postgres container"
  if podman container exists postgres; then
    podman rm -f postgres >/dev/null 2>&1 || true
  fi
  podman run -d --restart=always --pod "${POD_NAME}" \
    --name postgres \
    --env-file "${POSTGRES_ENV_FILE}" \
    -v "${HOST_BASE}/postgres:/var/lib/postgresql" \
    "${POSTGRES_IMAGE}"
else
  echo "postgres container already running"
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
    set $jobfetcher_origin https://remote-jobfetcher.example.com;
    location / {
      proxy_pass $jobfetcher_origin;
      proxy_set_header Host remote-jobfetcher.example.com;
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
echo "\nExternal ports exposed:"
podman port "${POD_NAME}" || true
echo "\nNote: The host mapping 0.0.0.0:${APP_PORT}->8080/tcp belongs to the pod and is shown for every container. Other service ports (5432,9000,8081) are internal only (no host binding)."
