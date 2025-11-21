#!/usr/bin/env bash
set -euo pipefail

# JobMatch Pod creation script using podman.
# Loads environment variables from .env (key=value) file in repo root.
# Creates pod 'jobmatch-pod' if it does not already exist, then launches
# containers: postgres, minio, nginx-jobfetcher-cache, app.
# Idempotent: skips creating containers if they already exist.

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
ENV_FILE="${REPO_DIR}/.env"
POD_NAME="jobmatch-pod"
APP_IMAGE="localhost/jobmatch:latest"
POSTGRES_IMAGE="docker.io/library/postgres:16"
MINIO_IMAGE="quay.io/minio/minio:latest"
NGINX_IMAGE="docker.io/library/nginx:1.27"

# Ensure .env exists
if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Missing .env file at ${ENV_FILE}" >&2
  exit 1
fi

# Export variables from .env (ignore comments / blank lines)
set -a
# shellcheck disable=SC2046
source <(grep -v '^#' "${ENV_FILE}" | sed -e '/^$/d')
set +a

# Required variables (fail fast if empty)
required_vars=(GOOGLE_CLIENT_ID GOOGLE_CLIENT_SECRET GOOGLE_REDIRECT_URL PG_CONN_STR PG_SECRET MINIO_ENDPOINT MINIO_ACCESS_KEY MINIO_SECRET_KEY MINIO_BUCKET JOB_FETCHER_URL JOB_FETCHER_TOKEN OPENAI_BASE_URL OPENAI_API_KEY)
missing=()
for v in "${required_vars[@]}"; do
  if [[ -z "${!v:-}" ]]; then
    missing+=("$v")
  fi
done
if (( ${#missing[@]} > 0 )); then
  echo "Missing required env vars: ${missing[*]}" >&2
  exit 1
fi

# Create pod if not exists
if ! podman pod exists "${POD_NAME}"; then
  echo "Creating pod ${POD_NAME}"
  podman pod create --name "${POD_NAME}" -p 8080:8080 -p 5432:5432 -p 9000:9000 -p 9001:9001 -p 8081:8081
else
  echo "Pod ${POD_NAME} already exists"
fi

# Create volumes directories (host paths) if not present
HOST_BASE="/var/lib/podman_volumes/jobmatch"
mkdir -p "${HOST_BASE}/postgres" "${HOST_BASE}/minio" "${HOST_BASE}/nginx/cache"

# Launch Postgres
if ! podman container exists postgres || ! podman container inspect postgres >/dev/null 2>&1; then
  echo "Starting postgres container"
  podman run -d --restart=always --pod "${POD_NAME}" \
    --name postgres \
    -e POSTGRES_DB=jobmatch \
    -e POSTGRES_USER=jobmatch \
    -e POSTGRES_PASSWORD=jobmatchpwd \
    -v "${HOST_BASE}/postgres:/var/lib/postgresql/data" \
    "${POSTGRES_IMAGE}"
else
  echo "postgres container already exists"
fi

# Launch MinIO
if ! podman container exists minio || ! podman container inspect minio >/dev/null 2>&1; then
  echo "Starting minio container"
  podman run -d --restart=always --pod "${POD_NAME}" \
    --name minio \
    -e MINIO_ROOT_USER="${MINIO_ACCESS_KEY}" \
    -e MINIO_ROOT_PASSWORD="${MINIO_SECRET_KEY}" \
    -v "${HOST_BASE}/minio:/data" \
    "${MINIO_IMAGE}" server /data
else
  echo "minio container already exists"
fi

# Prepare nginx config (cache reverse proxy) in temp dir mapped into container
NGINX_CONF_DIR="${HOST_BASE}/nginx/conf"
mkdir -p "${NGINX_CONF_DIR}" "${HOST_BASE}/nginx/cache"
NGINX_CONF_FILE="${NGINX_CONF_DIR}/nginx.conf"
if [[ ! -f "${NGINX_CONF_FILE}" ]]; then
  cat > "${NGINX_CONF_FILE}" <<'EOF'
# Nginx reverse proxy + cache for remote job fetcher
proxy_cache_path /cache levels=1:2 keys_zone=jobfetcher_cache:10m max_size=500m inactive=30m use_temp_path=off;
events {}
http {
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

# Launch Nginx cache proxy
if ! podman container exists nginx-jobfetcher-cache || ! podman container inspect nginx-jobfetcher-cache >/dev/null 2>&1; then
  echo "Starting nginx-jobfetcher-cache container"
  podman run -d --restart=always --pod "${POD_NAME}" \
    --name nginx-jobfetcher-cache \
    -v "${NGINX_CONF_DIR}:/etc/nginx" \
    -v "${HOST_BASE}/nginx/cache:/cache" \
    "${NGINX_IMAGE}"
else
  echo "nginx-jobfetcher-cache container already exists"
fi

# Ensure app image present (user must build beforehand)
if ! podman image exists "${APP_IMAGE}"; then
  echo "App image ${APP_IMAGE} not found. Build it first with: podman build -t ${APP_IMAGE} ." >&2
  exit 1
fi

# Launch application
if ! podman container exists jobmatch-app || ! podman container inspect jobmatch-app >/dev/null 2>&1; then
  echo "Starting jobmatch app container"
  podman run -d --restart=always --pod "${POD_NAME}" \
    --name jobmatch-app \
    --env-file "${ENV_FILE}" \
    -e ROOT_FOLDER_NAME="${ROOT_FOLDER_NAME:-JobMatch Applications}" \
    -e SERVER_ADDR="${SERVER_ADDR:-:8080}" \
    -e PG_CONN_STR="${PG_CONN_STR}" \
    "${APP_IMAGE}"
else
  echo "jobmatch-app container already exists"
fi

echo "Pod setup complete. Containers status:" 
podman ps --filter "pod=${POD_NAME}" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
