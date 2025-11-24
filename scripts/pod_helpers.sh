#!/bin/sh
# Shared helper functions for JobMatch pod/service scripts.
# Source this file from create_pod.sh or create_services_pod.sh:
#   SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
#   . "${SCRIPT_DIR}/pod_helpers.sh"
# Functions:
#   start_pgvector <pod_name> <env_file> <host_base> <image>
#   start_minio    <pod_name> <env_file> <host_base> <image> [console_addr]
#   start_nginx_cache <pod_name> <env_file> <host_base> <image>

start_pgvector() {
  pod_name="$1"; env_file="$2"; host_base="$3"; image="$4"
  if [ "$(podman container exists pgvector && podman inspect -f '{{.State.Running}}' pgvector 2>/dev/null || echo false)" != "true" ]; then
    echo "(Re)starting pgvector container"
    if podman container exists pgvector; then podman rm -f pgvector >/dev/null 2>&1 || true; fi
    podman run -d --restart=always --pod "$pod_name" \
      --name pgvector \
      --env-file "$env_file" \
      -v "${host_base}/pgvector:/var/lib/postgresql/data" \
      "$image"
  else
    echo "pgvector container already running"
  fi
}

start_minio() {
  pod_name="$1"; env_file="$2"; host_base="$3"; image="$4"; console_addr="${5:-}"
  if [ "$(podman container exists minio && podman inspect -f '{{.State.Running}}' minio 2>/dev/null || echo false)" != "true" ]; then
    echo "(Re)starting minio container"
    if podman container exists minio; then podman rm -f minio >/dev/null 2>&1 || true; fi
    if [ -n "$console_addr" ]; then
      podman run -d --restart=always --pod "$pod_name" \
        --name minio \
        --env-file "$env_file" \
        -v "${host_base}/minio:/data" \
        "$image" server /data --console-address "$console_addr"
    else
      podman run -d --restart=always --pod "$pod_name" \
        --name minio \
        --env-file "$env_file" \
        -v "${host_base}/minio:/data" \
        "$image" server /data
    fi
  else
    echo "minio container already running"
  fi
}

start_nginx_cache() {
  pod_name="$1"; env_file="$2"; host_base="$3"; image="$4"
  conf_dir="${host_base}/nginx/conf"; cache_dir="${host_base}/nginx/cache"; conf_file="${conf_dir}/nginx.conf"
  mkdir -p "$conf_dir" "$cache_dir"
  if [ ! -f "$conf_file" ]; then
    cat > "$conf_file" <<'EOF'
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
  if [ "$(podman container exists nginx-jobfetcher-cache && podman inspect -f '{{.State.Running}}' nginx-jobfetcher-cache 2>/dev/null || echo false)" != "true" ]; then
    echo "(Re)starting nginx-jobfetcher-cache container"
    if podman container exists nginx-jobfetcher-cache; then podman rm -f nginx-jobfetcher-cache >/dev/null 2>&1 || true; fi
    podman run -d --restart=always --pod "$pod_name" \
      --name nginx-jobfetcher-cache \
      --env-file "$env_file" \
      -v "${conf_dir}:/etc/nginx" \
      -v "${cache_dir}:/cache" \
      "$image"
  else
    echo "nginx-jobfetcher-cache container already running"
  fi
}
