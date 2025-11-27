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

start_openai_embeddings() {
  pod_name="$1"; host_base="$3"; image="$4"
  if [ "$(podman container exists openai-embeddings && podman inspect -f '{{.State.Running}}' openai-embeddings 2>/dev/null || echo false)" != "true" ]; then
    echo "(Re)starting openai-embeddings container"
    if podman container exists openai-embeddings; then podman rm -f openai-embeddings >/dev/null 2>&1 || true; fi
    podman run -d --restart=always --pod "$pod_name" \
      --name openai-embeddings \
      "$image"
  else
    echo "openai-embeddings container already running"
  fi
}

start_nginx_cache() {
  pod_name="$1"; env_file="$2"; host_base="$3"; image="$4"
  conf_dir="${host_base}/nginx/conf"; cache_dir="${host_base}/nginx/cache"; conf_file="${conf_dir}/nginx.conf"
  mkdir -p "$conf_dir" "$cache_dir"
  if [ ! -f "$conf_file" ]; then
    cat > "$conf_file" <<'EOF'
# Nginx reverse proxy + cache
user  nginx;
worker_processes  auto;
error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

events { worker_connections 1024; }

http {
  log_format verbose '$remote_addr $request $status $upstream_cache_status';
  server {
    listen 8081;
    location /jobfetcher {
      root /usr/share/nginx/html;
      default_type application/json;
    }
  }
}
EOF
  fi
  if [ "$(podman container exists nginx-cache && podman inspect -f '{{.State.Running}}' nginx-cache 2>/dev/null || echo false)" != "true" ]; then
    echo "(Re)starting nginx-cache container"
    if podman container exists nginx-cache; then podman rm -f nginx-cache >/dev/null 2>&1 || true; fi
    podman run -d --restart=always --pod "$pod_name" \
      --name nginx-cache \
      --env-file "$env_file" \
      -v "${conf_dir}:/etc/nginx" \
      -v "${cache_dir}:/cache" \
      -v "${host_base}/output.json:/usr/share/nginx/html/jobfetcher/output.json:ro" \
      "$image"
  else
    echo "nginx-cache container already running"
  fi
}
