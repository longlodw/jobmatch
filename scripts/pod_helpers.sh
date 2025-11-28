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
  pod_name="$1"; host_base="$2"; image="$3"
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
