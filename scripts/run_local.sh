#!/bin/sh
set -eu

# run_local.sh
# Loads environment variables from .env.local (repo root) and runs the Go application.
# Ignores commented (#...) and blank lines. Supports simple KEY=VALUE pairs.
# Usage:
#   bash scripts/run_local.sh
# (Ensure .env.local exists; if you use .env.app instead, set ENV_FILE=.env.app)

REPO_DIR="$(cd "$(dirname "$0")"/.. && pwd)"
ENV_FILE="${ENV_FILE:-${REPO_DIR}/.env.local}"

if [ ! -f "$ENV_FILE" ]; then
  echo "Environment file not found: $ENV_FILE" >&2
  exit 1
fi

echo "Loading environment from $ENV_FILE"
while IFS='=' read -r key value; do
  [ -z "$key" ] && continue
  case "$key" in \#*) continue ;; esac
  # only export ALLCAPS/underscore keys
  case "$key" in [A-Z0-9_]* ) ;; *) continue ;; esac
  value="${value%\"}"; value="${value#\"}"  # strip surrounding quotes
  export "$key=$value"
done < "$ENV_FILE"

cd "$REPO_DIR"
echo "Starting Go application..."
# Explicitly list Go source files to avoid traversing non-code directories.
exec go run \
  main.go \
  service.go \
  storage.go \
  fetcher.go \
  embedding.go \
  gservices.go \
  csrf.go
