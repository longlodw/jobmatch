# JobMatch MVP

This repository contains an MVP implementation of a job application assistant. It focuses on a single Go backend with server‑rendered HTML (HTMX fragments) to help users browse jobs.

## Implemented Features

- Google Sign-In (OIDC) login and logout flow
- HTMX fragment endpoints for:
  - Pending job swipe deck (single-card Tinder-style)
  - Job detail panel (raw content preview)

  - Job status update (Interested / Not Interested actions)
  - Resume list + upload (link a Google Doc file ID)
  - Settings panel (search URL only)
- (Removed) Status filtering UI and standalone Google Drive enable flow
- Persistent storage integration (Postgres + MinIO via `Storage` abstraction)
- Daily/remote job ingester integration via `JobFetcher` (external service URL + token)
- Embedding service integration (OpenAI‑compatible base URL + API key)
- Unified error fragment (`error_fragment`) for all HTMX endpoints
- CSRF protection for all state‑changing POST requests and selected GET fragments (`/settings`)
- Consistent HTTP status codes (`http.Status*`)

## Repository Layout

- `main.go` — HTTP server, route registration, template parsing
- `service.go` — High-level orchestration / business logic layer
- `storage.go` — Persistence (Postgres + MinIO) operations
- `fetcher.go` — Job fetcher client wrapper
- `embedding.go` — Embedding (vector generation) client wrapper
- `gservices.go` — Google API (Drive/Docs/OAuth) helpers
- `csrf.go` — CSRF token generation/validation helpers
- `templates/` — Base page, fragments, error partial
- `assets/style.css` — Minimal styling

## HTMX Fragment Pattern

All fragment endpoints either render a success template or, on failure, call the shared `fragmentError` helper which responds with:
```
<div class="alert">{message}</div>
```
This keeps UI error handling consistent and lightweight. Consumers (buttons/forms) swap fragment HTML directly via `hx-target` and `hx-swap`.

## CSRF Protection

A CSRF token is generated on initial page load and set in a cookie + `<meta name="csrf-token">`. A small script registers the token into every HTMX request header (`X-CSRF-Token`). Server validation occurs in `validateCSRF(r)` before processing POSTs (and select sensitive GET fragments).

## Required Environment Variables

The server fails fast if any required configuration is missing. Provide these before running:

| Variable | Purpose |
|----------|---------|
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `WEB_REDIRECT_URL` | OAuth redirect URI for browser login flow |
| `API_REDIRECT_URL` | OAuth redirect URI for API/client login flow |
| `DRIVE_REDIRECT_URL` | OAuth redirect URI for Drive enable callback |
| `PG_CONN_STR` | Postgres connection string |
| `PG_SECRET` | Encryption / key material for sensitive data |
| `MINIO_ENDPOINT` | MinIO/S3 endpoint (host:port) |
| `MINIO_ACCESS_KEY` | MinIO access key |
| `MINIO_SECRET_KEY` | MinIO secret key |
| `MINIO_BUCKET` | Bucket for raw job JSON / artifacts |
| `JOB_FETCHER_URL` | External job fetcher base URL |
| `JOB_FETCHER_TOKEN` | Auth token for job fetcher |
| `OPENAI_BASE_URL` | Embedding service base URL (OpenAI compatible) |
| `OPENAI_API_KEY` | API key for embedding service |

Optional variables with defaults:
- `ROOT_FOLDER_NAME` (default: `JobMatch Applications`)
- `SERVER_ADDR` (default: `:8080`)

## Quick Start

### Building the Docker Image

A multi-stage `Dockerfile` is provided. Build and run locally:
```bash
podman build -t localhost/jobmatch:latest .
# or docker build -t jobmatch:latest .
```
The runtime image is a minimal Alpine with a non-root `jobmatch` user. Supply application variables at run time via `--env-file .env.app`.


## Podman Pod

A helper script `scripts/create_pod.sh` replaces the previous `podman-pod.yaml`. It creates an idempotent multi-container pod (Postgres, MinIO, Nginx cache proxy, app) using per-service env files: `.env.app`, `.env.postgres`, `.env.minio`, `.env.nginx`.

Steps:
1. Populate `.env.app`, `.env.postgres`, `.env.minio` (and optional `.env.nginx`) with required variables (see table above for app).
2. Build the app image: `podman build -t localhost/jobmatch:latest .`
3. Run the script: `bash scripts/create_pod.sh`
4. Inspect containers: `podman ps --filter pod=jobmatch-pod`
5. Access app at `http://localhost:8080`.

The script:
- Fails fast if required variables are missing.
- Reuses existing pod/containers on subsequent runs.
- Mounts host directories under `/var/lib/podman_volumes/jobmatch/` for persistence.
- Supplies env vars for each container via its own `--env-file`.

To rebuild and restart app only:
```bash
podman rm -f jobmatch-app
podman build -t localhost/jobmatch:latest .
bash scripts/create_pod.sh
```

To tear down everything:
```bash
podman pod rm -f jobmatch-pod
rm -rf /var/lib/podman_volumes/jobmatch
```

## Services-Only Pod (Run App Locally)

Use `scripts/create_services_pod.sh` to start only Postgres, MinIO (API + Console), and the Nginx job fetcher cache, exposing their ports to the host while you run the Go app directly.

Usage:
1. Ensure `.env.postgres`, `.env.minio`, `.env.nginx`, and your `.env.app` exist.
2. Start services: `bash scripts/create_services_pod.sh`
3. Run the app locally (inject env): `env $(grep -v '^#' .env.app | xargs) go run .`
4. Access:
   - App (when running): http://localhost:8080
   - Postgres: localhost:5432
   - MinIO API: http://localhost:9000
   - MinIO Console: http://localhost:9090
   - Nginx Cache: http://localhost:8081

Set `RECREATE_POD=1` to force pod recreation.

1. Export / set all required environment variables.
2. Ensure Postgres and MinIO are running and accessible.
3. Create the required bucket in MinIO (if not auto‑created).
4. Run the server:
   ```bash
   go run .
   ```
5. Navigate to `http://localhost:8080`.
6. Log in with Google; interact with Jobs, Resumes, and Settings.

## Development Notes

- Templates are parsed once at startup (add new files under `templates/` and include them in `template.ParseFiles` list if needed).
- Error handling for fragments uses `fragmentError`; avoid duplicating raw `ExecuteTemplate("error_fragment", ...)` in handlers.
- Plain text responses remain for simple POST actions (`/settings/search`, resume upload success messages). These can be migrated to fragments if richer UI feedback is desired.
- CSRF is enforced on all POST endpoints and select GET endpoints that expose user settings or integration flows.

## License

MIT License. See `LICENSE` file for details.
