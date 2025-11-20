# JobMatch MVP

This repository contains an MVP implementation of a job application assistant. It focuses on a single Go backend with server‑rendered HTML (HTMX fragments) to help users browse jobs, manage notes and statuses, upload resume document references, and configure basic settings.

## Implemented Features

- Google Sign-In (OIDC) login and logout flow
- HTMX fragment endpoints for:
  - Job listing with status filtering
  - Job detail panel (raw content preview)
  - Inline job note edit/save/cancel
  - Job status update (dropdown)
  - Resume list + upload (link a Google Doc file ID)
  - Settings panel (search URL + Drive enable)
- Google Drive enable flow (returns authorization URL)
- Persistent storage integration (Postgres + MinIO via `Storage` abstraction)
- Daily/remote job ingester integration via `JobFetcher` (external service URL + token)
- Embedding service integration (OpenAI‑compatible base URL + API key)
- Unified error fragment (`error_fragment`) for all HTMX endpoints
- CSRF protection for all state‑changing POST requests and selected GET fragments (`/settings`, `/settings/drive`)
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
| `GOOGLE_REDIRECT_URL` | OAuth redirect URI (must match console) |
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
- `FRONTEND_ORIGIN` (default: `http://localhost:5173` for CORS dev)

## Quick Start

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

## Future / Backlog (Not Yet Implemented Here)

The original broader MVP vision (swipe interface, re‑ranking, multi‑service split, PostgREST/RLS enforcement in a separate stack) is not fully represented in this single repository. Potential next steps:
- Expand UI to include swipe / table views with richer filtering
- Re‑rank matches using cross‑encoders and add explanation tooltips
- Resume tailoring / cover letter drafting workflow
- Background scheduler for recurring embedding + ingestion tasks
- Drive folder organization enhancements (subfolders per stage)
- Structured audit logging with searchable index

## Contributing

1. Open an issue describing proposed change.
2. Keep handlers lean; prefer adding helper functions for repeated logic.
3. Maintain consistent error fragment usage.
4. Avoid adding heavy dependencies without discussion.

## License

(Choose and state a license appropriate for distribution; currently not specified.)
