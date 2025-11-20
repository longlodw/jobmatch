# JobMatch MVP

This repository contains an MVP for a job application assistant that helps users discover roles, match them to their best resume version, and organize application artifacts on Google Drive.

## MVP Scope

- Google Sign-In (OAuth/OIDC)
- Store user-selected resume versions by linking specific Google Docs
- Daily job ingestion from existing job-fetching API (JSON list)
- Persist raw job posts in S3-compatible storage (immutable JSON)
- Index metadata in Postgres; expose via PostgREST
- Hybrid matching (embeddings + lexical) to rank resume↔job fit
- User reviews matches in two UIs:
  - Tinder-like swipe view (accept/reject)
  - Table view (sortable/filterable)
- On acceptance:
  - Create an application folder in the user’s Google Drive
  - Copy the chosen Google Doc resume into that folder (Google Docs copy)
  - Record application with folder and file URLs
- Views for accepted applications (title, company, created date, links)
- Basic audit logs for sensitive operations (Drive/file access)

## Non-Goals (MVP)

- Automated LinkedIn scraping or non-compliant data collection
- Cover letter generation or resume rewriting (future)
- Complex multi-tenant admin features
- Advanced analytics or A/B testing

## High-Level Components

- frontend/ — Web UI (Swipe and Table views, auth, match actions)
- backend/ — Services + infra:
  - Auth Service (Go): Google OAuth + app JWT issuance
  - Match Service (Go): ingestion coordination, embeddings, scoring, accept/reject flows
  - PostgREST: views for matches and accepted applications
  - PostgreSQL: relational index and app data (pgvector optional)
  - S3-compatible storage: raw job posting JSON objects
  - Google APIs (Drive/Docs): resume access and application folder creation

## Data Flow (MVP)

1. Fetcher (existing) → S3: writes JSON objects per posting; calls backend upsert to index metadata.
2. Backend index → Postgres: stores metadata, S3 pointers, dedup by (source, external_id).
3. Matcher (daily): embeds and scores new jobs vs user resumes; inserts proposed matches.
4. Frontend: displays proposed matches in swipe/table; user accepts or rejects.
5. Acceptance: backend creates Drive folder, copies the Google Doc resume (no PDF export), records application, updates status.

## Security & Privacy

- OAuth scopes: least privilege (drive.file, drive.readonly for selected docs)
- Encrypt Google refresh tokens and sensitive columns at rest
- RLS in Postgres enforced via PostgREST JWT claims
- Short-lived presigned URLs for raw S3 access (server-side only)

## Local Development

- Docker Compose for Postgres, PostgREST, MinIO (S3), services
- Seed scripts to create minimal schema and roles
- Env-driven configuration for API keys and endpoints

## Future Enhancements

- Cross-encoder re-ranking and explainability
- Email ingestion (job alerts), browser extension save-to-app
- Cover letter drafting, resume tailoring
- Multi-ATS integrations (Greenhouse/Lever)
