# Multi-stage Dockerfile for JobMatch Go application
# Build stage
FROM golang:latest AS build
WORKDIR /app

# Enable modules and copy go files
COPY go.mod go.sum ./
COPY . .

# Build binary (static, disable cgo for Alpine runtime)
ENV CGO_ENABLED=0
RUN go build -o jobmatch .

# Runtime stage
FROM alpine:latest AS runtime
WORKDIR /app
# Add minimal CA certs for outbound HTTPS (Google, OpenAI, etc.)
RUN apk add --no-cache ca-certificates

# Create non-root user
RUN addgroup -g 1001 jobmatch && adduser -D -u 1001 -G jobmatch jobmatch
# Copy binary and templates/assets
COPY --from=build /app/jobmatch ./jobmatch
COPY --from=build /app/templates ./templates
COPY --from=build /app/assets ./assets

# Expose default server port
EXPOSE 8080

USER jobmatch

# Environment variables expected (supplied at runtime via --env-file)
# GOOGLE_CLIENT_ID
# GOOGLE_CLIENT_SECRET
# GOOGLE_REDIRECT_URL
# PG_CONN_STR
# PG_SECRET
# MINIO_ENDPOINT
# MINIO_ACCESS_KEY
# MINIO_SECRET_KEY
# MINIO_BUCKET
# JOB_FETCHER_URL
# JOB_FETCHER_TOKEN
# OPENAI_BASE_URL
# OPENAI_API_KEY
# ROOT_FOLDER_NAME (optional)
# SERVER_ADDR (optional)

ENTRYPOINT ["/app/jobmatch"]
