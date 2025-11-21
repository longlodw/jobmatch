# Multi-stage Dockerfile for JobMatch Go application
# Build stage
FROM docker.io/library/golang:1.23 AS build
WORKDIR /app

# Enable modules and copy go files
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build binary (static)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o jobmatch ./

# Runtime stage
FROM docker.io/library/alpine:3.20 AS runtime
WORKDIR /app
# Add minimal CA certs for outbound HTTPS (Google, OpenAI, etc.)
RUN apk add --no-cache ca-certificates

# Create non-root user
RUN addgroup -S jobmatch && adduser -S jobmatch -G jobmatch

# Copy binary and templates/assets
COPY --from=build /app/jobmatch /app/jobmatch
COPY --from=build /app/templates /app/templates
COPY --from=build /app/assets /app/assets

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
