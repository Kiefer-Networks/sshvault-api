# Build stage
# Pin to specific minor version; in production, pin to SHA256 digest for reproducible builds:
#   FROM --platform=$BUILDPLATFORM golang:1.24-alpine@sha256:<digest> AS builder
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-w -s" -o /sshvault-server ./cmd/server
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-w -s" -o /sshvault-cli ./cmd/cli

# Runtime stage
# In production, pin to SHA256 digest: FROM alpine:3.21@sha256:<digest>
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata postgresql16-client gzip

WORKDIR /app

COPY --from=builder /sshvault-server .
COPY --from=builder /sshvault-cli .
COPY migrations/ ./migrations/
COPY api/ ./api/

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN mkdir -p /app/backups /app/keys /app/logs && chown appuser:appgroup /app/backups /app/keys /app/logs
USER appuser

EXPOSE 8080

ENTRYPOINT ["./sshvault-server"]
