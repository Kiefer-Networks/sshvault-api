# Build stage
# Multi-platform digests are updated by Dependabot.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS builder

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
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk upgrade --no-cache && apk add --no-cache ca-certificates tzdata postgresql16-client gzip

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
