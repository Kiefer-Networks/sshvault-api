# Build stage
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-w -s" -o /shellvault-server ./cmd/server
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-w -s" -o /shellvault-cli ./cmd/cli

# Runtime stage
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata postgresql16-client gzip

WORKDIR /app

COPY --from=builder /shellvault-server .
COPY --from=builder /shellvault-cli .
COPY migrations/ ./migrations/
COPY api/ ./api/

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN mkdir -p /app/backups /app/keys /app/logs && chown appuser:appgroup /app/backups /app/keys /app/logs
USER appuser

EXPOSE 8080

ENTRYPOINT ["./shellvault-server"]
