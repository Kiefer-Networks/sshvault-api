# ShellVault Server

Zero-Knowledge encrypted sync server for the ShellVault SSH client app.

Built by [Kiefer Networks](https://kiefer-networks.de).

## Architecture

ShellVault uses a Zero-Knowledge architecture: the server never sees plaintext data. Clients encrypt everything locally using AES-256-GCM with Argon2id key derivation. The server stores only opaque encrypted blobs.

### Key Features

- **Encrypted Blob Sync** with optimistic locking and version history
- **Ed25519 JWT authentication** with refresh token rotation
- **Billing** via Stripe, Apple App Store, Google Play
- **Self-Hosted friendly** — billing disabled when Stripe keys are absent
- **Admin CLI** for user management, billing, and database backups

## Quick Start

### Prerequisites

- Go 1.25+
- PostgreSQL 16+
- Docker & Docker Compose (optional)
- A reverse proxy (Traefik or Caddy) for TLS termination

### Local Development

```bash
cp .env.example .env
# Edit .env with your database URL

# Generate JWT signing key
make keygen

# Start PostgreSQL (via Docker)
docker compose -f docker/docker-compose.yml up postgres -d

# Run migrations and start server
make migrate
make run
```

### Docker Compose (Production)

```bash
cp .env.example .env
# Edit .env — set POSTGRES_PASSWORD, TRUSTED_PROXIES, etc.
# IMPORTANT: Set SERVER_ADDR=0.0.0.0:8080 for Docker (binds inside container)
```

#### Build

```bash
docker compose --env-file .env -f docker/docker-compose.yml build
```

#### Start

```bash
docker compose --env-file .env -f docker/docker-compose.yml up -d
```

#### Stop

```bash
docker compose --env-file .env -f docker/docker-compose.yml down
```

#### Restart (after config changes)

```bash
docker compose --env-file .env -f docker/docker-compose.yml up -d --force-recreate
```

#### Logs

```bash
docker compose --env-file .env -f docker/docker-compose.yml logs -f server
```

#### Update (rebuild + restart)

```bash
git pull
docker compose --env-file .env -f docker/docker-compose.yml build
docker compose --env-file .env -f docker/docker-compose.yml up -d --force-recreate
```

> **Note:** `SERVER_ADDR` must be set to `0.0.0.0:8080` inside Docker containers. The port mapping in `docker-compose.yml` (`127.0.0.1:8080:8080`) ensures the server is only reachable via localhost on the host. A reverse proxy is **required** for TLS termination — see [Reverse Proxy Setup](#reverse-proxy-setup) below.

## CLI Tool

The `shellvault-cli` binary is included in the Docker image and provides admin commands for user management, billing, and database backups.

### Using the CLI in Docker

Run CLI commands via `docker compose exec` against the running server container:

```bash
# Shorthand (set once)
COMPOSE="docker compose --env-file .env -f docker/docker-compose.yml"

# User management
$COMPOSE exec server ./shellvault-cli user list
$COMPOSE exec server ./shellvault-cli user list --all        # include deleted
$COMPOSE exec server ./shellvault-cli user info user@example.com
$COMPOSE exec server ./shellvault-cli user deactivate user@example.com
$COMPOSE exec server ./shellvault-cli user activate user@example.com
$COMPOSE exec server ./shellvault-cli user delete user@example.com
$COMPOSE exec server ./shellvault-cli user delete user@example.com --hard

# Billing / subscriptions
$COMPOSE exec server ./shellvault-cli billing info user@example.com
$COMPOSE exec server ./shellvault-cli billing set user@example.com --days 365
$COMPOSE exec server ./shellvault-cli billing set user@example.com --provider stripe --status active --days 30
$COMPOSE exec server ./shellvault-cli billing revoke user@example.com

# Database backups (manual)
$COMPOSE exec server ./shellvault-cli backup create
$COMPOSE exec server ./shellvault-cli backup list
$COMPOSE exec server ./shellvault-cli backup restore /app/backups/shellvault_20260304_120000.sql.gz
```

### Automatic Backups

The `docker-compose.yml` includes a dedicated `backup` service that runs `shellvault-cli backup auto` as a daemon. It creates compressed pg_dump backups on a configurable interval and prunes old backups automatically.

Configure via environment variables:

| Variable | Default | Description |
|---|---|---|
| `BACKUP_DIR` | `/app/backups` | Backup storage directory |
| `BACKUP_INTERVAL` | `24h` | Time between backups |
| `BACKUP_RETENTION` | `7` | Number of backups to keep |

The backup service starts automatically with `docker compose up -d`. To check its status:

```bash
$COMPOSE logs -f backup
```

### Local Development (without Docker)

```bash
make build-cli
./bin/shellvault-cli user list
./bin/shellvault-cli backup create -o ./backups
```

### CLI Command Reference

#### User Management

| Command | Description |
|---|---|
| `user list [--all]` | List users (optionally include deleted) |
| `user info <email-or-id>` | Show user profile, subscription, vault, devices |
| `user delete <email-or-id> [--hard]` | Soft delete (default) or permanent delete with CASCADE |
| `user deactivate <email-or-id>` | Soft delete + revoke all sessions |
| `user activate <email-or-id>` | Reactivate a deactivated user |
| `user logout <email-or-id>` | Revoke all sessions without deactivating |
| `user devices <email-or-id>` | List registered devices |
| `user delete-device <email-or-id> <device-id>` | Remove a specific device |
| `user audit <email-or-id> [-n LIMIT]` | Show audit log (default: last 50 entries) |
| `user reset-vault <email-or-id>` | Delete user's encrypted vault and history |

#### Billing

| Command | Description |
|---|---|
| `billing info <email-or-id>` | Show subscription history |
| `billing set <email-or-id> [--provider] [--status] [--days]` | Create or update subscription |
| `billing revoke <email-or-id>` | Cancel all subscriptions |
| `billing sync` | Reconcile active subscriptions against provider APIs |

#### Database Backup

| Command | Description |
|---|---|
| `backup create [-o DIR]` | Create compressed database backup + manifest |
| `backup list` | List available backups |
| `backup restore <file> [--no-reconcile]` | Restore database with post-restore reconciliation |
| `backup auto` | Start backup daemon (reads interval from ENV) |

## Reverse Proxy Setup

The server does not handle TLS itself. You **must** place a reverse proxy in front of it. Below are production-ready configurations for Traefik and Caddy.

### Option A: Caddy (Recommended)

Caddy handles TLS certificates automatically via Let's Encrypt.

Create `/etc/caddy/Caddyfile`:

```caddyfile
api.example.com {
    reverse_proxy 127.0.0.1:8080

    header {
        -Server
    }

    log {
        output file /var/log/caddy/shellvault.log
        format json
    }
}
```

```bash
sudo systemctl enable --now caddy
```

Set in `.env`:

```
TRUSTED_PROXIES=127.0.0.1/8,::1/128
API_BASE_URL=https://api.example.com
```

### Option B: Traefik

Create `traefik/docker-compose.override.yml` alongside the main compose file:

```yaml
services:
  traefik:
    image: traefik:v3.0
    command:
      - "--api.dashboard=false"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--entrypoints.web.http.redirections.entryPoint.to=websecure"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
      - "--certificatesresolvers.letsencrypt.acme.email=admin@example.com"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - letsencrypt:/letsencrypt
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true

  server:
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.shellvault.rule=Host(`api.example.com`)"
      - "traefik.http.routers.shellvault.tls.certresolver=letsencrypt"
      - "traefik.http.services.shellvault.loadbalancer.server.port=8080"

volumes:
  letsencrypt:
```

```bash
docker compose -f docker/docker-compose.yml -f traefik/docker-compose.override.yml up -d
```

Set in `.env`:

```
TRUSTED_PROXIES=172.16.0.0/12
API_BASE_URL=https://api.example.com
```

Use the Docker network CIDR as trusted proxy range when Traefik runs in the same Docker network.

## API

Base URL: `https://api.example.com`

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/health` | GET | No | Liveness check |
| `/ready` | GET | No | Readiness check |
| `/v1/auth/challenge` | GET | No | Get PoW challenge |
| `/v1/auth/register` | POST | No | Register with email + password |
| `/v1/auth/login` | POST | No | Login → access + refresh token |
| `/v1/auth/refresh` | POST | No | Rotate tokens |
| `/v1/auth/logout` | POST | No | Revoke refresh token |
| `/v1/auth/logout-all` | POST | Yes | Revoke all sessions |
| `/v1/auth/verify-email` | GET | No | Verify email via token |
| `/v1/auth/forgot-password` | POST | No | Send password reset link |
| `/v1/auth/reset-password` | POST | No | Reset password via token |
| `/v1/vault` | GET | Yes | Get encrypted vault blob |
| `/v1/vault` | PUT | Yes | Upload vault (optimistic locking) |
| `/v1/vault/history` | GET | Yes | Version history |
| `/v1/vault/history/{version}` | GET | Yes | Retrieve historical version |
| `/v1/user` | GET/PUT/DELETE | Yes | User profile management |
| `/v1/user/password` | PUT | Yes | Change password |
| `/v1/devices` | GET/POST | Yes | List / register devices |
| `/v1/devices/{id}` | DELETE | Yes | Remove device |
| `/v1/billing/status` | GET | Yes | Subscription status |
| `/v1/billing/checkout` | POST | Yes | Create Stripe checkout |
| `/v1/billing/portal` | POST | Yes | Stripe customer portal |
| `/v1/webhooks/stripe` | POST | No | Stripe webhook |
| `/v1/webhooks/apple` | POST | No | Apple App Store webhook |
| `/v1/webhooks/google` | POST | No | Google Play webhook |
| `/v1/audit` | GET | Yes | User activity log |
| `/v1/attestation` | GET | No | Server attestation (signed JWT) |

Full OpenAPI spec: [`api/openapi.yaml`](api/openapi.yaml)

## Stripe Webhooks

When using Stripe billing, you must configure a webhook endpoint in the [Stripe Dashboard](https://dashboard.stripe.com/webhooks):

**Endpoint URL:** `https://api.example.com/v1/webhooks/stripe`

**Required events (Webhook scope):**

| Event | Purpose |
|---|---|
| `checkout.session.completed` | Activates subscription after successful payment |
| `customer.subscription.updated` | Syncs plan changes, renewals, and payment failures |
| `customer.subscription.deleted` | Marks subscription as canceled |

Set `STRIPE_WEBHOOK_SECRET` in your `.env` to the signing secret from the Stripe Dashboard (starts with `whsec_`). The server verifies every webhook signature — unsigned or tampered payloads are rejected.

**Minimal setup:**

1. Go to [Stripe Dashboard → Webhooks](https://dashboard.stripe.com/webhooks)
2. Click "Add endpoint"
3. Enter your endpoint URL
4. Select the three events listed above
5. Copy the signing secret into `STRIPE_WEBHOOK_SECRET`

## Configuration

See [`.env.example`](.env.example) for all configuration options.

Key environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `SERVER_ADDR` | No | `127.0.0.1:8080` | Bind address (`0.0.0.0:8080` for Docker) |
| `TRUSTED_PROXIES` | No | `127.0.0.1/8,::1/128` | CIDR ranges of trusted reverse proxies |
| `JWT_PRIVATE_KEY_PATH` | No | `./keys/ed25519.pem` | Path to Ed25519 PEM key (auto-generated if missing) |
| `STRIPE_SECRET_KEY` | No | — | Enables billing when set |
| `SMTP_HOST` | No | — | Enables email sending when set |
| `POSTGRES_PASSWORD` | Yes | — | PostgreSQL password (Docker Compose) |

## Self-Hosted

For self-hosted instances:
- Leave `STRIPE_SECRET_KEY` empty → billing is disabled, sync always allowed
- Leave `SMTP_HOST` empty → emails logged to stdout
- All data remains encrypted — the server cannot read vault contents
- Set `TRUSTED_PROXIES` to match your reverse proxy's IP/network
- **Never expose port 8080 directly to the internet** — always use a reverse proxy with TLS

## Security

### Server Hardening

- Binds to `127.0.0.1:8080` by default (not reachable from outside)
- Trusted proxy validation — `X-Forwarded-For` only accepted from configured CIDRs
- Aggressive timeouts: 2s header read, 5s body read, 10s write, 30s idle
- Request body limited to 10 MB, headers limited to 1 MB
- Docker containers: `read_only`, `no-new-privileges`, non-root user
- PostgreSQL port not exposed to host

### Cryptography

- Passwords: Argon2id (64 MB, 3 iterations, parallelism 4)
- JWT: Ed25519 signatures (no shared HMAC secrets)
- Refresh tokens: SHA-256 hashed in database

### Protection

- Rate limiting: 10 req/s global, 5 req/min on auth endpoints
- Brute force protection: account lockout after 5 failures, IP block after 20
- All queries parameterized (no SQL injection)
- Soft delete + 30-day purge for account deletion

### HTTP Headers

- `Strict-Transport-Security` with 2-year max-age and preload
- `Content-Security-Policy: default-src 'none'`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Embedder-Policy: require-corp`
- `Cross-Origin-Resource-Policy: same-origin`
- `Referrer-Policy: no-referrer`
- `Cache-Control: no-store`
- `Permissions-Policy` disables camera, microphone, geolocation, Topics API

## Documentation

Detailed integration guides are available in the [`docs/`](docs/) directory:

| Document | Description |
|----------|-------------|
| [Google Play Integration](docs/google-play-integration.md) | Full implementation guide for Google Play Billing |

## License

This project is licensed under the [MIT License](LICENSE).
