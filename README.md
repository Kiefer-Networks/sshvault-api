# ShellVault Server

Zero-Knowledge encrypted sync server for the ShellVault SSH client app.

Built by [Kiefer Networks](https://kiefer-networks.de).

## Architecture

ShellVault uses a Zero-Knowledge architecture: the server never sees plaintext data. Clients encrypt everything locally using AES-256-GCM with Argon2id key derivation. The server stores only opaque encrypted blobs.

### Key Features

- **Encrypted Blob Sync** with optimistic locking and version history
- **Ed25519 JWT authentication** with refresh token rotation
- **OAuth** (Apple Sign-In, Google Sign-In)
- **Billing** via Stripe, Apple App Store, Google Play
- **Self-Hosted friendly** — billing disabled when Stripe keys are absent

## Quick Start

### Prerequisites

- Go 1.22+
- PostgreSQL 16+
- Docker & Docker Compose (optional)

### Local Development

```bash
# Clone and setup
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

### Docker Compose (Full Stack)

```bash
cp .env.example .env
make docker-up
```

This starts the server, PostgreSQL, and Traefik (TLS).

## API

Base URL: `https://api.shellvault.app`

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/health` | GET | No | Liveness check |
| `/ready` | GET | No | Readiness check |
| `/v1/auth/register` | POST | No | Register with email + password |
| `/v1/auth/login` | POST | No | Login → access + refresh token |
| `/v1/auth/refresh` | POST | No | Rotate tokens |
| `/v1/auth/logout` | POST | No | Revoke refresh token |
| `/v1/auth/oauth/{provider}` | POST | No | OAuth login (apple, google) |
| `/v1/vault` | GET | Yes | Get encrypted vault blob |
| `/v1/vault` | PUT | Yes | Upload vault (optimistic locking) |
| `/v1/vault/history` | GET | Yes | Version history |
| `/v1/user` | GET/PUT/DELETE | Yes | User profile management |
| `/v1/user/password` | PUT | Yes | Change password |
| `/v1/devices` | GET | Yes | List devices |
| `/v1/devices/{id}` | DELETE | Yes | Remove device |
| `/v1/billing/status` | GET | Yes | Subscription status |
| `/v1/billing/checkout` | POST | Yes | Create Stripe checkout |
| `/v1/billing/portal` | POST | Yes | Stripe customer portal |

Full OpenAPI spec: [`api/openapi.yaml`](api/openapi.yaml)

## Configuration

See [`.env.example`](.env.example) for all configuration options.

Key environment variables:

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `JWT_PRIVATE_KEY_PATH` | No | Path to Ed25519 PEM key (auto-generated if missing) |
| `STRIPE_SECRET_KEY` | No | Enables billing when set |
| `SMTP_HOST` | No | Enables email sending when set |

## Self-Hosted

For self-hosted instances:
- Leave `STRIPE_SECRET_KEY` empty → billing is disabled, sync always allowed
- Leave `SMTP_HOST` empty → emails logged to stdout
- All data remains encrypted — the server cannot read vault contents

## Security

- Passwords: Argon2id (64 MB, 3 iterations, parallelism 4)
- JWT: Ed25519 signatures (no shared HMAC secrets)
- Refresh tokens: SHA-256 hashed in database
- Rate limiting: 5 req/min on auth endpoints
- All queries parameterized (no SQL injection)
- Soft delete + 30-day purge for account deletion
- TLS via Traefik reverse proxy

## License

Proprietary — Kiefer Networks. All rights reserved.
