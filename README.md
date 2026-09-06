<p align="center">
  <img src="api/logo.png" alt="SSHVault Server" width="128" height="128">
</p>

<h1 align="center">SSHVault Server</h1>

<p align="center">
  Zero-Knowledge encrypted sync server for the <a href="https://github.com/Kiefer-Networks/sshvault">SSHVault</a> SSH client app.
  <br>
  Built by <a href="https://kiefer-networks.de">Kiefer Networks</a>.
</p>

<p align="center">
  <a href="https://github.com/Kiefer-Networks/sshvault-api/releases"><img src="https://img.shields.io/github/v/release/Kiefer-Networks/sshvault-api?style=flat-square" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License: MIT"></a>
  <a href="https://github.com/Kiefer-Networks/sshvault-api/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Kiefer-Networks/sshvault-api/ci.yml?style=flat-square&label=CI" alt="CI"></a>
  <a href="https://github.com/Kiefer-Networks/sshvault-api/issues"><img src="https://img.shields.io/github/issues/Kiefer-Networks/sshvault-api?style=flat-square" alt="Issues"></a>
  <a href="https://github.com/Kiefer-Networks/sshvault-api/stargazers"><img src="https://img.shields.io/github/stars/Kiefer-Networks/sshvault-api?style=flat-square" alt="Stars"></a>
</p>

---

## Architecture

SSHVault uses a Zero-Knowledge architecture: the server never sees plaintext data. Clients encrypt everything locally using AES-256-GCM with Argon2id key derivation. The server stores only opaque encrypted blobs.

### Key Features

- **Encrypted Blob Sync** with optimistic locking and version history
- **Ed25519 JWT authentication** with refresh token rotation
- **Zero-Knowledge IP privacy** — no plaintext IPs stored anywhere (hashed for brute-force only)
- **Self-Hosted friendly** — server cannot read vault contents
- **Admin CLI** for user management and database backups

### Privacy by Design

The server follows strict privacy principles:

- **No IP logging** in application or audit logs
- **No plaintext IP storage** in the database — brute-force protection uses SHA-256 hashed IPs
- **Device tracking** records sync timestamps only, no IP addresses
- **Audit log anonymization** on account deletion (30-day grace period)

## Quick Start

### Prerequisites

- Go 1.27+
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

The `sshvault-cli` binary is included in the Docker image and provides admin commands for user management and database backups.

### Using the CLI in Docker

Run CLI commands via `docker compose exec` against the running server container:

```bash
# Shorthand (set once)
COMPOSE="docker compose --env-file .env -f docker/docker-compose.yml"

# User management
$COMPOSE exec server ./sshvault-cli user list
$COMPOSE exec server ./sshvault-cli user list --all        # include deleted
$COMPOSE exec server ./sshvault-cli user info user@example.com
$COMPOSE exec server ./sshvault-cli user deactivate user@example.com
$COMPOSE exec server ./sshvault-cli user activate user@example.com
$COMPOSE exec server ./sshvault-cli user delete user@example.com
$COMPOSE exec server ./sshvault-cli user delete user@example.com --hard

# Database backups (manual)
$COMPOSE exec backup ./sshvault-cli backup create
$COMPOSE exec backup ./sshvault-cli backup list
$COMPOSE exec backup ./sshvault-cli backup restore /app/backups/sshvault_20260304_120000.sql.gz
```

### Automatic Backups

The `docker-compose.yml` includes a dedicated `backup` service that runs `sshvault-cli backup auto` as a daemon. It creates compressed pg_dump backups on a configurable interval and prunes old backups automatically.

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
./bin/sshvault-cli user list
./bin/sshvault-cli backup create -o ./backups
```

### CLI Command Reference

#### User Management

| Command | Description |
|---|---|
| `user list [--all]` | List users (optionally include deleted) |
| `user info <email-or-id>` | Show user profile, vault, devices |
| `user delete <email-or-id> [--hard]` | Soft delete (default) or permanent delete with CASCADE |
| `user deactivate <email-or-id>` | Soft delete + revoke all sessions |
| `user activate <email-or-id>` | Reactivate a deactivated user |
| `user logout <email-or-id>` | Revoke all sessions without deactivating |
| `user devices <email-or-id>` | List registered devices |
| `user delete-device <email-or-id> <device-id>` | Remove a specific device |
| `user audit <email-or-id> [-n LIMIT]` | Show audit log (default: last 50 entries) |
| `user reset-vault <email-or-id>` | Delete user's encrypted vault and history |

#### Database Backup

| Command | Description |
|---|---|
| `backup create [-o DIR]` | Create compressed database backup + manifest |
| `backup list` | List available backups |
| `backup restore <file> [--no-reconcile]` | Restore database with post-restore reconciliation |
| `backup auto` | Start backup daemon (reads interval from ENV) |

Keep each `.sql.gz` dump together with its `.manifest.json` sidecar. Both are captured from one PostgreSQL snapshot; the versioned sidecar contains the dump's SHA-256 digest. Restore rejects missing, legacy, or mismatched sidecars before changing the database. Temporary `.partial` files are incomplete backups and are not listed or retained as completed backups.

Restore pauses account mutations and other restores with a database maintenance lock, captures retained deletions after acquiring that lock, and preserves the latest deletion timestamp during reconciliation. All restored sessions and verification tokens are invalidated in the restore transaction. The explicit `--no-reconcile` override permits old or unbound backups and skips deleted-account preservation; it still invalidates tokens and holds the maintenance lock. Server and CLI processes must run the updated code to participate in this coordination.

## Reverse Proxy Setup

The server does not handle TLS itself. You **must** place a reverse proxy in front of it. Below are production-ready configurations for Caddy, Nginx, Apache, and Traefik.

Each configuration includes optional security hardening directives (commented out). Uncomment the ones you need based on your threat model.

### Option A: Caddy (Recommended)

Caddy handles TLS certificates automatically via Let's Encrypt.

Create a site config (e.g. `/etc/caddy/sites/sshvault.conf`):

```caddyfile
api.example.com {
    # --- TLS Configuration ---
    # Automatic HTTPS via Let's Encrypt by default.
    # Uncomment to enforce TLS 1.3 only with strong ciphers:
    # tls you@example.com {
    #     protocols tls1.3
    #     ciphers TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256
    #     curves x25519 secp384r1
    # }

    # --- Security Headers ---
    # Remove server identity headers to reduce information leakage:
    header {
        -Server
        -X-Powered-By
    }
    # Uncomment to add strict security headers:
    # header {
    #     # Forces HTTPS for 2 years, including subdomains; submits to browser preload list:
    #     Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    #     # Prevents MIME-type sniffing, which can lead to XSS via content-type confusion:
    #     X-Content-Type-Options "nosniff"
    #     # Blocks the page from being embedded in iframes, preventing clickjacking attacks:
    #     X-Frame-Options "DENY"
    #     # Controls how much referrer info is sent with requests to other origins:
    #     Referrer-Policy "strict-origin-when-cross-origin"
    #     # Disables browser features (camera, mic, geolocation) that this API does not need:
    #     Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
    #     # Disables the legacy XSS filter (modern browsers handle this natively):
    #     X-XSS-Protection "0"
    #     # Prevents the page from being paired with cross-origin popups (isolation):
    #     Cross-Origin-Opener-Policy "same-origin"
    #     # Restricts which origins can load this resource (same-origin only):
    #     Cross-Origin-Resource-Policy "same-origin"
    # }

    # --- Request Size Limit ---
    # Limits the maximum request body size to prevent abuse:
    request_body {
        max_size 21037056
    }

    # --- Route Filtering ---
    # Only proxy known API paths; redirect everything else to the app:
    @api_paths {
        path /health /ready /docs /docs/* /favicon.ico /v1/*
    }
    @not_api {
        not path /health /ready /docs /docs/* /favicon.ico /v1/*
    }
    redir @not_api https://your-app-domain.com{uri} permanent

    # --- Reverse Proxy ---
    # Forwards requests to the SSHVault API server running on localhost:
    reverse_proxy @api_paths 127.0.0.1:8080 {
        # Passes the real client IP to the backend for rate limiting:
        header_up X-Real-IP {remote_host}
        header_up Host {host}

        # Uncomment to set upstream timeouts (prevents hanging connections):
        # transport http {
        #     read_timeout 180s
        #     write_timeout 180s
        #     dial_timeout 5s
        # }
    }

    # --- Logging ---
    # Writes access logs in JSON format with automatic rotation:
    log {
        output file /var/log/caddy/sshvault_api.log {
            roll_size 100MiB
            roll_keep 10
        }
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

### Option B: Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name api.example.com;

    # --- TLS Configuration ---
    # Paths to your SSL certificate and private key (e.g. from Let's Encrypt):
    ssl_certificate     /etc/letsencrypt/live/api.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;

    # Uncomment to enforce TLS 1.2+ with strong ciphers only:
    # ssl_protocols TLSv1.2 TLSv1.3;
    # ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    # ssl_prefer_server_ciphers on;
    # Uncomment to enable OCSP stapling (validates certificate status without client lookup):
    # ssl_stapling on;
    # ssl_stapling_verify on;

    # --- Security Headers ---
    # Uncomment to add strict security headers:
    # # Forces HTTPS for 2 years, including subdomains; submits to browser preload list:
    # add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    # # Prevents MIME-type sniffing, which can lead to XSS via content-type confusion:
    # add_header X-Content-Type-Options "nosniff" always;
    # # Blocks the page from being embedded in iframes, preventing clickjacking attacks:
    # add_header X-Frame-Options "DENY" always;
    # # Controls how much referrer info is sent with requests to other origins:
    # add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    # # Disables browser features (camera, mic, geolocation) that this API does not need:
    # add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=()" always;
    # # Prevents the page from being paired with cross-origin popups (isolation):
    # add_header Cross-Origin-Opener-Policy "same-origin" always;
    # # Restricts which origins can load this resource (same-origin only):
    # add_header Cross-Origin-Resource-Policy "same-origin" always;

    # Hides the Nginx version from response headers to reduce information leakage:
    server_tokens off;

    # --- Request Size Limit ---
    # Limits the maximum request body size to prevent abuse:
    client_max_body_size 21037056;

    # --- Reverse Proxy ---
    location / {
        # Forwards requests to the SSHVault API server running on localhost:
        proxy_pass http://127.0.0.1:8080;
        # Passes the real client IP to the backend for rate limiting:
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;

        # Uncomment to set upstream timeouts (prevents hanging connections):
        # proxy_connect_timeout 5s;
        # proxy_read_timeout 180s;
        # proxy_send_timeout 180s;
    }

    # --- Logging ---
    access_log /var/log/nginx/sshvault_api_access.log;
    error_log  /var/log/nginx/sshvault_api_error.log;
}

# --- HTTP to HTTPS Redirect ---
# Redirects all plain HTTP traffic to HTTPS:
server {
    listen 80;
    server_name api.example.com;
    return 301 https://$host$request_uri;
}
```

```bash
sudo ln -s /etc/nginx/sites-available/sshvault-api /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Set in `.env`:

```
TRUSTED_PROXIES=127.0.0.1/8,::1/128
API_BASE_URL=https://api.example.com
```

### Option C: Apache

```apache
<VirtualHost *:443>
    ServerName api.example.com

    # --- TLS Configuration ---
    # Enable SSL and set certificate paths (e.g. from Let's Encrypt):
    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/api.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/api.example.com/privkey.pem

    # Uncomment to enforce TLS 1.2+ with strong ciphers only:
    # SSLProtocol -all +TLSv1.2 +TLSv1.3
    # SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    # SSLHonorCipherOrder on

    # --- Security Headers ---
    # Uncomment to add strict security headers:
    # # Forces HTTPS for 2 years, including subdomains; submits to browser preload list:
    # Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    # # Prevents MIME-type sniffing, which can lead to XSS via content-type confusion:
    # Header always set X-Content-Type-Options "nosniff"
    # # Blocks the page from being embedded in iframes, preventing clickjacking attacks:
    # Header always set X-Frame-Options "DENY"
    # # Controls how much referrer info is sent with requests to other origins:
    # Header always set Referrer-Policy "strict-origin-when-cross-origin"
    # # Disables browser features (camera, mic, geolocation) that this API does not need:
    # Header always set Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
    # # Prevents the page from being paired with cross-origin popups (isolation):
    # Header always set Cross-Origin-Opener-Policy "same-origin"
    # # Restricts which origins can load this resource (same-origin only):
    # Header always set Cross-Origin-Resource-Policy "same-origin"

    # Hides the Apache version and OS from response headers:
    ServerSignature Off
    Header always unset X-Powered-By

    # --- Request Size Limit ---
    # Limits the maximum request body size to allow a 15 MiB vault plus Base64/JSON overhead:
    LimitRequestBody 21037056

    # --- Reverse Proxy ---
    # Required modules: mod_proxy, mod_proxy_http, mod_headers
    ProxyPreserveHost On
    # Forwards requests to the SSHVault API server running on localhost:
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/

    # Passes the real client IP to the backend for rate limiting:
    RequestHeader set X-Real-IP "%{REMOTE_ADDR}e"
    RequestHeader set X-Forwarded-Proto "https"

    # Uncomment to set upstream timeouts (prevents hanging connections):
    # ProxyTimeout 10
    # Timeout 15

    # --- Logging ---
    ErrorLog  /var/log/apache2/sshvault_api_error.log
    CustomLog /var/log/apache2/sshvault_api_access.log combined
</VirtualHost>

# --- HTTP to HTTPS Redirect ---
# Redirects all plain HTTP traffic to HTTPS:
<VirtualHost *:80>
    ServerName api.example.com
    Redirect permanent / https://api.example.com/
</VirtualHost>
```

```bash
sudo a2enmod proxy proxy_http headers ssl
sudo a2ensite sshvault-api
sudo apachectl configtest && sudo systemctl reload apache2
```

Set in `.env`:

```
TRUSTED_PROXIES=127.0.0.1/8,::1/128
API_BASE_URL=https://api.example.com
```

### Option D: Traefik

Create `traefik/docker-compose.override.yml` alongside the main compose file:

```yaml
services:
  traefik:
    image: traefik:v3.0
    command:
      # Disable the dashboard (not needed for API-only usage):
      - "--api.dashboard=false"
      # Enable Docker provider to auto-discover services by labels:
      - "--providers.docker=true"
      # Do not expose containers by default (only labeled ones):
      - "--providers.docker.exposedbydefault=false"
      # Listen on port 80 for HTTP and port 443 for HTTPS:
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      # Redirect all HTTP traffic to HTTPS automatically:
      - "--entrypoints.web.http.redirections.entryPoint.to=websecure"
      # Use Let's Encrypt HTTP challenge for automatic TLS certificates:
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
      - "--certificatesresolvers.letsencrypt.acme.email=admin@example.com"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
      # Uncomment to enforce TLS 1.3 only:
      # - "--entrypoints.websecure.http.tls.options=strict@file"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - letsencrypt:/letsencrypt
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    networks:
      - proxy
    # Uncomment to add security headers via middleware labels:
    # labels:
    #   # Forces HTTPS for 2 years, including subdomains:
    #   - "traefik.http.middlewares.security-headers.headers.stsSeconds=63072000"
    #   - "traefik.http.middlewares.security-headers.headers.stsIncludeSubdomains=true"
    #   - "traefik.http.middlewares.security-headers.headers.stsPreload=true"
    #   # Prevents MIME-type sniffing:
    #   - "traefik.http.middlewares.security-headers.headers.contentTypeNosniff=true"
    #   # Blocks embedding in iframes:
    #   - "traefik.http.middlewares.security-headers.headers.frameDeny=true"
    #   # Controls referrer info sent to other origins:
    #   - "traefik.http.middlewares.security-headers.headers.referrerPolicy=strict-origin-when-cross-origin"

  server:
    labels:
      # Enable Traefik for this container:
      - "traefik.enable=true"
      # Route requests for api.example.com to this service:
      - "traefik.http.routers.sshvault.rule=Host(`api.example.com`)"
      # Use Let's Encrypt for automatic TLS certificates:
      - "traefik.http.routers.sshvault.tls.certresolver=letsencrypt"
      # Forward traffic to port 8080 inside the container:
      - "traefik.http.services.sshvault.loadbalancer.server.port=8080"
      # Uncomment to apply the security headers middleware:
      # - "traefik.http.routers.sshvault.middlewares=security-headers"

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
| `/v1/auth/register` | POST | No | Opaque registration acceptance; mailbox verification required |
| `/v1/auth/login` | POST | No | Login → access + refresh token |
| `/v1/auth/refresh` | POST | No | Rotate tokens |
| `/v1/auth/logout` | POST | No | Revoke refresh token |
| `/v1/auth/logout-all` | POST | Yes | Revoke all sessions |
| `/v1/auth/verify-email` | GET | No | Preview activation password form without consuming token |
| `/v1/auth/verify-email` | POST | No | Verify mailbox; activate a new account with token and owner-chosen `new_password` |
| `/v1/auth/confirm-email-change` | GET/POST | No | Preview confirmation / explicitly confirm email and revoke sessions |
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
| `/v1/user/avatar` | PUT | Yes | Update avatar (base64, max 512 KB) |
| `/v1/user/avatar` | DELETE | Yes | Delete avatar |
| `/v1/audit` | GET | Yes | User activity log |
| `/v1/attestation` | GET | No | Server attestation (Ed25519 signed) |
| `/v1/attestation/pubkey` | GET | No | Attestation public key (for TOFU pinning) |

Registration returns HTTP `202` with exactly:

```json
{"status":"If registration is available, check your email to verify your account."}
```

New, existing, and soft-deleted addresses receive the same response. Registration returns no account identifiers or access/refresh tokens. Each valid signup attempt performs the same expensive password hashing before account-existence checks, then discards that hash. The signup password never becomes credentials. New accounts have cryptographically random, unusable password values until the mailbox owner chooses a password during activation. Login before activation returns HTTP `401` with `{"error":"invalid credentials"}`; protected access for a new unverified account returns `403` with `{"error":"verification_required"}`.

The verification email links to `GET /v1/auth/verify-email?token=...`, a non-mutating password-entry form. Opening or scanning the link does not activate the account or consume the token. Submit the form or call `POST /v1/auth/verify-email` with `{"token":"...","new_password":"your-chosen-password"}` (8�256 bytes). The single-use POST atomically verifies the mailbox and installs the owner's chosen password for a new account, independent of every password previously submitted at registration. A link from an earlier signup request is safe to use with your own password. Existing grandfathered verification links only mark the address verified and preserve existing credentials. Links expire after 24 hours; activation does not return session tokens, so sign in afterwards.

Verification, recovery, and email-change delivery each have a database-enforced 60-second cooldown per normalized recipient and purpose, shared across clients, IPs, and server processes. Only a recipient digest is stored in the budget table. At most one unused token exists per account and purpose. A throttled signup keeps the same opaque response, sends no mail, and preserves the existing viable link. Only an admitted resend after the cooldown replaces it.

SMTP runs through a bounded queue (128 messages, two workers), so SMTP latency never blocks registration responses. Queue saturation and delivery failure preserve registration's opaque result; retry after the cooldown. Mail draining shares the single process shutdown deadline; SMTP observes cancellation and separate connection, command-I/O, and overall deadlines. Configured SMTP requires certificate-verified TLS 1.2 or newer: port 465 uses implicit TLS, and other ports require STARTTLS. No credentials or message content are sent before TLS succeeds. If SMTP credentials are configured, missing or rejected AUTH fails delivery; plaintext fallback is never used. Trusted certificates must match `SMTP_HOST`.

HTTP JSON errors and other JSON responses up to 64 KiB are padded to 1 KiB boundaries and remain uncompressed, including early `400`, `413`, and `429` rejections. CORS and security headers wrap these rejection paths. Opaque vault/history blobs stream as JSON with optional gzip; they are not padded. Larger general responses also bypass buffering after 64 KiB. Existing vaults above 15 MiB remain readable, exportable, and available in history; only new/replacement writes (including client imports through the write endpoint) use the 15 MiB ceiling. Requests must contain exactly one JSON value. Configure proxy request limits to **21,037,056 bytes** for the default Base64 JSON envelope; a decoded blob of 15,728,641 bytes returns `413` even when its wire body fits.

Trusted proxy processing validates every forwarded IP and walks the chain from right to left through explicitly trusted hops. The first untrusted hop is the client; untrusted direct callers cannot supply forwarding addresses. Malformed forwarding from a trusted proxy returns `400`. `TRUSTED_PROXIES` accepts IPs/CIDRs; an empty value trusts no proxy. Public URLs and CORS origins, ports, limits, rates, durations, and timeout ordering are validated before runtime resources start.

Process shutdown uses one **30-second total budget** by default. HTTP receives at most two thirds for graceful drain, then remaining connections are closed. Background cancellation, mail/audit drain, rate-limiter joins, and database-pool closure share the remaining deadline. Stuck handlers or repositories cannot hold process return indefinitely. Audit and mail shutdown report entries/messages whose successful delivery is unconfirmed, including queued work abandoned at the deadline. A non-cooperative operation may finish later; shutdown never claims that such an in-flight entry was persisted.

JWT signing keys are generated only when the configured path does not exist, published without overwriting another key, and synced before use. Corrupt, unreadable, insecure Unix permissions, and persistence failures abort startup. Existing keys are never silently replaced. On Windows, provision the key directory with an appropriate owner-only ACL; Unix mode bits do not express Windows ACLs.

Migration `023` explicitly marks pre-upgrade accounts as `verification_grandfathered`, including those whose `verified` value is false. Their existing sessions, login, and synchronization remain authorized. New accounts default to requiring verification; the migration does not rewrite actual mailbox verification status. Downgrade is refused while any new unverified account would lose that distinction; a later re-upgrade cannot silently grandfather it. Migration `024` removes the obsolete requester-password column from databases that applied an earlier draft, randomizes pending-account password placeholders, and preserves viable mailbox tokens. Its down migration restores only an empty compatibility column; discarded requester hashes are never restored. Deploy this code with all migrations applied.


Login reserves each attempt atomically before password verification. Up to five pending or failed attempts per normalized email, and twenty per IP across accounts, are admitted within fifteen minutes. Successful authentication clears completed older failures while preserving pending and newer attempts. Cancelled requests remain charged until the window expires.

Refresh tokens rotate once within a persistent family. Reusing a consumed refresh token revokes every access and refresh session for that account. Clients must serialize refresh requests; concurrent reuse causes session revocation even when one rotation succeeds. Upgrading preserves live refresh tokens and assigns their family and current session version. Consumed family history stays until the last descendant expires. Migration 025 is forward-only because dropping this history would disable replay protection.

PoW difficulty increases only for accepted work. Verification enforces both the issued and current difficulty, and consumes the challenge on submission. Obtain a fresh challenge after rejection. Access JWTs require issuer sshvault, audience sshvault-api, a user UUID subject, expiry, issued-at, and a nonnegative session version matching the account.

To change email, send `PUT /v1/user` with `{"email":"new@example.com","current_password":"your-current-password"}`. A successful request returns HTTP `202` and `{"status":"pending_confirmation"}`. The old address remains active for login and password recovery, and keeps its verified state. The profile exposes `pending_email` until confirmation. The email sent to the pending address links to `GET /v1/auth/confirm-email-change?token=...`, a non-mutating preview page. The token is valid for one hour. The user must submit the confirmation form, or call `POST /v1/auth/confirm-email-change` with `{"token":"..."}`. GETs, including mail-scanner visits, never consume the token. The explicit POST installs and verifies the new address, clears the pending value, revokes every access/refresh session and obsolete email/reset token, and requires a fresh login. Replacing a pending request invalidates its previous confirmation link. Changing or resetting the password cancels pending email changes and unconfirmed signup links. Requests that keep the existing email, empty profile updates, and avatar updates retain their existing response shape.

Full OpenAPI spec: [`api/openapi.yaml`](api/openapi.yaml)

## Configuration

See [`.env.example`](.env.example) for all configuration options.

Key environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| **Server** | | | |
| `SERVER_READ_HEADER_TIMEOUT` | No | `2s` | Maximum header read time |
| `SERVER_READ_TIMEOUT` | No | `120s` | Maximum request read time |
| `SERVER_REQUEST_TIMEOUT` | No | `180s` | Context deadline for handler/database work |
| `SERVER_WRITE_TIMEOUT` | No | `180s` | Maximum response write time |
| `SERVER_IDLE_TIMEOUT` | No | `30s` | Idle keep-alive timeout |
| `SERVER_SHUTDOWN_TIMEOUT` | No | `30s` | Single total shutdown budget |
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `POSTGRES_PASSWORD` | Yes | — | PostgreSQL password (Docker Compose) |
| `HOST_PORT` | No | `127.0.0.1:8080` | Host-side port mapping for Docker Compose |
| `SERVER_ADDR` | No | `127.0.0.1:8080` | Bind address (`0.0.0.0:8080` for Docker) |
| `SERVER_ENV` | No | `production` | `production` or `development` |
| `SERVER_ID` | No | `sshvault-primary` | Server identity for attestation |
| `APP_BASE_URL` | No | `https://app.example.com` | Frontend URL (for emails, redirects) |
| `API_BASE_URL` | No | `https://api.example.com` | Public API URL |
| `TRUSTED_PROXIES` | No | `127.0.0.1/8,::1/128` | CIDR ranges of trusted reverse proxies |
| `CORS_ORIGINS` | No | — | Comma-separated allowed origins |
| **Auth** | | | |
| `JWT_PRIVATE_KEY_PATH` | No | `./keys/ed25519.pem` | Path to Ed25519 PEM key (auto-generated) |
| `JWT_ACCESS_TTL` | No | `15m` | Access token lifetime |
| `JWT_REFRESH_TTL` | No | `720h` | Refresh token lifetime |
| **Mail** | | | |
| `SMTP_HOST` | No | — | Enables email sending when set |
| `SMTP_PORT` | No | `587` | `465` uses implicit TLS; all other ports require STARTTLS |
| `SMTP_USER` | No | — | SMTP username |
| `SMTP_PASS` | No | — | SMTP password |
| `SMTP_CONNECT_TIMEOUT` | No | `10s` | Connection deadline |
| `SMTP_COMMAND_TIMEOUT` | No | `10s` | Deadline for each SMTP read/write operation |
| `SMTP_DELIVERY_TIMEOUT` | No | `30s` | Overall delivery deadline including connection |
| `SMTP_FROM` | No | `noreply@example.com` | Sender address |
| **Vault** | | | |
| `VAULT_MAX_SIZE_MB` | No | `15` | Decoded write limit in MiB; may be reduced, never raised above 15 |
| `VAULT_HISTORY_LIMIT` | No | `10` | Maximum stored vault versions |
| **Rate Limiting** | | | |
| `RATE_LIMIT_RPS` | No | `10` | Requests per second (global) |
| `RATE_LIMIT_BURST` | No | `20` | Burst capacity |
| **Backup** | | | |
| `BACKUP_DIR` | No | `./backups` | Backup directory path |
| `BACKUP_INTERVAL` | No | `24h` | Auto-backup interval |
| `BACKUP_RETENTION` | No | `7` | Number of backups to keep |
| **Logging** | | | |
| `LOG_FILE_PATH` | No | — | Log file path (empty = stdout only) |
| `LOG_MAX_SIZE_MB` | No | `100` | Max log file size before rotation |
| `LOG_MAX_AGE_DAYS` | No | `90` | Max log file age |
| `LOG_MAX_BACKUPS` | No | `10` | Number of rotated log files to keep |
| `LOG_COMPRESS` | No | `true` | Compress rotated log files |
| **Audit** | | | |
| `AUDIT_RETENTION_DAYS` | No | `365` | Audit log retention period |
| `AUDIT_BUFFER_SIZE` | No | `4096` | Audit event buffer size |

## Self-Hosted

For self-hosted instances:
- Leave `SMTP_HOST` empty to deliver email bodies through stdout. Activation and password-reset links are included, so restrict access to these logs and configure SMTP for internet-facing installations.
- All data remains encrypted — the server cannot read vault contents
- Set `TRUSTED_PROXIES` to match your reverse proxy's IP/network
- **Never expose port 8080 directly to the internet** — always use a reverse proxy with TLS

## Security

### Zero-Knowledge Privacy

- **No plaintext IPs** stored in the database or log files
- Brute-force protection uses SHA-256 hashed IPs (irreversible)
- Device sync tracking stores timestamps only, no network metadata
- Audit logs contain no IP addresses
- All vault data is encrypted client-side — server stores only opaque blobs

### Server Hardening

- Binds to `127.0.0.1:8080` by default (not reachable from outside)
- Trusted proxy validation — `X-Forwarded-For` only accepted from configured CIDRs
- Aggressive timeouts: 2s header read, 120s body read, 180s write, 30s idle
- Vault uploads accept exactly 15 MiB (15,728,640 bytes) of decoded data at the default limit (20 MiB Base64 plus 64 KiB JSON envelope; 21,037,056 bytes on the wire); other request bodies remain limited to 10 MiB, headers to 1 MiB
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

## Related

- [SSHVault App](https://github.com/Kiefer-Networks/sshvault) — Flutter client (Android, iOS, macOS, Linux, Windows)
- [Google Play](https://play.google.com/store/apps/details?id=de.kiefer_networks.sshvault) — Android download
- [API Documentation](api/openapi.yaml) — OpenAPI 3.1.0 specification

## Donate

If you find SSHVault useful, consider supporting development:

[Donate via Liberapay](https://de.liberapay.com/beli3ver)

## License

Copyright (C) 2024-2026 [Kiefer Networks](https://kiefer-networks.de)

This project is licensed under the [MIT License](LICENSE).
