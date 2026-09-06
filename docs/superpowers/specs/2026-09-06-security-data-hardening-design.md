# Security and Data Integrity Hardening Design

## Goal

Resolve every finding from the second deep review, reduce the decoded vault upload limit to 15 MiB, preserve access for existing installations, and make database upgrades, account lifecycle operations, backup/restore, and process shutdown deterministic under failure and concurrency.

## Compatibility guarantees

- Existing users remain able to sign in and synchronize after the upgrade. A migration treats accounts created before verification enforcement as grandfathered accounts; new accounts must verify their mailbox before protected API access is granted.
- Existing access and refresh tokens remain valid until their normal expiry unless the user changes security-sensitive account state or a refresh-token replay is detected.
- Existing vaults larger than 15 MiB remain readable and exportable. New and replacement uploads are limited to 15 MiB decoded data.
- Existing profile updates that do not change the email address retain their request shape. Email changes become a two-step flow and require the current password.
- Database migrations remain forward-only and must succeed both on an empty database and on a database containing audit rows with legacy IP values.

## Change groups

### Data integrity and lifecycle

Migration 020 must clear legacy audit IP values while the immutability trigger is safely disabled inside the migration transaction, then restore the trigger before commit. A migration regression test will apply the relevant old schema, insert a legacy row, and prove the upgrade succeeds and removes the IP.

User purge will move candidate selection, row locking, audit anonymization, child deletion, and user deletion into one database transaction. It will operate on a stable candidate set selected with row locks and return the identifiers actually purged. Reactivation uses the same user-row lock, so it completes either before the purge selection or after the purge, without an intermediate active account whose data has already been deleted. Hard delete will use the same anonymizing deletion primitive.

Failed authentication audits will store masked or keyed pseudonymous identifiers instead of plaintext email input. Audit entries that belong to a known user remain attributable through `actor_id` until the atomic purge anonymizes them.

### Backup and restore

Backup creation will open a repeatable-read transaction, export its PostgreSQL snapshot, capture the manifest in that snapshot, and run `pg_dump --snapshot` while the exporting transaction remains open. Dump and manifest will be written under temporary names, flushed, linked by a format version and dump digest, and only then renamed to their final names.

Restore will acquire an application-wide PostgreSQL advisory lock also observed by server-side account mutations and CLI lifecycle operations. It will capture current tombstones after taking that lock and hold the lock through the single-transaction restore and reconciliation. Reconciliation will preserve the later deletion timestamp when both restored data and the live manifest contain a tombstone. A missing or mismatched sidecar is an explicit error unless the operator supplies the existing override flag.

### Authentication

New registration returns the same generic response for new and existing addresses and does not expose account identifiers or usable full-access credentials. Existing accounts are grandfathered during migration; accounts created afterward must verify their mailbox before protected routes are available. Login for an unverified new account returns a stable verification-required response without exposing whether an arbitrary address exists through the registration endpoint.

Email change becomes a pending operation. The request requires the current password, stores `pending_email`, creates a purpose-specific single-use token, and sends confirmation to the new mailbox. Confirmation atomically installs the new address, clears the pending value, marks it verified, increments `session_version`, and revokes refresh tokens. The current address remains the recovery address until confirmation.

Login attempt admission and failure accounting will be serialized per normalized account identity in PostgreSQL. A request reserves an attempt before Argon2 verification, so concurrent guesses cannot all pass the pre-check. Successful authentication clears or supersedes the reserved failures atomically.

Refresh tokens gain a family identifier and consumed/replacement state. Reuse of a consumed token atomically revokes its family and increments `session_version`. Normal rotation consumes one token and creates exactly one successor in the same transaction.

PoW adaptive difficulty will count only valid completed work or measured accepted authentication load. Invalid challenge identifiers and nonces cannot raise global difficulty. Challenge verification validates the difficulty policy at consumption time so stockpiled low-difficulty challenges do not bypass current policy.

JWT validation will require issuer, audience, subject, expiry, issued-at, and session-version claims. Startup generates a signing key only when the configured path does not exist; malformed, unreadable, or unsavable key state aborts startup.

### Runtime and HTTP behavior

SMTP delivery will use a context-aware dialer with explicit connect, command, and overall timeouts. Registration and recovery responses will not wait indefinitely for SMTP. Process shutdown will have one total deadline: graceful HTTP drain, forced connection close, bounded audit flush, background cleanup, and process return all fit inside it.

Audit logger shutdown accepts a context and stops draining when its total deadline expires while reporting the number of discarded entries. It cannot spend one per-entry timeout for the entire configured buffer.

CORS and response normalization wrap middleware that can terminate early, so 413 and 429 responses retain CORS headers and the selected response-shaping policy. Compression will not invalidate the stated padding property. Forwarded client addresses are accepted only as syntactically valid IP addresses through a right-to-left chain of explicitly trusted proxy hops.

Configuration loading rejects non-positive durations, limits, rates, buffer sizes, retention values, invalid public URLs, malformed trusted-proxy entries, and invalid SMTP port values before starting goroutines or listeners.

Vault responses will avoid a second complete response-sized buffer. The response-padding policy applies only to bounded JSON responses; large opaque vault responses stream through JSON encoding/compression. Resource and concurrency tests will cover the 15 MiB maximum without allocating the former 75 MiB envelope.

Container runtime images, including PostgreSQL in Compose, will be digest pinned. CI will continue testing pinned actions, migration upgrades, PostgreSQL integration behavior, race-sensitive flows, image hardening, and the 15 MiB request boundary.

## API changes

- Registration returns a generic accepted response and requires mailbox verification for accounts created after this release.
- Protected access for a new unverified account returns `403 verification_required`.
- Email change requires `current_password` and returns a pending-confirmation response.
- A confirmation endpoint consumes the email-change token. Existing verification links remain supported for registration verification.
- Uploading decoded vault data above 15 MiB returns `413`; existing oversized stored data remains retrievable.

OpenAPI, README, environment examples, and reverse-proxy examples will describe these behaviors and exact limits.

## Testing and delivery

Each change group is implemented test-first on its own `codex/` branch. Regression tests must demonstrate the original failure before implementation and pass afterward. Database race tests use controlled concurrent transactions rather than timing sleeps. The final integration branch runs formatting, unit tests, PostgreSQL integration tests, race tests where supported, vet, vulnerability scanning, migration upgrade tests, Docker build/hardening checks, and documentation consistency checks.

All implementation branches are pushed. After review they are merged into `main`, `main` is pushed, and the complete remote CI run is monitored to a terminal result.
