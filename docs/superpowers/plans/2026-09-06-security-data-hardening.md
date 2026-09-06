# Security and Data Integrity Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix every finding from the second deep review while preserving existing installations and reducing new decoded vault uploads to 15 MiB.

**Architecture:** Changes are delivered in five independently reviewed branches and integrated in dependency order. PostgreSQL owns lifecycle atomicity; handlers expose explicit verification and conflict states; process and HTTP boundaries use total resource budgets.

**Tech Stack:** Go 1.26, PostgreSQL 16, golang-migrate, chi, pgx, Docker Compose, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-06-security-data-hardening-design.md`

## Global Constraints

- Existing accounts remain usable after upgrade.
- Existing vaults larger than 15 MiB remain readable; all new decoded uploads are limited to exactly 15 MiB.
- Migration upgrades must work with legacy audit IP rows.
- Security-sensitive state changes are atomic and retry-safe.
- No plaintext email input or IP address is retained in audit logs.
- Every branch uses focused red-green regression tests and is pushed before integration.

---

### Task 1: Atomic purge, audit privacy, and migration repair

**Branch:** `codex/data-integrity`

**Files:**
- Modify: `migrations/020_remove_ip_tracking.up.sql`
- Create: new forward migration(s) for atomic purge support
- Modify: `internal/repository/user_repo.go`
- Modify: `internal/repository/user_repo_pg.go`
- Modify: `internal/audit/repository.go`
- Modify: `cmd/server/main.go`
- Modify: `cmd/cli/user.go`
- Modify: `internal/handler/auth_handler.go`
- Test: repository, migration, handler, and CLI integration tests

**Interfaces:**
- Produce one transactionally safe purge/hard-delete API returning actually deleted IDs/count.
- Anonymize audit data before deleting user identity.

- [ ] Add a PostgreSQL regression test that proves migration 020 fails with a legacy IP row.
- [ ] Change migration 020 to disable and restore the update trigger inside its transaction; prove the legacy IP is cleared.
- [ ] Add deterministic Purge↔Activate concurrency test demonstrating partial child deletion.
- [ ] Implement stable `FOR UPDATE` candidate selection and atomic audit anonymization plus child/user deletion.
- [ ] Route scheduled purge and CLI hard delete through the atomic primitive; abort when candidate discovery/anonymization fails.
- [ ] Add tests proving active/reactivated users never lose children and failed anonymization rolls back deletion.
- [ ] Replace raw failed-auth email details with a masked/pseudonymous value and test audit payloads.
- [ ] Run focused tests, full tests, vet, format, and commit.

### Task 2: Consistent and exclusive backup/restore

**Branch:** `codex/backup-consistency`

**Files:**
- Modify: `cmd/cli/backup.go`
- Modify: `cmd/cli/manifest.go`
- Modify: account mutation entry points to observe maintenance lock
- Test: `cmd/cli/backup_test.go` and concurrency integration tests

**Interfaces:**
- Produce snapshot-bound dump/manifest artifacts carrying a digest and format version.
- Produce an advisory-lock helper shared by restore and account mutations.

- [ ] Add tests showing manifest/dump snapshot disagreement and restore/delete races.
- [ ] Export a repeatable-read snapshot and pass it to `pg_dump --snapshot` while capturing the manifest from the same transaction.
- [ ] Write dump and sidecar under temporary names, fsync, bind with SHA-256, then publish final names.
- [ ] Acquire and hold an application advisory lock through live manifest capture, restore, and reconciliation; account mutations must share it.
- [ ] Preserve the later tombstone timestamp during reconciliation.
- [ ] Reject missing/mismatched sidecars unless the explicit override is used.
- [ ] Remove database credentials from child process arguments by using supported environment/connection parameters.
- [ ] Run focused tests, full tests, vet, format, and commit.

### Task 3: Verified registration and safe email changes

**Branch:** `codex/auth-lifecycle`

**Files:**
- Create: migrations for grandfathering and `pending_email`
- Modify: auth/user services, repositories, handlers, routes, mail templates
- Modify: `api/openapi.yaml` and `README.md`
- Test: service, handler, middleware, and PostgreSQL integration tests

**Interfaces:**
- Registration returns one generic response for new and existing addresses.
- Existing users are grandfathered; new accounts require verification for protected routes.
- Email changes require current password and confirmation before changing the recovery address.

- [ ] Add failing tests for registration enumeration, unverified protected access, and bearer-only email takeover.
- [ ] Add grandfathering state and pending-email persistence migration.
- [ ] Return an identical opaque registration result without full-access credentials.
- [ ] Enforce verification for newly created accounts while preserving upgraded accounts.
- [ ] Implement password re-authenticated pending email change and a single-use confirmation endpoint.
- [ ] Atomically install the confirmed address, revoke sessions, and invalidate obsolete tokens.
- [ ] Update documentation and OpenAPI; add compatibility tests.
- [ ] Run focused tests, full tests, vet, format, and commit.

### Task 4: Authentication abuse and token replay hardening

**Branch:** `codex/auth-replay-abuse`

**Files:**
- Create: migrations for refresh families and atomic login admission
- Modify: `internal/middleware/pow.go`
- Modify: `internal/middleware/brute_force.go`
- Modify: auth/token repositories and services
- Modify: `internal/auth/jwt.go`
- Test: adversarial, concurrency, and integration tests

**Interfaces:**
- Produce atomic login-attempt admission.
- Produce refresh-family rotation with replay-triggered family/session revocation.

- [ ] Add concurrent lockout test and implement atomic attempt reservation before password verification.
- [ ] Add tests proving invalid PoW requests cannot raise global difficulty and stockpiled work cannot bypass current policy.
- [ ] Count only accepted PoW/auth load and enforce current difficulty at verification.
- [ ] Add refresh family/parent/consumed metadata and replay tests.
- [ ] Revoke the entire family and increment `session_version` atomically on replay.
- [ ] Require JWT issuer, audience, subject, expiry, issued-at, and session-version claims.
- [ ] Run focused tests, full tests, vet, format, and commit.

### Task 5: Bounded runtime, HTTP behavior, and 15 MiB vault limit

**Branch:** `codex/runtime-vault-15mb`

**Files:**
- Modify: server lifecycle, audit logger, SMTP mailer, middleware, configuration
- Modify: response encoding for large vault payloads
- Modify: Docker Compose and CI checks
- Modify: `.env.example`, `README.md`, `api/openapi.yaml`, proxy examples
- Test: shutdown, mail cancellation, router-chain, config, proxy, allocation/limit tests

**Interfaces:**
- Produce context-bounded mail and audit shutdown APIs.
- Produce validated configuration before resource construction.
- Set decoded upload maximum to exactly 15 MiB while allowing reads of existing larger blobs.

- [ ] Add never-returning handler/repository tests and enforce a single total shutdown budget.
- [ ] Replace blocking SMTP helper with context-aware, timeout-bounded delivery.
- [ ] Place CORS/response normalization outside early rejection middleware and make compression compatible with the stated policy.
- [ ] Parse trusted proxy chains strictly and reject invalid forwarding values.
- [ ] Validate all positive limits/durations/rates/ports/URLs/CIDRs at config load.
- [ ] Generate JWT key only for `os.ErrNotExist`; abort on corrupt/unreadable/unsavable state.
- [ ] Stream or bypass full-response padding for vault blobs and add bounded allocation/concurrency tests.
- [ ] Change all defaults, docs, OpenAPI, proxy examples, and tests from 75 MiB to 15 MiB.
- [ ] Digest-pin the Compose PostgreSQL image and verify CI coverage.
- [ ] Run focused tests, full tests, vet, vulnerability scan, Docker checks, format, and commit.

### Task 6: Integration, final review, and delivery

**Branch:** `codex/security-hardening-integration`

**Files:**
- Merge all task branches in dependency order.
- Resolve documentation and migration numbering conflicts.
- Add only integration fixes required by combined behavior.

- [ ] Merge Tasks 1–5 and run complete local validation with PostgreSQL 16.
- [ ] Run final whole-branch code review and fix all Critical/Important findings.
- [ ] Push every branch and the integration branch.
- [ ] Merge integration into `main`, push `main`, and verify the working tree is clean.
- [ ] Wait for every required GitHub Actions job to reach a successful terminal state.
