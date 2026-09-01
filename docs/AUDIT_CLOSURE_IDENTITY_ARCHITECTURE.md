# Axion Audit-Closure Identity Architecture

## Scope lock

This branch may only recover and harden Axion's real registry product and implement the approved durable AI-worker identity architecture. No HTML/operator console, execution-attestation subsystem, placeholder, mock, demo-only feature, or unrelated product surface is permitted.

Approved work:
1. Preserve the existing registry and credential core.
2. Add durable persistence and migrations.
3. Add organizations/tenancy and scoped API keys so the effective HTTP path is authenticated and authorized.
4. Add rate limiting and security audit records.
5. Add durable logical worker identity that remains stable across provider/model session swaps.
6. Keep capability, permission requirement, granted authority, trust/qualification, credential status, revocation and provider-session identity separate.
7. Add signed passport integrity and signing-key rotation/revocation because Axion's identity/trust product explicitly requires independently verifiable identity records.
8. Add production API routes for the approved registry, credentials, provider-session binding and passport verification only.
9. Add tests that exercise the real request path, tenant isolation, provider replacement, credential revocation and signature tamper detection.

## Competitive engineering inputs

Useful identity-system strengths are applied only inside Axion's approved purpose: stable workload identity, short-lived/revocable credentials, cryptographic verification, issuer/key lifecycle, and provider-independent identity. No external system's feature set becomes automatic Axion scope.

## Architecture

Client -> request-path auth/scope enforcement -> tenant-aware Axion service -> existing registry + credentials -> durable database -> logical worker/provider-session mapping -> signed passport projection -> verification endpoint.

Registration identifies a worker/system. Registration never grants execution authority. Provider-session binding says which model/provider currently operated under the durable identity; it does not replace the durable identity.

## Evidence plan

### Durable logical worker identity
Purpose: preserve worker identity when Qwen, Codex, Claude or another model/provider is swapped.
Mechanism: canonical Axion identity owns zero or more provider-session records; provider session IDs are temporary and cannot mutate the canonical identity ID.
Expected advantage: stable trust/revocation/qualification history independent of model vendor.
Tradeoff: requires explicit binding lifecycle.
Failure mode: provider session is bound to the wrong tenant/identity.
Measurement: tenant/provider-swap tests.
Benchmark: provider/model replacement leaves canonical identity and credential history unchanged.
Fallback: reject invalid binding.
Validation: multi-provider identity test.

### Request-path authorization
Purpose: ensure security code actually protects product routes.
Mechanism: hashed scoped API keys, tenant ownership checks and per-route scope requirements executed inside the HTTP handler.
Expected advantage: eliminates the disconnected-auth defect found in the audit.
Tradeoff: key lifecycle and scope administration.
Failure mode: a mutating route bypasses the authorizer.
Measurement: route matrix test.
Benchmark: every mutating private route returns 401 without credentials and 403 for insufficient scope.
Fallback: deny by default.
Validation: real HTTP integration tests.

### Signed passports/key lifecycle
Purpose: independently verify that an Axion passport has not been altered and determine which Axion key signed it.
Mechanism: Ed25519 signatures over canonical passport content; public key metadata; key rotation, supersession and revocation.
Expected advantage: tamper detection and historical verification without trusting transport alone.
Tradeoff: secure private-key storage is required in deployment.
Failure mode: key compromise or accidental deletion.
Measurement: tamper/rotation/revocation tests.
Benchmark: modified passport fails verification; superseded non-revoked keys verify historical records; revoked keys fail.
Fallback: revoke affected key and rotate; unsigned/unverifiable passport is not trusted.
Validation: signature lifecycle test.

### Durable persistence/tenancy
Purpose: replace in-memory/JSON prototype state with transactional product state.
Mechanism: SQLite for the local single-node production baseline with explicit migrations, WAL, foreign keys, atomic transactions and backup support; database boundary remains replaceable for later Postgres scale-out.
Expected advantage: immediate durable correctness without forcing hosted infrastructure into the local product.
Tradeoff: a single SQLite writer limits horizontal multi-node scale.
Failure mode: disk corruption or storage exhaustion.
Measurement: restart, migration and backup/restore qualification.
Benchmark: registered identity/credentials/provider bindings survive restart with identical IDs/digests.
Fallback: restore from verified backup.
Validation: persistence/recovery test.

## Scale analysis

1x: single local registry instance; prioritize integrity and simple operations.
10x: organizations/API keys/provider sessions increase read/write concurrency; WAL and indexes must avoid global scans.
100x: multi-node hosted operation becomes the scaling boundary; move the persistence adapter to Postgres while preserving identity and signature semantics.

Success-too-well risk: a widely adopted registry can become a trust bottleneck. Verification must remain cacheable/offline-capable through signed passports/public keys so every verification does not require a synchronous Axion database round trip.
