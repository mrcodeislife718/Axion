# Axion Technical Superiority Architecture

## Scope

Axion is evaluated independently as a durable identity, capability, qualification, trust, credential, and revocation layer for AI systems and workers.

## Competitive reference set

Relevant strengths to preserve or exceed:

- SPIFFE/SPIRE: portable workload identity, short-lived verifiable identity documents, trust-domain separation, local workload identity delivery.
- Sigstore: identity-bound signing, short-lived signing material, verifiable signatures, transparent key/identity provenance.
- OAuth/OIDC-style credential systems: explicit scopes, expiry, revocation, issuer/audience boundaries.
- PKI/key-management systems: asymmetric signatures, rotation, revocation, public verification.
- Software supply-chain provenance systems: digest-bound identity/version evidence.

Structural weaknesses Axion should avoid:

- treating registration as authorization;
- identity changing whenever provider/model changes;
- one opaque trust score hiding underlying evidence;
- long-lived bearer credentials with broad scope;
- verification depending on Axion being online for every read;
- key rotation invalidating all historical proof;
- provider-specific identity schemas;
- revocation that erases history rather than preventing future trust;
- cross-tenant identity collisions or confused ownership.

## Improved architecture

### 1. Stable identity + ephemeral execution binding

1. Purpose: preserve worker continuity when model/provider/runtime changes.
2. Mechanism: durable canonical identity is versioned independently; provider/model sessions are short-lived bindings to a task/execution segment.
3. Expected advantage: model independence, portable reputation/qualification, clean audit continuity.
4. Tradeoff: consumers must distinguish identity from execution session.
5. Failure mode: stale provider binding continues after revocation or task end.
6. Measurement: invalid-binding acceptance rate and provider-swap continuity tests.
7. Benchmark: zero identity changes during valid provider swaps; revoked/expired bindings rejected 100%.
8. Fallback: require a fresh binding for every new execution segment when state is uncertain.
9. Validation: swap Qwen/Codex/Claude-like provider records under one identity; expire/revoke old sessions and verify history remains intact.

### 2. Offline-verifiable signed passports

1. Purpose: avoid making Axion a synchronous bottleneck for every trust decision.
2. Mechanism: canonical passport payloads signed with asymmetric keys; verifiers cache public keys and validate digest/version/expiry locally.
3. Expected advantage: low verification latency, high availability, interoperability.
4. Tradeoff: revocation freshness is bounded by cache/refresh policy.
5. Failure mode: compromised signing key or stale cached key set.
6. Measurement: verification p95, availability during Axion outage, stale-revocation window.
7. Benchmark: local verification p95 <5 ms for ordinary passports and successful verification while registry service is unavailable.
8. Fallback: short validity windows plus forced online refresh for high-consequence decisions.
9. Validation: service-offline verification, rotated key, revoked key, tampered payload, expired passport.

### 3. Rotation without historical-proof destruction

1. Purpose: permit safe key rotation while preserving old evidence.
2. Mechanism: retain public verification metadata for retired keys, distinguish active/retired/revoked signing keys, and bind signatures to key id and creation time.
3. Expected advantage: forward security with durable historical verification.
4. Tradeoff: verifier logic and key metadata become more complex.
5. Failure mode: revocation semantics accidentally validate post-compromise signatures.
6. Measurement: historical verification correctness across rotations/revocations.
7. Benchmark: pre-revocation valid signatures remain historically attributable while signatures created after declared compromise boundary are rejected.
8. Fallback: require online verification for ambiguous compromise windows.
9. Validation: rotate keys across multiple passport generations; revoke one with compromise timestamp and replay verification.

### 4. Evidence-decomposed trust and qualification

1. Purpose: avoid an unexplained universal trust score.
2. Mechanism: expose separate qualification status, evidence references, verification pass rates, policy violations, rollback rates, recency, issuer, and scope.
3. Expected advantage: explainable worker selection and less brittle governance.
4. Tradeoff: consumers must define their own decision policy.
5. Failure mode: consumers cherry-pick favorable signals.
6. Measurement: ability to reproduce a trust decision from underlying evidence.
7. Benchmark: every trust/qualification field has an attributable source/version and no hidden aggregate is required.
8. Fallback: provide policy templates without collapsing evidence into one authoritative score.
9. Validation: conflicting qualifications from multiple issuers and expired/outdated evidence.

### 5. Strict tenant and scope boundaries

1. Purpose: prevent ownership confusion and credential overreach.
2. Mechanism: organization-bound identity ownership, scoped credentials, explicit subject/action/environment boundaries, rate limits, and deny-by-default cross-tenant access.
3. Expected advantage: safer multi-tenant production operation and clearer revocation.
4. Tradeoff: more authorization metadata and credential-management operations.
5. Failure mode: wildcard scopes become effectively permanent root authority.
6. Measurement: cross-tenant access violations, scope-escalation test pass rate, credential age.
7. Benchmark: 100% denial of unauthorized cross-tenant reads/writes in adversarial tests.
8. Fallback: owner-only recovery path with explicit audit record.
9. Validation: horizontal-privilege tests, expired key, revoked key, wildcard restrictions, identity transfer attempts.

## 1x / 10x / 100x consequences

### 1x

Small number of identities. Main priorities are correct separation of identity/capability/authority and simple verification.

### 10x

Many workers, providers, qualifications, and organizations. Key rotation, revocation lookup, credential indexing, and API rate limits become important.

### 100x

Large ecosystems can create millions of identity versions and verification requests. Online registry calls must not sit on every execution path; cached public verification, partitionable storage, bounded passport size, and efficient revocation distribution become necessary.

## Success-too-well failures

- Axion becomes a central synchronous dependency for every agent action.
- Passport payloads grow without bound as qualifications accumulate.
- Trust consumers treat registration as endorsement.
- Key rotation volume causes verifier cache churn.
- Provider sessions accumulate indefinitely.
- Qualification issuers flood low-quality evidence.

Controls: offline verification, bounded passport projections, explicit non-authorization invariant, retention/expiry, issuer attribution, revocation freshness classes.

## Evidence plan

Required benchmark suites:

1. Passport sign/verify p50/p95 and payload-size scaling.
2. Verification during registry outage.
3. Key rotation and historical verification.
4. Key compromise/revocation boundary correctness.
5. Provider/model swap continuity.
6. Cross-tenant and scope-escalation adversarial tests.
7. Credential/qualification expiry and revocation latency.
8. 1K/100K/1M identity lookup and verification behavior.
9. New-provider onboarding with no core identity schema migration.

No superiority claim is valid without reproducible comparison to a named identity/trust baseline.