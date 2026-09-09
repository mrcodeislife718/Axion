import { randomUUID } from 'node:crypto';
import { AxionRegistry } from './axion.js';
import { AxionCredentialRegistry } from './credentials.js';
import { JsonStore } from './store.js';
import { AxionKeyRing } from './signing.js';
import { AxionTransparencyLedger } from './transparency-ledger.js';
import { createTrustBundle, trustBundleAllowsIdentity, verifyTrustBundle } from './trust-bundle.js';
import { fromA2AAgentCard, fromMcpServerJson, resolveCompatibility, validateAxionPassportManifest } from './standard.js';

const mapEntries = (map) => [...map.entries()].map(([key, value]) => [key, structuredClone(value)]);
const fromEntries = (items = []) => new Map(items.map(([key, value]) => [key, value]));
const now = () => new Date().toISOString();
const generatedId = (prefix) => `${prefix}_${randomUUID()}`;

export class AxionService {
  constructor({
    registry = new AxionRegistry(),
    store = new JsonStore(process.env.AXION_DATA ?? './data/axion.json'),
    keyRing = null,
    ledger = null,
    passportTtlMs = Number(process.env.AXION_PASSPORT_TTL_MS ?? 15 * 60 * 1000),
    trustDomainId = process.env.AXION_TRUST_DOMAIN ?? 'axion:trust-domain:local',
    namespaceRoots = [],
  } = {}) {
    this.registry = registry;
    this.credentials = new AxionCredentialRegistry(registry);
    this.store = store;
    const statePath = typeof store.path === 'string' && store.path ? store.path : './data/axion.json';
    this.keyRing = keyRing ?? new AxionKeyRing({ root: process.env.AXION_SIGNING_ROOT ?? `${statePath}.keys` });
    this.ledger = ledger ?? new AxionTransparencyLedger({ root: process.env.AXION_TRANSPARENCY_ROOT ?? `${statePath}.transparency` });
    if (!Number.isFinite(passportTtlMs) || passportTtlMs < 30_000 || passportTtlMs > 86_400_000) throw new Error('passport TTL must be between 30 seconds and 24 hours');
    this.passportTtlMs = passportTtlMs;
    this.trustDomainId = trustDomainId;
    this.namespaceRoots = [...new Set(namespaceRoots.map(String))].sort();
    this.providerSessions = new Map();
    this.qualifications = new Map();
  }

  async initialize() {
    const state = await this.store.load(null);
    if (state) {
      this.registry.systems = fromEntries(state.systems);
      this.registry.releases = fromEntries(state.releases);
      this.registry.audit = state.audit ?? [];
      this.credentials.credentials = fromEntries(state.credentials);
      this.credentials.revocations = fromEntries(state.revocations);
      this.providerSessions = fromEntries(state.providerSessions);
      this.qualifications = fromEntries(state.qualifications);
    }
    const ledger = this.ledger.verify();
    if (!ledger.verified) throw new Error(`transparency ledger integrity failure: ${ledger.reason}`);
    return this;
  }

  snapshot() {
    return {
      systems: mapEntries(this.registry.systems),
      releases: mapEntries(this.registry.releases),
      audit: structuredClone(this.registry.audit),
      credentials: mapEntries(this.credentials.credentials),
      revocations: mapEntries(this.credentials.revocations),
      providerSessions: mapEntries(this.providerSessions),
      qualifications: mapEntries(this.qualifications),
    };
  }

  async persist() { await this.store.save(this.snapshot()); }

  dashboard() {
    const systems = [...this.registry.systems.values()].map((system) => structuredClone(system));
    const credentials = [...this.credentials.credentials.values()].map((credential) => structuredClone(credential));
    return {
      totals: {
        identities: systems.length,
        activeIdentities: systems.filter((item) => item.status === 'active').length,
        credentials: credentials.length,
        activeCredentials: credentials.filter((item) => item.status === 'active').length,
        providerSessions: this.providerSessions.size,
        qualifications: this.qualifications.size,
      },
      identities: systems,
      credentials,
      audit: this.registry.audit.slice(-50).reverse().map((event) => structuredClone(event)),
      transparency: this.ledger.verify(),
    };
  }

  validateManifest(manifest) { return validateAxionPassportManifest(manifest); }
  translateA2A(card, options = {}) { return fromA2AAgentCard(card, options); }
  translateMcp(server, options = {}) { return fromMcpServerJson(server, options); }
  compatibility(left, right) { return resolveCompatibility(left, right); }

  async register(manifest) {
    const conformance = validateAxionPassportManifest(manifest);
    if (!conformance.valid) throw new Error(`manifest failed Axion conformance: ${conformance.errors.join('; ')}`);
    const result = this.registry.register(manifest);
    this.ledger.append('release.registered', result.identityId, { version: result.version, digest: result.digest, publisher: manifest.identity.publisher, type: manifest.identity.type });
    await this.persist();
    return result;
  }
  inspect(id) { return this.registry.inspect(id); }
  search(filters) { return this.registry.search(filters); }
  verifyRelease(id, version) { return this.registry.verify(id, version); }
  async setLifecycle(id, status) {
    const result = this.registry.setLifecycle(id, status);
    this.ledger.append('identity.lifecycle', id, { status });
    await this.persist();
    return result;
  }
  async issueCredential(input) {
    const result = this.credentials.issue(input);
    this.ledger.append('credential.issued', input.subjectId, { credentialId: result.credentialId, issuerId: result.issuerId });
    await this.persist();
    return result;
  }
  verifyCredential(id) { return this.credentials.verify(id); }
  async revokeCredential(id, input) {
    const record = this.credentials.credentials.get(id);
    const result = this.credentials.revoke(id, input);
    this.ledger.append('credential.revoked', record?.subjectId ?? 'unknown', { credentialId: id, reason: input?.reason ?? null });
    await this.persist();
    return result;
  }

  async bindProviderSession(identityId, input = {}) {
    if (!this.registry.inspect(identityId)) throw new Error('identity not found');
    const provider = String(input.provider ?? '').trim();
    if (!provider) throw new Error('provider required');
    const at = now();
    for (const [id, session] of this.providerSessions) {
      if (session.identityId === identityId && session.status === 'active') this.providerSessions.set(id, { ...session, status: 'ended', endedAt: at });
    }
    const session = {
      id: generatedId('provider'),
      identityId,
      provider,
      model: input.model ? String(input.model) : null,
      externalSessionId: input.externalSessionId ? String(input.externalSessionId) : null,
      status: 'active',
      startedAt: at,
      endedAt: null,
      metadata: input.metadata && typeof input.metadata === 'object' && !Array.isArray(input.metadata) ? structuredClone(input.metadata) : {},
    };
    this.providerSessions.set(session.id, session);
    this.ledger.append('provider_session.bound', identityId, { providerSessionId: session.id, provider: session.provider, model: session.model });
    await this.persist();
    return structuredClone(session);
  }

  providerSessionHistory(identityId) {
    return [...this.providerSessions.values()].filter((item) => item.identityId === identityId).sort((a, b) => b.startedAt.localeCompare(a.startedAt)).map((item) => structuredClone(item));
  }

  async recordQualification(identityId, input = {}) {
    const inspected = this.registry.inspect(identityId);
    if (!inspected) throw new Error('identity not found');
    const kind = String(input.kind ?? '').trim();
    if (!kind) throw new Error('qualification kind required');
    const status = String(input.status ?? '').trim();
    if (!['qualified','unverified','failed','revoked'].includes(status)) throw new Error('invalid qualification status');
    const score = input.score == null ? null : Number(input.score);
    if (score != null && (!Number.isFinite(score) || score < 0 || score > 1)) throw new Error('qualification score must be between 0 and 1');
    const evaluatorId = String(input.evaluatorId ?? 'axion-registry-authority').trim();
    if (status === 'qualified' && !evaluatorId) throw new Error('qualified evidence requires an evaluator');
    const expiresAt = input.expiresAt ? new Date(input.expiresAt).toISOString() : null;
    const qualification = {
      id: generatedId('qualification'),
      identityId,
      kind,
      status,
      score,
      evidence: Array.isArray(input.evidence) ? structuredClone(input.evidence) : [],
      recordedAt: now(),
      expiresAt,
      revokedAt: status === 'revoked' ? now() : null,
      releaseVersion: inspected.release.version,
      releaseDigest: inspected.release.digest,
      evaluatorId,
      methodology: input.methodology ? String(input.methodology) : null,
    };
    this.qualifications.set(qualification.id, qualification);
    this.ledger.append('qualification.recorded', identityId, { qualificationId: qualification.id, kind, status, releaseVersion: qualification.releaseVersion, releaseDigest: qualification.releaseDigest, evaluatorId, evidence: qualification.evidence });
    await this.persist();
    return structuredClone(qualification);
  }

  async revokeQualification(identityId, qualificationId) {
    const qualification = this.qualifications.get(qualificationId);
    if (!qualification || qualification.identityId !== identityId) throw new Error('qualification not found');
    const updated = { ...qualification, status: 'revoked', revokedAt: now() };
    this.qualifications.set(qualificationId, updated);
    this.ledger.append('qualification.revoked', identityId, { qualificationId });
    await this.persist();
    return structuredClone(updated);
  }

  qualificationHistory(identityId) {
    return [...this.qualifications.values()].filter((item) => item.identityId === identityId).sort((a, b) => b.recordedAt.localeCompare(a.recordedAt)).map((item) => structuredClone(item));
  }

  passport(identityId, { nowMs = Date.now() } = {}) {
    const inspected = this.registry.inspect(identityId);
    if (!inspected) return null;
    const credentials = this.credentials.listForSubject(identityId, { includeRevoked: true }).map((record) => ({
      credentialId: record.credentialId,
      issuerId: record.issuerId,
      status: record.status,
      claims: structuredClone(record.claims),
      issuedAt: record.issuedAt,
      expiresAt: record.expiresAt,
      verification: this.credentials.verify(record.credentialId),
    }));
    const qualifications = this.qualificationHistory(identityId);
    const activeQualifications = qualifications.filter((item) => item.status === 'qualified' && !item.revokedAt && item.releaseVersion === inspected.release.version && item.releaseDigest === inspected.release.digest && (!item.expiresAt || Date.parse(item.expiresAt) > nowMs));
    const issuedAt = new Date(nowMs);
    const ledger = this.ledger.verify();
    const passport = {
      axionPassportVersion: '1.2',
      issuedAt: issuedAt.toISOString(),
      expiresAt: new Date(nowMs + this.passportTtlMs).toISOString(),
      identity: inspected.system,
      release: inspected.release,
      capabilityClaims: inspected.release.manifest.capabilities ?? [],
      permissionRequirements: inspected.release.manifest.permissions ?? [],
      trust: {
        releaseVerified: this.registry.verify(identityId, inspected.system.currentVersion).verified,
        activeCredentials: credentials.filter((item) => item.verification.verified).length,
        totalCredentials: credentials.length,
        activeQualifications: activeQualifications.length,
        transparencyHead: ledger.verified ? ledger.headHash : null,
        trustDomainId: this.trustDomainId,
      },
      providerSessions: this.providerSessionHistory(identityId),
      qualifications,
      credentials,
    };
    const signature = this.keyRing.sign(passport);
    return { passport, signature, verification: this.verifyPassport({ passport, signature }, { nowMs }) };
  }

  verifyPassport(bundle, { nowMs = Date.now(), publicKeys = null } = {}) {
    const passport = bundle?.passport;
    if (!passport?.issuedAt || !passport?.expiresAt) return { verified: false, reason: 'passport-validity-missing' };
    const issuedAt = Date.parse(passport.issuedAt), expiresAt = Date.parse(passport.expiresAt);
    if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || expiresAt <= issuedAt) return { verified: false, reason: 'passport-validity-invalid' };
    if (nowMs < issuedAt - 60_000) return { verified: false, reason: 'passport-not-yet-valid' };
    if (nowMs >= expiresAt) return { verified: false, reason: 'passport-expired' };
    return publicKeys ? AxionKeyRing.verifyOffline(passport, bundle.signature, publicKeys) : this.keyRing.verify(passport, bundle.signature);
  }

  signingKeys() { return this.keyRing.publicKeys(); }
  ledgerStatus() { return this.ledger.verify(); }
  ledgerCheckpoint() { return this.ledger.checkpoint(this.keyRing); }
  trustBundle(options = {}) { return createTrustBundle({ domainId: this.trustDomainId, namespaceRoots: options.namespaceRoots ?? this.namespaceRoots, keyRing: this.keyRing, ledger: this.ledger, ttlMs: options.ttlMs, nowMs: options.nowMs }); }
  verifyTrustBundle(bundle, policy = {}) { return verifyTrustBundle(bundle, policy); }
  trustBundleAllowsIdentity(bundle, identityId) { return trustBundleAllowsIdentity(bundle, identityId); }
  rotateSigningKey(reason = 'rotation') {
    const key = this.keyRing.rotate({ reason });
    this.ledger.append('signing_key.rotated', this.trustDomainId, { keyId: key.keyId, reason });
    return key;
  }
  revokeSigningKey(keyId, reason = 'revoked', invalidAfter = null) {
    const key = this.keyRing.revoke(keyId, { reason, invalidAfter });
    this.ledger.append('signing_key.revoked', this.trustDomainId, { keyId, reason, invalidAfter: key.invalidAfter });
    return key;
  }
}
