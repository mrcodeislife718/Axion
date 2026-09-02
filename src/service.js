import path from 'node:path';
import { AxionRegistry } from './axion.js';
import { AxionCredentialRegistry } from './credentials.js';
import { AxionStore } from './store.js';
import { AxionKeyRing } from './signing.js';
import { AxionTransparencyLedger } from './transparency-ledger.js';
import { validateAxionPassportManifest, resolveCompatibility, fromA2AAgentCard, fromMcpServerJson } from './standard.js';

const mapEntries = map => [...map.entries()].map(([key, value]) => [key, structuredClone(value)]);
const fromEntries = items => new Map((items || []).map(([key, value]) => [key, value]));

export class AxionService {
  constructor({ registry = new AxionRegistry(), store = new AxionStore(), keyRing = null, ledger = null, passportTtlMs = 15 * 60 * 1000 } = {}) {
    this.registry = registry;
    this.credentials = new AxionCredentialRegistry(registry);
    this.store = store;
    this.keyRing = keyRing || new AxionKeyRing({ root: path.join(store.home, 'signing') });
    this.ledger = ledger || new AxionTransparencyLedger({ root:path.join(store.home,'transparency') });
    if (!Number.isFinite(passportTtlMs) || passportTtlMs < 30_000 || passportTtlMs > 86_400_000) throw new Error('passport TTL must be between 30 seconds and 24 hours');
    this.passportTtlMs = passportTtlMs;
  }
  initialize() {
    const state = this.store.loadSnapshot();
    if (state) {
      this.registry.systems = fromEntries(state.systems);
      this.registry.releases = fromEntries(state.releases);
      this.registry.audit = state.audit || [];
      this.credentials.credentials = fromEntries(state.credentials);
      this.credentials.revocations = fromEntries(state.revocations);
    }
    const ledgerCheck=this.ledger.verify();
    if (!ledgerCheck.verified) throw new Error(`transparency ledger integrity failure: ${ledgerCheck.reason}`);
    return this;
  }
  snapshot() { return { systems: mapEntries(this.registry.systems), releases: mapEntries(this.registry.releases), audit: structuredClone(this.registry.audit), credentials: mapEntries(this.credentials.credentials), revocations: mapEntries(this.credentials.revocations) }; }
  persist() { this.store.saveSnapshot(this.snapshot()); }

  bootstrap(organizationName) {
    const org = this.store.createOrganization(organizationName);
    const key = this.store.issueApiKey({ organizationId: org.id, label: 'bootstrap-owner', scopes: ['*'] });
    this.store.audit(org.id, 'organization.bootstrapped', key.keyId, {});
    return { organization: org, ...key };
  }

  assertOwner(identityId, principal) {
    const owner = this.store.identityOrganization(identityId);
    if (!owner) throw new Error('identity is not registered to an organization');
    if (owner !== principal.organizationId) throw new Error('identity belongs to another organization');
  }

  validateManifest(manifest) { return validateAxionPassportManifest(manifest); }
  translateA2A(card, options={}) { return fromA2AAgentCard(card,options); }
  translateMcp(server, options={}) { return fromMcpServerJson(server,options); }
  compatibility(left,right) { return resolveCompatibility(left,right); }

  register(manifest, principal) {
    const conformance=validateAxionPassportManifest(manifest);
    if (!conformance.valid) throw new Error(`manifest failed Axion conformance: ${conformance.errors.join('; ')}`);
    const identityId = manifest?.identity?.id;
    if (!identityId) throw new Error('manifest identity required');
    const existingOwner = this.store.identityOrganization(identityId);
    if (existingOwner && existingOwner !== principal.organizationId) throw new Error('identity belongs to another organization');
    const result = this.registry.register(manifest);
    this.store.claimIdentity(identityId, principal.organizationId);
    this.persist();
    this.store.audit(principal.organizationId, 'identity.registered', principal.keyId, { identityId, version: result.version, digest: result.digest });
    this.ledger.append('release.registered',identityId,{version:result.version,digest:result.digest,publisher:manifest.identity.publisher,type:manifest.identity.type});
    return result;
  }
  inspect(identityId, principal = null) {
    const record = this.registry.inspect(identityId); if (!record) return null;
    const owner = this.store.identityOrganization(identityId);
    if (principal && owner && owner !== principal.organizationId) throw new Error('identity belongs to another organization');
    return record;
  }
  search(filters, principal) { return this.registry.search(filters).filter(item => this.store.identityOrganization(item.id) === principal.organizationId); }
  setLifecycle(identityId, status, principal) {
    this.assertOwner(identityId, principal);
    const result = this.registry.setLifecycle(identityId, status); this.persist();
    this.store.audit(principal.organizationId, 'identity.lifecycle', principal.keyId, { identityId, status });
    this.ledger.append('identity.lifecycle',identityId,{status});
    return result;
  }

  issueCredential(input, principal) { this.assertOwner(input.subjectId, principal); const result = this.credentials.issue(input); this.persist(); this.store.audit(principal.organizationId, 'credential.issued', principal.keyId, { credentialId: result.credentialId, subjectId: input.subjectId }); this.ledger.append('credential.issued',input.subjectId,{credentialId:result.credentialId}); return result; }
  verifyCredential(id) { return this.credentials.verify(id); }
  revokeCredential(id, input, principal) { const record = this.credentials.credentials.get(id); if (!record) throw new Error('credential not found'); this.assertOwner(record.subjectId, principal); const result = this.credentials.revoke(id, input); this.persist(); this.store.audit(principal.organizationId, 'credential.revoked', principal.keyId, { credentialId: id, reason: input.reason }); this.ledger.append('credential.revoked',record.subjectId,{credentialId:id,reason:input.reason}); return result; }

  bindProviderSession(identityId, input, principal) {
    this.assertOwner(identityId, principal);
    if (!input?.provider?.trim()) throw new Error('provider required');
    const session = this.store.bindProviderSession({ identityId, organizationId: principal.organizationId, provider: input.provider.trim(), model: input.model || null, externalSessionId: input.externalSessionId || null, metadata: input.metadata || {} });
    this.store.audit(principal.organizationId, 'provider_session.bound', principal.keyId, { identityId, providerSessionId: session.id, provider: session.provider, model: session.model });
    return session;
  }

  recordQualification(identityId, input, principal) {
    this.assertOwner(identityId, principal);
    const inspected=this.registry.inspect(identityId); if(!inspected) throw new Error('identity not found');
    const evaluatorId=String(input.evaluatorId || '').trim();
    const result = this.store.recordQualification({
      identityId, organizationId: principal.organizationId, kind: input.kind, status: input.status, score: input.score ?? null,
      evidence: input.evidence || [], expiresAt: input.expiresAt || null,
      releaseVersion: inspected.release.version, releaseDigest: inspected.release.digest,
      evaluatorId: evaluatorId || (input.status==='qualified' ? null : principal.keyId), methodology: input.methodology || null,
    });
    this.store.audit(principal.organizationId, 'qualification.recorded', principal.keyId, { identityId, qualificationId: result.id, kind: result.kind, status: result.status, releaseVersion:result.release_version, releaseDigest:result.release_digest, evaluatorId:result.evaluator_id });
    this.ledger.append('qualification.recorded',identityId,{qualificationId:result.id,kind:result.kind,status:result.status,releaseVersion:result.release_version,releaseDigest:result.release_digest,evaluatorId:result.evaluator_id,evidence:result.evidence});
    return result;
  }
  revokeQualification(identityId, qualificationId, principal) { this.assertOwner(identityId, principal); this.store.revokeQualification(qualificationId, principal.organizationId); this.store.audit(principal.organizationId, 'qualification.revoked', principal.keyId, { identityId, qualificationId }); this.ledger.append('qualification.revoked',identityId,{qualificationId}); return { revoked: true }; }

  passport(identityId, principal = null) {
    const inspected = this.inspect(identityId, principal); if (!inspected) return null;
    const owner = this.store.identityOrganization(identityId);
    const credentials = this.credentials.listForSubject(identityId, { includeRevoked: true }).map(record => ({
      credentialId: record.credentialId, issuerId: record.issuerId, status: record.status, claims: structuredClone(record.claims), issuedAt: record.issuedAt, expiresAt: record.expiresAt, verification: this.credentials.verify(record.credentialId),
    }));
    const providerSessions = owner ? this.store.providerSessions(identityId, owner) : [];
    const qualifications = owner ? this.store.qualifications(identityId, owner) : [];
    const activeQualifications = qualifications.filter(item => item.status === 'qualified' && !item.revoked_at && item.release_version===inspected.release.version && item.release_digest===inspected.release.digest && (!item.expires_at || Date.parse(item.expires_at) > Date.now()));
    const issuedAt = new Date();
    const ledgerHead=this.ledger.verify();
    const passport = {
      axionPassportVersion: '1.2',
      issuedAt: issuedAt.toISOString(),
      expiresAt: new Date(issuedAt.getTime() + this.passportTtlMs).toISOString(),
      identity: inspected.system,
      release: inspected.release,
      capabilityClaims: inspected.release.manifest.capabilities || [],
      permissionRequirements: inspected.release.manifest.permissions || [],
      trust: {
        releaseVerified: this.registry.verify(identityId, inspected.system.currentVersion).verified,
        activeCredentials: credentials.filter(item => item.verification.verified).length,
        totalCredentials: credentials.length,
        activeQualifications: activeQualifications.length,
        transparencyHead: ledgerHead.verified ? ledgerHead.headHash : null,
      },
      providerSessions,
      qualifications,
      credentials,
    };
    const signature = this.keyRing.sign(passport);
    return { passport, signature, verification: this.verifyPassport({ passport, signature }) };
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
  rotateSigningKey(reason, principal) { const key = this.keyRing.rotate({ reason }); this.store.audit(principal.organizationId, 'signing_key.rotated', principal.keyId, { keyId: key.keyId, reason }); this.ledger.append('signing_key.rotated','axion:trust-domain:local',{keyId:key.keyId,reason}); return key; }
  revokeSigningKey(keyId, reason, principal, invalidAfter = null) { const key = this.keyRing.revoke(keyId, { reason, invalidAfter }); this.store.audit(principal.organizationId, 'signing_key.revoked', principal.keyId, { keyId, reason, invalidAfter: key.invalidAfter }); this.ledger.append('signing_key.revoked','axion:trust-domain:local',{keyId,reason,invalidAfter:key.invalidAfter}); return key; }
  close() { this.store.close(); }
}
