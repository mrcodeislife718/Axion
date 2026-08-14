import { createHash, randomUUID } from 'node:crypto';
import { canonicalize } from './axion.js';

function digest(value) {
  return createHash('sha256').update(JSON.stringify(canonicalize(value))).digest('hex');
}

export class AxionCredentialRegistry {
  constructor(registry, { now = () => new Date().toISOString() } = {}) {
    if (!registry) throw new Error('AxionCredentialRegistry requires an AxionRegistry instance');
    this.registry = registry;
    this.now = now;
    this.credentials = new Map();
    this.revocations = new Map();
  }

  issue({ subjectId, issuerId, claims, expiresAt = null, evidence = [] }) {
    const subject = this.registry.inspect(subjectId);
    if (!subject) throw new Error('subject identity is not registered');
    if (subject.system.status !== 'active') throw new Error('subject identity is not active');
    if (!issuerId?.trim()) throw new Error('issuerId is required');
    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) throw new Error('claims must be an object');
    if (!Array.isArray(evidence)) throw new Error('evidence must be an array');
    if (expiresAt && !Number.isFinite(Date.parse(expiresAt))) throw new Error('expiresAt must be a valid date-time');

    const credentialId = `axion:credential:${randomUUID()}`;
    const body = {
      credentialId,
      subjectId,
      subjectVersion: subject.system.currentVersion,
      subjectDigest: subject.system.currentDigest,
      issuerId,
      claims: canonicalize(claims),
      evidence: canonicalize(evidence),
      issuedAt: this.now(),
      expiresAt,
    };
    const record = { ...body, digest: digest(body), status: 'active' };
    this.credentials.set(credentialId, record);
    return structuredClone(record);
  }

  verify(credentialId, { at = this.now() } = {}) {
    const record = this.credentials.get(credentialId);
    if (!record) return { verified: false, reason: 'credential-not-found' };
    if (record.status !== 'active' || this.revocations.has(credentialId)) return { verified: false, reason: 'credential-revoked' };
    if (record.expiresAt && Date.parse(record.expiresAt) <= Date.parse(at)) return { verified: false, reason: 'credential-expired' };

    const subject = this.registry.inspect(record.subjectId);
    if (!subject) return { verified: false, reason: 'subject-not-found' };
    if (subject.system.status === 'revoked' || subject.system.status === 'retired') return { verified: false, reason: 'subject-not-active' };
    if (subject.system.currentDigest !== record.subjectDigest) return { verified: false, reason: 'subject-release-changed' };

    const { digest: storedDigest, status, ...body } = record;
    const calculatedDigest = digest(body);
    if (calculatedDigest !== storedDigest) return { verified: false, reason: 'credential-integrity-failed', expectedDigest: storedDigest, calculatedDigest };
    return { verified: true, credential: structuredClone(record) };
  }

  revoke(credentialId, { reason, revokedBy }) {
    const record = this.credentials.get(credentialId);
    if (!record) throw new Error('credential not found');
    if (!reason?.trim()) throw new Error('revocation reason is required');
    if (!revokedBy?.trim()) throw new Error('revokedBy is required');
    if (this.revocations.has(credentialId)) return structuredClone(this.revocations.get(credentialId));
    const revocation = { id: randomUUID(), credentialId, reason, revokedBy, revokedAt: this.now() };
    record.status = 'revoked';
    this.revocations.set(credentialId, revocation);
    return structuredClone(revocation);
  }

  listForSubject(subjectId, { includeRevoked = false } = {}) {
    return [...this.credentials.values()]
      .filter((record) => record.subjectId === subjectId && (includeRevoked || record.status === 'active'))
      .map((record) => structuredClone(record));
  }
}
