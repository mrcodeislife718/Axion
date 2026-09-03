import crypto from 'node:crypto';

export class IdentityRegistry {
  #identities = new Map();
  #credentials = new Map();
  #revocations = new Map();

  register({ id = crypto.randomUUID(), kind = 'agent', owner, runtime = null, model = null, parentIdentityId = null, metadata = {} }) {
    if (!owner) throw new Error('identity owner is required');
    if (this.#identities.has(id)) throw new Error(`identity ${id} already exists`);
    if (parentIdentityId && !this.#identities.has(parentIdentityId)) throw new Error(`unknown parent identity: ${parentIdentityId}`);
    const identity = { id, kind, owner, runtime, model, parentIdentityId, metadata: structuredClone(metadata), status: 'active', createdAt: Date.now(), version: 1 };
    this.#identities.set(id, identity);
    return this.identity(id);
  }

  issueCredential(identityId, { type, claims = {}, issuer, expiresAt = null }) {
    const identity = this.#requireActive(identityId);
    if (!type || !issuer) throw new Error('credential type and issuer are required');
    const payload = { identityId, type, claims: structuredClone(claims), issuer, expiresAt };
    const id = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
    const credential = { id, ...payload, issuedAt: Date.now(), status: 'active' };
    this.#credentials.set(id, credential);
    return structuredClone(credential);
  }

  attest(identityId, { attestor, subject, value, expiresAt = null }) {
    return this.issueCredential(identityId, { type: 'attestation', issuer: attestor, expiresAt, claims: { subject, value } });
  }

  lineage(identityId) {
    const path = [];
    const seen = new Set();
    let current = this.#require(identityId);
    while (current) {
      if (seen.has(current.id)) throw new Error('identity lineage cycle detected');
      seen.add(current.id);
      path.push(this.identity(current.id));
      current = current.parentIdentityId ? this.#require(current.parentIdentityId) : null;
    }
    return path;
  }

  discover(predicate = () => true) {
    return [...this.#identities.values()].filter(i => i.status === 'active').map(i => this.identity(i.id)).filter(predicate);
  }

  revoke(identityId, { reason, revokedBy }) {
    const identity = this.#require(identityId);
    if (!reason || !revokedBy) throw new Error('revocation reason and actor are required');
    identity.status = 'revoked';
    identity.version += 1;
    const record = { identityId, reason, revokedBy, revokedAt: Date.now() };
    this.#revocations.set(identityId, record);
    for (const credential of this.#credentials.values()) if (credential.identityId === identityId) credential.status = 'revoked';
    return structuredClone(record);
  }

  credential(id) {
    const credential = this.#credentials.get(id);
    if (!credential) throw new Error(`unknown credential: ${id}`);
    const expired = credential.expiresAt && Date.now() > new Date(credential.expiresAt).getTime();
    return { ...structuredClone(credential), status: expired && credential.status === 'active' ? 'expired' : credential.status };
  }

  identity(id) { return structuredClone(this.#require(id)); }
  #require(id) { const i = this.#identities.get(id); if (!i) throw new Error(`unknown identity: ${id}`); return i; }
  #requireActive(id) { const i = this.#require(id); if (i.status !== 'active') throw new Error(`identity ${id} is not active`); return i; }
}
