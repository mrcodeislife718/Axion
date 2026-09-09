import { randomUUID } from 'node:crypto';

const clone = (value) => structuredClone(value);

export class AgentAuthorityLedger {
  constructor({ now = () => Date.now() } = {}) {
    this.now = now;
    this.identities = new Map();
    this.delegations = new Map();
    this.revoked = new Set();
    this.audit = [];
  }

  registerAgent({ id, ownerId, version, capabilities = [], resourceScopes = [], credentialScopes = [], quotas = {}, expiresAt = null, metadata = {} }) {
    if (!id || !ownerId || !version) throw new TypeError('agent id, ownerId, and version are required');
    if (this.identities.has(id)) throw new Error('agent identity already exists');
    const record = Object.freeze({
      id,
      kind: 'agent',
      ownerId,
      version,
      capabilities: unique(capabilities),
      resourceScopes: unique(resourceScopes),
      credentialScopes: unique(credentialScopes),
      quotas: normalizeQuotas(quotas),
      expiresAt: normalizeExpiry(expiresAt),
      metadata: clone(metadata),
      createdAt: this.now()
    });
    this.identities.set(id, record);
    this.#record('agent.registered', id, { ownerId, version });
    return clone(record);
  }

  delegate({ fromId, toId, capabilities = [], resourceScopes = [], credentialScopes = [], quotas = {}, expiresAt = null, allowRedelegation = false }) {
    const from = this.#active(fromId);
    const to = this.#active(toId);
    const effectiveCapabilities = intersect(unique(capabilities), from.capabilities);
    const effectiveResources = intersect(unique(resourceScopes), from.resourceScopes);
    const effectiveCredentials = intersect(unique(credentialScopes), from.credentialScopes);
    const requestedQuotas = normalizeQuotas(quotas);
    const effectiveQuotas = capQuotas(requestedQuotas, from.quotas);
    const delegation = Object.freeze({
      id: randomUUID(), fromId: from.id, toId: to.id,
      capabilities: effectiveCapabilities,
      resourceScopes: effectiveResources,
      credentialScopes: effectiveCredentials,
      quotas: effectiveQuotas,
      expiresAt: earliestExpiry(normalizeExpiry(expiresAt), from.expiresAt, to.expiresAt),
      allowRedelegation: Boolean(allowRedelegation),
      createdAt: this.now()
    });
    this.delegations.set(delegation.id, delegation);
    this.#record('authority.delegated', to.id, { delegationId: delegation.id, fromId });
    return clone(delegation);
  }

  evaluate({ actorId, capability, resource = null, credential = null, usage = {}, delegationId = null }) {
    const actor = this.#active(actorId);
    const grant = delegationId ? this.#activeDelegation(delegationId, actorId) : actor;
    const capabilities = grant.capabilities ?? actor.capabilities;
    const resources = grant.resourceScopes ?? actor.resourceScopes;
    const credentials = grant.credentialScopes ?? actor.credentialScopes;
    const quotas = grant.quotas ?? actor.quotas;
    const reasons = [];
    if (!capabilities.includes(capability)) reasons.push('capability_not_granted');
    if (resource && !matchesAny(resource, resources)) reasons.push('resource_out_of_scope');
    if (credential && !matchesAny(credential, credentials)) reasons.push('credential_out_of_scope');
    for (const [key, value] of Object.entries(usage)) if (Number.isFinite(quotas[key]) && Number(value) > quotas[key]) reasons.push(`quota_exceeded:${key}`);
    const allowed = reasons.length === 0;
    this.#record(allowed ? 'authority.allowed' : 'authority.denied', actorId, { capability, resource, delegationId, reasons });
    return { allowed, reasons };
  }

  revoke(id, reason = 'revoked') {
    this.revoked.add(id);
    this.#record('authority.revoked', id, { reason });
  }

  #active(id) {
    const record = this.identities.get(id);
    if (!record) throw new Error('identity not found');
    if (this.revoked.has(id)) throw new Error('identity revoked');
    if (record.expiresAt != null && record.expiresAt <= this.now()) throw new Error('identity expired');
    return record;
  }

  #activeDelegation(id, actorId) {
    const delegation = this.delegations.get(id);
    if (!delegation || delegation.toId !== actorId) throw new Error('delegation not found for actor');
    if (this.revoked.has(id)) throw new Error('delegation revoked');
    if (delegation.expiresAt != null && delegation.expiresAt <= this.now()) throw new Error('delegation expired');
    return delegation;
  }

  #record(type, subjectId, payload) {
    this.audit.push({ id: randomUUID(), type, subjectId, at: this.now(), payload: clone(payload) });
  }
}

function unique(values) { return [...new Set((values ?? []).filter((value) => typeof value === 'string' && value))]; }
function intersect(a, b) { const allowed = new Set(b); return a.filter((value) => allowed.has(value)); }
function normalizeExpiry(value) { if (value == null) return null; const n = Number(value); if (!Number.isFinite(n)) throw new TypeError('invalid expiry'); return n; }
function earliestExpiry(...values) { const finite = values.filter((value) => value != null); return finite.length ? Math.min(...finite) : null; }
function normalizeQuotas(quotas) { const out = {}; for (const [key, value] of Object.entries(quotas ?? {})) { const n = Number(value); if (!Number.isFinite(n) || n < 0) throw new TypeError(`invalid quota ${key}`); out[key] = n; } return out; }
function capQuotas(requested, parent) { const out = {}; for (const [key, value] of Object.entries(requested)) out[key] = Number.isFinite(parent[key]) ? Math.min(value, parent[key]) : value; return out; }
function matchesAny(value, scopes) { return scopes.includes('*') || scopes.some((scope) => scope === value || (scope.endsWith('*') && value.startsWith(scope.slice(0, -1)))); }
