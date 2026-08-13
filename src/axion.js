import { createHash, randomUUID } from 'node:crypto';

const REQUIRED_TYPES = new Set(['agent','mcp-server','runtime','orchestrator','memory','tool','model-integration','observability','evaluation','governance']);

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  return value;
}

export function digestManifest(manifest) {
  return createHash('sha256').update(JSON.stringify(canonicalize(manifest))).digest('hex');
}

export function validateManifest(manifest) {
  const errors = [];
  if (!manifest || typeof manifest !== 'object') return { valid: false, errors: ['manifest must be an object'] };
  if (manifest.axion_version !== '1.0') errors.push('axion_version must equal 1.0');
  const identity = manifest.identity ?? {};
  if (!/^axion:[a-z0-9-]+:[a-z0-9._-]+$/i.test(identity.id ?? '')) errors.push('identity.id is invalid');
  if (!identity.name?.trim()) errors.push('identity.name is required');
  if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(identity.version ?? '')) errors.push('identity.version must be semantic');
  if (!identity.publisher?.trim()) errors.push('identity.publisher is required');
  if (!REQUIRED_TYPES.has(identity.type)) errors.push('identity.type is unsupported');
  if (manifest.capabilities != null && !Array.isArray(manifest.capabilities)) errors.push('capabilities must be an array');
  if (manifest.permissions != null && !Array.isArray(manifest.permissions)) errors.push('permissions must be an array');
  return { valid: errors.length === 0, errors };
}

export class AxionRegistry {
  constructor({ now = () => new Date().toISOString() } = {}) {
    this.now = now;
    this.systems = new Map();
    this.releases = new Map();
    this.audit = [];
  }

  register(manifest) {
    const validation = validateManifest(manifest);
    if (!validation.valid) throw new Error(`invalid manifest: ${validation.errors.join('; ')}`);
    const canonical = canonicalize(manifest);
    const digest = digestManifest(canonical);
    const id = canonical.identity.id;
    const releaseKey = `${id}@${canonical.identity.version}`;
    const existing = this.releases.get(releaseKey);
    if (existing && existing.digest !== digest) throw new Error('release version already exists with different content');
    const record = { registryId: randomUUID(), identityId: id, version: canonical.identity.version, manifest: canonical, digest, status: 'active', registeredAt: this.now() };
    this.releases.set(releaseKey, record);
    const system = this.systems.get(id) ?? { id, publisher: canonical.identity.publisher, type: canonical.identity.type, releases: [], status: 'active' };
    if (!system.releases.includes(canonical.identity.version)) system.releases.push(canonical.identity.version);
    system.currentVersion = canonical.identity.version;
    system.currentDigest = digest;
    system.updatedAt = this.now();
    this.systems.set(id, system);
    this.#audit('release.registered', id, { version: record.version, digest });
    return structuredClone(record);
  }

  inspect(id) {
    const system = this.systems.get(id);
    if (!system) return null;
    const release = this.releases.get(`${id}@${system.currentVersion}`);
    return { system: structuredClone(system), release: structuredClone(release) };
  }

  verify(id, version) {
    const release = this.releases.get(`${id}@${version}`);
    if (!release) return { verified: false, reason: 'release-not-found' };
    const calculated = digestManifest(release.manifest);
    return { verified: calculated === release.digest, expectedDigest: release.digest, calculatedDigest: calculated };
  }

  search({ type, capability, publisher } = {}) {
    return [...this.systems.values()].filter((system) => {
      const release = this.releases.get(`${system.id}@${system.currentVersion}`);
      if (type && system.type !== type) return false;
      if (publisher && system.publisher !== publisher) return false;
      if (capability && !(release.manifest.capabilities ?? []).some((item) => typeof item === 'string' ? item === capability : item?.name === capability)) return false;
      return true;
    }).map((system) => structuredClone(system));
  }

  setLifecycle(id, status) {
    if (!['active','superseded','revoked','retired'].includes(status)) throw new Error('invalid lifecycle status');
    const system = this.systems.get(id);
    if (!system) throw new Error('system not found');
    system.status = status;
    system.updatedAt = this.now();
    this.#audit('system.lifecycle_changed', id, { status });
    return structuredClone(system);
  }

  #audit(type, identityId, payload) {
    this.audit.push({ id: randomUUID(), type, identityId, at: this.now(), payload: structuredClone(payload) });
  }
}
