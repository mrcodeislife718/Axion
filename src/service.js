import { AxionRegistry } from './axion.js';
import { AxionCredentialRegistry } from './credentials.js';
import { JsonStore } from './store.js';

const mapEntries = (map) => [...map.entries()].map(([key, value]) => [key, structuredClone(value)]);
const fromEntries = (items = []) => new Map(items.map(([key, value]) => [key, value]));

export class AxionService {
  constructor({ registry = new AxionRegistry(), store = new JsonStore(process.env.AXION_DATA ?? './data/axion.json') } = {}) {
    this.registry = registry;
    this.credentials = new AxionCredentialRegistry(registry);
    this.store = store;
  }

  async initialize() {
    const state = await this.store.load(null);
    if (!state) return this;
    this.registry.systems = fromEntries(state.systems);
    this.registry.releases = fromEntries(state.releases);
    this.registry.audit = state.audit ?? [];
    this.credentials.credentials = fromEntries(state.credentials);
    this.credentials.revocations = fromEntries(state.revocations);
    return this;
  }

  snapshot() {
    return {
      systems: mapEntries(this.registry.systems),
      releases: mapEntries(this.registry.releases),
      audit: structuredClone(this.registry.audit),
      credentials: mapEntries(this.credentials.credentials),
      revocations: mapEntries(this.credentials.revocations),
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
      },
      identities: systems,
      credentials,
      audit: this.registry.audit.slice(-50).reverse().map((event) => structuredClone(event)),
    };
  }

  async register(manifest) { const result = this.registry.register(manifest); await this.persist(); return result; }
  inspect(id) { return this.registry.inspect(id); }
  search(filters) { return this.registry.search(filters); }
  verifyRelease(id, version) { return this.registry.verify(id, version); }
  async setLifecycle(id, status) { const result = this.registry.setLifecycle(id, status); await this.persist(); return result; }
  async issueCredential(input) { const result = this.credentials.issue(input); await this.persist(); return result; }
  verifyCredential(id) { return this.credentials.verify(id); }
  async revokeCredential(id, input) { const result = this.credentials.revoke(id, input); await this.persist(); return result; }
}
