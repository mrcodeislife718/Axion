import { AxionRegistry } from './axion.js';
const registry = new AxionRegistry();
const manifest = { axion_version: '1.0', identity: { id: 'axion:agent:example', name: 'Example Agent', version: '1.0.0', publisher: 'Example Publisher', type: 'agent' }, capabilities: ['code-review'], permissions: [], compatibility: {}, governance: {}, observability: {}, verification: {} };
const release = registry.register(manifest);
console.log(JSON.stringify({ release, verification: registry.verify(manifest.identity.id, manifest.identity.version) }, null, 2));
