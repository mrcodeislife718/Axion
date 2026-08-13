import test from 'node:test';
import assert from 'node:assert/strict';
import { AxionRegistry, digestManifest, validateManifest } from '../src/axion.js';

const manifest = { axion_version: '1.0', identity: { id: 'axion:agent:reviewer', name: 'Reviewer', version: '1.0.0', publisher: 'Studio', type: 'agent' }, capabilities: ['code-review'], permissions: [], compatibility: {}, governance: {}, observability: {}, verification: {} };

test('manifest validation and canonical digest are deterministic', () => {
  assert.equal(validateManifest(manifest).valid, true);
  const reordered = { permissions: [], identity: manifest.identity, capabilities: ['code-review'], axion_version: '1.0', verification: {}, governance: {}, observability: {}, compatibility: {} };
  assert.equal(digestManifest(manifest), digestManifest(reordered));
});

test('registry registers, verifies and discovers a system', () => {
  const registry = new AxionRegistry({ now: () => '2026-08-13T18:30:00.000Z' });
  const release = registry.register(manifest);
  assert.equal(release.identityId, manifest.identity.id);
  assert.equal(registry.verify(manifest.identity.id, '1.0.0').verified, true);
  assert.equal(registry.search({ capability: 'code-review' }).length, 1);
  assert.equal(registry.setLifecycle(manifest.identity.id, 'retired').status, 'retired');
});

test('same identity version cannot silently mutate', () => {
  const registry = new AxionRegistry();
  registry.register(manifest);
  const changed = structuredClone(manifest);
  changed.capabilities = ['code-review', 'planning'];
  assert.throws(() => registry.register(changed), /different content/);
});
