import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AxionService } from '../src/service.js';
import { JsonStore } from '../src/store.js';

const manifest = {
  axion_version: '1.0',
  identity: { id: 'axion:agent:prod', name: 'Production Agent', version: '1.0.0', publisher: 'example', type: 'agent' },
  capabilities: ['search'],
  permissions: [],
};

test('persists identity, credential, and lifecycle state', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'axion-'));
  try {
    const path = join(dir, 'state.json');
    const service = await new AxionService({ store: new JsonStore(path) }).initialize();
    await service.register(manifest);
    const credential = await service.issueCredential({ subjectId: manifest.identity.id, issuerId: 'axion:issuer:ops', claims: { approved: true } });
    assert.equal(service.verifyCredential(credential.credentialId).verified, true);

    const restored = await new AxionService({ store: new JsonStore(path) }).initialize();
    assert.equal(restored.inspect(manifest.identity.id).system.currentVersion, '1.0.0');
    assert.equal(restored.verifyCredential(credential.credentialId).verified, true);
    await restored.revokeCredential(credential.credentialId, { reason: 'test revocation', revokedBy: 'axion:issuer:ops' });
    assert.equal(restored.verifyCredential(credential.credentialId).reason, 'credential-revoked');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
