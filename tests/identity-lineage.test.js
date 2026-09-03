import test from 'node:test';
import assert from 'node:assert/strict';
import { IdentityRegistry } from '../src/identity-lineage.js';

test('tracks identity lineage, credentials and revocation', () => {
  const registry = new IdentityRegistry();
  registry.register({ id: 'parent', owner: 'org-1' });
  registry.register({ id: 'child', owner: 'org-1', parentIdentityId: 'parent', model: 'model-x' });
  const credential = registry.attest('child', { attestor: 'org-1', subject: 'runtime', value: 'verified' });
  assert.deepEqual(registry.lineage('child').map(x => x.id), ['child', 'parent']);
  assert.equal(registry.credential(credential.id).status, 'active');
  registry.revoke('child', { reason: 'retired', revokedBy: 'org-1' });
  assert.equal(registry.identity('child').status, 'revoked');
  assert.equal(registry.credential(credential.id).status, 'revoked');
});
