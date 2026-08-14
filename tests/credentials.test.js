import test from 'node:test';
import assert from 'node:assert/strict';
import { AxionRegistry } from '../src/axion.js';
import { AxionCredentialRegistry } from '../src/credentials.js';

function manifest(version = '1.0.0') {
  return {
    axion_version: '1.0',
    identity: {
      id: 'axion:agent:example',
      name: 'Example Agent',
      version,
      publisher: 'example',
      type: 'agent',
    },
    capabilities: ['search'],
    permissions: [],
  };
}

test('issues and verifies an integrity-bound credential', () => {
  const registry = new AxionRegistry({ now: () => '2026-08-13T20:00:00.000Z' });
  registry.register(manifest());
  const credentials = new AxionCredentialRegistry(registry, { now: () => '2026-08-13T20:00:00.000Z' });
  const credential = credentials.issue({ subjectId: 'axion:agent:example', issuerId: 'axion:issuer:test', claims: { productionApproved: true }, evidence: [{ type: 'test-suite', result: 'passed' }] });
  const result = credentials.verify(credential.credentialId);
  assert.equal(result.verified, true);
  assert.equal(result.credential.subjectDigest, registry.inspect('axion:agent:example').system.currentDigest);
});

test('revocation invalidates a credential', () => {
  const registry = new AxionRegistry();
  registry.register(manifest());
  const credentials = new AxionCredentialRegistry(registry);
  const credential = credentials.issue({ subjectId: 'axion:agent:example', issuerId: 'axion:issuer:test', claims: { trusted: true } });
  credentials.revoke(credential.credentialId, { reason: 'superseded', revokedBy: 'axion:issuer:test' });
  assert.deepEqual(credentials.verify(credential.credentialId), { verified: false, reason: 'credential-revoked' });
});

test('credential fails when subject release changes', () => {
  const registry = new AxionRegistry();
  registry.register(manifest('1.0.0'));
  const credentials = new AxionCredentialRegistry(registry);
  const credential = credentials.issue({ subjectId: 'axion:agent:example', issuerId: 'axion:issuer:test', claims: { trusted: true } });
  registry.register(manifest('1.1.0'));
  assert.equal(credentials.verify(credential.credentialId).reason, 'subject-release-changed');
});
