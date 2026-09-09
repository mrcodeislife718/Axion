import test from 'node:test';
import assert from 'node:assert/strict';
import { AgentAuthorityLedger } from '../src/agent-authority.js';

test('delegation can only narrow parent authority', () => {
  const ledger = new AgentAuthorityLedger({ now: () => 1000 });
  ledger.registerAgent({ id: 'owner-agent', ownerId: 'org-1', version: '1.0.0', capabilities: ['read','write'], resourceScopes: ['db:*'], credentialScopes: ['vault:read'], quotas: { writes: 10 } });
  ledger.registerAgent({ id: 'child-agent', ownerId: 'org-1', version: '1.0.0', capabilities: ['read','write'], resourceScopes: ['db:*'], credentialScopes: ['vault:read'], quotas: { writes: 100 } });
  const delegation = ledger.delegate({ fromId: 'owner-agent', toId: 'child-agent', capabilities: ['write','admin'], resourceScopes: ['db:customers','other:*'], credentialScopes: ['vault:read','vault:write'], quotas: { writes: 50 } });
  assert.deepEqual(delegation.capabilities, ['write']);
  assert.deepEqual(delegation.resourceScopes, ['db:customers']);
  assert.deepEqual(delegation.credentialScopes, ['vault:read']);
  assert.equal(delegation.quotas.writes, 10);
  assert.equal(ledger.evaluate({ actorId: 'child-agent', delegationId: delegation.id, capability: 'write', resource: 'db:customers', credential: 'vault:read', usage: { writes: 9 } }).allowed, true);
  assert.equal(ledger.evaluate({ actorId: 'child-agent', delegationId: delegation.id, capability: 'write', resource: 'db:customers', usage: { writes: 11 } }).allowed, false);
});

test('revocation and expiry fail closed', () => {
  let now = 1000;
  const ledger = new AgentAuthorityLedger({ now: () => now });
  ledger.registerAgent({ id: 'agent-a', ownerId: 'org-1', version: '1.0.0', capabilities: ['read'], resourceScopes: ['*'], expiresAt: 1100 });
  assert.equal(ledger.evaluate({ actorId: 'agent-a', capability: 'read' }).allowed, true);
  now = 1200;
  assert.throws(() => ledger.evaluate({ actorId: 'agent-a', capability: 'read' }), /expired/);
});
