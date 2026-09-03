import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { afterEach, test } from 'node:test';
import { createAxionHandler } from '../src/http-app.js';

const servers = new Set();
afterEach(async () => {
  await Promise.all([...servers].map((server) => new Promise((resolve) => server.close(resolve))));
  servers.clear();
});

function fakeService() {
  return {
    async initialize() { return this; },
    dashboard() { return { identities: 1 }; },
    async register(input) { return { registered: true, input }; },
    inspect(id) { return id === 'known' ? { id, lifecycle: 'active' } : null; },
    async setLifecycle(id, status) { return { id, status }; },
    async issueCredential(input) { return { credentialId: 'cred-1', ...input }; },
    verifyCredential(id) { return { credentialId: id, verified: true }; },
    async revokeCredential(id, input) { return { credentialId: id, revoked: true, ...input }; },
  };
}

async function listen(handler) {
  const server = createServer(handler);
  servers.add(server);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  return `http://127.0.0.1:${address.port}`;
}

async function expectStatus(response, status) {
  if (response.status === status) return;
  assert.fail(`Expected HTTP ${status}, received ${response.status}: ${await response.text()}`);
}

test('production fails closed without registry authority', async () => {
  await assert.rejects(createAxionHandler({ service: fakeService(), requireAuthority: true, authorityKey: '' }), /AXION_AUTHORITY_KEY is required/);
});

test('identity inspection and credential verification remain public while mutations are protected', async () => {
  const base = await listen(await createAxionHandler({ service: fakeService(), requireAuthority: true, authorityKey: 'authority-secret' }));
  const identity = await fetch(`${base}/api/identities/known`);
  await expectStatus(identity, 200);
  assert.equal((await identity.json()).lifecycle, 'active');

  const verified = await fetch(`${base}/api/credentials/cred-1/verify`);
  await expectStatus(verified, 200);
  assert.equal((await verified.json()).verified, true);

  const denied = await fetch(`${base}/api/identities`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  await expectStatus(denied, 401);
  assert.equal((await denied.json()).error, 'registry_authority_required');

  const allowed = await fetch(`${base}/api/identities`, { method: 'POST', headers: { authorization: 'Bearer authority-secret', 'content-type': 'application/json' }, body: '{}' });
  await expectStatus(allowed, 201);
  assert.equal((await allowed.json()).registered, true);
});

test('unknown public identity returns 404 instead of a 200 error envelope', async () => {
  const base = await listen(await createAxionHandler({ service: fakeService(), requireAuthority: true, authorityKey: 'authority-secret' }));
  const response = await fetch(`${base}/api/identities/unknown`);
  await expectStatus(response, 404);
});

test('API rate limiting covers public trust reads and protected operations', async () => {
  const base = await listen(await createAxionHandler({ service: fakeService(), requireAuthority: true, authorityKey: 'authority-secret', rateLimitMax: 1, rateLimitWindowMs: 60_000 }));
  await expectStatus(await fetch(`${base}/api/identities/known`), 200);
  const limited = await fetch(`${base}/api/credentials/cred-1/verify`);
  await expectStatus(limited, 429);
  assert.equal((await limited.json()).error, 'rate_limited');
});
