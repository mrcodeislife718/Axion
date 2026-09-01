import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';
import { AxionStore } from '../src/store.js';
import { AxionKeyRing } from '../src/signing.js';
import { AxionService } from '../src/service.js';
import { createAxionHandler } from '../src/http-app.js';

const manifest = id => ({ axion_version:'1.0', identity:{ id, name:'Durable Worker', version:'1.0.0', publisher:'test', type:'agent' }, capabilities:['code'], permissions:['repository:write'] });

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'axion-prod-'));
  const store = new AxionStore({ home: root });
  const service = new AxionService({ store, keyRing:new AxionKeyRing({ root:path.join(root,'keys') }) }).initialize();
  const server = http.createServer(createAxionHandler({ service }));
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  return { root, store, service, server, base:`http://127.0.0.1:${server.address().port}` };
}
async function json(base, pathname, { method='GET', token=null, body=null }={}) {
  const res = await fetch(`${base}${pathname}`, { method, headers:{ ...(token?{authorization:`Bearer ${token}`}:{ }), ...(body?{'content-type':'application/json'}:{}) }, body:body?JSON.stringify(body):undefined });
  return { status:res.status, body:await res.json() };
}

test('mutating routes execute authentication and scope checks', async () => {
  const f=await fixture();
  try {
    const denied=await json(f.base,'/v1/identities',{method:'POST',body:manifest('axion:agent:denied')});
    assert.equal(denied.status,401);
    const boot=await json(f.base,'/v1/bootstrap',{method:'POST',body:{organizationName:'Test Org'}});
    assert.equal(boot.status,201);
    const created=await json(f.base,'/v1/identities',{method:'POST',token:boot.body.apiKey,body:manifest('axion:agent:worker')});
    assert.equal(created.status,201);
    const reader=f.store.issueApiKey({organizationId:boot.body.organization.id,label:'reader',scopes:['registry:read']});
    const scopeDenied=await json(f.base,'/v1/identities/axion%3Aagent%3Aworker/lifecycle',{method:'POST',token:reader.apiKey,body:{status:'retired'}});
    assert.equal(scopeDenied.status,403);
  } finally { await new Promise(resolve=>f.server.close(resolve)); f.service.close(); await rm(f.root,{recursive:true,force:true}); }
});

test('durable worker identity survives provider swaps and qualifications remain separate', async () => {
  const f=await fixture();
  try {
    const boot=await json(f.base,'/v1/bootstrap',{method:'POST',body:{organizationName:'Identity Org'}});
    const token=boot.body.apiKey; const identity='axion:agent:maya';
    assert.equal((await json(f.base,'/v1/identities',{method:'POST',token,body:manifest(identity)})).status,201);
    const qwen=await json(f.base,`/v1/identities/${encodeURIComponent(identity)}/provider-sessions`,{method:'POST',token,body:{provider:'qwen',model:'qwen-test'}});
    const codex=await json(f.base,`/v1/identities/${encodeURIComponent(identity)}/provider-sessions`,{method:'POST',token,body:{provider:'codex',model:'codex-test'}});
    assert.equal(qwen.status,201); assert.equal(codex.status,201);
    assert.equal(qwen.body.identity_id,identity); assert.equal(codex.body.identity_id,identity); assert.notEqual(qwen.body.id,codex.body.id);
    const qualification=await json(f.base,`/v1/identities/${encodeURIComponent(identity)}/qualifications`,{method:'POST',token,body:{kind:'repository-editing',status:'qualified',score:0.95,evidence:['test-suite-1']}});
    assert.equal(qualification.status,201);
    const passport=await json(f.base,`/v1/identities/${encodeURIComponent(identity)}/passport`,{token});
    assert.equal(passport.body.passport.identity.id,identity);
    assert.equal(passport.body.passport.providerSessions.length,2);
    assert.equal(passport.body.passport.trust.activeQualifications,1);
  } finally { await new Promise(resolve=>f.server.close(resolve)); f.service.close(); await rm(f.root,{recursive:true,force:true}); }
});

test('signed passports detect tampering and revoked keys stop verifying', async () => {
  const f=await fixture();
  try {
    const boot=f.service.bootstrap('Signing Org');
    const principal=f.store.authenticateApiKey(boot.apiKey);
    f.service.register(manifest('axion:agent:signed'),principal);
    const bundle=f.service.passport('axion:agent:signed',principal);
    assert.equal(bundle.verification.verified,true);
    const tampered=structuredClone(bundle.passport); tampered.identity.status='revoked';
    assert.equal(f.service.keyRing.verify(tampered,bundle.signature).verified,false);
    const oldKey=bundle.signature.keyId;
    const rotated=f.service.rotateSigningKey('rotation',principal);
    assert.notEqual(rotated.keyId,oldKey);
    assert.equal(f.service.keyRing.verify(bundle.passport,bundle.signature).verified,true);
    f.service.revokeSigningKey(oldKey,'compromised',principal);
    assert.equal(f.service.keyRing.verify(bundle.passport,bundle.signature).verified,false);
  } finally { f.service.close(); await rm(f.root,{recursive:true,force:true}); }
});

test('tenant ownership prevents cross-organization identity access', async () => {
  const f=await fixture();
  try {
    const a=f.service.bootstrap('Org A');
    const orgB=f.store.createOrganization('Org B');
    const b=f.store.issueApiKey({organizationId:orgB.id,scopes:['*']});
    const pa=f.store.authenticateApiKey(a.apiKey), pb=f.store.authenticateApiKey(b.apiKey);
    f.service.register(manifest('axion:agent:private'),pa);
    assert.throws(()=>f.service.inspect('axion:agent:private',pb),/another organization/);
  } finally { f.service.close(); await rm(f.root,{recursive:true,force:true}); }
});
