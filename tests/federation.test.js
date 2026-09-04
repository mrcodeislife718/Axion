import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { AxionKeyRing } from '../src/signing.js';
import { AxionTransparencyLedger } from '../src/transparency-ledger.js';
import { createTrustBundle, trustBundleAllowsIdentity, verifyTrustBundle } from '../src/trust-bundle.js';

function fixture() {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'axion-federation-'));
  const keyRing=new AxionKeyRing({root:path.join(root,'keys')});
  const ledger=new AxionTransparencyLedger({root:path.join(root,'ledger')});
  ledger.append('release.registered','axion:agent:example.org/worker',{version:'1.0.0',digest:'abc'});
  return {root,keyRing,ledger};
}

test('trust domain bundle verifies offline when its signing key is pinned', () => {
  const f=fixture();
  try {
    const envelope=createTrustBundle({domainId:'axion:trust-domain:example.org',namespaceRoots:['axion:agent:example.org'],keyRing:f.keyRing,ledger:f.ledger,nowMs:Date.parse('2026-09-02T12:00:00Z')});
    const result=verifyTrustBundle(envelope,{expectedDomainId:'axion:trust-domain:example.org',trustedKeyIds:[envelope.signature.keyId],nowMs:Date.parse('2026-09-02T12:01:00Z')});
    assert.equal(result.verified,true);
    assert.equal(result.domainId,'axion:trust-domain:example.org');
    assert.equal(trustBundleAllowsIdentity(envelope,'axion:agent:example.org/worker'),true);
    assert.equal(trustBundleAllowsIdentity(envelope,'axion:agent:other.org/worker'),false);
  } finally { fs.rmSync(f.root,{recursive:true,force:true}); }
});

test('trust bundle fails closed for an unpinned domain key', () => {
  const f=fixture();
  try {
    const envelope=createTrustBundle({domainId:'axion:trust-domain:example.org',namespaceRoots:['axion:agent:example.org'],keyRing:f.keyRing,ledger:f.ledger,nowMs:Date.parse('2026-09-02T12:00:00Z')});
    const result=verifyTrustBundle(envelope,{trustedKeyIds:['axion:key:not-trusted'],nowMs:Date.parse('2026-09-02T12:01:00Z')});
    assert.equal(result.verified,false);
    assert.equal(result.reason,'untrusted-domain-key');
  } finally { fs.rmSync(f.root,{recursive:true,force:true}); }
});

test('trust bundle expiry and embedded transparency checkpoint are enforced', () => {
  const f=fixture();
  try {
    const envelope=createTrustBundle({domainId:'axion:trust-domain:example.org',namespaceRoots:['axion:agent:example.org'],keyRing:f.keyRing,ledger:f.ledger,ttlMs:30_000,nowMs:Date.parse('2026-09-02T12:00:00Z')});
    assert.equal(verifyTrustBundle(envelope,{nowMs:Date.parse('2026-09-02T12:00:31Z')}).reason,'trust-bundle-expired');
    const tampered=structuredClone(envelope);
    tampered.bundle.transparencyCheckpoint.statement.headHash='tampered';
    const result=verifyTrustBundle(tampered,{nowMs:Date.parse('2026-09-02T12:00:10Z')});
    assert.equal(result.verified,false);
  } finally { fs.rmSync(f.root,{recursive:true,force:true}); }
});
