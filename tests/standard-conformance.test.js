import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { fromA2AAgentCard, fromMcpServerJson, resolveCompatibility, validateAxionPassportManifest } from '../src/standard.js';
import { AxionTransparencyLedger } from '../src/transparency-ledger.js';

const manifest = (id,protocol,capabilities=[]) => ({
  axion_version:'1.0', identity:{id,name:id,version:'1.0.0',publisher:'test',type:'agent'}, capabilities, permissions:[], compatibility:{protocols:[{name:protocol,version:'1'}]}, extensions:{'example.org/test':{ok:true}}
});

test('Axion manifest conformance is deterministic and requires namespaced extensions', () => {
  const good=validateAxionPassportManifest(manifest('axion:agent:test/one','a2a'));
  assert.equal(good.valid,true); assert.ok(good.digest);
  assert.equal(validateAxionPassportManifest({...manifest('axion:agent:test/two','mcp'),extensions:{bad:{}}}).valid,false);
});

test('A2A and MCP records translate without inventing unsupported claims', () => {
  const a2a=fromA2AAgentCard({name:'Researcher',version:'1.0.0',protocolVersion:'1',url:'https://example.test/a2a',skills:[{id:'research'}]},{publisher:'example.org'});
  assert.equal(a2a.validation.valid,true); assert.equal(a2a.manifest.compatibility.protocols[0].name,'a2a');
  const mcp=fromMcpServerJson({name:'tools',version:'1.0.0',packages:[{registryType:'npm',identifier:'tools'}]},{publisher:'example.org'});
  assert.equal(mcp.validation.valid,true); assert.equal(mcp.manifest.identity.type,'mcp-server');
});

test('compatibility resolver rejects incompatible protocols and reports shared protocols', () => {
  assert.equal(resolveCompatibility(manifest('axion:agent:a/one','a2a'),manifest('axion:agent:b/two','mcp')).status,'incompatible');
  const compatible=resolveCompatibility(manifest('axion:agent:a/one','a2a',['search']),manifest('axion:agent:b/two','a2a',['search']));
  assert.equal(compatible.status,'compatible'); assert.deepEqual(compatible.commonProtocols,['a2a']);
});

test('transparency ledger detects historical tampering', () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'axion-ledger-'));
  try {
    const ledger=new AxionTransparencyLedger({root});
    ledger.append('release.registered','axion:agent:test/one',{version:'1.0.0',digest:'abc'});
    ledger.append('identity.lifecycle','axion:agent:test/one',{status:'revoked'});
    assert.equal(ledger.verify().verified,true);
    const lines=fs.readFileSync(path.join(root,'ledger.ndjson'),'utf8').trim().split('\n');
    const first=JSON.parse(lines[0]); first.payload.digest='tampered'; lines[0]=JSON.stringify(first); fs.writeFileSync(path.join(root,'ledger.ndjson'),`${lines.join('\n')}\n`);
    assert.equal(ledger.verify().verified,false);
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});
