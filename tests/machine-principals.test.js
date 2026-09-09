import test from 'node:test';
import assert from 'node:assert/strict';
import { AxionRegistry } from '../src/axion.js';

test('agent executions are distinct identities linked to the persistent agent', () => {
  const registry=new AxionRegistry({now:()=> '2026-09-09T14:00:00.000Z'});
  registry.register({axion_version:'1.0',identity:{id:'axion:agent:maya',name:'Maya',version:'1.0.0',publisher:'Charles',type:'agent'},capabilities:['career']});
  const run=registry.register({axion_version:'1.0',identity:{id:'axion:execution:maya-run-1',name:'Maya run 1',version:'1.0.0',publisher:'Charles',type:'agent-execution',parent_agent_id:'axion:agent:maya'},capabilities:['career']});
  assert.equal(registry.inspect(run.identityId).system.parentAgentId,'axion:agent:maya');
});

test('agent execution identity fails validation without a parent agent', () => {
  const registry=new AxionRegistry();
  assert.throws(()=>registry.register({axion_version:'1.0',identity:{id:'axion:execution:orphan',name:'orphan',version:'1.0.0',publisher:'Charles',type:'agent-execution'}}),/parent_agent_id/);
});
