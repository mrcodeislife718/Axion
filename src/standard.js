import { canonicalize, digestManifest, validateManifest } from './axion.js';

export const AXION_STANDARD_VERSION = '1.0';
export const CORE_PROTOCOLS = new Set(['a2a','mcp','http','https','json-rpc','sse','websocket','stdio']);

function asArray(value) { return Array.isArray(value) ? value : []; }
function stringSet(value) { return new Set(asArray(value).filter(item=>typeof item==='string')); }
function object(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {}; }

export function normalizeIdentityId(value) {
  if (typeof value !== 'string') throw new Error('identity id must be a string');
  const id = value.trim().toLowerCase();
  if (!/^axion:[a-z0-9-]+:[a-z0-9._/-]+$/.test(id)) throw new Error('identity id is invalid');
  if (id.includes('/../') || id.endsWith('/..') || id.includes('//')) throw new Error('identity id path is invalid');
  return id;
}

export function validateAxionPassportManifest(manifest) {
  const base = validateManifest(manifest);
  const errors = [...base.errors];
  if (manifest?.identity?.id) {
    try { if (normalizeIdentityId(manifest.identity.id) !== manifest.identity.id.toLowerCase()) errors.push('identity.id is not canonical'); }
    catch (error) { errors.push(error.message); }
  }
  const compatibility = object(manifest?.compatibility);
  const protocols = asArray(compatibility.protocols);
  for (const protocol of protocols) {
    const name = typeof protocol === 'string' ? protocol : protocol?.name;
    if (!name || typeof name !== 'string') errors.push('compatibility protocol entry must have a name');
  }
  const extensions = object(manifest?.extensions);
  for (const key of Object.keys(extensions)) if (!/^[a-z0-9][a-z0-9.-]*\/[a-z0-9._-]+$/i.test(key)) errors.push(`extension key must be namespaced: ${key}`);
  return { valid: errors.length === 0, errors, canonical: errors.length ? null : canonicalize(manifest), digest: errors.length ? null : digestManifest(manifest), standardVersion:AXION_STANDARD_VERSION };
}

export function fromA2AAgentCard(card, { publisher = 'unknown', identityId = null } = {}) {
  if (!card || typeof card !== 'object') throw new Error('A2A Agent Card must be an object');
  const name = String(card.name || card.title || '').trim();
  if (!name) throw new Error('A2A Agent Card name required');
  const skills = asArray(card.skills).map(skill => typeof skill === 'string' ? skill : skill?.id || skill?.name).filter(Boolean);
  const url = card.url || card.endpoint || null;
  const id = identityId || `axion:agent:${String(publisher).toLowerCase().replace(/[^a-z0-9.-]+/g,'-')}/${name.toLowerCase().replace(/[^a-z0-9._-]+/g,'-')}`;
  const manifest = {
    axion_version:'1.0',
    identity:{ id, name, version:String(card.version || '0.0.0'), publisher:String(publisher), type:'agent' },
    capabilities:skills,
    permissions:[],
    compatibility:{ protocols:[{name:'a2a',version:String(card.protocolVersion || card.version || 'unknown')}], transports:url?[{type:'https',endpoint:url}]:[] },
    extensions:{ 'a2a.project/source-card': canonicalize(card) },
  };
  return { manifest, source:'a2a-agent-card', partial:true, unsupportedFields:Object.keys(card).filter(key=>!['name','title','skills','url','endpoint','version','protocolVersion'].includes(key)), validation:validateAxionPassportManifest(manifest) };
}

export function fromMcpServerJson(server, { publisher = 'unknown', identityId = null } = {}) {
  if (!server || typeof server !== 'object') throw new Error('MCP server.json must be an object');
  const name = String(server.name || server.title || '').trim();
  if (!name) throw new Error('MCP server name required');
  const id = identityId || `axion:mcp-server:${String(publisher).toLowerCase().replace(/[^a-z0-9.-]+/g,'-')}/${name.toLowerCase().replace(/[^a-z0-9._-]+/g,'-')}`;
  const packages = asArray(server.packages);
  const remotes = asArray(server.remotes);
  const manifest = {
    axion_version:'1.0',
    identity:{ id, name, version:String(server.version || '0.0.0'), publisher:String(publisher), type:'mcp-server' },
    capabilities:asArray(server.capabilities),
    permissions:[],
    compatibility:{ protocols:[{name:'mcp',version:String(server.protocolVersion || 'unknown')}], packages, remotes },
    extensions:{ 'modelcontextprotocol.io/source-server': canonicalize(server) },
  };
  return { manifest, source:'mcp-server-json', partial:true, unsupportedFields:Object.keys(server).filter(key=>!['name','title','version','protocolVersion','packages','remotes','capabilities'].includes(key)), validation:validateAxionPassportManifest(manifest) };
}

function protocolMap(manifest) {
  const protocols = asArray(object(manifest.compatibility).protocols);
  const map = new Map();
  for (const item of protocols) {
    if (typeof item === 'string') map.set(item,{name:item});
    else if (item?.name) map.set(item.name,item);
  }
  return map;
}

export function resolveCompatibility(left, right) {
  const leftValidation = validateAxionPassportManifest(left), rightValidation = validateAxionPassportManifest(right);
  if (!leftValidation.valid || !rightValidation.valid) return { status:'incompatible', reasons:['invalid-manifest'], leftErrors:leftValidation.errors, rightErrors:rightValidation.errors };
  const reasons = [], conditions = [];
  const leftProtocols = protocolMap(left), rightProtocols = protocolMap(right);
  const commonProtocols = [...leftProtocols.keys()].filter(name=>rightProtocols.has(name));
  if (leftProtocols.size && rightProtocols.size && commonProtocols.length===0) reasons.push('no-common-protocol');
  for (const name of commonProtocols) {
    const a=leftProtocols.get(name), b=rightProtocols.get(name);
    if (a.version && b.version && a.version!=='unknown' && b.version!=='unknown' && a.version!==b.version) conditions.push(`protocol-version-negotiation:${name}:${a.version}:${b.version}`);
  }
  const leftRequires = stringSet(object(left.compatibility).requires);
  const rightCapabilities = new Set(asArray(right.capabilities).map(item=>typeof item==='string'?item:item?.name).filter(Boolean));
  const missingLeftRequirements = [...leftRequires].filter(item=>!rightCapabilities.has(item));
  if (missingLeftRequirements.length) reasons.push(...missingLeftRequirements.map(item=>`missing-required-capability:${item}`));
  const rightRequires = stringSet(object(right.compatibility).requires);
  const leftCapabilities = new Set(asArray(left.capabilities).map(item=>typeof item==='string'?item:item?.name).filter(Boolean));
  const missingRightRequirements = [...rightRequires].filter(item=>!leftCapabilities.has(item));
  if (missingRightRequirements.length) reasons.push(...missingRightRequirements.map(item=>`missing-required-capability:${item}`));
  const status = reasons.length ? 'incompatible' : conditions.length ? 'conditional' : (commonProtocols.length || (!leftProtocols.size && !rightProtocols.size)) ? 'compatible' : 'unknown';
  return { status, reasons, conditions, commonProtocols, leftIdentity:left.identity.id, rightIdentity:right.identity.id };
}

export function conformanceVector(manifest) {
  const result = validateAxionPassportManifest(manifest);
  return { standardVersion:AXION_STANDARD_VERSION, valid:result.valid, errors:result.errors, canonical:result.canonical, digest:result.digest };
}
