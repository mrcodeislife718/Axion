import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';

const now = () => new Date().toISOString();
const id = prefix => `${prefix}_${crypto.randomUUID()}`;
const hash = value => crypto.createHash('sha256').update(String(value)).digest('hex');

export class AxionStore {
  constructor({ home = process.env.AXION_HOME || path.join(os.homedir(), '.axion') } = {}) {
    this.home = path.resolve(home);
    fs.mkdirSync(this.home, { recursive: true, mode: 0o700 });
    this.dbPath = path.join(this.home, 'axion.sqlite');
    this.db = new Database(this.dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.migrate();
  }

  migrate() {
    this.db.exec(`
      create table if not exists schema_migrations(version integer primary key,name text not null,applied_at text not null);
      create table if not exists registry_state(id integer primary key check(id=1),snapshot_json text not null,updated_at text not null);
      create table if not exists organizations(id text primary key,name text not null,status text not null,created_at text not null,updated_at text not null);
      create table if not exists api_keys(id text primary key,organization_id text not null,label text not null,secret_hash text not null,scopes_json text not null,status text not null,created_at text not null,expires_at text,revoked_at text,last_used_at text,foreign key(organization_id) references organizations(id));
      create table if not exists identity_owners(identity_id text primary key,organization_id text not null,created_at text not null,foreign key(organization_id) references organizations(id));
      create table if not exists provider_sessions(id text primary key,identity_id text not null,organization_id text not null,provider text not null,model text,external_session_id text,status text not null,started_at text not null,ended_at text,metadata_json text not null);
      create table if not exists qualifications(id text primary key,identity_id text not null,organization_id text not null,kind text not null,status text not null,score real,evidence_json text not null,recorded_at text not null,expires_at text,revoked_at text);
      create table if not exists security_audit(id text primary key,organization_id text,event_type text not null,principal_key_id text,payload_json text not null,created_at text not null);
      create index if not exists idx_api_keys_org on api_keys(organization_id,status);
      create index if not exists idx_provider_identity on provider_sessions(identity_id,started_at);
      create index if not exists idx_qual_identity on qualifications(identity_id,recorded_at);
    `);
    if (!this.db.prepare('select 1 from schema_migrations where version=1').get()) {
      this.db.prepare('insert into schema_migrations(version,name,applied_at) values(1,?,?)').run('durable_identity_store', now());
    }
  }

  loadSnapshot() { const row = this.db.prepare('select snapshot_json from registry_state where id=1').get(); return row ? JSON.parse(row.snapshot_json) : null; }
  saveSnapshot(snapshot) { this.db.prepare(`insert into registry_state(id,snapshot_json,updated_at) values(1,?,?) on conflict(id) do update set snapshot_json=excluded.snapshot_json,updated_at=excluded.updated_at`).run(JSON.stringify(snapshot), now()); }

  createOrganization(name) {
    if (typeof name !== 'string' || name.trim().length < 2) throw new Error('organization name required');
    const row = { id: id('org'), name: name.trim(), status: 'active', created_at: now(), updated_at: now() };
    this.db.prepare('insert into organizations(id,name,status,created_at,updated_at) values(@id,@name,@status,@created_at,@updated_at)').run(row);
    return row;
  }
  getOrganization(orgId) { return this.db.prepare('select * from organizations where id=?').get(orgId) || null; }

  issueApiKey({ organizationId, label = 'default', scopes = ['registry:read'] }) {
    if (!this.getOrganization(organizationId)) throw new Error('organization not found');
    const keyId = id('key'); const secret = crypto.randomBytes(32).toString('base64url');
    this.db.prepare('insert into api_keys(id,organization_id,label,secret_hash,scopes_json,status,created_at) values(?,?,?,?,?,\'active\',?)').run(keyId, organizationId, label, hash(secret), JSON.stringify(scopes), now());
    return { apiKey: `axk_${keyId}.${secret}`, keyId, organizationId, scopes };
  }
  authenticateApiKey(raw) {
    const match = /^axk_(key_[^.]+)\.(.+)$/.exec(String(raw || '')); if (!match) return null;
    const row = this.db.prepare('select * from api_keys where id=?').get(match[1]);
    if (!row || row.status !== 'active' || row.revoked_at || (row.expires_at && Date.parse(row.expires_at) <= Date.now())) return null;
    const a = Buffer.from(hash(match[2])); const b = Buffer.from(row.secret_hash);
    if (a.length !== b.length || !crypto.timingSafeEqual(a,b)) return null;
    this.db.prepare('update api_keys set last_used_at=? where id=?').run(now(), row.id);
    return { keyId: row.id, organizationId: row.organization_id, scopes: JSON.parse(row.scopes_json) };
  }
  revokeApiKey(keyId, organizationId) { this.db.prepare("update api_keys set status='revoked',revoked_at=? where id=? and organization_id=?").run(now(), keyId, organizationId); }

  claimIdentity(identityId, organizationId) {
    const current = this.db.prepare('select * from identity_owners where identity_id=?').get(identityId);
    if (current && current.organization_id !== organizationId) throw new Error('identity belongs to another organization');
    this.db.prepare('insert or ignore into identity_owners(identity_id,organization_id,created_at) values(?,?,?)').run(identityId, organizationId, now());
  }
  identityOrganization(identityId) { return this.db.prepare('select organization_id from identity_owners where identity_id=?').get(identityId)?.organization_id || null; }

  bindProviderSession({ identityId, organizationId, provider, model = null, externalSessionId = null, metadata = {} }) {
    this.db.prepare("update provider_sessions set status='ended',ended_at=? where identity_id=? and organization_id=? and status='active'").run(now(), identityId, organizationId);
    const row = { id: id('provider'), identity_id: identityId, organization_id: organizationId, provider, model, external_session_id: externalSessionId, status: 'active', started_at: now(), metadata_json: JSON.stringify(metadata || {}) };
    this.db.prepare('insert into provider_sessions(id,identity_id,organization_id,provider,model,external_session_id,status,started_at,metadata_json) values(@id,@identity_id,@organization_id,@provider,@model,@external_session_id,@status,@started_at,@metadata_json)').run(row);
    return { ...row, metadata };
  }
  providerSessions(identityId, organizationId) { return this.db.prepare('select * from provider_sessions where identity_id=? and organization_id=? order by started_at desc').all(identityId, organizationId).map(row => ({ ...row, metadata: JSON.parse(row.metadata_json) })); }

  recordQualification({ identityId, organizationId, kind, status, score = null, evidence = [], expiresAt = null }) {
    if (!['qualified','unverified','failed','revoked'].includes(status)) throw new Error('invalid qualification status');
    if (score != null && (!Number.isFinite(score) || score < 0 || score > 1)) throw new Error('qualification score must be between 0 and 1');
    const row = { id: id('qualification'), identity_id: identityId, organization_id: organizationId, kind, status, score, evidence_json: JSON.stringify(evidence), recorded_at: now(), expires_at: expiresAt };
    this.db.prepare('insert into qualifications(id,identity_id,organization_id,kind,status,score,evidence_json,recorded_at,expires_at) values(@id,@identity_id,@organization_id,@kind,@status,@score,@evidence_json,@recorded_at,@expires_at)').run(row);
    return { ...row, evidence };
  }
  revokeQualification(qualificationId, organizationId) { this.db.prepare("update qualifications set status='revoked',revoked_at=? where id=? and organization_id=?").run(now(), qualificationId, organizationId); }
  qualifications(identityId, organizationId) { return this.db.prepare('select * from qualifications where identity_id=? and organization_id=? order by recorded_at desc').all(identityId, organizationId).map(row => ({ ...row, evidence: JSON.parse(row.evidence_json) })); }

  audit(organizationId, eventType, principalKeyId, payload = {}) { this.db.prepare('insert into security_audit(id,organization_id,event_type,principal_key_id,payload_json,created_at) values(?,?,?,?,?,?)').run(id('audit'), organizationId, eventType, principalKeyId, JSON.stringify(payload), now()); }
  backup(destination) { this.db.pragma('wal_checkpoint(FULL)'); fs.copyFileSync(this.dbPath, destination); return { destination, digest: hash(fs.readFileSync(destination)) }; }
  close() { this.db.close(); }
}
