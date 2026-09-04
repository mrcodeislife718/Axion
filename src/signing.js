import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { canonicalize } from './axion.js';

const now = () => new Date().toISOString();
const digest = value => crypto.createHash('sha256').update(JSON.stringify(canonicalize(value))).digest('hex');

export class AxionKeyRing {
  constructor({ root }) {
    if (!root) throw new Error('key root required');
    this.root = path.resolve(root);
    this.metaPath = path.join(this.root, 'keys.json');
    fs.mkdirSync(this.root, { recursive: true, mode: 0o700 });
    if (!fs.existsSync(this.metaPath)) fs.writeFileSync(this.metaPath, JSON.stringify({ keys: [] }, null, 2), { mode: 0o600 });
  }
  metadata() { return JSON.parse(fs.readFileSync(this.metaPath, 'utf8')); }
  save(meta) {
    const temp = `${this.metaPath}.${process.pid}.${Date.now()}.tmp`;
    fs.writeFileSync(temp, JSON.stringify(meta, null, 2), { mode: 0o600 });
    fs.renameSync(temp, this.metaPath);
    fs.chmodSync(this.metaPath, 0o600);
  }
  activeKey() { return this.metadata().keys.find(key => key.status === 'active') || null; }
  rotate({ reason = 'rotation' } = {}) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const keyId = `axion:key:${crypto.createHash('sha256').update(publicPem).digest('hex').slice(0,24)}`;
    const meta = this.metadata();
    for (const key of meta.keys) if (key.status === 'active') { key.status = 'retired'; key.retiredAt = now(); }
    const record = { keyId, algorithm: 'Ed25519', status: 'active', createdAt: now(), reason, publicKeyPem: publicPem };
    meta.keys.push(record);
    fs.writeFileSync(path.join(this.root, `${encodeURIComponent(keyId)}.private.pem`), privatePem, { mode: 0o600 });
    this.save(meta);
    return record;
  }
  revoke(keyId, { reason = 'revoked', invalidAfter = null } = {}) {
    const meta = this.metadata();
    const key = meta.keys.find(item => item.keyId === keyId);
    if (!key) throw new Error('signing key not found');
    const revokedAt = now();
    const cutoff = invalidAfter || revokedAt;
    if (!Number.isFinite(Date.parse(cutoff))) throw new Error('invalid revocation cutoff');
    key.status = 'revoked';
    key.revokedAt = revokedAt;
    key.invalidAfter = new Date(cutoff).toISOString();
    key.revocationReason = reason;
    this.save(meta);
    return key;
  }
  sign(payload) {
    let key = this.activeKey(); if (!key) key = this.rotate({ reason: 'initial' });
    const payloadDigest = digest(payload);
    const privatePem = fs.readFileSync(path.join(this.root, `${encodeURIComponent(key.keyId)}.private.pem`), 'utf8');
    const signedAt = now();
    return { keyId: key.keyId, algorithm: 'Ed25519', payloadDigest, signature: crypto.sign(null, Buffer.from(payloadDigest), privatePem).toString('base64url'), signedAt };
  }
  verify(payload, envelope, { requireActive = false } = {}) {
    if (!envelope?.keyId || !envelope.signature || !envelope.payloadDigest || !envelope.signedAt) return { verified: false, reason: 'invalid-signature-envelope' };
    const signedAt = Date.parse(envelope.signedAt);
    if (!Number.isFinite(signedAt)) return { verified: false, reason: 'invalid-signing-time' };
    const key = this.metadata().keys.find(item => item.keyId === envelope.keyId);
    if (!key) return { verified: false, reason: 'unknown-key' };
    if (requireActive && key.status !== 'active') return { verified: false, reason: 'key-not-active' };
    if (key.status === 'revoked') {
      const invalidAfter = Date.parse(key.invalidAfter || key.revokedAt || key.createdAt);
      if (!Number.isFinite(invalidAfter) || signedAt >= invalidAfter) return { verified: false, reason: 'key-revoked-for-signing-time' };
    }
    const calculated = digest(payload);
    if (calculated !== envelope.payloadDigest) return { verified: false, reason: 'payload-digest-mismatch' };
    const verified = crypto.verify(null, Buffer.from(calculated), key.publicKeyPem, Buffer.from(envelope.signature, 'base64url'));
    return { verified, keyId: key.keyId, keyStatus: key.status, signedAt: envelope.signedAt, historical: key.status !== 'active' };
  }
  publicKeys() { return this.metadata().keys.map(({ publicKeyPem, ...key }) => ({ ...key, publicKeyPem })); }
  static verifyOffline(payload, envelope, publicKeys, { requireActive = false } = {}) {
    if (!Array.isArray(publicKeys)) return { verified: false, reason: 'invalid-key-set' };
    const key = publicKeys.find(item => item?.keyId === envelope?.keyId);
    if (!key) return { verified: false, reason: 'unknown-key' };
    if (!envelope?.signature || !envelope?.payloadDigest || !envelope?.signedAt) return { verified: false, reason: 'invalid-signature-envelope' };
    const signedAt = Date.parse(envelope.signedAt);
    if (!Number.isFinite(signedAt)) return { verified: false, reason: 'invalid-signing-time' };
    if (requireActive && key.status !== 'active') return { verified: false, reason: 'key-not-active' };
    if (key.status === 'revoked') {
      const invalidAfter = Date.parse(key.invalidAfter || key.revokedAt || key.createdAt);
      if (!Number.isFinite(invalidAfter) || signedAt >= invalidAfter) return { verified: false, reason: 'key-revoked-for-signing-time' };
    }
    const calculated = digest(payload);
    if (calculated !== envelope.payloadDigest) return { verified: false, reason: 'payload-digest-mismatch' };
    const verified = crypto.verify(null, Buffer.from(calculated), key.publicKeyPem, Buffer.from(envelope.signature, 'base64url'));
    return { verified, keyId: key.keyId, keyStatus: key.status, signedAt: envelope.signedAt, historical: key.status !== 'active' };
  }
}
