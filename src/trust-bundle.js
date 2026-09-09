import { AxionKeyRing } from './signing.js';

const validDomain = value => /^axion:trust-domain:[a-z0-9._/-]+$/i.test(String(value || ''));
const validNamespace = value => /^axion:[a-z0-9-]+:[a-z0-9._/-]+$/i.test(String(value || ''));

export function createTrustBundle({ domainId, namespaceRoots = [], keyRing, ledger, ttlMs = 60 * 60 * 1000, nowMs = Date.now() }) {
  if (!validDomain(domainId)) throw new Error('invalid Axion trust domain id');
  if (!keyRing || !ledger) throw new Error('key ring and transparency ledger are required');
  if (!Number.isFinite(ttlMs) || ttlMs < 30_000 || ttlMs > 7 * 24 * 60 * 60 * 1000) throw new Error('trust bundle TTL must be between 30 seconds and 7 days');
  const roots = [...new Set(namespaceRoots.map(String))].sort();
  for (const root of roots) if (!validNamespace(root)) throw new Error(`invalid Axion namespace root: ${root}`);
  const generatedAt = new Date(nowMs).toISOString();
  const expiresAt = new Date(nowMs + ttlMs).toISOString();
  const checkpoint = ledger.checkpoint(keyRing);
  const bundle = {
    axionTrustBundleVersion:'1.0',
    domainId,
    generatedAt,
    expiresAt,
    namespaceRoots:roots,
    signingKeys:keyRing.publicKeys(),
    transparencyCheckpoint:checkpoint,
  };
  return { bundle, signature:keyRing.sign(bundle) };
}

export function verifyTrustBundle(envelope, { trustedKeyIds = [], expectedDomainId = null, nowMs = Date.now() } = {}) {
  const bundle = envelope?.bundle;
  if (!bundle || bundle.axionTrustBundleVersion !== '1.0') return { verified:false, reason:'invalid-trust-bundle-version' };
  if (!validDomain(bundle.domainId)) return { verified:false, reason:'invalid-trust-domain-id' };
  if (expectedDomainId && bundle.domainId !== expectedDomainId) return { verified:false, reason:'unexpected-trust-domain' };
  const generatedAt = Date.parse(bundle.generatedAt), expiresAt = Date.parse(bundle.expiresAt);
  if (!Number.isFinite(generatedAt) || !Number.isFinite(expiresAt) || expiresAt <= generatedAt) return { verified:false, reason:'invalid-trust-bundle-validity' };
  if (nowMs < generatedAt - 60_000) return { verified:false, reason:'trust-bundle-not-yet-valid' };
  if (nowMs >= expiresAt) return { verified:false, reason:'trust-bundle-expired' };
  if (!Array.isArray(bundle.signingKeys) || bundle.signingKeys.length === 0) return { verified:false, reason:'trust-bundle-keys-missing' };
  const pinned = new Set(trustedKeyIds.map(String));
  if (pinned.size && !pinned.has(envelope?.signature?.keyId)) return { verified:false, reason:'untrusted-domain-key' };
  const signature = AxionKeyRing.verifyOffline(bundle, envelope.signature, bundle.signingKeys);
  if (!signature.verified) return signature;
  const checkpoint = bundle.transparencyCheckpoint;
  const checkpointVerification = AxionKeyRing.verifyOffline(checkpoint?.statement, checkpoint?.signature, bundle.signingKeys);
  if (!checkpointVerification.verified) return { verified:false, reason:`invalid-transparency-checkpoint:${checkpointVerification.reason || 'signature'}` };
  if (checkpoint.statement?.ledger !== 'axion-transparency-v1') return { verified:false, reason:'invalid-transparency-ledger-profile' };
  return { verified:true, domainId:bundle.domainId, keyId:signature.keyId, expiresAt:bundle.expiresAt, namespaceRoots:[...(bundle.namespaceRoots || [])], transparencyHead:checkpoint.statement.headHash || null };
}

export function trustBundleAllowsIdentity(bundleEnvelope, identityId) {
  const roots = bundleEnvelope?.bundle?.namespaceRoots;
  if (!Array.isArray(roots) || roots.length === 0) return false;
  return roots.some(root => identityId === root || identityId.startsWith(`${root}/`));
}
