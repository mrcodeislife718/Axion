import { randomUUID, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AxionService } from './service.js';

const publicRoot = fileURLToPath(new URL('../public/', import.meta.url));
const contentTypes = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };

function requestId(req) {
  const candidate = req.headers['x-request-id'];
  return typeof candidate === 'string' && candidate.length > 0 && candidate.length <= 128 ? candidate : randomUUID();
}

function applySecurityHeaders(res, id) {
  res.setHeader('x-request-id', id);
  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('x-frame-options', 'DENY');
  res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader('permissions-policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('content-security-policy', "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'");
}

function sendJson(res, status, value) {
  const payload = JSON.stringify(value);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(payload), 'cache-control': 'no-store' });
  res.end(payload);
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 1_000_000) throw Object.assign(new Error('request body too large'), { statusCode: 413 });
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('JSON body must be an object');
    return parsed;
  } catch (error) {
    if (error?.statusCode) throw error;
    throw Object.assign(new Error('invalid JSON body'), { statusCode: 400 });
  }
}

async function servePublic(pathname, res) {
  const relative = normalize(pathname === '/' ? 'index.html' : pathname.slice(1)).replace(/^(\.\.(\/|\\|$))+/, '');
  const path = join(publicRoot, relative);
  if (!path.startsWith(publicRoot)) return false;
  try {
    const content = await readFile(path);
    res.writeHead(200, { 'content-type': contentTypes[extname(path)] ?? 'application/octet-stream', 'content-length': content.length, 'cache-control': extname(path) === '.html' ? 'no-cache' : 'public, max-age=300' });
    res.end(content);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

function secureEqual(left, right) {
  const a = Buffer.from(String(left ?? ''), 'utf8');
  const b = Buffer.from(String(right ?? ''), 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

function suppliedAuthority(req) {
  const authorization = req.headers.authorization;
  if (typeof authorization === 'string' && authorization.startsWith('Bearer ')) return authorization.slice(7).trim();
  const direct = req.headers['x-api-key'];
  return typeof direct === 'string' ? direct.trim() : '';
}

function createRateLimiter({ windowMs, max }) {
  const buckets = new Map();
  return {
    consume(key, now = Date.now()) {
      const current = buckets.get(key);
      if (!current || current.resetAt <= now) {
        const resetAt = now + windowMs;
        buckets.set(key, { count: 1, resetAt });
        return { allowed: true, remaining: max - 1, resetAt };
      }
      current.count += 1;
      return { allowed: current.count <= max, remaining: Math.max(0, max - current.count), resetAt: current.resetAt };
    },
  };
}

export async function createAxionHandler({
  service = new AxionService(),
  authorityKey = process.env.AXION_AUTHORITY_KEY ?? '',
  requireAuthority = process.env.NODE_ENV === 'production',
  rateLimitWindowMs = Number(process.env.AXION_RATE_LIMIT_WINDOW_MS ?? 60_000),
  rateLimitMax = Number(process.env.AXION_RATE_LIMIT_MAX ?? 180),
} = {}) {
  if (requireAuthority && !authorityKey) throw new Error('AXION_AUTHORITY_KEY is required in production.');
  if (!Number.isFinite(rateLimitWindowMs) || rateLimitWindowMs <= 0) throw new Error('Invalid Axion rate-limit window.');
  if (!Number.isInteger(rateLimitMax) || rateLimitMax <= 0) throw new Error('Invalid Axion rate-limit maximum.');
  await service.initialize();
  const limiter = createRateLimiter({ windowMs: rateLimitWindowMs, max: rateLimitMax });

  return async function handler(req, res) {
    const id = requestId(req);
    applySecurityHeaders(res, id);
    const url = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);
    try {
      if (req.method === 'GET' && url.pathname === '/health') return sendJson(res, 200, { ok: true, service: 'axion', requestId: id });

      if (url.pathname.startsWith('/api/')) {
        const remote = String(req.headers['x-forwarded-for'] ?? '').split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
        const rate = limiter.consume(remote);
        res.setHeader('x-ratelimit-remaining', String(rate.remaining));
        res.setHeader('x-ratelimit-reset', String(Math.ceil(rate.resetAt / 1000)));
        if (!rate.allowed) return sendJson(res, 429, { error: 'rate_limited', requestId: id });
      }

      const publicIdentity = url.pathname.match(/^\/api\/identities\/([^/]+)$/);
      const publicCredentialVerification = url.pathname.match(/^\/api\/credentials\/([^/]+)\/verify$/);
      const publicRead = (req.method === 'GET' && Boolean(publicIdentity || publicCredentialVerification));
      const protectedSurface = url.pathname === '/api/dashboard' || (url.pathname.startsWith('/api/') && !publicRead);
      if (protectedSurface && (requireAuthority || authorityKey) && !secureEqual(suppliedAuthority(req), authorityKey)) {
        res.setHeader('www-authenticate', 'Bearer realm="Axion Registry Authority"');
        return sendJson(res, 401, { error: 'registry_authority_required', requestId: id });
      }

      if (req.method === 'GET' && url.pathname === '/api/dashboard') return sendJson(res, 200, service.dashboard());
      if (req.method === 'POST' && url.pathname === '/api/identities') return sendJson(res, 201, await service.register(await readJson(req)));
      if (publicIdentity && req.method === 'GET') {
        const inspected = service.inspect(decodeURIComponent(publicIdentity[1]));
        return inspected ? sendJson(res, 200, inspected) : sendJson(res, 404, { error: 'not_found', requestId: id });
      }
      const lifecycle = url.pathname.match(/^\/api\/identities\/([^/]+)\/lifecycle$/);
      if (lifecycle && req.method === 'POST') {
        const input = await readJson(req);
        if (typeof input.status !== 'string' || !input.status) throw Object.assign(new Error('status is required'), { statusCode: 400 });
        return sendJson(res, 200, await service.setLifecycle(decodeURIComponent(lifecycle[1]), input.status));
      }
      if (req.method === 'POST' && url.pathname === '/api/credentials') return sendJson(res, 201, await service.issueCredential(await readJson(req)));
      if (publicCredentialVerification && req.method === 'GET') return sendJson(res, 200, service.verifyCredential(decodeURIComponent(publicCredentialVerification[1])));
      const revokeCredential = url.pathname.match(/^\/api\/credentials\/([^/]+)\/revoke$/);
      if (revokeCredential && req.method === 'POST') return sendJson(res, 200, await service.revokeCredential(decodeURIComponent(revokeCredential[1]), await readJson(req)));
      if (req.method === 'GET' && !url.pathname.startsWith('/api/') && await servePublic(url.pathname, res)) return;
      return sendJson(res, 404, { error: 'not_found', requestId: id });
    } catch (error) {
      return sendJson(res, error.statusCode ?? 400, { error: error.message ?? 'request_failed', requestId: id });
    }
  };
}
