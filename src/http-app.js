import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AxionService } from './service.js';

const publicRoot = fileURLToPath(new URL('../public/', import.meta.url));
const contentTypes = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };

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
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw Object.assign(new Error('invalid JSON body'), { statusCode: 400 }); }
}

async function servePublic(pathname, res) {
  const relative = normalize(pathname === '/' ? 'index.html' : pathname.slice(1)).replace(/^(\.\.(\/|\\|$))+/, '');
  const path = join(publicRoot, relative);
  if (!path.startsWith(publicRoot)) return false;
  try {
    const content = await readFile(path);
    res.writeHead(200, { 'content-type': contentTypes[extname(path)] ?? 'application/octet-stream', 'content-length': content.length });
    res.end(content);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

export async function createAxionHandler({ service = new AxionService() } = {}) {
  await service.initialize();
  return async function handler(req, res) {
    const url = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);
    try {
      if (req.method === 'GET' && url.pathname === '/health') return sendJson(res, 200, { ok: true, service: 'axion' });
      if (req.method === 'GET' && url.pathname === '/api/dashboard') return sendJson(res, 200, service.dashboard());
      if (req.method === 'POST' && url.pathname === '/api/identities') return sendJson(res, 201, await service.register(await readJson(req)));
      const identity = url.pathname.match(/^\/api\/identities\/([^/]+)$/);
      if (identity && req.method === 'GET') return sendJson(res, 200, service.inspect(decodeURIComponent(identity[1])) ?? { error: 'not_found' });
      const lifecycle = url.pathname.match(/^\/api\/identities\/([^/]+)\/lifecycle$/);
      if (lifecycle && req.method === 'POST') {
        const input = await readJson(req);
        return sendJson(res, 200, await service.setLifecycle(decodeURIComponent(lifecycle[1]), input.status));
      }
      if (req.method === 'POST' && url.pathname === '/api/credentials') return sendJson(res, 201, await service.issueCredential(await readJson(req)));
      const verifyCredential = url.pathname.match(/^\/api\/credentials\/([^/]+)\/verify$/);
      if (verifyCredential && req.method === 'GET') return sendJson(res, 200, service.verifyCredential(decodeURIComponent(verifyCredential[1])));
      const revokeCredential = url.pathname.match(/^\/api\/credentials\/([^/]+)\/revoke$/);
      if (revokeCredential && req.method === 'POST') return sendJson(res, 200, await service.revokeCredential(decodeURIComponent(revokeCredential[1]), await readJson(req)));
      if (req.method === 'GET' && !url.pathname.startsWith('/api/') && await servePublic(url.pathname, res)) return;
      return sendJson(res, 404, { error: 'not_found' });
    } catch (error) {
      return sendJson(res, error.statusCode ?? 400, { error: error.message ?? 'request_failed' });
    }
  };
}
