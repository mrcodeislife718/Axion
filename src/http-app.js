import { AxionService } from './service.js';
import { AxionAuthorizer, FixedWindowRateLimiter } from './auth.js';

function security(extra = {}) { return { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer', ...extra }; }
function sendJson(res, status, value, extra = {}) { const payload = JSON.stringify(value); res.writeHead(status, security({ 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(payload), ...extra })); res.end(payload); }
async function readJson(req, max = 1_000_000) { const chunks=[]; let size=0; for await (const chunk of req) { size += chunk.length; if (size > max) throw Object.assign(new Error('request body too large'), { statusCode: 413 }); chunks.push(chunk); } if (!chunks.length) return {}; try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw Object.assign(new Error('invalid JSON body'), { statusCode: 400 }); } }
function ip(req) { return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim(); }

export function createAxionHandler({ service = new AxionService().initialize(), authorizer = null, publicRateLimiter = new FixedWindowRateLimiter({ limit: 120 }), privateRateLimiter = new FixedWindowRateLimiter({ limit: 600 }) } = {}) {
  const auth = authorizer || new AxionAuthorizer({ store: service.store });
  return async function handler(req, res) {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    try {
      if (req.method === 'GET' && url.pathname === '/health') return sendJson(res, 200, { ok: true, service: 'axion' });
      if (req.method === 'GET' && url.pathname === '/v1/public/keys') return sendJson(res, 200, { keys: service.signingKeys() });
      let match;
      if ((match = url.pathname.match(/^\/v1\/public\/identities\/([^/]+)\/passport$/)) && req.method === 'GET') {
        const limit = publicRateLimiter.check(ip(req)); if (!limit.allowed) return sendJson(res, 429, { error: 'rate_limited' });
        const bundle = service.passport(decodeURIComponent(match[1]), null);
        return bundle ? sendJson(res, 200, bundle) : sendJson(res, 404, { error: 'not_found' });
      }
      if (req.method === 'POST' && url.pathname === '/v1/public/passports/verify') {
        const limit = publicRateLimiter.check(ip(req)); if (!limit.allowed) return sendJson(res, 429, { error: 'rate_limited' });
        return sendJson(res, 200, service.verifyPassport(await readJson(req)));
      }
      if (req.method === 'POST' && url.pathname === '/v1/bootstrap') {
        const remote = ip(req);
        const local = ['127.0.0.1','::1','::ffff:127.0.0.1'].includes(remote);
        const count = service.store.db.prepare('select count(*) n from organizations').get().n;
        if (!local || count !== 0) return sendJson(res, 403, { error: 'bootstrap_disabled' });
        const body = await readJson(req);
        return sendJson(res, 201, service.bootstrap(body.organizationName));
      }

      const provisional = auth.authenticate(req);
      const rate = privateRateLimiter.check(provisional?.keyId || ip(req));
      if (!rate.allowed) return sendJson(res, 429, { error: 'rate_limited' });
      const requireScope = scope => {
        const decision = auth.require(req, scope);
        if (!decision.authorized) { sendJson(res, decision.status, { error: decision.reason }); return null; }
        return decision.principal;
      };

      if (req.method === 'GET' && url.pathname === '/v1/me') { const p=requireScope('registry:read'); if(!p)return; return sendJson(res,200,{ principal:p, organization:service.store.getOrganization(p.organizationId) }); }
      if (req.method === 'POST' && url.pathname === '/v1/identities') { const p=requireScope('registry:write'); if(!p)return; return sendJson(res,201,service.register(await readJson(req),p)); }
      if (req.method === 'GET' && url.pathname === '/v1/identities') { const p=requireScope('registry:read'); if(!p)return; return sendJson(res,200,{ identities:service.search(Object.fromEntries(url.searchParams),p) }); }
      if ((match=url.pathname.match(/^\/v1\/identities\/([^/]+)$/)) && req.method==='GET') { const p=requireScope('registry:read'); if(!p)return; const result=service.inspect(decodeURIComponent(match[1]),p); return result?sendJson(res,200,result):sendJson(res,404,{error:'not_found'}); }
      if ((match=url.pathname.match(/^\/v1\/identities\/([^/]+)\/lifecycle$/)) && req.method==='POST') { const p=requireScope('registry:write'); if(!p)return; const body=await readJson(req); return sendJson(res,200,service.setLifecycle(decodeURIComponent(match[1]),body.status,p)); }
      if ((match=url.pathname.match(/^\/v1\/identities\/([^/]+)\/provider-sessions$/)) && req.method==='POST') { const p=requireScope('identity:operate'); if(!p)return; return sendJson(res,201,service.bindProviderSession(decodeURIComponent(match[1]),await readJson(req),p)); }
      if ((match=url.pathname.match(/^\/v1\/identities\/([^/]+)\/qualifications$/)) && req.method==='POST') { const p=requireScope('qualification:write'); if(!p)return; return sendJson(res,201,service.recordQualification(decodeURIComponent(match[1]),await readJson(req),p)); }
      if ((match=url.pathname.match(/^\/v1\/identities\/([^/]+)\/qualifications\/([^/]+)\/revoke$/)) && req.method==='POST') { const p=requireScope('qualification:write'); if(!p)return; return sendJson(res,200,service.revokeQualification(decodeURIComponent(match[1]),decodeURIComponent(match[2]),p)); }
      if ((match=url.pathname.match(/^\/v1\/identities\/([^/]+)\/passport$/)) && req.method==='GET') { const p=requireScope('registry:read'); if(!p)return; const result=service.passport(decodeURIComponent(match[1]),p); return result?sendJson(res,200,result):sendJson(res,404,{error:'not_found'}); }
      if (req.method==='POST' && url.pathname==='/v1/credentials') { const p=requireScope('credentials:write'); if(!p)return; return sendJson(res,201,service.issueCredential(await readJson(req),p)); }
      if ((match=url.pathname.match(/^\/v1\/credentials\/([^/]+)\/verify$/)) && req.method==='GET') { const p=requireScope('verify:read'); if(!p)return; return sendJson(res,200,service.verifyCredential(decodeURIComponent(match[1]))); }
      if ((match=url.pathname.match(/^\/v1\/credentials\/([^/]+)\/revoke$/)) && req.method==='POST') { const p=requireScope('credentials:write'); if(!p)return; return sendJson(res,200,service.revokeCredential(decodeURIComponent(match[1]),await readJson(req),p)); }
      if (req.method==='POST' && url.pathname==='/v1/api-keys') { const p=requireScope('admin:keys'); if(!p)return; const body=await readJson(req); return sendJson(res,201,service.store.issueApiKey({ organizationId:p.organizationId,label:body.label,scopes:body.scopes })); }
      if ((match=url.pathname.match(/^\/v1\/api-keys\/([^/]+)\/revoke$/)) && req.method==='POST') { const p=requireScope('admin:keys'); if(!p)return; service.store.revokeApiKey(decodeURIComponent(match[1]),p.organizationId); return sendJson(res,200,{revoked:true}); }
      if (req.method==='POST' && url.pathname==='/v1/signing/rotate') { const p=requireScope('admin:signing'); if(!p)return; const body=await readJson(req); return sendJson(res,201,service.rotateSigningKey(body.reason||'operator_rotation',p)); }
      if ((match=url.pathname.match(/^\/v1\/signing\/([^/]+)\/revoke$/)) && req.method==='POST') { const p=requireScope('admin:signing'); if(!p)return; const body=await readJson(req); return sendJson(res,200,service.revokeSigningKey(decodeURIComponent(match[1]),body.reason||'operator_revocation',p)); }
      return sendJson(res,404,{error:'not_found'});
    } catch (error) {
      const message=error?.message||'request_failed';
      const status=error?.statusCode || (/belongs to another|scope|unauthor/i.test(message)?403:/not found/.test(message)?404:400);
      return sendJson(res,status,{error:'request_failed',message});
    }
  };
}
