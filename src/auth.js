export class AxionAuthorizer {
  constructor({ store }) { if (!store) throw new Error('AxionAuthorizer requires store'); this.store = store; }
  authenticate(req) {
    const bearer = req.headers.authorization?.match(/^Bearer\s+(.+)$/i)?.[1];
    const raw = bearer || req.headers['x-api-key'];
    if (typeof raw !== 'string' || !raw) return null;
    return this.store.authenticateApiKey(raw);
  }
  require(req, scope) {
    const principal = this.authenticate(req);
    if (!principal) return { authorized: false, status: 401, reason: 'authentication_required' };
    if (scope && !principal.scopes.includes('*') && !principal.scopes.includes(scope)) return { authorized: false, status: 403, reason: 'scope_denied', principal };
    return { authorized: true, principal };
  }
}

export class FixedWindowRateLimiter {
  constructor({ limit = 120, windowMs = 60_000 } = {}) { this.limit = limit; this.windowMs = windowMs; this.buckets = new Map(); }
  check(key, at = Date.now()) {
    const current = this.buckets.get(key);
    if (!current || current.resetAt <= at) {
      const next = { count: 1, resetAt: at + this.windowMs };
      this.buckets.set(key, next);
      return { allowed: true, remaining: this.limit - 1, resetAt: next.resetAt };
    }
    if (current.count >= this.limit) return { allowed: false, remaining: 0, resetAt: current.resetAt };
    current.count += 1;
    return { allowed: true, remaining: this.limit - current.count, resetAt: current.resetAt };
  }
}
