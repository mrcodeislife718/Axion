import { timingSafeEqual } from 'node:crypto';

function safeEqual(a, b) {
  const left = Buffer.from(String(a ?? ''));
  const right = Buffer.from(String(b ?? ''));
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

export class AxionAuthorizer {
  constructor({ apiKey = process.env.AXION_API_KEY ?? null } = {}) {
    this.apiKey = apiKey;
  }

  required() { return Boolean(this.apiKey); }

  authorize(req) {
    if (!this.apiKey) return { authorized: true, mode: 'open' };
    const provided = req.headers['x-api-key'];
    if (!provided || !safeEqual(provided, this.apiKey)) return { authorized: false, reason: 'invalid_api_key' };
    return { authorized: true, mode: 'api-key' };
  }
}
