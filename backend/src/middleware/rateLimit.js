import rateLimit, { ipKeyGenerator } from 'express-rate-limit';

export function createLimiters(config) {
  const rl = config.rateLimit;
  const make = (opts) => (rl.enabled
    ? rateLimit({
      standardHeaders: 'draft-7', legacyHeaders: false, validate: { xForwardedForHeader: false },
      handler: (_req, res) => res.status(429).json({ error: { code: 'too_many_requests', message: 'Слишком много попыток, попробуйте позже' } }),
      ...opts,
    })
    : (_req, _res, next) => next());
  const emailKey = (req) => `${ipKeyGenerator(req.ip)}|${String(req.body?.email || '').toLowerCase().slice(0, 254)}`;
  return {
    api: make({ windowMs: 60_000, limit: rl.apiMax }),
    // All auth endpoints: per IP.
    authIp: make({ windowMs: 15 * 60_000, limit: rl.authIpMax }),
    // Credential guessing: per IP+email; only failed attempts count.
    login: make({ windowMs: 15 * 60_000, limit: rl.loginMax, keyGenerator: emailKey, skipSuccessfulRequests: true }),
  };
}
