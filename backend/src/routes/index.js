import { Router } from 'express';
import { z } from 'zod';
import { validate } from '../middleware/validate.js';
import { requireAuth } from '../middleware/auth.js';
import { PLANS, DEFAULT_PLAN_ID } from '../services/plans.js';

const email = z.string().trim().toLowerCase().max(254).email('некорректный email');
const password = z.string().min(8, 'минимум 8 символов').max(128, 'максимум 128 символов');
const token = z.string().min(10).max(512);

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res)).catch(next);

export function createRouter({ auth, subscriptions, payments, vpn, limiters }) {
  const r = Router();
  const guard = requireAuth(auth);

  // ---- public ----
  r.get('/health', (_req, res) => res.json({ ok: true }));
  r.get('/plans', (_req, res) => res.json({ plans: Object.values(PLANS) }));

  // ---- auth ----
  const a = Router();
  a.use(limiters.authIp);
  a.post('/register', validate(z.object({ email, password })), wrap(async (req, res) => {
    res.status(201).json(await auth.register(req.body.email, req.body.password));
  }));
  a.post('/login', limiters.login, validate(z.object({ email, password: z.string().min(1).max(128) })), wrap(async (req, res) => {
    res.json(await auth.login(req.body.email, req.body.password));
  }));
  a.post('/refresh', validate(z.object({ refreshToken: token })), (req, res) => {
    res.json(auth.refresh(req.body.refreshToken));
  });
  a.post('/logout', validate(z.object({ refreshToken: token })), (req, res) => {
    auth.logout(req.body.refreshToken);
    res.status(204).end();
  });
  a.post('/password/forgot', validate(z.object({ email })), wrap(async (req, res) => {
    await auth.requestPasswordReset(req.body.email);
    res.status(202).json({ ok: true }); // same answer whether or not the email exists
  }));
  a.post('/password/reset', validate(z.object({ token, password })), wrap(async (req, res) => {
    await auth.resetPassword(req.body.token, req.body.password);
    res.json({ ok: true });
  }));
  r.use('/auth', a);

  // ---- account ----
  r.get('/me', guard, (req, res) => {
    res.json({
      user: { id: req.user.id, email: req.user.email, createdAt: req.user.created_at },
      subscription: subscriptions.status(req.user.id),
      vpnServers: vpn.servers(),
    });
  });

  r.post('/subscription/cancel', guard, wrap(async (req, res) => {
    subscriptions.cancel(req.user.id);
    await vpn.reconcile(); // peers are removed from the server before we answer
    res.json({ subscription: subscriptions.status(req.user.id) });
  }));

  // ---- payments ----
  r.post('/payments', guard, validate(z.object({ planId: z.string().max(32).default(DEFAULT_PLAN_ID) })), wrap(async (req, res) => {
    const result = await payments.create(req.user.id, req.body.planId);
    res.status(201).json({ ...result, subscription: subscriptions.status(req.user.id) });
  }));
  r.get('/payments', guard, (req, res) => res.json({ payments: payments.list(req.user.id) }));
  // Provider callbacks (authenticated by signature, not by user token).
  r.post('/payments/webhook/:provider', wrap(async (req, res) => {
    await payments.handleWebhook(req.params.provider, req);
    res.json({ ok: true });
  }));

  // ---- vpn ----
  const idParam = z.object({ id: z.coerce.number().int().positive() });
  const v = Router();
  v.use(guard);
  v.get('/profiles', (req, res) => res.json({ profiles: vpn.list(req.user.id) }));
  v.post('/profiles', validate(z.object({ name: z.string().trim().min(1).max(64).default('My device') })), wrap(async (req, res) => {
    res.status(201).json({ profile: await vpn.create(req.user.id, req.body.name) });
  }));
  v.get('/profiles/:id', validate(idParam, 'params'), (req, res) => res.json({ profile: vpn.get(req.user.id, req.params.id) }));
  v.get('/profiles/:id/config', validate(idParam, 'params'), (req, res) => {
    const { filename, text } = vpn.config(req.user.id, req.params.id);
    res.set({
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Cache-Control': 'no-store',
    }).send(text);
  });
  v.post('/profiles/:id/revoke', validate(idParam, 'params'), wrap(async (req, res) => {
    res.json({ profile: await vpn.revoke(req.user.id, req.params.id) });
  }));
  r.use('/vpn', v);

  return r;
}
