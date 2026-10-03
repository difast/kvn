import { tx } from '../../db.js';
import { HttpError } from '../../lib/errors.js';
import { PLANS } from '../plans.js';
import { mockProvider } from './mock.js';
import { createSberProvider } from './sber.js';

const DAY = 86_400_000;

export function createPaymentService({ db, config, subscriptions }) {
  const providers = { mock: mockProvider, sber: createSberProvider(config.payments.sber) };
  const provider = providers[config.payments.provider];
  if (!provider) throw new Error(`Unknown PAYMENT_PROVIDER "${config.payments.provider}"`);

  const view = (p) => ({
    id: p.id, planId: p.plan_id, provider: p.provider, status: p.status,
    amountKop: p.amount_kop, currency: p.currency, createdAt: p.created_at, paidAt: p.paid_at,
  });

  // Idempotent: marks the payment paid and grants the period exactly once.
  function settle(paymentId, status) {
    return tx(db, () => {
      const p = db.prepare('SELECT * FROM payments WHERE id = ?').get(paymentId);
      if (!p || p.status !== 'pending') return p; // already settled -> no double grant
      if (status === 'failed') {
        db.prepare("UPDATE payments SET status = 'failed' WHERE id = ?").run(p.id);
      } else {
        const now = new Date().toISOString();
        db.prepare("UPDATE payments SET status = 'succeeded', paid_at = ? WHERE id = ?").run(now, p.id);
        subscriptions.grant(p.user_id, p.id, PLANS[p.plan_id].days * DAY);
      }
      return db.prepare('SELECT * FROM payments WHERE id = ?').get(p.id);
    });
  }

  return {
    provider: provider.name,

    async create(userId, planId) {
      const plan = PLANS[planId];
      if (!plan) throw new HttpError(400, 'unknown_plan', 'Неизвестный тариф');
      const id = db.prepare(
        "INSERT INTO payments (user_id, plan_id, provider, amount_kop, currency, status) VALUES (?,?,?,?,?,'pending')",
      ).run(userId, plan.id, provider.name, plan.priceKop, plan.currency).lastInsertRowid;

      const created = await provider.createPayment(db.prepare('SELECT * FROM payments WHERE id = ?').get(id));
      db.prepare('UPDATE payments SET provider_payment_id = ? WHERE id = ?').run(created.providerPaymentId, id);
      const final = created.status === 'pending' ? db.prepare('SELECT * FROM payments WHERE id = ?').get(id) : settle(id, created.status);
      return { payment: view(final), redirectUrl: created.redirectUrl || null };
    },

    // Entry point for provider callbacks (POST /payments/webhook/:provider).
    async handleWebhook(providerName, req) {
      if (providerName !== provider.name) throw new HttpError(404, 'not_found', 'Unknown provider');
      const { providerPaymentId, status } = await provider.parseWebhook(req);
      const p = db.prepare('SELECT * FROM payments WHERE provider = ? AND provider_payment_id = ?').get(provider.name, providerPaymentId);
      if (!p) throw new HttpError(404, 'not_found', 'Unknown payment');
      settle(p.id, status);
    },

    list(userId) {
      return db.prepare('SELECT * FROM payments WHERE user_id = ? ORDER BY id DESC LIMIT 50').all(userId).map(view);
    },
  };
}
