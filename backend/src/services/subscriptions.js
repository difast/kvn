const iso = (ms) => new Date(ms).toISOString();

export function createSubscriptionService({ db, onExtended }) {
  const currentEnd = (userId) => db.prepare('SELECT MAX(ends_at) AS e FROM subscriptions WHERE user_id = ?').get(userId).e;

  return {
    // Adds a period; if the user is still active it is appended after the current end.
    grant(userId, paymentId, durationMs) {
      const end = currentEnd(userId);
      const start = end && Date.parse(end) > Date.now() ? Date.parse(end) : Date.now();
      const endsAt = iso(start + durationMs);
      db.prepare('INSERT INTO subscriptions (user_id, payment_id, starts_at, ends_at) VALUES (?,?,?,?)')
        .run(userId, paymentId, iso(start), endsAt);
      onExtended?.(userId, endsAt);
      return endsAt;
    },

    status(userId) {
      const end = currentEnd(userId);
      const active = !!end && Date.parse(end) > Date.now();
      return { status: active ? 'active' : end ? 'expired' : 'none', active, expiresAt: end || null };
    },

    // Ends access immediately (no refund logic in the MVP). Returns the new end timestamp.
    cancel(userId) {
      const now = iso(Date.now());
      db.prepare('UPDATE subscriptions SET ends_at = ? WHERE user_id = ? AND ends_at > ?').run(now, userId, now);
      onExtended?.(userId, now); // profiles expire together with the subscription
      return now;
    },

    endsAt: currentEnd,
  };
}
