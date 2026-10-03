import jwt from 'jsonwebtoken';
import { HttpError } from '../lib/errors.js';
import { hashPassword, verifyPassword, sha256, randomToken } from '../lib/crypto.js';

const iso = (d = new Date()) => d.toISOString();
const plusMs = (ms) => iso(new Date(Date.now() + ms));
const DAY = 86_400_000;

export function createAuthService({ db, config, mailer }) {
  // Used to equalise timing when the email is unknown.
  const dummyHash = hashPassword('dummy-password-for-timing');

  const publicUser = (u) => ({ id: u.id, email: u.email, createdAt: u.created_at });

  function signAccess(user) {
    return jwt.sign({ sub: String(user.id) }, config.jwtSecret, {
      algorithm: 'HS256',
      expiresIn: config.accessTokenTtlSec,
    });
  }

  function issueTokens(user) {
    const refreshToken = randomToken(48);
    db.prepare('INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?,?,?)').run(
      user.id, sha256(refreshToken), plusMs(config.refreshTokenTtlDays * DAY),
    );
    return {
      accessToken: signAccess(user),
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: config.accessTokenTtlSec,
    };
  }

  return {
    verifyAccessToken(token) {
      try {
        const p = jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] });
        return db.prepare('SELECT * FROM users WHERE id = ?').get(Number(p.sub)) || null;
      } catch {
        return null;
      }
    },

    async register(email, password) {
      if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) {
        throw new HttpError(409, 'email_taken', 'Этот email уже зарегистрирован');
      }
      const hash = await hashPassword(password);
      let id;
      try {
        id = db.prepare('INSERT INTO users (email, password_hash) VALUES (?,?)').run(email, hash).lastInsertRowid;
      } catch {
        throw new HttpError(409, 'email_taken', 'Этот email уже зарегистрирован');
      }
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
      return { user: publicUser(user), ...issueTokens(user) };
    },

    async login(email, password) {
      const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
      const ok = await verifyPassword(password, user ? user.password_hash : await dummyHash);
      if (!user || !ok) throw new HttpError(401, 'invalid_credentials', 'Неверный email или пароль');
      return { user: publicUser(user), ...issueTokens(user) };
    },

    // Refresh tokens rotate: the presented one is revoked, a new pair is issued.
    refresh(refreshToken) {
      const row = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(sha256(refreshToken));
      if (!row || row.revoked_at || row.expires_at < iso()) {
        throw new HttpError(401, 'invalid_refresh_token', 'Сессия истекла, войдите заново');
      }
      db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?').run(iso(), row.id);
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(row.user_id);
      return issueTokens(user);
    },

    logout(refreshToken) {
      db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL')
        .run(iso(), sha256(refreshToken));
    },

    // Always behaves the same whether or not the email exists (no user enumeration).
    async requestPasswordReset(email) {
      const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
      if (!user) return;
      const token = randomToken(32);
      db.prepare('INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?,?,?)')
        .run(user.id, sha256(token), plusMs(60 * 60 * 1000));
      await mailer.send({
        to: user.email,
        subject: 'Восстановление пароля',
        text: `Ссылка действует 1 час: ${config.frontendUrl}/reset.html#token=${token}`,
      });
    },

    async resetPassword(token, newPassword) {
      const row = db.prepare('SELECT * FROM password_resets WHERE token_hash = ?').get(sha256(token));
      if (!row || row.used_at || row.expires_at < iso()) {
        throw new HttpError(400, 'invalid_reset_token', 'Ссылка недействительна или устарела');
      }
      const hash = await hashPassword(newPassword);
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, row.user_id);
      db.prepare('UPDATE password_resets SET used_at = ? WHERE id = ?').run(iso(), row.id);
      // Sign out everywhere.
      db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').run(iso(), row.user_id);
    },
  };
}
