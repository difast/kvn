import crypto from 'node:crypto';
import { tx } from '../../db.js';
import { HttpError } from '../../lib/errors.js';
import { encrypt, decrypt } from '../../lib/crypto.js';
import { createXrayApplier } from './xray-applier.js';

const nowIso = () => new Date().toISOString();

export function createVlessService({ db, config, subscriptions }) {
  const applier = createXrayApplier(config.vless);
  const key = config.encryptionKey;
  const tag = config.vless.inboundTag;

  configureSeedServer();

  // Environment is the source of truth for the seed server's public Reality parameters
  // (applied on every start, so adding VLESS to an existing install needs no manual SQL).
  function configureSeedServer() {
    const v = config.vless.seedServer;
    if (!v.publicKey) return;
    const server = db.prepare('SELECT * FROM vpn_servers ORDER BY id LIMIT 1').get();
    if (!server) return;
    const host = v.host || server.endpoint.replace(/:\d+$/, '');
    db.prepare('UPDATE vpn_servers SET vless_host=?, vless_port=?, vless_public_key=?, vless_short_id=?, vless_sni=?, vless_flow=? WHERE id=?')
      .run(host, v.port, v.publicKey, v.shortId, v.sni, v.flow, server.id);
  }

  const serverOf = (id) => db.prepare('SELECT * FROM vpn_servers WHERE id = ?').get(id);
  const effectiveStatus = (a) => (a.status === 'revoked' ? 'revoked' : a.expires_at > nowIso() ? 'active' : 'expired');

  function view(a) {
    const s = serverOf(a.server_id);
    return {
      id: a.id, protocol: 'vless', name: a.name, status: effectiveStatus(a),
      server: { id: s.id, name: s.name, region: s.region },
      createdAt: a.created_at, expiresAt: a.expires_at, revokedAt: a.revoked_at,
    };
  }

  function owned(userId, id) {
    const a = db.prepare('SELECT * FROM vless_accounts WHERE id = ? AND user_id = ?').get(id, userId);
    if (!a) throw new HttpError(404, 'not_found', 'Конфигурация не найдена');
    return a;
  }

  function pickServer() {
    const rows = db.prepare(`
      SELECT s.*, (SELECT COUNT(*) FROM vless_accounts a WHERE a.server_id = s.id AND a.status = 'active') AS load
      FROM vpn_servers s WHERE s.is_active = 1 AND s.vless_port IS NOT NULL ORDER BY load ASC, s.id ASC`).all();
    const s = rows.find((r) => r.load < r.capacity);
    if (!s) throw new HttpError(503, 'vless_unavailable', 'VLESS пока недоступен на сервере');
    return s;
  }

  let chain = Promise.resolve();
  const reconcile = () => (chain = chain.then(doReconcile, doReconcile));
  async function doReconcile() {
    const now = nowIso();
    for (const server of db.prepare('SELECT * FROM vpn_servers WHERE vless_port IS NOT NULL').all()) {
      const accounts = db.prepare('SELECT * FROM vless_accounts WHERE server_id = ?').all(server.id);
      let live;
      try { live = await applier.listUsers(server); } catch (e) { console.error(`[vless] list users on ${server.name}:`, e.message); continue; }
      for (const a of accounts) {
        const wanted = a.status === 'active' && a.expires_at > now;
        try {
          if (wanted && !live.has(a.email)) {
            await applier.addUser(server, { uuid: decrypt(key, a.uuid_enc), email: a.email, flow: server.vless_flow, port: server.vless_port });
          } else if (!wanted && live.has(a.email)) {
            await applier.removeUser(server, { email: a.email });
          }
        } catch (e) { console.error(`[vless] account ${a.id} on ${server.name}:`, e.message); }
      }
    }
  }

  // Standard share link understood by Happ, INCY, v2rayN, Hiddify, Streisand, NekoBox, ...
  function buildLink(a) {
    const s = serverOf(a.server_id);
    const q = new URLSearchParams({
      encryption: 'none', flow: s.vless_flow, security: 'reality', sni: s.vless_sni, fp: config.vless.fingerprint,
      pbk: s.vless_public_key, sid: s.vless_short_id, type: 'tcp',
    });
    return `vless://${decrypt(key, a.uuid_enc)}@${s.vless_host}:${s.vless_port}?${q}#${encodeURIComponent(`KVN ${s.region}`)}`;
  }

  return {
    reconcile,
    available: () => !!db.prepare('SELECT 1 FROM vpn_servers WHERE is_active = 1 AND vless_port IS NOT NULL').get(),

    extendAccounts(userId, endsAt) {
      db.prepare("UPDATE vless_accounts SET expires_at = ? WHERE user_id = ? AND status = 'active'").run(endsAt, userId);
    },

    list(userId) {
      return db.prepare('SELECT * FROM vless_accounts WHERE user_id = ? ORDER BY id DESC').all(userId).map(view);
    },

    async create(userId, name) {
      const sub = subscriptions.status(userId);
      if (!sub.active) throw new HttpError(402, 'subscription_required', 'Для получения VPN нужна активная подписка');
      const id = tx(db, () => {
        const have = db.prepare("SELECT COUNT(*) AS c FROM vless_accounts WHERE user_id = ? AND status = 'active'").get(userId).c;
        if (have >= config.vless.maxAccountsPerUser) {
          throw new HttpError(409, 'profile_limit', 'Достигнут лимит конфигураций. Отзовите старую, чтобы создать новую');
        }
        const server = pickServer();
        return db.prepare(
          "INSERT INTO vless_accounts (user_id, server_id, name, email, uuid_enc, status, expires_at) VALUES (?,?,?,?,?,'active',?)",
        ).run(userId, server.id, name, `acc-${crypto.randomBytes(8).toString('hex')}@kvn`, encrypt(key, crypto.randomUUID()), sub.expiresAt).lastInsertRowid;
      });
      await reconcile();
      return view(db.prepare('SELECT * FROM vless_accounts WHERE id = ?').get(id));
    },

    // The only place a VLESS credential leaves the backend.
    link(userId, id) {
      const a = owned(userId, id);
      const st = effectiveStatus(a);
      if (st === 'revoked') throw new HttpError(410, 'profile_revoked', 'Конфигурация отозвана');
      if (st === 'expired' || !subscriptions.status(userId).active) throw new HttpError(402, 'subscription_required', 'Подписка закончилась, продлите её');
      return buildLink(a);
    },

    async revoke(userId, id) {
      const a = owned(userId, id);
      if (a.status !== 'revoked') {
        db.prepare("UPDATE vless_accounts SET status = 'revoked', revoked_at = ? WHERE id = ?").run(nowIso(), a.id);
        await reconcile();
      }
      return view(db.prepare('SELECT * FROM vless_accounts WHERE id = ?').get(a.id));
    },
    inboundTag: tag,
  };
}
