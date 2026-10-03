import { tx } from '../../db.js';
import { HttpError } from '../../lib/errors.js';
import { encrypt, decrypt } from '../../lib/crypto.js';
import { generateKeyPair, generatePresharedKey, renderClientConfig, subnetHosts } from './wireguard.js';
import { createApplier } from './applier.js';

const nowIso = () => new Date().toISOString();

export function createVpnService({ db, config, subscriptions }) {
  const applier = createApplier(config.vpn.applyMode);
  const key = config.encryptionKey;

  seedServerIfEmpty();

  function seedServerIfEmpty() {
    if (db.prepare('SELECT COUNT(*) AS c FROM vpn_servers').get().c > 0) return;
    const s = config.vpn.seedServer;
    let publicKey = s.publicKey;
    if (!publicKey) {
      if (config.isProd) throw new Error('WG_SERVER_PUBLIC_KEY must be set to seed the first VPN server');
      publicKey = generateKeyPair().publicKey; // dev placeholder
      console.warn('[vpn] WG_SERVER_PUBLIC_KEY not set: using a throw-away dev key (configs will not connect)');
    }
    db.prepare(
      'INSERT INTO vpn_servers (name, region, endpoint, public_key, interface, subnet, dns, allowed_ips) VALUES (?,?,?,?,?,?,?,?)',
    ).run(s.name, s.region, s.endpoint, publicKey, s.interface, s.subnet, s.dns, s.allowedIps);
  }

  const peerOf = (p) => ({ publicKey: p.public_key, presharedKey: decrypt(key, p.preshared_key_enc), address: `${p.address}/32` });
  const serverOf = (id) => db.prepare('SELECT * FROM vpn_servers WHERE id = ?').get(id);

  function effectiveStatus(p) {
    if (p.status === 'revoked') return 'revoked';
    return p.expires_at > nowIso() ? 'active' : 'expired';
  }

  function view(p) {
    const s = serverOf(p.server_id);
    return {
      id: p.id, name: p.name, status: effectiveStatus(p), address: p.address,
      server: { id: s.id, name: s.name, region: s.region },
      publicKey: p.public_key, createdAt: p.created_at, expiresAt: p.expires_at, revokedAt: p.revoked_at,
    };
  }

  // Least-loaded active server that still has capacity.
  function pickServer() {
    const rows = db.prepare(`
      SELECT s.*, (SELECT COUNT(*) FROM vpn_profiles p WHERE p.server_id = s.id AND p.status = 'active') AS load
      FROM vpn_servers s WHERE s.is_active = 1 ORDER BY load ASC, s.id ASC`).all();
    const s = rows.find((r) => r.load < r.capacity);
    if (!s) throw new HttpError(503, 'no_capacity', 'Нет доступных серверов, попробуйте позже');
    return s;
  }

  function allocateAddress(server) {
    const used = new Set(db.prepare("SELECT address FROM vpn_profiles WHERE server_id = ? AND status = 'active'").all(server.id).map((r) => r.address));
    const { first, last, toIp } = subnetHosts(server.subnet);
    for (let n = first; n <= last; n++) if (!used.has(toIp(n))) return toIp(n);
    throw new HttpError(503, 'no_capacity', 'На сервере закончились адреса');
  }

  // Bring each real server in line with the DB: peers of active, unexpired profiles must be present;
  // peers of revoked/expired profiles must be absent. Diffing against the live interface (not a DB flag)
  // makes this self-healing after a wg0 restart or reboot. Peers unknown to the DB are never touched.
  // Runs are serialized (a call made after a profile change always sees that change).
  let chain = Promise.resolve();
  const reconcile = () => (chain = chain.then(doReconcile, doReconcile));
  async function doReconcile() {
    const now = nowIso();
    for (const server of db.prepare('SELECT * FROM vpn_servers').all()) {
      const profiles = db.prepare('SELECT * FROM vpn_profiles WHERE server_id = ?').all(server.id);
      let live;
      try { live = await applier.listPeers(server); } catch (e) { console.error(`[vpn] list peers on ${server.name}:`, e.message); continue; }
      for (const p of profiles) {
        const wanted = p.status === 'active' && p.expires_at > now;
        try {
          if (wanted && !live.has(p.public_key)) await applier.addPeer(server, peerOf(p));
          else if (!wanted && live.has(p.public_key)) await applier.removePeer(server, { publicKey: p.public_key });
        } catch (e) { console.error(`[vpn] peer ${p.id} on ${server.name}:`, e.message); }
      }
    }
  }

  function owned(userId, id) {
    const p = db.prepare('SELECT * FROM vpn_profiles WHERE id = ? AND user_id = ?').get(id, userId);
    if (!p) throw new HttpError(404, 'not_found', 'Конфигурация не найдена');
    return p;
  }

  return {
    reconcile,
    // Keep profile lifetime = subscription lifetime.
    extendProfiles(userId, endsAt) {
      db.prepare("UPDATE vpn_profiles SET expires_at = ? WHERE user_id = ? AND status = 'active'").run(endsAt, userId);
    },

    servers() {
      return db.prepare('SELECT id, name, region FROM vpn_servers WHERE is_active = 1 ORDER BY id').all();
    },

    list(userId) {
      return db.prepare('SELECT * FROM vpn_profiles WHERE user_id = ? ORDER BY id DESC').all(userId).map(view);
    },

    async create(userId, name) {
      const sub = subscriptions.status(userId);
      if (!sub.active) throw new HttpError(402, 'subscription_required', 'Для получения VPN нужна активная подписка');

      const id = tx(db, () => {
        const have = db.prepare("SELECT COUNT(*) AS c FROM vpn_profiles WHERE user_id = ? AND status = 'active'").get(userId).c;
        if (have >= config.vpn.maxProfilesPerUser) {
          throw new HttpError(409, 'profile_limit', 'Достигнут лимит конфигураций. Отзовите старую, чтобы создать новую');
        }
        const server = pickServer();
        const kp = generateKeyPair();
        return db.prepare(
          `INSERT INTO vpn_profiles (user_id, server_id, name, public_key, private_key_enc, preshared_key_enc, address, status, expires_at)
           VALUES (?,?,?,?,?,?,?,'active',?)`,
        ).run(
          userId, server.id, name, kp.publicKey, encrypt(key, kp.privateKey), encrypt(key, generatePresharedKey()),
          allocateAddress(server), sub.expiresAt,
        ).lastInsertRowid;
      });
      await reconcile();
      return view(db.prepare('SELECT * FROM vpn_profiles WHERE id = ?').get(id));
    },

    get(userId, id) {
      return view(owned(userId, id));
    },

    // The only place a client private key leaves the backend.
    config(userId, id) {
      const p = owned(userId, id);
      const st = effectiveStatus(p);
      if (st === 'revoked') throw new HttpError(410, 'profile_revoked', 'Конфигурация отозвана');
      if (st === 'expired' || !subscriptions.status(userId).active) {
        throw new HttpError(402, 'subscription_required', 'Подписка закончилась, продлите её');
      }
      const text = renderClientConfig({
        privateKey: decrypt(key, p.private_key_enc),
        presharedKey: decrypt(key, p.preshared_key_enc),
        address: `${p.address}/32`,
        server: serverOf(p.server_id),
      });
      return { filename: `kvn-${p.id}.conf`, text };
    },

    async revoke(userId, id) {
      const p = owned(userId, id);
      if (p.status !== 'revoked') {
        db.prepare("UPDATE vpn_profiles SET status = 'revoked', revoked_at = ? WHERE id = ?").run(nowIso(), p.id);
        await reconcile();
      }
      return view(db.prepare('SELECT * FROM vpn_profiles WHERE id = ?').get(p.id));
    },
  };
}
