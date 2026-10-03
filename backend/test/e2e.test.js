import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.js';
import { config as base } from '../src/config.js';

let server, url, db;
const config = { ...base, dbPath: ':memory:', rateLimit: { ...base.rateLimit, loginMax: 5 } };

before(async () => {
  const mails = (globalThis.__mails = []);
  const created = createApp({ config, db: undefined, mailer: { send: async (m) => mails.push(m) } });
  db = created.db;
  server = created.app.listen(0);
  url = `http://127.0.0.1:${server.address().port}/api`;
});
after(() => server.close());

const call = async (path, { method = 'GET', body, token } = {}) => {
  const res = await fetch(url + path, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token && { Authorization: `Bearer ${token}` }) },
    body: body && JSON.stringify(body),
  });
  const ct = res.headers.get('content-type') || '';
  return { res, data: ct.includes('json') ? await res.json() : await res.text() };
};

const creds = { email: 'User@Example.com', password: 'correct horse battery' };
let tokens;

test('validation rejects bad input', async () => {
  assert.equal((await call('/auth/register', { method: 'POST', body: { email: 'nope', password: 'x' } })).res.status, 400);
});

test('register, duplicate, login', async () => {
  const r = await call('/auth/register', { method: 'POST', body: creds });
  assert.equal(r.res.status, 201);
  assert.equal(r.data.user.email, 'user@example.com');
  assert.ok(!JSON.stringify(r.data).includes('password'));
  assert.equal((await call('/auth/register', { method: 'POST', body: creds })).res.status, 409);
  const l = await call('/auth/login', { method: 'POST', body: creds });
  assert.equal(l.res.status, 200);
  tokens = l.data;
  assert.equal((await call('/auth/login', { method: 'POST', body: { ...creds, password: 'wrongwrong' } })).res.status, 401);
  // password is stored hashed
  assert.match(db.prepare('SELECT password_hash FROM users').get().password_hash, /^scrypt\$/);
});

test('protected routes need a token', async () => {
  assert.equal((await call('/me')).res.status, 401);
  assert.equal((await call('/me', { token: 'garbage' })).res.status, 401);
});

test('no subscription -> no VPN', async () => {
  const me = await call('/me', { token: tokens.accessToken });
  assert.equal(me.data.subscription.status, 'none');
  assert.equal((await call('/vpn/profiles', { method: 'POST', body: {}, token: tokens.accessToken })).res.status, 402);
});

let profile;
test('mock payment activates 30-day subscription', async () => {
  const p = await call('/payments', { method: 'POST', body: {}, token: tokens.accessToken });
  assert.equal(p.res.status, 201);
  assert.equal(p.data.payment.status, 'succeeded');
  assert.equal(p.data.payment.amountKop, 50000);
  const days = (Date.parse(p.data.subscription.expiresAt) - Date.now()) / 86_400_000;
  assert.ok(days > 29.9 && days <= 30);
  // second payment appends another period
  const p2 = await call('/payments', { method: 'POST', body: {}, token: tokens.accessToken });
  const days2 = (Date.parse(p2.data.subscription.expiresAt) - Date.now()) / 86_400_000;
  assert.ok(days2 > 59.9);
});

test('generate and download WireGuard config', async () => {
  const c = await call('/vpn/profiles', { method: 'POST', body: { name: 'Phone' }, token: tokens.accessToken });
  assert.equal(c.res.status, 201);
  profile = c.data.profile;
  assert.ok(!JSON.stringify(profile).toLowerCase().includes('private'));
  assert.equal(profile.address, '10.8.0.2');
  // limit of 1 active profile
  assert.equal((await call('/vpn/profiles', { method: 'POST', body: {}, token: tokens.accessToken })).res.status, 409);

  const f = await call(`/vpn/profiles/${profile.id}/config`, { token: tokens.accessToken });
  assert.equal(f.res.status, 200);
  assert.match(f.res.headers.get('content-disposition'), /attachment; filename="kvn-\d+\.conf"/);
  assert.match(f.data, /\[Interface\]\nPrivateKey = [A-Za-z0-9+/]{43}=\n/);
  assert.match(f.data, /\[Peer\]/);
  assert.match(f.data, /Address = 10\.8\.0\.2\/32/);
  // key in the config is a valid 32-byte key, and the stored copy is encrypted
  const priv = /PrivateKey = (\S+)/.exec(f.data)[1];
  assert.equal(Buffer.from(priv, 'base64').length, 32);
  const row = db.prepare('SELECT private_key_enc FROM vpn_profiles').get();
  assert.ok(!row.private_key_enc.includes(priv));
});

test("other users cannot access someone else's profile", async () => {
  const other = await call('/auth/register', { method: 'POST', body: { email: 'b@example.com', password: 'another-password' } });
  assert.equal((await call(`/vpn/profiles/${profile.id}/config`, { token: other.data.accessToken })).res.status, 404);
  assert.equal((await call(`/vpn/profiles/${profile.id}/revoke`, { method: 'POST', token: other.data.accessToken })).res.status, 404);
});

test('revoke blocks the config; a new one gets a distinct key', async () => {
  const oldPub = profile.publicKey;
  const rv = await call(`/vpn/profiles/${profile.id}/revoke`, { method: 'POST', token: tokens.accessToken });
  assert.equal(rv.data.profile.status, 'revoked');
  assert.equal((await call(`/vpn/profiles/${profile.id}/config`, { token: tokens.accessToken })).res.status, 410);
  const c = await call('/vpn/profiles', { method: 'POST', body: {}, token: tokens.accessToken });
  assert.equal(c.res.status, 201);
  assert.notEqual(c.data.profile.publicKey, oldPub);
});

test('expired subscription blocks config', async () => {
  db.prepare("UPDATE subscriptions SET ends_at = '2000-01-01T00:00:00.000Z'").run();
  db.prepare("UPDATE vpn_profiles SET expires_at = '2000-01-01T00:00:00.000Z'").run();
  const me = await call('/me', { token: tokens.accessToken });
  assert.equal(me.data.subscription.status, 'expired');
  const list = await call('/vpn/profiles', { token: tokens.accessToken });
  const active = list.data.profiles.find((p) => p.status === 'expired');
  assert.ok(active);
  assert.equal((await call(`/vpn/profiles/${active.id}/config`, { token: tokens.accessToken })).res.status, 402);
  // paying again revives the profile
  await call('/payments', { method: 'POST', body: {}, token: tokens.accessToken });
  assert.equal((await call(`/vpn/profiles/${active.id}/config`, { token: tokens.accessToken })).res.status, 200);
});

test('refresh rotates tokens, logout revokes', async () => {
  const r = await call('/auth/refresh', { method: 'POST', body: { refreshToken: tokens.refreshToken } });
  assert.equal(r.res.status, 200);
  assert.equal((await call('/auth/refresh', { method: 'POST', body: { refreshToken: tokens.refreshToken } })).res.status, 401);
  await call('/auth/logout', { method: 'POST', body: { refreshToken: r.data.refreshToken } });
  assert.equal((await call('/auth/refresh', { method: 'POST', body: { refreshToken: r.data.refreshToken } })).res.status, 401);
});

test('password reset flow', async () => {
  assert.equal((await call('/auth/password/forgot', { method: 'POST', body: { email: 'nobody@example.com' } })).res.status, 202);
  assert.equal(globalThis.__mails.length, 0);
  await call('/auth/password/forgot', { method: 'POST', body: { email: 'user@example.com' } });
  const token = /token=(\S+)/.exec(globalThis.__mails[0].text)[1];
  assert.equal((await call('/auth/password/reset', { method: 'POST', body: { token, password: 'brand-new-password' } })).res.status, 200);
  assert.equal((await call('/auth/password/reset', { method: 'POST', body: { token, password: 'brand-new-password' } })).res.status, 400);
  assert.equal((await call('/auth/login', { method: 'POST', body: { email: 'user@example.com', password: 'brand-new-password' } })).res.status, 200);
});

test('brute-force protection on login', async () => {
  const body = { email: 'victim@example.com', password: 'guess-guess' };
  const codes = [];
  for (let i = 0; i < 7; i++) codes.push((await call('/auth/login', { method: 'POST', body })).res.status);
  assert.deepEqual(codes.slice(0, 5), [401, 401, 401, 401, 401]);
  assert.equal(codes[6], 429);
});

test('cancelling the subscription revokes VPN access immediately', async () => {
  const u = await call('/auth/register', { method: 'POST', body: { email: 'c@example.com', password: 'cancel-password' } });
  const t = u.data.accessToken;
  await call('/payments', { method: 'POST', body: {}, token: t });
  const pr = (await call('/vpn/profiles', { method: 'POST', body: {}, token: t })).data.profile;
  assert.equal((await call(`/vpn/profiles/${pr.id}/config`, { token: t })).res.status, 200);
  const c = await call('/subscription/cancel', { method: 'POST', token: t });
  assert.equal(c.data.subscription.active, false);
  assert.equal((await call(`/vpn/profiles/${pr.id}/config`, { token: t })).res.status, 402);
});
