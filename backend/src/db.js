import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS password_resets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  used_at TEXT
);
CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  plan_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  provider_payment_id TEXT,
  amount_kop INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'RUB',
  status TEXT NOT NULL CHECK (status IN ('pending','succeeded','failed')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  paid_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS payments_provider_id ON payments(provider, provider_payment_id);
-- One row per purchased period; the user's access ends at MAX(ends_at).
CREATE TABLE IF NOT EXISTS subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  payment_id INTEGER NOT NULL UNIQUE REFERENCES payments(id),
  starts_at TEXT NOT NULL,
  ends_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS subscriptions_user ON subscriptions(user_id);
CREATE TABLE IF NOT EXISTS vpn_servers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  region TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  public_key TEXT NOT NULL,
  interface TEXT NOT NULL DEFAULT 'wg0',
  subnet TEXT NOT NULL,
  dns TEXT NOT NULL,
  allowed_ips TEXT NOT NULL,
  capacity INTEGER NOT NULL DEFAULT 250,
  is_active INTEGER NOT NULL DEFAULT 1,
  vless_host TEXT, vless_port INTEGER, vless_public_key TEXT, vless_short_id TEXT, vless_sni TEXT, vless_flow TEXT
);
CREATE TABLE IF NOT EXISTS vpn_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  server_id INTEGER NOT NULL REFERENCES vpn_servers(id),
  name TEXT NOT NULL,
  public_key TEXT NOT NULL UNIQUE,
  private_key_enc TEXT NOT NULL,
  preshared_key_enc TEXT NOT NULL,
  address TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active','revoked')),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS vpn_profiles_user ON vpn_profiles(user_id);
-- An address is held only by non-revoked profiles.
CREATE UNIQUE INDEX IF NOT EXISTS vpn_profiles_addr ON vpn_profiles(server_id, address) WHERE status = 'active';
-- VLESS+Reality accounts (for Happ / INCY / v2rayN ...). The uuid is a credential, so it is stored encrypted.
CREATE TABLE IF NOT EXISTS vless_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  server_id INTEGER NOT NULL REFERENCES vpn_servers(id),
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  uuid_enc TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active','revoked')),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS vless_accounts_user ON vless_accounts(user_id);
`;

// Columns added after the first release: ALTER only when missing (CREATE IF NOT EXISTS skips existing tables).
const MIGRATIONS = [
  ['vpn_servers', 'vless_host', 'TEXT'], ['vpn_servers', 'vless_port', 'INTEGER'], ['vpn_servers', 'vless_public_key', 'TEXT'],
  ['vpn_servers', 'vless_short_id', 'TEXT'], ['vpn_servers', 'vless_sni', 'TEXT'], ['vpn_servers', 'vless_flow', 'TEXT'],
];

export function openDb(file) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  db.exec(SCHEMA);
  for (const [table, col, type] of MIGRATIONS) {
    if (!db.prepare(`PRAGMA table_info(${table})`).all().some((c) => c.name === col)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${type}`);
  }
  return db;
}

// Run fn inside a transaction (node:sqlite has no helper).
export function tx(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const r = fn();
    db.exec('COMMIT');
    return r;
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}
