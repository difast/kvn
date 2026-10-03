import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const env = process.env;
const isProd = env.NODE_ENV === 'production';
const dataDir = path.resolve(env.DATA_DIR || './data');

// In development missing secrets are generated once and kept in data/ (git-ignored).
// In production they MUST come from environment variables.
function devSecrets() {
  const file = path.join(dataDir, '.dev-secrets.json');
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    const s = {
      jwtSecret: crypto.randomBytes(48).toString('base64'),
      encryptionKey: crypto.randomBytes(32).toString('base64'),
    };
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(file, JSON.stringify(s), { mode: 0o600 });
    return s;
  }
}

function secret(name, devKey) {
  if (env[name]) return env[name];
  if (isProd) throw new Error(`${name} must be set in production`);
  return devSecrets()[devKey];
}

const encryptionKey = Buffer.from(secret('DATA_ENCRYPTION_KEY', 'encryptionKey'), 'base64');
if (encryptionKey.length !== 32) throw new Error('DATA_ENCRYPTION_KEY must be 32 bytes, base64-encoded');

const num = (v, d) => (v === undefined || v === '' ? d : Number(v));

export const config = {
  isProd,
  port: num(env.PORT, 3000),
  dbPath: env.DB_PATH || path.join(dataDir, 'kvn.sqlite'),
  jwtSecret: secret('JWT_SECRET', 'jwtSecret'),
  encryptionKey,
  accessTokenTtlSec: num(env.ACCESS_TOKEN_TTL_SEC, 15 * 60),
  refreshTokenTtlDays: num(env.REFRESH_TOKEN_TTL_DAYS, 30),
  corsOrigins: (env.CORS_ORIGINS || 'http://localhost:8080').split(',').map((s) => s.trim()).filter(Boolean),
  trustProxy: env.TRUST_PROXY === undefined ? (isProd ? 1 : false) : Number(env.TRUST_PROXY) || env.TRUST_PROXY === 'true',
  frontendUrl: env.FRONTEND_URL || 'http://localhost:8080',
  rateLimit: {
    enabled: env.RATE_LIMIT_DISABLED !== 'true',
    loginMax: num(env.RATE_LIMIT_LOGIN_MAX, 10), // attempts / 15 min per ip+email
    authIpMax: num(env.RATE_LIMIT_AUTH_IP_MAX, 50), // auth requests / 15 min per ip
    apiMax: num(env.RATE_LIMIT_API_MAX, 300), // requests / min per ip
  },
  payments: {
    provider: env.PAYMENT_PROVIDER || 'mock',
    // Guard: the fake provider must never run in production by accident.
    allowMockInProd: env.ALLOW_MOCK_PAYMENTS === 'true',
    sber: {
      baseUrl: env.SBER_API_URL || '',
      userName: env.SBER_USERNAME || '',
      password: env.SBER_PASSWORD || '',
      webhookSecret: env.SBER_WEBHOOK_SECRET || '',
    },
  },
  vpn: {
    // 'none' = only record peers in the DB (dev); 'wg' = run `wg set` on this host.
    maxProfilesPerUser: num(env.VPN_MAX_PROFILES_PER_USER, 1),
    applyMode: env.WG_APPLY_MODE || 'none',
    seedServer: {
      name: env.WG_SERVER_NAME || 'Server 1',
      region: env.WG_SERVER_REGION || 'RU',
      endpoint: env.WG_ENDPOINT || '203.0.113.10:51820', // TEST-NET placeholder
      publicKey: env.WG_SERVER_PUBLIC_KEY || '', // public key only; the server private key never enters this app
      interface: env.WG_INTERFACE || 'wg0',
      subnet: env.WG_SUBNET || '10.8.0.0/24',
      dns: env.WG_DNS || '1.1.1.1, 1.0.0.1',
      allowedIps: env.WG_ALLOWED_IPS || '0.0.0.0/0, ::/0',
    },
  },
};

if (isProd && config.payments.provider === 'mock' && !config.payments.allowMockInProd) {
  throw new Error('PAYMENT_PROVIDER=mock is not allowed in production (set ALLOW_MOCK_PAYMENTS=true to override)');
}
