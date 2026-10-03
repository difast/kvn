import crypto from 'node:crypto';

// WireGuard keys are raw 32-byte X25519 keys, base64-encoded. Generated in pure Node,
// so no `wg` binary is needed on the API host.
export function generateKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
  const priv = privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32);
  const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { privateKey: priv.toString('base64'), publicKey: pub.toString('base64') };
}

export const generatePresharedKey = () => crypto.randomBytes(32).toString('base64');

export function renderClientConfig({ privateKey, presharedKey, address, server }) {
  return [
    '[Interface]',
    `PrivateKey = ${privateKey}`,
    `Address = ${address}`,
    `DNS = ${server.dns}`,
    '',
    '[Peer]',
    `PublicKey = ${server.public_key}`,
    `PresharedKey = ${presharedKey}`,
    `Endpoint = ${server.endpoint}`,
    `AllowedIPs = ${server.allowed_ips}`,
    'PersistentKeepalive = 25',
    '',
  ].join('\n');
}

// IPv4 pool helpers. First usable host (.1) is reserved for the server itself.
const toInt = (ip) => ip.split('.').reduce((a, o) => ((a << 8) | Number(o)) >>> 0, 0);
const toIp = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');

export function subnetHosts(cidr) {
  const [ip, bits] = cidr.split('/');
  const size = 2 ** (32 - Number(bits));
  const base = (toInt(ip) & (~(size - 1) >>> 0)) >>> 0;
  return { first: base + 2, last: base + size - 2, toIp };
}
