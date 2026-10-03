import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

function run(args, stdin) {
  return new Promise((resolve, reject) => {
    const p = spawn(process.env.WG_BIN || 'wg', args, { stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '', err = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (err += d));
    p.on('error', reject);
    p.on('close', (code) => (code === 0 ? resolve(out) : reject(new Error(`wg ${args[0]} failed: ${err.trim()}`))));
    // wg may exit before reading stdin (error case): an unhandled EPIPE would crash the whole API.
    p.stdin.on('error', () => {});
    p.stdin.end(stdin ?? '');
  });
}

// Applier = how peers get onto / off a real WireGuard server. Three operations:
//   listPeers(server)  -> Set of public keys currently configured on the interface
//   addPeer(server, {publicKey, presharedKey, address})
//   removePeer(server, {publicKey})
// "none": in-memory only (dev/CI). "wg": runs `wg` on this host (needs CAP_NET_ADMIN).
// For remote VPN servers add another implementation (SSH / agent HTTP API) with the same shape.
export function createApplier(mode) {
  if (mode === 'wg') {
    return {
      async listPeers(server) {
        const out = await run(['show', server.interface, 'peers']);
        return new Set(out.split('\n').map((s) => s.trim()).filter(Boolean));
      },
      async addPeer(server, { publicKey, presharedKey, address }) {
        // `wg` only reads the preshared key from a file (not argv: visible in `ps`; not /dev/stdin: Node's
        // stdio is a socket and wg's fopen() on it fails). Private 0700 dir + 0600 file, removed right after.
        const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'kvn-'));
        const file = path.join(dir, 'psk');
        try {
          await fs.writeFile(file, `${presharedKey}\n`, { mode: 0o600 });
          await run(['set', server.interface, 'peer', publicKey, 'preshared-key', file, 'allowed-ips', address]);
        } finally {
          await fs.rm(dir, { recursive: true, force: true });
        }
      },
      async removePeer(server, { publicKey }) {
        await run(['set', server.interface, 'peer', publicKey, 'remove']);
      },
    };
  }
  const peers = new Set();
  return {
    async listPeers() { return new Set(peers); },
    async addPeer(_s, { publicKey }) { peers.add(publicKey); },
    async removePeer(_s, { publicKey }) { peers.delete(publicKey); },
  };
}
