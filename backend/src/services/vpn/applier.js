import { spawn } from 'node:child_process';

function run(args, stdin) {
  return new Promise((resolve, reject) => {
    const p = spawn('wg', args, { stdio: ['pipe', 'ignore', 'pipe'] });
    let err = '';
    p.stderr.on('data', (d) => (err += d));
    p.on('error', reject);
    p.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`wg ${args[0]} failed: ${err.trim()}`))));
    p.stdin.end(stdin ?? '');
  });
}

// Applier = how a peer gets onto / off the real WireGuard server.
// "none": only the DB is updated (dev/CI). "wg": runs `wg set` on this host.
// For remote VPN servers, add another implementation (SSH / agent HTTP API) with the same shape.
export function createApplier(mode) {
  if (mode === 'wg') {
    return {
      async addPeer(server, { publicKey, presharedKey, address }) {
        await run(['set', server.interface, 'peer', publicKey, 'preshared-key', '/dev/stdin', 'allowed-ips', address], `${presharedKey}\n`);
      },
      async removePeer(server, { publicKey }) {
        await run(['set', server.interface, 'peer', publicKey, 'remove']);
      },
    };
  }
  return { async addPeer() {}, async removePeer() {} };
}
