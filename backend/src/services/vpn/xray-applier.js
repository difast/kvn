import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

// NOTE: `xray api ...` exits 0 even when it failed, so success is decided from its output text.
function run(bin, args) {
  return new Promise((resolve, reject) => {
    const p = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (out += d));
    p.on('error', reject);
    p.on('close', (code) => (code === 0 ? resolve(out) : reject(new Error(`xray ${args[1]} exited ${code}: ${out.trim()}`))));
  });
}

// Same shape as the WireGuard applier: listUsers / addUser / removeUser.
export function createXrayApplier({ applyMode, bin, apiAddr, inboundTag }) {
  if (applyMode === 'xray') {
    const server = `--server=${apiAddr}`;
    return {
      async listUsers() {
        const out = await run(bin, ['api', 'inbounduser', server, `-tag=${inboundTag}`]);
        const json = JSON.parse(out.trim() || '{}');
        return new Set((json.users || []).map((u) => u.email));
      },
      async addUser(_s, { uuid, email, flow, port }) {
        const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'kvn-'));
        const file = path.join(dir, 'user.json');
        try {
          // The uuid is a credential: private 0700 dir + 0600 file, deleted right after.
          await fs.writeFile(file, JSON.stringify({
            inbounds: [{ tag: inboundTag, port, protocol: 'vless', settings: { decryption: 'none', clients: [{ id: uuid, email, flow }] } }],
          }), { mode: 0o600 });
          const out = await run(bin, ['api', 'adu', server, file]);
          if (!/Added 1 user/.test(out)) throw new Error(`xray adu failed: ${out.trim()}`);
        } finally {
          await fs.rm(dir, { recursive: true, force: true });
        }
      },
      async removeUser(_s, { email }) {
        const out = await run(bin, ['api', 'rmu', server, `-tag=${inboundTag}`, email]);
        if (!/Removed 1 user/.test(out) && !/not found/.test(out)) throw new Error(`xray rmu failed: ${out.trim()}`);
      },
    };
  }
  const users = new Set();
  return {
    async listUsers() { return new Set(users); },
    async addUser(_s, { email }) { users.add(email); },
    async removeUser(_s, { email }) { users.delete(email); },
  };
}
