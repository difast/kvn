import { config } from './config.js';
import { createApp } from './app.js';

const { app, reconcileAll } = createApp();
app.listen(config.port, () => console.log(`[api] listening on :${config.port} (provider=${config.payments.provider}, wg=${config.vpn.applyMode}, xray=${config.vless.applyMode})`));

// Expire/revoke peers on the real server and retry failed applies.
reconcileAll();
setInterval(() => reconcileAll(), config.vpn.reconcileIntervalSec * 1000).unref();
