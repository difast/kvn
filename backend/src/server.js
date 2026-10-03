import { config } from './config.js';
import { createApp } from './app.js';

const { app, vpn } = createApp();
app.listen(config.port, () => console.log(`[api] listening on :${config.port} (provider=${config.payments.provider}, wg=${config.vpn.applyMode})`));

// Expire/revoke peers on the real server and retry failed applies.
vpn.reconcile();
setInterval(() => vpn.reconcile(), config.vpn.reconcileIntervalSec * 1000).unref();
