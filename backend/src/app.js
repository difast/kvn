import express from 'express';
import path from 'node:path';
import fs from 'node:fs';
import helmet from 'helmet';
import cors from 'cors';
import { config as defaultConfig } from './config.js';
import { openDb } from './db.js';
import { HttpError } from './lib/errors.js';
import { consoleMailer } from './services/mailer.js';
import { createAuthService } from './services/auth.js';
import { createSubscriptionService } from './services/subscriptions.js';
import { createPaymentService } from './services/payments/index.js';
import { createVpnService } from './services/vpn/index.js';
import { createVlessService } from './services/vpn/vless.js';
import { createLimiters } from './middleware/rateLimit.js';
import { createRouter } from './routes/index.js';

export function createApp({ config = defaultConfig, db = openDb(config.dbPath), mailer = consoleMailer } = {}) {
  const refs = {};
  // Subscription changes (renewal / cancel) propagate to every protocol's profiles.
  const subscriptions = createSubscriptionService({
    db,
    onExtended: (u, e) => { refs.vpn.extendProfiles(u, e); refs.vless.extendAccounts(u, e); },
  });
  const vpn = (refs.vpn = createVpnService({ db, config, subscriptions }));
  const vless = (refs.vless = createVlessService({ db, config, subscriptions }));
  const reconcileAll = () => Promise.all([vpn.reconcile(), vless.reconcile()]);
  const auth = createAuthService({ db, config, mailer });
  const payments = createPaymentService({ db, config, subscriptions });

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);
  app.use(helmet({
    // Plain-HTTP dev must not be force-upgraded to https.
    contentSecurityPolicy: { directives: { upgradeInsecureRequests: config.isProd ? [] : null } },
  }));
  // Bearer-token API: no cookies, so no credentialed CORS needed.
  app.use(cors({ origin: config.corsOrigins, exposedHeaders: ['Content-Disposition'] }));
  app.use(express.json({ limit: '10kb' }));

  const limiters = createLimiters(config);
  app.use('/api', limiters.api, createRouter({ auth, subscriptions, payments, vpn, vless, reconcileAll, limiters }));

  // Optional: serve the static frontend from the same process (single-service deploys).
  const webDir = path.resolve(config.frontendDir);
  if (config.serveFrontend && fs.existsSync(path.join(webDir, 'index.html'))) {
    app.use((req, res, next) => (req.path === '/serve.js' ? res.status(404).end() : next()));
    app.use(express.static(webDir, { index: 'index.html', extensions: ['html'], dotfiles: 'ignore' }));
  } else if (config.serveFrontend) {
    console.warn(`[web] FRONTEND_DIR ${webDir} not found: serving API only`);
  }

  app.use('/api', (_req, _res, next) => next(new HttpError(404, 'not_found', 'Не найдено')));
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    if (err instanceof HttpError) {
      return res.status(err.status).json({ error: { code: err.code, message: err.message } });
    }
    if (err.type === 'entity.parse.failed') {
      return res.status(400).json({ error: { code: 'bad_json', message: 'Некорректный JSON' } });
    }
    if (err.type === 'entity.too.large') {
      return res.status(413).json({ error: { code: 'too_large', message: 'Слишком большой запрос' } });
    }
    console.error(err);
    res.status(500).json({ error: { code: 'internal', message: 'Внутренняя ошибка' } });
  });

  return { app, db, vpn, vless, reconcileAll };
}
