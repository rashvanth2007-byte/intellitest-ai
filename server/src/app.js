import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { config } from './config.js';
import { openDb } from './db/index.js';
import { loadUser, csrfGuard } from './auth/session.js';
import { authRouter } from './auth/routes.js';
import { scanRouter } from './scan/routes.js';
import { settingsRouter } from './settings/routes.js';
import { recoverInterrupted } from './scan/jobs.js';
import { HttpError } from './util/http.js';

export function createApp() {
  const app = express();
  app.disable('x-powered-by');
  // Only trust X-Forwarded-For behind a real reverse proxy (Render sets TRUST_PROXY=1); otherwise it can be spoofed.
  app.set('trust proxy', config.trustProxy);

  // Desktop app: refuse requests whose Host isn't ours (blocks DNS rebinding from malicious web pages).
  if (config.allowedHosts.length) {
    app.use((req, res, next) => (config.allowedHosts.includes(String(req.headers.host || '').toLowerCase()) ? next() : res.status(421).send('Misdirected request')));
  }

  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
        imgSrc: ["'self'", 'data:', 'https://avatars.githubusercontent.com'],
        connectSrc: ["'self'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'", 'https://github.com'],
        upgradeInsecureRequests: config.cookieSecure ? [] : null,
      },
    },
    crossOriginEmbedderPolicy: false,
    hsts: config.cookieSecure,
  }));
  app.use(cookieParser());
  app.use(express.json({ limit: '3mb' }));

  app.get('/healthz', (_req, res) => res.json({ ok: true, time: Date.now() }));

  const api = express.Router();
  api.use(rateLimit({ windowMs: 60 * 1000, limit: 300, standardHeaders: 'draft-7', legacyHeaders: false }));
  api.use(loadUser);
  api.use(csrfGuard);
  api.use('/auth', authRouter);
  api.use('/scans', scanRouter);
  api.use('/settings', settingsRouter);
  api.use((_req, _res, next) => next(new HttpError(404, 'Not found')));
  app.use('/api', api);

  // Serve the built web UI (single page app with hash routing).
  if (fs.existsSync(path.join(config.webDist, 'index.html'))) {
    app.use(express.static(config.webDist, { index: false, maxAge: '1h', setHeaders: (res, p) => { if (/[\\/]assets[\\/]/.test(p)) res.setHeader('Cache-Control', 'public, max-age=31536000, immutable'); } }));
    app.get(/^\/(?!api\/).*/, (_req, res) => res.sendFile(path.join(config.webDist, 'index.html')));
  } else {
    app.get('/', (_req, res) => res.type('text').send('IntelliTest AI API is running. Build the web UI with "npm run build" or use "npm run dev".'));
  }

  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err); // e.g. an SSE stream: let Express close the connection
    const raw = Number(err.status || err.statusCode);
    const status = Number.isInteger(raw) && raw >= 400 && raw <= 599 ? raw : 500;
    if (status >= 500) console.error('[error]', req.method, req.originalUrl, err);
    const masked = status >= 500 && config.isProd;
    res.status(status).json({ error: masked ? 'Internal server error' : err.message || 'Error', code: masked ? undefined : err.code });
  });
  return app;
}

/** Start the HTTP server. Used by the CLI entry point and by the Electron app. */
export async function startServer({ port = config.port, host = config.host } = {}) {
  await openDb(config);
  await recoverInterrupted();
  const app = createApp();
  const server = await new Promise((resolve, reject) => {
    const s = app.listen(port, host, () => resolve(s));
    s.on('error', reject);
  });
  server.requestTimeout = 15 * 60 * 1000; // large uploads
  const actual = server.address().port;
  return { server, port: actual, url: `http://${host === '0.0.0.0' ? 'localhost' : host}:${actual}` };
}
