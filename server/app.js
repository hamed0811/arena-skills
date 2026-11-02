/**
 * Express application factory.
 *
 * Kept separate from the listener (server/index.js) so tests can build the
 * exact production middleware stack against a throwaway database.
 */
import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import session from 'express-session';
import { ROOT_DIR, config as defaultConfig } from './config.js';
import { errorHandler } from './lib/errors.js';
import { SqliteSessionStore } from './lib/session-store.js';
import {
  enforceJsonContentType,
  noStore,
  requestId,
  requestLogger,
  securityHeaders,
} from './middleware/http.js';
import { createApiRouter } from './routes/index.js';

/**
 * @param {{
 *   db: import('node:sqlite').DatabaseSync,
 *   appConfig?: typeof defaultConfig,
 * }} options
 */
export function createApp({ db, appConfig = defaultConfig } = {}) {
  if (!db) throw new Error('createApp() requires an open database instance.');

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', appConfig.http.trustProxyHops);
  app.set('query parser', 'simple');
  app.set('etag', false);

  app.locals.db = db;
  app.locals.config = appConfig;

  // --- Security & observability -------------------------------------------
  app.use(requestId);
  app.use(securityHeaders(appConfig));
  app.use(noStore);
  app.use(requestLogger);
  app.use(enforceJsonContentType);
  app.use(express.json({ limit: appConfig.http.bodyLimit, strict: true }));

  // --- Server-side sessions ----------------------------------------------
  const sessionStore = new SqliteSessionStore(db, { ttlMs: appConfig.session.ttlMs });
  app.locals.sessionStore = sessionStore;

  app.use(session({
    name: appConfig.session.name,
    secret: appConfig.session.secret,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    proxy: appConfig.http.trustProxyHops > 0,
    cookie: {
      httpOnly: true,
      secure: appConfig.session.cookieSecure,
      sameSite: appConfig.session.sameSite,
      maxAge: appConfig.session.ttlMs,
      path: '/',
    },
  }));

  // --- API ----------------------------------------------------------------
  const apiRouter = createApiRouter({ db, appConfig });
  app.locals.limiters = apiRouter.limiters;
  app.use('/api', apiRouter);

  // --- Static client ------------------------------------------------------
  const clientDir = path.join(ROOT_DIR, 'client');
  app.use(express.static(clientDir, {
    dotfiles: 'deny',
    index: 'index.html',
    etag: true,
    lastModified: true,
    maxAge: appConfig.isProduction ? '1h' : 0,
    setHeaders(res, filePath) {
      if (filePath.endsWith('.html')) {
        res.setHeader('Cache-Control', 'no-store');
      }
    },
  }));

  const indexHtml = path.join(clientDir, 'index.html');
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) return next();
    if (req.method !== 'GET' && req.method !== 'HEAD') return next();
    if (!fs.existsSync(indexHtml)) {
      return res.status(404).type('text/plain').send('Client is not built yet.');
    }
    res.setHeader('Cache-Control', 'no-store');
    return res.sendFile(indexHtml);
  });

  // --- Errors -------------------------------------------------------------
  app.use(errorHandler);

  /** Release timers/connections owned by the app (used by tests and shutdown). */
  app.locals.close = () => {
    sessionStore.close();
    for (const limiter of app.locals.limiters ?? []) limiter.close?.();
  };

  return app;
}
