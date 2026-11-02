#!/usr/bin/env node
/**
 * Server bootstrap.
 *
 * Responsibilities: open the database, verify it is usable, build the app,
 * start HTTP, and shut down cleanly (stop accepting connections, close the
 * session store timers, checkpoint + close SQLite).
 */
import http from 'node:http';
import { config } from './config.js';
import { createApp } from './app.js';
import { applySchema, openDatabase } from './db.js';

function fail(message, error) {
  console.error(`\n✖ ${message}`);
  if (error) console.error(error.stack ?? String(error));
  process.exit(1);
}

function assertSchemaReady(db) {
  const hasMeta = db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'meta'")
    .get();

  if (!hasMeta) {
    console.warn('⚠  Empty database detected — applying database/schema.sql.');
    applySchema(db);
    console.warn('⚠  Schema created, but there is no user yet. Run: npm run db:reset');
    return;
  }

  const admin = db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND is_active = 1").get();
  if (Number(admin.n) === 0) {
    console.warn('⚠  No active administrator exists. Run: npm run db:reset');
  }

  const mustChange = db.prepare('SELECT COUNT(*) AS n FROM users WHERE must_change_password = 1').get();
  if (Number(mustChange.n) > 0) {
    console.warn(`⚠  ${mustChange.n} account(s) still use a temporary password.`);
  }

  const quickCheck = db.prepare('PRAGMA quick_check').get();
  const result = Object.values(quickCheck)[0];
  if (result !== 'ok') {
    throw new Error(`SQLite quick_check failed: ${result}`);
  }
}

function main() {
  if (!config.isProduction && config.session.secret === 'dev-only-insecure-session-secret-change-me') {
    console.warn('⚠  Development session secret in use. Set SESSION_SECRET before deploying.');
  }
  if (config.session.cookieSecure && config.http.trustProxyHops === 0 && config.isProduction) {
    console.warn('⚠  Secure cookies are enabled but no reverse proxy hops are trusted; set TRUST_PROXY_HOPS.');
  }

  let db;
  try {
    db = openDatabase();
    assertSchemaReady(db);
  } catch (error) {
    fail('Could not open the database. Run `npm run db:reset` if this is a fresh checkout.', error);
    return;
  }

  const app = createApp({ db, appConfig: config });
  const server = http.createServer(app);

  // Slow-loris / resource-exhaustion hardening.
  server.requestTimeout = config.http.requestTimeoutMs;
  server.headersTimeout = config.http.requestTimeoutMs + 5_000;
  server.keepAliveTimeout = 5_000;
  server.maxRequestsPerSocket = 1_000;

  server.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
      fail(`Port ${config.http.port} is already in use. Stop the other process or set PORT.`);
    } else {
      fail('HTTP server error.', error);
    }
  });

  server.listen(config.http.port, config.http.host, () => {
    console.log('');
    console.log('  Enterprise Budget System');
    console.log(`  environment : ${config.env}`);
    console.log(`  listening   : http://${config.http.host}:${config.http.port}`);
    console.log(`  database    : ${config.db.path}`);
    console.log(`  health      : http://localhost:${config.http.port}/api/health`);
    console.log('');
  });

  let shuttingDown = false;
  const shutdown = (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`\n${signal} received — shutting down…`);

    server.close((error) => {
      try {
        app.locals.close?.();
        db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
        db.close();
      } catch (closeError) {
        console.error(closeError);
      }
      if (error) {
        console.error(error);
        process.exit(1);
      }
      console.log('Shutdown complete.');
      process.exit(0);
    });

    // Do not hang forever on a stuck connection.
    setTimeout(() => {
      console.error('Forced shutdown after timeout.');
      process.exit(1);
    }, 10_000).unref();
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('unhandledRejection', (reason) => {
    console.error('Unhandled rejection:', reason);
  });
}

main();
