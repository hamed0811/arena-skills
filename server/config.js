/**
 * Central configuration. Every value can be overridden with an environment
 * variable so the same build runs in dev, staging and production without code
 * changes. Never hard-code secrets here.
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const env = process.env.NODE_ENV ?? 'development';
const isProduction = env === 'production';

function intEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`Invalid ${name}: expected a non-negative integer, got "${raw}"`);
  }
  return value;
}

function boolEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(raw.toLowerCase());
}

const DEV_SESSION_SECRET = 'dev-only-insecure-session-secret-change-me';
const sessionSecret = process.env.SESSION_SECRET ?? (isProduction ? '' : DEV_SESSION_SECRET);

if (isProduction && sessionSecret.length < 32) {
  throw new Error('SESSION_SECRET must be set to a random string of at least 32 characters in production.');
}

export const config = {
  env,
  isProduction,
  role: process.env.ROLE || 'standalone',
  http: {
    host: process.env.HOST ?? '0.0.0.0',
    port: intEnv('PORT', 3000),
    /**
     * Number of reverse proxies in front of the app (Express `trust proxy`).
     * Keep 0 unless you actually run behind nginx/IIS, otherwise clients can
     * spoof X-Forwarded-For and poison audit logs / rate limiting.
     */
    trustProxyHops: intEnv('TRUST_PROXY_HOPS', 0),
    bodyLimit: process.env.BODY_LIMIT ?? '1mb',
    requestTimeoutMs: intEnv('REQUEST_TIMEOUT_MS', 30_000),
  },
  db: {
    path: process.env.DB_PATH ? path.resolve(process.env.DB_PATH) : path.join(ROOT_DIR, 'database', 'budget.db'),
    schemaPath: path.join(ROOT_DIR, 'database', 'schema.sql'),
  },
  session: {
    name: 'ebs.sid',
    secret: sessionSecret,
    ttlMs: intEnv('SESSION_TTL_MINUTES', 8 * 60) * 60_000,
    /** Cookies must be Secure in production (HTTPS only). */
    cookieSecure: boolEnv('SESSION_COOKIE_SECURE', isProduction),
    /**
     * 'strict' is ideal for a standalone deployment. Embedded previews and
     * cross-site iframes need 'none' + Secure (see HANDOFF.md).
     */
    sameSite: process.env.SESSION_COOKIE_SAMESITE ?? (isProduction ? 'strict' : 'lax'),
  },
  security: {
    /** CSP frame-ancestors. Kept configurable because the Arena preview embeds the app. */
    frameAncestors: (process.env.FRAME_ANCESTORS
      ?? (isProduction ? "'none'" : "'self' https://*.e2b.app"))
      .split(/\s+/)
      .filter(Boolean),
    bcryptRounds: intEnv('BCRYPT_ROUNDS', 12),
    maxFailedLogins: intEnv('MAX_FAILED_LOGINS', 5),
    lockoutMinutes: intEnv('LOCKOUT_MINUTES', 15),
    /** How long a login may stay alive (absolute lifetime, independent of activity). */
    maxSessionAgeMs: intEnv('MAX_SESSION_HOURS', 12) * 3_600_000,
  },
  logging: {
    requests: boolEnv('LOG_REQUESTS', true),
  },
  rateLimit: {
    api: {
      windowMs: intEnv('API_RATE_WINDOW_MINUTES', 5) * 60_000,
      max: intEnv('API_RATE_MAX', 600),
    },
    login: {
      windowMs: intEnv('LOGIN_RATE_WINDOW_MINUTES', 15) * 60_000,
      max: intEnv('LOGIN_RATE_MAX', 10),
    },
  },
  backups: {
    dir: process.env.BACKUP_DIR ? path.resolve(process.env.BACKUP_DIR) : path.join(ROOT_DIR, 'database', 'backups'),
  },
  uploads: {
    dir: process.env.UPLOAD_DIR ? path.resolve(process.env.UPLOAD_DIR) : path.join(ROOT_DIR, 'database', 'uploads'),
    maxFileSizeBytes: intEnv('MAX_UPLOAD_MB', 15) * 1024 * 1024,
    allowedExtensions: ['.xlsx', '.xlsm'],
    maxSheets: intEnv('MAX_UPLOAD_SHEETS', 50),
    maxRowsPerSheet: intEnv('MAX_UPLOAD_ROWS', 50_000),
  },
  currencies: ['IRR', 'USD', 'EUR', 'AED', 'GBP'],
  /** Minor-unit exponent per currency (IRR has no fractional unit). */
  currencyExponent: { IRR: 0, USD: 2, EUR: 2, AED: 2, GBP: 2 },
  defaults: {
    adminUsername: 'admin',
    adminPassword: 'Test-password1!',
    adminFullName: 'مدیر سیستم',
  },
};
