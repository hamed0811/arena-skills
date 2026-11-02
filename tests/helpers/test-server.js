/**
 * Test harness: boots the real Express app against a throwaway SQLite file and
 * provides a cookie-aware HTTP client (no supertest dependency).
 */
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../../server/app.js';
import { config } from '../../server/config.js';
import { openDatabase } from '../../server/db.js';
import { resetDatabase } from '../../scripts/reset-db.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/** @param {{adminPassword?: string}} [options] */
export async function startTestServer(options = {}) {
  const adminPassword = options.adminPassword ?? 'Test-password1!';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebs-api-'));
  const dbPath = path.join(dir, 'test.db');

  await resetDatabase({ dbPath, adminPassword, quiet: true });

  const db = openDatabase(dbPath);
  const appConfig = {
    ...config,
    backups: { dir: path.join(dir, 'backups') },
    isProduction: false,
    session: {
      ...config.session,
      secret: 'test-session-secret-0123456789abcdef0123456789abcdef',
      cookieSecure: false,
      sameSite: 'lax',
    },
    security: {
      ...config.security,
      bcryptRounds: 10,
      maxFailedLogins: 5,
      lockoutMinutes: 1,
      maxSessionAgeMs: 12 * 60 * 60 * 1000,
    },
    rateLimit: {
      api: { windowMs: 60_000, max: 100_000 },
      login: { windowMs: 60_000, max: 100_000 },
    },
    logging: { requests: false },
  };

  const app = createApp({ db, appConfig });
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  return {
    app,
    db,
    dbPath,
    baseUrl: `http://127.0.0.1:${port}`,
    async close() {
      await new Promise((resolve) => server.close(resolve));
      app.locals.close();
      db.close();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

/**
 * Minimal browser-like client: keeps cookies, remembers the CSRF token, and
 * serialises JSON bodies.
 * @param {string} baseUrl
 */
export function createClient(baseUrl) {
  /** @type {Map<string, string>} */
  const cookies = new Map();
  let csrfToken = null;

  async function request(method, requestPath, options = {}) {
    const { body, headers = {}, useCsrf = true, rawBody } = options;
    const requestHeaders = { ...headers };

    if (body !== undefined) requestHeaders['content-type'] ??= 'application/json';
    if (cookies.size > 0) {
      requestHeaders.cookie = [...cookies.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
    }
    if (useCsrf && csrfToken && !SAFE_METHODS.has(method)) {
      requestHeaders['x-csrf-token'] = csrfToken;
    }

    const response = await fetch(baseUrl + requestPath, {
      method,
      headers: requestHeaders,
      body: rawBody !== undefined ? rawBody : (body === undefined ? undefined : JSON.stringify(body)),
      redirect: 'manual',
    });

    const setCookies = typeof response.headers.getSetCookie === 'function'
      ? response.headers.getSetCookie()
      : [];

    for (const cookie of setCookies) {
      const [pair, ...attributes] = cookie.split(';');
      const separator = pair.indexOf('=');
      if (separator < 0) continue;
      const name = pair.slice(0, separator).trim();
      const value = pair.slice(separator + 1).trim();
      const expired = attributes.some((attribute) => {
        const normalized = attribute.trim().toLowerCase();
        return normalized === 'max-age=0'
          || /expires=thu, 01 jan 1970/.test(normalized)
          || (normalized.startsWith('expires=') && Date.parse(normalized.slice(8)) <= Date.now());
      });
      if (!value || expired) cookies.delete(name);
      else cookies.set(name, value);
    }

    const text = await response.text();
    let json = null;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        json = null;
      }
    }

    return { status: response.status, headers: response.headers, body: json, text, cookies };
  }

  return {
    request,
    get: (p, options) => request('GET', p, options),
    post: (p, body, options) => request('POST', p, { ...options, body }),
    put: (p, body, options) => request('PUT', p, { ...options, body }),
    delete: (p, options) => request('DELETE', p, options),

    get csrfToken() {
      return csrfToken;
    },
    set csrfToken(value) {
      csrfToken = value;
    },
    get cookieHeader() {
      return [...cookies.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
    },

    async fetchCsrf() {
      const response = await request('GET', '/api/auth/csrf');
      if (response.status === 200) csrfToken = response.body?.csrfToken ?? null;
      return csrfToken;
    },

    async login(username, password) {
      // Always obtain a fresh token for the current (possibly new) session —
      // mirrors the login page, which calls /api/auth/csrf on every load.
      await this.fetchCsrf();
      const response = await request('POST', '/api/auth/login', { body: { username, password } });
      if (response.status === 200 && response.body?.csrfToken) {
        csrfToken = response.body.csrfToken;
      }
      return response;
    },

    async logout() {
      const response = await request('POST', '/api/auth/logout');
      csrfToken = null;
      return response;
    },
  };
}
