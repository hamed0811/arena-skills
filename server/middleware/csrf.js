/**
 * CSRF protection (synchronizer token + Fetch Metadata + Origin check).
 *
 * Token lifecycle:
 *   - GET /api/auth/csrf issues a session-bound random token (pre-login too).
 *   - The client must echo it in the `X-CSRF-Token` header on every unsafe
 *     request (POST/PUT/PATCH/DELETE).
 *   - The token is rotated on login (session regeneration) and available from
 *     the login response and GET /api/auth/me.
 *
 * Defence in depth: a request is also rejected when Fetch Metadata says it
 * came from another site, or when the Origin header's host differs from ours.
 */
import { forbidden } from '../lib/errors.js';
import { randomToken, timingSafeEqualStrings } from '../lib/security.js';

export const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/** Generate the token once per session. */
export function ensureCsrfToken(req) {
  if (!req.session) throw new Error('ensureCsrfToken() requires a session');
  if (typeof req.session.csrfToken !== 'string' || req.session.csrfToken.length < 32) {
    req.session.csrfToken = randomToken(32);
  }
  return req.session.csrfToken;
}

/** Persist the session before responding (needed after regenerate/login). */
export function saveSession(req) {
  return new Promise((resolve, reject) => {
    if (!req.session) return reject(new Error('No session to save'));
    return req.session.save((error) => (error ? reject(error) : resolve()));
  });
}

/** Destroy the session and clear the cookie. */
export function destroySession(req, res, cookieName) {
  return new Promise((resolve) => {
    if (!req.session) return resolve();
    return req.session.destroy(() => {
      if (res && cookieName) res.clearCookie(cookieName, { path: '/' });
      return resolve();
    });
  });
}

/**
 * Reject unsafe requests that do not carry a valid CSRF token.
 * @type {import('express').RequestHandler}
 */
export function verifyCsrf(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();

  const fetchSite = req.get('sec-fetch-site');
  if (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none') {
    return next(forbidden('Cross-site request blocked.', 'CSRF_ORIGIN_MISMATCH'));
  }

  const origin = req.get('origin');
  if (origin) {
    let originHost;
    try {
      originHost = new URL(origin).host.toLowerCase();
    } catch {
      return next(forbidden('Invalid Origin header.', 'CSRF_ORIGIN_MISMATCH'));
    }
    const requestHost = String(req.get('host') ?? '').toLowerCase();
    if (originHost !== requestHost) {
      return next(forbidden('Cross-origin request blocked.', 'CSRF_ORIGIN_MISMATCH'));
    }
  }

  const provided = req.get('x-csrf-token') ?? '';
  const expected = req.session?.csrfToken;
  if (typeof expected !== 'string' || !timingSafeEqualStrings(provided, expected)) {
    return next(forbidden('CSRF token is missing or invalid. Reload the page and try again.', 'CSRF_TOKEN_INVALID'));
  }

  return next();
}
