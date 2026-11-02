/**
 * Authentication / authorisation middleware.
 *
 * Identity is never trusted from the cookie alone: the session only carries a
 * user id, and the user row is re-read on every request. That means a
 * deactivated user loses access immediately, and role changes take effect on
 * the next request instead of on the next login.
 */
import { forbidden, unauthorized } from '../lib/errors.js';

/**
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {typeof import('../config.js').config} appConfig
 */
export function loadUser(db, appConfig) {
  const findUser = db.prepare(`
    SELECT id, username, full_name, role, is_active, must_change_password,
           last_login_at, password_changed_at, created_at, updated_at
    FROM users
    WHERE id = ?
  `);

  return function loadUserMiddleware(req, res, next) {
    req.user = null;
    const userId = req.session?.userId;
    if (!Number.isSafeInteger(userId) || userId <= 0) return next();

    try {
      const user = findUser.get(userId);
      if (!user || !user.is_active) {
        // Revoked, deleted or deactivated account: destroy the session row.
        return req.session.destroy(() => next());
      }

      // Absolute session lifetime (independent of sliding cookie expiry).
      const startedAt = Number(req.session.createdAt ?? 0);
      if (startedAt > 0 && Date.now() - startedAt > appConfig.security.maxSessionAgeMs) {
        return req.session.destroy(() => next());
      }

      req.user = user;
      return next();
    } catch (error) {
      return next(error);
    }
  };
}

/** Require an authenticated, active user. */
export function requireAuth(req, res, next) {
  if (!req.user) return next(unauthorized());
  return next();
}

/**
 * Role gate. Usage: router.post('/', requireAdmin, handler)
 * @param {...string} roles
 */
export function requireRole(...roles) {
  return function roleMiddleware(req, res, next) {
    if (!req.user) return next(unauthorized());
    if (!roles.includes(req.user.role)) {
      return next(forbidden(
        `This action requires one of the following roles: ${roles.join(', ')}.`,
        'INSUFFICIENT_ROLE',
      ));
    }
    return next();
  };
}

/** Only `admin` may manage users, imports, backups and the audit trail. */
export const requireAdmin = requireRole('admin');
