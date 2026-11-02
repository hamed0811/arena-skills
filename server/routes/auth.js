/**
 * Authentication routes.
 *
 *   GET  /api/auth/csrf            issue/refresh the CSRF token (also pre-login)
 *   POST /api/auth/login           bcrypt login, session regeneration
 *   POST /api/auth/logout          destroy the server-side session
 *   GET  /api/auth/me              current user + CSRF token
 *   POST /api/auth/change-password rotate password, revoke other sessions
 */
import express from 'express';
import { withTransaction } from '../db.js';
import { recordAudit } from '../lib/audit.js';
import { userDto } from '../lib/dto.js';
import {
  ApiError,
  asyncHandler,
  badRequest,
  unauthorized,
} from '../lib/errors.js';
import {
  assertPasswordPolicy,
  dummyPasswordHash,
  hashPassword,
  randomToken,
  verifyPassword,
} from '../lib/security.js';
import { fieldString, readBody } from '../lib/validate.js';
import { requireAuth } from '../middleware/auth.js';
import { destroySession, ensureCsrfToken, saveSession } from '../middleware/csrf.js';

/** @param {{db: import('node:sqlite').DatabaseSync, appConfig: typeof import('../config.js').config, loginLimiter?: import('express').RequestHandler}} deps */
export function createAuthRouter({ db, appConfig, loginLimiter }) {
  const router = express.Router();
  const rounds = appConfig.security.bcryptRounds;

  const findUserByUsername = db.prepare('SELECT * FROM users WHERE username = ?');
  const findUserById = db.prepare('SELECT * FROM users WHERE id = ?');
  const findPasswordHash = db.prepare('SELECT password_hash FROM users WHERE id = ?');

  const resetLoginCounters = db.prepare(`
    UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?
  `);
  const registerFailedAttempt = db.prepare(`
    UPDATE users
    SET failed_login_attempts = failed_login_attempts + 1,
        locked_until = ?
    WHERE id = ?
  `);
  const updatePassword = db.prepare(`
    UPDATE users
    SET password_hash = ?, password_changed_at = ?, must_change_password = 0,
        failed_login_attempts = 0, locked_until = NULL
    WHERE id = ?
  `);

  function accountLockedError(lockedUntil) {
    const retryAfter = Math.max(1, Math.ceil((Date.parse(lockedUntil) - Date.now()) / 1000));
    return new ApiError(
      423,
      'ACCOUNT_LOCKED',
      'Too many failed sign-in attempts. The account is temporarily locked.',
      undefined,
      { 'Retry-After': String(retryAfter) },
    );
  }

  /**
   * Count a failed attempt and write the audit row atomically. Locks the
   * account once the configured threshold is reached.
   */
  function recordFailedLogin(req, user, username, reason) {
    withTransaction(db, () => {
      if (user) {
        const attempts = Number(user.failed_login_attempts ?? 0) + 1;
        const lockedUntil = attempts >= appConfig.security.maxFailedLogins
          ? new Date(Date.now() + appConfig.security.lockoutMinutes * 60_000).toISOString()
          : null;
        // Keep an existing lock if it is still in the future.
        const effectiveLock = lockedUntil
          ?? (user.locked_until && Date.parse(user.locked_until) > Date.now() ? user.locked_until : null);
        registerFailedAttempt.run(effectiveLock, user.id);
      }
      // The actor is anonymous: entity_id records the targeted account.
      recordAudit(db, req, {
        action: 'auth.login_failed',
        entityType: 'user',
        entityId: user?.id ?? null,
        userId: null,
        details: { username, reason },
      });
    });
  }

  // -- CSRF bootstrap ------------------------------------------------------
  router.get('/csrf', asyncHandler(async (req, res) => {
    const csrfToken = ensureCsrfToken(req);
    await saveSession(req);
    res.json({ csrfToken });
  }));

  // -- Login ---------------------------------------------------------------
  const loginChain = [
    ...(loginLimiter ? [loginLimiter] : []),
    asyncHandler(async (req, res) => {
      const body = readBody(req);
      const username = fieldString(body, 'username', {
        min: 3,
        max: 64,
        pattern: /^[A-Za-z0-9._-]+$/,
        patternMessage: 'Only letters, digits, dot, underscore and dash are allowed.',
      });
      const password = fieldString(body, 'password', { min: 1, max: 200, trim: false });

      const user = findUserByUsername.get(username);
      // Always perform one bcrypt comparison, even for unknown usernames, so
      // response time does not reveal whether the account exists.
      const hashToCheck = user?.password_hash ?? dummyPasswordHash(rounds);
      const passwordOk = await verifyPassword(password, hashToCheck);

      if (!user || !passwordOk || !user.is_active) {
        const reason = !user ? 'unknown_user' : (!passwordOk ? 'bad_password' : 'inactive_user');
        recordFailedLogin(req, user, username, reason);
        throw new ApiError(401, 'INVALID_CREDENTIALS', 'Username or password is incorrect.');
      }

      if (user.locked_until && Date.parse(user.locked_until) > Date.now()) {
        throw accountLockedError(user.locked_until);
      }

      // Successful authentication: clear counters + audit, in one transaction.
      withTransaction(db, () => {
        resetLoginCounters.run(new Date().toISOString(), user.id);
        recordAudit(db, req, {
          action: 'auth.login_success',
          entityType: 'user',
          entityId: user.id,
          userId: user.id,
          details: { username: user.username },
        });
      });

      // Session fixation defence: throw away the pre-login session entirely.
      await new Promise((resolve, reject) => {
        req.session.regenerate((error) => (error ? reject(error) : resolve()));
      });
      req.session.userId = user.id;
      req.session.csrfToken = randomToken(32);
      req.session.createdAt = Date.now();
      req.session.cookie.maxAge = appConfig.session.ttlMs;
      await saveSession(req);

      const fresh = findUserById.get(user.id);
      res.json({
        user: userDto(fresh),
        csrfToken: req.session.csrfToken,
        expiresInSeconds: Math.floor(appConfig.session.ttlMs / 1000),
      });
    }),
  ];
  router.post('/login', ...loginChain);

  // -- Logout --------------------------------------------------------------
  router.post('/logout', requireAuth, asyncHandler(async (req, res) => {
    const { id: userId, username } = req.user;
    await destroySession(req, res, appConfig.session.name);
    recordAudit(db, req, {
      action: 'auth.logout',
      entityType: 'user',
      entityId: userId,
      userId,
      details: { username },
    });
    res.status(204).end();
  }));

  // -- Current user --------------------------------------------------------
  router.get('/me', requireAuth, asyncHandler(async (req, res) => {
    const csrfToken = ensureCsrfToken(req);
    await saveSession(req);
    res.json({
      user: userDto(req.user),
      csrfToken,
      sessionStartedAt: req.session.createdAt ?? null,
      passwordChangedAt: req.user.password_changed_at ?? null,
    });
  }));

  // -- Change own password -------------------------------------------------
  router.post('/change-password', requireAuth, asyncHandler(async (req, res) => {
    const body = readBody(req);
    const currentPassword = fieldString(body, 'currentPassword', { min: 1, max: 200, trim: false });
    const newPassword = fieldString(body, 'newPassword', { min: 12, max: 128, trim: false });

    assertPasswordPolicy(newPassword, {
      username: req.user.username,
      fullName: req.user.full_name,
    });

    const row = findPasswordHash.get(req.user.id);
    if (!row) throw unauthorized();

    if (!(await verifyPassword(currentPassword, row.password_hash))) {
      throw new ApiError(400, 'INVALID_CURRENT_PASSWORD', 'The current password is incorrect.', [
        { field: 'currentPassword', message: 'Incorrect password.' },
      ]);
    }
    if (await verifyPassword(newPassword, row.password_hash)) {
      throw badRequest('The new password must be different from the current one.', [
        { field: 'newPassword', message: 'Choose a password you have not used here before.' },
      ]);
    }

    const newHash = await hashPassword(newPassword, rounds);
    const currentSid = req.sessionID;

    withTransaction(db, () => {
      updatePassword.run(newHash, new Date().toISOString(), req.user.id);
      // All other devices are signed out; the current session is rotated below.
      db.prepare('DELETE FROM sessions WHERE user_id = ? AND sid <> ?').run(req.user.id, currentSid);
      recordAudit(db, req, {
        action: 'auth.password_changed',
        entityType: 'user',
        entityId: req.user.id,
        details: { revokedOtherSessions: true },
      });
    });

    // Rotate the session id again so the post-change session is new.
    await new Promise((resolve, reject) => {
      req.session.regenerate((error) => (error ? reject(error) : resolve()));
    });
    req.session.userId = req.user.id;
    req.session.csrfToken = randomToken(32);
    req.session.createdAt = Date.now();
    req.session.cookie.maxAge = appConfig.session.ttlMs;
    await saveSession(req);

    res.json({
      csrfToken: req.session.csrfToken,
      mustChangePassword: false,
      message: 'Password changed successfully. Other sessions were signed out.',
    });
  }));

  return router;
}
