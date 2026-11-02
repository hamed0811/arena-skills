/**
 * User management — admin only (`requireAdmin` is mounted by the API router).
 *
 * Financial-system invariants enforced here:
 *   - you cannot demote or deactivate yourself;
 *   - the last active administrator cannot be removed;
 *   - deactivation revokes every session immediately;
 *   - users are hard-deleted only when no history references them, otherwise
 *     they are deactivated (audit history is never rewritten).
 */
import express from 'express';
import { withTransaction } from '../db.js';
import { recordAudit } from '../lib/audit.js';
import { userDto } from '../lib/dto.js';
import { asyncHandler, forbidden, isForeignKeyViolation, notFound } from '../lib/errors.js';
import { assertPasswordPolicy, hashPassword } from '../lib/security.js';
import {
  fieldBoolean,
  fieldEnum,
  fieldIdParam,
  fieldString,
  queryBoolean,
  readBody,
} from '../lib/validate.js';
import { requireAdmin, requireAuth } from '../middleware/auth.js';

const ROLES = ['admin', 'operator', 'viewer'];

const USER_COLUMNS = `
  id, username, full_name, role, is_active, must_change_password,
  last_login_at, password_changed_at, created_at, updated_at
`;

/** @param {{db: import('node:sqlite').DatabaseSync, appConfig: typeof import('../config.js').config}} deps */
export function createUsersRouter({ db, appConfig }) {
  const router = express.Router();
  const rounds = appConfig.security.bcryptRounds;

  router.use(requireAuth, requireAdmin);

  const findById = db.prepare(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?`);
  const countOtherActiveAdmins = db.prepare(`
    SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND is_active = 1 AND id <> ?
  `);

  // -- List ----------------------------------------------------------------
  router.get('/', (req, res) => {
    const includeInactive = queryBoolean(req.query, 'includeInactive', true);
    const q = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 100) : '';

    const conditions = [];
    const params = [];
    if (!includeInactive) conditions.push('is_active = 1');
    if (q) {
      conditions.push('(username LIKE ? OR full_name LIKE ?)');
      params.push(`%${q}%`, `%${q}%`);
    }
    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    const users = db
      .prepare(`SELECT ${USER_COLUMNS} FROM users ${where} ORDER BY is_active DESC, role, username`)
      .all(...params);

    res.json({ users: users.map(userDto) });
  });

  // -- Create --------------------------------------------------------------
  router.post('/', asyncHandler(async (req, res) => {
    const body = readBody(req);
    const username = fieldString(body, 'username', {
      min: 3,
      max: 64,
      pattern: /^[A-Za-z0-9._-]+$/,
      patternMessage: 'Only letters, digits, dot, underscore and dash are allowed.',
    });
    const fullName = fieldString(body, 'fullName', { min: 2, max: 120 });
    const role = fieldEnum(body, 'role', ROLES, { required: false }) ?? 'operator';
    const password = fieldString(body, 'password', { min: 12, max: 128, trim: false });

    assertPasswordPolicy(password, { username, fullName });

    // Hash outside the transaction: bcrypt deliberately takes ~250 ms and we
    // must not hold the SQLite write lock for that long.
    const passwordHash = await hashPassword(password, rounds);

    const created = withTransaction(db, () => {
      const result = db.prepare(`
        INSERT INTO users (username, password_hash, full_name, role, is_active, must_change_password)
        VALUES (?, ?, ?, ?, 1, 1)
      `).run(username, passwordHash, fullName, role);

      const id = Number(result.lastInsertRowid);
      recordAudit(db, req, {
        action: 'user.created',
        entityType: 'user',
        entityId: id,
        details: { username, role },
      });
      return findById.get(id);
    });

    res.status(201).json({ user: userDto(created) });
  }));

  // -- Read one ------------------------------------------------------------
  router.get('/:id', (req, res) => {
    const id = fieldIdParam(req);
    const user = findById.get(id);
    if (!user) throw notFound('User not found.', 'USER_NOT_FOUND');
    res.json({ user: userDto(user) });
  });

  // -- Update --------------------------------------------------------------
  router.put('/:id', (req, res) => {
    const id = fieldIdParam(req);
    const body = readBody(req);
    const target = findById.get(id);
    if (!target) throw notFound('User not found.', 'USER_NOT_FOUND');

    const fullName = fieldString(body, 'fullName', { required: false, min: 2, max: 120 }) ?? target.full_name;
    const role = fieldEnum(body, 'role', ROLES, { required: false }) ?? target.role;
    const isActive = fieldBoolean(body, 'isActive') ?? Boolean(target.is_active);

    if (id === req.user.id) {
      if (role !== target.role) {
        throw forbidden('You cannot change your own role.', 'SELF_ROLE_CHANGE_FORBIDDEN');
      }
      if (!isActive) {
        throw forbidden('You cannot deactivate your own account.', 'SELF_DEACTIVATION_FORBIDDEN');
      }
    }

    const removesAnActiveAdmin = target.role === 'admin' && target.is_active && (role !== 'admin' || !isActive);
    if (removesAnActiveAdmin && Number(countOtherActiveAdmins.get(id).n) === 0) {
      throw forbidden('At least one active administrator must remain.', 'LAST_ADMIN');
    }

    const updated = withTransaction(db, () => {
      db.prepare(`
        UPDATE users SET full_name = ?, role = ?, is_active = ? WHERE id = ?
      `).run(fullName, role, isActive ? 1 : 0, id);

      if (!isActive) {
        db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
      }

      recordAudit(db, req, {
        action: 'user.updated',
        entityType: 'user',
        entityId: id,
        details: {
          username: target.username,
          changes: {
            fullName: fullName !== target.full_name ? { from: target.full_name, to: fullName } : undefined,
            role: role !== target.role ? { from: target.role, to: role } : undefined,
            isActive: Boolean(isActive) !== Boolean(target.is_active)
              ? { from: Boolean(target.is_active), to: Boolean(isActive) }
              : undefined,
          },
        },
      });
      return findById.get(id);
    });

    res.json({ user: userDto(updated) });
  });

  // -- Admin password reset ------------------------------------------------
  router.post('/:id/reset-password', asyncHandler(async (req, res) => {
    const id = fieldIdParam(req);
    const body = readBody(req);
    const target = findById.get(id);
    if (!target) throw notFound('User not found.', 'USER_NOT_FOUND');

    const newPassword = fieldString(body, 'newPassword', { min: 12, max: 128, trim: false });
    assertPasswordPolicy(newPassword, { username: target.username, fullName: target.full_name });

    const passwordHash = await hashPassword(newPassword, rounds);

    withTransaction(db, () => {
      db.prepare(`
        UPDATE users
        SET password_hash = ?, password_changed_at = ?, must_change_password = 1,
            failed_login_attempts = 0, locked_until = NULL
        WHERE id = ?
      `).run(passwordHash, new Date().toISOString(), id);

      if (id === req.user.id) {
        // Keep the admin's own current session; sign out every other device.
        db.prepare('DELETE FROM sessions WHERE user_id = ? AND sid <> ?').run(id, req.sessionID);
      } else {
        db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
      }

      recordAudit(db, req, {
        action: 'user.password_reset',
        entityType: 'user',
        entityId: id,
        details: { username: target.username, sessionsRevoked: true },
      });
    });

    res.json({
      user: userDto(findById.get(id)),
      message: 'Password reset. The user must choose a new password at next sign-in.',
    });
  }));

  // -- Delete / deactivate -------------------------------------------------
  router.delete('/:id', (req, res) => {
    const id = fieldIdParam(req);
    const target = findById.get(id);
    if (!target) throw notFound('User not found.', 'USER_NOT_FOUND');

    if (id === req.user.id) {
      throw forbidden('You cannot delete your own account.', 'SELF_DELETE_FORBIDDEN');
    }
    if (target.role === 'admin' && target.is_active && Number(countOtherActiveAdmins.get(id).n) === 0) {
      throw forbidden('At least one active administrator must remain.', 'LAST_ADMIN');
    }

    const mode = withTransaction(db, () => {
      db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);

      let outcome = 'deleted';
      try {
        // Safe by construction: a single row, identified by primary key.
        db.prepare('DELETE FROM users WHERE id = ?').run(id);
      } catch (error) {
        if (isForeignKeyViolation(error)) {
          // Referenced by requests / budgets / audit history -> preserve history.
          db.prepare('UPDATE users SET is_active = 0 WHERE id = ?').run(id);
          outcome = 'deactivated';
        } else {
          throw error;
        }
      }

      recordAudit(db, req, {
        action: outcome === 'deleted' ? 'user.deleted' : 'user.deactivated',
        entityType: 'user',
        entityId: id,
        details: { username: target.username, mode: outcome },
      });
      return outcome;
    });

    res.json({ id, mode, isActive: mode === 'deactivated' ? false : null });
  });

  return router;
}
