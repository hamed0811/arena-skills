/**
 * Read-only audit trail (admin only).
 * The table itself is append-only; this router deliberately exposes no
 * write endpoints.
 */
import express from 'express';
import { auditLogDto } from '../lib/dto.js';
import { badRequest } from '../lib/errors.js';
import { pagination } from '../lib/validate.js';
import { requireAdmin, requireAuth } from '../middleware/auth.js';

/** @param {{db: import('node:sqlite').DatabaseSync}} deps */
export function createAuditLogsRouter({ db }) {
  const router = express.Router();
  router.use(requireAuth, requireAdmin);

  router.get('/', (req, res) => {
    const { page, pageSize, offset } = pagination(req.query, { defaultPageSize: 50, maxPageSize: 200 });
    const conditions = [];
    const params = [];

    if (typeof req.query.action === 'string' && req.query.action.trim()) {
      conditions.push('a.action = ?');
      params.push(req.query.action.trim().slice(0, 64));
    }
    if (typeof req.query.entityType === 'string' && req.query.entityType.trim()) {
      conditions.push('a.entity_type = ?');
      params.push(req.query.entityType.trim().slice(0, 40));
    }
    if (typeof req.query.userId === 'string' && /^\d+$/.test(req.query.userId)) {
      conditions.push('a.user_id = ?');
      params.push(Number(req.query.userId));
    }
    if (typeof req.query.from === 'string' && req.query.from) {
      if (Number.isNaN(Date.parse(req.query.from))) {
        throw badRequest('Invalid query parameter.', [{ field: 'from', message: 'Must be an ISO date.' }]);
      }
      conditions.push('a.created_at >= ?');
      params.push(new Date(req.query.from).toISOString());
    }
    if (typeof req.query.to === 'string' && req.query.to) {
      if (Number.isNaN(Date.parse(req.query.to))) {
        throw badRequest('Invalid query parameter.', [{ field: 'to', message: 'Must be an ISO date.' }]);
      }
      conditions.push('a.created_at <= ?');
      params.push(new Date(req.query.to).toISOString());
    }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const total = Number(db.prepare(`SELECT COUNT(*) AS n FROM audit_logs a ${where}`).get(...params).n);
    const rows = db.prepare(`
      SELECT a.*, u.username
      FROM audit_logs a
      LEFT JOIN users u ON u.id = a.user_id
      ${where}
      ORDER BY a.id DESC
      LIMIT ? OFFSET ?
    `).all(...params, pageSize, offset);

    res.json({
      logs: rows.map(auditLogDto),
      page,
      pageSize,
      total,
      totalPages: Math.max(1, Math.ceil(total / pageSize)),
    });
  });

  return router;
}
