/**
 * Budget requests: submit / edit / approve / reject / cancel / delete.
 *
 * Workflow
 *   submitted ──approve──> approved
 *       │  └────reject───> rejected
 *       ├────cancel──────> cancelled
 *       └──(admin) delete
 *
 * Rules enforced here *and* in the schema:
 *   - an approval/rejection always records who and when;
 *   - nobody can approve or reject their own request (separation of duties);
 *   - approved requests are financial records: they can never be deleted;
 *   - operators only see their own requests, viewers only approved ones.
 */
import express from 'express';
import { withTransaction } from '../db.js';
import { recordAudit } from '../lib/audit.js';
import { requestDto } from '../lib/dto.js';
import {
  ApiError,
  asyncHandler,
  badRequest,
  conflict,
  forbidden,
  notFound,
} from '../lib/errors.js';
import {
  escapeLike,
  fieldEnum,
  fieldIdParam,
  fieldInteger,
  fieldNullableString,
  fieldString,
  pagination,
  readBody,
} from '../lib/validate.js';
import { requireAdmin, requireAuth, requireRole } from '../middleware/auth.js';

const STATUSES = ['draft', 'submitted', 'approved', 'rejected', 'cancelled'];
const EDITABLE_STATUSES = ['draft', 'submitted'];
const DELETABLE_STATUSES = ['draft', 'rejected', 'cancelled'];
const SORTS = {
  created_at: 'r.created_at',
  updated_at: 'r.updated_at',
  amount_minor: 'r.amount_minor',
  fiscal_year: 'r.fiscal_year',
  request_no: 'r.request_no',
  status: 'r.status',
};

/** @param {{db: import('node:sqlite').DatabaseSync, appConfig: typeof import('../config.js').config}} deps */
export function createRequestsRouter({ db, appConfig }) {
  const router = express.Router();
  router.use(requireAuth);

  const findById = db.prepare('SELECT * FROM requests WHERE id = ?');
  const findFullById = db.prepare('SELECT * FROM v_requests_full WHERE id = ?');
  const findCostCenter = db.prepare('SELECT id, is_active FROM cost_centers WHERE id = ?');
  const findCategory = db.prepare('SELECT id, is_active FROM categories WHERE id = ?');

  function getFullOr404(id) {
    const row = findFullById.get(id);
    if (!row) throw notFound('Request not found.', 'REQUEST_NOT_FOUND');
    return row;
  }

  function assertCanView(user, row) {
    if (user.role === 'admin') return;
    if (row.requester_id === user.id) return;
    if (user.role === 'viewer' && row.status === 'approved') return;
    throw forbidden('You do not have access to this request.', 'REQUEST_ACCESS_DENIED');
  }

  function assertMasterDataResolvable(costCenterId, categoryId) {
    const costCenter = findCostCenter.get(costCenterId);
    if (!costCenter) {
      throw badRequest('Validation failed.', [{ field: 'costCenterId', message: 'Cost center does not exist.' }]);
    }
    if (!costCenter.is_active) {
      throw badRequest('Validation failed.', [{ field: 'costCenterId', message: 'Cost center is inactive.' }]);
    }
    const category = findCategory.get(categoryId);
    if (!category) {
      throw badRequest('Validation failed.', [{ field: 'categoryId', message: 'Category does not exist.' }]);
    }
    if (!category.is_active) {
      throw badRequest('Validation failed.', [{ field: 'categoryId', message: 'Category is inactive.' }]);
    }
  }

  /**
   * Sequential, gap-free request number per fiscal year: REQ-1404-00042.
   * Called inside a BEGIN IMMEDIATE transaction, so two concurrent writers
   * cannot allocate the same number.
   */
  function nextRequestNumber(fiscalYear) {
    const prefix = `REQ-${fiscalYear}-`;
    const row = db.prepare(`
      SELECT COALESCE(MAX(CAST(substr(request_no, ?) AS INTEGER)), 0) AS max_seq
      FROM requests
      WHERE request_no LIKE ?
    `).get(prefix.length + 1, `${prefix}%`);
    return `${prefix}${String(Number(row.max_seq) + 1).padStart(5, '0')}`;
  }

  function parseCreateFields(body) {
    const title = fieldString(body, 'title', { min: 2, max: 200 });
    const description = fieldNullableString(body, 'description', { max: 2000 }) ?? null;
    const costCenterId = fieldInteger(body, 'costCenterId', { min: 1 });
    const categoryId = fieldInteger(body, 'categoryId', { min: 1 });
    const fiscalYear = fieldInteger(body, 'fiscalYear', { min: 1300, max: 2200 });
    const currency = fieldEnum(body, 'currency', appConfig.currencies, { required: false }) ?? 'IRR';
    const amountMinor = fieldInteger(body, 'amountMinor', { min: 1 });

    return { title, description, costCenterId, categoryId, fiscalYear, currency, amountMinor };
  }

  // -- List (scoped by role) ------------------------------------------------
  router.get('/', (req, res) => {
    if (!['admin', 'operator', 'viewer'].includes(req.user.role)) {
      throw forbidden('Unknown role.', 'INSUFFICIENT_ROLE');
    }

    const { page, pageSize, offset } = pagination(req.query, { defaultPageSize: 25, maxPageSize: 100 });
    const conditions = [];
    const params = [];

    if (req.user.role === 'operator') {
      conditions.push('r.requester_id = ?');
      params.push(req.user.id);
    } else if (req.user.role === 'viewer') {
      conditions.push("r.status = 'approved'");
    }

    if (req.query.status !== undefined) {
      const status = fieldEnum(req.query, 'status', STATUSES);
      conditions.push('r.status = ?');
      params.push(status);
    }
    if (req.query.fiscalYear !== undefined) {
      const fiscalYear = fieldInteger(req.query, 'fiscalYear', { min: 1300, max: 2200 });
      conditions.push('r.fiscal_year = ?');
      params.push(fiscalYear);
    }
    if (req.query.currency !== undefined) {
      const currency = fieldEnum(req.query, 'currency', appConfig.currencies);
      conditions.push('r.currency = ?');
      params.push(currency);
    }
    if (req.query.costCenterId !== undefined) {
      const costCenterId = fieldInteger(req.query, 'costCenterId', { min: 1 });
      conditions.push('r.cost_center_id = ?');
      params.push(costCenterId);
    }
    if (req.query.categoryId !== undefined) {
      const categoryId = fieldInteger(req.query, 'categoryId', { min: 1 });
      conditions.push('r.category_id = ?');
      params.push(categoryId);
    }
    if (typeof req.query.q === 'string' && req.query.q.trim()) {
      const term = `%${escapeLike(req.query.q.trim().slice(0, 100))}%`;
      conditions.push("(r.request_no LIKE ? ESCAPE '\\' OR r.title LIKE ? ESCAPE '\\')");
      params.push(term, term);
    }

    const sortKey = typeof req.query.sort === 'string' ? req.query.sort : 'created_at';
    const sortColumn = SORTS[sortKey];
    if (!sortColumn) {
      throw badRequest('Invalid query parameter.', [{ field: 'sort', message: `Must be one of: ${Object.keys(SORTS).join(', ')}.` }]);
    }
    const direction = typeof req.query.direction === 'string' ? req.query.direction.toLowerCase() : 'desc';
    if (!['asc', 'desc'].includes(direction)) {
      throw badRequest('Invalid query parameter.', [{ field: 'direction', message: 'Must be asc or desc.' }]);
    }

    const whereSql = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    const total = Number(db.prepare(`SELECT COUNT(*) AS n FROM requests r ${whereSql}`).get(...params).n);
    const rows = db.prepare(`
      SELECT r.* FROM v_requests_full r
      ${whereSql}
      ORDER BY ${sortColumn} ${direction.toUpperCase()}, r.id DESC
      LIMIT ? OFFSET ?
    `).all(...params, pageSize, offset);

    res.json({
      requests: rows.map(requestDto),
      page,
      pageSize,
      total,
      totalPages: Math.max(1, Math.ceil(total / pageSize)),
    });
  });

  // -- Read one ------------------------------------------------------------
  router.get('/:id', (req, res) => {
    const id = fieldIdParam(req);
    const row = getFullOr404(id);
    assertCanView(req.user, row);
    res.json({ request: requestDto(row) });
  });

  // -- Submit --------------------------------------------------------------
  router.post('/', requireRole('admin', 'operator'), asyncHandler(async (req, res) => {
    const body = readBody(req);
    const fields = parseCreateFields(body);
    assertMasterDataResolvable(fields.costCenterId, fields.categoryId);

    const created = withTransaction(db, () => {
      const requestNo = nextRequestNumber(fields.fiscalYear);
      const result = db.prepare(`
        INSERT INTO requests
          (request_no, title, description, requester_id, cost_center_id, category_id,
           fiscal_year, currency, amount_minor, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'submitted')
      `).run(
        requestNo,
        fields.title,
        fields.description,
        req.user.id,
        fields.costCenterId,
        fields.categoryId,
        fields.fiscalYear,
        fields.currency,
        fields.amountMinor,
      );

      const id = Number(result.lastInsertRowid);
      recordAudit(db, req, {
        action: 'request.created',
        entityType: 'request',
        entityId: id,
        details: {
          requestNo,
          amountMinor: fields.amountMinor,
          currency: fields.currency,
          fiscalYear: fields.fiscalYear,
          costCenterId: fields.costCenterId,
          categoryId: fields.categoryId,
        },
      });
      return getFullOr404(id);
    });

    res.status(201).json({ request: requestDto(created) });
  }));

  // -- Edit (owner while submitted/draft, or admin) ------------------------
  router.put('/:id', asyncHandler(async (req, res) => {
    const id = fieldIdParam(req);
    const body = readBody(req);
    const target = findById.get(id);
    if (!target) throw notFound('Request not found.', 'REQUEST_NOT_FOUND');

    const isOwner = target.requester_id === req.user.id;
    if (req.user.role !== 'admin' && !isOwner) {
      throw forbidden('You can only edit your own requests.', 'REQUEST_ACCESS_DENIED');
    }
    if (!['admin', 'operator'].includes(req.user.role)) {
      throw forbidden('Viewers cannot edit requests.', 'INSUFFICIENT_ROLE');
    }
    if (!EDITABLE_STATUSES.includes(target.status)) {
      throw conflict('REQUEST_NOT_EDITABLE', 'Only requests that have not been decided can be edited.');
    }

    const title = fieldString(body, 'title', { required: false, min: 2, max: 200 }) ?? target.title;
    const descriptionRaw = fieldNullableString(body, 'description', { max: 2000 });
    const description = descriptionRaw === undefined ? target.description : descriptionRaw;
    const costCenterId = fieldInteger(body, 'costCenterId', { required: false, min: 1 }) ?? target.cost_center_id;
    const categoryId = fieldInteger(body, 'categoryId', { required: false, min: 1 }) ?? target.category_id;
    const fiscalYear = fieldInteger(body, 'fiscalYear', { required: false, min: 1300, max: 2200 }) ?? target.fiscal_year;
    const currency = fieldEnum(body, 'currency', appConfig.currencies, { required: false }) ?? target.currency;
    const amountMinor = fieldInteger(body, 'amountMinor', { required: false, min: 1 }) ?? target.amount_minor;

    assertMasterDataResolvable(costCenterId, categoryId);

    const updated = withTransaction(db, () => {
      const result = db.prepare(`
        UPDATE requests
        SET title = ?, description = ?, cost_center_id = ?, category_id = ?,
            fiscal_year = ?, currency = ?, amount_minor = ?
        WHERE id = ? AND status IN ('draft', 'submitted')
      `).run(
        title, description, costCenterId, categoryId, fiscalYear, currency, amountMinor, id,
      );

      if (result.changes === 0) {
        throw conflict('REQUEST_NOT_EDITABLE', 'The request was decided by someone else in the meantime.');
      }

      recordAudit(db, req, {
        action: 'request.updated',
        entityType: 'request',
        entityId: id,
        details: {
          requestNo: target.request_no,
          changes: {
            title: title !== target.title ? { from: target.title, to: title } : undefined,
            amountMinor: amountMinor !== target.amount_minor
              ? { from: target.amount_minor, to: amountMinor }
              : undefined,
            currency: currency !== target.currency ? { from: target.currency, to: currency } : undefined,
            fiscalYear: fiscalYear !== target.fiscal_year ? { from: target.fiscal_year, to: fiscalYear } : undefined,
            costCenterId: costCenterId !== target.cost_center_id
              ? { from: target.cost_center_id, to: costCenterId }
              : undefined,
            categoryId: categoryId !== target.category_id
              ? { from: target.category_id, to: categoryId }
              : undefined,
          },
        },
      });
      return getFullOr404(id);
    });

    res.json({ request: requestDto(updated) });
  }));

  // -- Decisions -----------------------------------------------------------
  function decide(req, res, { status, requireNote }) {
    const id = fieldIdParam(req);
    const body = readBody(req);
    const target = findById.get(id);
    if (!target) throw notFound('Request not found.', 'REQUEST_NOT_FOUND');

    if (target.status !== 'submitted') {
      throw conflict('INVALID_STATUS', `Only submitted requests can be ${status}. This request is "${target.status}".`);
    }
    if (target.requester_id === req.user.id) {
      throw forbidden('You cannot decide on your own request.', 'SELF_DECISION_FORBIDDEN');
    }

    const noteRaw = fieldNullableString(body, 'note', { max: 1000 });
    const note = noteRaw ?? null;
    if (requireNote && (!note || note.trim().length < 3)) {
      throw badRequest('A reason is required for this decision.', [
        { field: 'note', message: 'Please provide at least 3 characters.' },
      ]);
    }

    const updated = withTransaction(db, () => {
      const result = db.prepare(`
        UPDATE requests
        SET status = ?, decided_by = ?, decided_at = ?, decision_note = ?
        WHERE id = ? AND status = 'submitted'
      `).run(status, req.user.id, new Date().toISOString(), note, id);

      if (result.changes === 0) {
        throw new ApiError(409, 'INVALID_STATUS', 'The request was already decided by someone else.');
      }

      recordAudit(db, req, {
        action: `request.${status}`,
        entityType: 'request',
        entityId: id,
        details: { requestNo: target.request_no, note },
      });
      return getFullOr404(id);
    });

    res.json({ request: requestDto(updated) });
  }

  router.post('/:id/approve', requireAdmin, asyncHandler(async (req, res) => {
    decide(req, res, { status: 'approved', requireNote: false });
  }));

  router.post('/:id/reject', requireAdmin, asyncHandler(async (req, res) => {
    decide(req, res, { status: 'rejected', requireNote: true });
  }));

  // -- Cancel (owner or admin) ---------------------------------------------
  router.post('/:id/cancel', asyncHandler(async (req, res) => {
    const id = fieldIdParam(req);
    const target = findById.get(id);
    if (!target) throw notFound('Request not found.', 'REQUEST_NOT_FOUND');

    const isOwner = target.requester_id === req.user.id;
    if (req.user.role !== 'admin' && !isOwner) {
      throw forbidden('You can only cancel your own requests.', 'REQUEST_ACCESS_DENIED');
    }
    if (!EDITABLE_STATUSES.includes(target.status)) {
      throw conflict('INVALID_STATUS', 'Only requests that have not been decided can be cancelled.');
    }

    const body = readBody(req);
    const noteRaw = fieldNullableString(body, 'note', { max: 1000 });

    const updated = withTransaction(db, () => {
      const result = db.prepare(`
        UPDATE requests SET status = 'cancelled', decision_note = ?
        WHERE id = ? AND status IN ('draft', 'submitted')
      `).run(noteRaw ?? null, id);

      if (result.changes === 0) {
        throw conflict('INVALID_STATUS', 'The request changed status in the meantime.');
      }

      recordAudit(db, req, {
        action: 'request.cancelled',
        entityType: 'request',
        entityId: id,
        details: { requestNo: target.request_no, note: noteRaw ?? null },
      });
      return getFullOr404(id);
    });

    res.json({ request: requestDto(updated) });
  }));

  // -- Delete (admin, never for approved requests) -------------------------
  router.delete('/:id', requireAdmin, (req, res) => {
    const id = fieldIdParam(req);
    const target = findById.get(id);
    if (!target) throw notFound('Request not found.', 'REQUEST_NOT_FOUND');

    if (!DELETABLE_STATUSES.includes(target.status)) {
      throw conflict(
        'REQUEST_NOT_DELETABLE',
        'Approved requests are financial records and cannot be deleted. Cancel or reject instead.',
      );
    }

    withTransaction(db, () => {
      const result = db.prepare(`
        DELETE FROM requests WHERE id = ? AND status IN ('draft', 'rejected', 'cancelled')
      `).run(id);

      if (result.changes === 0) {
        throw conflict('REQUEST_NOT_DELETABLE', 'The request changed status and can no longer be deleted.');
      }

      recordAudit(db, req, {
        action: 'request.deleted',
        entityType: 'request',
        entityId: id,
        details: {
          requestNo: target.request_no,
          status: target.status,
          amountMinor: target.amount_minor,
          currency: target.currency,
        },
      });
    });

    res.status(204).end();
  });

  return router;
}
