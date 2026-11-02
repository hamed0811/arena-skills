/**
 * Cost centers (مرکز هزینه / معاونت) CRUD.
 *
 * Read: any authenticated user. Write: admin only.
 * Deletes are a single-row `DELETE ... WHERE id = ?`; the database refuses to
 * remove a cost center that is referenced by requests, budgets, or children.
 */
import express from 'express';
import { withTransaction } from '../db.js';
import { recordAudit } from '../lib/audit.js';
import { costCenterDto } from '../lib/dto.js';
import { conflict, isForeignKeyViolation, notFound } from '../lib/errors.js';
import { assertValidParent } from '../lib/hierarchy.js';
import {
  fieldBoolean,
  fieldIdParam,
  fieldNullableId,
  fieldNullableString,
  fieldString,
  queryBoolean,
  readBody,
} from '../lib/validate.js';
import { requireAdmin, requireAuth } from '../middleware/auth.js';

const TABLE = 'cost_centers';
const CODE_PATTERN = /^[\p{L}\p{N}._\-/]+$/u;

/** @param {{db: import('node:sqlite').DatabaseSync}} deps */
export function createCostCentersRouter({ db }) {
  const router = express.Router();
  router.use(requireAuth);

  const findById = db.prepare(`SELECT * FROM ${TABLE} WHERE id = ?`);

  // -- List ----------------------------------------------------------------
  router.get('/', (req, res) => {
    const isAdmin = req.user.role === 'admin';
    const includeInactive = isAdmin && queryBoolean(req.query, 'includeInactive', false);

    const rows = includeInactive
      ? db.prepare(`SELECT * FROM ${TABLE} ORDER BY code`).all()
      : db.prepare(`SELECT * FROM ${TABLE} WHERE is_active = 1 ORDER BY code`).all();

    res.json({ costCenters: rows.map(costCenterDto) });
  });

  // -- Read one ------------------------------------------------------------
  router.get('/:id', (req, res) => {
    const id = fieldIdParam(req);
    const row = findById.get(id);
    if (!row) throw notFound('Cost center not found.', 'COST_CENTER_NOT_FOUND');
    res.json({ costCenter: costCenterDto(row) });
  });

  // -- Create --------------------------------------------------------------
  router.post('/', requireAdmin, (req, res) => {
    const body = readBody(req);
    const code = fieldString(body, 'code', {
      min: 1,
      max: 32,
      pattern: CODE_PATTERN,
      patternMessage: 'Only letters, digits, dot, dash, underscore and slash are allowed.',
    });
    const name = fieldString(body, 'name', { min: 2, max: 160 });
    const manager = fieldNullableString(body, 'manager', { max: 120 }) ?? null;
    const parentId = fieldNullableId(body, 'parentId') ?? null;

    assertValidParent(db, TABLE, parentId, null);

    const created = withTransaction(db, () => {
      const result = db.prepare(`
        INSERT INTO ${TABLE} (code, name, manager, parent_id) VALUES (?, ?, ?, ?)
      `).run(code, name, manager, parentId);
      const id = Number(result.lastInsertRowid);

      recordAudit(db, req, {
        action: 'cost_center.created',
        entityType: 'cost_center',
        entityId: id,
        details: { code, name, parentId },
      });
      return findById.get(id);
    });

    res.status(201).json({ costCenter: costCenterDto(created) });
  });

  // -- Update --------------------------------------------------------------
  router.put('/:id', requireAdmin, (req, res) => {
    const id = fieldIdParam(req);
    const body = readBody(req);
    const target = findById.get(id);
    if (!target) throw notFound('Cost center not found.', 'COST_CENTER_NOT_FOUND');

    const code = fieldString(body, 'code', {
      required: false,
      min: 1,
      max: 32,
      pattern: CODE_PATTERN,
      patternMessage: 'Only letters, digits, dot, dash, underscore and slash are allowed.',
    }) ?? target.code;

    const name = fieldString(body, 'name', { required: false, min: 2, max: 160 }) ?? target.name;

    const managerRaw = fieldNullableString(body, 'manager', { max: 120 });
    const manager = managerRaw === undefined ? target.manager : managerRaw;

    const parentIdRaw = fieldNullableId(body, 'parentId');
    const parentId = parentIdRaw === undefined ? target.parent_id : parentIdRaw;

    const isActive = fieldBoolean(body, 'isActive') ?? Boolean(target.is_active);

    assertValidParent(db, TABLE, parentId, id);

    const updated = withTransaction(db, () => {
      db.prepare(`
        UPDATE ${TABLE}
        SET code = ?, name = ?, manager = ?, parent_id = ?, is_active = ?
        WHERE id = ?
      `).run(code, name, manager, parentId, isActive ? 1 : 0, id);

      recordAudit(db, req, {
        action: 'cost_center.updated',
        entityType: 'cost_center',
        entityId: id,
        details: {
          changes: {
            code: code !== target.code ? { from: target.code, to: code } : undefined,
            name: name !== target.name ? { from: target.name, to: name } : undefined,
            manager: manager !== target.manager ? { from: target.manager, to: manager } : undefined,
            parentId: parentId !== target.parent_id ? { from: target.parent_id, to: parentId } : undefined,
            isActive: Boolean(isActive) !== Boolean(target.is_active)
              ? { from: Boolean(target.is_active), to: Boolean(isActive) }
              : undefined,
          },
        },
      });
      return findById.get(id);
    });

    res.json({ costCenter: costCenterDto(updated) });
  });

  // -- Delete --------------------------------------------------------------
  router.delete('/:id', requireAdmin, (req, res) => {
    const id = fieldIdParam(req);
    const target = findById.get(id);
    if (!target) throw notFound('Cost center not found.', 'COST_CENTER_NOT_FOUND');

    try {
      withTransaction(db, () => {
        db.prepare(`DELETE FROM ${TABLE} WHERE id = ?`).run(id);
        recordAudit(db, req, {
          action: 'cost_center.deleted',
          entityType: 'cost_center',
          entityId: id,
          details: { code: target.code, name: target.name },
        });
      });
    } catch (error) {
      if (isForeignKeyViolation(error)) {
        throw conflict(
          'COST_CENTER_IN_USE',
          'This cost center is used by requests, budgets or child cost centers and cannot be deleted. Deactivate it instead.',
        );
      }
      throw error;
    }

    res.status(204).end();
  });

  return router;
}
