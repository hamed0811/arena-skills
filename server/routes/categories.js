/**
 * Categories (سرفصل) CRUD.
 *
 * Read: any authenticated user. Write: admin only.
 * Deletes are a single-row `DELETE ... WHERE id = ?`; the database refuses to
 * remove a category that is referenced by requests, budgets, or child rows.
 */
import express from 'express';
import { withTransaction } from '../db.js';
import { recordAudit } from '../lib/audit.js';
import { categoryDto } from '../lib/dto.js';
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

const TABLE = 'categories';
const CODE_PATTERN = /^[\p{L}\p{N}._\-/]+$/u;

/** @param {{db: import('node:sqlite').DatabaseSync}} deps */
export function createCategoriesRouter({ db }) {
  const router = express.Router();
  router.use(requireAuth);

  const findById = db.prepare(`SELECT * FROM ${TABLE} WHERE id = ?`);

  // -- List ----------------------------------------------------------------
  router.get('/', (req, res) => {
    const isAdmin = req.user.role === 'admin';
    const includeInactive = isAdmin && queryBoolean(req.query, 'includeInactive', false);

    const categories = includeInactive
      ? db.prepare(`SELECT * FROM ${TABLE} ORDER BY code`).all()
      : db.prepare(`SELECT * FROM ${TABLE} WHERE is_active = 1 ORDER BY code`).all();

    res.json({ categories: categories.map(categoryDto) });
  });

  // -- Read one ------------------------------------------------------------
  router.get('/:id', (req, res) => {
    const id = fieldIdParam(req);
    const category = findById.get(id);
    if (!category) throw notFound('Category not found.', 'CATEGORY_NOT_FOUND');
    res.json({ category: categoryDto(category) });
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
    const description = fieldNullableString(body, 'description', { max: 1000 }) ?? null;
    const parentId = fieldNullableId(body, 'parentId') ?? null;

    assertValidParent(db, TABLE, parentId, null);

    const created = withTransaction(db, () => {
      const result = db.prepare(`
        INSERT INTO ${TABLE} (code, name, description, parent_id) VALUES (?, ?, ?, ?)
      `).run(code, name, description, parentId);
      const id = Number(result.lastInsertRowid);

      recordAudit(db, req, {
        action: 'category.created',
        entityType: 'category',
        entityId: id,
        details: { code, name, parentId },
      });
      return findById.get(id);
    });

    res.status(201).json({ category: categoryDto(created) });
  });

  // -- Update --------------------------------------------------------------
  router.put('/:id', requireAdmin, (req, res) => {
    const id = fieldIdParam(req);
    const body = readBody(req);
    const target = findById.get(id);
    if (!target) throw notFound('Category not found.', 'CATEGORY_NOT_FOUND');

    const code = fieldString(body, 'code', {
      required: false,
      min: 1,
      max: 32,
      pattern: CODE_PATTERN,
      patternMessage: 'Only letters, digits, dot, dash, underscore and slash are allowed.',
    }) ?? target.code;

    const name = fieldString(body, 'name', { required: false, min: 2, max: 160 }) ?? target.name;

    const descriptionRaw = fieldNullableString(body, 'description', { max: 1000 });
    const description = descriptionRaw === undefined ? target.description : descriptionRaw;

    const parentIdRaw = fieldNullableId(body, 'parentId');
    const parentId = parentIdRaw === undefined ? target.parent_id : parentIdRaw;

    const isActive = fieldBoolean(body, 'isActive') ?? Boolean(target.is_active);

    assertValidParent(db, TABLE, parentId, id);

    const updated = withTransaction(db, () => {
      db.prepare(`
        UPDATE ${TABLE}
        SET code = ?, name = ?, description = ?, parent_id = ?, is_active = ?
        WHERE id = ?
      `).run(code, name, description, parentId, isActive ? 1 : 0, id);

      recordAudit(db, req, {
        action: 'category.updated',
        entityType: 'category',
        entityId: id,
        details: {
          changes: {
            code: code !== target.code ? { from: target.code, to: code } : undefined,
            name: name !== target.name ? { from: target.name, to: name } : undefined,
            parentId: parentId !== target.parent_id ? { from: target.parent_id, to: parentId } : undefined,
            isActive: Boolean(isActive) !== Boolean(target.is_active)
              ? { from: Boolean(target.is_active), to: Boolean(isActive) }
              : undefined,
          },
        },
      });
      return findById.get(id);
    });

    res.json({ category: categoryDto(updated) });
  });

  // -- Delete --------------------------------------------------------------
  router.delete('/:id', requireAdmin, (req, res) => {
    const id = fieldIdParam(req);
    const target = findById.get(id);
    if (!target) throw notFound('Category not found.', 'CATEGORY_NOT_FOUND');

    try {
      withTransaction(db, () => {
        // Exactly one row, by primary key. Never a WHERE-less DELETE.
        db.prepare(`DELETE FROM ${TABLE} WHERE id = ?`).run(id);
        recordAudit(db, req, {
          action: 'category.deleted',
          entityType: 'category',
          entityId: id,
          details: { code: target.code, name: target.name },
        });
      });
    } catch (error) {
      if (isForeignKeyViolation(error)) {
        throw conflict(
          'CATEGORY_IN_USE',
          'This category is used by requests, budgets or child categories and cannot be deleted. Deactivate it instead.',
        );
      }
      throw error;
    }

    res.status(204).end();
  });

  return router;
}
