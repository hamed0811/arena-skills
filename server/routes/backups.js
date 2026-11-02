/**
 * Database backups — admin only (contains password hashes and every record).
 *
 * A backup is a consistent snapshot produced by SQLite's `VACUUM INTO`, which
 * is safe while the application is serving traffic (unlike copying the file).
 * Restore is deliberately NOT exposed over HTTP: it is an operator action,
 * documented in HANDOFF.md, precisely so a compromised admin session cannot
 * replace the production database with an arbitrary file.
 */
import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import { recordAudit } from '../lib/audit.js';
import { asyncHandler, badRequest, notFound } from '../lib/errors.js';
import { requireAdmin, requireAuth } from '../middleware/auth.js';

const BACKUP_NAME = /^budget-[A-Za-z0-9._-]+\.db$/;

/** @param {{db: import('node:sqlite').DatabaseSync, appConfig: typeof import('../config.js').config}} deps */
export function createBackupsRouter({ db, appConfig }) {
  const router = express.Router();
  router.use(requireAuth, requireAdmin);

  const backupDir = appConfig.backups.dir;

  function assertSafeName(rawName) {
    const name = String(rawName ?? '');
    if (!BACKUP_NAME.test(name) || name.includes('..') || path.basename(name) !== name) {
      throw badRequest('Invalid backup file name.', [{ field: 'name', message: 'Invalid file name.' }]);
    }
    const fullPath = path.resolve(backupDir, name);
    if (!fullPath.startsWith(path.resolve(backupDir) + path.sep)) {
      throw badRequest('Invalid backup file name.', [{ field: 'name', message: 'Invalid file name.' }]);
    }
    return { name, fullPath };
  }

  // -- Create a consistent snapshot ---------------------------------------
  router.post('/', asyncHandler(async (req, res) => {
    fs.mkdirSync(backupDir, { recursive: true });

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    let name = `budget-${timestamp}.db`;
    let fullPath = path.join(backupDir, name);
    let suffix = 1;
    while (fs.existsSync(fullPath)) {
      name = `budget-${timestamp}-${suffix}.db`;
      fullPath = path.join(backupDir, name);
      suffix += 1;
    }

    // VACUUM INTO writes a transactionally consistent copy; the target name is
    // generated here, never taken from the request.
    db.prepare('VACUUM INTO ?').run(fullPath);

    const stat = fs.statSync(fullPath);
    recordAudit(db, req, {
      action: 'backup.created',
      entityType: 'backup',
      entityId: name,
      details: { sizeBytes: stat.size },
    });

    res.status(201).json({
      backup: {
        name,
        sizeBytes: stat.size,
        createdAt: new Date(stat.mtimeMs).toISOString(),
      },
    });
  }));

  // -- List ----------------------------------------------------------------
  router.get('/', (req, res) => {
    fs.mkdirSync(backupDir, { recursive: true });
    const backups = fs.readdirSync(backupDir, { withFileTypes: true })
      .filter((entry) => entry.isFile() && BACKUP_NAME.test(entry.name))
      .map((entry) => {
        const stat = fs.statSync(path.join(backupDir, entry.name));
        return {
          name: entry.name,
          sizeBytes: stat.size,
          createdAt: new Date(stat.mtimeMs).toISOString(),
        };
      })
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));

    res.json({ backups });
  });

  // -- Download ------------------------------------------------------------
  router.get('/:name', (req, res) => {
    const { name, fullPath } = assertSafeName(req.params.name);
    if (!fs.existsSync(fullPath)) throw notFound('Backup not found.', 'BACKUP_NOT_FOUND');

    recordAudit(db, req, {
      action: 'backup.downloaded',
      entityType: 'backup',
      entityId: name,
    });

    res.setHeader('Content-Type', 'application/vnd.sqlite3');
    res.setHeader('Cache-Control', 'no-store');
    res.download(fullPath, name);
  });

  return router;
}
