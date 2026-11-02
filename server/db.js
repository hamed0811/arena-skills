/**
 * SQLite access layer.
 *
 * Uses node:sqlite (built into Node >= 22.5), which is a synchronous,
 * single-connection, embedded engine — the same operating model as
 * better-sqlite3 but without a native build step.
 *
 * Safety rules enforced here:
 *   - foreign_keys = ON   (the schema's FKs actually do something)
 *   - journal_mode = WAL  (readers never block the writer)
 *   - synchronous = FULL  (no lost transactions on power failure)
 *   - busy_timeout        (write contention waits instead of failing)
 *   - trusted_schema = OFF (schema can't be abused as an attack surface)
 */
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { config } from './config.js';

export const DB_PATH = config.db.path;

/**
 * Open (and, if necessary, create) the database with hardened pragmas.
 * @param {string} [filePath] defaults to the configured production path
 * @param {{ readonly?: boolean, timeoutMs?: number }} [options]
 */
export function openDatabase(filePath = DB_PATH, options = {}) {
  const { readonly = false, timeoutMs = 5000 } = options;

  if (!readonly) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
  }

  const db = new DatabaseSync(filePath, { readOnly: readonly });

  db.exec('PRAGMA foreign_keys = ON');
  db.exec(`PRAGMA busy_timeout = ${Number(timeoutMs)}`);
  db.exec('PRAGMA trusted_schema = OFF');
  if (!readonly) {
    db.exec('PRAGMA journal_mode = WAL');
    db.exec('PRAGMA synchronous = FULL');
    db.exec('PRAGMA wal_autocheckpoint = 1000');
  }
  return db;
}

/**
 * Run `fn` inside a single write transaction. Rolls back on any throw.
 * BEGIN IMMEDIATE takes the write lock up-front, which avoids the classic
 * "database is locked" upgrade deadlock between two concurrent writers.
 * @template T
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {() => T} fn
 * @returns {T}
 */
export function withTransaction(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    try {
      db.exec('ROLLBACK');
    } catch {
      /* transaction already rolled back by SQLite (e.g. constraint abort) */
    }
    throw error;
  }
}

/** Run SQLite's own consistency checks. Returns a list of problems (empty = healthy). */
export function checkIntegrity(db) {
  const problems = [];
  const integrity = db.prepare('PRAGMA integrity_check').all();
  for (const row of integrity) {
    const value = Object.values(row)[0];
    if (value !== 'ok') problems.push(`integrity_check: ${value}`);
  }
  for (const row of db.prepare('PRAGMA foreign_key_check').all()) {
    problems.push(`foreign_key_check: ${JSON.stringify(row)}`);
  }
  return problems;
}

/** Small helper: timestamps in the same format as the schema defaults. */
export function nowIso() {
  return new Date().toISOString();
}

/** Load and execute the schema file (idempotent, uses CREATE ... IF NOT EXISTS). */
export function applySchema(db, schemaPath = config.db.schemaPath) {
  const sql = fs.readFileSync(schemaPath, 'utf8');
  db.exec(sql);
}
