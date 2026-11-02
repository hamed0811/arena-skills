/**
 * SQLite access layer.
 *
 * Uses node:sqlite (built into Node >= 22.5), a synchronous embedded engine.
 * WAL and FULL synchronous mode protect concurrent reads and durable writes.
 */
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { config, ROOT_DIR } from './config.js';
export const DB_PATH = config.db.path;
export function openDatabase(filePath = DB_PATH, options = {}) {
  const { readonly = false, timeoutMs = 5000 } = options;
  if (!readonly) fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const db = new DatabaseSync(filePath, { readOnly: readonly });
  db.exec('PRAGMA foreign_keys = ON');
  db.exec(`PRAGMA busy_timeout = ${Number(timeoutMs)}`);
  db.exec('PRAGMA trusted_schema = OFF');
  if (!readonly) { db.exec('PRAGMA journal_mode = WAL'); db.exec('PRAGMA synchronous = FULL'); db.exec('PRAGMA wal_autocheckpoint = 1000'); }
  return db;
}
export function withTransaction(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try { const result = fn(); db.exec('COMMIT'); return result; }
  catch (error) { try { db.exec('ROLLBACK'); } catch {} throw error; }
}
export function checkIntegrity(db) {
  const problems=[];
  for (const row of db.prepare('PRAGMA integrity_check').all()) { const value=Object.values(row)[0]; if(value!=='ok') problems.push(`integrity_check: ${value}`); }
  for (const row of db.prepare('PRAGMA foreign_key_check').all()) problems.push(`foreign_key_check: ${JSON.stringify(row)}`);
  return problems;
}
export function nowIso(){return new Date().toISOString();}
export function applySchema(db,schemaPath=config.db.schemaPath){
  db.exec(fs.readFileSync(schemaPath,'utf8'));
  const importSchema=path.join(ROOT_DIR,'database','import-schema.sql');
  if(fs.existsSync(importSchema)) db.exec(fs.readFileSync(importSchema,'utf8'));
}
