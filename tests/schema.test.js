/**
 * Phase 1 verification: the schema must be structurally sound, the seeded
 * admin must use bcrypt, and the database itself must enforce the invariants
 * the application relies on (FKs, money rules, append-only audit log).
 *
 * Run: npm test
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test, { after, before } from 'node:test';
import bcrypt from 'bcrypt';
import { applySchema, checkIntegrity, openDatabase, withTransaction } from '../server/db.js';
import { resetDatabase } from '../scripts/reset-db.js';

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebs-schema-'));
const dbPath = path.join(tmpDir, 'test.db');
const ADMIN_PASSWORD = 'Test-password1!';

let db;
let adminId;
let costCenterId;
let categoryId;

before(async () => {
  await resetDatabase({ dbPath, adminPassword: ADMIN_PASSWORD, quiet: true });
  db = openDatabase(dbPath);
  adminId = Number(db.prepare("SELECT id FROM users WHERE username = 'admin'").get().id);
  costCenterId = Number(db.prepare("SELECT id FROM cost_centers WHERE code = 'CC-100'").get().id);
  categoryId = Number(db.prepare("SELECT id FROM categories WHERE code = '330'").get().id);
});

after(() => {
  db?.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function insertRequest(overrides = {}) {
  const row = {
    request_no: `REQ-TEST-${Math.random().toString(36).slice(2, 10)}`,
    title: 'درخواست آزمایشی',
    requester_id: adminId,
    cost_center_id: costCenterId,
    category_id: categoryId,
    fiscal_year: 1404,
    currency: 'IRR',
    amount_minor: 1_000_000,
    status: 'submitted',
    ...overrides,
  };
  return db.prepare(`
    INSERT INTO requests
      (request_no, title, requester_id, cost_center_id, category_id,
       fiscal_year, currency, amount_minor, status, decided_by, decided_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    row.request_no, row.title, row.requester_id, row.cost_center_id, row.category_id,
    row.fiscal_year, row.currency, row.amount_minor, row.status,
    row.decided_by ?? null, row.decided_at ?? null,
  );
}

test('all required tables, indexes and the read view exist', () => {
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((r) => r.name);
  for (const required of ['users', 'cost_centers', 'categories', 'requests', 'budgets', 'audit_logs', 'sessions', 'meta']) {
    assert.ok(tables.includes(required), `missing table: ${required}`);
  }
  const views = db.prepare("SELECT name FROM sqlite_master WHERE type = 'view'").all().map((r) => r.name);
  assert.ok(views.includes('v_requests_full'));

  // Every FK column must have a real foreign key, not just a comment.
  const fkCount = (table) => db.prepare(`PRAGMA foreign_key_list(${table})`).all().length;
  assert.equal(fkCount('requests'), 4, 'requests must FK to requester, cost_center, category and decided_by');
  assert.equal(fkCount('budgets'), 3);
  assert.equal(fkCount('audit_logs'), 1);
  assert.equal(fkCount('cost_centers'), 1);
  assert.equal(fkCount('categories'), 1);
  assert.equal(fkCount('sessions'), 1);
});

test('seeded admin password is bcrypt-hashed and verifies', async () => {
  const admin = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
  assert.equal(admin.role, 'admin');
  assert.equal(admin.is_active, 1);
  assert.equal(admin.must_change_password, 1);
  assert.match(admin.password_hash, /^\$2[aby]\$\d{2}\$/);
  assert.ok(!admin.password_hash.includes(ADMIN_PASSWORD));
  assert.equal(await bcrypt.compare(ADMIN_PASSWORD, admin.password_hash), true);
  assert.equal(await bcrypt.compare('wrong-password', admin.password_hash), false);
});

test('usernames are unique case-insensitively', () => {
  assert.throws(
    () => db.prepare("INSERT INTO users (username, password_hash, full_name) VALUES ('ADMIN', ?, 'x')")
      .run('$2b$12$' + 'a'.repeat(53)),
    /UNIQUE|constraint/i,
  );
});

test('foreign keys reject orphan requests and protect master data', () => {
  assert.throws(
    () => insertRequest({ cost_center_id: 999_999 }),
    /FOREIGN KEY/i,
  );
  const inserted = insertRequest();
  assert.ok(inserted.changes === 1);
  assert.throws(
    () => db.prepare('DELETE FROM cost_centers WHERE id = ?').run(costCenterId),
    /FOREIGN KEY/i,
  );
  assert.throws(
    () => db.prepare('DELETE FROM users WHERE id = ?').run(adminId),
    /FOREIGN KEY/i,
  );
});

test('money rules are enforced by CHECK constraints', () => {
  assert.throws(() => insertRequest({ amount_minor: -1 }), /CHECK/i);
  assert.throws(() => insertRequest({ amount_minor: 0 }), /CHECK/i);
  assert.throws(() => insertRequest({ currency: 'BTC' }), /CHECK/i);
  assert.throws(() => insertRequest({ currency: 'usd' }), /CHECK/i);
  assert.throws(() => insertRequest({ fiscal_year: 12 }), /CHECK/i);
});

test('a decision must be attributable to another user', () => {
  assert.throws(
    () => insertRequest({ status: 'approved' }),
    /CHECK/i,
  );
  assert.throws(
    () => insertRequest({ status: 'approved', decided_by: adminId, decided_at: new Date().toISOString() }),
    /CHECK/i,
  );

  const operatorId = Number(db.prepare(`
    INSERT INTO users (username, password_hash, full_name, role)
    VALUES ('operator1', ?, 'کاربر عملیات', 'operator')
  `).run('$2b$12$' + 'b'.repeat(53)).lastInsertRowid);

  const ok = insertRequest({
    status: 'approved',
    decided_by: operatorId,
    decided_at: new Date().toISOString(),
  });
  assert.equal(ok.changes, 1);
});

test('audit_logs is append-only at the database level', () => {
  const id = Number(db.prepare(`
    INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details)
    VALUES (?, 'test.action', 'test', '1', '{}')
  `).run(adminId).lastInsertRowid);

  assert.throws(
    () => db.prepare("UPDATE audit_logs SET action = 'tampered' WHERE id = ?").run(id),
    /append-only/i,
  );
  assert.throws(
    () => db.prepare('DELETE FROM audit_logs WHERE id = ?').run(id),
    /append-only/i,
  );
});

test('budgets are unique per year / cost center / category / currency', () => {
  const insert = db.prepare(`
    INSERT INTO budgets (fiscal_year, cost_center_id, category_id, currency, amount_minor, created_by)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  insert.run(1404, costCenterId, categoryId, 'IRR', 5_000_000, adminId);
  assert.throws(
    () => insert.run(1404, costCenterId, categoryId, 'IRR', 6_000_000, adminId),
    /UNIQUE/i,
  );
  // Same envelope in a different currency is legitimately a different budget.
  insert.run(1404, costCenterId, categoryId, 'USD', 100_00, adminId);
});

test('updated_at is maintained by the trigger', () => {
  const before = db.prepare('SELECT updated_at FROM categories WHERE id = ?').get(categoryId).updated_at;
  db.prepare('UPDATE categories SET name = ? WHERE id = ?').run('هزینه‌های جاری و اداری', categoryId);
  const after = db.prepare('SELECT updated_at FROM categories WHERE id = ?').get(categoryId).updated_at;
  assert.ok(after >= before);
});

test('schema can be re-applied safely and the file is consistent', () => {
  applySchema(db); // idempotent
  assert.deepEqual(checkIntegrity(db), []);
  const version = db.prepare("SELECT value FROM meta WHERE key = 'schema_version'").get();
  assert.equal(version.value, '1');
});

test('transactions roll back completely on error', () => {
  const countBefore = Number(db.prepare('SELECT COUNT(*) AS n FROM cost_centers').get().n);
  assert.throws(() => withTransaction(db, () => {
    db.prepare("INSERT INTO cost_centers (code, name) VALUES ('CC-TX', 'مرکز موقت')").run();
    throw new Error('boom');
  }), /boom/);
  const countAfter = Number(db.prepare('SELECT COUNT(*) AS n FROM cost_centers').get().n);
  assert.equal(countAfter, countBefore);
});
