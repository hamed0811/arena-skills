#!/usr/bin/env node
/**
 * Destructive database reset + seed.
 *
 *   node scripts/reset-db.js                 # recreate database/budget.db
 *   node scripts/reset-db.js --db ./tmp.db   # recreate an arbitrary file
 *   node scripts/reset-db.js --force         # required when NODE_ENV=production
 *
 * What it does:
 *   1. Deletes the existing database file (including -wal / -shm).
 *   2. Creates a fresh database from database/schema.sql.
 *   3. Seeds the admin user with a bcrypt hash (default password:
 *      "Test-password1!", override with ADMIN_PASSWORD).
 *   4. Seeds a minimal, clearly-labelled set of cost centers and categories.
 *   5. Verifies password hashing + database integrity before exiting.
 *
 * In production this refuses to run without --force, and refuses to seed the
 * well-known default password at all.
 */
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import bcrypt from 'bcrypt';
import { config } from '../server/config.js';
import { applySchema, checkIntegrity, openDatabase, withTransaction } from '../server/db.js';

const DEFAULT_COST_CENTERS = [
  { code: 'CC-100', name: 'معاونت فناوری اطلاعات', manager: 'مدیر فناوری اطلاعات', parent: null },
  { code: 'CC-110', name: 'مدیریت توسعه نرمافزار', manager: null, parent: 'CC-100' },
  { code: 'CC-120', name: 'مدیریت زیرساخت و شبکه', manager: null, parent: 'CC-100' },
  { code: 'CC-200', name: 'معاونت مالی و اداری', manager: 'مدیر مالی', parent: null },
  { code: 'CC-300', name: 'معاونت منابع انسانی', manager: null, parent: null },
];

const DEFAULT_CATEGORIES = [
  { code: '210', name: 'حقوق و دستمزد', description: 'سرفصل ۲۱۰ — هزینه‌های پرسنلی' },
  { code: '330', name: 'هزینه‌های جاری و اداری', description: 'سرفصل ۳۳۰ — هزینه‌های عمومی' },
  { code: '420', name: 'خرید تجهیزات و اموال', description: 'سرفصل ۴۲۰ — دارایی‌های سرمایه‌ای' },
  { code: '510', name: 'خدمات پشتیبانی و نگهداری', description: 'سرفصل ۵۱۰ — قراردادهای پشتیبانی' },
  { code: '620', name: 'آموزش و توسعه', description: 'سرفصل ۶۲۰ — دوره‌های آموزشی' },
];

/**
 * Reset and seed a database.
 * @param {{
 *   dbPath?: string,
 *   adminUsername?: string,
 *   adminPassword?: string,
 *   adminFullName?: string,
 *   seedReferenceData?: boolean,
 *   quiet?: boolean,
 *   productionOverride?: boolean,
 * }} [options]
 */
export async function resetDatabase(options = {}) {
  const dbPath = path.resolve(options.dbPath ?? config.db.path);
  const adminUsername = options.adminUsername ?? config.defaults.adminUsername;
  const adminPassword = options.adminPassword
    ?? process.env.ADMIN_PASSWORD
    ?? config.defaults.adminPassword;
  const adminFullName = options.adminFullName ?? config.defaults.adminFullName;
  const seedReferenceData = options.seedReferenceData ?? true;
  const productionOverride = options.productionOverride ?? false;
  const log = options.quiet ? () => {} : (...args) => console.log(...args);

  if (config.isProduction && !productionOverride) {
    throw new Error('Refusing to reset the database in production. Re-run with --force if you are absolutely sure.');
  }
  if (config.isProduction && adminPassword === config.defaults.adminPassword) {
    throw new Error('Refusing to seed the default admin password in production. Set ADMIN_PASSWORD.');
  }
  if (adminPassword.length < 12) {
    throw new Error('Admin password must be at least 12 characters long.');
  }

  // 1. Remove the old database and its WAL sidecar files.
  for (const suffix of ['', '-wal', '-shm']) {
    const target = `${dbPath}${suffix}`;
    if (fs.existsSync(target)) {
      fs.rmSync(target, { force: true });
      log(`  removed ${path.basename(target)}`);
    }
  }
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });

  // 2. Fresh schema. (Schema creation happens before any data, in its own
  //    statements, because SQLite DDL is not transactional inside WAL mode
  //    the way row writes are.)
  const db = openDatabase(dbPath);
  try {
    applySchema(db);

    // 3. Hash the admin password with bcrypt. Cost 12 ≈ 250 ms per hash, which
    //    is a deliberate brute-force barrier. The plaintext is never stored.
    const passwordHash = await bcrypt.hash(adminPassword, config.security.bcryptRounds);
    const usingDefaultPassword = adminPassword === config.defaults.adminPassword;

    // 4. Seed everything atomically.
    let adminId;
    withTransaction(db, () => {
      const insertUser = db.prepare(`
        INSERT INTO users (username, password_hash, full_name, role, is_active, must_change_password)
        VALUES (?, ?, ?, 'admin', 1, ?)
      `);
      const adminResult = insertUser.run(
        adminUsername,
        passwordHash,
        adminFullName,
        usingDefaultPassword ? 1 : 0,
      );
      adminId = Number(adminResult.lastInsertRowid);

      if (seedReferenceData) {
        const insertCostCenter = db.prepare(`
          INSERT INTO cost_centers (code, name, manager, parent_id) VALUES (?, ?, ?, ?)
        `);
        const costCenterIds = new Map();
        for (const cc of DEFAULT_COST_CENTERS) {
          const parentId = cc.parent ? costCenterIds.get(cc.parent) ?? null : null;
          const result = insertCostCenter.run(cc.code, cc.name, cc.manager, parentId);
          costCenterIds.set(cc.code, Number(result.lastInsertRowid));
        }

        const insertCategory = db.prepare(`
          INSERT INTO categories (code, name, description) VALUES (?, ?, ?)
        `);
        for (const category of DEFAULT_CATEGORIES) {
          insertCategory.run(category.code, category.name, category.description);
        }
      }

      db.prepare(`
        INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details)
        VALUES (?, 'system.db_reset', 'database', ?, ?)
      `).run(
        adminId,
        path.basename(dbPath),
        JSON.stringify({
          seededAdmin: adminUsername,
          referenceData: seedReferenceData,
          schemaVersion: 1,
          environment: config.env,
        }),
      );
    });

    // 5. Verify: the hash must verify, and SQLite must report a healthy file.
    const stored = db.prepare('SELECT username, password_hash, role FROM users WHERE id = 1').get();
    if (!stored || !(await bcrypt.compare(adminPassword, stored.password_hash))) {
      throw new Error('Post-seed verification failed: admin password hash does not verify.');
    }
    if (stored.password_hash.includes(adminPassword)) {
      throw new Error('Post-seed verification failed: password appears to be stored in plaintext.');
    }
    const problems = checkIntegrity(db);
    if (problems.length > 0) {
      throw new Error(`Post-seed database integrity check failed:\n${problems.join('\n')}`);
    }

    const counts = {};
    for (const table of ['users', 'cost_centers', 'categories', 'requests', 'budgets', 'audit_logs']) {
      counts[table] = Number(db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n);
    }

    log('');
    log('============================================================');
    log(' Database reset complete');
    log('============================================================');
    log(`  file            : ${dbPath}`);
    log(`  schema version  : 1`);
    log(`  admin username  : ${adminUsername}`);
    log(`  admin password  : ${usingDefaultPassword ? adminPassword : '(from ADMIN_PASSWORD)'}`);
    if (usingDefaultPassword) {
      log('  ⚠  DEFAULT PASSWORD — the UI forces a password change after login.');
    }
    log(`  bcrypt rounds   : ${config.security.bcryptRounds}`);
    log('  seeded rows     : ' + Object.entries(counts).map(([k, v]) => `${k}=${v}`).join(', '));
    log('  integrity       : ok');
    log('');
    log('  Next: npm start  →  http://localhost:' + config.http.port);
    log('');

    return { dbPath, adminId, adminUsername, counts, usingDefaultPassword };
  } finally {
    db.close();
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
const isDirectRun = process.argv[1]
  && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (isDirectRun) {
  const { values } = parseArgs({
    options: {
      db: { type: 'string' },
      force: { type: 'boolean', default: false },
      'admin-username': { type: 'string' },
      'admin-password': { type: 'string' },
      'no-reference-data': { type: 'boolean', default: false },
      quiet: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
    allowPositionals: false,
  });

  if (values.help) {
    console.log(`Usage: node scripts/reset-db.js [options]

  --db <path>              target database file (default: database/budget.db)
  --force                  allow running with NODE_ENV=production
  --admin-username <name>  admin username (default: admin)
  --admin-password <pw>    admin password (default: Test-password1!)
  --no-reference-data      seed the admin user only
  --quiet                  suppress output
  -h, --help               show this help
`);
    process.exit(0);
  }

  resetDatabase({
    dbPath: values.db,
    adminUsername: values['admin-username'],
    adminPassword: values['admin-password'],
    seedReferenceData: !values['no-reference-data'],
    productionOverride: values.force,
    quiet: values.quiet,
  }).catch((error) => {
    console.error('\n✖ Database reset failed: ' + error.message + '\n');
    process.exit(1);
  });
}
