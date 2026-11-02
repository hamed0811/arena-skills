/**
 * Phase 2 verification — exercises the real HTTP stack:
 * security headers/CSP, session auth, CSRF, RBAC, CRUD, workflow rules,
 * audit trail, and the "no WHERE-less DELETE" policy.
 *
 * Run: npm test
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test, { after, before } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createClient, startTestServer } from './helpers/test-server.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

let server;
let db;
let adminClient;
let operatorClient;
let viewerClient;

let adminId;
let costCenterId;
let categoryId;
let operatorId;
let viewerId;

// Created during the request-workflow test and reused later.
let approvedRequestId;
let rejectedRequestId;
let cancelledRequestId;

function expectError(response, status, code) {
  assert.equal(
    response.status,
    status,
    `expected HTTP ${status}, got ${response.status}: ${response.text}`,
  );
  if (code) {
    assert.equal(response.body?.error?.code, code, `expected error code ${code}, got ${response.text}`);
  }
}

function auditCount(action) {
  return Number(db.prepare('SELECT COUNT(*) AS n FROM audit_logs WHERE action = ?').get(action).n);
}

before(async () => {
  server = await startTestServer();
  db = server.db;

  adminId = Number(db.prepare("SELECT id FROM users WHERE username = 'admin'").get().id);
  costCenterId = Number(db.prepare("SELECT id FROM cost_centers WHERE code = 'CC-100'").get().id);
  categoryId = Number(db.prepare("SELECT id FROM categories WHERE code = '330'").get().id);
});

after(async () => {
  await server?.close();
});

// ---------------------------------------------------------------------------
// 1. Headers / CSP
// ---------------------------------------------------------------------------
test('security headers enforce a strict CSP with script-src-attr none', async () => {
  const client = createClient(server.baseUrl);
  const health = await client.get('/api/health');

  assert.equal(health.status, 200);
  assert.equal(health.body.status, 'ok');
  assert.equal(health.body.database, 'ok');

  const csp = health.headers.get('content-security-policy') ?? '';
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /script-src 'self'/);
  assert.match(csp, /script-src-attr 'none'/);
  assert.match(csp, /object-src 'none'/);
  assert.match(csp, /base-uri 'none'/);
  assert.match(csp, /frame-ancestors/);

  assert.equal(health.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(health.headers.get('x-powered-by'), null);
  assert.equal(health.headers.get('x-frame-options'), null, 'CSP frame-ancestors replaces XFO');
  assert.match(health.headers.get('permissions-policy') ?? '', /camera=\(\)/);
  assert.match(health.headers.get('cache-control') ?? '', /no-store/);
  assert.ok(health.headers.get('x-request-id'));
});

// ---------------------------------------------------------------------------
// 2. Authentication, CSRF bootstrap, session storage
// ---------------------------------------------------------------------------
test('login requires a CSRF token, rejects bad credentials and creates a DB session', async () => {
  const client = createClient(server.baseUrl);

  expectError(await client.get('/api/requests'), 401, 'UNAUTHENTICATED');
  expectError(await client.get('/api/users'), 401, 'UNAUTHENTICATED');

  // No CSRF token yet -> login is blocked.
  expectError(
    await client.request('POST', '/api/auth/login', { body: { username: 'admin', password: 'x' } }),
    403,
    'CSRF_TOKEN_INVALID',
  );

  await client.fetchCsrf();
  assert.ok(client.csrfToken.length >= 32, 'token is long enough');
  assert.match(client.cookieHeader, /ebs\.sid=/);

  const failed = await client.login('admin', 'definitely-not-the-password');
  expectError(failed, 401, 'INVALID_CREDENTIALS');
  assert.ok(auditCount('auth.login_failed') >= 1);

  const preLoginToken = client.csrfToken;
  const login = await client.login('admin', 'Test-password1!');
  assert.equal(login.status, 200, login.text);
  assert.equal(login.body.user.username, 'admin');
  assert.equal(login.body.user.role, 'admin');
  assert.equal(login.body.user.passwordHash, undefined);
  assert.ok(login.body.csrfToken);
  assert.notEqual(login.body.csrfToken, preLoginToken, 'CSRF token rotates on login');

  const setCookie = login.headers.getSetCookie().join(';');
  assert.match(setCookie, /HttpOnly/i);
  assert.match(setCookie, /SameSite=Lax/i);

  // Server-side session row exists.
  const sessionCount = Number(db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n);
  assert.ok(sessionCount >= 1);

  const me = await client.get('/api/auth/me');
  assert.equal(me.status, 200);
  assert.equal(me.body.user.id, adminId);
  assert.ok(me.body.csrfToken);

  adminClient = client;
});

test('accounts lock after repeated failed logins', async () => {
  const created = await adminClient.post('/api/users', {
    username: 'lockme',
    fullName: 'کاربر قفل',
    role: 'operator',
    password: 'Lock-me-Pass1!',
  });
  assert.equal(created.status, 201, created.text);

  const client = createClient(server.baseUrl);
  await client.fetchCsrf();

  for (let attempt = 1; attempt <= 5; attempt += 1) {
    const response = await client.login('lockme', 'Wrong-pass1!');
    expectError(response, 401, 'INVALID_CREDENTIALS');
  }

  const locked = await client.login('lockme', 'Lock-me-Pass1!');
  expectError(locked, 423, 'ACCOUNT_LOCKED');
  assert.ok(Number(locked.headers.get('retry-after')) > 0);

  const row = db.prepare("SELECT failed_login_attempts, locked_until FROM users WHERE username = 'lockme'").get();
  assert.equal(Number(row.failed_login_attempts), 5);
  assert.ok(row.locked_until);
});

// ---------------------------------------------------------------------------
// 3. User administration + RBAC
// ---------------------------------------------------------------------------
test('admin manages users; operator is denied admin-only areas', async () => {
  const operator = await adminClient.post('/api/users', {
    username: 'operator1',
    fullName: 'کاربر عملیات',
    role: 'operator',
    password: 'Operator-Pass1!',
  });
  assert.equal(operator.status, 201, operator.text);
  assert.equal(operator.body.user.role, 'operator');
  assert.equal(operator.body.user.mustChangePassword, true);
  assert.equal(operator.body.user.passwordHash, undefined);
  operatorId = operator.body.user.id;

  const viewer = await adminClient.post('/api/users', {
    username: 'viewer1',
    fullName: 'ناظر گزارش‌ها',
    role: 'viewer',
    password: 'Viewer-Pass1!',
  });
  assert.equal(viewer.status, 201, viewer.text);
  viewerId = viewer.body.user.id;

  expectError(
    await adminClient.post('/api/users', {
      username: 'operator1',
      fullName: 'تکراری',
      role: 'operator',
      password: 'Duplicate-Pass1!',
    }),
    409,
    'DUPLICATE_VALUE',
  );

  expectError(
    await adminClient.post('/api/users', {
      username: 'weakling',
      fullName: 'رمز ضعیف',
      role: 'operator',
      password: 'short',
    }),
    400,
    'VALIDATION_ERROR',
  );

  expectError(
    await adminClient.post('/api/users', {
      username: 'bad name!',
      fullName: 'نام نامعتبر',
      role: 'operator',
      password: 'Valid-Password1!',
    }),
    400,
    'VALIDATION_ERROR',
  );

  operatorClient = createClient(server.baseUrl);
  const operatorLogin = await operatorClient.login('operator1', 'Operator-Pass1!');
  assert.equal(operatorLogin.status, 200, operatorLogin.text);
  assert.equal(operatorLogin.body.user.role, 'operator');

  viewerClient = createClient(server.baseUrl);
  const viewerLogin = await viewerClient.login('viewer1', 'Viewer-Pass1!');
  assert.equal(viewerLogin.status, 200, viewerLogin.text);

  // Operator: read reference data, but no admin capabilities.
  assert.equal((await operatorClient.get('/api/categories')).status, 200);
  assert.equal((await operatorClient.get('/api/cost-centers')).status, 200);

  expectError(await operatorClient.get('/api/users'), 403, 'INSUFFICIENT_ROLE');
  expectError(await operatorClient.get('/api/audit-logs'), 403, 'INSUFFICIENT_ROLE');
  expectError(
    await operatorClient.post('/api/categories', { code: '777', name: 'دستکاری' }),
    403,
    'INSUFFICIENT_ROLE',
  );
  expectError(
    await operatorClient.delete(`/api/cost-centers/${costCenterId}`),
    403,
    'INSUFFICIENT_ROLE',
  );
  expectError(
    await operatorClient.post('/api/users', {
      username: 'sneaky',
      fullName: 'کاربر غیرمجاز',
      role: 'admin',
      password: 'Sneaky-Pass1!',
    }),
    403,
    'INSUFFICIENT_ROLE',
  );

  // The admin cannot lock themselves out.
  expectError(
    await adminClient.put(`/api/users/${adminId}`, { isActive: false }),
    403,
    'SELF_DEACTIVATION_FORBIDDEN',
  );
  expectError(
    await adminClient.put(`/api/users/${adminId}`, { role: 'operator' }),
    403,
    'SELF_ROLE_CHANGE_FORBIDDEN',
  );
});

// ---------------------------------------------------------------------------
// 4. Master data CRUD + FK protection + hierarchy validation
// ---------------------------------------------------------------------------
test('categories and cost centers support CRUD with FK-safe deletes', async () => {
  const createdCategory = await adminClient.post('/api/categories', {
    code: '999',
    name: 'سرفصل آزمایشی فاز دو',
    description: 'برای تست',
  });
  assert.equal(createdCategory.status, 201, createdCategory.text);
  const temporaryCategoryId = createdCategory.body.category.id;

  const updatedCategory = await adminClient.put(`/api/categories/${temporaryCategoryId}`, {
    name: 'سرفصل آزمایشی ویرایش‌شده',
    description: null,
  });
  assert.equal(updatedCategory.status, 200, updatedCategory.text);
  assert.equal(updatedCategory.body.category.name, 'سرفصل آزمایشی ویرایش‌شده');
  assert.equal(updatedCategory.body.category.description, null);

  assert.equal((await adminClient.delete(`/api/categories/${temporaryCategoryId}`)).status, 204);
  expectError(
    await adminClient.get(`/api/categories/${temporaryCategoryId}`),
    404,
    'CATEGORY_NOT_FOUND',
  );

  // Hierarchy: create child, reject self-parenting and bogus parents.
  const childCenter = await adminClient.post('/api/cost-centers', {
    code: 'CC-900',
    name: 'مرکز هزینه آزمایشی',
    parentId: costCenterId,
    manager: 'مدیر آزمایشی',
  });
  assert.equal(childCenter.status, 201, childCenter.text);
  const childId = childCenter.body.costCenter.id;
  assert.equal(childCenter.body.costCenter.parentId, costCenterId);

  expectError(
    await adminClient.put(`/api/cost-centers/${childId}`, { parentId: childId }),
    400,
    'VALIDATION_ERROR',
  );
  expectError(
    await adminClient.post('/api/cost-centers', {
      code: 'CC-901',
      name: 'مرکز با والد ناموجود',
      parentId: 999_999,
    }),
    400,
    'VALIDATION_ERROR',
  );

  // Deleting a parent with children is refused by the database.
  expectError(
    await adminClient.delete(`/api/cost-centers/${costCenterId}`),
    409,
    'COST_CENTER_IN_USE',
  );
  assert.equal((await adminClient.delete(`/api/cost-centers/${childId}`)).status, 204);

  const missing = await adminClient.delete('/api/categories/999999');
  expectError(missing, 404, 'CATEGORY_NOT_FOUND');
});

// ---------------------------------------------------------------------------
// 5. Request workflow + role scoping + separation of duties
// ---------------------------------------------------------------------------
test('requests: submit, scope, approve, reject, cancel, delete', async () => {
  const first = await operatorClient.post('/api/requests', {
    title: 'خرید تجهیزات شبکه',
    description: 'تجهیزات آزمایشگاهی',
    costCenterId,
    categoryId,
    fiscalYear: 1404,
    currency: 'IRR',
    amountMinor: 150_000_000,
  });
  assert.equal(first.status, 201, first.text);
  assert.equal(first.body.request.status, 'submitted');
  assert.match(first.body.request.requestNo, /^REQ-1404-\d{5}$/);
  assert.equal(first.body.request.amountMinor, 150_000_000);
  assert.equal(first.body.request.currency, 'IRR');
  assert.equal(first.body.request.requesterId, operatorId);
  approvedRequestId = first.body.request.id;

  // Validation: money must be a positive integer, currency must be exact.
  for (const invalid of [
    { amountMinor: 1.5 },
    { amountMinor: 0 },
    { amountMinor: -5 },
    { currency: 'usd' },
    { currency: 'BTC' },
    { fiscalYear: 12 },
    { title: 'x' },
    { costCenterId: 999_999 },
  ]) {
    expectError(
      await operatorClient.post('/api/requests', {
        title: 'درخواست آزمایشی',
        costCenterId,
        categoryId,
        fiscalYear: 1404,
        currency: 'IRR',
        amountMinor: 1000,
        ...invalid,
      }),
      400,
      'VALIDATION_ERROR',
    );
  }

  const second = await operatorClient.post('/api/requests', {
    title: 'قرارداد پشتیبانی سالانه',
    costCenterId,
    categoryId,
    fiscalYear: 1404,
    currency: 'IRR',
    amountMinor: 250_000_000,
  });
  assert.equal(second.status, 201, second.text);
  rejectedRequestId = second.body.request.id;
  assert.notEqual(first.body.request.requestNo, second.body.request.requestNo);

  const operatorList = await operatorClient.get('/api/requests');
  assert.equal(operatorList.status, 200);
  assert.equal(operatorList.body.total, 2);
  assert.ok(operatorList.body.requests.every((row) => row.requesterId === operatorId));

  // Admin sees everything.
  const adminRequest = await adminClient.post('/api/requests', {
    title: 'درخواست مدیر سیستم',
    costCenterId,
    categoryId,
    fiscalYear: 1404,
    currency: 'USD',
    amountMinor: 12_500,
  });
  assert.equal(adminRequest.status, 201, adminRequest.text);
  assert.equal((await adminClient.get('/api/requests')).body.total, 3);

  expectError(
    await operatorClient.get(`/api/requests/${adminRequest.body.request.id}`),
    403,
    'REQUEST_ACCESS_DENIED',
  );

  // Separation of duties.
  expectError(
    await operatorClient.post(`/api/requests/${approvedRequestId}/approve`),
    403,
    'INSUFFICIENT_ROLE',
  );
  expectError(
    await adminClient.post(`/api/requests/${adminRequest.body.request.id}/approve`),
    403,
    'SELF_DECISION_FORBIDDEN',
  );

  const approval = await adminClient.post(`/api/requests/${approvedRequestId}/approve`);
  assert.equal(approval.status, 200, approval.text);
  assert.equal(approval.body.request.status, 'approved');
  assert.equal(approval.body.request.decidedBy, adminId);
  assert.ok(approval.body.request.decidedAt);

  expectError(
    await adminClient.post(`/api/requests/${approvedRequestId}/approve`),
    409,
    'INVALID_STATUS',
  );

  expectError(
    await adminClient.post(`/api/requests/${rejectedRequestId}/reject`, {}),
    400,
    'VALIDATION_ERROR',
  );
  const rejection = await adminClient.post(`/api/requests/${rejectedRequestId}/reject`, {
    note: 'بودجه کافی وجود ندارد.',
  });
  assert.equal(rejection.status, 200, rejection.text);
  assert.equal(rejection.body.request.status, 'rejected');
  assert.equal(rejection.body.request.decisionNote, 'بودجه کافی وجود ندارد.');

  // Viewer only sees approved requests.
  const viewerList = await viewerClient.get('/api/requests');
  assert.equal(viewerList.status, 200);
  assert.equal(viewerList.body.total, 1);
  assert.equal(viewerList.body.requests[0].id, approvedRequestId);
  expectError(
    await viewerClient.get(`/api/requests/${rejectedRequestId}`),
    403,
    'REQUEST_ACCESS_DENIED',
  );
  expectError(
    await viewerClient.post('/api/requests', {
      title: 'درخواست ناظر',
      costCenterId,
      categoryId,
      fiscalYear: 1404,
      amountMinor: 1000,
    }),
    403,
    'INSUFFICIENT_ROLE',
  );

  // Owner can cancel a submitted request; it is then deletable by an admin.
  const third = await operatorClient.post('/api/requests', {
    title: 'درخواست لغوشدنی',
    costCenterId,
    categoryId,
    fiscalYear: 1404,
    amountMinor: 5_000_000,
  });
  assert.equal(third.status, 201, third.text);
  cancelledRequestId = third.body.request.id;

  const cancellation = await operatorClient.post(`/api/requests/${cancelledRequestId}/cancel`, {
    note: 'نیازی نیست.',
  });
  assert.equal(cancellation.status, 200, cancellation.text);
  assert.equal(cancellation.body.request.status, 'cancelled');

  expectError(
    await operatorClient.delete(`/api/requests/${cancelledRequestId}`),
    403,
    'INSUFFICIENT_ROLE',
  );
  expectError(
    await adminClient.delete(`/api/requests/${approvedRequestId}`),
    409,
    'REQUEST_NOT_DELETABLE',
  );

  assert.equal((await adminClient.delete(`/api/requests/${cancelledRequestId}`)).status, 204);
  assert.equal((await adminClient.get(`/api/requests/${cancelledRequestId}`)).status, 404);
  assert.equal((await adminClient.delete(`/api/requests/${rejectedRequestId}`)).status, 204);

  // Admin cancels then deletes their own submitted request.
  const adminCancel = await adminClient.post(`/api/requests/${adminRequest.body.request.id}/cancel`);
  assert.equal(adminCancel.status, 200, adminCancel.text);
  assert.equal((await adminClient.delete(`/api/requests/${adminRequest.body.request.id}`)).status, 204);

  assert.ok(auditCount('request.created') >= 4);
  assert.ok(auditCount('request.approved') >= 1);
  assert.ok(auditCount('request.rejected') >= 1);
  assert.ok(auditCount('request.deleted') >= 3);
});

// ---------------------------------------------------------------------------
// 6. CSRF / origin / content-type defences
// ---------------------------------------------------------------------------
test('CSRF, Origin, Fetch Metadata and content-type defences', async () => {
  const validToken = operatorClient.csrfToken;

  // 1. Missing token.
  expectError(
    await operatorClient.request('POST', '/api/requests', {
      body: {
        title: 'بدون توکن',
        costCenterId,
        categoryId,
        fiscalYear: 1404,
        amountMinor: 1000,
      },
      useCsrf: false,
    }),
    403,
    'CSRF_TOKEN_INVALID',
  );

  // 2. Wrong token.
  expectError(
    await operatorClient.request('POST', '/api/requests', {
      body: {
        title: 'توکن غلط',
        costCenterId,
        categoryId,
        fiscalYear: 1404,
        amountMinor: 1000,
      },
      useCsrf: false,
      headers: { 'x-csrf-token': 'not-the-right-token' },
    }),
    403,
    'CSRF_TOKEN_INVALID',
  );

  // 3. Cross-origin Origin header.
  expectError(
    await operatorClient.request('POST', '/api/requests', {
      body: {
        title: 'درخواست بین‌سایتی',
        costCenterId,
        categoryId,
        fiscalYear: 1404,
        amountMinor: 1000,
      },
      headers: { origin: 'https://evil.example' },
    }),
    403,
    'CSRF_ORIGIN_MISMATCH',
  );

  // 4. Fetch Metadata says cross-site.
  expectError(
    await operatorClient.request('POST', '/api/requests', {
      body: {
        title: 'درخواست بین‌سایتی',
        costCenterId,
        categoryId,
        fiscalYear: 1404,
        amountMinor: 1000,
      },
      headers: { 'sec-fetch-site': 'cross-site' },
    }),
    403,
    'CSRF_ORIGIN_MISMATCH',
  );

  // 5. HTML form content type is rejected outright.
  expectError(
    await operatorClient.request('POST', '/api/requests', {
      rawBody: 'title=form',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    }),
    415,
    'UNSUPPORTED_MEDIA_TYPE',
  );

  // 6. A legitimate same-origin request still works.
  const allowed = await operatorClient.request('POST', '/api/requests', {
    body: {
      title: 'درخواست معتبر با Origin',
      costCenterId,
      categoryId,
      fiscalYear: 1404,
      amountMinor: 1_000,
    },
    headers: { origin: server.baseUrl, 'sec-fetch-site': 'same-origin' },
  });
  assert.equal(allowed.status, 201, allowed.text);
  assert.ok(validToken);
});

// ---------------------------------------------------------------------------
// 7. Sessions: logout, revocation, deactivation
// ---------------------------------------------------------------------------
test('sessions live in SQLite and are revoked by logout and deactivation', async () => {
  const operatorSessions = () => Number(
    db.prepare('SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?').get(operatorId).n,
  );
  assert.ok(operatorSessions() >= 1);

  const logout = await operatorClient.logout();
  assert.equal(logout.status, 204);
  assert.equal(operatorSessions(), 0);
  expectError(await operatorClient.get('/api/auth/me'), 401, 'UNAUTHENTICATED');

  // Sign in again, then have the admin deactivate the account.
  const relogin = await operatorClient.login('operator1', 'Operator-Pass1!');
  assert.equal(relogin.status, 200, relogin.text);
  assert.ok(operatorSessions() >= 1);

  const deactivate = await adminClient.put(`/api/users/${operatorId}`, { isActive: false });
  assert.equal(deactivate.status, 200, deactivate.text);
  assert.equal(deactivate.body.user.isActive, false);
  assert.equal(operatorSessions(), 0);
  expectError(await operatorClient.get('/api/auth/me'), 401, 'UNAUTHENTICATED');

  // Deactivated users cannot log in.
  expectError(
    await createClient(server.baseUrl).login('operator1', 'Operator-Pass1!'),
    401,
    'INVALID_CREDENTIALS',
  );

  const reactivate = await adminClient.put(`/api/users/${operatorId}`, { isActive: true });
  assert.equal(reactivate.status, 200, reactivate.text);
  const login = await operatorClient.login('operator1', 'Operator-Pass1!');
  assert.equal(login.status, 200, login.text);
});

// ---------------------------------------------------------------------------
// 8. Password rotation
// ---------------------------------------------------------------------------
test('password change enforces policy and revokes other sessions', async () => {
  const created = await adminClient.post('/api/users', {
    username: 'pwuser',
    fullName: 'کاربر رمز',
    role: 'operator',
    password: 'Pw-user-Pass1!',
  });
  assert.equal(created.status, 201, created.text);

  const firstDevice = createClient(server.baseUrl);
  const secondDevice = createClient(server.baseUrl);
  assert.equal((await firstDevice.login('pwuser', 'Pw-user-Pass1!')).status, 200);
  assert.equal((await secondDevice.login('pwuser', 'Pw-user-Pass1!')).status, 200);

  expectError(
    await firstDevice.post('/api/auth/change-password', {
      currentPassword: 'not-my-password',
      newPassword: 'Pw-user-New2@',
    }),
    400,
    'INVALID_CURRENT_PASSWORD',
  );

  expectError(
    await firstDevice.post('/api/auth/change-password', {
      currentPassword: 'Pw-user-Pass1!',
      newPassword: 'short',
    }),
    400,
    'VALIDATION_ERROR',
  );

  const changed = await firstDevice.post('/api/auth/change-password', {
    currentPassword: 'Pw-user-Pass1!',
    newPassword: 'Pw-user-New2@',
  });
  assert.equal(changed.status, 200, changed.text);
  assert.ok(changed.body.csrfToken);
  assert.equal(changed.body.mustChangePassword, false);

  // Second device is signed out; first device stays signed in with a fresh session.
  expectError(await secondDevice.get('/api/auth/me'), 401, 'UNAUTHENTICATED');
  assert.equal((await firstDevice.get('/api/auth/me')).status, 200);

  expectError(
    await createClient(server.baseUrl).login('pwuser', 'Pw-user-Pass1!'),
    401,
    'INVALID_CREDENTIALS',
  );
  assert.equal((await createClient(server.baseUrl).login('pwuser', 'Pw-user-New2@')).status, 200);

  const row = db.prepare("SELECT must_change_password FROM users WHERE username = 'pwuser'").get();
  assert.equal(Number(row.must_change_password), 0);
});

// ---------------------------------------------------------------------------
// 9. Audit trail
// ---------------------------------------------------------------------------
test('audit log is admin-only, filterable and records security events', async () => {
  expectError(await operatorClient.get('/api/audit-logs'), 403, 'INSUFFICIENT_ROLE');

  const logs = await adminClient.get('/api/audit-logs?pageSize=200');
  assert.equal(logs.status, 200, logs.text);
  assert.ok(logs.body.total >= 10);

  const actions = new Set(logs.body.logs.map((entry) => entry.action));
  for (const expected of [
    'auth.login_success',
    'auth.login_failed',
    'auth.logout',
    'auth.password_changed',
    'user.created',
    'category.created',
    'category.deleted',
    'cost_center.created',
    'request.created',
    'request.approved',
    'request.rejected',
    'request.deleted',
  ]) {
    assert.ok(actions.has(expected), `missing audit action: ${expected}`);
  }

  // No secrets in the audit payload.
  const serialized = JSON.stringify(logs.body.logs);
  assert.ok(!serialized.includes('Test-password1!'));
  assert.ok(!serialized.includes('password_hash'));
  assert.ok(!/"password"\s*:/.test(serialized));

  const filtered = await adminClient.get('/api/audit-logs?action=request.approved&pageSize=10');
  assert.equal(filtered.status, 200);
  assert.ok(filtered.body.logs.length >= 1);
  assert.ok(filtered.body.logs.every((entry) => entry.action === 'request.approved'));

  // The API is read-only: rewriting history is impossible.
  expectError(
    await adminClient.post('/api/audit-logs', { action: 'fake' }),
    404,
    'NOT_FOUND',
  );
});

// ---------------------------------------------------------------------------
// 9b. Backups (admin only)
// ---------------------------------------------------------------------------
test('backups are admin-only and produce a valid SQLite snapshot', async () => {
  expectError(await operatorClient.get('/api/backups'), 403, 'INSUFFICIENT_ROLE');
  expectError(await operatorClient.post('/api/backups'), 403, 'INSUFFICIENT_ROLE');

  const created = await adminClient.post('/api/backups');
  assert.equal(created.status, 201, created.text);
  const { name, sizeBytes } = created.body.backup;
  assert.match(name, /^budget-.+\.db$/);
  assert.ok(sizeBytes > 0);

  const list = await adminClient.get('/api/backups');
  assert.equal(list.status, 200);
  assert.ok(list.body.backups.some((backup) => backup.name === name));

  const download = await adminClient.get(`/api/backups/${encodeURIComponent(name)}`);
  assert.equal(download.status, 200, download.text);
  assert.ok(download.text.startsWith('SQLite format 3'), 'downloaded file is a SQLite database');

  expectError(
    await adminClient.get('/api/backups/..%2F..%2Fetc%2Fpasswd'),
    400,
    'VALIDATION_ERROR',
  );
  expectError(
    await adminClient.get('/api/backups/backup.txt'),
    400,
    'VALIDATION_ERROR',
  );

  assert.ok(auditCount('backup.created') >= 1);
  assert.ok(auditCount('backup.downloaded') >= 1);
});

// ---------------------------------------------------------------------------
// 10. Input hardening
// ---------------------------------------------------------------------------
test('malformed and oversized JSON bodies are rejected safely', async () => {
  const malformed = await operatorClient.request('POST', '/api/requests', {
    rawBody: '{"title": "broken",',
    headers: { 'content-type': 'application/json' },
  });
  expectError(malformed, 400, 'MALFORMED_JSON');

  const hugeBody = JSON.stringify({ title: 'x'.repeat(1_100_000) });
  const oversized = await operatorClient.request('POST', '/api/requests', {
    rawBody: hugeBody,
    headers: { 'content-type': 'application/json' },
  });
  expectError(oversized, 413, 'PAYLOAD_TOO_LARGE');
});

// ---------------------------------------------------------------------------
// 11. Static safety audit
// ---------------------------------------------------------------------------
test('no SQL DELETE without WHERE and no id interpolation in SQL', () => {
  const files = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.js')) files.push(full);
    }
  };
  walk(path.join(ROOT, 'server'));
  walk(path.join(ROOT, 'scripts'));

  assert.ok(files.length >= 10);

  let deleteStatements = 0;
  for (const file of files) {
    const source = fs.readFileSync(file, 'utf8');

    // Every `DELETE FROM ...` must be constrained by a WHERE clause.
    for (const match of source.matchAll(/DELETE\s+FROM\s+\S+/gi)) {
      const statement = source.slice(match.index, match.index + 300).split(/[`'"]/)[0];
      assert.match(
        statement,
        /\bWHERE\b/i,
        `DELETE without WHERE in ${path.relative(ROOT, file)}: ${statement.trim()}`,
      );
      deleteStatements += 1;
    }

    // Request data must never be interpolated into SQL. Check line by line so
    // ordinary template strings (log lines, error envelopes) are not flagged.
    for (const line of source.split('\n')) {
      if (!/\b(SELECT|INSERT|UPDATE|DELETE|PRAGMA)\b/.test(line)) continue;
      assert.doesNotMatch(
        line,
        /\$\{\s*(?:id|userId|requesterId|costCenterId|categoryId|req\b|body\b|params\b|query\b)/,
        `SQL interpolation of user data in ${path.relative(ROOT, file)}: ${line.trim()}`,
      );
    }
  }

  assert.ok(deleteStatements >= 6, `expected DELETE statements, found ${deleteStatements}`);
});
