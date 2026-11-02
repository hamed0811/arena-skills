-- ============================================================================
--  Enterprise Financial Budget System — Database Schema (SQLite 3.37+)
-- ----------------------------------------------------------------------------
--  Conventions
--    * All timestamps are ISO-8601 UTC strings ("YYYY-MM-DDTHH:MM:SS.sssZ").
--    * All monetary values are stored as INTEGER minor units (`amount_minor`).
--        - IRR / AED : 1 unit == 1 minor unit (no fractional rials)
--        - USD / EUR / GBP : 1 unit == 100 minor units (cents)
--      Never store money as REAL: binary floating point cannot represent
--      currency exactly and silently corrupts totals.
--    * `currency` is stored on every monetary row so Rials and Dollars can
--      never be silently aggregated together.
--    * Master data is protected with ON DELETE RESTRICT: deleting a cost
--      center/category that is referenced by a request or a budget is
--      rejected by the database itself, not only by application code.
--    * `audit_logs` is append-only, enforced by triggers.
-- ============================================================================

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
--  meta — schema bookkeeping (single row per key)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS meta (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

-- ---------------------------------------------------------------------------
--  users — authentication + RBAC
--    role: admin    -> full access (user management, imports, backups)
--          operator -> create/read own requests, read reference data
--          viewer   -> read-only (reports)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    username              TEXT    NOT NULL COLLATE NOCASE
                                  CHECK (length(trim(username)) BETWEEN 3 AND 64),
    password_hash         TEXT    NOT NULL CHECK (length(password_hash) >= 20),
    full_name             TEXT    NOT NULL CHECK (length(trim(full_name)) BETWEEN 2 AND 120),
    role                  TEXT    NOT NULL DEFAULT 'operator'
                                  CHECK (role IN ('admin', 'operator', 'viewer')),
    is_active             INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    must_change_password  INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0, 1)),
    failed_login_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_login_attempts >= 0),
    locked_until          TEXT,
    last_login_at         TEXT,
    password_changed_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    created_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS ux_users_username ON users (username COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_users_role_active ON users (role, is_active);

-- ---------------------------------------------------------------------------
--  cost_centers — organisational units (معاونت / مرکز هزینه)
--    parent_id allows a tree: معاونت -> مدیریت -> اداره
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cost_centers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    code        TEXT    NOT NULL COLLATE NOCASE
                        CHECK (length(trim(code)) BETWEEN 1 AND 32),
    name        TEXT    NOT NULL COLLATE NOCASE
                        CHECK (length(trim(name)) BETWEEN 2 AND 160),
    parent_id   INTEGER REFERENCES cost_centers (id) ON DELETE RESTRICT ON UPDATE CASCADE,
    manager     TEXT,
    is_active   INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (parent_id IS NULL OR parent_id <> id)
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS ux_cost_centers_code ON cost_centers (code COLLATE NOCASE);
CREATE UNIQUE INDEX IF NOT EXISTS ux_cost_centers_name ON cost_centers (name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_cost_centers_parent ON cost_centers (parent_id);

-- ---------------------------------------------------------------------------
--  categories — budget line items (سرفصل)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS categories (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    code        TEXT    NOT NULL COLLATE NOCASE
                        CHECK (length(trim(code)) BETWEEN 1 AND 32),
    name        TEXT    NOT NULL COLLATE NOCASE
                        CHECK (length(trim(name)) BETWEEN 2 AND 160),
    parent_id   INTEGER REFERENCES categories (id) ON DELETE RESTRICT ON UPDATE CASCADE,
    description TEXT,
    is_active   INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (parent_id IS NULL OR parent_id <> id)
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS ux_categories_code ON categories (code COLLATE NOCASE);
CREATE UNIQUE INDEX IF NOT EXISTS ux_categories_name ON categories (name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_categories_parent ON categories (parent_id);

-- ---------------------------------------------------------------------------
--  requests — budget requests submitted by users, approved/rejected by admin
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS requests (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    request_no     TEXT    NOT NULL UNIQUE,
    title          TEXT    NOT NULL CHECK (length(trim(title)) BETWEEN 2 AND 200),
    description    TEXT,
    requester_id   INTEGER NOT NULL REFERENCES users (id)        ON DELETE RESTRICT ON UPDATE CASCADE,
    cost_center_id INTEGER NOT NULL REFERENCES cost_centers (id) ON DELETE RESTRICT ON UPDATE CASCADE,
    category_id    INTEGER NOT NULL REFERENCES categories (id)   ON DELETE RESTRICT ON UPDATE CASCADE,
    fiscal_year    INTEGER NOT NULL CHECK (fiscal_year BETWEEN 1300 AND 2200),
    currency       TEXT    NOT NULL DEFAULT 'IRR'
                           CHECK (currency IN ('IRR', 'USD', 'EUR', 'AED', 'GBP')),
    amount_minor   INTEGER NOT NULL CHECK (amount_minor > 0),
    status         TEXT    NOT NULL DEFAULT 'submitted'
                           CHECK (status IN ('draft', 'submitted', 'approved', 'rejected', 'cancelled')),
    decided_by     INTEGER REFERENCES users (id) ON DELETE SET NULL ON UPDATE CASCADE,
    decided_at     TEXT,
    decision_note  TEXT,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    -- A decision must always be attributable and timestamped.
    CHECK (
        (status IN ('approved', 'rejected') AND decided_by IS NOT NULL AND decided_at IS NOT NULL)
        OR status NOT IN ('approved', 'rejected')
    ),
    CHECK (decided_by IS NULL OR decided_by <> requester_id)
) STRICT;

CREATE INDEX IF NOT EXISTS ix_requests_requester ON requests (requester_id);
CREATE INDEX IF NOT EXISTS ix_requests_status_year ON requests (status, fiscal_year);
CREATE INDEX IF NOT EXISTS ix_requests_cc_category ON requests (cost_center_id, category_id);
CREATE INDEX IF NOT EXISTS ix_requests_year_currency ON requests (fiscal_year, currency);

-- ---------------------------------------------------------------------------
--  budgets — approved envelope per (year, cost center, category, currency)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS budgets (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    fiscal_year    INTEGER NOT NULL CHECK (fiscal_year BETWEEN 1300 AND 2200),
    cost_center_id INTEGER NOT NULL REFERENCES cost_centers (id) ON DELETE RESTRICT ON UPDATE CASCADE,
    category_id    INTEGER NOT NULL REFERENCES categories (id)   ON DELETE RESTRICT ON UPDATE CASCADE,
    currency       TEXT    NOT NULL DEFAULT 'IRR'
                           CHECK (currency IN ('IRR', 'USD', 'EUR', 'AED', 'GBP')),
    amount_minor   INTEGER NOT NULL CHECK (amount_minor >= 0),
    notes          TEXT,
    created_by     INTEGER REFERENCES users (id) ON DELETE SET NULL ON UPDATE CASCADE,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (fiscal_year, cost_center_id, category_id, currency)
) STRICT;

CREATE INDEX IF NOT EXISTS ix_budgets_year ON budgets (fiscal_year);
CREATE INDEX IF NOT EXISTS ix_budgets_cc ON budgets (cost_center_id, category_id);

-- ---------------------------------------------------------------------------
--  audit_logs — append-only security/business trail
--    user_id is nullable for system events (imports, resets) that have no actor.
--    ON DELETE RESTRICT is deliberate: a user with audit history can never be
--    hard-deleted (which would otherwise rewrite history / fight the
--    append-only triggers). Deactivate users with is_active = 0 instead.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES users (id) ON DELETE RESTRICT ON UPDATE CASCADE,
    action      TEXT    NOT NULL CHECK (length(trim(action)) BETWEEN 2 AND 64),
    entity_type TEXT    NOT NULL CHECK (length(trim(entity_type)) BETWEEN 2 AND 40),
    entity_id   TEXT,
    details     TEXT,
    ip_address  TEXT,
    user_agent  TEXT,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE INDEX IF NOT EXISTS ix_audit_created ON audit_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS ix_audit_user ON audit_logs (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_audit_entity ON audit_logs (entity_type, entity_id);

-- ---------------------------------------------------------------------------
--  sessions — server-side session store (no in-memory store in production)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    sid        TEXT PRIMARY KEY,
    user_id    INTEGER REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE,
    data       TEXT    NOT NULL,
    expires_at TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE INDEX IF NOT EXISTS ix_sessions_expires ON sessions (expires_at);
CREATE INDEX IF NOT EXISTS ix_sessions_user ON sessions (user_id);

-- ===========================================================================
--  Read model
-- ===========================================================================
CREATE VIEW IF NOT EXISTS v_requests_full AS
SELECT
    r.id,
    r.request_no,
    r.title,
    r.description,
    r.fiscal_year,
    r.currency,
    r.amount_minor,
    r.status,
    r.created_at,
    r.updated_at,
    r.decided_at,
    r.decision_note,
    r.requester_id,
    u.username      AS requester_username,
    u.full_name     AS requester_name,
    r.cost_center_id,
    cc.code         AS cost_center_code,
    cc.name         AS cost_center_name,
    r.category_id,
    c.code          AS category_code,
    c.name          AS category_name,
    r.decided_by,
    du.full_name    AS decided_by_name
FROM requests r
JOIN users        u  ON u.id  = r.requester_id
JOIN cost_centers cc ON cc.id = r.cost_center_id
JOIN categories   c  ON c.id  = r.category_id
LEFT JOIN users   du ON du.id = r.decided_by;

-- ===========================================================================
--  Triggers — updated_at maintenance
-- ===========================================================================
CREATE TRIGGER IF NOT EXISTS trg_users_updated_at
AFTER UPDATE ON users FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE users SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_cost_centers_updated_at
AFTER UPDATE ON cost_centers FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE cost_centers SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_categories_updated_at
AFTER UPDATE ON categories FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE categories SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_requests_updated_at
AFTER UPDATE ON requests FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE requests SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_budgets_updated_at
AFTER UPDATE ON budgets FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE budgets SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;

-- ===========================================================================
--  Triggers — audit log is append-only (no UPDATE, no DELETE, ever)
-- ===========================================================================
CREATE TRIGGER IF NOT EXISTS trg_audit_logs_no_update
BEFORE UPDATE ON audit_logs FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'audit_logs is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_logs_no_delete
BEFORE DELETE ON audit_logs FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'audit_logs is append-only: DELETE is forbidden');
END;

-- ===========================================================================
--  Seed schema version (idempotent)
-- ===========================================================================
INSERT INTO meta (key, value)
VALUES ('schema_version', '1')
ON CONFLICT (key) DO UPDATE SET value = excluded.value,
                                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now');
