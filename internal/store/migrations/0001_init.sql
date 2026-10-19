PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id                 TEXT PRIMARY KEY,
    username           TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash      TEXT NOT NULL,
    display_name       TEXT NOT NULL DEFAULT '',
    locale             TEXT NOT NULL DEFAULT 'en',
    status             TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    is_platform_admin  INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS registration_requests (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL COLLATE NOCASE,
    display_name  TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    email         TEXT NOT NULL DEFAULT '',
    reason        TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    reviewed_by   TEXT,
    reviewed_at   TEXT,
    created_at    TEXT NOT NULL,
    FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_registration_status
    ON registration_requests(status, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_registration_pending_username
    ON registration_requests(username) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    csrf_token   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS projects (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'completed', 'archived')),
    owner_id    TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS project_members (
    project_id TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'operator' CHECK (role IN ('owner', 'operator', 'viewer', 'auditor')),
    joined_at  TEXT NOT NULL,
    PRIMARY KEY (project_id, user_id),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS project_phases (
    project_id TEXT NOT NULL,
    key        TEXT NOT NULL,
    name_en    TEXT NOT NULL,
    name_zh    TEXT NOT NULL,
    position   INTEGER NOT NULL,
    color      TEXT NOT NULL,
    PRIMARY KEY (project_id, key),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS entities (
    id             TEXT PRIMARY KEY,
    project_id     TEXT NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('target', 'service', 'finding', 'credential', 'evidence', 'command', 'task', 'note', 'action')),
    title          TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'confirmed', 'exploited', 'fixed', 'false_positive')),
    phase          TEXT NOT NULL DEFAULT 'recon',
    data           TEXT NOT NULL DEFAULT '{}',
    field_versions TEXT NOT NULL DEFAULT '{}',
    version        INTEGER NOT NULL DEFAULT 1,
    created_by     TEXT NOT NULL,
    updated_by     TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    deleted_at     TEXT,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE RESTRICT,
    FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_entities_project
    ON entities(project_id, deleted_at, phase);
CREATE INDEX IF NOT EXISTS idx_entities_kind
    ON entities(project_id, kind, deleted_at);

CREATE TABLE IF NOT EXISTS target_details (
    entity_id  TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    ip         TEXT NOT NULL,
    hostname   TEXT NOT NULL DEFAULT '',
    os         TEXT NOT NULL DEFAULT '',
    tags       TEXT NOT NULL DEFAULT '',
    deleted_at TEXT,
    FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_target_ip
    ON target_details(project_id, ip) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS service_details (
    entity_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    port      INTEGER NOT NULL,
    protocol  TEXT NOT NULL DEFAULT 'tcp',
    name      TEXT NOT NULL DEFAULT '',
    product   TEXT NOT NULL DEFAULT '',
    version   TEXT NOT NULL DEFAULT '',
    banner    TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE,
    FOREIGN KEY (target_id) REFERENCES entities(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS finding_details (
    entity_id   TEXT PRIMARY KEY,
    target_id   TEXT,
    service_id  TEXT,
    severity    TEXT NOT NULL DEFAULT 'medium',
    cve         TEXT NOT NULL DEFAULT '',
    cvss        REAL,
    description TEXT NOT NULL DEFAULT '',
    evidence    TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS credential_details (
    entity_id TEXT PRIMARY KEY,
    protocol  TEXT NOT NULL DEFAULT '',
    username  TEXT NOT NULL DEFAULT '',
    secret    TEXT NOT NULL DEFAULT '',
    source    TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS evidence_details (
    entity_id    TEXT PRIMARY KEY,
    kind         TEXT NOT NULL DEFAULT '',
    filename     TEXT NOT NULL DEFAULT '',
    sha256       TEXT NOT NULL DEFAULT '',
    storage_path TEXT NOT NULL DEFAULT '',
    size         INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS command_details (
    entity_id   TEXT PRIMARY KEY,
    target_id   TEXT,
    command     TEXT NOT NULL DEFAULT '',
    output      TEXT NOT NULL DEFAULT '',
    exit_code   INTEGER,
    started_at  TEXT,
    finished_at TEXT,
    FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS task_details (
    entity_id TEXT PRIMARY KEY,
    assignee  TEXT NOT NULL DEFAULT '',
    due_at    TEXT,
    done_at   TEXT,
    FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS note_details (
    entity_id TEXT PRIMARY KEY,
    text      TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attack_edges (
    id             TEXT PRIMARY KEY,
    project_id     TEXT NOT NULL,
    from_entity_id TEXT NOT NULL,
    to_entity_id   TEXT NOT NULL,
    label          TEXT NOT NULL DEFAULT '',
    created_by     TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    deleted_at     TEXT,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (from_entity_id) REFERENCES entities(id) ON DELETE CASCADE,
    FOREIGN KEY (to_entity_id) REFERENCES entities(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_edge_unique
    ON attack_edges(project_id, from_entity_id, to_entity_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_edges_project ON attack_edges(project_id, deleted_at);

CREATE TABLE IF NOT EXISTS graph_layouts (
    project_id TEXT NOT NULL,
    entity_id  TEXT NOT NULL,
    x          REAL NOT NULL,
    y          REAL NOT NULL,
    locked     INTEGER NOT NULL DEFAULT 0,
    updated_by TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, entity_id),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS events (
    project_id  TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    event_id    TEXT NOT NULL UNIQUE,
    actor_id    TEXT NOT NULL,
    node_id     TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id   TEXT NOT NULL,
    op          TEXT NOT NULL,
    base_version INTEGER,
    payload     TEXT NOT NULL,
    hlc         TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (project_id, seq),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    scopes       TEXT NOT NULL DEFAULT 'read',
    project_id   TEXT,
    expires_at   TEXT,
    last_used_at TEXT,
    created_at   TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         TEXT PRIMARY KEY,
    actor_id   TEXT,
    project_id TEXT,
    action     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT '',
    ip         TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_project ON audit_log(project_id, created_at);
