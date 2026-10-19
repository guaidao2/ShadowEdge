CREATE TABLE IF NOT EXISTS sync_state (
    local_project_id  TEXT PRIMARY KEY,
    remote_project_id TEXT NOT NULL,
    master_url        TEXT NOT NULL,
    node_id           TEXT NOT NULL,
    last_seq          INTEGER NOT NULL DEFAULT 0,
    updated_at        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sync_state_remote
    ON sync_state(master_url, remote_project_id);

CREATE TABLE IF NOT EXISTS sync_outbox (
    id           TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL,
    op           TEXT NOT NULL,
    entity_type  TEXT NOT NULL,
    entity_id    TEXT NOT NULL,
    base_version INTEGER,
    payload      TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0,
    last_error   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sync_outbox_project
    ON sync_outbox(project_id, created_at);

CREATE TABLE IF NOT EXISTS sync_conflicts (
    id         TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    entity_id  TEXT NOT NULL,
    op         TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sync_conflicts_project
    ON sync_conflicts(project_id, created_at);
