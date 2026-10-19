ALTER TABLE sync_state ADD COLUMN role TEXT NOT NULL DEFAULT 'edge';
ALTER TABLE sync_state ADD COLUMN token_cipher TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_sync_state_role ON sync_state(role);
