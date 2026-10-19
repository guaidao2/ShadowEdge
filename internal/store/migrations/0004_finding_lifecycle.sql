-- Finding lifecycle: findings are asset-scoped records with a stable identity.
-- Existing findings get a unique legacy key; new findings use a deterministic
-- key derived from project + asset + CVE/type/title.

UPDATE entities
SET data = json_set(data, '$.finding_key', 'legacy:' || id)
WHERE kind = 'finding' AND json_extract(data, '$.finding_key') IS NULL;

UPDATE entities
SET data = json_set(
    data,
    '$.phase_history',
    json_array(json_object('phase', phase, 'status', status, 'at', updated_at))
)
WHERE kind = 'finding' AND json_extract(data, '$.phase_history') IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_lifecycle_key
    ON entities(json_extract(data, '$.finding_key'))
    WHERE kind = 'finding'
      AND deleted_at IS NULL
      AND json_extract(data, '$.finding_key') IS NOT NULL;
