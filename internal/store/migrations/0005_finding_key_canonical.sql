-- Rekey findings from the 0004 legacy namespace to the canonical asset-scoped
-- identity. Drop the unique index first: upgraded databases may contain
-- duplicate findings for the same asset/identity, and the canonical key is
-- intentionally non-unique (new findings converge by deterministic ID).

DROP INDEX IF EXISTS idx_finding_lifecycle_key;

UPDATE entities
SET data = json_set(
    data,
    '$.finding_key',
    CASE
        WHEN COALESCE(json_extract(data, '$.service_id'), '') <> ''
            THEN 'service:' || json_extract(data, '$.service_id')
        WHEN COALESCE(json_extract(data, '$.target_id'), '') <> ''
            THEN 'target:' || json_extract(data, '$.target_id')
        ELSE 'unattached:' || project_id
    END
    || '|' ||
    CASE
        WHEN COALESCE(TRIM(json_extract(data, '$.cve')), '') <> ''
            THEN 'cve:' || LOWER(TRIM(json_extract(data, '$.cve')))
        ELSE 'type:' || LOWER(TRIM(COALESCE(json_extract(data, '$.vuln_type'), '')))
            || '|title:' || LOWER(TRIM(title))
            || '|endpoint:' || LOWER(TRIM(COALESCE(json_extract(data, '$.endpoint'), '')))
            || '|parameter:' || LOWER(TRIM(COALESCE(json_extract(data, '$.parameter'), '')))
    END
)
WHERE kind = 'finding'
  AND (
      json_extract(data, '$.finding_key') IS NULL
      OR json_extract(data, '$.finding_key') LIKE 'legacy:%'
  );

CREATE INDEX IF NOT EXISTS idx_finding_lifecycle_key
    ON entities(json_extract(data, '$.finding_key'))
    WHERE kind = 'finding'
      AND deleted_at IS NULL
      AND json_extract(data, '$.finding_key') IS NOT NULL;
