package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"shadowedge/internal/domain"
)

// appendOutboxTx records an edge-side write for the syncer. It is a no-op on a
// master/standalone store.
func (s *Store) appendOutboxTx(ctx context.Context, tx *sql.Tx, projectID, op, entityType, entityID string, baseVersion *int, payload any) error {
	var role string
	err := tx.QueryRowContext(ctx,
		`SELECT role FROM sync_state WHERE local_project_id = ?`, projectID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if role != "edge" {
		return nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var base any
	if baseVersion != nil {
		base = *baseVersion
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO sync_outbox
			(id, project_id, op, entity_type, entity_id, base_version, payload, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		newID(), projectID, op, entityType, entityID, base, string(body), now())
	return err
}

// ApplySyncOperations applies a batch of edge operations on a master. The
// master is authoritative: stale base versions are reported as conflicts and
// are not applied.
func (s *Store) ApplySyncOperations(ctx context.Context, projectID, actorID, nodeID string, ops []domain.SyncOperation) (*domain.SyncPushResponse, error) {
	resp := &domain.SyncPushResponse{Conflicts: []domain.SyncConflict{}}
	if nodeID == "" {
		nodeID = "edge"
	}
	err := s.withWrite(ctx, func(tx *sql.Tx) error {
		for _, op := range ops {
			switch op.Op {
			case "entity_upsert":
				if op.Entity == nil {
					addSyncConflict(resp, "", op.Op, "missing entity payload")
					continue
				}
				if err := applyMasterEntityUpsert(ctx, tx, projectID, actorID, nodeID, op, resp); err != nil {
					return err
				}
			case "entity_delete":
				if op.EntityID == "" {
					addSyncConflict(resp, "", op.Op, "missing entity_id")
					continue
				}
				if err := applyMasterEntityDelete(ctx, tx, projectID, actorID, nodeID, op, resp); err != nil {
					return err
				}
			case "edge_upsert":
				if op.Edge == nil {
					addSyncConflict(resp, "", op.Op, "missing edge payload")
					continue
				}
				if err := applyMasterEdgeUpsert(ctx, tx, projectID, actorID, nodeID, op, resp); err != nil {
					return err
				}
			case "edge_delete":
				if op.EdgeID == "" {
					addSyncConflict(resp, "", op.Op, "missing edge_id")
					continue
				}
				if err := applyMasterEdgeDelete(ctx, tx, projectID, actorID, nodeID, op, resp); err != nil {
					return err
				}
			default:
				addSyncConflict(resp, "", op.Op, "unknown operation")
			}
		}
		var seq int
		if err := tx.QueryRowContext(ctx,
			`SELECT COALESCE(MAX(seq), 0) FROM events WHERE project_id = ?`, projectID).Scan(&seq); err != nil {
			return err
		}
		resp.LastSeq = seq
		return nil
	})
	return resp, err
}

func addSyncConflict(resp *domain.SyncPushResponse, entityID, op, detail string) {
	resp.Conflicts = append(resp.Conflicts, domain.SyncConflict{
		EntityID: entityID, Op: op, Detail: detail,
	})
}

func applyMasterEntityUpsert(ctx context.Context, tx *sql.Tx, projectID, actorID, nodeID string, op domain.SyncOperation, resp *domain.SyncPushResponse) error {
	e := *op.Entity
	if e.ID == "" {
		addSyncConflict(resp, "", op.Op, "missing entity id")
		return nil
	}
	e.Title = strings.TrimSpace(e.Title)
	if e.Status == "" {
		e.Status = domain.StatusNew
	}
	e.Phase = domain.NormalizePhase(e.Phase)
	if e.Data == nil {
		e.Data = map[string]any{}
	}
	if err := validateEntityInput(e.Kind, e.Title, e.Status); err != nil {
		addSyncConflict(resp, e.ID, op.Op, err.Error())
		return nil
	}
	if err := validatePhaseTx(ctx, tx, projectID, e.Phase); err != nil {
		addSyncConflict(resp, e.ID, op.Op, err.Error())
		return nil
	}

	var ip, hostname, osName, tags string
	if e.Kind == domain.KindTarget {
		var err error
		ip, hostname, osName, tags, err = targetFields(e.Data)
		if err != nil {
			addSyncConflict(resp, e.ID, op.Op, err.Error())
			return nil
		}
		var otherID string
		err = tx.QueryRowContext(ctx, `
			SELECT entity_id FROM target_details
			WHERE project_id = ? AND ip = ? AND deleted_at IS NULL AND entity_id <> ?`,
			projectID, ip, e.ID).Scan(&otherID)
		if err == nil {
			addSyncConflict(resp, e.ID, op.Op, "target address already exists on master")
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}

	dataJSON, err := json.Marshal(e.Data)
	if err != nil {
		addSyncConflict(resp, e.ID, op.Op, "invalid entity data")
		return nil
	}

	var currentVersion int
	var deletedAt sql.NullString
	err = tx.QueryRowContext(ctx,
		`SELECT version, deleted_at FROM entities WHERE project_id = ? AND id = ?`,
		projectID, e.ID).Scan(&currentVersion, &deletedAt)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if exists && deletedAt.Valid && deletedAt.String != "" {
		addSyncConflict(resp, e.ID, op.Op, "entity was deleted on master")
		return nil
	}
	if exists && op.BaseVersion != nil && currentVersion != *op.BaseVersion {
		addSyncConflict(resp, e.ID, op.Op,
			fmt.Sprintf("version conflict: master=%d edge=%d", currentVersion, *op.BaseVersion))
		return nil
	}

	ts := now()
	newVersion := 1
	var baseVersion *int
	if exists {
		newVersion = currentVersion + 1
		bv := currentVersion
		baseVersion = &bv
		if _, err := tx.ExecContext(ctx, `
			UPDATE entities
			SET kind = ?, title = ?, status = ?, phase = ?, data = ?, version = ?,
			    updated_by = ?, updated_at = ?
			WHERE project_id = ? AND id = ?`,
			e.Kind, e.Title, e.Status, e.Phase, string(dataJSON), newVersion,
			actorID, ts, projectID, e.ID); err != nil {
			return err
		}
	} else {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO entities
				(id, project_id, kind, title, status, phase, data, field_versions, version,
				 created_by, updated_by, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, '{}', ?, ?, ?, ?, ?)`,
			e.ID, projectID, e.Kind, e.Title, e.Status, e.Phase, string(dataJSON),
			newVersion, actorID, actorID, ts, ts); err != nil {
			if isUniqueViolation(err) {
				addSyncConflict(resp, e.ID, op.Op, "entity already exists")
				return nil
			}
			return err
		}
	}

	if e.Kind == domain.KindTarget {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO target_details (entity_id, project_id, ip, hostname, os, tags, deleted_at)
			VALUES (?, ?, ?, ?, ?, ?, NULL)
			ON CONFLICT(entity_id) DO UPDATE SET
				project_id = excluded.project_id,
				ip = excluded.ip,
				hostname = excluded.hostname,
				os = excluded.os,
				tags = excluded.tags,
				deleted_at = NULL`,
			e.ID, projectID, ip, hostname, osName, tags); err != nil {
			if isUniqueViolation(err) {
				addSyncConflict(resp, e.ID, op.Op, "target address already exists on master")
				return nil
			}
			return err
		}
	} else {
		if _, err := tx.ExecContext(ctx, `DELETE FROM target_details WHERE entity_id = ?`, e.ID); err != nil {
			return err
		}
	}

	stored := e
	stored.ProjectID = projectID
	stored.Version = newVersion
	stored.UpdatedBy = actorID
	stored.UpdatedAt = ts
	if !exists || stored.CreatedBy == "" {
		stored.CreatedBy = actorID
	}
	if !exists || stored.CreatedAt == "" {
		stored.CreatedAt = ts
	}
	if err := appendEventTx(ctx, tx, nodeID, projectID, actorID, "entity", e.ID, "entity_upsert", baseVersion, stored); err != nil {
		return err
	}
	resp.Accepted++
	return nil
}

func applyMasterEntityDelete(ctx context.Context, tx *sql.Tx, projectID, actorID, nodeID string, op domain.SyncOperation, resp *domain.SyncPushResponse) error {
	var version int
	err := tx.QueryRowContext(ctx,
		`SELECT version FROM entities WHERE project_id = ? AND id = ? AND deleted_at IS NULL`,
		projectID, op.EntityID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		addSyncConflict(resp, op.EntityID, op.Op, "entity not found")
		return nil
	}
	if err != nil {
		return err
	}
	if op.BaseVersion != nil && *op.BaseVersion != version {
		addSyncConflict(resp, op.EntityID, op.Op,
			fmt.Sprintf("version conflict: master=%d edge=%d", version, *op.BaseVersion))
		return nil
	}
	ts := now()
	newVersion := version + 1
	if _, err := tx.ExecContext(ctx, `
		UPDATE entities SET deleted_at = ?, updated_at = ?, version = ?
		WHERE project_id = ? AND id = ? AND deleted_at IS NULL`,
		ts, ts, newVersion, projectID, op.EntityID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE target_details SET deleted_at = ? WHERE entity_id = ?`, ts, op.EntityID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE attack_edges SET deleted_at = ?
		WHERE project_id = ? AND (from_entity_id = ? OR to_entity_id = ?) AND deleted_at IS NULL`,
		ts, projectID, op.EntityID, op.EntityID); err != nil {
		return err
	}
	payload := map[string]any{"entity_id": op.EntityID, "version": newVersion}
	if err := appendEventTx(ctx, tx, nodeID, projectID, actorID, "entity", op.EntityID, "entity_delete", &version, payload); err != nil {
		return err
	}
	resp.Accepted++
	return nil
}

func applyMasterEdgeUpsert(ctx context.Context, tx *sql.Tx, projectID, actorID, nodeID string, op domain.SyncOperation, resp *domain.SyncPushResponse) error {
	e := *op.Edge
	if e.ID == "" || e.FromEntityID == "" || e.ToEntityID == "" {
		addSyncConflict(resp, e.ID, op.Op, "missing edge fields")
		return nil
	}
	if e.FromEntityID == e.ToEntityID {
		addSyncConflict(resp, e.ID, op.Op, "edge cannot reference itself")
		return nil
	}
	var n int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM entities
		WHERE project_id = ? AND deleted_at IS NULL AND id IN (?, ?)`,
		projectID, e.FromEntityID, e.ToEntityID).Scan(&n); err != nil {
		return err
	}
	if n != 2 {
		addSyncConflict(resp, e.ID, op.Op, "edge endpoints not found on master")
		return nil
	}

	var existingDeleted sql.NullString
	err := tx.QueryRowContext(ctx,
		`SELECT deleted_at FROM attack_edges WHERE project_id = ? AND id = ?`,
		projectID, e.ID).Scan(&existingDeleted)
	existing := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if existing && existingDeleted.Valid && existingDeleted.String != "" {
		addSyncConflict(resp, e.ID, op.Op, "edge was deleted on master")
		return nil
	}
	ts := now()
	if existing {
		if _, err := tx.ExecContext(ctx, `
			UPDATE attack_edges SET label = ?
			WHERE project_id = ? AND id = ?`,
			e.Label, projectID, e.ID); err != nil {
			return err
		}
	} else {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO attack_edges
				(id, project_id, from_entity_id, to_entity_id, label, created_by, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			e.ID, projectID, e.FromEntityID, e.ToEntityID, e.Label, actorID, ts); err != nil {
			if isUniqueViolation(err) {
				addSyncConflict(resp, e.ID, op.Op, "edge already exists")
				return nil
			}
			return err
		}
	}

	stored := e
	stored.ProjectID = projectID
	stored.CreatedBy = actorID
	if stored.CreatedAt == "" {
		stored.CreatedAt = ts
	}
	if err := appendEventTx(ctx, tx, nodeID, projectID, actorID, "edge", e.ID, "edge_upsert", nil, stored); err != nil {
		return err
	}
	resp.Accepted++
	return nil
}

func applyMasterEdgeDelete(ctx context.Context, tx *sql.Tx, projectID, actorID, nodeID string, op domain.SyncOperation, resp *domain.SyncPushResponse) error {
	var n int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM attack_edges WHERE project_id = ? AND id = ? AND deleted_at IS NULL`,
		projectID, op.EdgeID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		addSyncConflict(resp, op.EdgeID, op.Op, "edge not found")
		return nil
	}
	ts := now()
	if _, err := tx.ExecContext(ctx, `
		UPDATE attack_edges SET deleted_at = ?
		WHERE project_id = ? AND id = ? AND deleted_at IS NULL`, ts, projectID, op.EdgeID); err != nil {
		return err
	}
	payload := map[string]any{"edge_id": op.EdgeID}
	if err := appendEventTx(ctx, tx, nodeID, projectID, actorID, "edge", op.EdgeID, "edge_delete", nil, payload); err != nil {
		return err
	}
	resp.Accepted++
	return nil
}
