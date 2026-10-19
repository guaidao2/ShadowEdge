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

// ---------- sync state ----------

const syncStateColumns = `local_project_id, remote_project_id, master_url, node_id, last_seq, role, token_cipher, updated_at`

func scanSyncState(scanner interface{ Scan(...any) error }) (*domain.SyncState, error) {
	var s domain.SyncState
	err := scanner.Scan(&s.LocalProjectID, &s.RemoteProjectID, &s.MasterURL, &s.NodeID,
		&s.LastSeq, &s.Role, &s.TokenCipher, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if s.Role == "" {
		s.Role = "edge"
	}
	return &s, nil
}

func (s *Store) GetSyncState(ctx context.Context, localProjectID string) (*domain.SyncState, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+syncStateColumns+` FROM sync_state WHERE local_project_id = ?`, localProjectID)
	state, err := scanSyncState(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return state, err
}

func (s *Store) FindSyncStateByRemote(ctx context.Context, masterURL, remoteProjectID string) (*domain.SyncState, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+syncStateColumns+` FROM sync_state WHERE master_url = ? AND remote_project_id = ?`,
		masterURL, remoteProjectID)
	state, err := scanSyncState(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return state, err
}

func (s *Store) SetSyncState(ctx context.Context, state domain.SyncState) error {
	if state.Role == "" {
		state.Role = "edge"
	}
	if state.UpdatedAt == "" {
		state.UpdatedAt = now()
	}
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		return setSyncStateTx(ctx, tx, state)
	})
}

func setSyncStateTx(ctx context.Context, tx *sql.Tx, state domain.SyncState) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO sync_state
			(local_project_id, remote_project_id, master_url, node_id, last_seq, role, token_cipher, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(local_project_id) DO UPDATE SET
			remote_project_id = excluded.remote_project_id,
			master_url = excluded.master_url,
			node_id = excluded.node_id,
			last_seq = excluded.last_seq,
			role = excluded.role,
			token_cipher = CASE
				WHEN excluded.token_cipher = '' THEN sync_state.token_cipher
				ELSE excluded.token_cipher
			END,
			updated_at = excluded.updated_at`,
		state.LocalProjectID, state.RemoteProjectID, state.MasterURL, state.NodeID,
		state.LastSeq, state.Role, state.TokenCipher, state.UpdatedAt)
	return err
}

func (s *Store) ListSyncStates(ctx context.Context) ([]domain.SyncState, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+syncStateColumns+` FROM sync_state ORDER BY updated_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var states []domain.SyncState
	for rows.Next() {
		state, err := scanSyncState(rows)
		if err != nil {
			return nil, err
		}
		states = append(states, *state)
	}
	return states, rows.Err()
}

func (s *Store) ListEdgeSyncStates(ctx context.Context) ([]domain.SyncState, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+syncStateColumns+` FROM sync_state WHERE role = 'edge' ORDER BY updated_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var states []domain.SyncState
	for rows.Next() {
		state, err := scanSyncState(rows)
		if err != nil {
			return nil, err
		}
		states = append(states, *state)
	}
	return states, rows.Err()
}

// ProjectSyncRole returns edge, master or standalone. Projects without a
// sync_state row are standalone.
func (s *Store) ProjectSyncRole(ctx context.Context, projectID string) (string, error) {
	var role string
	err := s.db.QueryRowContext(ctx,
		`SELECT role FROM sync_state WHERE local_project_id = ?`, projectID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "standalone", nil
	}
	if err != nil {
		return "", err
	}
	if role == "" {
		return "standalone", nil
	}
	return role, nil
}

func (s *Store) DeleteSyncState(ctx context.Context, projectID string) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`DELETE FROM sync_state WHERE local_project_id = ?`, projectID)
		return err
	})
}

// ResetProjectData removes the local replica data before a project is
// re-pointed at a different master. Detail rows cascade from entities.
func (s *Store) ResetProjectData(ctx context.Context, projectID string) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		return resetProjectDataTx(ctx, tx, projectID)
	})
}

func resetProjectDataTx(ctx context.Context, tx *sql.Tx, projectID string) error {
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM attack_edges WHERE project_id = ?`, projectID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM entities WHERE project_id = ?`, projectID); err != nil {
		return err
	}
	return nil
}

// AdvanceSyncSeq updates only the edge cursor. It never creates a sync_state
// row, so a concurrently deleted role cannot be resurrected by a pull.
func (s *Store) AdvanceSyncSeq(ctx context.Context, projectID, masterURL, remoteProjectID string, seq int) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE sync_state SET last_seq = ?, updated_at = ?
			 WHERE local_project_id = ? AND master_url = ? AND remote_project_id = ?`,
			seq, now(), projectID, masterURL, remoteProjectID)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// ClearSyncQueue removes pending outbox rows and conflict records when a
// project stops being an edge replica.
func (s *Store) ClearSyncQueue(ctx context.Context, projectID string) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		return clearSyncQueueTx(ctx, tx, projectID)
	})
}

func clearSyncQueueTx(ctx context.Context, tx *sql.Tx, projectID string) error {
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM sync_outbox WHERE project_id = ?`, projectID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx,
		`DELETE FROM sync_conflicts WHERE project_id = ?`, projectID)
	return err
}

// ---------- outbox ----------

func (s *Store) ListOutbox(ctx context.Context, projectID string, limit int) ([]domain.SyncOutbox, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, project_id, op, entity_type, entity_id, base_version, payload, created_at, attempts, last_error
		FROM sync_outbox WHERE project_id = ? ORDER BY created_at LIMIT ?`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.SyncOutbox
	for rows.Next() {
		var item domain.SyncOutbox
		var base sql.NullInt64
		var payload string
		if err := rows.Scan(&item.ID, &item.ProjectID, &item.Op, &item.EntityType,
			&item.EntityID, &base, &payload, &item.CreatedAt, &item.Attempts, &item.LastError); err != nil {
			return nil, err
		}
		if base.Valid {
			v := int(base.Int64)
			item.BaseVersion = &v
		}
		if err := json.Unmarshal([]byte(payload), &item.Payload); err != nil {
			item.Payload = payload
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) DeleteOutbox(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
		args := make([]any, len(ids))
		for i, id := range ids {
			args[i] = id
		}
		_, err := tx.ExecContext(ctx,
			`DELETE FROM sync_outbox WHERE id IN (`+placeholders+`)`, args...)
		return err
	})
}

func (s *Store) MarkOutboxError(ctx context.Context, id, message string) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE sync_outbox SET attempts = attempts + 1, last_error = ?
			WHERE id = ?`, message, id)
		return err
	})
}

func (s *Store) CountOutbox(ctx context.Context, projectID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sync_outbox WHERE project_id = ?`, projectID).Scan(&n)
	return n, err
}

// ---------- conflicts ----------

func (s *Store) RecordConflict(ctx context.Context, projectID, entityID, op, detail string) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO sync_conflicts (id, project_id, entity_id, op, detail, created_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			newID(), projectID, entityID, op, detail, now())
		return err
	})
}

func (s *Store) CountConflicts(ctx context.Context, projectID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sync_conflicts WHERE project_id = ?`, projectID).Scan(&n)
	return n, err
}

func (s *Store) ListConflicts(ctx context.Context, projectID string, limit int) ([]domain.SyncConflict, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT entity_id, op, detail FROM sync_conflicts
		WHERE project_id = ? ORDER BY created_at DESC LIMIT ?`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.SyncConflict
	for rows.Next() {
		var c domain.SyncConflict
		if err := rows.Scan(&c.EntityID, &c.Op, &c.Detail); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---------- applying master events on an edge ----------

func (s *Store) ApplySyncEvent(ctx context.Context, localProjectID, masterURL, remoteProjectID string, event domain.Event, localOwnerID string) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		switch event.Op {
		case "entity_upsert":
			var e domain.Entity
			if err := decodeSyncPayload(event.Payload, &e); err != nil {
				return err
			}
			e.ProjectID = localProjectID
			if err := applyEntityFromSyncTx(ctx, tx, localProjectID, localOwnerID, &e); err != nil {
				return err
			}
		case "entity_delete":
			var payload struct {
				EntityID string `json:"entity_id"`
				Version  int    `json:"version"`
			}
			if err := decodeSyncPayload(event.Payload, &payload); err != nil {
				return err
			}
			if payload.EntityID == "" {
				return fmt.Errorf("%w: sync entity_delete has no entity_id", ErrValidation)
			}
			if err := applyEntityDeleteFromSyncTx(ctx, tx, localProjectID, payload.EntityID, payload.Version); err != nil {
				return err
			}
		case "edge_upsert":
			var e domain.Edge
			if err := decodeSyncPayload(event.Payload, &e); err != nil {
				return err
			}
			e.ProjectID = localProjectID
			if err := applyEdgeFromSyncTx(ctx, tx, localProjectID, localOwnerID, &e); err != nil {
				return err
			}
		case "edge_delete":
			var payload struct {
				EdgeID string `json:"edge_id"`
			}
			if err := decodeSyncPayload(event.Payload, &payload); err != nil {
				return err
			}
			if payload.EdgeID == "" {
				return fmt.Errorf("%w: sync edge_delete has no edge_id", ErrValidation)
			}
			if _, err := tx.ExecContext(ctx, `
				UPDATE attack_edges SET deleted_at = ?
				WHERE project_id = ? AND id = ? AND deleted_at IS NULL`,
				now(), localProjectID, payload.EdgeID); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: unknown sync event op %q", ErrValidation, event.Op)
		}
		if event.Seq > 0 {
			var exists int
			if err := tx.QueryRowContext(ctx, `
				SELECT COUNT(*) FROM sync_state
				WHERE local_project_id = ? AND master_url = ? AND remote_project_id = ?`,
				localProjectID, masterURL, remoteProjectID).Scan(&exists); err != nil {
				return err
			}
			if exists == 0 {
				return ErrNotFound
			}
			// The state identity is the fence; an already-advanced cursor is fine
			// and must not roll back the event data.
			if _, err := tx.ExecContext(ctx, `
				UPDATE sync_state SET last_seq = ?, updated_at = ?
				WHERE local_project_id = ? AND master_url = ? AND remote_project_id = ? AND last_seq < ?`,
				event.Seq, now(), localProjectID, masterURL, remoteProjectID, event.Seq); err != nil {
				return err
			}
		}
		return nil
	})
}

func decodeSyncPayload(payload any, dst any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dst)
}

func applyEntityFromSyncTx(ctx context.Context, tx *sql.Tx, localProjectID, localOwnerID string, e *domain.Entity) error {
	if e.ID == "" {
		return fmt.Errorf("%w: synced entity has no id", ErrValidation)
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
		return err
	}

	var ip, hostname, osName, tags string
	if e.Kind == domain.KindTarget {
		var err error
		ip, hostname, osName, tags, err = targetFields(e.Data)
		if err != nil {
			return err
		}
		var otherID string
		err = tx.QueryRowContext(ctx, `
			SELECT entity_id FROM target_details
			WHERE project_id = ? AND ip = ? AND deleted_at IS NULL AND entity_id <> ?`,
			localProjectID, ip, e.ID).Scan(&otherID)
		if err == nil {
			// Master is authoritative: retire the local duplicate so the master
			// target can own this address.
			ts := now()
			if _, err := tx.ExecContext(ctx, `
				UPDATE entities SET deleted_at = ?, updated_at = ?
				WHERE project_id = ? AND id = ? AND deleted_at IS NULL`,
				ts, ts, localProjectID, otherID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx,
				`UPDATE target_details SET deleted_at = ? WHERE entity_id = ?`, ts, otherID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				UPDATE attack_edges SET deleted_at = ?
				WHERE project_id = ? AND (from_entity_id = ? OR to_entity_id = ?) AND deleted_at IS NULL`,
				ts, localProjectID, otherID, otherID); err != nil {
				return err
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}

	version := e.Version
	if version <= 0 {
		version = 1
	}

	var err error
	var existingVersion int
	var existingDataRaw string
	err = tx.QueryRowContext(ctx,
		`SELECT version, data FROM entities WHERE project_id = ? AND id = ?`,
		localProjectID, e.ID).Scan(&existingVersion, &existingDataRaw)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if exists && e.Kind == domain.KindFinding {
		var existingData map[string]any
		if existingDataRaw != "" {
			_ = json.Unmarshal([]byte(existingDataRaw), &existingData)
		}
		if history := mergePhaseHistory(existingData, e.Data); len(history) > 0 {
			e.Data["phase_history"] = history
		}
		if _, ok := e.Data["finding_key"]; !ok {
			if key, ok := existingData["finding_key"]; ok {
				e.Data["finding_key"] = key
			}
		}
	}
	dataJSON, err := json.Marshal(e.Data)
	if err != nil {
		return err
	}
	ts := now()
	if exists {
		if _, err := tx.ExecContext(ctx, `
			UPDATE entities
			SET kind = ?, title = ?, status = ?, phase = ?, data = ?, version = ?,
			    updated_by = ?, updated_at = ?, deleted_at = NULL
			WHERE project_id = ? AND id = ?`,
			e.Kind, e.Title, e.Status, e.Phase, string(dataJSON), version,
			localOwnerID, ts, localProjectID, e.ID); err != nil {
			return err
		}
	} else {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO entities
				(id, project_id, kind, title, status, phase, data, field_versions, version,
				 created_by, updated_by, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, '{}', ?, ?, ?, ?, ?)`,
			e.ID, localProjectID, e.Kind, e.Title, e.Status, e.Phase, string(dataJSON),
			version, localOwnerID, localOwnerID, ts, ts); err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: synced entity already exists", ErrConflict)
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
			e.ID, localProjectID, ip, hostname, osName, tags); err != nil {
			return err
		}
	} else {
		if _, err := tx.ExecContext(ctx, `DELETE FROM target_details WHERE entity_id = ?`, e.ID); err != nil {
			return err
		}
	}
	return nil
}

func applyEntityDeleteFromSyncTx(ctx context.Context, tx *sql.Tx, localProjectID, entityID string, version int) error {
	ts := now()
	versionExpr := "version"
	args := []any{ts, ts, localProjectID, entityID}
	if version > 0 {
		versionExpr = "?"
		args = []any{ts, ts, version, localProjectID, entityID}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE entities SET deleted_at = ?, updated_at = ?, version = `+versionExpr+`
		WHERE project_id = ? AND id = ? AND deleted_at IS NULL`, args...); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE target_details SET deleted_at = ? WHERE entity_id = ?`, ts, entityID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
		UPDATE attack_edges SET deleted_at = ?
		WHERE project_id = ? AND (from_entity_id = ? OR to_entity_id = ?) AND deleted_at IS NULL`,
		ts, localProjectID, entityID, entityID)
	return err
}

func applyEdgeFromSyncTx(ctx context.Context, tx *sql.Tx, localProjectID, localOwnerID string, e *domain.Edge) error {
	if e.ID == "" || e.FromEntityID == "" || e.ToEntityID == "" {
		return fmt.Errorf("%w: synced edge has missing fields", ErrValidation)
	}
	if e.FromEntityID == e.ToEntityID {
		return fmt.Errorf("%w: synced edge references itself", ErrValidation)
	}
	var n int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM entities
		WHERE project_id = ? AND deleted_at IS NULL AND id IN (?, ?)`,
		localProjectID, e.FromEntityID, e.ToEntityID).Scan(&n); err != nil {
		return err
	}
	if n != 2 {
		return fmt.Errorf("%w: synced edge endpoints are missing", ErrValidation)
	}
	var existing int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM attack_edges WHERE project_id = ? AND id = ?`,
		localProjectID, e.ID).Scan(&existing); err != nil {
		return err
	}
	if existing > 0 {
		_, err := tx.ExecContext(ctx, `
			UPDATE attack_edges SET label = ?, deleted_at = NULL
			WHERE project_id = ? AND id = ?`, e.Label, localProjectID, e.ID)
		return err
	}

	// Master is authoritative: retire a local edge with the same endpoints but
	// a different id before inserting the master edge.
	var otherID string
	err := tx.QueryRowContext(ctx, `
		SELECT id FROM attack_edges
		WHERE project_id = ? AND from_entity_id = ? AND to_entity_id = ?
		  AND deleted_at IS NULL AND id <> ?`,
		localProjectID, e.FromEntityID, e.ToEntityID, e.ID).Scan(&otherID)
	if err == nil {
		if _, err := tx.ExecContext(ctx, `
			UPDATE attack_edges SET deleted_at = ?
			WHERE project_id = ? AND id = ?`, now(), localProjectID, otherID); err != nil {
			return err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	createdAt := e.CreatedAt
	if createdAt == "" {
		createdAt = now()
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO attack_edges
			(id, project_id, from_entity_id, to_entity_id, label, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.ID, localProjectID, e.FromEntityID, e.ToEntityID, e.Label, localOwnerID, createdAt)
	return err
}

// ApplySnapshot seeds/refreshes a local edge project from a master snapshot.
func (s *Store) ApplySnapshot(ctx context.Context, localProjectID, localOwnerID string, snap *domain.SyncSnapshot) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		return applySnapshotTx(ctx, tx, localProjectID, localOwnerID, snap)
	})
}

func applySnapshotTx(ctx context.Context, tx *sql.Tx, localProjectID, localOwnerID string, snap *domain.SyncSnapshot) error {
	if _, err := tx.ExecContext(ctx, `
			UPDATE projects SET name = ?, description = ?, updated_at = ?
			WHERE id = ?`,
		snap.Project.Name, snap.Project.Description, now(), localProjectID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM project_phases WHERE project_id = ?`, localProjectID); err != nil {
		return err
	}
	if len(snap.Phases) == 0 {
		if err := insertDefaultPhasesTx(ctx, tx, localProjectID); err != nil {
			return err
		}
	} else {
		for _, ph := range snap.Phases {
			if _, err := tx.ExecContext(ctx, `
					INSERT INTO project_phases (project_id, key, name_en, name_zh, position, color)
					VALUES (?, ?, ?, ?, ?, ?)`,
				localProjectID, ph.Key, ph.NameEN, ph.NameZH, ph.Position, ph.Color); err != nil {
				return err
			}
		}
	}
	for i := range snap.Entities {
		e := snap.Entities[i]
		e.ProjectID = localProjectID
		if err := applyEntityFromSyncTx(ctx, tx, localProjectID, localOwnerID, &e); err != nil {
			return err
		}
	}
	for i := range snap.Edges {
		e := snap.Edges[i]
		e.ProjectID = localProjectID
		if err := applyEdgeFromSyncTx(ctx, tx, localProjectID, localOwnerID, &e); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `
			UPDATE sync_state SET last_seq = ?, updated_at = ?
			WHERE local_project_id = ?`,
		snap.LastSeq, now(), localProjectID); err != nil {
		return err
	}
	return nil
}

func (s *Store) ApplySnapshotWithState(ctx context.Context, localProjectID, localOwnerID string, snap *domain.SyncSnapshot, state domain.SyncState, reset bool) error {
	if state.Role == "" {
		state.Role = "edge"
	}
	if state.UpdatedAt == "" {
		state.UpdatedAt = now()
	}
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		if reset {
			if err := resetProjectDataTx(ctx, tx, localProjectID); err != nil {
				return err
			}
		}
		if err := applySnapshotTx(ctx, tx, localProjectID, localOwnerID, snap); err != nil {
			return err
		}
		if err := setSyncStateTx(ctx, tx, state); err != nil {
			return err
		}
		if reset {
			if err := clearSyncQueueTx(ctx, tx, localProjectID); err != nil {
				return err
			}
		}
		return nil
	})
}
