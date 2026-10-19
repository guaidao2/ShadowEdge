package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"shadowedge/internal/domain"
)

var targetAddressPattern = regexp.MustCompile(`^[0-9A-Za-z._:\-]{1,255}$`)

type EntityInput struct {
	Kind   domain.EntityKind   `json:"kind"`
	Title  string              `json:"title"`
	Status domain.EntityStatus `json:"status"`
	Phase  string              `json:"phase"`
	Data   map[string]any      `json:"data"`
}

type EntityPatch struct {
	Title       *string              `json:"title,omitempty"`
	Status      *domain.EntityStatus `json:"status,omitempty"`
	Phase       *string              `json:"phase,omitempty"`
	Data        *map[string]any      `json:"data,omitempty"`
	BaseVersion *int                 `json:"base_version,omitempty"`
}

const entityColumns = `id, project_id, kind, title, status, phase, data, version, created_by, updated_by, created_at, updated_at`

func scanEntity(scanner interface{ Scan(...any) error }) (*domain.Entity, error) {
	var e domain.Entity
	var data string
	err := scanner.Scan(&e.ID, &e.ProjectID, &e.Kind, &e.Title, &e.Status, &e.Phase,
		&data, &e.Version, &e.CreatedBy, &e.UpdatedBy, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if data == "" {
		data = "{}"
	}
	if err := json.Unmarshal([]byte(data), &e.Data); err != nil {
		return nil, fmt.Errorf("decode entity data: %w", err)
	}
	if e.Data == nil {
		e.Data = map[string]any{}
	}
	return &e, nil
}

func validatePhaseTx(ctx context.Context, tx *sql.Tx, projectID, phase string) error {
	var n int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM project_phases WHERE project_id = ? AND key = ?`,
		projectID, phase).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: unknown phase %q", ErrValidation, phase)
	}
	return nil
}

func validateEntityInput(kind domain.EntityKind, title string, status domain.EntityStatus) error {
	if !kind.Valid() {
		return fmt.Errorf("%w: invalid entity kind", ErrValidation)
	}
	if !status.Valid() {
		return fmt.Errorf("%w: invalid entity status", ErrValidation)
	}
	if strings.TrimSpace(title) == "" {
		return fmt.Errorf("%w: title is required", ErrValidation)
	}
	if len(title) > 200 {
		return fmt.Errorf("%w: title is too long", ErrValidation)
	}
	return nil
}

func targetFields(data map[string]any) (ip, hostname, osName, tags string, err error) {
	ip, _ = data["ip"].(string)
	ip = strings.TrimSpace(ip)
	if !targetAddressPattern.MatchString(ip) {
		return "", "", "", "", fmt.Errorf("%w: invalid target address", ErrValidation)
	}
	hostname, _ = data["hostname"].(string)
	osName, _ = data["os"].(string)
	switch v := data["tags"].(type) {
	case string:
		tags = v
	case nil:
		tags = ""
	default:
		b, _ := json.Marshal(v)
		tags = string(b)
	}
	return ip, hostname, osName, tags, nil
}

func (s *Store) CreateEntity(ctx context.Context, projectID, actorID string, in EntityInput) (*domain.Entity, error) {
	in.Title = strings.TrimSpace(in.Title)
	if in.Status == "" {
		in.Status = domain.StatusNew
	}
	in.Phase = domain.NormalizePhase(in.Phase)
	if in.Data == nil {
		in.Data = map[string]any{}
	}
	if err := validateEntityInput(in.Kind, in.Title, in.Status); err != nil {
		return nil, err
	}

	var out *domain.Entity
	err := s.withWrite(ctx, func(tx *sql.Tx) error {
		if err := validatePhaseTx(ctx, tx, projectID, in.Phase); err != nil {
			return err
		}
		id := newID()
		ts := now()
		dataJSON, err := json.Marshal(in.Data)
		if err != nil {
			return fmt.Errorf("%w: data is not valid JSON", ErrValidation)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO entities
				(id, project_id, kind, title, status, phase, data, field_versions, version,
				 created_by, updated_by, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, '{}', 1, ?, ?, ?, ?)`,
			id, projectID, in.Kind, in.Title, in.Status, in.Phase, string(dataJSON),
			actorID, actorID, ts, ts); err != nil {
			return err
		}

		if in.Kind == domain.KindTarget {
			ip, hostname, osName, tags, err := targetFields(in.Data)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO target_details (entity_id, project_id, ip, hostname, os, tags, deleted_at)
				VALUES (?, ?, ?, ?, ?, ?, NULL)`,
				id, projectID, ip, hostname, osName, tags); err != nil {
				if isUniqueViolation(err) {
					return fmt.Errorf("%w: target address already exists in this project", ErrConflict)
				}
				return err
			}
		}

		out = &domain.Entity{
			ID: id, ProjectID: projectID, Kind: in.Kind, Title: in.Title,
			Status: in.Status, Phase: in.Phase, Data: in.Data, Version: 1,
			CreatedBy: actorID, UpdatedBy: actorID, CreatedAt: ts, UpdatedAt: ts,
		}
		if err := s.appendEventTx(ctx, tx, projectID, actorID, "entity", id, "entity_upsert", nil, out); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, projectID, "entity_upsert", "entity", id, nil, out)
	})
	return out, err
}

func (s *Store) GetEntity(ctx context.Context, projectID, id string) (*domain.Entity, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+entityColumns+`
		FROM entities WHERE project_id = ? AND id = ? AND deleted_at IS NULL`, projectID, id)
	e, err := scanEntity(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

func (s *Store) ListEntities(ctx context.Context, projectID string, filter domain.EntityFilter) ([]domain.Entity, error) {
	query := `SELECT ` + entityColumns + ` FROM entities WHERE project_id = ? AND deleted_at IS NULL`
	args := []any{projectID}

	if filter.Kind != "" {
		query += ` AND kind = ?`
		args = append(args, filter.Kind)
	}
	if filter.Status != "" {
		query += ` AND status = ?`
		args = append(args, filter.Status)
	}
	if filter.Phase != "" {
		query += ` AND phase = ?`
		args = append(args, filter.Phase)
	}
	if filter.TargetID != "" {
		query += ` AND (id = ? OR json_extract(data, '$.target_id') = ?)`
		args = append(args, filter.TargetID, filter.TargetID)
	}
	if filter.Query != "" {
		like := "%" + filter.Query + "%"
		query += ` AND (title LIKE ? OR data LIKE ?)`
		args = append(args, like, like)
	}
	query += ` ORDER BY created_at`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entities []domain.Entity
	for rows.Next() {
		e, err := scanEntity(rows)
		if err != nil {
			return nil, err
		}
		entities = append(entities, *e)
	}
	return entities, rows.Err()
}

func (s *Store) UpdateEntity(ctx context.Context, projectID, id, actorID string, patch EntityPatch) (*domain.Entity, error) {
	var out *domain.Entity
	err := s.withWrite(ctx, func(tx *sql.Tx) error {
		var current domain.Entity
		var dataRaw string
		err := tx.QueryRowContext(ctx, `SELECT `+entityColumns+`
			FROM entities WHERE project_id = ? AND id = ? AND deleted_at IS NULL`,
			projectID, id).Scan(&current.ID, &current.ProjectID, &current.Kind, &current.Title,
			&current.Status, &current.Phase, &dataRaw, &current.Version, &current.CreatedBy,
			&current.UpdatedBy, &current.CreatedAt, &current.UpdatedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if patch.BaseVersion != nil && *patch.BaseVersion != current.Version {
			return fmt.Errorf("%w: entity version changed", ErrConflict)
		}
		if dataRaw == "" {
			dataRaw = "{}"
		}
		if err := json.Unmarshal([]byte(dataRaw), &current.Data); err != nil {
			return err
		}
		if current.Data == nil {
			current.Data = map[string]any{}
		}

		title := current.Title
		if patch.Title != nil {
			title = strings.TrimSpace(*patch.Title)
		}
		status := current.Status
		if patch.Status != nil {
			status = *patch.Status
		}
		phase := current.Phase
		if patch.Phase != nil {
			phase = domain.NormalizePhase(*patch.Phase)
		}
		data := current.Data
		if patch.Data != nil {
			data = *patch.Data
			if data == nil {
				data = map[string]any{}
			}
		}
		if err := validateEntityInput(current.Kind, title, status); err != nil {
			return err
		}
		if err := validatePhaseTx(ctx, tx, projectID, phase); err != nil {
			return err
		}

		dataJSON, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("%w: data is not valid JSON", ErrValidation)
		}
		ts := now()
		if _, err := tx.ExecContext(ctx, `
			UPDATE entities
			SET title = ?, status = ?, phase = ?, data = ?, version = version + 1,
			    updated_by = ?, updated_at = ?
			WHERE project_id = ? AND id = ? AND deleted_at IS NULL`,
			title, status, phase, string(dataJSON), actorID, ts, projectID, id); err != nil {
			return err
		}

		if current.Kind == domain.KindTarget {
			ip, hostname, osName, tags, err := targetFields(data)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				UPDATE target_details SET ip = ?, hostname = ?, os = ?, tags = ?
				WHERE entity_id = ? AND deleted_at IS NULL`,
				ip, hostname, osName, tags, id); err != nil {
				if isUniqueViolation(err) {
					return fmt.Errorf("%w: target address already exists in this project", ErrConflict)
				}
				return err
			}
		}

		baseVersion := current.Version
		current.Title, current.Status, current.Phase = title, status, phase
		current.Data = data
		current.Version++
		current.UpdatedBy = actorID
		current.UpdatedAt = ts
		out = &current
		if err := s.appendEventTx(ctx, tx, projectID, actorID, "entity", id, "entity_upsert", &baseVersion, out); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, projectID, "entity_upsert", "entity", id, &baseVersion, out)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) DeleteEntity(ctx context.Context, projectID, id, actorID string) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		var version int
		err := tx.QueryRowContext(ctx,
			`SELECT version FROM entities WHERE project_id = ? AND id = ? AND deleted_at IS NULL`,
			projectID, id).Scan(&version)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		ts := now()
		res, err := tx.ExecContext(ctx, `
			UPDATE entities SET deleted_at = ?, updated_at = ?
			WHERE project_id = ? AND id = ? AND deleted_at IS NULL`, ts, ts, projectID, id)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrNotFound
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE target_details SET deleted_at = ? WHERE entity_id = ?`, ts, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE attack_edges SET deleted_at = ?
			WHERE project_id = ? AND (from_entity_id = ? OR to_entity_id = ?) AND deleted_at IS NULL`,
			ts, projectID, id, id); err != nil {
			return err
		}
		payload := map[string]any{"entity_id": id}
		if err := s.appendEventTx(ctx, tx, projectID, actorID, "entity", id, "entity_delete", &version, payload); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, projectID, "entity_delete", "entity", id, &version, payload)
	})
}

// ---------- DAG ----------

func (s *Store) CreateEdge(ctx context.Context, projectID, actorID, from, to, label string) (*domain.Edge, error) {
	if from == to {
		return nil, fmt.Errorf("%w: cannot link an entity to itself", ErrValidation)
	}
	var out *domain.Edge
	err := s.withWrite(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM entities
			WHERE project_id = ? AND deleted_at IS NULL AND id IN (?, ?)`,
			projectID, from, to).Scan(&n); err != nil {
			return err
		}
		if n != 2 {
			return fmt.Errorf("%w: both entities must exist in this project", ErrValidation)
		}
		id := newID()
		ts := now()
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO attack_edges
				(id, project_id, from_entity_id, to_entity_id, label, created_by, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			id, projectID, from, to, label, actorID, ts); err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: this link already exists", ErrConflict)
			}
			return err
		}
		out = &domain.Edge{
			ID: id, ProjectID: projectID, FromEntityID: from, ToEntityID: to,
			Label: label, CreatedBy: actorID, CreatedAt: ts,
		}
		if err := s.appendEventTx(ctx, tx, projectID, actorID, "edge", id, "edge_upsert", nil, out); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, projectID, "edge_upsert", "edge", id, nil, out)
	})
	return out, err
}

func (s *Store) ListEdges(ctx context.Context, projectID string) ([]domain.Edge, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT e.id, e.project_id, e.from_entity_id, e.to_entity_id, e.label, e.created_by, e.created_at
		FROM attack_edges e
		JOIN entities f ON f.id = e.from_entity_id AND f.deleted_at IS NULL
		JOIN entities t ON t.id = e.to_entity_id AND t.deleted_at IS NULL
		WHERE e.project_id = ? AND e.deleted_at IS NULL
		ORDER BY e.created_at`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var edges []domain.Edge
	for rows.Next() {
		var e domain.Edge
		if err := rows.Scan(&e.ID, &e.ProjectID, &e.FromEntityID, &e.ToEntityID,
			&e.Label, &e.CreatedBy, &e.CreatedAt); err != nil {
			return nil, err
		}
		edges = append(edges, e)
	}
	return edges, rows.Err()
}

func (s *Store) DeleteEdge(ctx context.Context, projectID, edgeID, actorID string) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		ts := now()
		res, err := tx.ExecContext(ctx, `
			UPDATE attack_edges SET deleted_at = ?
			WHERE project_id = ? AND id = ? AND deleted_at IS NULL`, ts, projectID, edgeID)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrNotFound
		}
		payload := map[string]any{"edge_id": edgeID}
		if err := s.appendEventTx(ctx, tx, projectID, actorID, "edge", edgeID, "edge_delete", nil, payload); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, projectID, "edge_delete", "edge", edgeID, nil, payload)
	})
}

func (s *Store) Graph(ctx context.Context, projectID string) (*domain.Graph, error) {
	nodes, err := s.ListEntities(ctx, projectID, domain.EntityFilter{})
	if err != nil {
		return nil, err
	}
	edges, err := s.ListEdges(ctx, projectID)
	if err != nil {
		return nil, err
	}
	return &domain.Graph{Nodes: nodes, Edges: edges}, nil
}

// ---------- events ----------

func (s *Store) appendEventTx(ctx context.Context, tx *sql.Tx, projectID, actorID, entityType, entityID, op string, baseVersion *int, payload any) error {
	nodeID := "local"
	var stateNode string
	err := tx.QueryRowContext(ctx,
		`SELECT node_id FROM sync_state WHERE local_project_id = ?`, projectID).Scan(&stateNode)
	if err == nil && stateNode != "" {
		nodeID = stateNode
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return appendEventTx(ctx, tx, nodeID, projectID, actorID, entityType, entityID, op, baseVersion, payload)
}

func appendEventTx(ctx context.Context, tx *sql.Tx, nodeID, projectID, actorID, entityType, entityID, op string, baseVersion *int, payload any) error {
	var seq int
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(seq), 0) + 1 FROM events WHERE project_id = ?`, projectID).Scan(&seq); err != nil {
		return err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if payload == nil {
		body = []byte("null")
	}
	var base any
	if baseVersion != nil {
		base = *baseVersion
	}
	ts := now()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO events
			(project_id, seq, event_id, actor_id, node_id, entity_type, entity_id, op,
			 base_version, payload, hlc, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		projectID, seq, newID(), actorID, nodeID, entityType, entityID, op, base, string(body), ts, ts)
	return err
}

func (s *Store) ListEvents(ctx context.Context, projectID string, sinceSeq int) ([]domain.Event, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT project_id, seq, event_id, actor_id, node_id, entity_type, entity_id, op,
		       base_version, payload, hlc, created_at
		FROM events WHERE project_id = ? AND seq > ? ORDER BY seq`, projectID, sinceSeq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []domain.Event
	for rows.Next() {
		var e domain.Event
		var base sql.NullInt64
		var payload string
		if err := rows.Scan(&e.ProjectID, &e.Seq, &e.EventID, &e.ActorID, &e.NodeID,
			&e.EntityType, &e.EntityID, &e.Op, &base, &payload, &e.HLC, &e.CreatedAt); err != nil {
			return nil, err
		}
		if base.Valid {
			v := int(base.Int64)
			e.BaseVersion = &v
		}
		if err := json.Unmarshal([]byte(payload), &e.Payload); err != nil {
			e.Payload = payload
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

func (s *Store) LastEventSeq(ctx context.Context, projectID string) (int, error) {
	var seq int
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(seq), 0) FROM events WHERE project_id = ?`, projectID).Scan(&seq)
	return seq, err
}
