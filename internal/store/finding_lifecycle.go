package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"shadowedge/internal/domain"
)

var findingPhaseRanks = map[string]int{
	"recon": 0, "scan": 1, "initial_access": 2, "foothold": 3,
	"privesc": 4, "credential_access": 5, "lateral": 6, "persistence": 7,
	"collection": 8, "objective": 9, "reporting": 10,
}

func laterPhase(a, b string) string {
	if findingPhaseRanks[a] >= findingPhaseRanks[b] {
		return a
	}
	return b
}

// findingKey gives a finding a stable identity independent of the phase in
// which it was captured. The asset is part of the identity; CVE wins over
// type/title when present.
func findingKey(projectID, title string, data map[string]any) string {
	asset := ""
	if serviceID, _ := data["service_id"].(string); strings.TrimSpace(serviceID) != "" {
		asset = "service:" + strings.TrimSpace(serviceID)
	} else if targetID, _ := data["target_id"].(string); strings.TrimSpace(targetID) != "" {
		asset = "target:" + strings.TrimSpace(targetID)
	}
	if asset == "" {
		asset = "unattached:" + projectID
	}

	identity := ""
	if cve, _ := data["cve"].(string); strings.TrimSpace(cve) != "" {
		identity = "cve:" + strings.ToLower(strings.TrimSpace(cve))
	}
	if identity == "" {
		vulnType, _ := data["vuln_type"].(string)
		endpoint, _ := data["endpoint"].(string)
		parameter, _ := data["parameter"].(string)
		identity = "type:" + strings.ToLower(strings.TrimSpace(vulnType)) +
			"|title:" + strings.ToLower(strings.TrimSpace(title)) +
			"|endpoint:" + strings.ToLower(strings.TrimSpace(endpoint)) +
			"|parameter:" + strings.ToLower(strings.TrimSpace(parameter))
	}
	return asset + "|" + identity
}

func appendPhaseHistory(data map[string]any, phase string, status domain.EntityStatus, actorID, ts string) {
	raw, _ := data["phase_history"].([]any)
	entry := map[string]any{"phase": phase, "status": string(status), "at": ts, "by": actorID}
	if len(raw) > 0 {
		if last, ok := raw[len(raw)-1].(map[string]any); ok && last["phase"] == phase {
			last["status"] = string(status)
			last["at"] = ts
			last["by"] = actorID
			data["phase_history"] = raw
			return
		}
	}
	data["phase_history"] = append(raw, entry)
}

func mergeFindingData(existing, incoming map[string]any) map[string]any {
	out := make(map[string]any, len(existing)+len(incoming))
	for key, value := range existing {
		out[key] = value
	}
	for key, value := range incoming {
		if key == "finding_key" || key == "phase_history" {
			continue
		}
		if value == nil {
			continue
		}
		if text, ok := value.(string); ok && strings.TrimSpace(text) == "" {
			continue
		}
		out[key] = value
	}
	return out
}

func mergePhaseHistory(existing, incoming map[string]any) []any {
	seen := map[string]bool{}
	out := []any{}
	for _, source := range []map[string]any{existing, incoming} {
		raw, _ := source["phase_history"].([]any)
		for _, item := range raw {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			key := fmt.Sprintf("%v|%v|%v", entry["phase"], entry["status"], entry["at"])
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, item)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		left, _ := out[i].(map[string]any)
		right, _ := out[j].(map[string]any)
		return fmt.Sprint(left["at"]) < fmt.Sprint(right["at"])
	})
	return out
}

// validateRelationsTx keeps asset pointers honest: a service must exist, and a
// service must belong to the target it claims.
func validateRelationsTx(ctx context.Context, tx *sql.Tx, projectID string, kind domain.EntityKind, data map[string]any) error {
	if kind == domain.KindTarget {
		return nil
	}
	targetID, _ := data["target_id"].(string)
	targetID = strings.TrimSpace(targetID)
	serviceID, _ := data["service_id"].(string)
	serviceID = strings.TrimSpace(serviceID)

	if serviceID != "" {
		var serviceTarget string
		err := tx.QueryRowContext(ctx, `
			SELECT COALESCE(json_extract(data, '$.target_id'), '')
			FROM entities
			WHERE project_id = ? AND id = ? AND kind = 'service' AND deleted_at IS NULL`,
			projectID, serviceID).Scan(&serviceTarget)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: service not found in this project", ErrValidation)
		}
		if err != nil {
			return err
		}
		if targetID == "" {
			targetID = serviceTarget
			data["target_id"] = serviceTarget
		} else if serviceTarget != "" && targetID != serviceTarget {
			return fmt.Errorf("%w: service does not belong to target", ErrValidation)
		}
	}

	if targetID != "" {
		var count int
		if err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM entities
			WHERE project_id = ? AND id = ? AND kind = 'target' AND deleted_at IS NULL`,
			projectID, targetID).Scan(&count); err != nil {
			return err
		}
		if count == 0 {
			return fmt.Errorf("%w: target not found in this project", ErrValidation)
		}
		data["target_id"] = targetID
	}
	return nil
}

func loadEntityTx(ctx context.Context, tx *sql.Tx, projectID, id string) (*domain.Entity, error) {
	row := tx.QueryRowContext(ctx, `SELECT `+entityColumns+`
		FROM entities WHERE project_id = ? AND id = ? AND deleted_at IS NULL`, projectID, id)
	entity, err := scanEntity(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return entity, err
}

func loadEntityAnyTx(ctx context.Context, tx *sql.Tx, projectID, id string) (*domain.Entity, error) {
	row := tx.QueryRowContext(ctx, `SELECT `+entityColumns+`
		FROM entities WHERE project_id = ? AND id = ?`, projectID, id)
	entity, err := scanEntity(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return entity, err
}

// mergeFindingTx folds a new phase occurrence into an existing finding,
// including reviving a soft-deleted finding with the same deterministic ID.
func (s *Store) mergeFindingTx(ctx context.Context, tx *sql.Tx, projectID, actorID, existingID string, in EntityInput, key string) (*domain.Entity, error) {
	existing, err := loadEntityAnyTx(ctx, tx, projectID, existingID)
	if err != nil {
		return nil, err
	}
	baseVersion := existing.Version
	data := mergeFindingData(existing.Data, in.Data)
	data["finding_key"] = key

	status := in.Status
	if status == domain.StatusNew && existing.Status != domain.StatusNew {
		status = existing.Status
	}
	phase := laterPhase(in.Phase, existing.Phase)
	ts := now()
	appendPhaseHistory(data, in.Phase, status, actorID, ts)

	dataJSON, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("%w: data is not valid JSON", ErrValidation)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE entities
		SET title = ?, status = ?, phase = ?, data = ?, version = version + 1,
		    updated_by = ?, updated_at = ?, deleted_at = NULL
		WHERE project_id = ? AND id = ?`,
		in.Title, status, phase, string(dataJSON), actorID, ts, projectID, existingID); err != nil {
		return nil, err
	}

	existing.Title = in.Title
	existing.Status = status
	existing.Phase = phase
	existing.Data = data
	existing.Version = baseVersion + 1
	existing.UpdatedBy = actorID
	existing.UpdatedAt = ts
	existing.Merged = true

	payload := *existing
	payload.Merged = false
	if err := s.appendEventTx(ctx, tx, projectID, actorID, "entity", existingID, "entity_upsert", &baseVersion, &payload); err != nil {
		return nil, err
	}
	if err := s.appendOutboxTx(ctx, tx, projectID, "entity_upsert", "entity", existingID, &baseVersion, &payload); err != nil {
		return nil, err
	}
	return existing, nil
}
