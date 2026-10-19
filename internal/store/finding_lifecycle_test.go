package store

import (
	"context"
	"errors"
	"testing"

	"shadowedge/internal/domain"
)

func phaseHistoryLen(t *testing.T, entity *domain.Entity) int {
	t.Helper()
	history, _ := entity.Data["phase_history"].([]any)
	return len(history)
}

func TestFindingLifecycleAndAssetRelations(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	admin := newTestUser(t, st, "admin", true)
	project, err := st.CreateProject(ctx, admin.ID, "Lifecycle", "")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	target, err := st.CreateEntity(ctx, project.ID, admin.ID, EntityInput{
		Kind: domain.KindTarget, Title: "host-1", Phase: "recon",
		Data: map[string]any{"ip": "10.10.0.10", "hostname": "host-1"},
	})
	if err != nil {
		t.Fatalf("CreateEntity target: %v", err)
	}
	service, err := st.CreateEntity(ctx, project.ID, admin.ID, EntityInput{
		Kind: domain.KindService, Title: "http-80", Phase: "scan",
		Data: map[string]any{"target_id": target.ID, "port": 80, "protocol": "tcp", "name": "http"},
	})
	if err != nil {
		t.Fatalf("CreateEntity service: %v", err)
	}

	finding, err := st.CreateEntity(ctx, project.ID, admin.ID, EntityInput{
		Kind: domain.KindFinding, Title: "SQL injection", Phase: "scan",
		Data: map[string]any{
			"service_id": service.ID, "vuln_type": "SQL Injection",
			"cve": "CVE-2026-0001", "severity": "high",
		},
	})
	if err != nil {
		t.Fatalf("CreateEntity finding: %v", err)
	}
	if finding.Merged {
		t.Fatal("first finding should not be marked merged")
	}
	if got := finding.Data["target_id"]; got != target.ID {
		t.Fatalf("service target was not derived on finding: %v", got)
	}
	if len(finding.Data["finding_key"].(string)) == 0 {
		t.Fatal("finding key was not set")
	}
	if got := phaseHistoryLen(t, finding); got != 1 {
		t.Fatalf("initial phase history = %d, want 1", got)
	}

	merged, err := st.CreateEntity(ctx, project.ID, admin.ID, EntityInput{
		Kind: domain.KindFinding, Title: "SQLi login", Phase: "initial_access",
		Data: map[string]any{
			"service_id": service.ID, "vuln_type": "SQL Injection",
			"cve": "CVE-2026-0001", "severity": "high", "endpoint": "/login",
		},
	})
	if err != nil {
		t.Fatalf("merge finding: %v", err)
	}
	if merged.ID != finding.ID || !merged.Merged {
		t.Fatalf("finding was not merged: old=%s new=%s merged=%v", finding.ID, merged.ID, merged.Merged)
	}
	if merged.Version != 2 || merged.Phase != "initial_access" {
		t.Fatalf("merged finding = version %d phase %q", merged.Version, merged.Phase)
	}
	if got := phaseHistoryLen(t, merged); got != 2 {
		t.Fatalf("phase history after merge = %d, want 2", got)
	}
	if got := merged.Data["endpoint"]; got != "/login" {
		t.Fatalf("merged endpoint = %v", got)
	}

	phase := "privesc"
	updated, err := st.UpdateEntity(ctx, project.ID, finding.ID, admin.ID, EntityPatch{Phase: &phase})
	if err != nil {
		t.Fatalf("update finding phase: %v", err)
	}
	if updated.Phase != "privesc" || phaseHistoryLen(t, updated) != 3 {
		t.Fatalf("updated lifecycle = phase %q history %d", updated.Phase, phaseHistoryLen(t, updated))
	}

	target2, err := st.CreateEntity(ctx, project.ID, admin.ID, EntityInput{
		Kind: domain.KindTarget, Title: "host-2", Phase: "recon",
		Data: map[string]any{"ip": "10.10.0.11"},
	})
	if err != nil {
		t.Fatalf("CreateEntity target2: %v", err)
	}
	other, err := st.CreateEntity(ctx, project.ID, admin.ID, EntityInput{
		Kind: domain.KindFinding, Title: "SQL injection", Phase: "scan",
		Data: map[string]any{
			"target_id": target2.ID, "vuln_type": "SQL Injection",
			"cve": "CVE-2026-0001", "severity": "high",
		},
	})
	if err != nil {
		t.Fatalf("CreateEntity other finding: %v", err)
	}
	if other.ID == finding.ID {
		t.Fatal("findings on different assets must have different identities")
	}

	if _, err := st.CreateEntity(ctx, project.ID, admin.ID, EntityInput{
		Kind: domain.KindFinding, Title: "bad relation", Phase: "scan",
		Data: map[string]any{"service_id": "missing", "vuln_type": "XSS"},
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid service relation error = %v, want validation", err)
	}

	if err := st.DeleteEntity(ctx, project.ID, target.ID, admin.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete target with dependents = %v, want conflict", err)
	}
	if err := st.DeleteEntity(ctx, project.ID, service.ID, admin.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete service with dependents = %v, want conflict", err)
	}
	if err := st.DeleteEntity(ctx, project.ID, finding.ID, admin.ID); err != nil {
		t.Fatalf("delete finding: %v", err)
	}
	revived, err := st.CreateEntity(ctx, project.ID, admin.ID, EntityInput{
		Kind: domain.KindFinding, Title: "SQL injection", Phase: "persistence",
		Data: map[string]any{
			"service_id": service.ID, "vuln_type": "SQL Injection",
			"cve": "CVE-2026-0001", "severity": "high",
		},
	})
	if err != nil {
		t.Fatalf("recreate finding after delete: %v", err)
	}
	if revived.ID != finding.ID || !revived.Merged {
		t.Fatalf("recreated finding = %s merged=%v, want %s", revived.ID, revived.Merged, finding.ID)
	}
	if revived.Phase != "persistence" || phaseHistoryLen(t, revived) != 4 {
		t.Fatalf("revived lifecycle = phase %q history %d", revived.Phase, phaseHistoryLen(t, revived))
	}
	if err := st.DeleteEntity(ctx, project.ID, revived.ID, admin.ID); err != nil {
		t.Fatalf("delete revived finding: %v", err)
	}
	if err := st.DeleteEntity(ctx, project.ID, service.ID, admin.ID); err != nil {
		t.Fatalf("delete service after findings: %v", err)
	}
	if err := st.DeleteEntity(ctx, project.ID, target.ID, admin.ID); err != nil {
		t.Fatalf("delete target after services: %v", err)
	}
}

func TestMergePhaseHistory(t *testing.T) {
	existing := map[string]any{"phase_history": []any{
		map[string]any{"phase": "scan", "status": "new", "at": "2026-10-19T10:00:00Z"},
	}}
	incoming := map[string]any{"phase_history": []any{
		map[string]any{"phase": "scan", "status": "new", "at": "2026-10-19T10:00:00Z"},
		map[string]any{"phase": "initial_access", "status": "confirmed", "at": "2026-10-19T11:00:00Z"},
	}}
	got := mergePhaseHistory(existing, incoming)
	if len(got) != 2 {
		t.Fatalf("merged history = %d, want 2: %+v", len(got), got)
	}
	first, _ := got[0].(map[string]any)
	second, _ := got[1].(map[string]any)
	if first["phase"] != "scan" || second["phase"] != "initial_access" {
		t.Fatalf("history order = %+v", got)
	}
}
