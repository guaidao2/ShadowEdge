package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"shadowedge/internal/domain"
)

func TestSyncFenceAndAtomicSnapshotReset(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "sync.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	owner, err := st.CreateUser(ctx, "fence-owner", "Fence Owner", "hash", "en", false)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	project, err := st.CreateProject(ctx, owner.ID, "Fence Project", "")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if err := st.SetSyncState(ctx, domain.SyncState{
		LocalProjectID: project.ID, RemoteProjectID: "remote-old",
		MasterURL: "http://old-master", NodeID: "edge-1", Role: "edge", LastSeq: 10,
	}); err != nil {
		t.Fatalf("SetSyncState: %v", err)
	}

	event := domain.Event{
		Seq: 10, Op: "entity_upsert", EntityID: "synced-target",
		Payload: map[string]any{
			"id": "synced-target", "kind": domain.KindTarget, "title": "synced-target",
			"status": domain.StatusNew, "phase": "recon", "version": 1,
			"data": map[string]any{"ip": "10.0.0.10"},
		},
	}

	// An event from a different master must be rejected and rolled back.
	if err := st.ApplySyncEvent(ctx, project.ID, "http://new-master", "remote-new", event, owner.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong-master apply = %v, want ErrNotFound", err)
	}
	if _, err := st.GetEntity(ctx, project.ID, "synced-target"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong-master event left an entity: %v", err)
	}

	// The same master is allowed even when the cursor is already at that seq;
	// the event data must not be rolled back.
	if err := st.ApplySyncEvent(ctx, project.ID, "http://old-master", "remote-old", event, owner.ID); err != nil {
		t.Fatalf("same-master apply: %v", err)
	}
	if _, err := st.GetEntity(ctx, project.ID, "synced-target"); err != nil {
		t.Fatalf("same-master event was not applied: %v", err)
	}

	local, err := st.CreateEntity(ctx, project.ID, owner.ID, EntityInput{
		Kind: domain.KindTarget, Title: "local-only", Phase: "recon",
		Data: map[string]any{"ip": "10.0.0.20"},
	})
	if err != nil {
		t.Fatalf("CreateEntity: %v", err)
	}

	snap := &domain.SyncSnapshot{
		Project: domain.Project{ID: project.ID, Name: "New Master"},
		LastSeq: 0,
	}
	state := domain.SyncState{
		LocalProjectID: project.ID, RemoteProjectID: "remote-new",
		MasterURL: "http://new-master", NodeID: "edge-1", Role: "edge", LastSeq: 0,
	}
	if err := st.ApplySnapshotWithState(ctx, project.ID, owner.ID, snap, state, true); err != nil {
		t.Fatalf("ApplySnapshotWithState: %v", err)
	}
	if _, err := st.GetEntity(ctx, project.ID, local.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("re-point reset kept local entity: %v", err)
	}
	got, err := st.GetSyncState(ctx, project.ID)
	if err != nil {
		t.Fatalf("GetSyncState: %v", err)
	}
	if got.MasterURL != "http://new-master" || got.RemoteProjectID != "remote-new" || got.Role != "edge" {
		t.Fatalf("sync state after reset = %+v", got)
	}
}
