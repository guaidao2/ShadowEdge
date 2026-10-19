package edgesync_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"shadowedge/internal/auth"
	"shadowedge/internal/config"
	"shadowedge/internal/domain"
	"shadowedge/internal/edgesync"
	"shadowedge/internal/httpapi"
	"shadowedge/internal/store"
	"shadowedge/internal/syncsecret"
)

func openSyncStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "sync.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, dir
}

func createSyncUser(t *testing.T, st *store.Store, username string) *domain.User {
	t.Helper()
	hash, err := auth.HashPassword("sync-password-123")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user, err := st.CreateUser(context.Background(), username, username, hash, "en", true)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

func TestMasterEdgeBidirectionalSyncAndConflict(t *testing.T) {
	ctx := context.Background()

	master, _ := openSyncStore(t)
	masterAdmin := createSyncUser(t, master, "master-admin")
	masterProject, err := master.CreateProject(ctx, masterAdmin.ID, "Master Project", "")
	if err != nil {
		t.Fatalf("create master project: %v", err)
	}
	token, _, err := master.CreateAPIToken(ctx, masterAdmin.ID, "sync", "read,write", masterProject.ID, "")
	if err != nil {
		t.Fatalf("create sync token: %v", err)
	}

	cfg := config.Config{
		DataDir: t.TempDir(), DBPath: filepath.Join(t.TempDir(), "api.db"),
		SessionTTL: time.Hour, MaxUploadBytes: 10 << 20,
	}
	api, err := httpapi.New(cfg, master)
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	server := httptest.NewServer(api.Handler())
	defer server.Close()

	snapshot, err := edgesync.FetchSnapshot(ctx, server.URL, masterProject.ID, token)
	if err != nil {
		t.Fatalf("FetchSnapshot: %v", err)
	}
	if snapshot.Project.ID != masterProject.ID {
		t.Fatalf("snapshot project = %q", snapshot.Project.ID)
	}

	edge, edgeDataDir := openSyncStore(t)
	edgeAdmin := createSyncUser(t, edge, "edge-admin")
	edgeProject, err := edge.CreateProject(ctx, edgeAdmin.ID, "Edge Project", "")
	if err != nil {
		t.Fatalf("create edge project: %v", err)
	}
	key, err := syncsecret.LoadOrCreateKey(edgeDataDir)
	if err != nil {
		t.Fatalf("load sync key: %v", err)
	}
	cipher, err := syncsecret.Encrypt(key, token)
	if err != nil {
		t.Fatalf("encrypt sync token: %v", err)
	}
	if err := edge.SetSyncState(ctx, domain.SyncState{
		LocalProjectID: edgeProject.ID, RemoteProjectID: masterProject.ID,
		MasterURL: server.URL, NodeID: "edge-1", Role: "edge", LastSeq: 0,
		TokenCipher: cipher,
	}); err != nil {
		t.Fatalf("SetSyncState: %v", err)
	}
	syncer := edgesync.NewManager(edge, edgeDataDir, 10*time.Millisecond)

	// Master -> edge.
	masterTarget, err := master.CreateEntity(ctx, masterProject.ID, masterAdmin.ID, store.EntityInput{
		Kind: domain.KindTarget, Title: "dc01", Phase: "recon",
		Data: map[string]any{"ip": "10.0.0.10", "hostname": "dc01"},
	})
	if err != nil {
		t.Fatalf("master create target: %v", err)
	}
	if err := syncer.SyncOnce(ctx); err != nil {
		t.Fatalf("sync master->edge: %v", err)
	}
	pulled, err := edge.GetEntity(ctx, edgeProject.ID, masterTarget.ID)
	if err != nil {
		t.Fatalf("edge target missing: %v", err)
	}
	if pulled.Title != "dc01" || pulled.Version != 1 {
		t.Fatalf("edge target = %+v", pulled)
	}

	// Edge -> master.
	edgeService, err := edge.CreateEntity(ctx, edgeProject.ID, edgeAdmin.ID, store.EntityInput{
		Kind: domain.KindService, Title: "80/tcp http", Phase: "scan",
		Data: map[string]any{"target_id": masterTarget.ID, "port": 80, "protocol": "tcp", "name": "http"},
	})
	if err != nil {
		t.Fatalf("edge create service: %v", err)
	}
	if pending, err := edge.CountOutbox(ctx, edgeProject.ID); err != nil || pending != 1 {
		t.Fatalf("outbox before sync = %d, err = %v", pending, err)
	}
	if err := syncer.SyncOnce(ctx); err != nil {
		t.Fatalf("sync edge->master: %v", err)
	}
	pushed, err := master.GetEntity(ctx, masterProject.ID, edgeService.ID)
	if err != nil {
		t.Fatalf("master service missing: %v", err)
	}
	if pushed.Title != "80/tcp http" {
		t.Fatalf("master service = %+v", pushed)
	}
	if pending, err := edge.CountOutbox(ctx, edgeProject.ID); err != nil || pending != 0 {
		t.Fatalf("outbox after sync = %d, err = %v", pending, err)
	}

	// Master edge upsert/delete replicates to the edge.
	masterEdge, err := master.CreateEdge(ctx, masterProject.ID, masterAdmin.ID, masterTarget.ID, edgeService.ID, "exposes")
	if err != nil {
		t.Fatalf("master create edge: %v", err)
	}
	if err := syncer.SyncOnce(ctx); err != nil {
		t.Fatalf("sync master edge: %v", err)
	}
	edgeEdges, err := edge.ListEdges(ctx, edgeProject.ID)
	if err != nil || len(edgeEdges) != 1 {
		t.Fatalf("edge edges = %d, err = %v", len(edgeEdges), err)
	}
	if err := master.DeleteEdge(ctx, masterProject.ID, masterEdge.ID, masterAdmin.ID); err != nil {
		t.Fatalf("master delete edge: %v", err)
	}
	if err := syncer.SyncOnce(ctx); err != nil {
		t.Fatalf("sync edge delete: %v", err)
	}
	edgeEdges, err = edge.ListEdges(ctx, edgeProject.ID)
	if err != nil || len(edgeEdges) != 0 {
		t.Fatalf("edge edges after delete = %d, err = %v", len(edgeEdges), err)
	}

	// A master delete must not be resurrected by a stale edge update.
	if err := master.DeleteEntity(ctx, masterProject.ID, edgeService.ID, masterAdmin.ID); err != nil {
		t.Fatalf("master delete service: %v", err)
	}
	staleTitle := "stale-service"
	staleBase := edgeService.Version
	if _, err := edge.UpdateEntity(ctx, edgeProject.ID, edgeService.ID, edgeAdmin.ID,
		store.EntityPatch{Title: &staleTitle, BaseVersion: &staleBase}); err != nil {
		t.Fatalf("edge stale update: %v", err)
	}
	if err := syncer.SyncOnce(ctx); err != nil {
		t.Fatalf("sync delete conflict: %v", err)
	}
	if _, err := master.GetEntity(ctx, masterProject.ID, edgeService.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted master entity revived: %v", err)
	}
	if _, err := edge.GetEntity(ctx, edgeProject.ID, edgeService.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted edge entity not removed: %v", err)
	}

	// Concurrent updates: master is authoritative.
	titleV2 := "master-v2"
	titleV3 := "master-v3"
	if _, err := master.UpdateEntity(ctx, masterProject.ID, masterTarget.ID, masterAdmin.ID,
		store.EntityPatch{Title: &titleV2}); err != nil {
		t.Fatalf("master update v2: %v", err)
	}
	if _, err := master.UpdateEntity(ctx, masterProject.ID, masterTarget.ID, masterAdmin.ID,
		store.EntityPatch{Title: &titleV3}); err != nil {
		t.Fatalf("master update v3: %v", err)
	}

	edgeTitle := "edge-edit"
	base := pulled.Version // 1, stale against master version 3
	if _, err := edge.UpdateEntity(ctx, edgeProject.ID, masterTarget.ID, edgeAdmin.ID,
		store.EntityPatch{Title: &edgeTitle, BaseVersion: &base}); err != nil {
		t.Fatalf("edge update: %v", err)
	}
	if err := syncer.SyncOnce(ctx); err != nil {
		t.Fatalf("sync conflict: %v", err)
	}
	conflicts, err := edge.CountConflicts(ctx, edgeProject.ID)
	if err != nil {
		t.Fatalf("CountConflicts: %v", err)
	}
	if conflicts == 0 {
		t.Fatal("expected a recorded conflict")
	}
	masterNow, err := master.GetEntity(ctx, masterProject.ID, masterTarget.ID)
	if err != nil {
		t.Fatalf("master target after conflict: %v", err)
	}
	if masterNow.Title != titleV3 {
		t.Fatalf("master target title = %q, want %q", masterNow.Title, titleV3)
	}
	edgeNow, err := edge.GetEntity(ctx, edgeProject.ID, masterTarget.ID)
	if err != nil {
		t.Fatalf("edge target after conflict: %v", err)
	}
	if edgeNow.Title != titleV3 {
		t.Fatalf("edge target title = %q, want master %q", edgeNow.Title, titleV3)
	}

	// Snapshot can seed a fresh edge replica.
	snapshot, err = edgesync.FetchSnapshot(ctx, server.URL, masterProject.ID, token)
	if err != nil {
		t.Fatalf("FetchSnapshot after sync: %v", err)
	}
	fresh, _ := openSyncStore(t)
	freshAdmin := createSyncUser(t, fresh, "fresh-admin")
	freshProject, err := fresh.CreateProject(ctx, freshAdmin.ID, "Fresh", "")
	if err != nil {
		t.Fatalf("create fresh project: %v", err)
	}
	if err := fresh.ApplySnapshot(ctx, freshProject.ID, freshAdmin.ID, snapshot); err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	if _, err := fresh.GetEntity(ctx, freshProject.ID, masterTarget.ID); err != nil {
		t.Fatalf("snapshot target missing: %v", err)
	}
}

func TestManagerWebSocketTriggersImmediateSync(t *testing.T) {
	ctx := context.Background()

	master, _ := openSyncStore(t)
	masterAdmin := createSyncUser(t, master, "ws-master-admin")
	masterProject, err := master.CreateProject(ctx, masterAdmin.ID, "WS Master", "")
	if err != nil {
		t.Fatalf("create master project: %v", err)
	}
	token, _, err := master.CreateAPIToken(ctx, masterAdmin.ID, "ws-sync", "read,write", masterProject.ID, "")
	if err != nil {
		t.Fatalf("create sync token: %v", err)
	}

	cfg := config.Config{
		DataDir: t.TempDir(), DBPath: filepath.Join(t.TempDir(), "api.db"),
		SessionTTL: time.Hour, MaxUploadBytes: 10 << 20,
	}
	api, err := httpapi.New(cfg, master)
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	server := httptest.NewServer(api.Handler())
	defer server.Close()

	edge, edgeDataDir := openSyncStore(t)
	edgeAdmin := createSyncUser(t, edge, "ws-edge-admin")
	edgeProject, err := edge.CreateProject(ctx, edgeAdmin.ID, "WS Edge", "")
	if err != nil {
		t.Fatalf("create edge project: %v", err)
	}
	key, err := syncsecret.LoadOrCreateKey(edgeDataDir)
	if err != nil {
		t.Fatalf("load sync key: %v", err)
	}
	cipher, err := syncsecret.Encrypt(key, token)
	if err != nil {
		t.Fatalf("encrypt sync token: %v", err)
	}
	if err := edge.SetSyncState(ctx, domain.SyncState{
		LocalProjectID: edgeProject.ID, RemoteProjectID: masterProject.ID,
		MasterURL: server.URL, NodeID: "ws-edge-1", Role: "edge", TokenCipher: cipher,
	}); err != nil {
		t.Fatalf("SetSyncState: %v", err)
	}

	runCtx, stop := context.WithCancel(context.Background())
	defer stop()
	manager := edgesync.NewManager(edge, edgeDataDir, time.Hour)
	go manager.Run(runCtx)
	time.Sleep(500 * time.Millisecond)

	target, err := master.CreateEntity(ctx, masterProject.ID, masterAdmin.ID, store.EntityInput{
		Kind: domain.KindTarget, Title: "ws-target", Phase: "recon",
		Data: map[string]any{"ip": "10.0.0.99"},
	})
	if err != nil {
		t.Fatalf("master create target: %v", err)
	}
	api.NotifyProject(masterProject.ID)

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		if _, err := edge.GetEntity(waitCtx, edgeProject.ID, target.ID); err == nil {
			return
		}
		select {
		case <-waitCtx.Done():
			t.Fatalf("edge did not receive WebSocket-triggered entity: %v", waitCtx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}
