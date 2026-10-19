package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"shadowedge/internal/auth"
	"shadowedge/internal/domain"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	st, err := Open(context.Background(), filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func newTestUser(t *testing.T, st *Store, username string, admin bool) *domain.User {
	t.Helper()
	hash, err := auth.HashPassword("test-password-123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	u, err := st.CreateUser(context.Background(), username, username, hash, "en", admin)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

func TestMigrationsAndBootstrap(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	var tables int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'registration_requests'`).Scan(&tables); err != nil {
		t.Fatalf("query schema: %v", err)
	}
	if tables != 1 {
		t.Fatal("migration did not create registration_requests")
	}

	hash, _ := auth.HashPassword("bootstrap-password")
	created, err := st.EnsureBootstrapAdmin(ctx, "admin", hash)
	if err != nil {
		t.Fatalf("EnsureBootstrapAdmin: %v", err)
	}
	if !created {
		t.Fatal("expected bootstrap admin to be created")
	}
	created, err = st.EnsureBootstrapAdmin(ctx, "admin", hash)
	if err != nil {
		t.Fatalf("second EnsureBootstrapAdmin: %v", err)
	}
	if created {
		t.Fatal("expected bootstrap admin to be idempotent")
	}
}

func TestRegistrationApprovalFlow(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	admin := newTestUser(t, st, "admin", true)

	hash, _ := auth.HashPassword("applicant-password")
	reg, err := st.CreateRegistration(ctx, "coolmoon", "Cool Moon", hash, "cool@example.com", "red team")
	if err != nil {
		t.Fatalf("CreateRegistration: %v", err)
	}
	if reg.Status != domain.RegistrationPending {
		t.Fatalf("status = %q", reg.Status)
	}
	if _, err := st.GetUserByUsername(ctx, "coolmoon"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pending applicant should not be a user, got %v", err)
	}

	user, err := st.ReviewRegistration(ctx, reg.ID, admin.ID, true)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if user == nil || user.Username != "coolmoon" || user.IsPlatformAdmin {
		t.Fatalf("unexpected approved user: %+v", user)
	}
	if _, err := st.ReviewRegistration(ctx, reg.ID, admin.ID, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("second review error = %v, want conflict", err)
	}
}

func TestProjectEntityBoardAndGraph(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	owner := newTestUser(t, st, "guaidao2", false)

	project, err := st.CreateProject(ctx, owner.ID, "Lab", "internal lab")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	phases, err := st.ListPhases(ctx, project.ID)
	if err != nil {
		t.Fatalf("ListPhases: %v", err)
	}
	if len(phases) != len(domain.DefaultPhases) {
		t.Fatalf("phases = %d, want %d", len(phases), len(domain.DefaultPhases))
	}

	target, err := st.CreateEntity(ctx, project.ID, owner.ID, EntityInput{
		Kind: domain.KindTarget, Title: "dc01", Phase: "recon",
		Data: map[string]any{"ip": "10.0.0.10", "hostname": "dc01"},
	})
	if err != nil {
		t.Fatalf("CreateEntity target: %v", err)
	}
	if _, err := st.CreateEntity(ctx, project.ID, owner.ID, EntityInput{
		Kind: domain.KindTarget, Title: "duplicate", Phase: "recon",
		Data: map[string]any{"ip": "10.0.0.10"},
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate target error = %v, want conflict", err)
	}

	service, err := st.CreateEntity(ctx, project.ID, owner.ID, EntityInput{
		Kind: domain.KindService, Title: "80/tcp http", Phase: "scan",
		Data: map[string]any{"target_id": target.ID, "port": float64(80), "service": "http"},
	})
	if err != nil {
		t.Fatalf("CreateEntity service: %v", err)
	}

	board, err := st.Board(ctx, project.ID)
	if err != nil {
		t.Fatalf("Board: %v", err)
	}
	if len(board) != len(domain.DefaultPhases) {
		t.Fatalf("board columns = %d", len(board))
	}
	var scanColumn *domain.BoardColumn
	for i := range board {
		if board[i].Phase.Key == "scan" {
			scanColumn = &board[i]
			break
		}
	}
	if scanColumn == nil || len(scanColumn.Entities) != 1 {
		t.Fatalf("scan column = %+v, want 1 entity", scanColumn)
	}

	filtered, err := st.ListEntities(ctx, project.ID, domain.EntityFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("ListEntities target filter: %v", err)
	}
	if len(filtered) != 2 {
		t.Fatalf("target filter returned %d entities, want 2", len(filtered))
	}

	edge, err := st.CreateEdge(ctx, project.ID, owner.ID, target.ID, service.ID, "exposes")
	if err != nil {
		t.Fatalf("CreateEdge: %v", err)
	}
	if _, err := st.CreateEdge(ctx, project.ID, owner.ID, target.ID, service.ID, "again"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate edge error = %v, want conflict", err)
	}
	if _, err := st.CreateEdge(ctx, project.ID, owner.ID, target.ID, target.ID, "self"); !errors.Is(err, ErrValidation) {
		t.Fatalf("self edge error = %v, want validation", err)
	}

	graph, err := st.Graph(ctx, project.ID)
	if err != nil {
		t.Fatalf("Graph: %v", err)
	}
	if len(graph.Nodes) != 2 || len(graph.Edges) != 1 {
		t.Fatalf("graph = %d nodes, %d edges", len(graph.Nodes), len(graph.Edges))
	}

	events, err := st.ListEvents(ctx, project.ID, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) < 3 {
		t.Fatalf("events = %d, want at least 3", len(events))
	}

	if err := st.DeleteEntity(ctx, project.ID, service.ID, owner.ID); err != nil {
		t.Fatalf("DeleteEntity: %v", err)
	}
	graph, err = st.Graph(ctx, project.ID)
	if err != nil {
		t.Fatalf("Graph after delete: %v", err)
	}
	if len(graph.Nodes) != 1 || len(graph.Edges) != 0 {
		t.Fatalf("graph after delete = %d nodes, %d edges", len(graph.Nodes), len(graph.Edges))
	}

	if err := st.DeleteEdge(ctx, project.ID, edge.ID, owner.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting already-cascaded edge error = %v, want not found", err)
	}
}

func TestSessionsAndLocales(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	user := newTestUser(t, st, "session-user", false)

	sess, err := st.CreateSession(ctx, user.ID, auth.HashToken("token-1"), "csrf-1", "2999-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, gotUser, err := st.GetSessionByTokenHash(ctx, auth.HashToken("token-1"))
	if err != nil {
		t.Fatalf("GetSessionByTokenHash: %v", err)
	}
	if got.ID != sess.ID || gotUser.ID != user.ID {
		t.Fatalf("unexpected session/user: %+v %+v", got, gotUser)
	}
	if _, _, err := st.GetSessionByTokenHash(ctx, auth.HashToken("wrong")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong token error = %v", err)
	}

	if err := st.UpdateUserLocale(ctx, user.ID, "zh-CN"); err != nil {
		t.Fatalf("UpdateUserLocale: %v", err)
	}
	updated, err := st.GetUserByID(ctx, user.ID)
	if err != nil || updated.Locale != "zh-CN" {
		t.Fatalf("locale = %q, err = %v", updated.Locale, err)
	}

	if err := st.SetUserStatus(ctx, user.ID, domain.UserDisabled); err != nil {
		t.Fatalf("SetUserStatus: %v", err)
	}
	if _, _, err := st.GetSessionByTokenHash(ctx, auth.HashToken("token-1")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled user session error = %v, want not found", err)
	}
}

func TestAPITokenLifecycle(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	user := newTestUser(t, st, "token-user", false)
	project, err := st.CreateProject(ctx, user.ID, "Token project", "")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	token, meta, err := st.CreateAPIToken(ctx, user.ID, "mcp", "read,write", project.ID, "")
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	got, gotUser, err := st.GetAPITokenByHash(ctx, auth.HashToken(token))
	if err != nil {
		t.Fatalf("GetAPITokenByHash: %v", err)
	}
	if got.ID != meta.ID || got.ProjectID != project.ID || gotUser.ID != user.ID {
		t.Fatalf("unexpected token/user: %+v %+v", got, gotUser)
	}
	if tokens, err := st.ListAPITokens(ctx, user.ID, project.ID); err != nil || len(tokens) != 1 {
		t.Fatalf("project token list = %d, err = %v", len(tokens), err)
	}
	if tokens, err := st.ListAPITokens(ctx, user.ID, "other-project"); err != nil || len(tokens) != 0 {
		t.Fatalf("foreign project token list = %d, err = %v", len(tokens), err)
	}
	if err := st.DeleteAPIToken(ctx, user.ID, meta.ID, "other-project"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign project delete error = %v, want not found", err)
	}
	if err := st.DeleteAPIToken(ctx, user.ID, meta.ID, project.ID); err != nil {
		t.Fatalf("DeleteAPIToken: %v", err)
	}
	if _, _, err := st.GetAPITokenByHash(ctx, auth.HashToken(token)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked token error = %v, want not found", err)
	}
	if _, meta2, err := st.CreateAPIToken(ctx, user.ID, "second", "read", project.ID, ""); err != nil {
		t.Fatalf("CreateAPIToken second: %v", err)
	} else if err := st.DeleteAPIToken(ctx, user.ID, meta2.ID, "other-project"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign project delete error = %v, want not found", err)
	} else if err := st.DeleteAPIToken(ctx, user.ID, meta2.ID, project.ID); err != nil {
		t.Fatalf("DeleteAPIToken second: %v", err)
	}
	if _, _, err := st.CreateAPIToken(ctx, user.ID, "bad-scope", "wirte", "", ""); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid scope error = %v, want validation", err)
	}
	if _, _, err := st.CreateAPIToken(ctx, user.ID, "bad-expiry", "read", "", "not-a-date"); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid expiry error = %v, want validation", err)
	}
	if _, _, err := st.CreateAPIToken(ctx, user.ID, "past-expiry", "read", "", "2000-01-01T00:00:00Z"); !errors.Is(err, ErrValidation) {
		t.Fatalf("past expiry error = %v, want validation", err)
	}
}

func TestUpdateEntityVersioning(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	owner := newTestUser(t, st, "updater", false)
	project, err := st.CreateProject(ctx, owner.ID, "Update", "")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	target, err := st.CreateEntity(ctx, project.ID, owner.ID, EntityInput{
		Kind: domain.KindTarget, Title: "dc01", Phase: "recon",
		Data: map[string]any{"ip": "10.0.0.10"},
	})
	if err != nil {
		t.Fatalf("CreateEntity: %v", err)
	}

	newTitle := "dc01-updated"
	newPhase := "scan"
	newData := map[string]any{"ip": "10.0.0.10", "hostname": "dc01"}
	base := target.Version
	updated, err := st.UpdateEntity(ctx, project.ID, target.ID, owner.ID, EntityPatch{
		Title: &newTitle, Phase: &newPhase, Data: &newData, BaseVersion: &base,
	})
	if err != nil {
		t.Fatalf("UpdateEntity: %v", err)
	}
	if updated.Version != 2 || updated.Title != newTitle || updated.Phase != newPhase {
		t.Fatalf("unexpected updated entity: %+v", updated)
	}
	if updated.Data["hostname"] != "dc01" {
		t.Fatalf("data not updated: %+v", updated.Data)
	}

	stale := base
	if _, err := st.UpdateEntity(ctx, project.ID, target.ID, owner.ID, EntityPatch{
		Title: &newTitle, BaseVersion: &stale,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update error = %v, want conflict", err)
	}

	if _, err := st.CreateEntity(ctx, project.ID, owner.ID, EntityInput{
		Kind: domain.KindTarget, Title: "dc02", Phase: "recon",
		Data: map[string]any{"ip": "10.0.0.11"},
	}); err != nil {
		t.Fatalf("CreateEntity second target: %v", err)
	}
	duplicate := map[string]any{"ip": "10.0.0.11"}
	if _, err := st.UpdateEntity(ctx, project.ID, target.ID, owner.ID, EntityPatch{
		Data: &duplicate,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate target update error = %v, want conflict", err)
	}
}
