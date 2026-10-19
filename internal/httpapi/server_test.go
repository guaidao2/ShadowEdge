package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"shadowedge/internal/auth"
	"shadowedge/internal/config"
	"shadowedge/internal/store"
)

type testEnvelope struct {
	Data  json.RawMessage `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type testEnv struct {
	server *httptest.Server
	client *http.Client
	store  *store.Store
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Config{
		DataDir: dir, DBPath: filepath.Join(dir, "test.db"),
		SessionTTL: time.Hour, AdminUsername: "admin", MaxUploadBytes: 10 << 20,
	}
	st, err := store.Open(context.Background(), cfg.DBPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	hash, err := auth.HashPassword("admin-password-123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if _, err := st.CreateUser(context.Background(), "admin", "Administrator", hash, "en", true); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	api, err := New(cfg, st)
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	server := httptest.NewServer(api.Handler())
	t.Cleanup(func() {
		server.Close()
		st.Close()
	})
	return &testEnv{server: server, client: client, store: st}
}

func (e *testEnv) newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

func (e *testEnv) csrfFor(client *http.Client, rawURL string) string {
	u, _ := url.Parse(rawURL)
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == csrfCookie {
			return c.Value
		}
	}
	return ""
}

func (e *testEnv) csrf(rawURL string) string { return e.csrfFor(e.client, rawURL) }

func (e *testEnv) request(t *testing.T, method, path string, body any, headers map[string]string) (int, testEnvelope) {
	return e.requestWith(t, e.client, method, path, body, headers)
}

func (e *testEnv) requestWith(t *testing.T, client *http.Client, method, path string, body any, headers map[string]string) (int, testEnvelope) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req, err := http.NewRequest(method, e.server.URL+path, &buf)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(requestHeader, "1")
	if csrf := e.csrfFor(client, e.server.URL+path); csrf != "" {
		req.Header.Set(csrfHeader, csrf)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	var env testEnvelope
	if resp.StatusCode != http.StatusNoContent {
		_ = json.NewDecoder(resp.Body).Decode(&env)
	}
	return resp.StatusCode, env
}

func (e *testEnv) login(t *testing.T, client *http.Client, username, password string) {
	t.Helper()
	status, env := e.requestWith(t, client, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"username": username, "password": password,
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("login %s status = %d (%+v)", username, status, env.Error)
	}
}

func decodeData[T any](t *testing.T, env testEnvelope) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(env.Data, &out); err != nil {
		t.Fatalf("decode data: %v (%s)", err, string(env.Data))
	}
	return out
}

func TestAuthAndProjectFlow(t *testing.T) {
	e := newTestEnv(t)

	// Health is public.
	if status, _ := e.request(t, http.MethodGet, "/api/v1/health", nil, nil); status != http.StatusOK {
		t.Fatalf("health status = %d", status)
	}

	// Registration is a request; the applicant cannot log in yet.
	status, _ := e.request(t, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"username": "coolmoon", "display_name": "Cool Moon",
		"password": "cool-password-123", "email": "cool@example.com", "reason": "red team",
	}, nil)
	if status != http.StatusAccepted {
		t.Fatalf("register status = %d", status)
	}
	if status, _ := e.request(t, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"username": "coolmoon", "password": "cool-password-123",
	}, nil); status != http.StatusUnauthorized {
		t.Fatalf("pending login status = %d, want 401", status)
	}

	// Admin logs in, lists and approves the request.
	if status, _ := e.request(t, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"username": "admin", "password": "admin-password-123",
	}, nil); status != http.StatusOK {
		t.Fatalf("admin login status = %d", status)
	}
	status, env := e.request(t, http.MethodGet, "/api/v1/admin/registrations?status=pending", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("list registrations status = %d", status)
	}
	regs := decodeData[struct {
		Registrations []struct {
			ID string `json:"id"`
		} `json:"registrations"`
	}](t, env)
	if len(regs.Registrations) != 1 {
		t.Fatalf("pending registrations = %d", len(regs.Registrations))
	}
	status, _ = e.request(t, http.MethodPost,
		"/api/v1/admin/registrations/"+regs.Registrations[0].ID+"/approve", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("approve status = %d", status)
	}

	// Applicant can now log in.
	if status, _ := e.request(t, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"username": "coolmoon", "password": "cool-password-123",
	}, nil); status != http.StatusOK {
		t.Fatalf("approved login status = %d", status)
	}

	// CSRF is required for state-changing requests.
	if status, _ := e.request(t, http.MethodPost, "/api/v1/projects",
		map[string]any{"name": "no-csrf"}, map[string]string{requestHeader: ""}); status != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d, want 403", status)
	}

	status, env = e.request(t, http.MethodPost, "/api/v1/projects", map[string]any{
		"name": "Lab", "description": "internal lab",
	}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create project status = %d (%+v)", status, env.Error)
	}
	project := decodeData[struct {
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
	}](t, env)
	projectID := project.Project.ID

	// Target and service entities.
	status, env = e.request(t, http.MethodPost, "/api/v1/projects/"+projectID+"/entities", map[string]any{
		"kind": "target", "title": "dc01", "phase": "recon",
		"data": map[string]any{"ip": "10.0.0.10", "hostname": "dc01"},
	}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create target status = %d (%+v)", status, env.Error)
	}
	target := decodeData[struct {
		Entity struct {
			ID string `json:"id"`
		} `json:"entity"`
	}](t, env)

	status, env = e.request(t, http.MethodPost, "/api/v1/projects/"+projectID+"/entities", map[string]any{
		"kind": "service", "title": "80/tcp http", "phase": "scan",
		"data": map[string]any{"target_id": target.Entity.ID, "port": 80, "service": "http"},
	}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create service status = %d (%+v)", status, env.Error)
	}
	service := decodeData[struct {
		Entity struct {
			ID string `json:"id"`
		} `json:"entity"`
	}](t, env)

	// Phase board contains both entities in their phases.
	status, env = e.request(t, http.MethodGet, "/api/v1/projects/"+projectID+"/board", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("board status = %d", status)
	}
	board := decodeData[struct {
		Columns []struct {
			Phase struct {
				Key string `json:"key"`
			} `json:"phase"`
			Entities []struct {
				ID string `json:"id"`
			} `json:"entities"`
		} `json:"columns"`
	}](t, env)
	if len(board.Columns) != 11 {
		t.Fatalf("board columns = %d, want 11", len(board.Columns))
	}
	if len(board.Columns[1].Entities) != 1 {
		t.Fatalf("scan column entities = %d, want 1", len(board.Columns[1].Entities))
	}

	// DAG link and graph.
	status, _ = e.request(t, http.MethodPost, "/api/v1/projects/"+projectID+"/graph/edges", map[string]any{
		"from_entity_id": target.Entity.ID, "to_entity_id": service.Entity.ID, "label": "exposes",
	}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create edge status = %d", status)
	}
	status, env = e.request(t, http.MethodGet, "/api/v1/projects/"+projectID+"/graph", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("graph status = %d", status)
	}
	graph := decodeData[struct {
		Nodes []struct {
			ID string `json:"id"`
		} `json:"nodes"`
		Edges []struct {
			ID string `json:"id"`
		} `json:"edges"`
	}](t, env)
	if len(graph.Nodes) != 2 || len(graph.Edges) != 1 {
		t.Fatalf("graph = %d nodes, %d edges", len(graph.Nodes), len(graph.Edges))
	}

	// Reports.
	status, _ = e.request(t, http.MethodGet, "/api/v1/projects/"+projectID+"/report?format=html", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("HTML report status = %d", status)
	}
	status, _ = e.request(t, http.MethodGet, "/api/v1/projects/"+projectID+"/report?format=markdown", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("Markdown report status = %d", status)
	}

	// Entity updates use base_version; the SPA omits the immutable kind field.
	status, env = e.request(t, http.MethodPatch, "/api/v1/projects/"+projectID+"/entities/"+target.Entity.ID, map[string]any{
		"title": "dc01-updated", "phase": "scan",
		"data":         map[string]any{"ip": "10.0.0.10", "hostname": "dc01", "os": "Windows Server 2022"},
		"base_version": 1,
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("entity update status = %d (%+v)", status, env.Error)
	}
	status, _ = e.request(t, http.MethodPatch, "/api/v1/projects/"+projectID+"/entities/"+target.Entity.ID, map[string]any{
		"title": "stale", "base_version": 1,
	}, nil)
	if status != http.StatusConflict {
		t.Fatalf("stale entity update status = %d, want 409", status)
	}
}

func TestMCPTokenAndToolCall(t *testing.T) {
	e := newTestEnv(t)
	if status, _ := e.request(t, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"username": "admin", "password": "admin-password-123",
	}, nil); status != http.StatusOK {
		t.Fatalf("admin login status = %d", status)
	}

	status, env := e.request(t, http.MethodPost, "/api/v1/admin/tokens", map[string]any{
		"name": "test-mcp", "scopes": "read,write",
	}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create token status = %d (%+v)", status, env.Error)
	}
	tokenData := decodeData[struct {
		Token string `json:"token"`
	}](t, env)
	if tokenData.Token == "" {
		t.Fatal("token is empty")
	}

	// Without a token the MCP endpoint is closed.
	req, _ := http.NewRequest(http.MethodPost, e.server.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("unauthenticated MCP: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated MCP status = %d", resp.StatusCode)
	}

	call := func(method string, params any) map[string]any {
		body, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
		})
		req, _ := http.NewRequest(http.MethodPost, e.server.URL+"/mcp", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tokenData.Token)
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatalf("MCP %s: %v", method, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("MCP %s status = %d", method, resp.StatusCode)
		}
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode MCP response: %v", err)
		}
		return out
	}

	init := call("initialize", map[string]any{})
	if init["result"] == nil {
		t.Fatalf("initialize result missing: %+v", init)
	}
	tools := call("tools/list", map[string]any{})
	result, _ := tools["result"].(map[string]any)
	list, _ := result["tools"].([]any)
	if len(list) == 0 {
		t.Fatal("tools/list returned no tools")
	}
	callResult := call("tools/call", map[string]any{"name": "list_projects", "arguments": map[string]any{}})
	if callResult["result"] == nil {
		t.Fatalf("tools/call result missing: %+v", callResult)
	}

	// Read-only tokens can read but cannot write or mint tokens.
	status, env = e.request(t, http.MethodPost, "/api/v1/admin/tokens", map[string]any{
		"name": "read-only", "scopes": "read",
	}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create read-only token status = %d (%+v)", status, env.Error)
	}
	readToken := decodeData[struct {
		Token string `json:"token"`
	}](t, env)
	withRead := map[string]string{"Authorization": "Bearer " + readToken.Token}
	if status, _ := e.request(t, http.MethodPost, "/api/v1/projects", map[string]any{"name": "nope"}, withRead); status != http.StatusForbidden {
		t.Fatalf("read-only token create project = %d, want 403", status)
	}
	if status, _ := e.request(t, http.MethodGet, "/api/v1/admin/users", nil, withRead); status != http.StatusOK {
		t.Fatalf("read-only token list users = %d, want 200", status)
	}
	if status, _ := e.request(t, http.MethodPost, "/api/v1/admin/tokens", map[string]any{"name": "nope", "scopes": "read"}, withRead); status != http.StatusForbidden {
		t.Fatalf("read-only token mint token = %d, want 403", status)
	}
	if status, _ := e.request(t, http.MethodPost, "/api/v1/admin/tokens", map[string]any{"name": "bad", "scopes": "wirte"}, nil); status != http.StatusBadRequest {
		t.Fatalf("invalid scope token = %d, want 400", status)
	}
	if status, _ := e.request(t, http.MethodPost, "/api/v1/admin/tokens", map[string]any{
		"name": "bad-expiry", "scopes": "read", "expires_at": "not-a-date",
	}, nil); status != http.StatusBadRequest {
		t.Fatalf("invalid expiry token = %d, want 400", status)
	}

	// Project-scoped tokens only see their project.
	status, env = e.request(t, http.MethodPost, "/api/v1/projects", map[string]any{"name": "Scoped"}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create scoped project = %d (%+v)", status, env.Error)
	}
	scopedProject := decodeData[struct {
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
	}](t, env)
	status, env = e.request(t, http.MethodPost, "/api/v1/projects", map[string]any{"name": "Other"}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create other project = %d (%+v)", status, env.Error)
	}
	otherProject := decodeData[struct {
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
	}](t, env)
	status, env = e.request(t, http.MethodPost, "/api/v1/admin/tokens", map[string]any{
		"name": "scoped", "scopes": "read", "project_id": scopedProject.Project.ID,
	}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create scoped token = %d (%+v)", status, env.Error)
	}
	scopedToken := decodeData[struct {
		Token string `json:"token"`
	}](t, env)
	withScoped := map[string]string{"Authorization": "Bearer " + scopedToken.Token}
	status, env = e.request(t, http.MethodGet, "/api/v1/projects", nil, withScoped)
	if status != http.StatusOK {
		t.Fatalf("scoped token list projects = %d", status)
	}
	scopedList := decodeData[struct {
		Projects []struct {
			ID string `json:"id"`
		} `json:"projects"`
	}](t, env)
	if len(scopedList.Projects) != 1 || scopedList.Projects[0].ID != scopedProject.Project.ID {
		t.Fatalf("scoped token projects = %+v", scopedList.Projects)
	}
	if status, _ := e.request(t, http.MethodPost, "/api/v1/projects", map[string]any{"name": "blocked"}, withScoped); status != http.StatusForbidden {
		t.Fatalf("scoped token create project = %d, want 403", status)
	}
	if status, _ := e.request(t, http.MethodGet, "/api/v1/projects/"+otherProject.Project.ID, nil, withScoped); status != http.StatusForbidden {
		t.Fatalf("scoped token other project = %d, want 403", status)
	}
}

func TestProjectRolesAndMembers(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()

	hash, err := auth.HashPassword("operator-password-123")
	if err != nil {
		t.Fatalf("hash operator: %v", err)
	}
	operator, err := e.store.CreateUser(ctx, "operator", "Operator", hash, "en", false)
	if err != nil {
		t.Fatalf("create operator: %v", err)
	}
	hash, err = auth.HashPassword("viewer-password-123")
	if err != nil {
		t.Fatalf("hash viewer: %v", err)
	}
	viewer, err := e.store.CreateUser(ctx, "viewer", "Viewer", hash, "en", false)
	if err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	admin, err := e.store.GetUserByUsername(ctx, "admin")
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}

	adminClient := e.newClient()
	e.login(t, adminClient, "admin", "admin-password-123")
	operatorClient := e.newClient()
	e.login(t, operatorClient, "operator", "operator-password-123")
	viewerClient := e.newClient()
	e.login(t, viewerClient, "viewer", "viewer-password-123")

	status, env := e.requestWith(t, adminClient, http.MethodPost, "/api/v1/projects",
		map[string]any{"name": "Roles"}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create project status = %d (%+v)", status, env.Error)
	}
	project := decodeData[struct {
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
	}](t, env)
	projectID := project.Project.ID

	for _, member := range []struct {
		username string
		role     string
	}{{"operator", "operator"}, {"viewer", "viewer"}} {
		status, env = e.requestWith(t, adminClient, http.MethodPost,
			"/api/v1/projects/"+projectID+"/members",
			map[string]any{"username": member.username, "role": member.role}, nil)
		if status != http.StatusOK {
			t.Fatalf("add %s status = %d (%+v)", member.username, status, env.Error)
		}
	}

	if status, _ := e.requestWith(t, operatorClient, http.MethodGet, "/api/v1/projects/"+projectID, nil, nil); status != http.StatusOK {
		t.Fatalf("operator get project = %d", status)
	}
	status, env = e.requestWith(t, operatorClient, http.MethodPost,
		"/api/v1/projects/"+projectID+"/entities", map[string]any{
			"kind": "target", "title": "host-a", "phase": "recon",
			"data": map[string]any{"ip": "10.0.0.20"},
		}, nil)
	if status != http.StatusCreated {
		t.Fatalf("operator create entity = %d (%+v)", status, env.Error)
	}
	operatorEntity := decodeData[struct {
		Entity struct {
			ID string `json:"id"`
		} `json:"entity"`
	}](t, env)
	if status, _ := e.requestWith(t, operatorClient, http.MethodPatch,
		"/api/v1/projects/"+projectID, map[string]any{"name": "hijacked"}, nil); status != http.StatusForbidden {
		t.Fatalf("operator update project = %d, want 403", status)
	}

	if status, _ := e.requestWith(t, viewerClient, http.MethodGet,
		"/api/v1/projects/"+projectID+"/board", nil, nil); status != http.StatusOK {
		t.Fatalf("viewer board = %d", status)
	}
	if status, _ := e.requestWith(t, viewerClient, http.MethodPost,
		"/api/v1/projects/"+projectID+"/entities", map[string]any{
			"kind": "note", "title": "nope", "phase": "recon", "data": map[string]any{"text": "nope"},
		}, nil); status != http.StatusForbidden {
		t.Fatalf("viewer create entity = %d, want 403", status)
	}

	// A viewer's write-scoped token still cannot write through MCP.
	viewerToken, _, err := e.store.CreateAPIToken(ctx, viewer.ID, "viewer-write", "read,write", projectID, "")
	if err != nil {
		t.Fatalf("create viewer token: %v", err)
	}
	mcpBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name": "add_entity",
			"arguments": map[string]any{
				"project_id": projectID, "kind": "note", "title": "viewer-write", "phase": "recon",
				"data": map[string]any{"text": "nope"},
			},
		},
	})
	req, _ := http.NewRequest(http.MethodPost, e.server.URL+"/mcp", bytes.NewReader(mcpBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+viewerToken)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("viewer MCP request: %v", err)
	}
	defer resp.Body.Close()
	var mcpResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&mcpResp); err != nil {
		t.Fatalf("decode viewer MCP response: %v", err)
	}
	mcpResult, _ := mcpResp["result"].(map[string]any)
	if mcpResult == nil || mcpResult["isError"] != true {
		t.Fatalf("viewer MCP write should fail: %+v", mcpResp)
	}

	// Cross-project isolation: operator cannot read or mutate project B data.
	status, env = e.requestWith(t, adminClient, http.MethodPost, "/api/v1/projects", map[string]any{"name": "Other"}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create second project = %d (%+v)", status, env.Error)
	}
	otherProject := decodeData[struct {
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
	}](t, env)
	status, env = e.requestWith(t, adminClient, http.MethodPost, "/api/v1/projects/"+otherProject.Project.ID+"/entities", map[string]any{
		"kind": "note", "title": "secret", "phase": "recon", "data": map[string]any{"text": "secret"},
	}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create secret entity = %d (%+v)", status, env.Error)
	}
	secret := decodeData[struct {
		Entity struct {
			ID string `json:"id"`
		} `json:"entity"`
	}](t, env)

	if status, _ := e.requestWith(t, operatorClient, http.MethodGet, "/api/v1/projects/"+otherProject.Project.ID, nil, nil); status != http.StatusForbidden {
		t.Fatalf("operator cross-project get = %d, want 403", status)
	}
	if status, _ := e.requestWith(t, operatorClient, http.MethodGet, "/api/v1/projects/"+projectID+"/entities/"+secret.Entity.ID, nil, nil); status != http.StatusNotFound {
		t.Fatalf("operator cross-project entity get = %d, want 404", status)
	}
	if status, _ := e.requestWith(t, operatorClient, http.MethodPatch, "/api/v1/projects/"+projectID+"/entities/"+secret.Entity.ID, map[string]any{"title": "hijack"}, nil); status != http.StatusNotFound {
		t.Fatalf("operator cross-project entity patch = %d, want 404", status)
	}
	if status, _ := e.requestWith(t, operatorClient, http.MethodDelete, "/api/v1/projects/"+projectID+"/entities/"+secret.Entity.ID, nil, nil); status != http.StatusNotFound {
		t.Fatalf("operator cross-project entity delete = %d, want 404", status)
	}
	if status, _ := e.requestWith(t, operatorClient, http.MethodPost, "/api/v1/projects/"+projectID+"/graph/edges", map[string]any{
		"from_entity_id": secret.Entity.ID, "to_entity_id": operatorEntity.Entity.ID, "label": "cross",
	}, nil); status != http.StatusBadRequest {
		t.Fatalf("operator cross-project edge = %d, want 400", status)
	}

	if status, _ := e.requestWith(t, adminClient, http.MethodDelete,
		"/api/v1/projects/"+projectID+"/members/"+viewer.ID, nil, nil); status != http.StatusOK {
		t.Fatalf("remove viewer = %d", status)
	}
	if status, _ := e.requestWith(t, viewerClient, http.MethodGet,
		"/api/v1/projects/"+projectID, nil, nil); status != http.StatusForbidden {
		t.Fatalf("removed viewer get project = %d, want 403", status)
	}
	if status, _ := e.requestWith(t, adminClient, http.MethodDelete,
		"/api/v1/projects/"+projectID+"/members/"+operator.ID, nil, nil); status != http.StatusOK {
		t.Fatalf("remove operator = %d", status)
	}
	if status, _ := e.requestWith(t, operatorClient, http.MethodGet,
		"/api/v1/projects/"+projectID, nil, nil); status != http.StatusForbidden {
		t.Fatalf("removed operator get project = %d, want 403", status)
	}

	if status, _ := e.requestWith(t, adminClient, http.MethodDelete,
		"/api/v1/projects/"+projectID+"/members/"+admin.ID, nil, nil); status != http.StatusBadRequest {
		t.Fatalf("remove owner = %d, want 400", status)
	}
	if status, _ := e.requestWith(t, adminClient, http.MethodPost,
		"/api/v1/projects/"+projectID+"/members",
		map[string]any{"username": "ghost", "role": "operator"}, nil); status != http.StatusNotFound {
		t.Fatalf("add unknown member = %d, want 404", status)
	}
}

func TestSyncConfigWeb(t *testing.T) {
	e := newTestEnv(t)
	e.login(t, e.client, "admin", "admin-password-123")

	status, env := e.request(t, http.MethodPost, "/api/v1/projects", map[string]any{"name": "Sync Web"}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create project = %d (%+v)", status, env.Error)
	}
	project := decodeData[struct {
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
	}](t, env)
	projectID := project.Project.ID
	base := "/api/v1/projects/" + projectID + "/sync"

	type syncConfig struct {
		Role            string `json:"role"`
		MasterURL       string `json:"master_url"`
		RemoteProjectID string `json:"remote_project_id"`
		HasToken        bool   `json:"has_token"`
	}
	getConfig := func() syncConfig {
		t.Helper()
		status, env := e.request(t, http.MethodGet, base+"/config", nil, nil)
		if status != http.StatusOK {
			t.Fatalf("get sync config = %d (%+v)", status, env.Error)
		}
		return decodeData[syncConfig](t, env)
	}

	if cfg := getConfig(); cfg.Role != "standalone" {
		t.Fatalf("initial role = %q, want standalone", cfg.Role)
	}

	status, env = e.request(t, http.MethodPut, base+"/config", map[string]any{"role": "master"}, nil)
	if status != http.StatusOK {
		t.Fatalf("set master = %d (%+v)", status, env.Error)
	}
	if cfg := getConfig(); cfg.Role != "master" {
		t.Fatalf("master role = %q", cfg.Role)
	}

	// A read-only token must not change sync settings or trigger a sync.
	status, env = e.request(t, http.MethodPost, "/api/v1/admin/tokens", map[string]any{
		"name": "sync-read", "scopes": "read", "project_id": projectID,
	}, nil)
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("create read token = %d (%+v)", status, env.Error)
	}
	readToken := decodeData[struct {
		Token string `json:"token"`
	}](t, env).Token
	withRead := map[string]string{"Authorization": "Bearer " + readToken}
	if status, _ := e.request(t, http.MethodPut, base+"/config", map[string]any{"role": "master"}, withRead); status != http.StatusForbidden {
		t.Fatalf("read token update config = %d, want 403", status)
	}
	if status, _ := e.request(t, http.MethodPost, base+"/force", nil, withRead); status != http.StatusForbidden {
		t.Fatalf("read token force = %d, want 403", status)
	}

	status, env = e.request(t, http.MethodPost, "/api/v1/admin/tokens", map[string]any{
		"name": "sync-web", "scopes": "read,write", "project_id": projectID,
	}, nil)
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("create token = %d (%+v)", status, env.Error)
	}
	token := decodeData[struct {
		Token string `json:"token"`
	}](t, env).Token

	status, env = e.request(t, http.MethodPut, base+"/config", map[string]any{
		"role": "edge", "master_url": e.server.URL,
		"remote_project_id": projectID, "token": token, "reset": true,
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("set edge = %d (%+v)", status, env.Error)
	}
	cfg := getConfig()
	if cfg.Role != "edge" || !cfg.HasToken || cfg.MasterURL != e.server.URL || cfg.RemoteProjectID != projectID {
		t.Fatalf("edge config = %+v", cfg)
	}
	if status, _ := e.request(t, http.MethodPut, base+"/config", map[string]any{
		"role": "edge", "master_url": e.server.URL,
		"remote_project_id": "another-project", "token": token,
	}, nil); status != http.StatusBadRequest {
		t.Fatalf("re-point without reset = %d, want 400", status)
	}

	if status, _ := e.request(t, http.MethodPost, base+"/push",
		map[string]any{"node_id": "edge-1", "operations": []any{}}, nil); status != http.StatusForbidden {
		t.Fatalf("edge push = %d, want 403", status)
	}
	if status, _ := e.request(t, http.MethodPost, base+"/force", nil, nil); status != http.StatusServiceUnavailable {
		t.Fatalf("force without runner = %d, want 503", status)
	}

	status, env = e.request(t, http.MethodPut, base+"/config", map[string]any{"role": "standalone"}, nil)
	if status != http.StatusOK {
		t.Fatalf("set standalone = %d (%+v)", status, env.Error)
	}
	if cfg := getConfig(); cfg.Role != "standalone" {
		t.Fatalf("standalone role = %q", cfg.Role)
	}
}

func TestProjectStreamNotifications(t *testing.T) {
	e := newTestEnv(t)
	e.login(t, e.client, "admin", "admin-password-123")

	status, env := e.request(t, http.MethodPost, "/api/v1/projects", map[string]any{"name": "Stream"}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create project = %d (%+v)", status, env.Error)
	}
	projectID := decodeData[struct {
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
	}](t, env).Project.ID

	u, err := url.Parse(e.server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	cookies := e.client.Jar.Cookies(u)
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	wsURL := "ws" + strings.TrimPrefix(e.server.URL, "http") + "/api/v1/projects/" + projectID + "/stream"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Cookie": []string{strings.Join(parts, "; ")}},
	})
	if err != nil {
		t.Fatalf("dial stream: %v", err)
	}
	defer conn.CloseNow()

	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read ready: %v", err)
	}
	if !strings.Contains(string(data), "ready") {
		t.Fatalf("ready message = %s", data)
	}

	status, env = e.request(t, http.MethodPost, "/api/v1/projects/"+projectID+"/entities", map[string]any{
		"kind": "target", "title": "stream-target", "phase": "recon",
		"data": map[string]any{"ip": "10.9.9.9"},
	}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create entity = %d (%+v)", status, env.Error)
	}
	_, data, err = conn.Read(ctx)
	if err != nil {
		t.Fatalf("read changed: %v", err)
	}
	if !strings.Contains(string(data), "changed") {
		t.Fatalf("changed message = %s", data)
	}
}

func TestProjectStreamRequiresAccess(t *testing.T) {
	e := newTestEnv(t)
	e.login(t, e.client, "admin", "admin-password-123")

	status, env := e.request(t, http.MethodPost, "/api/v1/projects", map[string]any{"name": "Stream Auth"}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create project = %d (%+v)", status, env.Error)
	}
	projectID := decodeData[struct {
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
	}](t, env).Project.ID
	wsURL := "ws" + strings.TrimPrefix(e.server.URL, "http") + "/api/v1/projects/" + projectID + "/stream"

	cookieFor := func(client *http.Client) string {
		u, err := url.Parse(e.server.URL)
		if err != nil {
			t.Fatalf("parse server URL: %v", err)
		}
		cookies := client.Jar.Cookies(u)
		parts := make([]string, 0, len(cookies))
		for _, c := range cookies {
			parts = append(parts, c.Name+"="+c.Value)
		}
		return strings.Join(parts, "; ")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if conn, _, err := websocket.Dial(ctx, wsURL, nil); err == nil {
		conn.CloseNow()
		t.Fatal("stream without authentication succeeded")
	}

	badOrigin := http.Header{
		"Cookie": []string{cookieFor(e.client)},
		"Origin": []string{"http://evil.example"},
	}
	if conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: badOrigin}); err == nil {
		conn.CloseNow()
		t.Fatal("stream with a foreign origin succeeded")
	}

	hash, err := auth.HashPassword("outsider-password-123")
	if err != nil {
		t.Fatalf("hash outsider password: %v", err)
	}
	if _, err := e.store.CreateUser(context.Background(), "outsider", "Outsider", hash, "en", false); err != nil {
		t.Fatalf("create outsider: %v", err)
	}
	outsider := e.newClient()
	e.login(t, outsider, "outsider", "outsider-password-123")
	if conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Cookie": []string{cookieFor(outsider)}},
	}); err == nil {
		conn.CloseNow()
		t.Fatal("stream for a non-member succeeded")
	}
}

func TestSyncConfigEdgeRequiresPlatformAdmin(t *testing.T) {
	e := newTestEnv(t)
	hash, err := auth.HashPassword("owner-password-123")
	if err != nil {
		t.Fatalf("hash owner password: %v", err)
	}
	if _, err := e.store.CreateUser(context.Background(), "owner", "Owner", hash, "en", false); err != nil {
		t.Fatalf("create owner: %v", err)
	}
	owner := e.newClient()
	e.login(t, owner, "owner", "owner-password-123")

	status, env := e.requestWith(t, owner, http.MethodPost, "/api/v1/projects",
		map[string]any{"name": "Owner Project"}, nil)
	if status != http.StatusCreated {
		t.Fatalf("owner create project = %d (%+v)", status, env.Error)
	}
	projectID := decodeData[struct {
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
	}](t, env).Project.ID

	status, _ = e.requestWith(t, owner, http.MethodPut, "/api/v1/projects/"+projectID+"/sync/config",
		map[string]any{
			"role": "edge", "master_url": "http://127.0.0.1:9",
			"remote_project_id": "remote", "token": "token", "reset": true,
		}, nil)
	if status != http.StatusForbidden {
		t.Fatalf("non-admin edge config = %d, want 403", status)
	}
}
