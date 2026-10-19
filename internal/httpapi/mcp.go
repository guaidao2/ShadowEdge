package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"shadowedge/internal/domain"
	"shadowedge/internal/report"
	"shadowedge/internal/store"
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// handleMCP exposes a JSON-RPC MCP endpoint. Tokens are project-scoped and
// carry read/write scopes; the full Streamable HTTP transport can be layered on
// top of this handler without changing the tool implementations.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	token := currentToken(r)
	user := currentUser(r)
	if token == nil || user == nil {
		writeAPIError(w, http.StatusUnauthorized, "unauthenticated", "a platform API token is required")
		return
	}

	var req rpcRequest
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeRPC(w, rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
		return
	}

	switch req.Method {
	case "initialize":
		writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "ShadowEdge", "version": "0.1.0"},
		}})
	case "notifications/initialized":
		w.WriteHeader(http.StatusNoContent)
	case "ping":
		writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}})
	case "tools/list":
		writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": mcpTools()}})
	case "tools/call":
		var params toolCallParams
		if err := json.Unmarshal(req.Params, &params); err != nil || params.Name == "" {
			writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "invalid tool call"}})
			return
		}
		result, err := s.mcpCall(r.Context(), token, user, params.Name, params.Arguments)
		if err != nil {
			writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
				"isError": true,
				"content": []map[string]any{{"type": "text", "text": err.Error()}},
			}})
			return
		}
		body, err := json.Marshal(result)
		if err != nil {
			writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
				"isError": true,
				"content": []map[string]any{{"type": "text", "text": "could not encode result"}},
			}})
			return
		}
		writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
			"isError": false,
			"content": []map[string]any{{"type": "text", "text": string(body)}},
		}})
	default:
		writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "method not found"}})
	}
}

func writeRPC(w http.ResponseWriter, resp rpcResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) mcpCall(ctx context.Context, token *domain.APIToken, user *domain.User, name string, args map[string]any) (any, error) {
	switch name {
	case "list_projects":
		projects, err := s.st.ListProjectsForUser(ctx, user.ID, user.IsPlatformAdmin)
		if err != nil {
			return nil, err
		}
		if token.ProjectID != "" {
			filtered := projects[:0]
			for _, p := range projects {
				if p.ID == token.ProjectID {
					filtered = append(filtered, p)
				}
			}
			projects = filtered
		}
		return map[string]any{"projects": projects}, nil

	case "get_project":
		projectID, err := s.mcpProject(ctx, token, user, args)
		if err != nil {
			return nil, err
		}
		p, err := s.st.GetProject(ctx, projectID)
		if err != nil {
			return nil, err
		}
		members, err := s.st.ListMembers(ctx, projectID)
		if err != nil {
			return nil, err
		}
		return map[string]any{"project": p, "members": members}, nil

	case "list_entities":
		projectID, err := s.mcpProject(ctx, token, user, args)
		if err != nil {
			return nil, err
		}
		filter := domain.EntityFilter{
			Kind:   domain.EntityKind(argString(args, "kind")),
			Status: domain.EntityStatus(argString(args, "status")),
			Phase:  argString(args, "phase"),
		}
		if filter.Kind != "" && !filter.Kind.Valid() {
			return nil, fmt.Errorf("invalid entity kind")
		}
		if filter.Status != "" && !filter.Status.Valid() {
			return nil, fmt.Errorf("invalid entity status")
		}
		entities, err := s.st.ListEntities(ctx, projectID, filter)
		if err != nil {
			return nil, err
		}
		return map[string]any{"entities": entities}, nil

	case "get_phase_board":
		projectID, err := s.mcpProject(ctx, token, user, args)
		if err != nil {
			return nil, err
		}
		columns, err := s.st.Board(ctx, projectID)
		if err != nil {
			return nil, err
		}
		return map[string]any{"columns": columns}, nil

	case "get_attack_graph":
		projectID, err := s.mcpProject(ctx, token, user, args)
		if err != nil {
			return nil, err
		}
		graph, err := s.st.Graph(ctx, projectID)
		if err != nil {
			return nil, err
		}
		return graph, nil

	case "create_project":
		if !tokenHasScope(token.Scopes, "write") {
			return nil, fmt.Errorf("token has no write scope")
		}
		if token.ProjectID != "" {
			return nil, fmt.Errorf("project-scoped token cannot create projects")
		}
		p, err := s.st.CreateProject(ctx, user.ID, argString(args, "name"), argString(args, "description"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"project": p}, nil

	case "add_entity":
		if !tokenHasScope(token.Scopes, "write") {
			return nil, fmt.Errorf("token has no write scope")
		}
		projectID, err := s.mcpProjectWrite(ctx, token, user, args)
		if err != nil {
			return nil, err
		}
		data, _ := args["data"].(map[string]any)
		input := store.EntityInput{
			Kind:   domain.EntityKind(argString(args, "kind")),
			Title:  argString(args, "title"),
			Status: domain.EntityStatus(argString(args, "status")),
			Phase:  argString(args, "phase"),
			Data:   data,
		}
		if input.Status == "" {
			input.Status = domain.StatusNew
		}
		e, err := s.st.CreateEntity(ctx, projectID, user.ID, input)
		if err != nil {
			return nil, err
		}
		s.NotifyProject(projectID)
		return map[string]any{"entity": e}, nil

	case "add_edge":
		if !tokenHasScope(token.Scopes, "write") {
			return nil, fmt.Errorf("token has no write scope")
		}
		projectID, err := s.mcpProjectWrite(ctx, token, user, args)
		if err != nil {
			return nil, err
		}
		e, err := s.st.CreateEdge(ctx, projectID, user.ID,
			argString(args, "from_entity_id"), argString(args, "to_entity_id"), argString(args, "label"))
		if err != nil {
			return nil, err
		}
		s.NotifyProject(projectID)
		return map[string]any{"edge": e}, nil

	case "generate_report":
		projectID, err := s.mcpProject(ctx, token, user, args)
		if err != nil {
			return nil, err
		}
		data, err := report.Build(ctx, s.st, projectID, user.Username)
		if err != nil {
			return nil, err
		}
		if strings.EqualFold(argString(args, "format"), "markdown") || strings.EqualFold(argString(args, "format"), "md") {
			return map[string]any{"format": "markdown", "content": report.Markdown(data)}, nil
		}
		html, err := report.HTML(data)
		if err != nil {
			return nil, err
		}
		return map[string]any{"format": "html", "content": html}, nil

	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}

func (s *Server) mcpProject(ctx context.Context, token *domain.APIToken, user *domain.User, args map[string]any) (string, error) {
	projectID := argString(args, "project_id")
	if projectID == "" {
		return "", fmt.Errorf("project_id is required")
	}
	if token.ProjectID != "" && token.ProjectID != projectID {
		return "", fmt.Errorf("project-scoped token cannot access this project")
	}
	if user.IsPlatformAdmin {
		return projectID, nil
	}
	if _, err := s.st.MemberRole(ctx, projectID, user.ID); err != nil {
		return "", fmt.Errorf("project not found or access denied")
	}
	return projectID, nil
}

func (s *Server) mcpProjectWrite(ctx context.Context, token *domain.APIToken, user *domain.User, args map[string]any) (string, error) {
	projectID, err := s.mcpProject(ctx, token, user, args)
	if err != nil {
		return "", err
	}
	if user.IsPlatformAdmin {
		return projectID, nil
	}
	role, err := s.st.MemberRole(ctx, projectID, user.ID)
	if err != nil || !role.CanWrite() {
		return "", fmt.Errorf("write access denied")
	}
	return projectID, nil
}

func argString(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return strings.TrimSpace(v)
}

func mcpTools() []map[string]any {
	projectArg := map[string]any{"type": "string", "description": "Project ID"}
	return []map[string]any{
		{"name": "list_projects", "description": "List projects visible to the token", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}},
		{"name": "get_project", "description": "Get a project and its members", "inputSchema": schema(map[string]any{"project_id": projectArg}, "project_id")},
		{"name": "list_entities", "description": "List project entities", "inputSchema": schema(map[string]any{
			"project_id": projectArg, "kind": map[string]any{"type": "string"}, "status": map[string]any{"type": "string"}, "phase": map[string]any{"type": "string"},
		}, "project_id")},
		{"name": "get_phase_board", "description": "Get the penetration-phase board", "inputSchema": schema(map[string]any{"project_id": projectArg}, "project_id")},
		{"name": "get_attack_graph", "description": "Get DAG nodes and edges", "inputSchema": schema(map[string]any{"project_id": projectArg}, "project_id")},
		{"name": "create_project", "description": "Create a project", "inputSchema": schema(map[string]any{
			"name": map[string]any{"type": "string"}, "description": map[string]any{"type": "string"},
		}, "name")},
		{"name": "add_entity", "description": "Add a project entity", "inputSchema": schema(map[string]any{
			"project_id": projectArg, "kind": map[string]any{"type": "string"}, "title": map[string]any{"type": "string"},
			"phase": map[string]any{"type": "string"}, "status": map[string]any{"type": "string"}, "data": map[string]any{"type": "object"},
		}, "project_id", "kind", "title")},
		{"name": "add_edge", "description": "Link two entities in the DAG", "inputSchema": schema(map[string]any{
			"project_id": projectArg, "from_entity_id": map[string]any{"type": "string"},
			"to_entity_id": map[string]any{"type": "string"}, "label": map[string]any{"type": "string"},
		}, "project_id", "from_entity_id", "to_entity_id")},
		{"name": "generate_report", "description": "Generate an HTML or Markdown report", "inputSchema": schema(map[string]any{
			"project_id": projectArg, "format": map[string]any{"type": "string", "enum": []string{"html", "markdown"}},
		}, "project_id")},
	}
}

func schema(properties map[string]any, required ...string) map[string]any {
	return map[string]any{"type": "object", "properties": properties, "required": required}
}
