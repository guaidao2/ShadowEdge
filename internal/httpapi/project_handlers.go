package httpapi

import (
	"net/http"

	"shadowedge/internal/domain"
)

type projectCreateRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (s *Server) handleListProjects(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	projects, err := s.st.ListProjectsForUser(r.Context(), u.ID, u.IsPlatformAdmin)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	if tok := currentToken(r); tok != nil && tok.ProjectID != "" {
		filtered := projects[:0]
		for _, p := range projects {
			if p.ID == tok.ProjectID {
				filtered = append(filtered, p)
			}
		}
		projects = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": projects})
}

func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	if tok := currentToken(r); tok != nil && tok.ProjectID != "" {
		writeAPIError(w, http.StatusForbidden, "project_scope", "project-scoped token cannot create projects")
		return
	}
	var req projectCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := s.st.CreateProject(r.Context(), currentUser(r).ID, req.Name, req.Description)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"project": p})
}

func (s *Server) handleGetProject(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	_, role, err := s.projectAccess(r, projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	p, err := s.st.GetProject(r.Context(), projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	members, err := s.st.ListMembers(r.Context(), projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"project": p, "members": members, "role": role,
	})
}

type projectUpdateRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Status      *string `json:"status"`
}

func (s *Server) handleUpdateProject(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	_, role, err := s.projectAccess(r, projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	if !role.CanManage() {
		writeAPIError(w, http.StatusForbidden, "forbidden", "only the project owner can update the project")
		return
	}
	var req projectUpdateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := s.st.UpdateProject(r.Context(), projectID, req.Name, req.Description, req.Status)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"project": p})
}

func (s *Server) handleDeleteProject(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	_, role, err := s.projectAccess(r, projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	if !role.CanManage() {
		writeAPIError(w, http.StatusForbidden, "forbidden", "only the project owner can delete the project")
		return
	}
	if err := s.st.DeleteProject(r.Context(), projectID); err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleListMembers(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	if _, _, err := s.projectAccess(r, projectID); err != nil {
		s.handleStoreError(w, err)
		return
	}
	members, err := s.st.ListMembers(r.Context(), projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": members})
}

type memberAddRequest struct {
	Username string      `json:"username"`
	Role     domain.Role `json:"role"`
}

func (s *Server) handleAddMember(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	_, role, err := s.projectAccess(r, projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	if !role.CanManage() {
		writeAPIError(w, http.StatusForbidden, "forbidden", "only the project owner can manage members")
		return
	}
	var req memberAddRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Role == "" {
		req.Role = domain.RoleOperator
	}
	if !req.Role.Valid() {
		writeAPIError(w, http.StatusBadRequest, "validation", "invalid member role")
		return
	}
	if req.Role == domain.RoleOwner {
		writeAPIError(w, http.StatusBadRequest, "validation", "cannot add another owner")
		return
	}
	if err := s.st.AddMember(r.Context(), projectID, req.Username, req.Role); err != nil {
		s.handleStoreError(w, err)
		return
	}
	members, err := s.st.ListMembers(r.Context(), projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": members})
}

func (s *Server) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	_, role, err := s.projectAccess(r, projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	if !role.CanManage() {
		writeAPIError(w, http.StatusForbidden, "forbidden", "only the project owner can manage members")
		return
	}
	if err := s.st.RemoveMember(r.Context(), projectID, r.PathValue("uid")); err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}
