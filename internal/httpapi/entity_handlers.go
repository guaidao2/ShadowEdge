package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"shadowedge/internal/domain"
	"shadowedge/internal/report"
	"shadowedge/internal/store"
)

func (s *Server) handleListPhases(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	if _, _, err := s.projectAccess(r, projectID); err != nil {
		s.handleStoreError(w, err)
		return
	}
	phases, err := s.st.ListPhases(r.Context(), projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"phases": phases})
}

func (s *Server) handleBoard(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	if _, _, err := s.projectAccess(r, projectID); err != nil {
		s.handleStoreError(w, err)
		return
	}
	columns, err := s.st.Board(r.Context(), projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"columns": columns})
}

func (s *Server) handleListEntities(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	if _, _, err := s.projectAccess(r, projectID); err != nil {
		s.handleStoreError(w, err)
		return
	}

	filter := domain.EntityFilter{
		TargetID: r.URL.Query().Get("target_id"),
		Query:    strings.TrimSpace(r.URL.Query().Get("q")),
	}
	if raw := r.URL.Query().Get("kind"); raw != "" {
		kind := domain.EntityKind(raw)
		if !kind.Valid() {
			writeAPIError(w, http.StatusBadRequest, "validation", "invalid entity kind")
			return
		}
		filter.Kind = kind
	}
	if raw := r.URL.Query().Get("status"); raw != "" {
		status := domain.EntityStatus(raw)
		if !status.Valid() {
			writeAPIError(w, http.StatusBadRequest, "validation", "invalid entity status")
			return
		}
		filter.Status = status
	}
	if phase := r.URL.Query().Get("phase"); phase != "" {
		phases, err := s.st.ListPhases(r.Context(), projectID)
		if err != nil {
			s.handleStoreError(w, err)
			return
		}
		if !domain.ValidPhase(phases, phase) {
			writeAPIError(w, http.StatusBadRequest, "validation", "unknown phase")
			return
		}
		filter.Phase = phase
	}

	entities, err := s.st.ListEntities(r.Context(), projectID, filter)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entities": entities})
}

func (s *Server) handleCreateEntity(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	user, _, err := s.requireWrite(r, projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	var input store.EntityInput
	if !decodeJSON(w, r, &input) {
		return
	}
	entity, err := s.st.CreateEntity(r.Context(), projectID, user.ID, input)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	s.NotifyProject(projectID)
	writeJSON(w, http.StatusCreated, map[string]any{"entity": entity})
}

func (s *Server) handleGetEntity(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	if _, _, err := s.projectAccess(r, projectID); err != nil {
		s.handleStoreError(w, err)
		return
	}
	entity, err := s.st.GetEntity(r.Context(), projectID, r.PathValue("eid"))
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entity": entity})
}

func (s *Server) handleUpdateEntity(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	user, _, err := s.requireWrite(r, projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	var patch store.EntityPatch
	if !decodeJSON(w, r, &patch) {
		return
	}
	entity, err := s.st.UpdateEntity(r.Context(), projectID, r.PathValue("eid"), user.ID, patch)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	s.NotifyProject(projectID)
	writeJSON(w, http.StatusOK, map[string]any{"entity": entity})
}

func (s *Server) handleDeleteEntity(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	user, _, err := s.requireWrite(r, projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	if err := s.st.DeleteEntity(r.Context(), projectID, r.PathValue("eid"), user.ID); err != nil {
		s.handleStoreError(w, err)
		return
	}
	s.NotifyProject(projectID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	if _, _, err := s.projectAccess(r, projectID); err != nil {
		s.handleStoreError(w, err)
		return
	}
	graph, err := s.st.Graph(r.Context(), projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, graph)
}

type edgeCreateRequest struct {
	FromEntityID string `json:"from_entity_id"`
	ToEntityID   string `json:"to_entity_id"`
	Label        string `json:"label"`
}

func (s *Server) handleCreateEdge(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	user, _, err := s.requireWrite(r, projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	var req edgeCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	edge, err := s.st.CreateEdge(r.Context(), projectID, user.ID,
		req.FromEntityID, req.ToEntityID, strings.TrimSpace(req.Label))
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	s.NotifyProject(projectID)
	writeJSON(w, http.StatusCreated, map[string]any{"edge": edge})
}

func (s *Server) handleDeleteEdge(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	user, _, err := s.requireWrite(r, projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	if err := s.st.DeleteEdge(r.Context(), projectID, r.PathValue("eid"), user.ID); err != nil {
		s.handleStoreError(w, err)
		return
	}
	s.NotifyProject(projectID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	if _, _, err := s.projectAccess(r, projectID); err != nil {
		s.handleStoreError(w, err)
		return
	}
	since := 0
	if raw := r.URL.Query().Get("since_seq"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			writeAPIError(w, http.StatusBadRequest, "validation", "since_seq must be a non-negative integer")
			return
		}
		since = n
	}
	events, err := s.st.ListEvents(r.Context(), projectID, since)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	last := since
	if len(events) > 0 {
		last = events[len(events)-1].Seq
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "last_seq": last})
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	if _, _, err := s.projectAccess(r, projectID); err != nil {
		s.handleStoreError(w, err)
		return
	}
	data, err := report.Build(r.Context(), s.st, projectID, currentUser(r).Username)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}

	format := strings.ToLower(r.URL.Query().Get("format"))
	w.Header().Set("Cache-Control", "no-store")
	switch format {
	case "", "html":
		body, err := report.HTML(data)
		if err != nil {
			s.handleStoreError(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(body))
	case "md", "markdown", "text":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, _ = w.Write([]byte(report.Markdown(data)))
	default:
		writeAPIError(w, http.StatusBadRequest, "validation", "format must be html or markdown")
	}
}

// Keep domain referenced in this file for filters and status documentation.
var _ = domain.StatusNew
