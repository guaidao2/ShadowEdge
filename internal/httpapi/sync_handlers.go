package httpapi

import (
	"errors"
	"net/http"
	"strconv"

	"shadowedge/internal/domain"
	"shadowedge/internal/store"
)

func (s *Server) handleSyncSnapshot(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	if _, _, err := s.projectAccess(r, projectID); err != nil {
		s.handleStoreError(w, err)
		return
	}
	if !s.requireSyncIngest(w, r) {
		return
	}
	project, err := s.st.GetProject(r.Context(), projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	phases, err := s.st.ListPhases(r.Context(), projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	entities, err := s.st.ListEntities(r.Context(), projectID, domain.EntityFilter{})
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	edges, err := s.st.ListEdges(r.Context(), projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	lastSeq, err := s.st.LastEventSeq(r.Context(), projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, domain.SyncSnapshot{
		Project: *project, Phases: phases, Entities: entities, Edges: edges, LastSeq: lastSeq,
	})
}

func (s *Server) handleSyncEvents(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	if _, _, err := s.projectAccess(r, projectID); err != nil {
		s.handleStoreError(w, err)
		return
	}
	if !s.requireSyncIngest(w, r) {
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

func (s *Server) handleSyncPush(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	user, _, err := s.requireWrite(r, projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	if !s.requireSyncIngest(w, r) {
		return
	}
	var req domain.SyncPushRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.NodeID == "" {
		req.NodeID = "edge"
	}
	resp, err := s.st.ApplySyncOperations(r.Context(), projectID, user.ID, req.NodeID, req.Operations)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	if resp.Accepted > 0 || len(resp.Conflicts) > 0 {
		s.NotifyProject(projectID)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSyncStatus(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	if _, _, err := s.projectAccess(r, projectID); err != nil {
		s.handleStoreError(w, err)
		return
	}
	role, err := s.st.ProjectSyncRole(r.Context(), projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	if role == "edge" {
		state, err := s.st.GetSyncState(r.Context(), projectID)
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusOK, domain.SyncStatus{Mode: "edge"})
			return
		}
		if err != nil {
			s.handleStoreError(w, err)
			return
		}
		pending, err := s.st.CountOutbox(r.Context(), projectID)
		if err != nil {
			s.handleStoreError(w, err)
			return
		}
		conflicts, err := s.st.CountConflicts(r.Context(), projectID)
		if err != nil {
			s.handleStoreError(w, err)
			return
		}
		items, err := s.st.ListConflicts(r.Context(), projectID, 10)
		if err != nil {
			s.handleStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, domain.SyncStatus{
			Mode: "edge", MasterURL: state.MasterURL, RemoteProjectID: state.RemoteProjectID,
			LastSeq: state.LastSeq, Pending: pending, Conflicts: conflicts, ConflictItems: items,
		})
		return
	}
	last, err := s.st.LastEventSeq(r.Context(), projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, domain.SyncStatus{Mode: role, LastSeq: last})
}
