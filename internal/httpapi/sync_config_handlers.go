package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"shadowedge/internal/domain"
	"shadowedge/internal/edgesync"
	"shadowedge/internal/store"
	"shadowedge/internal/syncsecret"
)

func (s *Server) handleSyncConfig(w http.ResponseWriter, r *http.Request) {
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
	cfg, err := s.buildSyncConfig(r, projectID, role)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleSyncConfigUpdate(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	user, access, err := s.projectAccess(r, projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	if !access.CanManage() {
		writeAPIError(w, http.StatusForbidden, "forbidden", "only the project owner can change sync settings")
		return
	}
	var req domain.SyncConfigRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Role = strings.ToLower(strings.TrimSpace(req.Role))
	masterURL, err := normalizeMasterURL(req.MasterURL)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "validation", err.Error())
		return
	}
	req.MasterURL = masterURL
	req.RemoteProjectID = strings.TrimSpace(req.RemoteProjectID)
	req.Token = strings.TrimSpace(req.Token)
	if req.Role == "edge" && !user.IsPlatformAdmin {
		writeAPIError(w, http.StatusForbidden, "forbidden", "only a platform administrator can configure an edge replica")
		return
	}

	switch req.Role {
	case "standalone":
		if err := s.st.ClearSyncQueue(r.Context(), projectID); err != nil {
			s.handleStoreError(w, err)
			return
		}
		if err := s.st.DeleteSyncState(r.Context(), projectID); err != nil {
			s.handleStoreError(w, err)
			return
		}
	case "master":
		if err := s.st.ClearSyncQueue(r.Context(), projectID); err != nil {
			s.handleStoreError(w, err)
			return
		}
		if err := s.st.DeleteSyncState(r.Context(), projectID); err != nil {
			s.handleStoreError(w, err)
			return
		}
		if err := s.st.SetSyncState(r.Context(), domain.SyncState{
			LocalProjectID: projectID, Role: "master", NodeID: "master",
		}); err != nil {
			s.handleStoreError(w, err)
			return
		}
	case "edge":
		if req.MasterURL == "" || req.RemoteProjectID == "" {
			writeAPIError(w, http.StatusBadRequest, "validation", "master_url and remote_project_id are required")
			return
		}
		key, err := syncsecret.LoadOrCreateKey(s.cfg.DataDir)
		if err != nil {
			s.handleStoreError(w, err)
			return
		}
		token := req.Token
		existing, err := s.st.GetSyncState(r.Context(), projectID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.handleStoreError(w, err)
			return
		}
		if token == "" {
			if existing == nil || existing.TokenCipher == "" {
				writeAPIError(w, http.StatusBadRequest, "validation", "a sync token is required")
				return
			}
			token, err = syncsecret.Decrypt(key, existing.TokenCipher)
			if err != nil {
				writeAPIError(w, http.StatusBadRequest, "validation", "stored sync token cannot be decrypted")
				return
			}
		}
		cipher, err := syncsecret.Encrypt(key, token)
		if err != nil {
			s.handleStoreError(w, err)
			return
		}
		repoint := existing == nil || existing.Role != "edge" ||
			strings.TrimRight(existing.MasterURL, "/") != req.MasterURL ||
			existing.RemoteProjectID != req.RemoteProjectID
		if repoint && !req.Reset {
			writeAPIError(w, http.StatusBadRequest, "validation", "changing the master or remote project requires reset=true")
			return
		}
		if repoint && req.Token == "" {
			writeAPIError(w, http.StatusBadRequest, "validation", "re-enter the sync token when changing the master or remote project")
			return
		}

		lastSeq := 0
		nodeID := ""
		if existing != nil {
			lastSeq = existing.LastSeq
			if existing.Role == "edge" && existing.NodeID != "" && existing.NodeID != "master" {
				nodeID = existing.NodeID
			}
		}
		if nodeID == "" {
			nodeID = "edge-" + uuid.NewString()[:8]
		}
		var snapshot *domain.SyncSnapshot
		if repoint {
			snapshot, err = edgesync.FetchSnapshot(r.Context(), req.MasterURL, req.RemoteProjectID, token)
			if err != nil {
				writeAPIError(w, http.StatusBadGateway, "master_unreachable", "cannot fetch master snapshot; check the master URL and token")
				return
			}
			lastSeq = snapshot.LastSeq
		}
		state := domain.SyncState{
			LocalProjectID: projectID, RemoteProjectID: req.RemoteProjectID,
			MasterURL: req.MasterURL, NodeID: nodeID, LastSeq: lastSeq,
			Role: "edge", TokenCipher: cipher,
		}
		if repoint {
			if err := s.st.ApplySnapshotWithState(r.Context(), projectID, user.ID, snapshot, state, true); err != nil {
				s.handleStoreError(w, err)
				return
			}
		} else if err := s.st.SetSyncState(r.Context(), state); err != nil {
			s.handleStoreError(w, err)
			return
		}
	default:
		writeAPIError(w, http.StatusBadRequest, "validation", "role must be standalone, master or edge")
		return
	}

	role, err := s.st.ProjectSyncRole(r.Context(), projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	cfg, err := s.buildSyncConfig(r, projectID, role)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleSyncForce(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	_, access, err := s.projectAccess(r, projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	if !access.CanWrite() {
		writeAPIError(w, http.StatusForbidden, "forbidden", "write access is required to trigger a sync")
		return
	}
	role, err := s.st.ProjectSyncRole(r.Context(), projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	if role != "edge" {
		writeAPIError(w, http.StatusBadRequest, "validation", "project is not an edge replica")
		return
	}
	if s.syncRunner == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "sync_unavailable", "sync runner is not running")
		return
	}
	if err := s.syncRunner.SyncProject(r.Context(), projectID); err != nil {
		writeAPIError(w, http.StatusBadGateway, "sync_failed", "sync failed; check the master and token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "synced"})
}

func (s *Server) buildSyncConfig(r *http.Request, projectID, role string) (domain.SyncConfig, error) {
	cfg := domain.SyncConfig{Role: role}
	if role == "edge" {
		state, err := s.st.GetSyncState(r.Context(), projectID)
		if err == nil {
			cfg.MasterURL = state.MasterURL
			cfg.RemoteProjectID = state.RemoteProjectID
			cfg.HasToken = state.TokenCipher != ""
			cfg.LastSeq = state.LastSeq
		} else if !errors.Is(err, store.ErrNotFound) {
			return cfg, err
		}
		pending, err := s.st.CountOutbox(r.Context(), projectID)
		if err != nil {
			return cfg, err
		}
		conflicts, err := s.st.CountConflicts(r.Context(), projectID)
		if err != nil {
			return cfg, err
		}
		items, err := s.st.ListConflicts(r.Context(), projectID, 10)
		if err != nil {
			return cfg, err
		}
		cfg.Pending, cfg.Conflicts, cfg.ConflictItems = pending, conflicts, items
		return cfg, nil
	}
	last, err := s.st.LastEventSeq(r.Context(), projectID)
	if err != nil {
		return cfg, err
	}
	cfg.LastSeq = last
	return cfg, nil
}

// requireSyncIngest blocks master-only sync ingest for projects that are edge
// replicas, allowing one process to host both master and edge projects.
func (s *Server) requireSyncIngest(w http.ResponseWriter, r *http.Request) bool {
	projectID := r.PathValue("id")
	role, err := s.st.ProjectSyncRole(r.Context(), projectID)
	if err != nil {
		s.handleStoreError(w, err)
		return false
	}
	if role == "edge" {
		writeAPIError(w, http.StatusForbidden, "edge_project", "sync ingest is not available for an edge project")
		return false
	}
	return true
}

func normalizeMasterURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("master URL is invalid")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("master URL must use http or https")
	}
	if u.Host == "" {
		return "", fmt.Errorf("master URL must include a host")
	}
	if u.User != nil {
		return "", fmt.Errorf("master URL must not include credentials")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}
