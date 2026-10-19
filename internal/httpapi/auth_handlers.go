package httpapi

import (
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"shadowedge/internal/auth"
	"shadowedge/internal/domain"
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$`)

type registerRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	Email       string `json:"email"`
	Reason      string `json:"reason"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allow("register:"+clientIP(r), 5, time.Minute) {
		writeAPIError(w, http.StatusTooManyRequests, "rate_limited", "too many registration attempts")
		return
	}
	var req registerRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if !usernamePattern.MatchString(req.Username) {
		writeAPIError(w, http.StatusBadRequest, "validation", "username must be 3-32 characters: letters, digits, dot, underscore or dash")
		return
	}
	if req.DisplayName == "" {
		req.DisplayName = req.Username
	}
	if len(req.DisplayName) > 80 {
		writeAPIError(w, http.StatusBadRequest, "validation", "display name is too long")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "validation", err.Error())
		return
	}
	reg, err := s.st.CreateRegistration(r.Context(), req.Username, req.DisplayName, hash,
		strings.TrimSpace(req.Email), strings.TrimSpace(req.Reason))
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status": "pending", "registration_id": reg.ID,
		"message": "registration submitted; an administrator must approve it",
	})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if !s.limiter.allow("login:"+clientIP(r)+":"+strings.ToLower(req.Username), 10, time.Minute) {
		writeAPIError(w, http.StatusTooManyRequests, "rate_limited", "too many login attempts")
		return
	}

	user, err := s.st.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		// Equalize timing for unknown users.
		_ = auth.VerifyPassword(dummyPasswordHash, req.Password)
		writeAPIError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	hash, err := s.st.GetPasswordHash(r.Context(), user.ID)
	if err != nil || user.Status != domain.UserActive || !auth.VerifyPassword(hash, req.Password) {
		// Avoid user enumeration: every failure looks the same.
		writeAPIError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}

	sessionToken, err := auth.RandomToken(32)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal", "could not create session")
		return
	}
	csrf, err := auth.NewCSRFToken()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal", "could not create session")
		return
	}
	expires := time.Now().UTC().Add(s.cfg.SessionTTL).Format(time.RFC3339Nano)
	session, err := s.st.CreateSession(r.Context(), user.ID, auth.HashToken(sessionToken), csrf, expires)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	s.setSessionCookies(w, session, sessionToken)
	writeJSON(w, http.StatusOK, map[string]any{"user": user, "csrf_token": csrf})
}

var dummyPasswordHash = func() string {
	h, err := auth.HashPassword("shadowedge-dummy-password")
	if err != nil {
		return ""
	}
	return h
}()

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if sess := currentSession(r); sess != nil {
		_ = s.st.DeleteSessionByID(r.Context(), sess.ID)
	}
	s.clearSessionCookies(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"user": currentUser(r)})
}

type localeRequest struct {
	Locale string `json:"locale"`
}

func (s *Server) handleLocale(w http.ResponseWriter, r *http.Request) {
	var req localeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	user := currentUser(r)
	if err := s.st.UpdateUserLocale(r.Context(), user.ID, req.Locale); err != nil {
		s.handleStoreError(w, err)
		return
	}
	user.Locale = req.Locale
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

type passwordChangeRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if currentSession(r) == nil {
		writeAPIError(w, http.StatusForbidden, "session_required", "password changes require a browser session")
		return
	}
	var req passwordChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	user := currentUser(r)
	currentHash, err := s.st.GetPasswordHash(r.Context(), user.ID)
	if err != nil || !auth.VerifyPassword(currentHash, req.OldPassword) {
		writeAPIError(w, http.StatusBadRequest, "invalid_password", "current password is incorrect")
		return
	}
	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "validation", err.Error())
		return
	}
	if err := s.st.UpdatePassword(r.Context(), user.ID, newHash); err != nil {
		s.handleStoreError(w, err)
		return
	}
	if sess := currentSession(r); sess != nil {
		_ = s.st.DeleteOtherSessions(r.Context(), user.ID, sess.ID)
	}
	_ = s.st.DeleteAPITokensForUser(r.Context(), user.ID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "password_changed"})
}

// ---------- admin: registrations and users ----------

func (s *Server) handleListRegistrations(w http.ResponseWriter, r *http.Request) {
	status := domain.RegistrationStatus(r.URL.Query().Get("status"))
	if status == "" {
		status = domain.RegistrationPending
	}
	regs, err := s.st.ListRegistrations(r.Context(), status)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"registrations": regs})
}

func (s *Server) handleReviewRegistration(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		user, err := s.st.ReviewRegistration(r.Context(), id, currentUser(r).ID, approve)
		if err != nil {
			s.handleStoreError(w, err)
			return
		}
		if approve {
			writeJSON(w, http.StatusOK, map[string]any{"status": "approved", "user": user})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "rejected"})
	}
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.st.ListUsers(r.Context())
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

type userStatusRequest struct {
	Status domain.UserStatus `json:"status"`
}

func (s *Server) handleUserStatus(w http.ResponseWriter, r *http.Request) {
	var req userStatusRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Status != domain.UserActive && req.Status != domain.UserDisabled {
		writeAPIError(w, http.StatusBadRequest, "validation", "status must be active or disabled")
		return
	}
	id := r.PathValue("id")
	if id == currentUser(r).ID && req.Status == domain.UserDisabled {
		writeAPIError(w, http.StatusBadRequest, "validation", "cannot disable your own account")
		return
	}
	if err := s.st.SetUserStatus(r.Context(), id, req.Status); err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": string(req.Status)})
}

// ---------- admin: API tokens ----------

type tokenCreateRequest struct {
	Name      string `json:"name"`
	Scopes    string `json:"scopes"`
	ProjectID string `json:"project_id"`
	ExpiresAt string `json:"expires_at"`
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req tokenCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.ProjectID != "" {
		if _, err := s.st.GetProject(r.Context(), req.ProjectID); err != nil {
			s.handleStoreError(w, err)
			return
		}
	}
	token, meta, err := s.st.CreateAPIToken(r.Context(), currentUser(r).ID,
		req.Name, req.Scopes, req.ProjectID, req.ExpiresAt)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "api_token": meta})
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	scope := ""
	if tok := currentToken(r); tok != nil {
		scope = tok.ProjectID
	}
	tokens, err := s.st.ListAPITokens(r.Context(), currentUser(r).ID, scope)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	scope := ""
	if tok := currentToken(r); tok != nil {
		scope = tok.ProjectID
	}
	if err := s.st.DeleteAPIToken(r.Context(), currentUser(r).ID, r.PathValue("id"), scope); err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
