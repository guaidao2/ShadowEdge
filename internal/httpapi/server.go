package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"shadowedge/internal/auth"
	"shadowedge/internal/config"
	"shadowedge/internal/domain"
	"shadowedge/internal/store"
)

const (
	sessionCookie = "shadowedge_session"
	csrfCookie    = "shadowedge_csrf"
	csrfHeader    = "X-ShadowEdge-CSRF"
	requestHeader = "X-ShadowEdge"
)

type contextKey string

const (
	ctxUser    contextKey = "user"
	ctxSession contextKey = "session"
	ctxToken   contextKey = "token"
)

// Server wires HTTP routes to the store.
type Server struct {
	cfg        config.Config
	st         *store.Store
	mux        *http.ServeMux
	limiter    *rateLimiter
	syncRunner SyncRunner
	hub        *streamHub
}

// SyncRunner can force an immediate sync for one edge project.
type SyncRunner interface {
	SyncProject(ctx context.Context, localProjectID string) error
}

func (s *Server) SetSyncRunner(runner SyncRunner) { s.syncRunner = runner }

func New(cfg config.Config, st *store.Store) (*Server, error) {
	s := &Server{
		cfg:     cfg,
		st:      st,
		mux:     http.NewServeMux(),
		limiter: newRateLimiter(),
		hub:     newStreamHub(),
	}
	s.routes()
	return s, nil
}

// Handler returns the complete middleware chain.
func (s *Server) Handler() http.Handler {
	return s.securityHeaders(s.authenticate(s.csrf(s.mux)))
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "ShadowEdge"})
	})

	s.mux.HandleFunc("GET /api/v1/auth/csrf", s.handleCSRF)
	s.mux.HandleFunc("POST /api/v1/auth/register", s.handleRegister)
	s.mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/v1/auth/logout", s.requireAuth(s.handleLogout))
	s.mux.HandleFunc("GET /api/v1/auth/me", s.requireAuth(s.handleMe))
	s.mux.HandleFunc("PATCH /api/v1/auth/me/locale", s.requireWriteScope(s.handleLocale))
	s.mux.HandleFunc("PUT /api/v1/auth/me/password", s.requireAuth(s.handleChangePassword))

	s.mux.HandleFunc("GET /api/v1/admin/registrations", s.requireAdmin(s.handleListRegistrations))
	s.mux.HandleFunc("POST /api/v1/admin/registrations/{id}/approve", s.requireAdminWrite(s.handleReviewRegistration(true)))
	s.mux.HandleFunc("POST /api/v1/admin/registrations/{id}/reject", s.requireAdminWrite(s.handleReviewRegistration(false)))
	s.mux.HandleFunc("GET /api/v1/admin/users", s.requireAdmin(s.handleListUsers))
	s.mux.HandleFunc("PATCH /api/v1/admin/users/{id}/status", s.requireAdminWrite(s.handleUserStatus))

	s.mux.HandleFunc("POST /api/v1/admin/tokens", s.requireAdminWrite(s.handleCreateToken))
	s.mux.HandleFunc("GET /api/v1/admin/tokens", s.requireAdmin(s.handleListTokens))
	s.mux.HandleFunc("DELETE /api/v1/admin/tokens/{id}", s.requireAdminWrite(s.handleDeleteToken))

	s.mux.HandleFunc("GET /api/v1/projects", s.requireAuth(s.handleListProjects))
	s.mux.HandleFunc("POST /api/v1/projects", s.requireWriteScope(s.handleCreateProject))
	s.mux.HandleFunc("GET /api/v1/projects/{id}", s.requireAuth(s.handleGetProject))
	s.mux.HandleFunc("PATCH /api/v1/projects/{id}", s.requireWriteScope(s.handleUpdateProject))
	s.mux.HandleFunc("DELETE /api/v1/projects/{id}", s.requireWriteScope(s.handleDeleteProject))
	s.mux.HandleFunc("GET /api/v1/projects/{id}/members", s.requireAuth(s.handleListMembers))
	s.mux.HandleFunc("POST /api/v1/projects/{id}/members", s.requireWriteScope(s.handleAddMember))
	s.mux.HandleFunc("DELETE /api/v1/projects/{id}/members/{uid}", s.requireWriteScope(s.handleRemoveMember))

	s.mux.HandleFunc("GET /api/v1/projects/{id}/phases", s.requireAuth(s.handleListPhases))
	s.mux.HandleFunc("GET /api/v1/projects/{id}/board", s.requireAuth(s.handleBoard))
	s.mux.HandleFunc("GET /api/v1/projects/{id}/entities", s.requireAuth(s.handleListEntities))
	s.mux.HandleFunc("POST /api/v1/projects/{id}/entities", s.requireAuth(s.handleCreateEntity))
	s.mux.HandleFunc("GET /api/v1/projects/{id}/entities/{eid}", s.requireAuth(s.handleGetEntity))
	s.mux.HandleFunc("PATCH /api/v1/projects/{id}/entities/{eid}", s.requireAuth(s.handleUpdateEntity))
	s.mux.HandleFunc("DELETE /api/v1/projects/{id}/entities/{eid}", s.requireAuth(s.handleDeleteEntity))

	s.mux.HandleFunc("GET /api/v1/projects/{id}/graph", s.requireAuth(s.handleGraph))
	s.mux.HandleFunc("POST /api/v1/projects/{id}/graph/edges", s.requireAuth(s.handleCreateEdge))
	s.mux.HandleFunc("DELETE /api/v1/projects/{id}/graph/edges/{eid}", s.requireAuth(s.handleDeleteEdge))

	s.mux.HandleFunc("GET /api/v1/projects/{id}/report", s.requireAuth(s.handleReport))
	s.mux.HandleFunc("GET /api/v1/projects/{id}/events", s.requireAuth(s.handleEvents))
	s.mux.HandleFunc("GET /api/v1/projects/{id}/sync/snapshot", s.requireAuth(s.handleSyncSnapshot))
	s.mux.HandleFunc("GET /api/v1/projects/{id}/sync/events", s.requireAuth(s.handleSyncEvents))
	s.mux.HandleFunc("POST /api/v1/projects/{id}/sync/push", s.requireAuth(s.handleSyncPush))
	s.mux.HandleFunc("GET /api/v1/projects/{id}/sync/status", s.requireAuth(s.handleSyncStatus))
	s.mux.HandleFunc("GET /api/v1/projects/{id}/stream", s.requireAuth(s.handleStream))
	s.mux.HandleFunc("GET /api/v1/projects/{id}/sync/config", s.requireAuth(s.handleSyncConfig))
	s.mux.HandleFunc("PUT /api/v1/projects/{id}/sync/config", s.requireWriteScope(s.handleSyncConfigUpdate))
	s.mux.HandleFunc("POST /api/v1/projects/{id}/sync/force", s.requireWriteScope(s.handleSyncForce))

	s.mux.HandleFunc("POST /mcp", s.handleMCP)

	s.mux.HandleFunc("GET /api/", func(w http.ResponseWriter, r *http.Request) {
		writeAPIError(w, http.StatusNotFound, "not_found", "endpoint not found")
	})
	s.mux.HandleFunc("GET /", s.handleIndex)
	s.mux.HandleFunc("GET /index.html", s.handleIndex)
	s.mux.Handle("GET /vendor/", http.StripPrefix("/vendor/", s.vendorHandler()))
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		if s.cfg.SecureCookies {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		authenticated := false

		// Bearer tokens are authoritative when present (external agents/MCP).
		if token := bearerToken(r); token != "" {
			apiToken, user, err := s.st.GetAPITokenByHash(ctx, auth.HashToken(token))
			if err == nil {
				ctx = context.WithValue(ctx, ctxUser, user)
				ctx = context.WithValue(ctx, ctxToken, apiToken)
				authenticated = true
			}
		}

		if !authenticated {
			if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
				sess, user, err := s.st.GetSessionByTokenHash(ctx, auth.HashToken(c.Value))
				if err == nil {
					ctx = context.WithValue(ctx, ctxUser, user)
					ctx = context.WithValue(ctx, ctxSession, sess)
				}
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/mcp") {
			next.ServeHTTP(w, r)
			return
		}
		// Bearer tokens are not sent automatically by browsers, so they are not
		// subject to CSRF. Cookie-authenticated requests still go through the
		// custom-header/origin/double-submit checks below.
		if currentToken(r) != nil {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get(requestHeader) != "1" {
			writeAPIError(w, http.StatusForbidden, "csrf_required", "missing X-ShadowEdge header")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != r.Host {
				writeAPIError(w, http.StatusForbidden, "bad_origin", "origin does not match host")
				return
			}
		}
		if c, err := r.Cookie(csrfCookie); err == nil && c.Value != "" {
			if r.Header.Get(csrfHeader) != c.Value {
				writeAPIError(w, http.StatusForbidden, "bad_csrf", "invalid CSRF token")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if currentUser(r) == nil {
			writeAPIError(w, http.StatusUnauthorized, "unauthenticated", "login required")
			return
		}
		next(w, r)
	}
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if u := currentUser(r); u == nil || !u.IsPlatformAdmin {
			writeAPIError(w, http.StatusForbidden, "admin_required", "platform administrator required")
			return
		}
		if tok := currentToken(r); tok != nil && tok.ProjectID != "" {
			writeAPIError(w, http.StatusForbidden, "admin_scope", "project-scoped token cannot use admin APIs")
			return
		}
		next(w, r)
	})
}

func (s *Server) requireAdminWrite(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		if tok := currentToken(r); tok != nil && !tokenHasScope(tok.Scopes, "write") {
			writeAPIError(w, http.StatusForbidden, "write_scope_required", "token has no write scope")
			return
		}
		next(w, r)
	})
}

func (s *Server) requireWriteScope(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if tok := currentToken(r); tok != nil && !tokenHasScope(tok.Scopes, "write") {
			writeAPIError(w, http.StatusForbidden, "write_scope_required", "token has no write scope")
			return
		}
		next(w, r)
	})
}

func currentUser(r *http.Request) *domain.User {
	u, _ := r.Context().Value(ctxUser).(*domain.User)
	return u
}

func currentSession(r *http.Request) *domain.Session {
	s, _ := r.Context().Value(ctxSession).(*domain.Session)
	return s
}

func currentToken(r *http.Request) *domain.APIToken {
	t, _ := r.Context().Value(ctxToken).(*domain.APIToken)
	return t
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return strings.TrimSpace(r.Header.Get("X-API-Key"))
}

// projectAccess returns the caller, their effective role and an error. Platform
// administrators and owner-role API tokens are treated as project owners.
func (s *Server) projectAccess(r *http.Request, projectID string) (*domain.User, domain.Role, error) {
	u := currentUser(r)
	if u == nil {
		return nil, "", store.ErrForbidden
	}
	if tok := currentToken(r); tok != nil && tok.ProjectID != "" && tok.ProjectID != projectID {
		return nil, "", store.ErrForbidden
	}
	if u.IsPlatformAdmin {
		return u, domain.RoleOwner, nil
	}
	role, err := s.st.MemberRole(r.Context(), projectID, u.ID)
	if err != nil {
		return nil, "", store.ErrForbidden
	}
	return u, role, nil
}

func (s *Server) requireWrite(r *http.Request, projectID string) (*domain.User, domain.Role, error) {
	u, role, err := s.projectAccess(r, projectID)
	if err != nil {
		return nil, "", err
	}
	if !role.CanWrite() {
		return nil, "", store.ErrForbidden
	}
	if tok := currentToken(r); tok != nil && !tokenHasScope(tok.Scopes, "write") {
		return nil, "", store.ErrForbidden
	}
	return u, role, nil
}

func tokenHasScope(scopes, want string) bool {
	for _, s := range strings.Split(scopes, ",") {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == want || s == "*" || s == "admin" {
			return true
		}
	}
	return false
}

// ---------- JSON helpers ----------

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type apiEnvelope struct {
	Data  any       `json:"data,omitempty"`
	Error *apiError `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiEnvelope{Data: data})
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiEnvelope{Error: &apiError{Code: code, Message: message}})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		writeAPIError(w, http.StatusBadRequest, "invalid_json", "request body must contain one object")
		return false
	}
	return true
}

func (s *Server) handleStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, store.ErrConflict):
		writeAPIError(w, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, store.ErrValidation):
		writeAPIError(w, http.StatusBadRequest, "validation", err.Error())
	case errors.Is(err, store.ErrForbidden):
		writeAPIError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
	default:
		slog.Error("request failed", "error", err)
		writeAPIError(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

func (s *Server) handleCSRF(w http.ResponseWriter, r *http.Request) {
	token, err := auth.NewCSRFToken()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal", "could not create CSRF token")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: token, Path: "/", SameSite: http.SameSiteLaxMode,
		Secure: s.cfg.SecureCookies, MaxAge: int((24 * time.Hour).Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]string{"csrf_token": token})
}

func (s *Server) setSessionCookies(w http.ResponseWriter, session *domain.Session, token string) {
	maxAge := int(time.Until(parseTime(session.ExpiresAt)).Seconds())
	if maxAge <= 0 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: s.cfg.SecureCookies, MaxAge: maxAge,
	})
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: session.CSRFToken, Path: "/",
		SameSite: http.SameSiteLaxMode, Secure: s.cfg.SecureCookies, MaxAge: maxAge,
	})
}

func (s *Server) clearSessionCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: "", Path: "/", MaxAge: -1})
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Now().Add(-time.Hour)
	}
	return t
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	body, err := webFS.ReadFile("index.html")
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal", "web assets unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(body)
}
