package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"shadowedge/internal/auth"
	"shadowedge/internal/domain"
)

func normalizeTokenScopes(raw string) (string, error) {
	allowed := map[string]bool{"read": true, "write": true, "admin": true}
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		if !allowed[part] {
			return "", fmt.Errorf("%w: unknown token scope %q", ErrValidation, part)
		}
		seen[part] = true
	}
	if len(seen) == 0 {
		seen["read"] = true
	}
	if seen["write"] || seen["admin"] {
		seen["read"] = true
	}
	parts := []string{}
	for _, part := range []string{"read", "write", "admin"} {
		if seen[part] {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, ","), nil
}

func normalizeTokenExpiry(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return "", fmt.Errorf("%w: expires_at must be RFC3339", ErrValidation)
	}
	if !t.After(time.Now().UTC()) {
		return "", fmt.Errorf("%w: expires_at must be in the future", ErrValidation)
	}
	return t.UTC().Format(time.RFC3339), nil
}

// CreateAPIToken creates a project-scoped API token. The plaintext token is
// returned exactly once; only its SHA-256 hash is stored.
func (s *Store) CreateAPIToken(ctx context.Context, userID, name, scopes, projectID, expiresAt string) (string, *domain.APIToken, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil, fmt.Errorf("%w: token name is required", ErrValidation)
	}
	scopes = strings.TrimSpace(scopes)
	scopes, err := normalizeTokenScopes(scopes)
	if err != nil {
		return "", nil, err
	}
	expiresAt, err = normalizeTokenExpiry(expiresAt)
	if err != nil {
		return "", nil, err
	}
	token, err := auth.RandomToken(32)
	if err != nil {
		return "", nil, err
	}

	t := &domain.APIToken{
		ID: newID(), UserID: userID, Name: name, Scopes: scopes,
		ProjectID: projectID, ExpiresAt: expiresAt, CreatedAt: now(),
	}
	err = s.withWrite(ctx, func(tx *sql.Tx) error {
		var project any
		if projectID != "" {
			project = projectID
		}
		var expiry any
		if expiresAt != "" {
			expiry = expiresAt
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO api_tokens
				(id, user_id, name, token_hash, scopes, project_id, expires_at, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			t.ID, userID, name, auth.HashToken(token), scopes, project, expiry, t.CreatedAt)
		return err
	})
	if err != nil {
		return "", nil, err
	}
	return token, t, nil
}

const apiTokenColumns = `id, user_id, name, scopes, COALESCE(project_id, ''), COALESCE(expires_at, ''), COALESCE(last_used_at, ''), created_at`

func scanAPIToken(scanner interface{ Scan(...any) error }) (*domain.APIToken, error) {
	var t domain.APIToken
	err := scanner.Scan(&t.ID, &t.UserID, &t.Name, &t.Scopes, &t.ProjectID,
		&t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) ListAPITokens(ctx context.Context, userID, projectID string) ([]domain.APIToken, error) {
	query := `SELECT ` + apiTokenColumns + ` FROM api_tokens WHERE user_id = ?`
	args := []any{userID}
	if projectID != "" {
		query += ` AND project_id = ?`
		args = append(args, projectID)
	}
	query += ` ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []domain.APIToken
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, *t)
	}
	return tokens, rows.Err()
}

func (s *Store) DeleteAPIToken(ctx context.Context, userID, id, projectID string) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		query := `DELETE FROM api_tokens WHERE id = ? AND user_id = ?`
		args := []any{id, userID}
		if projectID != "" {
			query += ` AND project_id = ?`
			args = append(args, projectID)
		}
		res, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// GetAPITokenByHash validates a bearer token and returns its principal.
func (s *Store) GetAPITokenByHash(ctx context.Context, tokenHash string) (*domain.APIToken, *domain.User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT t.id, t.user_id, t.name, t.scopes, COALESCE(t.project_id, ''),
		       COALESCE(t.expires_at, ''), COALESCE(t.last_used_at, ''), t.created_at,
		       u.id, u.username, u.display_name, u.locale, u.status, u.is_platform_admin, u.created_at, u.updated_at
		FROM api_tokens t
		JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = ?
		  AND u.status = 'active'
		  AND (t.expires_at IS NULL OR t.expires_at = '' OR julianday(t.expires_at) > julianday(?))`,
		tokenHash, now())

	var t domain.APIToken
	var u domain.User
	var isAdmin int
	err := row.Scan(&t.ID, &t.UserID, &t.Name, &t.Scopes, &t.ProjectID,
		&t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt,
		&u.ID, &u.Username, &u.DisplayName, &u.Locale, &u.Status, &isAdmin, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	u.IsPlatformAdmin = isAdmin != 0
	return &t, &u, nil
}

func (s *Store) TouchAPIToken(ctx context.Context, id string) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, now(), id)
		return err
	})
}
