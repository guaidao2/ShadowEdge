package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"shadowedge/internal/domain"
)

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// EnsureBootstrapAdmin creates the first platform administrator if the users
// table is empty. It returns true when a user was created.
func (s *Store) EnsureBootstrapAdmin(ctx context.Context, username, passwordHash string) (bool, error) {
	created := false
	err := s.withWrite(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		_, err := createUserTx(ctx, tx, username, username, passwordHash, "en", true)
		if err != nil {
			return err
		}
		created = true
		return nil
	})
	return created, err
}

func createUserTx(ctx context.Context, tx *sql.Tx, username, displayName, passwordHash, locale string, isAdmin bool) (*domain.User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("%w: username is required", ErrValidation)
	}
	if locale == "" {
		locale = "en"
	}
	role := 0
	if isAdmin {
		role = 1
	}
	id := newID()
	ts := now()
	_, err := tx.ExecContext(ctx, `
		INSERT INTO users
			(id, username, password_hash, display_name, locale, status, is_platform_admin, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)`,
		id, username, passwordHash, displayName, locale, role, ts, ts)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: username already exists", ErrConflict)
		}
		return nil, err
	}
	return &domain.User{
		ID: id, Username: username, DisplayName: displayName, Locale: locale,
		Status: domain.UserActive, IsPlatformAdmin: isAdmin, CreatedAt: ts, UpdatedAt: ts,
	}, nil
}

// CreateUser creates an active user directly (used by bootstrap and tests).
func (s *Store) CreateUser(ctx context.Context, username, displayName, passwordHash, locale string, isAdmin bool) (*domain.User, error) {
	var user *domain.User
	err := s.withWrite(ctx, func(tx *sql.Tx) error {
		var err error
		user, err = createUserTx(ctx, tx, username, displayName, passwordHash, locale, isAdmin)
		return err
	})
	return user, err
}

func scanUser(scanner interface{ Scan(...any) error }) (*domain.User, error) {
	var u domain.User
	var isAdmin int
	err := scanner.Scan(
		&u.ID, &u.Username, &u.DisplayName, &u.Locale, &u.Status,
		&isAdmin, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	u.IsPlatformAdmin = isAdmin != 0
	return &u, nil
}

const userColumns = `id, username, display_name, locale, status, is_platform_admin, created_at, updated_at`

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE username = ? COLLATE NOCASE`, strings.TrimSpace(username))
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// GetPasswordHash returns the stored Argon2id hash for authentication.
func (s *Store) GetPasswordHash(ctx context.Context, userID string) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx,
		`SELECT password_hash FROM users WHERE id = ?`, userID).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return hash, err
}

func (s *Store) ListUsers(ctx context.Context) ([]domain.User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+userColumns+` FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	return users, rows.Err()
}

func (s *Store) SetUserStatus(ctx context.Context, id string, status domain.UserStatus) error {
	if status != domain.UserActive && status != domain.UserDisabled {
		return fmt.Errorf("%w: invalid user status", ErrValidation)
	}
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE users SET status = ?, updated_at = ? WHERE id = ?`, status, now(), id)
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

func (s *Store) UpdateUserLocale(ctx context.Context, id, locale string) error {
	if locale != "en" && locale != "zh-CN" {
		return fmt.Errorf("%w: unsupported locale", ErrValidation)
	}
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE users SET locale = ?, updated_at = ? WHERE id = ?`, locale, now(), id)
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

// UpdatePassword replaces a user's Argon2id password hash.
func (s *Store) UpdatePassword(ctx context.Context, userID, passwordHash string) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`,
			passwordHash, now(), userID)
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

// ---------- registration requests ----------

func (s *Store) CreateRegistration(ctx context.Context, username, displayName, passwordHash, email, reason string) (*domain.Registration, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("%w: username is required", ErrValidation)
	}
	var reg *domain.Registration
	err := s.withWrite(ctx, func(tx *sql.Tx) error {
		var existing int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM users WHERE username = ? COLLATE NOCASE`, username).Scan(&existing); err != nil {
			return err
		}
		if existing > 0 {
			return fmt.Errorf("%w: username already exists", ErrConflict)
		}
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM registration_requests WHERE username = ? COLLATE NOCASE AND status = 'pending'`,
			username).Scan(&existing); err != nil {
			return err
		}
		if existing > 0 {
			return fmt.Errorf("%w: registration already pending", ErrConflict)
		}

		id := newID()
		ts := now()
		_, err := tx.ExecContext(ctx, `
			INSERT INTO registration_requests
				(id, username, display_name, password_hash, email, reason, status, created_at)
			VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`,
			id, username, displayName, passwordHash, email, reason, ts)
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: registration already pending", ErrConflict)
			}
			return err
		}
		reg = &domain.Registration{
			ID: id, Username: username, DisplayName: displayName, Email: email,
			Reason: reason, Status: domain.RegistrationPending, CreatedAt: ts,
		}
		return nil
	})
	return reg, err
}

const registrationColumns = `id, username, display_name, email, reason, status, COALESCE(reviewed_by, ''), COALESCE(reviewed_at, ''), created_at`

func scanRegistration(scanner interface{ Scan(...any) error }) (*domain.Registration, error) {
	var r domain.Registration
	err := scanner.Scan(&r.ID, &r.Username, &r.DisplayName, &r.Email, &r.Reason,
		&r.Status, &r.ReviewedBy, &r.ReviewedAt, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) ListRegistrations(ctx context.Context, status domain.RegistrationStatus) ([]domain.Registration, error) {
	query := `SELECT ` + registrationColumns + ` FROM registration_requests`
	args := []any{}
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY created_at`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var regs []domain.Registration
	for rows.Next() {
		r, err := scanRegistration(rows)
		if err != nil {
			return nil, err
		}
		regs = append(regs, *r)
	}
	return regs, rows.Err()
}

func (s *Store) GetRegistration(ctx context.Context, id string) (*domain.Registration, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+registrationColumns+` FROM registration_requests WHERE id = ?`, id)
	r, err := scanRegistration(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// ReviewRegistration approves or rejects a pending registration. Approval
// copies the stored password hash into a new active user.
func (s *Store) ReviewRegistration(ctx context.Context, id, reviewerID string, approve bool) (*domain.User, error) {
	var created *domain.User
	err := s.withWrite(ctx, func(tx *sql.Tx) error {
		var username, displayName, passwordHash string
		var status domain.RegistrationStatus
		err := tx.QueryRowContext(ctx,
			`SELECT username, display_name, password_hash, status FROM registration_requests WHERE id = ?`,
			id).Scan(&username, &displayName, &passwordHash, &status)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if status != domain.RegistrationPending {
			return fmt.Errorf("%w: registration already reviewed", ErrConflict)
		}

		newStatus := domain.RegistrationRejected
		if approve {
			newStatus = domain.RegistrationApproved
			created, err = createUserTx(ctx, tx, username, displayName, passwordHash, "en", false)
			if err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE registration_requests SET status = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ?`,
			newStatus, reviewerID, now(), id); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

// ---------- sessions ----------

func (s *Store) CreateSession(ctx context.Context, userID, tokenHash, csrfToken, expiresAt string) (*domain.Session, error) {
	sess := &domain.Session{
		ID: newID(), UserID: userID, CSRFToken: csrfToken,
		ExpiresAt: expiresAt, CreatedAt: now(), LastSeenAt: now(),
	}
	err := s.withWrite(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO sessions (id, user_id, token_hash, csrf_token, expires_at, created_at, last_seen_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			sess.ID, userID, tokenHash, csrfToken, expiresAt, sess.CreatedAt, sess.LastSeenAt)
		return err
	})
	if err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *Store) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, *domain.User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT s.id, s.user_id, s.csrf_token, s.expires_at, s.created_at, s.last_seen_at,
		       u.id, u.username, u.display_name, u.locale, u.status, u.is_platform_admin, u.created_at, u.updated_at
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND julianday(s.expires_at) > julianday(?) AND u.status = 'active'`,
		tokenHash, now())

	var sess domain.Session
	var u domain.User
	var isAdmin int
	err := row.Scan(
		&sess.ID, &sess.UserID, &sess.CSRFToken, &sess.ExpiresAt, &sess.CreatedAt, &sess.LastSeenAt,
		&u.ID, &u.Username, &u.DisplayName, &u.Locale, &u.Status, &isAdmin, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	u.IsPlatformAdmin = isAdmin != 0
	return &sess, &u, nil
}

func (s *Store) DeleteSessionByID(ctx context.Context, id string) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
		return err
	})
}

func (s *Store) DeleteSessionByTokenHash(ctx context.Context, tokenHash string) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
		return err
	})
}

func (s *Store) TouchSession(ctx context.Context, id string) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE id = ?`, now(), id)
		return err
	})
}

func (s *Store) DeleteOtherSessions(ctx context.Context, userID, keepSessionID string) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`DELETE FROM sessions WHERE user_id = ? AND id <> ?`, userID, keepSessionID)
		return err
	})
}

func (s *Store) DeleteAPITokensForUser(ctx context.Context, userID string) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM api_tokens WHERE user_id = ?`, userID)
		return err
	})
}

func (s *Store) CleanupSessions(ctx context.Context) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now())
		return err
	})
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique constraint")
}
