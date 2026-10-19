package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"shadowedge/internal/domain"
)

func (s *Store) CreateProject(ctx context.Context, ownerID, name, description string) (*domain.Project, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("%w: project name is required", ErrValidation)
	}
	p := &domain.Project{
		ID: newID(), Name: name, Description: description, Status: "active",
		OwnerID: ownerID, CreatedAt: now(), UpdatedAt: now(),
	}
	err := s.withWrite(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO projects (id, name, description, status, owner_id, created_at, updated_at)
			VALUES (?, ?, ?, 'active', ?, ?, ?)`,
			p.ID, p.Name, p.Description, p.OwnerID, p.CreatedAt, p.UpdatedAt); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO project_members (project_id, user_id, role, joined_at)
			VALUES (?, ?, 'owner', ?)`, p.ID, ownerID, p.CreatedAt); err != nil {
			return err
		}
		return insertDefaultPhasesTx(ctx, tx, p.ID)
	})
	if err != nil {
		return nil, err
	}
	p.Stats = domain.ProjectStats{}
	return p, nil
}

func insertDefaultPhasesTx(ctx context.Context, tx *sql.Tx, projectID string) error {
	for _, ph := range domain.DefaultPhases {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO project_phases (project_id, key, name_en, name_zh, position, color)
			VALUES (?, ?, ?, ?, ?, ?)`,
			projectID, ph.Key, ph.NameEN, ph.NameZH, ph.Position, ph.Color); err != nil {
			return err
		}
	}
	return nil
}

const projectColumns = `id, name, description, status, owner_id, created_at, updated_at`

func scanProject(scanner interface{ Scan(...any) error }) (*domain.Project, error) {
	var p domain.Project
	err := scanner.Scan(&p.ID, &p.Name, &p.Description, &p.Status, &p.OwnerID, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) GetProject(ctx context.Context, id string) (*domain.Project, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+projectColumns+` FROM projects WHERE id = ?`, id)
	p, err := scanProject(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := s.fillProjectStats(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *Store) ListProjectsForUser(ctx context.Context, userID string, isAdmin bool) ([]domain.Project, error) {
	query := `SELECT ` + projectColumns + ` FROM projects p`
	args := []any{}
	if !isAdmin {
		query += ` JOIN project_members pm ON pm.project_id = p.id WHERE pm.user_id = ?`
		args = append(args, userID)
	}
	query += ` ORDER BY p.updated_at DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var projects []domain.Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		if err := s.fillProjectStats(ctx, p); err != nil {
			return nil, err
		}
		projects = append(projects, *p)
	}
	return projects, rows.Err()
}

func (s *Store) fillProjectStats(ctx context.Context, p *domain.Project) error {
	return s.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM entities WHERE project_id = ? AND kind = 'target' AND deleted_at IS NULL),
			(SELECT COUNT(*) FROM entities WHERE project_id = ? AND deleted_at IS NULL),
			(SELECT COUNT(*) FROM entities WHERE project_id = ? AND kind = 'finding' AND deleted_at IS NULL)`,
		p.ID, p.ID, p.ID).Scan(&p.Stats.Targets, &p.Stats.Entities, &p.Stats.Findings)
}

func (s *Store) UpdateProject(ctx context.Context, id string, name, description, status *string) (*domain.Project, error) {
	fields := []string{}
	args := []any{}
	if name != nil {
		n := strings.TrimSpace(*name)
		if n == "" {
			return nil, fmt.Errorf("%w: project name is required", ErrValidation)
		}
		fields = append(fields, "name = ?")
		args = append(args, n)
	}
	if description != nil {
		fields = append(fields, "description = ?")
		args = append(args, *description)
	}
	if status != nil {
		if *status != "active" && *status != "completed" && *status != "archived" {
			return nil, fmt.Errorf("%w: invalid project status", ErrValidation)
		}
		fields = append(fields, "status = ?")
		args = append(args, *status)
	}
	if len(fields) == 0 {
		return s.GetProject(ctx, id)
	}
	fields = append(fields, "updated_at = ?")
	args = append(args, now(), id)

	err := s.withWrite(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE projects SET `+strings.Join(fields, ", ")+` WHERE id = ?`, args...)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.GetProject(ctx, id)
}

func (s *Store) DeleteProject(ctx context.Context, id string) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM sync_state WHERE local_project_id = ?`, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM sync_outbox WHERE project_id = ?`, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM sync_conflicts WHERE project_id = ?`, id); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM projects WHERE id = ?`, id)
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

// ---------- members ----------

func (s *Store) ListMembers(ctx context.Context, projectID string) ([]domain.Member, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT pm.user_id, u.username, u.display_name, pm.role, pm.joined_at
		FROM project_members pm
		JOIN users u ON u.id = pm.user_id
		WHERE pm.project_id = ?
		ORDER BY CASE pm.role WHEN 'owner' THEN 0 WHEN 'operator' THEN 1 WHEN 'auditor' THEN 2 ELSE 3 END,
		         u.username`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []domain.Member
	for rows.Next() {
		var m domain.Member
		if err := rows.Scan(&m.UserID, &m.Username, &m.DisplayName, &m.Role, &m.JoinedAt); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

func (s *Store) AddMember(ctx context.Context, projectID, username string, role domain.Role) error {
	if !role.Valid() {
		return fmt.Errorf("%w: invalid role", ErrValidation)
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("%w: username is required", ErrValidation)
	}
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		var userID string
		err := tx.QueryRowContext(ctx,
			`SELECT id FROM users WHERE username = ? COLLATE NOCASE AND status = 'active'`, username).Scan(&userID)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: user not found", ErrNotFound)
		}
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO project_members (project_id, user_id, role, joined_at)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(project_id, user_id) DO UPDATE SET role = excluded.role`,
			projectID, userID, role, now())
		return err
	})
}

func (s *Store) RemoveMember(ctx context.Context, projectID, userID string) error {
	return s.withWrite(ctx, func(tx *sql.Tx) error {
		var role domain.Role
		err := tx.QueryRowContext(ctx,
			`SELECT role FROM project_members WHERE project_id = ? AND user_id = ?`,
			projectID, userID).Scan(&role)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if role == domain.RoleOwner {
			return fmt.Errorf("%w: cannot remove the project owner", ErrValidation)
		}
		_, err = tx.ExecContext(ctx,
			`DELETE FROM project_members WHERE project_id = ? AND user_id = ?`, projectID, userID)
		return err
	})
}

func (s *Store) MemberRole(ctx context.Context, projectID, userID string) (domain.Role, error) {
	var role domain.Role
	err := s.db.QueryRowContext(ctx,
		`SELECT role FROM project_members WHERE project_id = ? AND user_id = ?`,
		projectID, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return role, err
}

// ---------- phases and board ----------

func (s *Store) ListPhases(ctx context.Context, projectID string) ([]domain.Phase, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT key, name_en, name_zh, position, color
		FROM project_phases WHERE project_id = ? ORDER BY position`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var phases []domain.Phase
	for rows.Next() {
		var p domain.Phase
		if err := rows.Scan(&p.Key, &p.NameEN, &p.NameZH, &p.Position, &p.Color); err != nil {
			return nil, err
		}
		phases = append(phases, p)
	}
	return phases, rows.Err()
}

func (s *Store) Board(ctx context.Context, projectID string) ([]domain.BoardColumn, error) {
	phases, err := s.ListPhases(ctx, projectID)
	if err != nil {
		return nil, err
	}
	entities, err := s.ListEntities(ctx, projectID, domain.EntityFilter{})
	if err != nil {
		return nil, err
	}

	byPhase := map[string][]domain.Entity{}
	for _, e := range entities {
		byPhase[e.Phase] = append(byPhase[e.Phase], e)
	}

	columns := make([]domain.BoardColumn, 0, len(phases))
	for _, ph := range phases {
		items := byPhase[ph.Key]
		if items == nil {
			items = []domain.Entity{}
		}
		counts := map[string]int{}
		for _, e := range items {
			counts[string(e.Status)]++
		}
		columns = append(columns, domain.BoardColumn{
			Phase: ph, Entities: items, StatusCounts: counts,
		})
	}
	return columns, nil
}
