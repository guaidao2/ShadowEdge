// Package edgesync keeps a local edge replica in sync with a project master.
package edgesync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"shadowedge/internal/domain"
	"shadowedge/internal/store"
)

type Config struct {
	MasterURL       string
	RemoteProjectID string
	LocalProjectID  string
	Token           string
	NodeID          string
	LocalOwnerID    string
	Interval        time.Duration
	OnChange        func()
}

type Syncer struct {
	st     *store.Store
	cfg    Config
	client *http.Client
	log    *slog.Logger
}

func New(st *store.Store, cfg Config) *Syncer {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	return &Syncer{
		st: st, cfg: cfg,
		client: &http.Client{Timeout: 20 * time.Second},
		log:    slog.Default().With("component", "edgesync", "project", cfg.RemoteProjectID),
	}
}

type apiEnvelope struct {
	Data  json.RawMessage `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c Config) endpoint(path string) string {
	return strings.TrimRight(c.MasterURL, "/") + "/api/v1/projects/" +
		url.PathEscape(c.RemoteProjectID) + path
}

func doJSON(ctx context.Context, client *http.Client, method, endpoint, token string, in, out any) error {
	var body io.Reader
	if in != nil {
		payload, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var env apiEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil && err != io.EOF {
		return fmt.Errorf("decode master response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		if env.Error != nil && env.Error.Message != "" {
			return fmt.Errorf("master %d: %s", resp.StatusCode, env.Error.Message)
		}
		return fmt.Errorf("master returned HTTP %d", resp.StatusCode)
	}
	if env.Error != nil {
		return fmt.Errorf("master: %s", env.Error.Message)
	}
	if out != nil && len(env.Data) > 0 {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return fmt.Errorf("decode master data: %w", err)
		}
	}
	return nil
}

// FetchSnapshot pulls the initial project snapshot from a master.
func FetchSnapshot(ctx context.Context, masterURL, projectID, token string) (*domain.SyncSnapshot, error) {
	cfg := Config{MasterURL: masterURL, RemoteProjectID: projectID, Token: token}
	client := &http.Client{Timeout: 30 * time.Second}
	var snapshot domain.SyncSnapshot
	if err := doJSON(ctx, client, http.MethodGet, cfg.endpoint("/sync/snapshot"), token, nil, &snapshot); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

// Run performs a sync attempt every Interval until ctx is cancelled.
func (s *Syncer) Run(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	for {
		if err := s.SyncOnce(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("sync failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// SyncOnce pushes local outbox operations and then pulls master events. A push
// failure does not prevent the pull path, so master->edge replication continues
// even when the token cannot write or a local row is malformed.
func (s *Syncer) SyncOnce(ctx context.Context) error {
	pushErr := s.push(ctx)
	pullErr := s.pull(ctx)
	if pushErr != nil {
		return pushErr
	}
	return pullErr
}

func (s *Syncer) push(ctx context.Context) error {
	rows, err := s.st.ListOutbox(ctx, s.cfg.LocalProjectID, 100)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	ops := make([]domain.SyncOperation, 0, len(rows))
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		op, err := operationFromOutbox(row)
		if err != nil {
			// Malformed rows are dead-lettered: record the failure and remove
			// them so they cannot block the rest of the outbox.
			_ = s.st.MarkOutboxError(ctx, row.ID, err.Error())
			_ = s.st.RecordConflict(ctx, s.cfg.LocalProjectID, row.EntityID, row.Op, "bad outbox payload: "+err.Error())
			_ = s.st.DeleteOutbox(ctx, []string{row.ID})
			s.log.Warn("bad outbox row removed", "id", row.ID, "error", err)
			continue
		}
		ops = append(ops, op)
		ids = append(ids, row.ID)
	}
	if len(ops) == 0 {
		return nil
	}

	var resp domain.SyncPushResponse
	req := domain.SyncPushRequest{NodeID: s.cfg.NodeID, Operations: ops}
	if err := doJSON(ctx, s.client, http.MethodPost, s.cfg.endpoint("/sync/push"), s.cfg.Token, req, &resp); err != nil {
		for _, id := range ids {
			_ = s.st.MarkOutboxError(ctx, id, err.Error())
		}
		return err
	}
	if err := s.st.DeleteOutbox(ctx, ids); err != nil {
		return err
	}
	for _, conflict := range resp.Conflicts {
		_ = s.st.RecordConflict(ctx, s.cfg.LocalProjectID, conflict.EntityID, conflict.Op, conflict.Detail)
	}
	if resp.Accepted > 0 && s.cfg.OnChange != nil {
		s.cfg.OnChange()
	}
	if len(resp.Conflicts) > 0 {
		s.log.Warn("master rejected operations", "conflicts", len(resp.Conflicts), "accepted", resp.Accepted)
	}
	return nil
}

func (s *Syncer) pull(ctx context.Context) error {
	since := 0
	state, err := s.st.GetSyncState(ctx, s.cfg.LocalProjectID)
	if err == nil {
		since = state.LastSeq
	} else if err != store.ErrNotFound {
		return err
	}

	var resp struct {
		Events  []domain.Event `json:"events"`
		LastSeq int            `json:"last_seq"`
	}
	endpoint := fmt.Sprintf("%s?since_seq=%d", s.cfg.endpoint("/sync/events"), since)
	if err := doJSON(ctx, s.client, http.MethodGet, endpoint, s.cfg.Token, nil, &resp); err != nil {
		return err
	}
	for _, event := range resp.Events {
		if err := s.st.ApplySyncEvent(ctx, s.cfg.LocalProjectID, s.cfg.MasterURL, s.cfg.RemoteProjectID, event, s.cfg.LocalOwnerID); err != nil {
			_ = s.st.RecordConflict(ctx, s.cfg.LocalProjectID, event.EntityID, event.Op, err.Error())
			s.log.Warn("apply event failed", "seq", event.Seq, "op", event.Op, "error", err)
		}
	}
	if len(resp.Events) > 0 && s.cfg.OnChange != nil {
		s.cfg.OnChange()
	}
	if resp.LastSeq > since {
		return s.st.AdvanceSyncSeq(ctx, s.cfg.LocalProjectID, s.cfg.MasterURL, s.cfg.RemoteProjectID, resp.LastSeq)
	}
	return nil
}

func operationFromOutbox(row domain.SyncOutbox) (domain.SyncOperation, error) {
	op := domain.SyncOperation{Op: row.Op, BaseVersion: row.BaseVersion}
	switch row.Op {
	case "entity_upsert":
		var e domain.Entity
		if err := decodeOutbox(row.Payload, &e); err != nil {
			return op, err
		}
		op.Entity = &e
	case "entity_delete":
		op.EntityID = row.EntityID
	case "edge_upsert":
		var e domain.Edge
		if err := decodeOutbox(row.Payload, &e); err != nil {
			return op, err
		}
		op.Edge = &e
	case "edge_delete":
		op.EdgeID = row.EntityID
	default:
		return op, fmt.Errorf("unknown outbox op %q", row.Op)
	}
	return op, nil
}

func decodeOutbox(payload any, dst any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dst)
}
