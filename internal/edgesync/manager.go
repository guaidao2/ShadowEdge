package edgesync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"shadowedge/internal/store"
	"shadowedge/internal/syncsecret"
)

// Manager syncs every project whose sync role is edge. It lets one process host
// master, standalone and edge projects at the same time.
type Manager struct {
	st       *store.Store
	dataDir  string
	interval time.Duration
	log      *slog.Logger

	mu      sync.Mutex
	running map[string]bool
	keyMu   sync.Mutex
	key     []byte

	watchMu  sync.Mutex
	watchers map[string]projectWatcher
	notify   func(string)
}

type projectWatcher struct {
	sig    string
	cancel context.CancelFunc
}

func NewManager(st *store.Store, dataDir string, interval time.Duration) *Manager {
	if interval <= 0 {
		interval = time.Second
	}
	return &Manager{
		st: st, dataDir: dataDir, interval: interval,
		log:      slog.Default().With("component", "edgesync-manager"),
		running:  map[string]bool{},
		watchers: map[string]projectWatcher{},
	}
}

// SetNotifier registers a callback used to wake the local HTTP/WebSocket
// subscribers after a sync applies remote changes.
func (m *Manager) SetNotifier(fn func(string)) { m.notify = fn }

// Run syncs all edge projects every interval until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		if err := m.SyncOnce(ctx); err != nil && ctx.Err() == nil {
			m.log.Warn("sync pass failed", "error", err)
		}
		m.reconcileWatchers(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// SyncOnce performs one sync pass over all edge projects. Projects are synced
// concurrently so one unreachable master cannot stall the others.
func (m *Manager) SyncOnce(ctx context.Context) error {
	states, err := m.st.ListEdgeSyncStates(ctx)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for _, state := range states {
		state := state
		wg.Add(1)
		go func() {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			if err := m.SyncProject(pctx, state.LocalProjectID); err != nil {
				m.log.Warn("project sync failed", "project", state.LocalProjectID, "error", err)
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return firstErr
}

func (m *Manager) syncKey() ([]byte, error) {
	m.keyMu.Lock()
	defer m.keyMu.Unlock()
	if len(m.key) == 32 {
		return m.key, nil
	}
	key, err := syncsecret.LoadOrCreateKey(m.dataDir)
	if err != nil {
		return nil, err
	}
	m.key = key
	return key, nil
}

// SyncProject syncs one local edge project immediately.
func (m *Manager) SyncProject(ctx context.Context, localProjectID string) error {
	m.mu.Lock()
	if m.running[localProjectID] {
		m.mu.Unlock()
		return nil
	}
	m.running[localProjectID] = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.running, localProjectID)
		m.mu.Unlock()
	}()

	state, err := m.st.GetSyncState(ctx, localProjectID)
	if err != nil {
		return err
	}
	if state.Role != "edge" {
		return nil
	}
	if state.TokenCipher == "" {
		return fmt.Errorf("edge project %s has no sync token", localProjectID)
	}
	key, err := m.syncKey()
	if err != nil {
		return err
	}
	token, err := syncsecret.Decrypt(key, state.TokenCipher)
	if err != nil {
		return fmt.Errorf("decrypt sync token: %w", err)
	}
	project, err := m.st.GetProject(ctx, localProjectID)
	if err != nil {
		return err
	}
	syncer := New(m.st, Config{
		MasterURL: state.MasterURL, RemoteProjectID: state.RemoteProjectID,
		LocalProjectID: localProjectID, Token: token, NodeID: state.NodeID,
		LocalOwnerID: project.OwnerID, Interval: m.interval,
		OnChange: func() {
			if m.notify != nil {
				m.notify(localProjectID)
			}
		},
	})
	return syncer.SyncOnce(ctx)
}

// reconcileWatchers keeps one WebSocket subscriber per edge project and
// restarts it when the master URL, remote project, node or token changes.
func (m *Manager) reconcileWatchers(ctx context.Context) {
	states, err := m.st.ListEdgeSyncStates(ctx)
	if err != nil {
		if ctx.Err() == nil {
			m.log.Warn("list edge projects for watchers", "error", err)
		}
		return
	}
	desired := make(map[string]string, len(states))
	for _, state := range states {
		desired[state.LocalProjectID] = state.MasterURL + "|" + state.RemoteProjectID + "|" + state.NodeID + "|" + state.TokenCipher
	}

	m.watchMu.Lock()
	defer m.watchMu.Unlock()
	for id, watcher := range m.watchers {
		if desired[id] != watcher.sig {
			watcher.cancel()
			delete(m.watchers, id)
		}
	}
	for id, sig := range desired {
		if _, ok := m.watchers[id]; ok {
			continue
		}
		wctx, cancel := context.WithCancel(ctx)
		m.watchers[id] = projectWatcher{sig: sig, cancel: cancel}
		go m.watchProject(wctx, id)
	}
}

func (m *Manager) watchProject(ctx context.Context, localProjectID string) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		state, err := m.st.GetSyncState(ctx, localProjectID)
		if errors.Is(err, store.ErrNotFound) {
			return
		}
		if err != nil {
			if !sleepContext(ctx, 2*time.Second) {
				return
			}
			continue
		}
		if state.Role != "edge" {
			return
		}
		key, err := m.syncKey()
		if err != nil {
			if !sleepContext(ctx, 2*time.Second) {
				return
			}
			continue
		}
		token, err := syncsecret.Decrypt(key, state.TokenCipher)
		if err != nil {
			if !sleepContext(ctx, 2*time.Second) {
				return
			}
			continue
		}
		wsURL, err := streamURL(state.MasterURL, state.RemoteProjectID)
		if err != nil {
			if !sleepContext(ctx, 2*time.Second) {
				return
			}
			continue
		}
		dctx, dcancel := context.WithTimeout(ctx, 15*time.Second)
		conn, _, err := websocket.Dial(dctx, wsURL, &websocket.DialOptions{
			HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}},
		})
		dcancel()
		if err != nil {
			m.log.Warn("edge stream dial failed", "project", localProjectID, "error", err)
			if !sleepContext(ctx, backoff) {
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		for {
			rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			_, data, err := conn.Read(rctx)
			cancel()
			if err != nil {
				m.log.Warn("edge stream closed", "project", localProjectID, "error", err)
				break
			}
			var msg struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(data, &msg) == nil && (msg.Type == "changed" || msg.Type == "ready") {
				go m.syncNow(ctx, localProjectID)
			}
		}
		conn.CloseNow()
		if !sleepContext(ctx, backoff) {
			return
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (m *Manager) syncNow(parent context.Context, localProjectID string) {
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	if err := m.SyncProject(ctx, localProjectID); err != nil && parent.Err() == nil {
		m.log.Warn("websocket-triggered sync failed", "project", localProjectID, "error", err)
	}
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func streamURL(masterURL, remoteProjectID string) (string, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(masterURL), "/"))
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	default:
		return "", fmt.Errorf("master URL must use http or https")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1/projects/" + url.PathEscape(remoteProjectID) + "/stream"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}
