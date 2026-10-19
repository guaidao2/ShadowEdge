package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// streamHub fans out project change notifications to browser and edge
// WebSocket subscribers.
type streamHub struct {
	mu   sync.Mutex
	subs map[string]map[chan struct{}]struct{}
}

func newStreamHub() *streamHub {
	return &streamHub{subs: map[string]map[chan struct{}]struct{}{}}
}

func (h *streamHub) subscribe(projectID string) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	if h.subs[projectID] == nil {
		h.subs[projectID] = map[chan struct{}]struct{}{}
	}
	h.subs[projectID][ch] = struct{}{}
	h.mu.Unlock()

	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			h.mu.Lock()
			if set := h.subs[projectID]; set != nil {
				if _, ok := set[ch]; ok {
					delete(set, ch)
					close(ch)
				}
				if len(set) == 0 {
					delete(h.subs, projectID)
				}
			}
			h.mu.Unlock()
		})
	}
	return ch, unsubscribe
}

func (h *streamHub) notify(projectID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[projectID] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// NotifyProject wakes up all WebSocket subscribers of a project. It is safe to
// call from any goroutine and never blocks.
func (s *Server) NotifyProject(projectID string) {
	s.hub.notify(projectID)
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	if _, _, err := s.projectAccess(r, projectID); err != nil {
		s.handleStoreError(w, err)
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		slog.Warn("websocket accept failed", "error", err)
		return
	}
	defer conn.CloseNow()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	updates, unsubscribe := s.hub.subscribe(projectID)
	defer unsubscribe()

	// Detect client close; the write loop is the only writer.
	go func() {
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				cancel()
				return
			}
		}
	}()

	write := func(message string) bool {
		wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
		defer wcancel()
		return conn.Write(wctx, websocket.MessageText, []byte(message)) == nil
	}
	if !write(`{"type":"ready"}`) {
		return
	}
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !write(`{"type":"ping"}`) {
				return
			}
		case _, ok := <-updates:
			if !ok {
				return
			}
			if !write(`{"type":"changed"}`) {
				return
			}
		}
	}
}
