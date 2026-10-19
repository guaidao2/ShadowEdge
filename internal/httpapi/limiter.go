package httpapi

import (
	"sync"
	"time"
)

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string][]time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: map[string][]time.Time{}}
}

// allow reports whether key may perform another action within window. It also
// prunes timestamps outside the window.
func (l *rateLimiter) allow(key string, max int, window time.Duration) bool {
	now := time.Now()
	cutoff := now.Add(-window)

	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.buckets) > 10000 {
		l.buckets = map[string][]time.Time{}
	}
	values := l.buckets[key]
	kept := values[:0]
	for _, t := range values {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= max {
		l.buckets[key] = kept
		return false
	}
	l.buckets[key] = append(kept, now)
	return true
}
