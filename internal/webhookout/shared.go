package webhookout

import "sync"

var (
	sharedMu sync.RWMutex
	shared   *Service
)

// SetShared publishes the process-wide Service for the HTTP handlers (called by the wiring).
func SetShared(s *Service) {
	sharedMu.Lock()
	shared = s
	sharedMu.Unlock()
}

// Shared returns the Service published by the wiring, or nil before that (or without a database).
func Shared() *Service {
	sharedMu.RLock()
	defer sharedMu.RUnlock()
	return shared
}
