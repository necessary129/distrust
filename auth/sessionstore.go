package auth

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// LoginSessionStore persists [LoginSession] records that back the
// silent prompt=none flow. Implementations are concurrent-safe and
// must reap entries past their ExpiresAt in PurgeExpired.
//
// Lookup never returns expired sessions; it must also remove them
// so the janitor's eventual sweep cannot be raced.
type LoginSessionStore interface {
	Store(id uuid.UUID, s *LoginSession) error
	Lookup(id uuid.UUID) (*LoginSession, bool)
	DeleteBySubject(subject string) (int, error)
	PurgeExpired(now time.Time) error
	Close() error
}

type memorySessionStore struct {
	mu       sync.Mutex
	sessions map[uuid.UUID]*LoginSession
}

func newMemorySessionStore() *memorySessionStore {
	return &memorySessionStore{sessions: map[uuid.UUID]*LoginSession{}}
}

func (m *memorySessionStore) Store(id uuid.UUID, s *LoginSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[id] = s
	return nil
}

func (m *memorySessionStore) Lookup(id uuid.UUID) (*LoginSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, false
	}
	if time.Now().After(s.ExpiresAt) {
		delete(m.sessions, id)
		return nil, false
	}
	return s, true
}

func (m *memorySessionStore) DeleteBySubject(subject string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, s := range m.sessions {
		if s.Values.Get("external_id") == subject {
			delete(m.sessions, id)
			n++
		}
	}
	return n, nil
}

func (m *memorySessionStore) PurgeExpired(now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if now.After(s.ExpiresAt) {
			delete(m.sessions, id)
		}
	}
	return nil
}

func (m *memorySessionStore) Close() error { return nil }
