package auth

import (
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newTempSQLiteStore(t *testing.T) *sqliteSessionStore {
	t.Helper()
	dir := t.TempDir()
	store, err := newSQLiteSessionStore(filepath.Join(dir, "sessions.db"))
	if err != nil {
		t.Fatalf("opening sqlite store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestSQLiteStoreRoundTrip(t *testing.T) {
	store := newTempSQLiteStore(t)
	id := uuid.New()
	ls := &LoginSession{
		AuthTime:  time.Now().Add(-5 * time.Minute).Truncate(time.Microsecond),
		ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Microsecond),
		Values: url.Values{
			"external_id": {"42"},
			"username":    {"alice"},
			"groups":      {"team,admins"},
		},
	}

	if err := store.Store(id, ls); err != nil {
		t.Fatalf("store: %v", err)
	}
	got, ok := store.Lookup(id)
	if !ok {
		t.Fatal("expected session to be present after store")
	}
	if got.Values.Get("external_id") != "42" || got.Values.Get("username") != "alice" {
		t.Fatalf("unexpected values round-trip: %#v", got.Values)
	}
	if !got.AuthTime.Equal(ls.AuthTime) {
		t.Fatalf("auth_time mismatch: got %v want %v", got.AuthTime, ls.AuthTime)
	}
}

func TestSQLiteStoreLookupExpired(t *testing.T) {
	store := newTempSQLiteStore(t)
	id := uuid.New()
	if err := store.Store(id, &LoginSession{
		AuthTime:  time.Now().Add(-time.Hour),
		ExpiresAt: time.Now().Add(-time.Second),
		Values:    url.Values{"external_id": {"7"}},
	}); err != nil {
		t.Fatalf("store: %v", err)
	}
	if _, ok := store.Lookup(id); ok {
		t.Fatal("expected expired session to be absent from lookup")
	}
	// Lookup should have reaped the row so a second lookup also misses
	// without going through purgeExpired.
	if _, ok := store.Lookup(id); ok {
		t.Fatal("expected expired session to remain absent after first lookup")
	}
}

func TestSQLiteStoreDeleteBySubject(t *testing.T) {
	store := newTempSQLiteStore(t)
	idA1, idA2, idB := uuid.New(), uuid.New(), uuid.New()
	mustStore := func(id uuid.UUID, sub string) {
		t.Helper()
		if err := store.Store(id, &LoginSession{
			AuthTime:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
			Values:    url.Values{"external_id": {sub}},
		}); err != nil {
			t.Fatalf("store: %v", err)
		}
	}
	mustStore(idA1, "100")
	mustStore(idA2, "100")
	mustStore(idB, "200")

	n, err := store.DeleteBySubject("100")
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 rows deleted, got %d", n)
	}
	if _, ok := store.Lookup(idA1); ok {
		t.Fatal("expected idA1 to be gone")
	}
	if _, ok := store.Lookup(idA2); ok {
		t.Fatal("expected idA2 to be gone")
	}
	if _, ok := store.Lookup(idB); !ok {
		t.Fatal("expected idB (different subject) to remain")
	}
}

func TestSQLiteStorePersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.db")

	store1, err := newSQLiteSessionStore(path)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	id := uuid.New()
	if err := store1.Store(id, &LoginSession{
		AuthTime:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		Values:    url.Values{"external_id": {"99"}, "username": {"bob"}},
	}); err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := store1.Close(); err != nil {
		t.Fatalf("close 1: %v", err)
	}

	store2, err := newSQLiteSessionStore(path)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	defer store2.Close()
	got, ok := store2.Lookup(id)
	if !ok {
		t.Fatal("expected session to persist across reopen")
	}
	if got.Values.Get("username") != "bob" {
		t.Fatalf("unexpected payload after reopen: %#v", got.Values)
	}
}
