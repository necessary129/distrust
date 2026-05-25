package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	_ "modernc.org/sqlite"
)

// sqliteSessionStore persists LoginSession rows in a SQLite database
// so that silent prompt=none re-authentication survives across
// distrust restarts. The session payload is stored as a JSON blob;
// integrity at rest depends on filesystem permissions, the same
// model as the in-memory store.
type sqliteSessionStore struct {
	db *sql.DB
}

const sqliteSessionSchema = `
CREATE TABLE IF NOT EXISTS login_sessions (
    id          TEXT    PRIMARY KEY,
    subject     TEXT    NOT NULL,
    auth_time   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    values_json TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_sessions_subject    ON login_sessions(subject);
CREATE INDEX IF NOT EXISTS idx_login_sessions_expires_at ON login_sessions(expires_at);
`

// newSQLiteSessionStore opens (or creates) a SQLite database at path
// and prepares the login_sessions schema. WAL mode is enabled so a
// reader (Lookup) and the janitor (PurgeExpired) don't block one
// another under load.
func newSQLiteSessionStore(path string) (*sqliteSessionStore, error) {
	if path == "" {
		return nil, errors.New("sqlite session store: path is required")
	}
	// _journal_mode=WAL avoids reader/writer contention; _busy_timeout
	// gives the janitor a small window to retry on writer contention
	// instead of failing the request outright.
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite at %q: %w", path, err)
	}
	// SQLite serialises writes; cap to 1 writer + a handful of readers.
	// The handful is enough for our request rate and keeps file-handle
	// usage predictable.
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(5 * time.Minute)

	if _, err := db.Exec(sqliteSessionSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("preparing schema: %w", err)
	}
	return &sqliteSessionStore{db: db}, nil
}

func (s *sqliteSessionStore) Store(id uuid.UUID, ls *LoginSession) error {
	vals, err := json.Marshal(ls.Values)
	if err != nil {
		return fmt.Errorf("encoding values: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO login_sessions (id, subject, auth_time, expires_at, values_json)
		 VALUES (?, ?, ?, ?, ?)`,
		id.String(),
		ls.Values.Get("external_id"),
		ls.AuthTime.UnixNano(),
		ls.ExpiresAt.UnixNano(),
		string(vals),
	)
	if err != nil {
		return fmt.Errorf("inserting login session: %w", err)
	}
	return nil
}

func (s *sqliteSessionStore) Lookup(id uuid.UUID) (*LoginSession, bool) {
	row := s.db.QueryRow(
		`SELECT auth_time, expires_at, values_json FROM login_sessions WHERE id = ?`,
		id.String(),
	)
	var authNS, expNS int64
	var valsJSON string
	if err := row.Scan(&authNS, &expNS, &valsJSON); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Warn().Err(err).Msg("sqlite login session lookup failed")
		}
		return nil, false
	}
	expiresAt := time.Unix(0, expNS)
	if time.Now().After(expiresAt) {
		// Reap the row so a future request cannot resurrect it ahead of
		// the janitor's tick.
		if _, err := s.db.Exec(`DELETE FROM login_sessions WHERE id = ?`, id.String()); err != nil {
			log.Warn().Err(err).Msg("sqlite expired session cleanup failed")
		}
		return nil, false
	}
	var values url.Values
	if err := json.Unmarshal([]byte(valsJSON), &values); err != nil {
		log.Warn().Err(err).Msg("sqlite login session payload decode failed")
		return nil, false
	}
	return &LoginSession{
		AuthTime:  time.Unix(0, authNS),
		ExpiresAt: expiresAt,
		Values:    values,
	}, true
}

func (s *sqliteSessionStore) DeleteBySubject(subject string) (int, error) {
	if subject == "" {
		return 0, errors.New("delete by subject: empty subject")
	}
	res, err := s.db.Exec(`DELETE FROM login_sessions WHERE subject = ?`, subject)
	if err != nil {
		return 0, fmt.Errorf("deleting sessions for subject: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return int(n), nil
}

func (s *sqliteSessionStore) PurgeExpired(now time.Time) error {
	_, err := s.db.Exec(`DELETE FROM login_sessions WHERE expires_at <= ?`, now.UnixNano())
	if err != nil {
		return fmt.Errorf("purging expired sessions: %w", err)
	}
	return nil
}

func (s *sqliteSessionStore) Close() error { return s.db.Close() }
