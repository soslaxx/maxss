package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	conn *sql.DB
}

type User struct {
	ID             int64
	Username       string
	PasswordHash   string
	AllowedConfigs string
	TrafficLimitGB int64
	ExpiresAt      string
	Subscription   string
	CreatedAt      string
	TrafficUsedMB  int64
}

type Stats struct {
	TotalConnections int64
	ActiveConnections int64
	BytesIn          int64
	BytesOut         int64
	AuthFailures     int64
	Users            int64
	Configs          int64
}

func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	s := &Store{conn: db}
	if err := s.InitSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

func (s *Store) InitSchema() error {
	schema := `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    allowed_configs TEXT NOT NULL,
    traffic_limit_gb INTEGER NOT NULL DEFAULT -1,
    expires_at TIMESTAMP NOT NULL DEFAULT '-1',
    subscription_url TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    traffic_used_mb INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS server_stats (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS session_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    remote_addr TEXT,
    config_name TEXT,
    bytes_in INTEGER NOT NULL,
    bytes_out INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`
	_, err := s.conn.Exec(schema)
	if err != nil {
		return err
	}
	keys := []string{"total_connections", "active_connections", "bytes_in", "bytes_out", "auth_failures"}
	for _, k := range keys {
		if _, err := s.conn.Exec(`INSERT OR IGNORE INTO server_stats(key, value) VALUES (?, 0)`, k); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) CreateUser(username, passwordHash, allowedConfigs string, trafficLimitGB int64, expiresAt string) error {
	if strings.TrimSpace(username) == "" {
		return errors.New("username is required")
	}
	if strings.TrimSpace(passwordHash) == "" {
		return errors.New("password hash is required")
	}
	if strings.TrimSpace(allowedConfigs) == "" {
		allowedConfigs = "Secure Config"
	}
	if strings.TrimSpace(expiresAt) == "" {
		expiresAt = "-1"
	}
	_, err := s.conn.Exec(`INSERT INTO users(username, password_hash, allowed_configs, traffic_limit_gb, expires_at) VALUES (?, ?, ?, ?, ?)`,
		strings.TrimSpace(username), passwordHash, normalizeCSV(allowedConfigs), trafficLimitGB, expiresAt)
	return err
}

func (s *Store) DeleteUser(username string) error {
	res, err := s.conn.Exec(`DELETE FROM users WHERE username = ?`, strings.TrimSpace(username))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.conn.Query(`SELECT id, username, password_hash, allowed_configs, traffic_limit_gb, expires_at, COALESCE(subscription_url, ''), created_at, traffic_used_mb FROM users ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]User, 0)
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.AllowedConfigs, &u.TrafficLimitGB, &u.ExpiresAt, &u.Subscription, &u.CreatedAt, &u.TrafficUsedMB); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) GetUser(username string) (*User, error) {
	var u User
	err := s.conn.QueryRow(`SELECT id, username, password_hash, allowed_configs, traffic_limit_gb, expires_at, COALESCE(subscription_url, ''), created_at, traffic_used_mb FROM users WHERE username = ?`,
		strings.TrimSpace(username)).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.AllowedConfigs, &u.TrafficLimitGB, &u.ExpiresAt, &u.Subscription, &u.CreatedAt, &u.TrafficUsedMB)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) UpdateSubscription(username, link string) error {
	_, err := s.conn.Exec(`UPDATE users SET subscription_url = ? WHERE username = ?`, link, strings.TrimSpace(username))
	return err
}

func (s *Store) AddTraffic(username string, bytesIn, bytesOut int64) error {
	mbUsed := (bytesIn + bytesOut) / (1024 * 1024)
	if mbUsed < 0 {
		mbUsed = 0
	}
	if _, err := s.conn.Exec(`UPDATE users SET traffic_used_mb = traffic_used_mb + ? WHERE username = ?`, mbUsed, strings.TrimSpace(username)); err != nil {
		return err
	}
	if _, err := s.conn.Exec(`INSERT INTO session_log(username, bytes_in, bytes_out) VALUES (?, ?, ?)`, strings.TrimSpace(username), bytesIn, bytesOut); err != nil {
		return err
	}
	return nil
}

func (s *Store) IsUserAllowed(username, configName string) (bool, *User, error) {
	u, err := s.GetUser(username)
	if err != nil {
		return false, nil, err
	}
	if !csvContains(u.AllowedConfigs, configName) {
		return false, u, nil
	}

	if u.ExpiresAt != "-1" {
		t, err := time.Parse(time.RFC3339, u.ExpiresAt)
		if err == nil && time.Now().After(t) {
			return false, u, nil
		}
	}

	if u.TrafficLimitGB != -1 {
		limitMB := u.TrafficLimitGB * 1024
		if u.TrafficUsedMB >= limitMB {
			return false, u, nil
		}
	}

	return true, u, nil
}

func (s *Store) IncStat(key string, delta int64) error {
	_, err := s.conn.Exec(`UPDATE server_stats SET value = value + ? WHERE key = ?`, delta, key)
	return err
}

func (s *Store) SetStat(key string, value int64) error {
	_, err := s.conn.Exec(`INSERT INTO server_stats(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *Store) GetStats(configCount int64) (Stats, error) {
	st := Stats{}
	if err := s.conn.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&st.Users); err != nil {
		return st, err
	}
	st.Configs = configCount

	rows, err := s.conn.Query(`SELECT key, value FROM server_stats`)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var v int64
		if err := rows.Scan(&k, &v); err != nil {
			return st, err
		}
		switch k {
		case "total_connections":
			st.TotalConnections = v
		case "active_connections":
			st.ActiveConnections = v
		case "bytes_in":
			st.BytesIn = v
		case "bytes_out":
			st.BytesOut = v
		case "auth_failures":
			st.AuthFailures = v
		}
	}
	return st, rows.Err()
}

func normalizeCSV(v string) string {
	parts := strings.Split(v, ",")
	clean := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		clean = append(clean, p)
	}
	return strings.Join(clean, ",")
}

func csvContains(csv, val string) bool {
	for _, p := range strings.Split(csv, ",") {
		if strings.EqualFold(strings.TrimSpace(p), strings.TrimSpace(val)) {
			return true
		}
	}
	return false
}
