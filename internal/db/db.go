package db

import (
	"database/sql"
	"embed"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

//go:embed migrations/*.sql
var migrations embed.FS

type DB struct {
	conn *sql.DB
}

type User struct {
	ID           int64
	Username     string
	PasswordHash string
	CreatedAt    time.Time
}

type Certificate struct {
	ID                   int64
	Serial               int64
	Identity             string
	PublicKeyFingerprint string
	IssuedAt             time.Time
	ExpiresAt            time.Time
	Principal            string
}

func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable foreign keys and WAL mode for better concurrency
	if _, err := conn.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}
	if _, err := conn.Exec("PRAGMA journal_mode = WAL"); err != nil {
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	return &DB{conn: conn}, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

// InitSchema initializes the database schema by running all migrations
// Migrations are run in alphabetical order (001_, 002_, etc.)
// All migrations needs to be idempotent, i.e. can be run multiple times
func (db *DB) InitSchema() error {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	// Sort migrations by filename to ensure correct execution order
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		migration, err := migrations.ReadFile(filepath.Join("migrations/", entry.Name()))
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", entry.Name(), err)
		}

		if _, err := db.conn.Exec(string(migration)); err != nil {
			return fmt.Errorf("failed to execute migration %s: %w", entry.Name(), err)
		}
	}

	return nil
}

func (db *DB) CreateUser(username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	_, err = db.conn.Exec(
		"INSERT INTO users (username, password_hash) VALUES (?, ?)",
		username, string(hash),
	)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func (db *DB) AuthenticateUser(username, password string) (*User, error) {
	var user User
	err := db.conn.QueryRow(
		"SELECT id, username, password_hash, created_at FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("invalid credentials")
	}
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	return &user, nil
}

// AllocateSerial atomically allocates the next serial number for a certificate
// Uses a dedicated sequence table with AUTOINCREMENT to prevent race conditions
func (db *DB) AllocateSerial() (int64, error) {
	// Insert a row into the sequence table to get the next serial number
	// SQLite's AUTOINCREMENT guarantees this is atomic and unique
	result, err := db.conn.Exec("INSERT INTO serial_sequence (id) VALUES (NULL)")
	if err != nil {
		return 0, fmt.Errorf("failed to allocate serial: %w", err)
	}

	serial, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get last insert id: %w", err)
	}

	return serial, nil
}

func (db *DB) LogCertificate(cert *Certificate) error {
	_, err := db.conn.Exec(
		`INSERT INTO certificates (serial, identity, public_key_fingerprint, expires_at, principal)
		 VALUES (?, ?, ?, ?, ?)`,
		cert.Serial, cert.Identity, cert.PublicKeyFingerprint,
		cert.ExpiresAt, cert.Principal,
	)
	if err != nil {
		return fmt.Errorf("failed to log certificate: %w", err)
	}

	return nil
}
