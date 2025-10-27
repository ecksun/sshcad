-- Users table for authentication
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Certificates table for audit logging
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial INTEGER UNIQUE NOT NULL,
    identity TEXT NOT NULL,
    public_key_fingerprint TEXT NOT NULL,
    issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    principal TEXT NOT NULL
);

-- Serial sequence table for atomic serial number allocation
-- This prevents race conditions when multiple requests allocate serials concurrently
CREATE TABLE IF NOT EXISTS serial_sequence (
    id INTEGER PRIMARY KEY AUTOINCREMENT
);
