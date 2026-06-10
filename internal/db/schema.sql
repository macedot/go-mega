-- go-mega SQLite schema (core tables)
-- Run on startup with IF NOT EXISTS or simple migration table.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- Simple schema version table
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Users
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_address TEXT NOT NULL UNIQUE,
    password_digest TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin','user')),
    banned BOOLEAN NOT NULL DEFAULT 0,
    banned_at DATETIME,
    disk_quota_bytes INTEGER,
    otp_secret TEXT,
    otp_required BOOLEAN NOT NULL DEFAULT 0,
    last_otp_at DATETIME,
    terms_accepted_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email_address);

-- Sessions (for login sessions, like Rails)
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_address TEXT,
    user_agent TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);

-- Shared files (uploads)
CREATE TABLE IF NOT EXISTS shared_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    download_hash TEXT NOT NULL UNIQUE,
    original_filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    ttl_hours INTEGER NOT NULL DEFAULT 24,
    expires_at DATETIME NOT NULL,
    max_downloads INTEGER NOT NULL DEFAULT 5,
    download_count INTEGER NOT NULL DEFAULT 0,
    storage_key TEXT NOT NULL,  -- relative path or key under storage root
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_shared_files_hash ON shared_files(download_hash);
CREATE INDEX IF NOT EXISTS idx_shared_files_user ON shared_files(user_id);
CREATE INDEX IF NOT EXISTS idx_shared_files_expires ON shared_files(expires_at);

-- Bans (IP rate limit / abuse)
CREATE TABLE IF NOT EXISTS bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    reason TEXT,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_bans_ip ON bans(ip_address);
CREATE INDEX IF NOT EXISTS idx_bans_expires ON bans(expires_at);

-- Allowed MIME types (admin configurable, seeded)
CREATE TABLE IF NOT EXISTS allowed_mime_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mime_type TEXT NOT NULL UNIQUE,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_allowed_mime ON allowed_mime_types(mime_type);

-- Future: invitations, webauthn_credentials (omitted for MVP core)
