package db

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaFS embed.FS

var DB *sql.DB

// Open opens (or creates) the SQLite database at the given path.
// It applies the schema and runs any needed lightweight migrations.
func Open(dataSource string) (*sql.DB, error) {
	if dataSource == "" {
		dataSource = "storage/gomega.db?_journal_mode=WAL&_foreign_keys=on"
	}

	// Ensure parent dir exists for file-based DBs
	if !isMemory(dataSource) {
		if dir := filepath.Dir(dataSource); dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("mkdir db dir: %w", err)
			}
		}
	}

	dsn := dataSource
	if !isMemory(dataSource) && !contains(dsn, "?") {
		dsn += "?_journal_mode=WAL&_foreign_keys=on"
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	db.SetMaxOpenConns(1) // SQLite best with limited writers; fine for this use case
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	// Apply schema
	if err := applySchema(db); err != nil {
		db.Close()
		return nil, err
	}

	// Ensure storage dirs
	if err := ensureStorageDirs(); err != nil {
		log.Printf("warning: storage dirs: %v", err)
	}

	DB = db
	return db, nil
}

func isMemory(dsn string) bool {
	return dsn == ":memory:" || contains(dsn, ":memory:")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsHelper(s, sub))
}

func containsHelper(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func applySchema(db *sql.DB) error {
	schemaBytes, err := fs.ReadFile(schemaFS, "schema.sql")
	if err != nil {
		return fmt.Errorf("read embedded schema: %w", err)
	}
	src := string(schemaBytes)

	// Simpler split: on lines that end with ; (after stripping comments)
	lines := strings.Split(src, "\n")
	var current []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		current = append(current, line)
		if strings.HasSuffix(trimmed, ";") {
			stmt := strings.Join(current, "\n")
			stmt = strings.TrimSuffix(strings.TrimSpace(stmt), ";")
			if stmt != "" {
				if _, err := db.Exec(stmt); err != nil {
					// PRAGMAs and CREATEs are fine to ignore "already exists" in some cases
					if !strings.Contains(err.Error(), "already exists") && !strings.Contains(err.Error(), "duplicate column") {
						return fmt.Errorf("exec schema: %w\nstmt: %.120s", err, stmt)
					}
				}
			}
			current = nil
		}
	}

	_, _ = db.Exec(`INSERT OR IGNORE INTO schema_migrations (version) VALUES (1)`)
	return nil
}

func ensureStorageDirs() error {
	// Default storage locations; override via STORAGE_PATH env in main config
	base := getEnv("STORAGE_PATH", "storage")
	dirs := []string{
		filepath.Join(base, "uploads"),
		filepath.Join(base, "tmp"),
		"tmp/chunked_uploads",
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return err
		}
	}
	return nil
}

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Now helper for current time consistent with Rails Time.current
func Now() time.Time {
	return time.Now().UTC()
}
