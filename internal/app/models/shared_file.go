package models

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/macedot/go-mega/internal/app/services"
	"github.com/macedot/go-mega/internal/config"
)

type SharedFile struct {
	ID               int64
	UserID           int64
	DownloadHash     string
	OriginalFilename string
	ContentType      string
	FileSize         int64
	TTLHours         int
	ExpiresAt        time.Time
	MaxDownloads     int
	DownloadCount    int
	StorageKey       string // path relative to storage root, e.g. "uploads/abc123"
	CreatedAt        time.Time
	UpdatedAt        time.Time

	// joined
	User *User
}

func (f *SharedFile) Active() bool {
	now := time.Now().UTC()
	downloadsOk := f.MaxDownloads == 0 || f.DownloadCount < f.MaxDownloads
	expiresOk := f.TTLHours == 0 || now.Before(f.ExpiresAt)
	return downloadsOk && expiresOk
}

func (f *SharedFile) Expired() bool {
	if f.TTLHours == 0 {
		return false
	}
	now := time.Now().UTC()
	return now.After(f.ExpiresAt) || now.Equal(f.ExpiresAt)
}

func (f *SharedFile) Exhausted() bool {
	if f.MaxDownloads == 0 {
		return false
	}
	return f.DownloadCount >= f.MaxDownloads
}

func (f *SharedFile) DownloadsRemaining() int {
	if f.MaxDownloads == 0 {
		return 0 // caller checks MaxDownloads == 0 to mean unlimited
	}
	r := f.MaxDownloads - f.DownloadCount
	if r < 0 {
		return 0
	}
	return r
}

func (f *SharedFile) TimeRemaining() time.Duration {
	if f.TTLHours == 0 {
		return time.Hour * 24 * 365 * 100 // very long for "never"
	}
	rem := time.Until(f.ExpiresAt)
	if rem < 0 {
		return 0
	}
	return rem
}

func (f *SharedFile) IsPreviewable() bool {
	ct := f.ContentType
	switch {
	case strings.HasPrefix(ct, "image/"):
		return ct == "image/jpeg" || ct == "image/png" || ct == "image/gif" || ct == "image/webp" || ct == "image/svg+xml"
	case strings.HasPrefix(ct, "video/"):
		return ct == "video/mp4" || ct == "video/webm"
	case strings.HasPrefix(ct, "audio/"):
		return ct == "audio/mpeg" || ct == "audio/ogg"
	}
	return false
}

// GenerateDownloadHash creates a 24-byte url-safe base64 token (like original 24 bytes raw -> ~32 chars)
func generateDownloadHash() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil // note: original uses urlsafe_base64 which is same as URLEncoding without padding sometimes, but fine
}

// CreateSharedFileFromUpload creates the DB record + writes the file to storage.
// fileReader is consumed. Sanitizes filename.
func CreateSharedFileFromUpload(db *sql.DB, userID int64, originalName string, contentType string, size int64, maxDL, ttl int, fileReader io.Reader, storageRoot string) (*SharedFile, error) {
	if size <= 0 {
		return nil, errors.New("empty file")
	}
	if size > config.Cfg.Security.MaxUploadSizeBytes {
		return nil, fmt.Errorf("file too large (max %d bytes)", config.Cfg.Security.MaxUploadSizeBytes)
	}

	// sanitize
	safeName := services.SanitizeFilename(originalName, contentType)

	// check quota (loose, with grace)
	u, err := FindUserByID(db, userID)
	if err != nil {
		return nil, err
	}
	used, _ := u.StorageUsed(db)
	quota := u.DiskQuota()
	grace := config.Cfg.Security.DiskQuotaGraceBytes
	if used+size > quota+grace {
		return nil, errors.New("storage quota exceeded")
	}

	// Defense-in-depth: callers (e.g. the web handler) are responsible for
	// validating maxDL/ttl against the authenticated user's privileges
	// (non-admins may not request 0/unlimited or out-of-range values).
	// We only sanity-check here.
	if maxDL < 0 || ttl < 0 {
		return nil, errors.New("invalid download limit or expiration time")
	}

	// mime allow check (if any enabled)
	if allowed, _ := AllowedMimeTypesEnabled(db); len(allowed) > 0 {
		ok := false
		for _, m := range allowed {
			if m == contentType {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("file type %s not allowed", contentType)
		}
	}

	hash, err := generateDownloadHash()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	var expires time.Time
	if ttl == 0 {
		expires = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	} else {
		expires = now.Add(time.Duration(ttl) * time.Hour)
	}

	// storage key: uploads/<random or hash prefix>
	key := fmt.Sprintf("uploads/%s", hash[:12]) // short unique under uploads/
	fullPath := filepath.Join(storageRoot, key)

	// ensure dir
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return nil, err
	}

	// write file
	f, err := os.Create(fullPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	written, err := io.Copy(f, fileReader)
	if err != nil {
		os.Remove(fullPath)
		return nil, err
	}
	if written != size {
		os.Remove(fullPath)
		return nil, errors.New("size mismatch on write")
	}

	// insert record
	res, err := db.Exec(`
		INSERT INTO shared_files 
		(user_id, download_hash, original_filename, content_type, file_size, ttl_hours, expires_at, max_downloads, download_count, storage_key, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
		userID, hash, safeName, contentType, size, ttl, expires, maxDL, key, now, now)
	if err != nil {
		os.Remove(fullPath)
		return nil, err
	}
	id, _ := res.LastInsertId()

	sf := &SharedFile{
		ID:               id,
		UserID:           userID,
		DownloadHash:     hash,
		OriginalFilename: safeName,
		ContentType:      contentType,
		FileSize:         size,
		TTLHours:         ttl,
		ExpiresAt:        expires,
		MaxDownloads:     maxDL,
		DownloadCount:    0,
		StorageKey:       key,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	return sf, nil
}

func FindSharedFileByHash(db *sql.DB, hash string) (*SharedFile, error) {
	var f SharedFile
	var expires time.Time
	err := db.QueryRow(`
		SELECT id, user_id, download_hash, original_filename, content_type, file_size,
		       ttl_hours, expires_at, max_downloads, download_count, storage_key,
		       created_at, updated_at
		FROM shared_files WHERE download_hash = ?`, hash).
		Scan(&f.ID, &f.UserID, &f.DownloadHash, &f.OriginalFilename, &f.ContentType, &f.FileSize,
			&f.TTLHours, &expires, &f.MaxDownloads, &f.DownloadCount, &f.StorageKey,
			&f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		return nil, err
	}
	f.ExpiresAt = expires.UTC()
	// optionally load user
	u, _ := FindUserByID(db, f.UserID)
	f.User = u
	return &f, nil
}

func FindSharedFilesByUser(db *sql.DB, userID int64, activeOnly bool) ([]*SharedFile, error) {
	q := `
		SELECT id, user_id, download_hash, original_filename, content_type, file_size,
		       ttl_hours, expires_at, max_downloads, download_count, storage_key,
		       created_at, updated_at
		FROM shared_files WHERE user_id = ?
	`
	if activeOnly {
		q += ` AND (max_downloads = 0 OR download_count < max_downloads) AND (ttl_hours = 0 OR expires_at > ?)`
	}
	q += ` ORDER BY created_at DESC`

	args := []interface{}{userID}
	if activeOnly {
		args = append(args, time.Now().UTC())
	}

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*SharedFile
	for rows.Next() {
		var f SharedFile
		var exp time.Time
		if err := rows.Scan(&f.ID, &f.UserID, &f.DownloadHash, &f.OriginalFilename, &f.ContentType, &f.FileSize,
			&f.TTLHours, &exp, &f.MaxDownloads, &f.DownloadCount, &f.StorageKey, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		f.ExpiresAt = exp.UTC()
		out = append(out, &f)
	}
	return out, nil
}

func (f *SharedFile) IncrementDownload(db *sql.DB) (bool, error) {
	// Atomic-ish: only increment if still valid
	res, err := db.Exec(`
		UPDATE shared_files
		SET download_count = download_count + 1, updated_at = ?
		WHERE id = ? AND (max_downloads = 0 OR download_count < max_downloads) AND (ttl_hours = 0 OR expires_at > ? )`,
		time.Now().UTC(), f.ID, time.Now().UTC())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n == 1 {
		f.DownloadCount++
		return true, nil
	}
	return false, nil
}

func (f *SharedFile) Delete(db *sql.DB, storageRoot string) error {
	// remove file
	if f.StorageKey != "" {
		_ = os.Remove(filepath.Join(storageRoot, f.StorageKey))
	}
	_, err := db.Exec(`DELETE FROM shared_files WHERE id = ?`, f.ID)
	return err
}

// FullPath returns absolute path on disk for serving
func (f *SharedFile) FullPath(storageRoot string) string {
	return filepath.Join(storageRoot, f.StorageKey)
}

// AllowedMimeTypesEnabled returns list of enabled mime strings for validation
func AllowedMimeTypesEnabled(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT mime_type FROM allowed_mime_types WHERE enabled = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, err
		}
		list = append(list, m)
	}
	return list, nil
}

// SeedDefaultMimeTypes inserts the common list if table empty
func SeedDefaultMimeTypes(db *sql.DB) error {
	var count int
	db.QueryRow(`SELECT COUNT(*) FROM allowed_mime_types`).Scan(&count)
	if count > 0 {
		return nil
	}

	defaults := map[string]string{
		"application/pdf":                "PDF Document",
		"application/zip":                "ZIP Archive",
		"application/x-7z-compressed":    "7-Zip Archive",
		"application/gzip":               "GZip Archive",
		"application/x-tar":              "TAR Archive",
		"application/x-xz":               "XZ Archive",
		"application/x-bzip2":            "BZip2 Archive",
		"application/x-rar-compressed":   "RAR Archive",
		"application/octet-stream":       "Binary File",
		"image/jpeg":                     "JPEG Image",
		"image/png":                      "PNG Image",
		"image/gif":                      "GIF Image",
		"image/webp":                     "WebP Image",
		"image/svg+xml":                  "SVG Image",
		"video/mp4":                      "MP4 Video",
		"video/webm":                     "WebM Video",
		"audio/mpeg":                     "MP3 Audio",
		"audio/ogg":                      "OGG Audio",
		"text/plain":                     "Plain Text",
		"text/csv":                       "CSV File",
		"application/json":               "JSON File",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document": "Word Document",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":       "Excel Spreadsheet",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation": "PowerPoint",
	}

	now := time.Now().UTC()
	for mt, desc := range defaults {
		_, err := db.Exec(`INSERT OR IGNORE INTO allowed_mime_types (mime_type, description, enabled, created_at, updated_at) VALUES (?, ?, 1, ?, ?)`,
			mt, desc, now, now)
		if err != nil {
			return err
		}
	}
	return nil
}

// DetectContentType is provided for future; handlers use http.DetectContentType on seekable multipart files directly.
func DetectContentType(r io.Reader, filename string) (string, error) {
	buf := make([]byte, 512)
	n, _ := io.ReadFull(r, buf)
	if n > 0 {
		ct := http.DetectContentType(buf[:n])
		if ct != "application/octet-stream" {
			return ct, nil
		}
	}
	if ext := mime.TypeByExtension(filepath.Ext(filename)); ext != "" {
		return ext, nil
	}
	return "application/octet-stream", nil
}
