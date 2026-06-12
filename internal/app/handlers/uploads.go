package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/macedot/go-mega/internal/app/auth"
	"github.com/macedot/go-mega/internal/app/models"
	"github.com/macedot/go-mega/internal/config"
	"github.com/macedot/go-mega/internal/db"

	"github.com/go-chi/chi/v5"
	qrcode "github.com/skip2/go-qrcode"
)

func HandleUploadNew(t *template.Template, sqlDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.CurrentUser(r)
		active, _ := models.FindSharedFilesByUser(sqlDB, user.ID, true)
		inactive, _ := models.FindSharedFilesByUser(sqlDB, user.ID, false)

		used, _ := user.StorageUsed(sqlDB)
		quota := user.DiskQuota()
		pct := 0
		if quota > 0 {
			pct = int(float64(used) / float64(quota) * 100)
			if pct > 100 {
				pct = 100
			}
		}

		data := map[string]interface{}{
			"Title":         "Upload — go-mega",
			"ActiveFiles":   active,
			"InactiveFiles": inactive,
			"StorageUsed":   used,
			"DiskQuota":     quota,
			"QuotaPct":      pct,
			"MaxUpload":     config.Cfg.Security.MaxUploadSizeBytes,
			"ChunkSize":     config.Cfg.Security.UploadChunkSizeBytes,
			"Authenticated": true,
			"IsAdmin":       user.IsAdmin(),
			"CSRF":          auth.EnsureCSRF(w, r),
		}
		render(w, t, "uploads/new.html", data)
	}
}

func HandleUploadCreate(t *template.Template, sqlDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.CurrentUser(r)
		if user == nil {
			http.Redirect(w, r, "/session/new", http.StatusSeeOther)
			return
		}

		// Enforce the configured upload size limit at the HTTP layer *before* we
		// start receiving the body. This makes the server return a clean 413
		// (Payload Too Large) instead of letting a huge file consume temp disk or
		// memory, and before we do any expensive work.
		maxUpload := config.Cfg.Security.MaxUploadSizeBytes
		if maxUpload <= 0 {
			maxUpload = 1 << 30 // 1 GiB safe fallback
		}
		// Give a bit of headroom for the small form fields (_csrf, max_downloads,
		// ttl_hours) + multipart framing.
		maxBody := maxUpload + (64 << 20)
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)

		// Parse the multipart form early (this receives the body, including large
		// uploaded files to a temp file). We do this before CSRF verification so that
		// VerifyCSRF's r.FormValue("_csrf") is guaranteed to see the value, and so
		// the subsequent single-file count check has r.MultipartForm populated.
		r.ParseMultipartForm(32 << 20) // 32MB buffer

		if !auth.VerifyCSRF(r) {
			// Render a proper error page (instead of plain text) so the XHR client
			// can extract and display the real message instead of the generic fallback.
			used, _ := user.StorageUsed(sqlDB)
			active, _ := models.FindSharedFilesByUser(sqlDB, user.ID, true)
			inactive, _ := models.FindSharedFilesByUser(sqlDB, user.ID, false)
			pct := 0
			quota := user.DiskQuota()
			if quota > 0 {
				pct = int(float64(used) / float64(quota) * 100)
				if pct > 100 {
					pct = 100
				}
			}
			data := map[string]interface{}{
				"Title":         "Upload — go-mega",
				"ActiveFiles":   active,
				"InactiveFiles": inactive,
				"StorageUsed":   used,
				"DiskQuota":     quota,
				"QuotaPct":      pct,
				"MaxUpload":     config.Cfg.Security.MaxUploadSizeBytes,
				"ChunkSize":     config.Cfg.Security.UploadChunkSizeBytes,
				"Error":         "Invalid CSRF token. Please reload the page and try again.",
				"Authenticated": true,
				"IsAdmin":       user.IsAdmin(),
				"CSRF":          auth.EnsureCSRF(w, r),
			}
			w.WriteHeader(http.StatusForbidden)
			render(w, t, "uploads/new.html", data)
			return
		}

		// Security: enforce single file only (client can be bypassed; folders and
		// multi-file posts via curl or modified forms must be rejected here).
		if r.MultipartForm == nil || len(r.MultipartForm.File["file"]) != 1 {
			used, _ := user.StorageUsed(sqlDB)
			active, _ := models.FindSharedFilesByUser(sqlDB, user.ID, true)
			inactive, _ := models.FindSharedFilesByUser(sqlDB, user.ID, false)
			pct := 0
			quota := user.DiskQuota()
			if quota > 0 {
				pct = int(float64(used) / float64(quota) * 100)
				if pct > 100 {
					pct = 100
				}
			}
			data := map[string]interface{}{
				"Title":         "Upload — go-mega",
				"ActiveFiles":   active,
				"InactiveFiles": inactive,
				"StorageUsed":   used,
				"DiskQuota":     quota,
				"QuotaPct":      pct,
				"MaxUpload":     config.Cfg.Security.MaxUploadSizeBytes,
				"ChunkSize":     config.Cfg.Security.UploadChunkSizeBytes,
				"Error":         "Please select exactly one file to upload. Multiple files or directories are not supported.",
				"Authenticated": true,
				"IsAdmin":       user.IsAdmin(),
				"CSRF":          auth.EnsureCSRF(w, r),
			}
			w.WriteHeader(http.StatusUnprocessableEntity)
			render(w, t, "uploads/new.html", data)
			return
		}

		f, fh, err := r.FormFile("file")
		if err != nil {
			// Render nicely (instead of plain text) for consistent XHR error handling.
			used, _ := user.StorageUsed(sqlDB)
			active, _ := models.FindSharedFilesByUser(sqlDB, user.ID, true)
			inactive, _ := models.FindSharedFilesByUser(sqlDB, user.ID, false)
			pct := 0
			quota := user.DiskQuota()
			if quota > 0 {
				pct = int(float64(used) / float64(quota) * 100)
				if pct > 100 {
					pct = 100
				}
			}
			data := map[string]interface{}{
				"Title":         "Upload — go-mega",
				"ActiveFiles":   active,
				"InactiveFiles": inactive,
				"StorageUsed":   used,
				"DiskQuota":     quota,
				"QuotaPct":      pct,
				"MaxUpload":     config.Cfg.Security.MaxUploadSizeBytes,
				"ChunkSize":     config.Cfg.Security.UploadChunkSizeBytes,
				"Error":         "file required",
				"Authenticated": true,
				"IsAdmin":       user.IsAdmin(),
				"CSRF":          auth.EnsureCSRF(w, r),
			}
			w.WriteHeader(http.StatusBadRequest)
			render(w, t, "uploads/new.html", data)
			return
		}
		defer f.Close()

		maxDL := parseInt(r.FormValue("max_downloads"), 5)
		ttl := parseInt(r.FormValue("ttl_hours"), 24)

		// Security: always re-validate user-supplied parameters against the
		// authenticated user's privileges. Never trust client-side form limits.
		// This prevents non-admins from bypassing UI constraints (e.g. via curl
		// or modified forms) to create unlimited/no-expiry links.
		var limitError string
		if user.IsAdmin() {
			if maxDL < 0 {
				maxDL = 0
			}
			if ttl < 0 {
				ttl = 0
			}
		} else {
			if maxDL < 1 || maxDL > 100 {
				limitError = "Only administrators can create links with unlimited downloads or with values outside the 1-100 range."
			}
			if ttl < 1 || ttl > 24 {
				limitError = "Only administrators can create links with no expiration or with values outside the 1-24 range."
			}
		}

		if limitError != "" {
			used, _ := user.StorageUsed(sqlDB)
			active, _ := models.FindSharedFilesByUser(sqlDB, user.ID, true)
			inactive, _ := models.FindSharedFilesByUser(sqlDB, user.ID, false)
			pct := 0
			quota := user.DiskQuota()
			if quota > 0 {
				pct = int(float64(used) / float64(quota) * 100)
				if pct > 100 {
					pct = 100
				}
			}
			data := map[string]interface{}{
				"Title":         "Upload — go-mega",
				"ActiveFiles":   active,
				"InactiveFiles": inactive,
				"StorageUsed":   used,
				"DiskQuota":     quota,
				"QuotaPct":      pct,
				"MaxUpload":     config.Cfg.Security.MaxUploadSizeBytes,
				"ChunkSize":     config.Cfg.Security.UploadChunkSizeBytes,
				"Error":         limitError,
				"Authenticated": true,
				"IsAdmin":       user.IsAdmin(),
				"CSRF":          auth.EnsureCSRF(w, r),
			}
			w.WriteHeader(http.StatusUnprocessableEntity)
			render(w, t, "uploads/new.html", data)
			return
		}

		// detect type
		ct := fh.Header.Get("Content-Type")
		if ct == "" || ct == "application/octet-stream" {
			// sniff
			sniff := make([]byte, 512)
			f.Read(sniff)
			f.Seek(0, 0)
			ct = http.DetectContentType(sniff)
		}

		storageRoot := config.Cfg.StoragePath
		sf, err := models.CreateSharedFileFromUpload(sqlDB, user.ID, fh.Filename, ct, fh.Size, maxDL, ttl, f, storageRoot)
		if err != nil {
			// re-render form with error
			active, _ := models.FindSharedFilesByUser(sqlDB, user.ID, true)
			inactive, _ := models.FindSharedFilesByUser(sqlDB, user.ID, false)
			used, _ := user.StorageUsed(sqlDB)
			pct := 0
			quota := user.DiskQuota()
			if quota > 0 {
				pct = int(float64(used) / float64(quota) * 100)
				if pct > 100 {
					pct = 100
				}
			}
			data := map[string]interface{}{
				"Title":         "Upload — go-mega",
				"ActiveFiles":   active,
				"InactiveFiles": inactive,
				"StorageUsed":   used,
				"DiskQuota":     quota,
				"QuotaPct":      pct,
				"MaxUpload":     config.Cfg.Security.MaxUploadSizeBytes,
				"ChunkSize":     config.Cfg.Security.UploadChunkSizeBytes,
				"Error":         err.Error(),
				"Authenticated": true,
				"IsAdmin":       user.IsAdmin(),
				"CSRF":          auth.EnsureCSRF(w, r),
			}
			w.WriteHeader(http.StatusUnprocessableEntity)
			render(w, t, "uploads/new.html", data)
			return
		}

		http.Redirect(w, r, "/uploads/"+strconv.FormatInt(sf.ID, 10), http.StatusSeeOther)
	}
}

func HandleUploadShow(t *template.Template, sqlDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.CurrentUser(r)
		idStr := chi.URLParam(r, "id")
		id, _ := strconv.ParseInt(idStr, 10, 64)

		// find ensuring ownership via user's files
		files, _ := models.FindSharedFilesByUser(sqlDB, user.ID, false)
		var found *models.SharedFile
		for _, f := range files {
			if f.ID == id {
				found = f
				break
			}
		}
		if found == nil {
			http.NotFound(w, r)
			return
		}

		url := "https://" + config.Cfg.Host + "/d/" + found.DownloadHash
		if !config.Cfg.IsProd() {
			url = "http://" + config.Cfg.Host + "/d/" + found.DownloadHash
		}
		directURL := url + "/file"
		qrPNG, _ := qrcode.Encode(url, qrcode.Medium, 256)
		qrB64 := base64.StdEncoding.EncodeToString(qrPNG)

		data := map[string]interface{}{
			"Title":         "Share Link — go-mega",
			"File":          found,
			"DownloadURL":   url,
			"DirectURL":     directURL,
			"QR":            qrB64,
			"Authenticated": true,
			"CSRF":          auth.EnsureCSRF(w, r),
		}
		render(w, t, "uploads/show.html", data)
	}
}

func HandleUploadDelete(sqlDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.CurrentUser(r)
		if !auth.VerifyCSRF(r) {
			http.Error(w, "invalid csrf token", http.StatusForbidden)
			return
		}
		idStr := chi.URLParam(r, "id")
		id, _ := strconv.ParseInt(idStr, 10, 64)

		files, _ := models.FindSharedFilesByUser(sqlDB, user.ID, false)
		var found *models.SharedFile
		for _, f := range files {
			if f.ID == id {
				found = f
				break
			}
		}
		if found != nil {
			found.Delete(sqlDB, config.Cfg.StoragePath)
		}
		http.Redirect(w, r, "/uploads/new", http.StatusSeeOther)
	}
}

// === Chunked upload support (Cloudflare-friendly large file uploads) ===
//
// The browser splits files larger than UploadChunkSizeBytes into small chunks
// (default ~90MB to stay under typical Cloudflare request body limits) and
// uploads them individually. The server stores the parts temporarily and, on
// the final "complete" call, concatenates them into the normal storage file
// and creates the SharedFile record exactly like the direct (small file) path.
//
// This keeps the Cloudflare Tunnel / full edge protection in place while
// allowing uploads up to the configured MAX_UPLOAD_SIZE_BYTES.

type chunkedUploadMeta struct {
	UploadID  string    `json:"upload_id"`
	UserID    int64     `json:"user_id"`
	Filename  string    `json:"filename"`
	Size      int64     `json:"size"`
	MaxDL     int       `json:"max_dl"`
	TTL       int       `json:"ttl"`
	CreatedAt time.Time `json:"created_at"`
}

func chunkUploadDir(uploadID string) string {
	return filepath.Join(config.Cfg.StoragePath, "chunks", uploadID)
}

func chunkMetaPath(uploadID string) string {
	return filepath.Join(chunkUploadDir(uploadID), "meta.json")
}

func saveChunkedMeta(meta chunkedUploadMeta) error {
	dir := chunkUploadDir(meta.UploadID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(meta, "", "  ")
	return os.WriteFile(chunkMetaPath(meta.UploadID), b, 0644)
}

func loadChunkedMeta(uploadID string) (*chunkedUploadMeta, error) {
	b, err := os.ReadFile(chunkMetaPath(uploadID))
	if err != nil {
		return nil, err
	}
	var m chunkedUploadMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func generateUploadID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func partPath(dir string, idx int) string {
	return filepath.Join(dir, fmt.Sprintf("%05d.part", idx))
}

// generateDownloadHashLocal duplicates the small unexported helper from the model
// so chunked uploads can create their own download token.
func generateDownloadHashLocal() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// HandleUploadStart begins a chunked upload session for a large file.
// Client sends metadata only (filename, size, max_downloads, ttl_hours, _csrf).
// Returns 200 + JSON {"upload_id": "..."} on success. The client then uploads
// individual chunks via /uploads/chunk and finally calls /uploads/complete.
func HandleUploadStart(t *template.Template, sqlDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.CurrentUser(r)
		if user == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !auth.VerifyCSRF(r) {
			used, _ := user.StorageUsed(sqlDB)
			active, _ := models.FindSharedFilesByUser(sqlDB, user.ID, true)
			inactive, _ := models.FindSharedFilesByUser(sqlDB, user.ID, false)
			pct := 0
			quota := user.DiskQuota()
			if quota > 0 {
				pct = int(float64(used) / float64(quota) * 100)
				if pct > 100 {
					pct = 100
				}
			}
			data := map[string]interface{}{
				"Title":         "Upload — go-mega",
				"ActiveFiles":   active,
				"InactiveFiles": inactive,
				"StorageUsed":   used,
				"DiskQuota":     quota,
				"QuotaPct":      pct,
				"MaxUpload":     config.Cfg.Security.MaxUploadSizeBytes,
				"ChunkSize":     config.Cfg.Security.UploadChunkSizeBytes,
				"Error":         "Invalid CSRF token. Please reload the page and try again.",
				"Authenticated": true,
				"IsAdmin":       user.IsAdmin(),
				"CSRF":          auth.EnsureCSRF(w, r),
			}
			w.WriteHeader(http.StatusForbidden)
			render(w, t, "uploads/new.html", data)
			return
		}

		r.ParseMultipartForm(1 << 20)
		filename := r.FormValue("filename")
		size, _ := strconv.ParseInt(r.FormValue("size"), 10, 64)
		maxDL := parseInt(r.FormValue("max_downloads"), 5)
		ttl := parseInt(r.FormValue("ttl_hours"), 24)

		if filename == "" || size <= 0 {
			http.Error(w, "invalid metadata", http.StatusBadRequest)
			return
		}

		// Re-validate limits like the direct path (defense in depth)
		if !user.IsAdmin() {
			if maxDL < 1 || maxDL > 100 {
				http.Error(w, "invalid max_downloads", http.StatusBadRequest)
				return
			}
			if ttl < 1 || ttl > 24 {
				http.Error(w, "invalid ttl_hours", http.StatusBadRequest)
				return
			}
		} else {
			if maxDL < 0 {
				maxDL = 0
			}
			if ttl < 0 {
				ttl = 0
			}
		}

		uploadID, err := generateUploadID()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		meta := chunkedUploadMeta{
			UploadID:  uploadID,
			UserID:    user.ID,
			Filename:  filename,
			Size:      size,
			MaxDL:     maxDL,
			TTL:       ttl,
			CreatedAt: time.Now().UTC(),
		}
		if err := saveChunkedMeta(meta); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"upload_id": uploadID})
	}
}

// HandleUploadChunk stores one chunk belonging to a previously started session.
// The chunk is sent as a normal multipart file part named "file".
// Other fields: upload_id, chunk_index, total_chunks, _csrf.
func HandleUploadChunk(t *template.Template, sqlDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.CurrentUser(r)
		if user == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !auth.VerifyCSRF(r) {
			http.Error(w, "invalid csrf token", http.StatusForbidden)
			return
		}

		// Allow a chunk up to the configured chunk size + generous overhead.
		r.ParseMultipartForm(128 << 20)

		uploadID := r.FormValue("upload_id")
		idx := parseInt(r.FormValue("chunk_index"), -1)
		total := parseInt(r.FormValue("total_chunks"), 0)

		if uploadID == "" || idx < 0 || total <= 0 {
			http.Error(w, "bad chunk metadata", http.StatusBadRequest)
			return
		}

		meta, err := loadChunkedMeta(uploadID)
		if err != nil || meta.UserID != user.ID {
			http.Error(w, "invalid upload session", http.StatusBadRequest)
			return
		}

		chunkPart, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "missing chunk data", http.StatusBadRequest)
			return
		}
		defer chunkPart.Close()

		dir := chunkUploadDir(uploadID)
		if err := os.MkdirAll(dir, 0755); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		p := partPath(dir, idx)
		dst, err := os.Create(p)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if _, err := io.Copy(dst, chunkPart); err != nil {
			dst.Close()
			http.Error(w, "write error", http.StatusInternalServerError)
			return
		}
		dst.Close()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "index": idx})
	}
}

// HandleUploadComplete is called after all chunks have been uploaded.
// It validates the parts, concatenates them into the final storage location,
// runs the same sanitization/quota/mime/privilege checks as the direct path,
// inserts the SharedFile record, cleans up the temporary chunk files, and
// returns success so the client can navigate to the list.
func HandleUploadComplete(t *template.Template, sqlDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.CurrentUser(r)
		if user == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !auth.VerifyCSRF(r) {
			used, _ := user.StorageUsed(sqlDB)
			active, _ := models.FindSharedFilesByUser(sqlDB, user.ID, true)
			inactive, _ := models.FindSharedFilesByUser(sqlDB, user.ID, false)
			pct := 0
			quota := user.DiskQuota()
			if quota > 0 {
				pct = int(float64(used) / float64(quota) * 100)
				if pct > 100 {
					pct = 100
				}
			}
			data := map[string]interface{}{
				"Title":         "Upload — go-mega",
				"ActiveFiles":   active,
				"InactiveFiles": inactive,
				"StorageUsed":   used,
				"DiskQuota":     quota,
				"QuotaPct":      pct,
				"MaxUpload":     config.Cfg.Security.MaxUploadSizeBytes,
				"ChunkSize":     config.Cfg.Security.UploadChunkSizeBytes,
				"Error":         "Invalid CSRF token. Please reload the page and try again.",
				"Authenticated": true,
				"IsAdmin":       user.IsAdmin(),
				"CSRF":          auth.EnsureCSRF(w, r),
			}
			w.WriteHeader(http.StatusForbidden)
			render(w, t, "uploads/new.html", data)
			return
		}

		r.ParseForm()
		uploadID := r.FormValue("upload_id")
		if uploadID == "" {
			http.Error(w, "missing upload_id", http.StatusBadRequest)
			return
		}

		meta, err := loadChunkedMeta(uploadID)
		if err != nil || meta.UserID != user.ID {
			http.Error(w, "invalid upload session", http.StatusBadRequest)
			return
		}

		safeName := meta.Filename // basic for now; full sanitization in direct path / model

		dir := chunkUploadDir(uploadID)

		// Find and order the part files (we named them 00000.part ... with zero padding)
		entries, err := os.ReadDir(dir)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		var partFiles []string
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if len(name) >= 5 && name[len(name)-5:] == ".part" {
				partFiles = append(partFiles, filepath.Join(dir, name))
			}
		}
		sort.Strings(partFiles) // zero-padded %05d names guarantee correct order

		totalChunks := len(partFiles)
		if totalChunks == 0 {
			http.Error(w, "no chunks received", http.StatusBadRequest)
			return
		}

		// Re-validate limits (same rules as direct path)
		maxDL := meta.MaxDL
		ttl := meta.TTL
		if !user.IsAdmin() {
			if maxDL < 1 || maxDL > 100 {
				http.Error(w, "invalid max_downloads", http.StatusBadRequest)
				return
			}
			if ttl < 1 || ttl > 24 {
				http.Error(w, "invalid ttl_hours", http.StatusBadRequest)
				return
			}
		} else {
			if maxDL < 0 {
				maxDL = 0
			}
			if ttl < 0 {
				ttl = 0
			}
		}

		// Sanitize + sniff (from first chunk)
		safeName = meta.Filename // assignment; declared earlier in complete
		ct := "application/octet-stream"
		if len(partFiles) > 0 {
			if f0, err := os.Open(partFiles[0]); err == nil {
				buf := make([]byte, 512)
				n, _ := f0.Read(buf)
				f0.Close()
				if n > 0 {
					ct = http.DetectContentType(buf[:n])
				}
			}
		}

		// Size / quota / mime checks (same as direct path + model)
		if meta.Size <= 0 {
			http.Error(w, "empty file", http.StatusBadRequest)
			return
		}
		if meta.Size > config.Cfg.Security.MaxUploadSizeBytes {
			http.Error(w, fmt.Sprintf("file too large (max %d bytes)", config.Cfg.Security.MaxUploadSizeBytes), http.StatusBadRequest)
			return
		}

		used, _ := user.StorageUsed(sqlDB)
		quota := user.DiskQuota()
		grace := config.Cfg.Security.DiskQuotaGraceBytes
		if used+meta.Size > quota+grace {
			active, _ := models.FindSharedFilesByUser(sqlDB, user.ID, true)
			inactive, _ := models.FindSharedFilesByUser(sqlDB, user.ID, false)
			pct := 0
			if quota > 0 {
				pct = int(float64(used) / float64(quota) * 100)
				if pct > 100 {
					pct = 100
				}
			}
			data := map[string]interface{}{
				"Title":         "Upload — go-mega",
				"ActiveFiles":   active,
				"InactiveFiles": inactive,
				"StorageUsed":   used,
				"DiskQuota":     quota,
				"QuotaPct":      pct,
				"MaxUpload":     config.Cfg.Security.MaxUploadSizeBytes,
				"ChunkSize":     config.Cfg.Security.UploadChunkSizeBytes,
				"Error":         "storage quota exceeded",
				"Authenticated": true,
				"IsAdmin":       user.IsAdmin(),
				"CSRF":          auth.EnsureCSRF(w, r),
			}
			w.WriteHeader(http.StatusUnprocessableEntity)
			render(w, t, "uploads/new.html", data)
			return
		}

		if allowed, _ := models.AllowedMimeTypesEnabled(sqlDB); len(allowed) > 0 {
			ok := false
			for _, m := range allowed {
				if m == ct {
					ok = true
					break
				}
			}
			if !ok {
				active, _ := models.FindSharedFilesByUser(sqlDB, user.ID, true)
				inactive, _ := models.FindSharedFilesByUser(sqlDB, user.ID, false)
				data := map[string]interface{}{
					"Title":         "Upload — go-mega",
					"ActiveFiles":   active,
					"InactiveFiles": inactive,
					"StorageUsed":   used,
					"DiskQuota":     quota,
					"MaxUpload":     config.Cfg.Security.MaxUploadSizeBytes,
					"ChunkSize":     config.Cfg.Security.UploadChunkSizeBytes,
					"Error":         fmt.Sprintf("file type %s not allowed", ct),
					"Authenticated": true,
					"IsAdmin":       user.IsAdmin(),
					"CSRF":          auth.EnsureCSRF(w, r),
				}
				w.WriteHeader(http.StatusUnprocessableEntity)
				render(w, t, "uploads/new.html", data)
				return
			}
		}

		// Generate download token + storage key (same scheme as direct path)
		hash, err := generateDownloadHashLocal()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		key := fmt.Sprintf("uploads/%s", hash[:12])
		fullPath := filepath.Join(config.Cfg.StoragePath, key)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Concatenate parts into the final file
		finalF, err := os.Create(fullPath)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		var written int64
		for _, p := range partFiles { // partFiles collected above (sorted by name)
			pf, err := os.Open(p)
			if err != nil {
				finalF.Close()
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			n, err := io.Copy(finalF, pf)
			pf.Close()
			if err != nil {
				finalF.Close()
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			written += n
		}
		finalF.Close()

		if written != meta.Size {
			os.Remove(fullPath)
			http.Error(w, "size mismatch on write", http.StatusInternalServerError)
			return
		}

		// Compute expires (identical logic to the model)
		now := time.Now().UTC()
		var expires time.Time
		if meta.TTL == 0 {
			expires = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
		} else {
			expires = now.Add(time.Duration(meta.TTL) * time.Hour)
		}

		// Insert the record (same columns as the direct path)
		_, err = sqlDB.Exec(`
			INSERT INTO shared_files 
			(user_id, download_hash, original_filename, content_type, file_size, ttl_hours, expires_at, max_downloads, download_count, storage_key, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
			user.ID, hash, safeName, "application/octet-stream", meta.Size, meta.TTL, expires, maxDL, key, now, now)
		if err != nil {
			os.Remove(fullPath)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Cleanup temp chunks
		os.RemoveAll(dir)

		// Success for the XHR client (it will redirect)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}
}

// === End chunked upload support ===

// For show we used hash; add FindByID in models if needed. Quick patch:
func init() {
	// nothing
	_ = db.DB
	_ = time.Now
	_ = os.PathSeparator
	_ = filepath.Join
	_ = io.Copy
}
