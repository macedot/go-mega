package handlers

import (
	"database/sql"
	"html/template"
	"net/http"
	"os"
	"strings"

	"github.com/macedot/go-mega/internal/app/auth"
	"github.com/macedot/go-mega/internal/app/models"
	"github.com/macedot/go-mega/internal/config"
	"github.com/macedot/go-mega/internal/db"

	"github.com/go-chi/chi/v5"
)

func HandleDownloadShow(t *template.Template, sqlDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hash := chi.URLParam(r, "hash")
		sf, err := models.FindSharedFileByHash(sqlDB, hash)
		if err != nil || sf == nil {
			// record invalid for ban logic (later)
			recordInvalidAccess(r, sqlDB)
			render(w, t, "downloads/not_found.html", map[string]interface{}{"Title": "Not Found"})
			return
		}
		if sf.User != nil && sf.User.IsBanned() {
			render(w, t, "downloads/expired.html", map[string]interface{}{"Title": "Expired"})
			return
		}
		if !sf.Active() {
			render(w, t, "downloads/expired.html", map[string]interface{}{"Title": "Expired", "File": sf})
			return
		}

		data := map[string]interface{}{
			"Title":         "Download " + sf.OriginalFilename,
			"File":          sf,
			"Authenticated": auth.Authenticated(r),
			"CSRF":          auth.EnsureCSRF(w, r),
		}
		render(w, t, "downloads/show.html", data)
	}
}

func HandleDownloadConsume(t *template.Template, sqlDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// CSRF is only required for POST (the two-step form on the landing page).
		// For direct download links (GET /d/{hash}/file) we skip it — the secret hash itself
		// provides the access control, and we still perform the consume (increment + active check).
		if r.Method == http.MethodPost {
			if !auth.VerifyCSRF(r) {
				http.Error(w, "invalid csrf token", http.StatusForbidden)
				return
			}
		}
		hash := chi.URLParam(r, "hash")
		sf, err := models.FindSharedFileByHash(sqlDB, hash)
		if err != nil || sf == nil {
			recordInvalidAccess(r, sqlDB)
			if r.Method == http.MethodGet {
				http.NotFound(w, r)
				return
			}
			http.NotFound(w, r)
			return
		}
		if sf.User != nil && sf.User.IsBanned() {
			if r.Method == http.MethodGet {
				http.Error(w, "link expired or inactive", http.StatusGone)
				return
			}
			render(w, t, "downloads/expired.html", nil)
			return
		}
		ok, err := sf.IncrementDownload(sqlDB)
		if err != nil || !ok {
			if r.Method == http.MethodGet {
				http.Error(w, "link expired or download limit reached", http.StatusGone)
				return
			}
			render(w, t, "downloads/expired.html", map[string]interface{}{"File": sf})
			return
		}

		// TODO: enqueue download notification job for owner if online

		full := sf.FullPath(config.Cfg.StoragePath)
		f, err := os.Open(full)
		if err != nil {
			http.Error(w, "file missing", http.StatusGone)
			return
		}
		defer f.Close()

		w.Header().Set("Content-Type", sf.ContentType)
		// Safe filename in disposition (sanitizer already removes ", but double-escape for defense).
		safeName := strings.ReplaceAll(sf.OriginalFilename, `"`, "")
		w.Header().Set("Content-Disposition", `attachment; filename="`+safeName+`"`)
		http.ServeContent(w, r, sf.OriginalFilename, sf.UpdatedAt, f)
	}
}

func HandleDownloadPreview(sqlDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hash := chi.URLParam(r, "hash")
		sf, err := models.FindSharedFileByHash(sqlDB, hash)
		if err != nil || sf == nil || !sf.Active() || !sf.IsPreviewable() {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		full := sf.FullPath(config.Cfg.StoragePath)
		f, err := os.Open(full)
		if err != nil {
			w.WriteHeader(http.StatusGone)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", sf.ContentType)
		http.ServeContent(w, r, sf.OriginalFilename, sf.UpdatedAt, f)
	}
}

func recordInvalidAccess(r *http.Request, sqlDB *sql.DB) {
	// Security: record abuse (invalid hash access). Currently a stub.
	// In production this should feed the Ban model / rate limiter (e.g. after N attempts auto-ban IP).
	// See middleware/ratelimit.go and schema for bans table.
	ip := auth.RealIP(r)
	// TODO: implement counting + ban creation using sqlDB (e.g. INSERT or increment in a abuse table).
	// For now at least log at warn level (in real app use structured logger).
	_ = ip
	_ = db.DB
	// Example: log.Printf("security: invalid hash access from ip=%s", ip)
}
