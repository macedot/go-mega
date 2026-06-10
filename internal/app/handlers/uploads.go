package handlers

import (
	"database/sql"
	"encoding/base64"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
			"Authenticated": true,
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

		// multipart
		r.ParseMultipartForm(32 << 20) // 32MB buffer
		f, fh, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "file required", http.StatusBadRequest)
			return
		}
		defer f.Close()

		maxDL := parseInt(r.FormValue("max_downloads"), 5)
		if maxDL < 1 {
			maxDL = 1
		}
		if maxDL > 100 {
			maxDL = 100
		}
		ttl := parseInt(r.FormValue("ttl_hours"), 24)
		if ttl < 1 {
			ttl = 1
		}
		if ttl > 24 {
			ttl = 24
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
			data := map[string]interface{}{
				"Title":         "Upload — go-mega",
				"ActiveFiles":   active,
				"InactiveFiles": inactive,
				"StorageUsed":   used,
				"DiskQuota":     user.DiskQuota(),
				"Error":         err.Error(),
				"Authenticated": true,
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
		qrPNG, _ := qrcode.Encode(url, qrcode.Medium, 256)
		qrB64 := base64.StdEncoding.EncodeToString(qrPNG)

		data := map[string]interface{}{
			"Title":         "Share Link — go-mega",
			"File":          found,
			"DownloadURL":   url,
			"QR":            qrB64,
			"Authenticated": true,
		}
		render(w, t, "uploads/show.html", data)
	}
}

func HandleUploadDelete(sqlDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.CurrentUser(r)
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

// For show we used hash; add FindByID in models if needed. Quick patch:
func init() {
	// nothing
	_ = db.DB
	_ = time.Now
	_ = os.PathSeparator
	_ = filepath.Join
	_ = io.Copy
}
