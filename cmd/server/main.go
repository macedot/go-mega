package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/macedot/go-mega/internal/app/auth"
	"github.com/macedot/go-mega/internal/app/handlers"
	"github.com/macedot/go-mega/internal/app/models"
	"github.com/macedot/go-mega/internal/config"
	"github.com/macedot/go-mega/internal/db"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	appmiddleware "github.com/macedot/go-mega/internal/app/middleware"
)

func main() {
	cfg := config.Load()
	log.Printf("starting go-mega in %s mode on :%s", cfg.Env, cfg.Port)

	// DB
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = fmt.Sprintf("%s/gomega.db?_journal_mode=WAL&_foreign_keys=on", cfg.StoragePath)
	}
	sqlDB, err := db.Open(dsn)
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	defer sqlDB.Close()

	// Seed MIME types
	if err := models.SeedDefaultMimeTypes(sqlDB); err != nil {
		log.Printf("seed mimes: %v", err)
	}

	// Secure cookies
	auth.InitSecureCookie(cfg.AppSecret)

	// Templates from disk (run binary from repo root for templates/ to be found; restart for changes)
	tmpl := loadTemplates()

	// Router
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	// Use a long timeout for the whole app because large file uploads (multi-GB
	// backups etc.) can easily take many minutes. The old 60s value would kill
	// slow or large uploads mid-flight, making progress appear to "get stuck".
	r.Use(middleware.Timeout(30 * time.Minute))

	// Security: wire the existing rate limiter (was defined but unused).
	// It is a basic in-memory implementation; for production consider
	// integrating the full Ban model + per-endpoint limits (login, upload, setup, invalid hashes).
	r.Use(appmiddleware.RateLimit)

	// Security headers (CSP, HSTS, etc.). Applied early.
	r.Use(appmiddleware.SecurityHeaders)

	// Static (disk served)
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	r.Handle("/icons/*", http.StripPrefix("/icons/", http.FileServer(http.Dir("static/icons"))))

	// Public routes
	r.Group(func(r chi.Router) {
		r.Use(auth.LoadUser)
		r.Get("/", handlers.HandleRoot)
		r.Get("/session/new", handlers.HandleLoginPage(tmpl))
		r.Post("/session", handlers.HandleLogin(tmpl, sqlDB))
		r.Post("/session/delete", handlers.HandleLogout(sqlDB))

		r.Get("/setup", handlers.HandleSetupPage(tmpl))
		r.Post("/setup", handlers.HandleSetup(tmpl, sqlDB))

		// Public download (two step)
		r.Get("/d/{hash}", handlers.HandleDownloadShow(tmpl, sqlDB))
		// Support both POST (from landing page form, with CSRF) and GET (for direct download links)
		// The consume logic (check active, increment count, serve file) is the same.
		r.Get("/d/{hash}/file", handlers.HandleDownloadConsume(tmpl, sqlDB))
		r.Post("/d/{hash}/file", handlers.HandleDownloadConsume(tmpl, sqlDB))
		r.Get("/d/{hash}/preview", handlers.HandleDownloadPreview(sqlDB))
	})

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(auth.RequireAuth)
		r.Get("/uploads/new", handlers.HandleUploadNew(tmpl, sqlDB))
		r.Post("/uploads", handlers.HandleUploadCreate(tmpl, sqlDB))
		// Chunked upload support for Cloudflare compatibility (large files are split in the browser
		// into small chunks < ~90MB so they pass CF's body size limit, then merged server-side).
		r.Post("/uploads/start", handlers.HandleUploadStart(tmpl, sqlDB))
		r.Post("/uploads/chunk", handlers.HandleUploadChunk(tmpl, sqlDB))
		r.Post("/uploads/complete", handlers.HandleUploadComplete(tmpl, sqlDB))
		r.Get("/uploads/{id}", handlers.HandleUploadShow(tmpl, sqlDB))
		r.Post("/uploads/{id}/delete", handlers.HandleUploadDelete(sqlDB))

		r.Post("/logout", handlers.HandleLogout(sqlDB))
		r.Get("/profile", handlers.HandleProfile)
	})

	r.Get("/up", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	})

	// Background cleanup every 15 min
	stopCleanup := make(chan struct{})
	go runCleanup(sqlDB, cfg.StoragePath, stopCleanup)

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		// Long timeouts are required for large file uploads. A slow link uploading
		// several GB can easily exceed the previous 5m limits and cause the upload
		// to appear stuck or be aborted by the server.
		ReadTimeout:  30 * time.Minute,
		WriteTimeout: 30 * time.Minute,
	}

	go func() {
		log.Printf("listening on http://%s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down...")
	close(stopCleanup)
	srv.Close()
	time.Sleep(200 * time.Millisecond)
}

func loadTemplates() *template.Template {
	t := template.New("").Funcs(templateFuncs())
	base := "templates"
	_ = filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".html" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			log.Printf("template read: %s: %v", path, err)
			return nil
		}
		name := path[len(base)+1:]
		// Use the full relative name so ExecuteTemplate can find "uploads/new.html" etc.
		_, err = t.New(name).Parse(string(b))
		if err != nil {
			log.Printf("template parse %s: %v", name, err)
		}
		return nil
	})
	return t
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"humanSize": func(n int64) string {
			const unit = 1024
			if n < unit {
				return fmt.Sprintf("%d B", n)
			}
			div, exp := int64(unit), 0
			for n/div >= unit && exp < 5 {
				div *= unit
				exp++
			}
			return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
		},
		"mul": func(a, b float64) float64 { return a * b },
		"div": func(a, b float64) float64 {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"int": func(f float64) int { return int(f) },
		"float64": func(i int64) float64 { return float64(i) },
		"base64": func(b []byte) string {
			// simple base64 for QR png bytes if passed as []byte
			// but our templates use data: URIs built in handler mostly
			return ""
		},
	}
}

func runCleanup(sqlDB *sql.DB, storage string, stop <-chan struct{}) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			cleanupExpired(sqlDB, storage)
		}
	}
}

func cleanupExpired(sqlDB *sql.DB, storage string) {
	now := time.Now().UTC()
	rows, err := sqlDB.Query(`SELECT id, storage_key FROM shared_files WHERE (ttl_hours != 0 AND expires_at <= ?) OR (max_downloads != 0 AND download_count >= max_downloads)`, now)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var key string
		if err := rows.Scan(&id, &key); err != nil {
			continue
		}
		if key != "" {
			_ = os.Remove(filepath.Join(storage, key))
		}
		_, _ = sqlDB.Exec(`DELETE FROM shared_files WHERE id = ?`, id)
	}
	_, _ = sqlDB.Exec(`DELETE FROM bans WHERE expires_at <= ?`, now)
}
