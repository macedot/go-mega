package handlers

import (
	"database/sql"
	"html/template"
	"net/http"
	"strconv"

	"github.com/macedot/go-mega/internal/app/auth"
	"github.com/macedot/go-mega/internal/app/models"
	"github.com/macedot/go-mega/internal/config"
	"github.com/macedot/go-mega/internal/db"

	"github.com/go-chi/chi/v5"
)

func HandleRoot(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(r)
	if user == nil {
		cnt, _ := models.CountUsers(db.DB)
		if cnt == 0 {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/session/new", http.StatusSeeOther)
		return
	}
	// redirect logged in to upload dashboard
	http.Redirect(w, r, "/uploads/new", http.StatusSeeOther)
}

func HandleLoginPage(t *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if auth.Authenticated(r) {
			http.Redirect(w, r, "/uploads/new", http.StatusSeeOther)
			return
		}
		cnt, _ := models.CountUsers(db.DB)
		if cnt == 0 {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		csrf := auth.EnsureCSRF(w, r)
		render(w, t, "auth/login.html", map[string]interface{}{
			"Title": "Sign in — go-mega",
			"CSRF":  csrf,
		})
	}
}

func HandleLogin(t *template.Template, sqlDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !auth.VerifyCSRF(r) {
			http.Error(w, "invalid csrf token", http.StatusForbidden)
			return
		}
		email := r.FormValue("email_address")
		pass := r.FormValue("password")
		if email == "" || pass == "" {
			http.Error(w, "email and password required", http.StatusBadRequest)
			return
		}
		user, err := models.Authenticate(sqlDB, email, pass)
		if err != nil {
			// simple error for now
			w.WriteHeader(http.StatusUnauthorized)
			csrf := auth.EnsureCSRF(w, r)
			t.ExecuteTemplate(w, "auth/login.html", map[string]interface{}{
				"Title": "Sign in — go-mega",
				"Error": "Invalid email or password.",
				"CSRF":  csrf,
			})
			return
		}
		_, err = auth.StartSession(w, r, sqlDB, user)
		if err != nil {
			http.Error(w, "could not start session", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/uploads/new", http.StatusSeeOther)
	}
}

func HandleLogout(sqlDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !auth.VerifyCSRF(r) {
			http.Error(w, "invalid csrf token", http.StatusForbidden)
			return
		}
		if s := auth.CurrentSession(r); s != nil {
			auth.TerminateSession(w, r, sqlDB, s.ID)
		} else {
			// clear anyway
			auth.TerminateSession(w, r, sqlDB, 0)
		}
		http.Redirect(w, r, "/session/new", http.StatusSeeOther)
	}
}

func HandleSetupPage(t *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cnt, _ := models.CountUsers(db.DB)
		if cnt > 0 {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		csrf := auth.EnsureCSRF(w, r)
		render(w, t, "auth/setup.html", map[string]interface{}{"Title": "Initial Setup — go-mega", "CSRF": csrf})
	}
}

func HandleSetup(t *template.Template, sqlDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !auth.VerifyCSRF(r) {
			http.Error(w, "invalid csrf token", http.StatusForbidden)
			return
		}
		cnt, _ := models.CountUsers(sqlDB)
		if cnt > 0 {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		email := r.FormValue("email_address")
		pass := r.FormValue("password")
		// no confirm for simplicity; add in template
		user, err := models.CreateUser(sqlDB, email, pass, "admin", true)
		if err != nil {
			csrf := auth.EnsureCSRF(w, r)
			render(w, t, "auth/setup.html", map[string]interface{}{
				"Title": "Initial Setup — go-mega",
				"Error": err.Error(),
				"CSRF":  csrf,
			})
			return
		}
		auth.StartSession(w, r, sqlDB, user)
		http.Redirect(w, r, "/uploads/new", http.StatusSeeOther)
	}
}

func render(w http.ResponseWriter, t *template.Template, name string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// Stub for profile
func HandleProfile(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(r)
	w.Write([]byte("Profile for " + user.EmailAddress + " (not fully implemented yet)"))
}

// Helper for download hash from chi
func downloadHash(r *http.Request) string {
	return chi.URLParam(r, "hash")
}

// Basic number parse helper
func parseInt(s string, def int) int {
	if s == "" {
		return def
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return i
}

// Use config
var _ = config.Cfg
