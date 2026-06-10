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
		render(w, t, "auth/login.html", map[string]interface{}{
			"Title": "Sign in — go-mega",
		})
	}
}

func HandleLogin(t *template.Template, sqlDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
			t.ExecuteTemplate(w, "auth/login.html", map[string]interface{}{
				"Title": "Sign in — go-mega",
				"Error": "Invalid email or password.",
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
		render(w, t, "auth/setup.html", map[string]interface{}{"Title": "Initial Setup — go-mega"})
	}
}

func HandleSetup(t *template.Template, sqlDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
			render(w, t, "auth/setup.html", map[string]interface{}{
				"Title": "Initial Setup — go-mega",
				"Error": err.Error(),
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
