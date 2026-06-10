package auth

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/macedot/go-mega/internal/app/models"
	"github.com/macedot/go-mega/internal/config"
	"github.com/macedot/go-mega/internal/db"

	"github.com/gorilla/securecookie"
)

type contextKey string

const (
	sessionKey   contextKey = "session"
	currentUserKey contextKey = "current_user"
)

var (
	ErrNoSession   = errors.New("no session")
	ErrBanned      = errors.New("user banned")
	sc             *securecookie.SecureCookie
)

func init() {
	// Will be properly initialized in Load or middleware with secret
}

func InitSecureCookie(secret string) {
	// Use 32+ byte hash key and 16+ byte block for AES
	hashKey := []byte(secret)
	if len(hashKey) < 32 {
		// pad for dev
		pad := make([]byte, 32-len(hashKey))
		hashKey = append(hashKey, pad...)
	}
	blockKey := hashKey[:16] // first 16 for block
	sc = securecookie.New(hashKey, blockKey)
	sc.SetSerializer(securecookie.JSONEncoder{})
	sc.MaxAge(0) // session cookie? but we do permanent like Rails
}

// SessionRecord is the DB row
type SessionRecord struct {
	ID        int64
	UserID    int64
	IPAddress string
	UserAgent string
	CreatedAt time.Time
}

// GetSessionFromCookie reads signed cookie, loads from DB, checks ban.
func GetSessionFromCookie(r *http.Request, sqlDB *sql.DB) (*SessionRecord, *models.User, error) {
	cookie, err := r.Cookie("session_id")
	if err != nil || cookie.Value == "" {
		return nil, nil, ErrNoSession
	}

	var sid int64
	if err := sc.Decode("session_id", cookie.Value, &sid); err != nil {
		return nil, nil, ErrNoSession
	}

	var rec SessionRecord
	var created time.Time
	err = sqlDB.QueryRow(`SELECT id, user_id, ip_address, user_agent, created_at FROM sessions WHERE id = ?`, sid).
		Scan(&rec.ID, &rec.UserID, &rec.IPAddress, &rec.UserAgent, &created)
	if err != nil {
		return nil, nil, ErrNoSession
	}
	rec.CreatedAt = created

	user, err := models.FindUserByID(sqlDB, rec.UserID)
	if err != nil {
		return nil, nil, err
	}
	if user.IsBanned() {
		return nil, nil, ErrBanned
	}
	return &rec, user, nil
}

// StartSession creates DB session row and sets signed permanent cookie.
func StartSession(w http.ResponseWriter, r *http.Request, db *sql.DB, user *models.User) (*SessionRecord, error) {
	ip := RealIP(r)
	ua := r.UserAgent()

	res, err := db.Exec(`INSERT INTO sessions (user_id, ip_address, user_agent) VALUES (?, ?, ?)`,
		user.ID, ip, ua)
	if err != nil {
		return nil, err
	}
	sid, _ := res.LastInsertId()

	encoded, err := sc.Encode("session_id", sid)
	if err != nil {
		return nil, err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   config.Cfg.IsProd(),
		MaxAge:   60 * 60 * 24 * 365, // ~1 year, "permanent" like Rails
	})

	return &SessionRecord{ID: sid, UserID: user.ID, IPAddress: ip, UserAgent: ua}, nil
}

// TerminateSession deletes DB row and clears cookie.
func TerminateSession(w http.ResponseWriter, r *http.Request, db *sql.DB, sid int64) {
	if sid != 0 {
		_, _ = db.Exec(`DELETE FROM sessions WHERE id = ?`, sid)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// Middleware that populates context with session/user or redirects to login/setup.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, user, err := GetSessionFromCookie(r, db.DB) // package level set after Open
		if err != nil {
			if errors.Is(err, ErrBanned) || errors.Is(err, ErrNoSession) {
				if cnt, _ := models.CountUsers(db.DB); cnt == 0 {
					http.Redirect(w, r, "/setup", http.StatusSeeOther)
					return
				}
				http.Redirect(w, r, "/session/new", http.StatusSeeOther)
				return
			}
			http.Error(w, "auth error", http.StatusInternalServerError)
			return
		}

		ctx := context.WithValue(r.Context(), sessionKey, sess)
		ctx = context.WithValue(ctx, currentUserKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Allow unauth but still try to load user if present (for public pages that show navbar)
func LoadUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, user, err := GetSessionFromCookie(r, db.DB)
		if err == nil && user != nil && !user.IsBanned() {
			ctx := context.WithValue(r.Context(), sessionKey, sess)
			ctx = context.WithValue(ctx, currentUserKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func CurrentUser(r *http.Request) *models.User {
	if u, ok := r.Context().Value(currentUserKey).(*models.User); ok {
		return u
	}
	return nil
}

func CurrentSession(r *http.Request) *SessionRecord {
	if s, ok := r.Context().Value(sessionKey).(*SessionRecord); ok {
		return s
	}
	return nil
}

func Authenticated(r *http.Request) bool {
	return CurrentUser(r) != nil
}

// RealIP extracts client IP, preferring CF headers then X-Forwarded etc.
func RealIP(r *http.Request) string {
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		// take first
		for i := 0; i < len(ip); i++ {
			if ip[i] == ',' {
				return ip[:i]
			}
		}
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	host, _ := splitHostPort(r.RemoteAddr)
	return host
}

func splitHostPort(hostport string) (host, port string) {
	for i := len(hostport) - 1; i >= 0; i-- {
		if hostport[i] == ':' {
			return hostport[:i], hostport[i+1:]
		}
	}
	return hostport, ""
}
