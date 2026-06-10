package models

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/macedot/go-mega/internal/config"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID                int64
	EmailAddress      string
	PasswordDigest    string
	Role              string // "admin" or "user"
	Banned            bool
	BannedAt          *time.Time
	DiskQuotaBytes    *int64
	OTPSecret         sql.NullString
	OTPRequired       bool
	LastOTPAt         *time.Time
	TermsAcceptedAt   *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

func (u *User) IsAdmin() bool {
	return u.Role == "admin"
}

func (u *User) IsBanned() bool {
	return u.Banned
}

func (u *User) SoleAdmin(db *sql.DB) bool {
	if !u.IsAdmin() {
		return false
	}
	var count int
	_ = db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin' AND banned = 0`).Scan(&count)
	return count <= 1
}

func (u *User) StorageUsed(db *sql.DB) (int64, error) {
	var sum sql.NullInt64
	err := db.QueryRow(`SELECT SUM(file_size) FROM shared_files WHERE user_id = ?`, u.ID).Scan(&sum)
	if err != nil {
		return 0, err
	}
	if sum.Valid {
		return sum.Int64, nil
	}
	return 0, nil
}

func (u *User) DiskQuota() int64 {
	if u.DiskQuotaBytes != nil && *u.DiskQuotaBytes > 0 {
		return *u.DiskQuotaBytes
	}
	if config.Cfg != nil {
		return config.Cfg.Security.DefaultDiskQuotaBytes
	}
	// Fallback (should only happen in tests before config.Load)
	return 5 * 1024 * 1024 * 1024 // 5GB
}

func (u *User) StorageRemaining(db *sql.DB) (int64, error) {
	used, err := u.StorageUsed(db)
	if err != nil {
		return 0, err
	}
	quota := u.DiskQuota()
	rem := quota - used
	if rem < 0 {
		return 0, nil
	}
	return rem, nil
}

func (u *User) CanUpload(db *sql.DB, fileSize int64) (bool, error) {
	used, err := u.StorageUsed(db)
	if err != nil {
		return false, err
	}
	quota := u.DiskQuota()
	grace := int64(100 * 1024 * 1024)
	if config.Cfg != nil {
		grace = config.Cfg.Security.DiskQuotaGraceBytes
	}
	return (used + fileSize) <= (quota + grace), nil
}

// Authenticate finds user by email (normalized) and checks password.
func Authenticate(db *sql.DB, email, password string) (*User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var u User
	var banned bool
	err := db.QueryRow(`
		SELECT id, email_address, password_digest, role, banned, banned_at,
		       disk_quota_bytes, otp_secret, otp_required, last_otp_at, terms_accepted_at,
		       created_at, updated_at
		FROM users WHERE email_address = ?`, email).
		Scan(&u.ID, &u.EmailAddress, &u.PasswordDigest, &u.Role, &banned, &u.BannedAt,
			&u.DiskQuotaBytes, &u.OTPSecret, &u.OTPRequired, &u.LastOTPAt, &u.TermsAcceptedAt,
			&u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("invalid email or password")
		}
		return nil, err
	}
	u.Banned = banned

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordDigest), []byte(password)); err != nil {
		return nil, errors.New("invalid email or password")
	}
	if u.Banned {
		return nil, errors.New("account is banned")
	}
	return &u, nil
}

// CreateUser inserts a new user (for setup and registration later).
func CreateUser(db *sql.DB, email, password string, role string, skipTerms bool) (*User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if len(password) < 12 {
		return nil, errors.New("password must be at least 12 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	terms := sql.NullTime{}
	if !skipTerms {
		terms = sql.NullTime{Time: now, Valid: true}
	}

	res, err := db.Exec(`
		INSERT INTO users (email_address, password_digest, role, terms_accepted_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		email, string(hash), role, terms, now, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return FindUserByID(db, id)
}

func FindUserByID(db *sql.DB, id int64) (*User, error) {
	var u User
	var banned bool
	err := db.QueryRow(`
		SELECT id, email_address, password_digest, role, banned, banned_at,
		       disk_quota_bytes, otp_secret, otp_required, last_otp_at, terms_accepted_at,
		       created_at, updated_at
		FROM users WHERE id = ?`, id).
		Scan(&u.ID, &u.EmailAddress, &u.PasswordDigest, &u.Role, &banned, &u.BannedAt,
			&u.DiskQuotaBytes, &u.OTPSecret, &u.OTPRequired, &u.LastOTPAt, &u.TermsAcceptedAt,
			&u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	u.Banned = banned
	return &u, nil
}

func FindUserByEmail(db *sql.DB, email string) (*User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var u User
	var banned bool
	err := db.QueryRow(`
		SELECT id, email_address, password_digest, role, banned, banned_at,
		       disk_quota_bytes, otp_secret, otp_required, last_otp_at, terms_accepted_at,
		       created_at, updated_at
		FROM users WHERE email_address = ?`, email).
		Scan(&u.ID, &u.EmailAddress, &u.PasswordDigest, &u.Role, &banned, &u.BannedAt,
			&u.DiskQuotaBytes, &u.OTPSecret, &u.OTPRequired, &u.LastOTPAt, &u.TermsAcceptedAt,
			&u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	u.Banned = banned
	return &u, nil
}

func (u *User) Ban(db *sql.DB) error {
	now := time.Now().UTC()
	_, err := db.Exec(`UPDATE users SET banned = 1, banned_at = ?, updated_at = ? WHERE id = ?`, now, now, u.ID)
	if err != nil {
		return err
	}
	u.Banned = true
	u.BannedAt = &now
	// destroy sessions
	_, _ = db.Exec(`DELETE FROM sessions WHERE user_id = ?`, u.ID)
	return nil
}

func (u *User) Unban(db *sql.DB) error {
	now := time.Now().UTC()
	_, err := db.Exec(`UPDATE users SET banned = 0, banned_at = NULL, updated_at = ? WHERE id = ?`, now, u.ID)
	if err != nil {
		return err
	}
	u.Banned = false
	u.BannedAt = nil
	return nil
}

// CountUsers returns total user count (used for setup gate)
func CountUsers(db *sql.DB) (int, error) {
	var c int
	err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&c)
	return c, err
}
