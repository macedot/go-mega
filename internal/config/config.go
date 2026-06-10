package config

import (
	"os"
	"strconv"
	"time"
)

type SecurityConfig struct {
	RateLimitMultiplier     int
	BanDuration             time.Duration
	EnableBanning           bool
	MaxInvalidHashAttempts  int
	Max404Attempts          int
	DefaultDiskQuotaBytes   int64
	DiskQuotaGraceBytes     int64
	MaxUploadSizeBytes      int64
	UploadChunkSizeBytes    int64
}

type Config struct {
	Host            string
	Port            string
	Env             string // development, production
	AppSecret       string // for signing cookies, tokens etc. (like SECRET_KEY_BASE)
	StoragePath     string
	WebauthnOrigin  string
	WebauthnRPID    string
	Security        SecurityConfig
}

var Cfg *Config

func Load() *Config {
	env := getEnv("APP_ENV", "development")
	isProd := env == "production" || env == "prod"

	multiplier := 10
	banDur := time.Minute
	enableBan := false
	maxInv := 10
	max404 := 10
	if isProd {
		multiplier = 1
		banDur = time.Hour
		enableBan = true
		maxInv = 3
		max404 = 3
	}

	sec := SecurityConfig{
		RateLimitMultiplier:    getEnvInt("RATE_LIMIT_MULTIPLIER", multiplier),
		BanDuration:            banDur,
		EnableBanning:          getEnvBool("ENABLE_BANNING", enableBan),
		MaxInvalidHashAttempts: getEnvInt("MAX_INVALID_HASH_ATTEMPTS", maxInv),
		Max404Attempts:         getEnvInt("MAX_404_ATTEMPTS", max404),
		DefaultDiskQuotaBytes:  getEnvInt64("USER_DISK_QUOTA_BYTES", 5*1024*1024*1024), // 5GB
		DiskQuotaGraceBytes:    100 * 1024 * 1024,                                    // 100MB
		MaxUploadSizeBytes:     getEnvInt64("MAX_UPLOAD_SIZE_BYTES", 1*1024*1024*1024), // 1GB
		UploadChunkSizeBytes:   getEnvInt64("UPLOAD_CHUNK_SIZE_BYTES", 90*1024*1024),  // ~90MB for CF
	}

	cfg := &Config{
		Host:           getEnv("HOST", "localhost:8080"),
		Port:           getEnv("PORT", "8080"),
		Env:            env,
		AppSecret:      getEnv("APP_SECRET", "dev-secret-change-in-production-please-use-long-random"),
		StoragePath:    getEnv("STORAGE_PATH", "storage"),
		WebauthnOrigin: getEnv("WEBAUTHN_ORIGIN", ""),
		WebauthnRPID:   getEnv("WEBAUTHN_RP_ID", ""),
		Security:       sec,
	}
	Cfg = cfg
	return cfg
}

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getEnvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

func getEnvInt64(k string, def int64) int64 {
	if v := os.Getenv(k); v != "" {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			return i
		}
	}
	return def
}

func getEnvBool(k string, def bool) bool {
	if v := os.Getenv(k); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func (c *Config) IsProd() bool {
	return c.Env == "production" || c.Env == "prod"
}

func (c *Config) IsDev() bool {
	return !c.IsProd()
}
