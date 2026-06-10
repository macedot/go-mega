package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/macedot/go-mega/internal/app/auth"
	"github.com/macedot/go-mega/internal/config"
)

// Very basic in-memory rate limiter + ban hook (MVP).
// For production add a proper implementation or use the Ban model + counters.

var (
	mu        sync.Mutex
	counters  = map[string]int{}
	lastReset = time.Now()
)

func RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !config.Cfg.Security.EnableBanning {
			next.ServeHTTP(w, r)
			return
		}
		ip := auth.RealIP(r)
		// simplistic global throttle example (tune or replace)
		mu.Lock()
		if time.Since(lastReset) > time.Minute {
			counters = map[string]int{}
			lastReset = time.Now()
		}
		counters[ip]++
		count := counters[ip]
		mu.Unlock()

		limit := 300 * config.Cfg.Security.RateLimitMultiplier
		if count > limit {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("rate limit exceeded"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
