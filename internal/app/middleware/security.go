package middleware

import "net/http"

// SecurityHeaders sets common security headers (CSP, HSTS, etc.).
// Tailwind CDN in templates requires 'unsafe-inline' for styles (acceptable for this MVP;
// for production consider self-hosting Tailwind CSS and tightening CSP).
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Basic CSP - adjust as needed. 'unsafe-inline' for style because of CDN Tailwind + inline styles.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; img-src 'self' data:; connect-src 'self';")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// HSTS only in prod (assumes HTTPS termination at proxy like Cloudflare)
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		// X-XSS-Protection is deprecated but harmless for old browsers
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}
