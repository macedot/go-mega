# go-mega

Go port of [FrankMega](https://github.com/akitaonrails/FrankMega) — a self-hosted, security-hardened file sharing service for family & friends.

Upload a file, get a time-limited + download-count-limited share link (`/d/<hash>`). Two-step download (info page then consume). Files auto-expire and are cleaned up.

**Status**: Core MVP implemented and functional:
- First-run admin setup
- Email/password login + session cookies (signed, DB-backed)
- Upload (direct multipart, filename sanitization, quota check, MIME allowlist)
- Dashboard listing active/inactive shares with storage bar
- Share page with QR code + copyable link
- Public two-step downloads + atomic consume + preview for images/video/audio
- Background cleanup of expired files + old bans
- Local disk storage (no S3/ActiveStorage)

**Not yet ported** (future work):
- Invite-only registration
- TOTP 2FA
- WebAuthn/Passkeys
- Chunked uploads (for >~90MB behind Cloudflare)
- Admin panel (users, bans, MIME types, files)
- Rate limiting + auto IP banning on abuse (basic real-IP + CF headers present)
- Real-time download notifications (SSE possible)
- Full Tailwind build (currently uses CDN + inline styles for simplicity)

## Quick start (local)

```bash
go run ./cmd/server
# or
go build -o server ./cmd/server && ./server
```

Visit http://localhost:8080 — if no users exist you'll be taken to setup to create the admin.

Default storage in `./storage/`. DB is `storage/gomega.db`.

Env:

```bash
cp .env.example .env
# edit APP_SECRET etc.
```

## Docker

### Pre-built images (recommended)

Images are automatically built and published to GitHub Container Registry on every new release:

```bash
docker pull ghcr.io/macedot/go-mega:latest
docker pull ghcr.io/macedot/go-mega:v0.1.0
```

Example `docker-compose.yml` using the published image:

```yaml
services:
  web:
    image: ghcr.io/macedot/go-mega:latest
    restart: unless-stopped
    environment:
      - APP_ENV=production
      - APP_SECRET=your-long-random-secret-here
      - HOST=yourdomain.example.com
      - STORAGE_PATH=/data
    volumes:
      - go-mega-data:/data
    # ports:
    #   - "8080:8080"   # only if not using a reverse proxy / tunnel
volumes:
  go-mega-data:
```

### Build from source

```bash
docker compose up --build
```

Data is persisted in the `uploads` volume (or the volume you configure).

For production behind a Cloudflare Tunnel, see the original FrankMega documentation. Set `HOST`, `APP_SECRET`, etc. as needed.

### Triggering a new release image

1. Create a new tag + GitHub Release (e.g. `v0.2.0`).
2. The GitHub Action (`.github/workflows/docker-build.yml`) will automatically build multi-arch images (amd64 + arm64) and push them to `ghcr.io/macedot/go-mega`.

## Configuration

See `internal/config/config.go`. Key security knobs:

- `MAX_UPLOAD_SIZE_BYTES`
- `USER_DISK_QUOTA_BYTES`
- `UPLOAD_CHUNK_SIZE_BYTES` (placeholder for future chunked impl)

## Differences from Rails version & design choices

- Pure Go SQLite (`modernc.org/sqlite`) — no cgo, easy cross-build & Docker.
- No ActiveStorage: direct `storage/uploads/<key>` files + metadata row.
- Chi router + std `html/template` + funcs.
- htmx or vanilla + server-rendered pages (no Turbo).
- For realtime later: SSE instead of Action Cable.
- Filename sanitizer ported closely.
- Download hash uses 24 random bytes (urlsafe base64) like original.

## Development

```bash
go build ./cmd/server
go test ./...   # (add tests in follow-up)
```

Templates live in `templates/`. Edit + restart to see changes (no hot reload yet).

## License

MIT (same as original FrankMega).

This is a community/educational port. For the canonical Ruby on Rails implementation and its Docker + Kamal + Cloudflare Tunnel production story, see https://github.com/akitaonrails/FrankMega .
