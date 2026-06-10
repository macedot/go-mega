# Build stage
FROM golang:1.26-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/server ./cmd/server

# Tailwind (optional prebuild css - we use CDN in templates for now, but include for future)
# RUN curl -sL -o /tmp/tailwind https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64 \
#   && chmod +x /tmp/tailwind && /tmp/tailwind -i assets/tailwind/input.css -o static/css/app.css --minify || true

# Runtime
FROM gcr.io/distroless/static-debian12

WORKDIR /app
COPY --from=builder /out/server /app/server
# static assets, templates, icons
COPY static /app/static
COPY templates /app/templates
# empty dirs for volume (create as root before switching user)
RUN mkdir -p /app/storage/uploads /app/tmp

ENV APP_ENV=production \
    PORT=8080 \
    STORAGE_PATH=/app/storage

EXPOSE 8080
VOLUME ["/app/storage"]

USER nonroot:nonroot
ENTRYPOINT ["/app/server"]
