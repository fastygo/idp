# Stage 1: Frontend assets
FROM node:22-alpine AS frontend
WORKDIR /build
COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts 2>/dev/null || npm install --ignore-scripts
COPY pkg/authkit/static/ pkg/authkit/static/
RUN npm run build:css

# Stage 2: Go build
FROM golang:1.25-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /build/pkg/authkit/static/css/app.css pkg/authkit/static/css/app.css
RUN go generate ./...
# Strip symbols + DWARF table to keep the image small and to avoid
# leaking a panic stack trace with full local paths in production.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /idp ./cmd/server

# Stage 3: Runtime
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tini

# Run as a dedicated unprivileged user. Keeping the IdP off uid 0 limits
# the blast radius if any code path is ever tricked into reading or
# writing arbitrary files inside the container.
RUN addgroup -S idp && adduser -S -G idp -H -h /app idp \
    && mkdir -p /app/keys \
    && chown -R idp:idp /app

WORKDIR /app
COPY --from=builder --chown=idp:idp /idp .
COPY --chown=idp:idp config.yaml .

# /app/keys is mounted writable for the runtime so the IdP can persist
# the generated RSA key + cert. Permissions are tight (0700) and owned
# by the idp user.
VOLUME /app/keys

USER idp:idp
EXPOSE 5800
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["./idp"]
