# Stage 1: Frontend assets
FROM node:22-alpine AS frontend
WORKDIR /build
COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts 2>/dev/null || npm install --ignore-scripts
COPY internal/web/static/ internal/web/static/
RUN npm run build:sdk && npm run build:css

# Stage 2: Go build
FROM golang:1.25-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /build/internal/web/static/css/app.css internal/web/static/css/app.css
COPY --from=frontend /build/internal/web/static/js/hanko-frontend-sdk.js internal/web/static/js/hanko-frontend-sdk.js
RUN go generate ./...
RUN CGO_ENABLED=0 go build -o /idp ./cmd/server

# Stage 3: Runtime
FROM alpine:3.21
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /idp .
COPY --from=builder /build/internal/web/static/ static/
COPY --from=builder /build/templates/ templates/
COPY config.yaml .
VOLUME /app/keys
EXPOSE 5800
CMD ["./idp"]
