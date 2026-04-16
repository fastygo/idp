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
RUN CGO_ENABLED=0 go build -o /idp ./cmd/server

# Stage 3: Runtime
FROM alpine:3.21
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /idp .
COPY config.yaml .
VOLUME /app/keys
EXPOSE 5800
CMD ["./idp"]
