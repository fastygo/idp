FROM golang:1.25-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /idp .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /idp .
COPY templates/ templates/
COPY config.yaml .
VOLUME /app/keys
EXPOSE 5800
CMD ["./idp"]
