# Stage 1: Build
FROM golang:1.23-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git gcc musl-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o lumberjack .

# Stage 2: Runtime
FROM alpine:latest

RUN apk --no-cache add ca-certificates curl tzdata

WORKDIR /app

COPY --from=builder /app/lumberjack /usr/local/bin/lumberjack
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Create directories
RUN mkdir -p /etc/lumberjack/live /var/lib/lumberjack /app/logs

EXPOSE 9483

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=40s \
    CMD curl -f http://localhost:9483/health || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
