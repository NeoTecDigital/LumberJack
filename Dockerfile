# ============================================================================
# Multi-stage Dockerfile for LumberJack
# ============================================================================
# Stage 1: Build the Go application
# Stage 2: Runtime with minimal Alpine image
# ============================================================================

# Stage 1: Build
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o lumberjack .

# Stage 2: Runtime
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates curl tzdata && \
    addgroup -g 1000 lumberjack && \
    adduser -D -u 1000 -G lumberjack lumberjack

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/lumberjack /usr/local/bin/lumberjack

# Create data directory
RUN mkdir -p /var/lib/lumberjack && \
    chown -R lumberjack:lumberjack /var/lib/lumberjack /app

# Switch to non-root user
USER lumberjack

# Expose port
EXPOSE 9483

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=40s \
    CMD curl -f http://localhost:9483/health || exit 1

# Start LumberJack server
CMD ["lumberjack", "start", "png-production", "-d"]
