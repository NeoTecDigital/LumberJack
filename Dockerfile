# Written by Richard Christopher, Copyright 2026 NeoTec, LLC
# Non-commercial use only; see LICENSE.
#
# The HTTP server as a container: `lumberjack serve` in the foreground. The server needs no cgo
# (the C ABI is ./ffi, built separately), so the binary is static.
#
#   docker build -t lumberjack .
#   docker run -p 9483:9483 --env-file .env -v lumberjack-data:/var/lib/lumberjack lumberjack
#
# .env.example names the variables. LUMBERJACK_JWT_SECRET is always required, and
# LUMBERJACK_ADMIN_PASS the first time a database is created; neither is ever defaulted.
# The API speaks plain HTTP: put a TLS terminator in front of the published port.

FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/lumberjack .

FROM alpine:3.22
RUN apk --no-cache add ca-certificates curl tzdata \
    && adduser -D -H -u 10001 lumberjack \
    && mkdir -p /var/lib/lumberjack /var/log/lumberjack \
    && chown lumberjack /var/lib/lumberjack /var/log/lumberjack
COPY --from=builder /out/lumberjack /usr/local/bin/lumberjack
USER lumberjack

# Inside a container loopback is unreachable from the published port, so bind every interface.
ENV LUMBERJACK_HOST=0.0.0.0
EXPOSE 9483
VOLUME ["/var/lib/lumberjack"]

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=20s \
    CMD curl -fsS http://127.0.0.1:9483/health || exit 1

ENTRYPOINT ["lumberjack", "serve", "--port", "9483", "--data-dir", "/var/lib/lumberjack", "--log-dir", "/var/log/lumberjack"]
CMD ["--db", "default"]
