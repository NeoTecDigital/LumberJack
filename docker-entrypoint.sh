#!/bin/sh
set -e

DB_NAME="${LUMBERJACK_DB_NAME:-png-production}"
SERVER_PORT="${SERVER_PORT:-9483}"
SERVER_HOST="${SERVER_HOST:-0.0.0.0}"
ADMIN_USER="${LUMBERJACK_ADMIN_USER:-admin}"
ADMIN_PASS="${LUMBERJACK_ADMIN_PASS:-admin}"

CONFIG_DIR="/etc/lumberjack"
CONFIG_FILE="$CONFIG_DIR/config.yaml"
DB_DIR="/var/lib/lumberjack"

# Create directories
mkdir -p "$CONFIG_DIR" "$CONFIG_DIR/live" "$DB_DIR/$DB_NAME" /app/logs

# Create config.yaml if it doesn't exist
if [ ! -f "$CONFIG_FILE" ]; then
    cat > "$CONFIG_FILE" << EOF
version: 0.1.1-alpha
databases:
    ${DB_NAME}:
        id: ""
        name: ${DB_NAME}
        pid: 0
        serverurl: ${SERVER_HOST}
        serverport: "${SERVER_PORT}"
        dashboardurl: ${SERVER_HOST}
        dashboardport: "0"
        dashboardup: false
        logpath: /app/logs
        databasepath: ${DB_DIR}/${DB_NAME}
        organization: PNG Construction
        phone: ""
        admin:
            username: ${ADMIN_USER}
            password: ${ADMIN_PASS}
            organization: PNG Construction
            phone: ""
            email: admin@pandgconstruction.com
EOF
    echo "Created LumberJack config: $CONFIG_FILE"
fi

# Run server directly in foreground (LUMBERJACK_SPAWNED=1 prevents fork)
export LUMBERJACK_SPAWNED=1
exec lumberjack start "$DB_NAME"
