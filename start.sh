#!/bin/bash
set -e

PGDATA=/tmp/pgdata
PGSOCKET=/tmp/pgsocket
PG_BIN=/usr/lib/postgresql/17/bin

# ── Kill any existing process on port 8080 ───────────────────────────────────
fuser -k 8080/tcp 2>/dev/null || true

# ── Start PostgreSQL if not already running ───────────────────────────────────
if ! $PG_BIN/pg_isready -p 5433 -h $PGSOCKET > /dev/null 2>&1; then
  echo "Starting PostgreSQL..."

  if [ ! -d "$PGDATA/global" ]; then
    echo "Initialising database cluster..."
    $PG_BIN/initdb -D $PGDATA > /dev/null
  fi

  mkdir -p $PGSOCKET
  $PG_BIN/pg_ctl -D $PGDATA -o "-p 5433 -k $PGSOCKET" -l $PGDATA/pg.log start
  sleep 1

  $PG_BIN/psql -U vscode -h $PGSOCKET -p 5433 -d postgres \
    -c "CREATE DATABASE ippf_audit;" > /dev/null 2>&1 || true
  echo "Database ready."
else
  echo "PostgreSQL already running."
fi

# ── Set environment variables explicitly ──────────────────────────────────────
export DATABASE_URL="postgresql://vscode@localhost/ippf_audit?host=/tmp/pgsocket&port=5433"
export SECRET_KEY="localdevsecret1234567890abcdef"
export ADMIN_PASSWORD="admin123"
export PORT=8080

# ── Start Flask app ───────────────────────────────────────────────────────────
echo "Starting app on http://172.17.0.2:8080 ..."
cd "$(dirname "$0")"
python app.py
