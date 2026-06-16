#!/bin/bash
# Initialize mtls-lab database: apply migrations and seed data
set -e

DB_CONTAINER="mtls-db"
DB_USER="mtls"
DB_NAME="mtls"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "  Waiting for $DB_CONTAINER to be healthy..."
for i in $(seq 1 30); do
  if docker exec "$DB_CONTAINER" pg_isready -U "$DB_USER" >/dev/null 2>&1; then
    echo "  $DB_CONTAINER ready ✅"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "  ERROR: $DB_CONTAINER not ready after 30 attempts"
    exit 1
  fi
  sleep 2
done

echo "  Applying migrations..."
for f in "$SCRIPT_DIR/migrations/"*.sql; do
  if [ -f "$f" ]; then
    echo "    Running $(basename "$f")..."
    docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" "$DB_NAME" < "$f"
    echo "    $(basename "$f") applied ✅"
  fi
done

echo "  Applying seed data..."
for f in "$SCRIPT_DIR/seeds/"*.sql; do
  if [ -f "$f" ]; then
    echo "    Running $(basename "$f")..."
    docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" "$DB_NAME" < "$f"
    echo "    $(basename "$f") applied ✅"
  fi
done

echo "  DB initialization complete ✅"
