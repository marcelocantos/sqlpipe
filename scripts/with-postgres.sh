#!/usr/bin/env bash
# Copyright 2026 The sqlpipe Authors
# SPDX-License-Identifier: Apache-2.0
#
# Start an ephemeral postgres:16 container, export PG* to it, run the
# given command, then remove the container. Does not use or touch a
# host-installed Postgres, nor a leftover container on :5432.
#
# Usage: scripts/with-postgres.sh <command> [args...]
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <command> [args...]" >&2
    exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "with-postgres: docker is required for a hermetic Postgres" >&2
    exit 1
fi

NAME="sqlpipe-pg-$$"
IMAGE="${SQLPIPE_PG_IMAGE:-postgres:16}"

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Bind an ephemeral host port on loopback only — never 5432, so this
# cannot collide with Homebrew Postgres or a sibling sqldeep-pg.
# Role must not be named `sqlpipe`: Postgres search_path is
# `"$user", public`, and sqlpipe's catalog schema is also `sqlpipe`.
# A matching role name makes unqualified CREATE TABLE land in the
# catalog after Master/Replica init, and sqlift extracts `public` only.
docker run -d --name "$NAME" \
    -e POSTGRES_USER=postgres \
    -e POSTGRES_PASSWORD=sqlpipe \
    -e POSTGRES_DB=sqlpipe \
    -p 127.0.0.1::5432 \
    "$IMAGE" >/dev/null

ready=0
i=0
while [ "$i" -lt 60 ]; do
        if docker exec "$NAME" pg_isready -U postgres -d sqlpipe >/dev/null 2>&1; then
        ready=1
        break
    fi
    i=$((i + 1))
    sleep 1
done
if [ "$ready" -ne 1 ]; then
    echo "with-postgres: $IMAGE did not become ready" >&2
    docker logs "$NAME" >&2 || true
    exit 1
fi

HOST_PORT=$(docker port "$NAME" 5432/tcp | head -1)
HOST_PORT=${HOST_PORT##*:}

export PGHOST=127.0.0.1
export PGPORT="$HOST_PORT"
export PGUSER=postgres
export PGPASSWORD=sqlpipe
export PGDATABASE=sqlpipe

"$@"
