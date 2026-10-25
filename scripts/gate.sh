#!/usr/bin/env bash
# Copyright 2026 The sqlpipe Authors
# SPDX-License-Identifier: Apache-2.0
#
# Owner gate. PG* must already point at a live server (make gate wraps
# this in scripts/with-postgres.sh). /release B.7 runs `make gate`.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

echo "→ cv test (SQLite + live Postgres, includes fault-suite:*)"
cv test
echo "✓ cv test"

echo "→ fault suite"
./build/sqlpipe_tests --list-test-cases --test-case='*fault-suite*'
./build/sqlpipe_tests --test-case='*fault-suite*'
echo "✓ fault suite"

echo "→ go test"
(
    cd go/sqlpipe
    GOWORK=off go test -count=1 ./...
)
echo "✓ go test"

if command -v swift >/dev/null 2>&1; then
    echo "→ swift build"
    (cd swift && swift build)
    echo "✓ swift build"
else
    echo "· swift build skipped (no swift)"
fi

if command -v emcc >/dev/null 2>&1 && command -v node >/dev/null 2>&1; then
    echo "→ cv wasm + TypeScript smoke"
    cv wasm
    (
        cd web
        if [ ! -d node_modules ]; then npm install; fi
        npx tsc
        node dist/test/smoke.test.js
    )
    echo "✓ wasm"
else
    echo "· wasm skipped (need emcc + node)"
fi
