#!/usr/bin/env bash
# Copyright 2026 The sqlpipe Authors
# SPDX-License-Identifier: Apache-2.0
#
# Owner gate. PG* must already point at a live server (make gate wraps
# this in scripts/with-postgres.sh). /release B.7 runs `make gate`.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

gate_tree=$(git rev-parse 'HEAD^{tree}')
gate_dirty=$(git status --porcelain)

if [ "$(uname -s)" = Darwin ]; then
    /bin/bash -c 'test "${BASH_VERSINFO[0]}" = 3'
    for script in scripts/*.sh scripts/hooks/pre-push; do
        /bin/bash -n "$script"
    done
fi

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
    echo "→ Go Postgres binding (live)"
    SQLPIPE_TEST_POSTGRES=1 GOWORK=off go test -tags postgres -count=1 ./...
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

# The hook checks this record instead of keeping an idle git transport open
# while Docker and the language suites run. Bind it to the measured tree.
[ "$(git rev-parse 'HEAD^{tree}')" = "$gate_tree" ]
[ "$(git status --porcelain)" = "$gate_dirty" ]
attestation=$(git rev-parse --git-path gate-attestation)
record=$(mktemp "${attestation}.XXXXXX")
trap 'rm -f "$record"' EXIT
dirty_count=0
if [ -n "$gate_dirty" ]; then
    dirty_count=$(printf '%s\n' "$gate_dirty" | wc -l | tr -d ' ')
fi
printf '%s %s %s\n' "$gate_tree" "$dirty_count" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$record"
mv "$record" "$attestation"
