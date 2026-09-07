#!/bin/bash
# Assert that every vendored wrapper copy of a source-of-truth file is
# byte-identical to that source.
#
# sqlpipe ships one library as several trees: the canonical two-file core in
# dist/, a C-API shim under go/sqlpipe/, and copies of both inside the Go and
# Swift wrapper packages (which must be self-contained so `go get` and SPM work
# without fetching this repo). scripts/bundle-deps.sh writes those copies; this
# script proves they have not drifted since. Run it in CI so a stale copy — a
# header missing a struct field, say — cannot ship silently.
#
# Usage: scripts/check-vendor-lockstep.sh
# Exit:  0 all copies in lockstep; 1 at least one has drifted.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

status=0

# Each entry is "source:copy". The copy must be byte-identical to the source.
# Kept in the same order as the copy steps in scripts/bundle-deps.sh.
COPIES=(
    "dist/sqlpipe.h:go/sqlpipe/internal/c/sqlpipe.h"
    "dist/sqlpipe.cpp:go/sqlpipe/internal/c/sqlpipe.cpp"
    "dist/sqlpipe.h:swift/Sources/CSqlpipe/sqlpipe.h"
    "dist/sqlpipe.cpp:swift/Sources/CSqlpipe/sqlpipe.cpp"
    "dist/sqlpipe.h:swift/Sources/CSqlpipe/include/sqlpipe.h"
    "go/sqlpipe/sqlpipe_capi.h:go/sqlpipe/internal/c/sqlpipe_capi.h"
    "go/sqlpipe/sqlpipe_capi.cpp:go/sqlpipe/internal/c/sqlpipe_capi.cpp"
    "go/sqlpipe/sqlpipe_capi.h:swift/Sources/CSqlpipe/include/sqlpipe_capi.h"
)

for entry in "${COPIES[@]}"; do
    src="${entry%%:*}"
    copy="${entry##*:}"
    if [[ ! -f "$copy" ]]; then
        echo "MISSING $copy (should be a copy of $src)" >&2
        status=1
    elif ! diff -q "$src" "$copy" >/dev/null; then
        echo "DRIFTED $copy differs from $src" >&2
        diff -u "$src" "$copy" | head -40 >&2
        status=1
    fi
done

# The Swift copy of the C-API implementation differs from the Go original in
# exactly two #include lines: the Swift package resolves its headers under
# include/, the Go module under internal/c/. Compare modulo that rewrite so the
# rest of the translation unit is still held in lockstep.
swift_capi_expected="$(mktemp)"
trap 'rm -f "$swift_capi_expected"' EXIT
sed -e 's|^#include "sqlpipe_capi\.h"$|#include "include/sqlpipe_capi.h"|' \
    -e 's|^#include "internal/c/sqlpipe\.h"$|#include "include/sqlpipe.h"|' \
    go/sqlpipe/sqlpipe_capi.cpp > "$swift_capi_expected"
if ! diff -q "$swift_capi_expected" swift/Sources/CSqlpipe/sqlpipe_capi.cpp >/dev/null; then
    echo "DRIFTED swift/Sources/CSqlpipe/sqlpipe_capi.cpp differs from go/sqlpipe/sqlpipe_capi.cpp (modulo include paths)" >&2
    diff -u "$swift_capi_expected" swift/Sources/CSqlpipe/sqlpipe_capi.cpp | head -40 >&2
    status=1
fi

# The vendored deepparser sources must be identical in both wrappers.
if ! diff -rq go/sqlpipe/internal/c/deepparser swift/Sources/CSqlpipe/deepparser >/dev/null; then
    echo "DRIFTED vendored deepparser sources differ between the Go and Swift wrappers" >&2
    diff -rq go/sqlpipe/internal/c/deepparser swift/Sources/CSqlpipe/deepparser >&2
    status=1
fi

# A second copy of the C-API header outside include/ would be invisible to the
# Swift build (Package.swift sets publicHeadersPath: "include"), so it could rot
# unnoticed — as it did until 2026-09. There must be exactly one.
if [[ -f swift/Sources/CSqlpipe/sqlpipe_capi.h ]]; then
    echo "STALE swift/Sources/CSqlpipe/sqlpipe_capi.h shadows the real header in include/ and is not compiled; remove it" >&2
    status=1
fi

if [[ "$status" -eq 0 ]]; then
    echo "All vendored wrapper copies are in lockstep with their sources."
fi
exit "$status"
