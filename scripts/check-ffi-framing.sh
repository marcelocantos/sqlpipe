#!/bin/bash
# Assert that the two FFI shims encode the core's result types identically.
#
# sqlpipe exposes its C++ core through two hand-written shims: a C API for the
# Go wrapper (go/sqlpipe/sqlpipe_capi.cpp) and an emscripten API for the web
# package (web/sqlpipe_wapi.cpp). Both must serialize the same core types —
# OutMessage, ChangeEvent, QueryResult, HandleResult — into the same bytes, or
# the same conceptual value has two incompatible wire encodings and a decoder
# written against one silently misreads the other.
#
# That is not hypothetical: until 2026-09 the Wasm shim omitted the u8 delivery
# byte from every message, so the TypeScript surface could not distinguish
# Reliable from BestEffort while the Go surface could.
#
# Usage: scripts/check-ffi-framing.sh
# Exit:  0 the shared encoders agree; 1 they have diverged.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

GO_SHIM=go/sqlpipe/sqlpipe_capi.cpp
WASM_SHIM=web/sqlpipe_wapi.cpp

# Encoders that write the shared wire framing. Anything that turns a core type
# into bytes belongs here; shim-specific plumbing (handle allocation, callback
# marshalling, error reporting) legitimately differs and is not compared.
ENCODERS=(
    encode_value
    encode_change_event
    encode_query_result
    encode_messages
    encode_peer_messages
    encode_handle_result
    encode_peer_handle_result
)

# Print one function's body: from the line where it is defined at file scope to
# the closing brace in column 1. Comments are skipped so wording may differ.
extract() {
    local file="$1" fn="$2"
    awk -v fn="$fn" '
        !inside && $0 ~ ("^[A-Za-z].*[ *]" fn "\\(") { inside = 1 }
        inside {
            if ($0 !~ /^[ \t]*\/\//) print
            if ($0 == "}") exit
        }
    ' "$file"
}

status=0
for fn in "${ENCODERS[@]}"; do
    go_body="$(extract "$GO_SHIM" "$fn")"
    wasm_body="$(extract "$WASM_SHIM" "$fn")"
    if [[ -z "$go_body" ]]; then
        echo "NOTFOUND $fn is not defined in $GO_SHIM" >&2
        status=1
        continue
    fi
    if [[ -z "$wasm_body" ]]; then
        echo "NOTFOUND $fn is not defined in $WASM_SHIM" >&2
        status=1
        continue
    fi
    if [[ "$go_body" != "$wasm_body" ]]; then
        echo "DIVERGED $fn encodes differently in the two FFI shims:" >&2
        diff -u <(printf '%s\n' "$go_body") <(printf '%s\n' "$wasm_body") \
            | sed -e "s|^--- .*|--- $GO_SHIM|" -e "s|^+++ .*|+++ $WASM_SHIM|" >&2
        status=1
    fi
done

if [[ "$status" -eq 0 ]]; then
    echo "Both FFI shims encode the core result types identically."
fi
exit "$status"
