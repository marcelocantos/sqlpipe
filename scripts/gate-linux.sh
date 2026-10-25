#!/usr/bin/env bash
# Copyright 2026 The sqlpipe Authors
# SPDX-License-Identifier: Apache-2.0
#
# Optional Linux verification in Docker. Not part of `make gate`.
# Live Postgres stays on the host gate (ephemeral postgres:16).
# Usage: make gate-linux
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

if ! command -v docker >/dev/null 2>&1; then
    echo "gate-linux: docker is required" >&2
    exit 1
fi

PLATFORM="${GATE_LINUX_PLATFORM:-linux/arm64}"
IMAGE="${GATE_LINUX_IMAGE:-ubuntu:24.04}"
CV_REPO="marcelocantos/cv"

if command -v gh >/dev/null 2>&1; then
    CV_VERSION=$(gh release view --repo "$CV_REPO" --json tagName -q .tagName)
else
    echo "gate-linux: gh is required to fetch a cv release" >&2
    exit 1
fi
CV_VER=${CV_VERSION#v}
case "$PLATFORM" in
    linux/arm64) CV_ARCH=linux-arm64 ;;
    linux/amd64) CV_ARCH=linux-amd64 ;;
    *) echo "gate-linux: unsupported PLATFORM=$PLATFORM" >&2; exit 1 ;;
esac

echo "→ Linux $PLATFORM ($IMAGE, cv $CV_VERSION)"
docker run --rm --platform "$PLATFORM" \
    -v "$PWD:/src:ro" \
    -e DEBIAN_FRONTEND=noninteractive \
    -e CV_VERSION="$CV_VERSION" \
    -e CV_VER="$CV_VER" \
    -e CV_ARCH="$CV_ARCH" \
    "$IMAGE" \
    bash -lc '
        set -euo pipefail
        apt-get update -qq
        apt-get install -y -qq build-essential curl ca-certificates pkg-config \
            libpq-dev git golang-go >/dev/null
        curl -fsSL "https://github.com/marcelocantos/cv/releases/download/${CV_VERSION}/cv-${CV_VER}-${CV_ARCH}.tar.gz" \
            | tar xz -C /usr/local/bin cv
        cp -a /src /work
        rm -rf /work/build /work/.cv
        cd /work
        cv test
        (cd go/sqlpipe && GOWORK=off go test -count=1 ./...)
    '
echo "✓ gate-linux"
