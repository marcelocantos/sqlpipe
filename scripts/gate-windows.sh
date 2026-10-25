#!/usr/bin/env bash
# Copyright 2026 The sqlpipe Authors
# SPDX-License-Identifier: Apache-2.0
#
# Optional Windows verification on the local Parallels VM (ssh hms-vm).
# Not part of `make gate`. The VM is provisioned for mnemo today; this
# repo's C++/cv toolchain is not installed there yet.
# Usage: make gate-windows
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

VM="${WINCI_VM:-hms-vm}"

if ! ssh -o ConnectTimeout=8 -o BatchMode=yes "$VM" "echo ok" >/dev/null 2>&1; then
    echo "gate-windows: cannot ssh $VM — start the Parallels VM, then retry." >&2
    echo "  Default host is hms-vm (Win11 ARM64). Override with WINCI_VM." >&2
    exit 3
fi

echo "gate-windows: $VM is reachable, but this repo has no Windows toolchain yet." >&2
echo "  Next: install cv (or clang + libc++) on the VM, then rsync + cv test." >&2
exit 2
