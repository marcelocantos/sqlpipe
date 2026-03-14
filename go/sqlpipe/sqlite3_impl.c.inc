// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

// Compile the vendored SQLite3 with session extension support.
// The SQLITE_ENABLE_SESSION and SQLITE_ENABLE_PREUPDATE_HOOK defines
// are passed via CGo CFLAGS in wrapper.go.
#include "../../vendor/src/sqlite3.c"
