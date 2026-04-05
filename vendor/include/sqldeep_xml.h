// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

#pragma once

// sqldeep XML runtime functions for SQLite.
//
// Registers xml_element(), xml_attrs(), and xml_agg() as custom SQLite
// functions. These are the runtime counterparts to the XML literal syntax
// that the sqldeep transpiler emits.
//
// Requires sqlite3.h to be available at compile time and the SQLite library
// at link time.

#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

// Register xml_element, xml_attrs, and xml_agg on the given connection.
// Returns SQLITE_OK on success.
int sqldeep_register_sqlite_xml(sqlite3* db);

#ifdef __cplusplus
}
#endif
