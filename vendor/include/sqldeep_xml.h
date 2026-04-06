// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

#pragma once

// sqldeep runtime functions for SQLite.
//
// Registers all custom SQLite functions that the sqldeep transpiler emits:
// xml_element, xml_attrs, xml_agg (and _jsonml/_jsx variants),
// sqldeep_json, sqldeep_json_object, sqldeep_json_array,
// sqldeep_json_group_array.
//
// All structured values use a pure BLOB protocol — no SQLite subtypes.
// BLOBs starting with '<' are XML; all others are JSON.
//
// Requires sqlite3.h to be available at compile time and the SQLite library
// at link time.

#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

// Register all sqldeep runtime functions on the given connection.
// Returns SQLITE_OK on success.
int sqldeep_register_sqlite_xml(sqlite3* db);

#ifdef __cplusplus
}
#endif
