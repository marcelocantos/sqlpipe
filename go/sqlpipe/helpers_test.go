// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package sqlpipe

import (
	"testing"
)

func mustExec(t *testing.T, db *Database, sql string) {
	t.Helper()
	if err := db.Exec(sql); err != nil {
		t.Fatal(err)
	}
}

func openMemory(t *testing.T) *Database {
	t.Helper()
	db, err := OpenDatabase(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
	})
	return db
}
