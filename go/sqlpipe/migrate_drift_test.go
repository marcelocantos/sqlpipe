// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package sqlpipe

import (
	"path/filepath"
	"strings"
	"testing"
)

const driftSchemaV1 = `CREATE TABLE notes (
  id INTEGER PRIMARY KEY,
  body TEXT NOT NULL
);`

const driftSchemaV2 = `CREATE TABLE notes (
  id INTEGER PRIMARY KEY,
  body TEXT NOT NULL,
  trashed TEXT NOT NULL DEFAULT ''
);`

// openWithMaster opens path at schema and attaches a Master, as a
// consumer does, so sqlpipe's own tables exist when it closes.
func openWithMaster(t *testing.T, path, schema string) {
	t.Helper()
	db, err := OpenDatabase(path, schema)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewMaster(db, MasterConfig{})
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	mustExec(t, db, `INSERT INTO notes (body) VALUES ('kept')`)
	m.Close()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

// A store migrated once and then given a Master has _sqlpipe_meta, which
// the hash sqlift stored after that migration does not cover. The next
// schema change must still migrate it.
func TestMigrateAfterMasterAttachedIsNotDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	openWithMaster(t, path, driftSchemaV1)

	db, err := OpenDatabase(path, driftSchemaV2)
	if err != nil {
		t.Fatalf("migrating an existing store with sqlpipe's tables: %v", err)
	}
	defer db.Close()
	res, err := db.Query(`SELECT body, trashed FROM notes`)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("rows after migration = %d, want 1", len(res.Rows))
	}
}

// A table created behind sqlift's back is still drift, even when the new
// schema declares the same table (so the plan is not destructive and the
// drift check is what refuses it).
func TestMigrateStillRefusesGenuineDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	openWithMaster(t, path, driftSchemaV1)

	db, err := OpenDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `CREATE TABLE stray (x INTEGER)`)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = OpenDatabase(path, driftSchemaV2+"\nCREATE TABLE stray (x INTEGER);")
	if err == nil {
		db.Close()
		t.Fatal("a table added outside sqlift migrated without a drift error")
	}
	if !strings.Contains(err.Error(), "DRIFT") {
		t.Fatalf("error = %v, want a drift error", err)
	}
}
