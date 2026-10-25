// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package sqlpipe

import "testing"

func TestQueryWatchCommittedDependencies(t *testing.T) {
	db, err := OpenDatabase(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(sql string) {
		t.Helper()
		if err := db.Exec(sql); err != nil {
			t.Fatal(err)
		}
	}
	exec("CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT); CREATE TABLE other(id INTEGER PRIMARY KEY); INSERT INTO items VALUES(1,'first')")
	w, err := NewQueryWatch(db)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	// The nonce changes on every evaluation: empty notifications prove the
	// query was not evaluated, rather than only hash-deduplicated afterward.
	initial, err := w.Subscribe("SELECT {value, nonce: hex(randomblob(16))} FROM items WHERE id=1")
	if err != nil {
		t.Fatal(err)
	}
	expect := func(count int) {
		t.Helper()
		results, err := w.Notify()
		if err != nil {
			t.Fatal(err)
		}
		if len(results) != count {
			t.Fatalf("results=%+v, want %d", results, count)
		}
	}
	if len(initial.Rows) != 1 {
		t.Fatal("missing initial result")
	}
	expect(0)
	exec("INSERT INTO other VALUES(1)")
	expect(0)
	exec("UPDATE items SET value='first' WHERE id=1")
	expect(0)
	exec("BEGIN; UPDATE items SET value='rolled back' WHERE id=1")
	expect(0)
	exec("ROLLBACK")
	expect(0)
	exec("SAVEPOINT test; UPDATE items SET value='savepoint' WHERE id=1; ROLLBACK TO test; RELEASE test")
	expect(0)
	exec("BEGIN; UPDATE items SET value='second' WHERE id=1")
	expect(0)
	exec("COMMIT")
	expect(1)
	exec("INSERT INTO items VALUES(2,'same table conservatively invalidates')")
	expect(1)
	w.Unsubscribe(initial.ID)
	exec("UPDATE items SET value='third' WHERE id=1")
	expect(0)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Notify(); err == nil {
		t.Fatal("closed watch accepted notify")
	}
}

func TestQueryWatchSuppressesUnchangedProjection(t *testing.T) {
	db, err := OpenDatabase(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Exec("CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT); INSERT INTO items VALUES(1,'first')"); err != nil {
		t.Fatal(err)
	}
	w, err := NewQueryWatch(db)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Subscribe("SELECT count(*) FROM items"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Notify(); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("UPDATE items SET value='second'"); err != nil {
		t.Fatal(err)
	}
	results, err := w.Notify()
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("unchanged count emitted: %+v", results)
	}
}

func TestQueryWatchSurvivesTableReplacement(t *testing.T) {
	db, err := OpenDatabase(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Exec("CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT); INSERT INTO items VALUES(1,'old')"); err != nil {
		t.Fatal(err)
	}
	w, err := NewQueryWatch(db)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Subscribe("SELECT value FROM items"); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("BEGIN; DROP TABLE items; CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT); INSERT INTO items VALUES(1,'new'); COMMIT"); err != nil {
		t.Fatal(err)
	}
	result, err := w.Notify()
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].Rows[0][0] != "new" {
		t.Fatalf("replacement: %+v", result)
	}
}

func TestQueryWatchSurvivesPeerClose(t *testing.T) {
	db, err := OpenDatabase(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Exec("CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT); INSERT INTO items VALUES(1,'old')"); err != nil {
		t.Fatal(err)
	}
	w, err := NewQueryWatch(db)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Subscribe("SELECT value FROM items"); err != nil {
		t.Fatal(err)
	}
	p, err := NewPeer(db, PeerConfig{OwnedTables: map[string]bool{"items": true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Start(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("UPDATE items SET value='new'"); err != nil {
		t.Fatal(err)
	}
	result, err := w.Notify()
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("after peer close: %+v", result)
	}
}

func TestQueryWatchScalarSubqueryAndTransactionBoundary(t *testing.T) {
	db, err := OpenDatabase(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(sql string) {
		t.Helper()
		if err := db.Exec(sql); err != nil {
			t.Fatal(err)
		}
	}
	exec("CREATE TABLE providers(id INTEGER PRIMARY KEY, provider TEXT, status TEXT); INSERT INTO providers VALUES(1,'claude','available'); CREATE TABLE overrides(id INTEGER PRIMARY KEY,label TEXT); INSERT INTO overrides VALUES(1,'first')")
	w, err := NewQueryWatch(db)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	initial, err := w.Subscribe("SELECT {status, label: (SELECT label FROM overrides WHERE id=1)} FROM providers WHERE provider='claude'")
	if err != nil {
		t.Fatal(err)
	}
	exec("UPDATE overrides SET label='second' WHERE id=1")
	result, err := w.Notify()
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].ID != initial.ID {
		t.Fatalf("scalar subquery failed to invalidate: %+v", result)
	}
	exec("BEGIN")
	if _, err := w.Subscribe("SELECT count(*) FROM providers"); err == nil {
		t.Fatal("subscription accepted uncommitted initial state")
	}
	exec("ROLLBACK")
}
