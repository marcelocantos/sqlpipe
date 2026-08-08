// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package sqlpipe

import "testing"

func TestPredictionBeginCommitEnd(t *testing.T) {
	db, err := OpenDatabase(":memory:", "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	r, err := NewReplica(db, ReplicaConfig{QueueWhilePredicting: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if !r.QueuesWhilePredicting() {
		t.Fatal("want queue_while_predicting")
	}
	if err := r.BeginPrediction(); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO items (id, name) VALUES (1, 'pred')"); err != nil {
		t.Fatal(err)
	}
	if err := r.CommitPrediction(); err != nil {
		t.Fatal(err)
	}
	qr, err := db.Query("SELECT name FROM items WHERE id = 1")
	if err != nil {
		t.Fatal(err)
	}
	if len(qr.Rows) != 1 {
		t.Fatalf("predicted row missing: %v", qr.Rows)
	}
	if _, err := r.EndPrediction(); err != nil {
		t.Fatal(err)
	}
	// After end, prediction savepoint rolled back — row gone unless applied from server.
	qr, err = db.Query("SELECT name FROM items WHERE id = 1")
	if err != nil {
		t.Fatal(err)
	}
	if len(qr.Rows) != 0 {
		t.Fatalf("after end_prediction want empty, got %v", qr.Rows)
	}
}
