// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package sqlpipe

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func openMemory(t *testing.T) (*sql.DB, *sql.Conn) {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(context.Background())
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.Close()
		db.Close()
	})
	return db, conn
}

func mustExec(t *testing.T, conn *sql.Conn, query string) {
	t.Helper()
	_, err := conn.ExecContext(context.Background(), query)
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
}
