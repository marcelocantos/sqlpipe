// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

//go:build postgres

package sqlpipe

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// The owner gate supplies a disposable server; never mutate a developer's
// default libpq database merely because the postgres build tag was selected.
func TestPostgresBindingLive(t *testing.T) {
	if os.Getenv("SQLPIPE_TEST_POSTGRES") != "1" {
		t.Skip("run make gate for the disposable live Postgres server")
	}
	admin, err := OpenPostgres("")
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	setup, err := NewMasterPG(admin, MasterConfig{TableFilter: &TableFilter{}})
	if err != nil {
		t.Fatal(err)
	}
	defer setup.Close()

	var connections []*PGConn
	for _, role := range []string{"master", "replica"} {
		name := fmt.Sprintf("sqlpipe_go_%s_%d", role, time.Now().UnixNano())
		if err := setup.Exec("CREATE DATABASE " + name); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := setup.Exec("DROP DATABASE " + name + " WITH (FORCE)"); err != nil {
				t.Error(err)
			}
		}()
		conn, err := OpenPostgres("dbname=" + name)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		bootstrap, err := NewMasterPG(conn, MasterConfig{TableFilter: &TableFilter{}})
		if err != nil {
			t.Fatal(err)
		}
		err = bootstrap.Exec("CREATE TABLE items (id BIGINT PRIMARY KEY, value TEXT)")
		bootstrap.Close()
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
	}

	var flushed []OutMessage
	masterLogs, replicaLogs := 0, 0
	m, err := NewMasterPG(connections[0], MasterConfig{
		OnLog:   func(LogLevel, string) { masterLogs++ },
		OnFlush: func(msgs []OutMessage) { flushed = append(flushed, msgs...) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	r, err := NewReplicaPG(connections[1], ReplicaConfig{
		OnLog:                func(LogLevel, string) { replicaLogs++ },
		QueueWhilePredicting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if masterLogs == 0 || replicaLogs == 0 || !r.QueuesWhilePredicting() {
		t.Fatalf("configuration lost: master logs=%d replica logs=%d queue=%v", masterLogs, replicaLogs, r.QueuesWhilePredicting())
	}
	if err := SyncHandshake(m, r); err != nil {
		t.Fatal(err)
	}
	id, err := r.Subscribe("SELECT value FROM items ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Exec("INSERT INTO items VALUES (1, 'live')"); err != nil {
		t.Fatal(err)
	}
	if len(flushed) != 1 {
		t.Fatalf("OnFlush delivered %d messages, want 1", len(flushed))
	}
	hr, err := r.HandleMessage(flushed[0].Msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(hr.Subscriptions) != 1 || hr.Subscriptions[0].ID != id {
		t.Fatalf("missing subscription delivery: %+v", hr.Subscriptions)
	}
	rows := hr.Subscriptions[0].Rows
	if len(rows) != 1 || len(rows[0]) != 1 || rows[0][0] != "live" {
		t.Fatalf("replicated rows = %#v", rows)
	}
}
