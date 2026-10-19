// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package sqlpipe

import (
	"bytes"
	"fmt"
	"testing"
)

// A row either peer commits while the link is mid-handshake crosses the
// wire exactly once (in the handshake diff or in a live changeset, never
// both), and both peers stay live. This is the Go copy of the C++ test
// "peer: a write at any handshake step crosses exactly once"; the Go
// package compiles its own copy of the C++ sources.
func TestPeerWriteDuringHandshakeCrossesOnce(t *testing.T) {
	const schema = `CREATE TABLE c_rows (id INTEGER PRIMARY KEY, val TEXT);
		CREATE TABLE s_rows (id INTEGER PRIMARY KEY, val TEXT)`
	type inFlight struct {
		toServer bool
		msg      PeerMessage
	}
	run := func(t *testing.T, k int) int {
		cdb, sdb := openMemory(t), openMemory(t)
		mustExec(t, cdb, schema)
		mustExec(t, sdb, schema)
		mustExec(t, cdb, "INSERT INTO c_rows VALUES (1, 'c-before')")
		mustExec(t, sdb, "INSERT INTO s_rows VALUES (1, 's-before')")
		client, err := NewPeer(cdb, PeerConfig{OwnedTables: map[string]bool{"c_rows": true}})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		server, err := NewPeer(sdb, PeerConfig{ApproveOwnership: func(map[string]bool) bool { return true }})
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()

		var wire, log []inFlight
		send := func(toServer bool, out []PeerOutMessage) {
			for _, m := range out {
				wire = append(wire, inFlight{toServer, m.Msg})
			}
		}
		// deliverOne hands the oldest message on the wire to its peer and
		// puts the replies on the wire.
		deliverOne := func(k int) {
			f := wire[0]
			wire = wire[1:]
			log = append(log, f)
			var hr PeerHandleResult
			var err error
			if f.toServer {
				hr, err = server.HandleMessage(f.msg)
			} else {
				hr, err = client.HandleMessage(f.msg)
			}
			if err != nil {
				t.Fatalf("write before message %d: message %d (%T): %v", k, len(log)-1, f.msg.Payload, err)
			}
			send(!f.toServer, hr.Messages)
		}
		flush := func() {
			out, err := client.Flush()
			if err != nil {
				t.Fatal(err)
			}
			send(true, out)
			if out, err = server.Flush(); err != nil {
				t.Fatal(err)
			}
			send(false, out)
		}
		out, err := client.Start()
		if err != nil {
			t.Fatal(err)
		}
		send(true, out)
		step, wrote := 0, false
		for len(wire) > 0 {
			if step == k {
				mustExec(t, cdb, fmt.Sprintf("INSERT INTO c_rows VALUES (2, 'c-near-%d'), (5000, 'c-far-%d')", k, k))
				mustExec(t, sdb, fmt.Sprintf("INSERT INTO s_rows VALUES (2, 's-near-%d'), (5000, 's-far-%d')", k, k))
				wrote = true
				flush() // a caller that flushes after every write
			}
			deliverOne(k)
			step++
		}
		if client.State() != PeerLive || server.State() != PeerLive {
			t.Fatalf("handshake ended with client %v, server %v", client.State(), server.State())
		}
		if !wrote {
			return step
		}
		flush()
		for len(wire) > 0 {
			deliverOne(k)
		}
		for _, c := range []struct {
			val      string
			toServer bool
		}{
			{fmt.Sprintf("c-near-%d", k), true}, {fmt.Sprintf("c-far-%d", k), true},
			{fmt.Sprintf("s-near-%d", k), false}, {fmt.Sprintf("s-far-%d", k), false},
		} {
			n := 0
			for _, f := range log {
				if f.toServer != c.toServer {
					continue
				}
				var data []byte
				switch m := f.msg.Payload.(type) {
				case DiffReadyMsg:
					data = m.Patchset
				case ChangesetMsg:
					data = m.Data
				}
				if bytes.Contains(data, []byte(c.val)) {
					n++
				}
			}
			if n != 1 {
				t.Errorf("write before message %d: %s crossed %d times, want 1", k, c.val, n)
			}
		}
		return step
	}
	steps := run(t, 1<<20)
	if steps < 6 {
		t.Fatalf("a handshake of %d messages", steps)
	}
	for k := range steps {
		t.Run(fmt.Sprint(k), func(t *testing.T) { run(t, k) })
	}
}
