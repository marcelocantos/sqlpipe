// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package terntest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/marcelocantos/tern"

	sqlpipe "github.com/marcelocantos/sqlpipe/go/sqlpipe"
	"github.com/marcelocantos/sqlpipe/go/sqlpipe/transport"
)

// startRelay starts an in-process WebTransport relay on an ephemeral port.
func startRelay(t *testing.T) (url string, clientTLS *tls.Config) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}
	pool := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(certDER)
	pool.AddCert(parsed)

	srv, err := tern.NewWebTransportServer("127.0.0.1:0",
		&tls.Config{Certificates: []tls.Certificate{cert}}, "")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(conn)
	t.Cleanup(func() { srv.Close() })

	addr := conn.LocalAddr().(*net.UDPAddr)
	return "https://127.0.0.1:" + strconv.Itoa(addr.Port),
		&tls.Config{RootCAs: pool}
}

func TestReplicateThroughTernRelay(t *testing.T) {
	relayURL, tlsCfg := startRelay(t)

	// Create databases.
	mDB, err := sqlpipe.OpenDatabase(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer mDB.Close()
	rDB, err := sqlpipe.OpenDatabase(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer rDB.Close()

	schema := "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)"
	mDB.Exec(schema)
	rDB.Exec(schema)

	master, err := sqlpipe.NewMaster(mDB, sqlpipe.MasterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	replica, err := sqlpipe.NewReplica(rDB, sqlpipe.ReplicaConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := []tern.Option{
		tern.WithTLS(tlsCfg),
		tern.WithWebTransport(),
	}

	// Backend (master side) registers with the relay.
	backend, err := tern.Register(ctx, relayURL, opts...)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer backend.CloseNow()

	// Client (replica side) connects to the backend.
	client, err := tern.Connect(ctx, relayURL, backend.InstanceID(), opts...)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.CloseNow()

	// tern.Conn satisfies transport.Transport.
	mLink := transport.NewLink(backend)
	rLink := transport.NewLink(client)

	// Collect replica changes.
	var mu sync.Mutex
	var changes []sqlpipe.ChangeEvent
	handler := func(hr sqlpipe.HandleResult) error {
		mu.Lock()
		defer mu.Unlock()
		changes = append(changes, hr.Changes...)
		return nil
	}

	flushCh := make(chan struct{}, 10)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		mLink.RunMaster(ctx, master, flushCh)
	}()
	go func() {
		defer wg.Done()
		rLink.RunReplica(ctx, replica, handler)
	}()

	// Wait for handshake.
	deadline := time.Now().Add(5 * time.Second)
	for replica.State() != sqlpipe.ReplicaLive && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if replica.State() != sqlpipe.ReplicaLive {
		t.Fatalf("replica didn't reach Live, state=%d", replica.State())
	}

	// Insert and flush.
	mDB.Exec("INSERT INTO items VALUES (1, 'hello')")
	flushCh <- struct{}{}

	// Wait for replication.
	for time.Now().Before(deadline) {
		result, err := rDB.Query("SELECT name FROM items WHERE id = 1")
		if err == nil && len(result.Rows) > 0 {
			if result.Rows[0][0] == "hello" {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Verify.
	result, err := rDB.Query("SELECT name FROM items WHERE id = 1")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 || result.Rows[0][0] != "hello" {
		t.Fatalf("expected [{hello}], got %v", result.Rows)
	}

	mu.Lock()
	if len(changes) == 0 {
		t.Fatal("no change events received")
	}
	mu.Unlock()

	t.Log("Replicated through tern relay: PASS")
	cancel()
	wg.Wait()
}
