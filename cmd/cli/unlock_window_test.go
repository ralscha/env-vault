package main

import (
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVaultDirFingerprintStable(t *testing.T) {
	dir := filepath.Join("C:\\Temp", "Vault")
	if got, want := vaultDirFingerprint(dir), vaultDirFingerprint(filepath.Clean(dir)); got != want {
		t.Fatalf("unexpected fingerprint mismatch: %q != %q", got, want)
	}
}

func TestWriteReadUnlockLease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease.json")
	lease := unlockLease{
		Version:   unlockLeaseVersion,
		VaultDir:  "C:/vault",
		Network:   "unix",
		Endpoint:  "/tmp/env-vault.sock",
		Token:     "token-value",
		ExpiresAt: time.Date(2026, time.April, 6, 12, 0, 0, 0, time.UTC),
		PID:       99,
	}
	if err := writeUnlockLease(path, lease); err != nil {
		t.Fatalf("write unlock lease: %v", err)
	}

	loaded, err := readUnlockLease(path)
	if err != nil {
		t.Fatalf("read unlock lease: %v", err)
	}
	if loaded != lease {
		t.Fatalf("unexpected loaded lease: %#v", loaded)
	}
}

func TestReadUnlockLeaseMissing(t *testing.T) {
	if _, err := readUnlockLease(filepath.Join(t.TempDir(), "missing.json")); !errors.Is(err, errNoUnlockWindow) {
		t.Fatalf("expected errNoUnlockWindow, got %v", err)
	}
}

func TestCleanedVaultDirAbsolute(t *testing.T) {
	cleaned := cleanedVaultDir(".")
	if !filepath.IsAbs(cleaned) {
		t.Fatalf("expected absolute cleaned vault dir, got %q", cleaned)
	}
	if strings.TrimSpace(cleaned) == "" {
		t.Fatal("expected non-empty cleaned vault dir")
	}
}

func TestRandomUnlockToken(t *testing.T) {
	token, err := randomUnlockToken()
	if err != nil {
		t.Fatalf("random unlock token: %v", err)
	}
	if len(token) != 32 {
		t.Fatalf("unexpected token length: %d", len(token))
	}
}

func TestAppendUnlockAuditEventKeepsNewestEntries(t *testing.T) {
	events := []unlockAuditEvent{}
	for index := range unlockAuditEventLimit + 3 {
		events = appendUnlockAuditEvent(events, unlockAuditEvent{
			Timestamp: time.Date(2026, time.April, 6, 12, 0, index, 0, time.UTC),
			PID:       index,
			Command:   "exec",
			Target:    "chat",
		})
	}
	if len(events) != unlockAuditEventLimit {
		t.Fatalf("unexpected event count: %d", len(events))
	}
	if events[0].PID != 3 {
		t.Fatalf("expected oldest retained pid to be 3, got %d", events[0].PID)
	}
	if events[len(events)-1].PID != unlockAuditEventLimit+2 {
		t.Fatalf("unexpected newest pid: %d", events[len(events)-1].PID)
	}
}

func TestUnlockTransportRoundTrip(t *testing.T) {
	runtimeDir := t.TempDir()
	transport, listener, cleanup, err := listenUnlockTransport(runtimeDir, "abc123", "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("listen unlock transport: %v", err)
	}
	defer func() {
		_ = listener.Close()
	}()
	defer func() {
		_ = cleanup()
	}()

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer func() {
			_ = conn.Close()
		}()

		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			accepted <- err
			return
		}
		if string(buf) != "ping" {
			accepted <- errNoUnlockWindow
			return
		}
		_, err = conn.Write([]byte("pong"))
		accepted <- err
	}()

	conn, err := dialUnlockTransport(unlockLease{Network: transport.Network, Endpoint: transport.Endpoint}, time.Second)
	if err != nil {
		t.Fatalf("dial unlock transport: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("unexpected reply: %q", reply)
	}
	if err := <-accepted; err != nil {
		t.Fatalf("accept loop: %v", err)
	}
}
