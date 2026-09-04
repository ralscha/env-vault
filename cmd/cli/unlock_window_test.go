package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
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

func TestRemoveUnlockLeaseDoesNotRemoveReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease.json")
	lease := unlockLease{Version: unlockLeaseVersion, Token: "replacement"}
	if err := writeUnlockLease(path, lease); err != nil {
		t.Fatalf("write lease: %v", err)
	}
	if err := removeUnlockLease(path, "stale-token"); err != nil {
		t.Fatalf("remove stale lease: %v", err)
	}
	loaded, err := readUnlockLease(path)
	if err != nil {
		t.Fatalf("replacement lease was removed: %v", err)
	}
	if loaded.Token != lease.Token {
		t.Fatalf("unexpected replacement token: %q", loaded.Token)
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

func TestUnlockHelperExtendsActiveLease(t *testing.T) {
	leasePath := filepath.Join(t.TempDir(), "lease.json")
	initialExpiry := time.Now().UTC().Add(time.Minute)
	lease := unlockLease{
		Version:   unlockLeaseVersion,
		Token:     "token-value",
		ExpiresAt: initialExpiry,
	}
	state := &unlockWindowState{
		lease:       &lease,
		leasePath:   leasePath,
		expiryTimer: time.AfterFunc(time.Hour, func() {}),
	}
	defer state.expiryTimer.Stop()

	client, server := net.Pipe()
	done := make(chan bool, 1)
	go func() {
		done <- serveUnlockWindowConn(server, state)
	}()

	request := unlockRequest{
		Action:   unlockActionExtend,
		Token:    lease.Token,
		ExtendBy: 5 * time.Minute,
	}
	if err := json.NewEncoder(client).Encode(request); err != nil {
		t.Fatalf("encode extension request: %v", err)
	}
	response := unlockResponse{}
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatalf("decode extension response: %v", err)
	}
	_ = client.Close()
	if shutdown := <-done; shutdown {
		t.Fatal("extension unexpectedly shut down helper")
	}
	if response.Error != "" {
		t.Fatalf("extension returned error: %s", response.Error)
	}
	if !response.ExpiresAt.After(initialExpiry) {
		t.Fatalf("expiry was not extended: %s <= %s", response.ExpiresAt, initialExpiry)
	}

	persisted, err := readUnlockLease(leasePath)
	if err != nil {
		t.Fatalf("read extended lease: %v", err)
	}
	if !persisted.ExpiresAt.Equal(response.ExpiresAt) {
		t.Fatalf("persisted expiry %s != response expiry %s", persisted.ExpiresAt, response.ExpiresAt)
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
