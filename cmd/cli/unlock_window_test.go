package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"env-vault/internal/vault"

	"filippo.io/age"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == unlockHelperCommand {
		os.Exit(runMain(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func TestUnlockHelperLifecycle(t *testing.T) {
	cache := shortRuntimeDir(t)
	t.Setenv("LOCALAPPDATA", cache)
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("HOME", cache)
	dir := t.TempDir()
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := startUnlockHelper(dir, time.Minute, identity); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	t.Cleanup(func() {
		_, _ = clearUnlockWindow(dir)
		leasePath, err := unlockLeasePath(dir)
		if err != nil {
			t.Error(err)
			return
		}
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := readUnlockLease(leasePath); errors.Is(err, errNoUnlockWindow) {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Error("helper did not remove its lease after shutdown")
	})
	identityBytes, initialLease, err := fetchIdentityFromUnlockWindow(dir)
	if err != nil {
		t.Fatalf("fetch identity: %v", err)
	}
	defer vault.Wipe(identityBytes)
	fetchedIdentity, err := vault.ParseIdentity(identityBytes)
	if err != nil || fetchedIdentity.Recipient().String() != identity.Recipient().String() {
		t.Fatal("helper did not return the expected identity")
	}
	if err := extendUnlockWindow(dir, 2*time.Minute); err != nil {
		t.Fatalf("extend helper: %v", err)
	}
	status, err := unlockWindowStatus(dir)
	if err != nil {
		t.Fatalf("helper status: %v", err)
	}
	if !status.Lease.ExpiresAt.After(initialLease.ExpiresAt) {
		t.Fatal("helper expiry was not extended")
	}
	if cleared, err := clearUnlockWindow(dir); err != nil || !cleared {
		t.Fatalf("clear helper = %t, %v", cleared, err)
	}
}

func shortRuntimeDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != goosWindows {
		// Unix sockets have a small pathname limit; macOS test directories are long.
		dir, err := os.MkdirTemp("/tmp", "e")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		return dir
	}
	return t.TempDir()
}

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

func TestUnlockHelperRejectsMalformedTokens(t *testing.T) {
	for _, token := range []string{"", "short", strings.Repeat("z", 32), strings.Repeat("0", 34)} {
		if err := runUnlockHelper([]string{"--ttl", "1m", "--token", token}); err == nil {
			t.Fatalf("expected invalid token %q to fail before reading the identity", token)
		}
	}
}

func TestUnlockHelperRejectsExpiredRequests(t *testing.T) {
	for _, action := range []string{unlockActionIdentity, unlockActionStatus, unlockActionExtend} {
		t.Run(action, func(t *testing.T) {
			state := &unlockWindowState{lease: &unlockLease{
				Token:     "test-token",
				ExpiresAt: time.Now().Add(-time.Second),
			}}
			response, shutdown := handleUnlockRequest(unlockRequest{Token: state.lease.Token, Action: action, ExtendBy: time.Minute}, state)
			if response.Error != "unlock window has expired" || len(response.Identity) != 0 {
				t.Fatalf("expired helper returned unexpected response: %#v", response)
			}
			if !shutdown {
				t.Fatal("expired helper must shut down")
			}
		})
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

	request := unlockRequest{
		Action:   unlockActionExtend,
		Token:    lease.Token,
		ExtendBy: 5 * time.Minute,
	}
	response, shutdown := handleUnlockRequest(request, state)
	if shutdown {
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
	runtimeDir := shortRuntimeDir(t)
	token, err := randomUnlockToken()
	if err != nil {
		t.Fatal(err)
	}
	transport, listener, cleanup, err := listenUnlockTransport(runtimeDir, "test", token)
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
