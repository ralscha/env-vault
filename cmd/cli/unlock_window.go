package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"env-vault/internal/vault"

	"filippo.io/age"
)

const (
	unlockHelperCommand      = "__unlock-helper"
	unlockLeaseVersion       = 2
	unlockHelperStartupDelay = 2 * time.Second
	unlockActionIdentity     = "identity"
	unlockActionStatus       = "status"
	unlockActionAudit        = "audit"
	unlockActionShutdown     = "shutdown"
	unlockAuditEventLimit    = 12
)

var errNoUnlockWindow = errors.New("no active unlock window")

type unlockLease struct {
	Version   int       `json:"version"`
	VaultDir  string    `json:"vault_dir"`
	Network   string    `json:"network"`
	Endpoint  string    `json:"endpoint"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	PID       int       `json:"pid"`
}

type unlockTransport struct {
	Network  string
	Endpoint string
}

type unlockRequest struct {
	Action string            `json:"action"`
	Token  string            `json:"token"`
	Event  *unlockAuditEvent `json:"event,omitempty"`
}

type unlockResponse struct {
	Identity  []byte             `json:"identity,omitempty"`
	Events    []unlockAuditEvent `json:"events,omitempty"`
	ExpiresAt time.Time          `json:"expires_at"`
	Error     string             `json:"error,omitempty"`
}

type unlockWindowState struct {
	identity    *age.HybridIdentity
	auditEvents []unlockAuditEvent
}

type unlockStatusInfo struct {
	Lease  unlockLease
	Events []unlockAuditEvent
}

func runUnlock(args []string) error {
	fs := flag.NewFlagSet("unlock", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", defaultVaultDir(), "vault directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: env-vault unlock [--dir PATH] status|clear")
	}

	switch fs.Arg(0) {
	case "status":
		status, err := unlockWindowStatus(*dir)
		if err != nil {
			if errors.Is(err, errNoUnlockWindow) {
				return writeLine(os.Stdout, "No active unlock window.")
			}
			return err
		}
		if err := writeTextf(os.Stdout, "vault dir: %s\n", status.Lease.VaultDir); err != nil {
			return err
		}
		if err := writeTextf(os.Stdout, "transport: %s\n", status.Lease.Network); err != nil {
			return err
		}
		if err := writeTextf(os.Stdout, "endpoint: %s\n", status.Lease.Endpoint); err != nil {
			return err
		}
		if err := writeTextf(os.Stdout, "pid: %d\n", status.Lease.PID); err != nil {
			return err
		}
		if err := writeTextf(os.Stdout, "expires: %s\n", status.Lease.ExpiresAt.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
		if len(status.Events) == 0 {
			return writeLine(os.Stdout, "recent activity: none")
		}
		if err := writeLine(os.Stdout, "recent activity:"); err != nil {
			return err
		}
		for _, event := range status.Events {
			reuse := "started"
			if event.ReusedWindow {
				reuse = "reused"
			}
			if err := writeTextf(os.Stdout, "  %s pid=%d command=%s target=%s via=%s window=%s\n",
				event.Timestamp.UTC().Format(time.RFC3339),
				event.PID,
				event.Command,
				auditTargetDisplay(event.Target),
				event.UnlockSource,
				reuse,
			); err != nil {
				return err
			}
		}
		return nil
	case "clear":
		cleared, err := clearUnlockWindow(*dir)
		if err != nil {
			return err
		}
		if !cleared {
			return writeLine(os.Stdout, "No active unlock window.")
		}
		return writeLine(os.Stdout, "Cleared unlock window.")
	default:
		return fmt.Errorf("usage: env-vault unlock [--dir PATH] status|clear")
	}
}

func runUnlockHelper(args []string) error {
	fs := flag.NewFlagSet(unlockHelperCommand, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", defaultVaultDir(), "vault directory")
	ttl := fs.Duration("ttl", 0, "unlock window duration")
	token := fs.String("token", "", "unlock window token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%s does not accept positional arguments", unlockHelperCommand)
	}
	if *ttl <= 0 {
		return fmt.Errorf("--ttl must be greater than zero")
	}
	if *token == "" {
		return fmt.Errorf("--token is required")
	}

	identityBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read unlock helper identity: %w", err)
	}
	defer vault.Wipe(identityBytes)

	identity, err := vault.ParseIdentity(identityBytes)
	if err != nil {
		return fmt.Errorf("parse unlock helper identity: %w", err)
	}

	runtimeDir, err := unlockRuntimeDir()
	if err != nil {
		return err
	}
	transport, listener, cleanup, err := listenUnlockTransport(runtimeDir, vaultDirFingerprint(*dir), *token)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
	}()
	defer func() {
		_ = cleanup()
	}()

	leasePath, err := unlockLeasePath(*dir)
	if err != nil {
		return err
	}
	lease := unlockLease{
		Version:   unlockLeaseVersion,
		VaultDir:  cleanedVaultDir(*dir),
		Network:   transport.Network,
		Endpoint:  transport.Endpoint,
		Token:     *token,
		ExpiresAt: time.Now().UTC().Add(*ttl),
		PID:       os.Getpid(),
	}
	if err := writeUnlockLease(leasePath, lease); err != nil {
		return err
	}
	defer func() {
		_ = os.Remove(leasePath)
	}()
	expiryTimer := time.AfterFunc(time.Until(lease.ExpiresAt), func() {
		_ = listener.Close()
	})
	defer expiryTimer.Stop()

	state := &unlockWindowState{identity: identity}
	shutdown := false
	for !shutdown {
		conn, err := listener.Accept()
		if err != nil {
			if time.Now().After(lease.ExpiresAt) {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		shutdown = serveUnlockWindowConn(conn, lease, state)
	}
	return nil
}

func serveUnlockWindowConn(conn net.Conn, lease unlockLease, state *unlockWindowState) bool {
	defer func() {
		_ = conn.Close()
	}()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return false
	}
	decoder := json.NewDecoder(io.LimitReader(conn, 1<<20))
	encoder := json.NewEncoder(conn)

	request := unlockRequest{}
	if err := decoder.Decode(&request); err != nil {
		_ = encoder.Encode(unlockResponse{Error: fmt.Sprintf("decode request: %v", err)})
		return false
	}
	if request.Token != lease.Token {
		_ = encoder.Encode(unlockResponse{Error: "unauthorized"})
		return false
	}

	switch request.Action {
	case unlockActionIdentity:
		_ = encoder.Encode(unlockResponse{Identity: vault.MarshalIdentity(state.identity), ExpiresAt: lease.ExpiresAt})
		return false
	case unlockActionStatus:
		_ = encoder.Encode(unlockResponse{ExpiresAt: lease.ExpiresAt, Events: cloneUnlockAuditEvents(state.auditEvents)})
		return false
	case unlockActionAudit:
		if request.Event == nil || request.Event.Command == "" {
			_ = encoder.Encode(unlockResponse{Error: "missing audit event"})
			return false
		}
		state.auditEvents = appendUnlockAuditEvent(state.auditEvents, *request.Event)
		_ = encoder.Encode(unlockResponse{ExpiresAt: lease.ExpiresAt, Events: cloneUnlockAuditEvents(state.auditEvents)})
		return false
	case unlockActionShutdown:
		_ = encoder.Encode(unlockResponse{ExpiresAt: lease.ExpiresAt})
		return true
	default:
		_ = encoder.Encode(unlockResponse{Error: fmt.Sprintf("unsupported action %q", request.Action)})
		return false
	}
}

func withOpenedStore(dir string, unlock unlockOptions, audit unlockAuditEvent, fn func(*vault.Opened) error) error {
	store := vault.NewStore(dir)
	opened, err := openStoreWithUnlockWindow(store)
	if err == nil {
		defer opened.Close()
		if err := fn(opened); err != nil {
			return err
		}
		if err := recordUnlockWindowAudit(store.Dir(), finalizeUnlockAuditEvent(audit, "unlock-window", true)); err != nil {
			if writeErr := writeTextf(os.Stderr, "Warning: failed to record unlock activity for %s: %v\n", dir, err); writeErr != nil {
				return writeErr
			}
		}
		return nil
	}
	if !errors.Is(err, errNoUnlockWindow) && unlock.unlockWindow > 0 {
		if writeErr := writeTextf(os.Stderr, "Warning: failed to reuse unlock window for %s: %v\n", dir, err); writeErr != nil {
			return writeErr
		}
	}

	if unlock.unlockWindow <= 0 {
		return withMasterPassword(unlock, func(password []byte) error {
			opened, err := store.Open(password)
			if err != nil {
				return err
			}
			defer opened.Close()
			return fn(opened)
		})
	}

	return withMasterPassword(unlock, func(password []byte) error {
		identity, err := store.DecryptIdentity(password)
		if err != nil {
			return err
		}
		opened, err := store.OpenWithIdentity(identity)
		if err != nil {
			return err
		}
		defer opened.Close()

		windowReady := false
		if err := ensureUnlockWindow(store.Dir(), unlock.unlockWindow, identity); err != nil {
			if writeErr := writeTextf(os.Stderr, "Warning: failed to start unlock window for %s: %v\n", dir, err); writeErr != nil {
				return writeErr
			}
		} else {
			windowReady = true
		}
		if err := fn(opened); err != nil {
			return err
		}
		if windowReady {
			if err := recordUnlockWindowAudit(store.Dir(), finalizeUnlockAuditEvent(audit, unlockSourceName(unlock), false)); err != nil {
				if writeErr := writeTextf(os.Stderr, "Warning: failed to record unlock activity for %s: %v\n", dir, err); writeErr != nil {
					return writeErr
				}
			}
		}
		return nil
	})
}

func openStoreWithUnlockWindow(store *vault.Store) (*vault.Opened, error) {
	identityBytes, _, err := fetchIdentityFromUnlockWindow(store.Dir())
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(identityBytes)

	identity, err := vault.ParseIdentity(identityBytes)
	if err != nil {
		return nil, fmt.Errorf("parse unlock window identity: %w", err)
	}
	return store.OpenWithIdentity(identity)
}

func withUnlockWindowLease(dir string, fn func(unlockLease, string) error) error {
	leasePath, err := unlockLeasePath(dir)
	if err != nil {
		return err
	}
	lease, err := readUnlockLease(leasePath)
	if err != nil {
		return err
	}
	if lease.Version != unlockLeaseVersion {
		_ = os.Remove(leasePath)
		return errNoUnlockWindow
	}
	if time.Now().After(lease.ExpiresAt) {
		_ = os.Remove(leasePath)
		return errNoUnlockWindow
	}
	return fn(lease, leasePath)
}

func fetchIdentityFromUnlockWindow(dir string) ([]byte, unlockLease, error) {
	var identity []byte
	var lease unlockLease
	err := withUnlockWindowLease(dir, func(candidate unlockLease, leasePath string) error {
		response, err := requestUnlockHelper(candidate, unlockActionIdentity, nil)
		if err != nil {
			_ = os.Remove(leasePath)
			return errNoUnlockWindow
		}
		if response.Error != "" {
			if response.Error == "unauthorized" {
				_ = os.Remove(leasePath)
			}
			return fmt.Errorf("unlock helper: %s", response.Error)
		}
		identity = response.Identity
		lease = candidate
		return nil
	})
	if err != nil {
		return nil, unlockLease{}, err
	}
	return identity, lease, nil
}

func unlockWindowStatus(dir string) (unlockStatusInfo, error) {
	status := unlockStatusInfo{}
	err := withUnlockWindowLease(dir, func(candidate unlockLease, leasePath string) error {
		response, err := requestUnlockHelper(candidate, unlockActionStatus, nil)
		if err != nil {
			_ = os.Remove(leasePath)
			return errNoUnlockWindow
		}
		if response.Error != "" {
			return fmt.Errorf("unlock helper: %s", response.Error)
		}
		status.Lease = candidate
		status.Events = response.Events
		return nil
	})
	if err != nil {
		return unlockStatusInfo{}, err
	}
	return status, nil
}

func clearUnlockWindow(dir string) (bool, error) {
	cleared := false
	err := withUnlockWindowLease(dir, func(lease unlockLease, leasePath string) error {
		_, err := requestUnlockHelper(lease, unlockActionShutdown, nil)
		if err != nil && !errors.Is(err, errNoUnlockWindow) {
			_ = os.Remove(leasePath)
			return nil
		}
		if err := os.Remove(leasePath); err != nil {
			return err
		}
		cleared = true
		return nil
	})
	if err != nil {
		if errors.Is(err, errNoUnlockWindow) {
			return false, nil
		}
		return false, err
	}
	return cleared, nil
}

func ensureUnlockWindow(dir string, ttl time.Duration, identity *age.HybridIdentity) error {
	if ttl <= 0 {
		return nil
	}
	if _, err := unlockWindowStatus(dir); err == nil {
		return nil
	} else if !errors.Is(err, errNoUnlockWindow) {
		return err
	}
	return startUnlockHelper(dir, ttl, identity)
}

func startUnlockHelper(dir string, ttl time.Duration, identity *age.HybridIdentity) error {
	token, err := randomUnlockToken()
	if err != nil {
		return err
	}
	executablePath, err := currentExecutablePath()
	if err != nil {
		return err
	}
	identityBytes := vault.MarshalIdentity(identity)
	defer vault.Wipe(identityBytes)

	//nolint:gosec // the helper re-executes the current binary with fixed internal arguments.
	cmd := exec.Command(executablePath, unlockHelperCommand, "--dir", dir, "--ttl", ttl.String(), "--token", token)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	if _, err := stdin.Write(identityBytes); err != nil {
		_ = stdin.Close()
		return err
	}
	if err := stdin.Close(); err != nil {
		return err
	}
	if err := cmd.Process.Release(); err != nil {
		return err
	}

	leasePath, err := unlockLeasePath(dir)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(unlockHelperStartupDelay)
	for time.Now().Before(deadline) {
		lease, err := readUnlockLease(leasePath)
		if err == nil && lease.Token == token {
			if _, err := requestUnlockHelper(lease, unlockActionStatus, nil); err == nil {
				return nil
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for unlock helper startup")
}

func currentExecutablePath() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve current executable: %w", err)
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("resolve current executable symlinks: %w", err)
		}
		return path, nil
	}
	return path, nil
}

func requestUnlockHelper(lease unlockLease, action string, event *unlockAuditEvent) (unlockResponse, error) {
	conn, err := dialUnlockTransport(lease, time.Second)
	if err != nil {
		return unlockResponse{}, errNoUnlockWindow
	}
	defer func() {
		_ = conn.Close()
	}()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return unlockResponse{}, err
	}

	request := unlockRequest{Action: action, Token: lease.Token, Event: event}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return unlockResponse{}, err
	}
	response := unlockResponse{}
	if err := json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&response); err != nil {
		return unlockResponse{}, err
	}
	if response.Error != "" {
		return response, nil
	}
	if time.Now().After(lease.ExpiresAt) {
		return unlockResponse{}, errNoUnlockWindow
	}
	return response, nil
}

func recordUnlockWindowAudit(dir string, event unlockAuditEvent) error {
	if event.Command == "" {
		return nil
	}
	return withUnlockWindowLease(dir, func(lease unlockLease, leasePath string) error {
		response, err := requestUnlockHelper(lease, unlockActionAudit, &event)
		if err != nil {
			_ = os.Remove(leasePath)
			return errNoUnlockWindow
		}
		if response.Error != "" {
			return fmt.Errorf("unlock helper: %s", response.Error)
		}
		return nil
	})
}

func finalizeUnlockAuditEvent(event unlockAuditEvent, source string, reused bool) unlockAuditEvent {
	event.Timestamp = time.Now().UTC()
	event.UnlockSource = source
	event.ReusedWindow = reused
	return event
}

func appendUnlockAuditEvent(events []unlockAuditEvent, event unlockAuditEvent) []unlockAuditEvent {
	event.Timestamp = event.Timestamp.UTC()
	events = append(events, event)
	if len(events) <= unlockAuditEventLimit {
		return events
	}
	trimmed := make([]unlockAuditEvent, unlockAuditEventLimit)
	copy(trimmed, events[len(events)-unlockAuditEventLimit:])
	return trimmed
}

func cloneUnlockAuditEvents(events []unlockAuditEvent) []unlockAuditEvent {
	if len(events) == 0 {
		return nil
	}
	cloned := make([]unlockAuditEvent, len(events))
	copy(cloned, events)
	return cloned
}

func auditTargetDisplay(target string) string {
	if target == "" {
		return "-"
	}
	return target
}

func readUnlockLease(path string) (unlockLease, error) {
	// #nosec G304 -- the lease path is derived from the managed runtime directory for the selected vault.
	contents, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return unlockLease{}, errNoUnlockWindow
		}
		return unlockLease{}, err
	}
	lease := unlockLease{}
	if err := json.Unmarshal(contents, &lease); err != nil {
		return unlockLease{}, err
	}
	return lease, nil
}

func writeUnlockLease(path string, lease unlockLease) error {
	payload, err := json.MarshalIndent(lease, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	return vault.WriteFileAtomic(path, payload, 0o600)
}

func unlockLeasePath(dir string) (string, error) {
	runtimeDir, err := unlockRuntimeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(runtimeDir, vaultDirFingerprint(dir)+".json"), nil
}

func unlockRuntimeDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	path := filepath.Join(base, "env-vault", "unlock-window")
	if err := os.MkdirAll(path, 0o700); err != nil {
		return "", err
	}
	return path, nil
}

func vaultDirFingerprint(dir string) string {
	sum := sha256.Sum256([]byte(cleanedVaultDir(dir)))
	return hex.EncodeToString(sum[:16])
}

func cleanedVaultDir(dir string) string {
	cleaned := filepath.Clean(dir)
	if abs, err := filepath.Abs(cleaned); err == nil {
		cleaned = abs
	}
	if runtime.GOOS == goosWindows {
		cleaned = strings.ToLower(cleaned)
	}
	return cleaned
}

func randomUnlockToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
