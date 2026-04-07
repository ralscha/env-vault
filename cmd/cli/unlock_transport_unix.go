//go:build !windows

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

func listenUnlockTransport(runtimeDir, fingerprint, token string) (unlockTransport, net.Listener, func() error, error) {
	endpoint := filepath.Join(runtimeDir, fmt.Sprintf("%s-%s.sock", fingerprint, token[:8]))
	if err := os.Remove(endpoint); err != nil && !errors.Is(err, os.ErrNotExist) {
		return unlockTransport{}, nil, nil, err
	}
	listener, err := net.Listen("unix", endpoint)
	if err != nil {
		return unlockTransport{}, nil, nil, err
	}
	if err := os.Chmod(endpoint, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(endpoint)
		return unlockTransport{}, nil, nil, err
	}
	cleanup := func() error {
		if err := os.Remove(endpoint); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return unlockTransport{Network: "unix", Endpoint: endpoint}, listener, cleanup, nil
}

func dialUnlockTransport(lease unlockLease, timeout time.Duration) (net.Conn, error) {
	if lease.Network != "unix" {
		return nil, fmt.Errorf("unsupported unlock transport %q", lease.Network)
	}
	return net.DialTimeout("unix", lease.Endpoint, timeout)
}
