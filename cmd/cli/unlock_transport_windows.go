//go:build windows

package main

import (
	"fmt"
	"net"
	"time"

	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func listenUnlockTransport(_ string, fingerprint, token string) (unlockTransport, net.Listener, func() error, error) {
	endpoint := fmt.Sprintf(`\\.\pipe\env-vault-%s-%s`, fingerprint, token[:8])
	descriptor, err := currentUserPipeSecurityDescriptor()
	if err != nil {
		return unlockTransport{}, nil, nil, err
	}
	listener, err := winio.ListenPipe(endpoint, &winio.PipeConfig{
		SecurityDescriptor: descriptor,
		InputBufferSize:    4096,
		OutputBufferSize:   4096,
		MessageMode:        true,
	})
	if err != nil {
		return unlockTransport{}, nil, nil, err
	}
	cleanup := func() error {
		return nil
	}
	return unlockTransport{Network: "npipe", Endpoint: endpoint}, listener, cleanup, nil
}

func currentUserPipeSecurityDescriptor() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	sid := user.User.Sid.String()
	return fmt.Sprintf("D:P(A;;GA;;;SY)(A;;GA;;;%s)", sid), nil
}

func dialUnlockTransport(lease unlockLease, timeout time.Duration) (net.Conn, error) {
	if lease.Network != "npipe" {
		return nil, fmt.Errorf("unsupported unlock transport %q", lease.Network)
	}
	return winio.DialPipe(lease.Endpoint, &timeout)
}
