package tui

import (
	"os"
	"runtime"
	"testing"

	"env-vault/internal/vault"
)

func TestPasswordFDRemainsOpen(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "password")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if _, err := file.WriteString("test password\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	fd, err := intFromUintptr(file.Fd())
	if err != nil {
		t.Fatal(err)
	}
	password, err := readNonInteractiveMasterPassword(UnlockOptions{PasswordFDSet: true, PasswordFD: fd})
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(password)
	if string(password) != "test password" {
		t.Fatal("password was not read correctly")
	}
	runtime.GC()
	if _, err := file.Stat(); err != nil {
		t.Fatalf("reading password closed caller-owned descriptor: %v", err)
	}
}
