package secretio

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestDuplicateFDLeavesOriginalOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("test password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- path is a test fixture inside t.TempDir().
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	duplicate, err := DuplicateFD(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = duplicate.Close() }()
	contents, err := io.ReadAll(duplicate)
	if err != nil || string(contents) != "test password\n" {
		t.Fatalf("read duplicate: %q, %v", contents, err)
	}
	if err := duplicate.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("closing the duplicate closed the caller's descriptor: %v", err)
	}
	contents, err = io.ReadAll(file)
	if err != nil || string(contents) != "test password\n" {
		t.Fatalf("read original after closing duplicate: %q, %v", contents, err)
	}
}

func TestDuplicateFDRejectsNegativeDescriptor(t *testing.T) {
	if file, err := DuplicateFD(-1); err == nil || file != nil {
		t.Fatalf("DuplicateFD(-1) = %v, %v, want an error", file, err)
	}
}
