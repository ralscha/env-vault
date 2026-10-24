package vault

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileBackendRejectsConflictWithMatchingFileMetadata(t *testing.T) {
	ctx := context.Background()
	backend := NewFileBackend(t.TempDir())
	version, err := backend.Save(ctx, BlobVault, Blob{Data: []byte("before")}, SaveOptions{CreateOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(backend.Dir(), vaultFileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("after!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	_, err = backend.Save(ctx, BlobVault, Blob{Data: []byte("stale!")}, SaveOptions{ExpectedVersion: version})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("stale save returned %v, want ErrConflict", err)
	}
	blob, err := backend.Load(ctx, BlobVault)
	if err != nil {
		t.Fatal(err)
	}
	if string(blob.Data) != "after!" {
		t.Fatalf("stale save replaced newer data with %q", blob.Data)
	}
}

func TestFileBackendConcurrentSavesRejectStaleVersion(t *testing.T) {
	ctx := context.Background()
	backend := NewFileBackend(t.TempDir())
	version, err := backend.Save(ctx, BlobVault, Blob{Data: []byte("initial")}, SaveOptions{CreateOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, value := range []string{"first", "second"} {
		go func() {
			<-start
			_, err := backend.Save(ctx, BlobVault, Blob{Data: []byte(value)}, SaveOptions{ExpectedVersion: version})
			results <- err
		}()
	}
	close(start)
	saved, conflicts := 0, 0
	for range 2 {
		switch err := <-results; {
		case err == nil:
			saved++
		case errors.Is(err, ErrConflict):
			conflicts++
		default:
			t.Fatalf("save returned unexpected error: %v", err)
		}
	}
	if saved != 1 || conflicts != 1 {
		t.Fatalf("got %d successful saves and %d conflicts, want one of each", saved, conflicts)
	}
}
