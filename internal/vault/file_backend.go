package vault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type FileBackend struct {
	dir string
}

func NewFileBackend(dir string) *FileBackend {
	return &FileBackend{dir: dir}
}

func (b *FileBackend) Dir() string {
	return b.dir
}

func (b *FileBackend) Init(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.MkdirAll(b.dir, 0o700)
}

func (b *FileBackend) Stat(ctx context.Context, kind BlobKind) (bool, string, error) {
	if err := ctx.Err(); err != nil {
		return false, "", err
	}

	path, err := b.pathFor(kind)
	if err != nil {
		return false, "", err
	}

	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}

	return true, fileVersion(info), nil
}

func (b *FileBackend) Load(ctx context.Context, kind BlobKind) (Blob, error) {
	if err := ctx.Err(); err != nil {
		return Blob{}, err
	}

	path, err := b.pathFor(kind)
	if err != nil {
		return Blob{}, err
	}

	// #nosec G304 -- backend paths are derived from the configured vault directory and blob kind.
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Blob{}, ErrNotInitialized
		}
		return Blob{}, err
	}

	info, err := os.Stat(path)
	if err != nil {
		Wipe(data)
		return Blob{}, err
	}

	return Blob{Data: data, Version: fileVersion(info)}, nil
}

func (b *FileBackend) Save(ctx context.Context, kind BlobKind, blob Blob, opts SaveOptions) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	path, err := b.pathFor(kind)
	if err != nil {
		return "", err
	}

	exists, currentVersion, err := b.Stat(ctx, kind)
	if err != nil {
		return "", err
	}
	if opts.CreateOnly && exists {
		return "", ErrAlreadyInitialized
	}
	if opts.ExpectedVersion != "" {
		if !exists || opts.ExpectedVersion != currentVersion {
			return "", ErrConflict
		}
	}

	if err := WriteFileAtomic(path, blob.Data, 0o600); err != nil {
		return "", err
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	return fileVersion(info), nil
}

func (b *FileBackend) pathFor(kind BlobKind) (string, error) {
	switch kind {
	case BlobIdentity:
		return filepath.Join(b.dir, identityFileName), nil
	case BlobVault:
		return filepath.Join(b.dir, vaultFileName), nil
	default:
		return "", fmt.Errorf("unsupported blob kind %q", kind)
	}
}

func fileVersion(info os.FileInfo) string {
	return fmt.Sprintf("%d-%d", info.ModTime().UnixNano(), info.Size())
}

func WriteFileAtomic(path string, contents []byte, perm os.FileMode) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if cleanupErr := os.Remove(tmpName); cleanupErr != nil && !errors.Is(cleanupErr, os.ErrNotExist) && err == nil {
			err = cleanupErr
		}
	}()

	closeTemp := func(writeErr error) error {
		if err := tmp.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			return errors.Join(writeErr, err)
		}
		return writeErr
	}

	if _, err := tmp.Write(contents); err != nil {
		return closeTemp(err)
	}
	if err := tmp.Chmod(perm); err != nil {
		return closeTemp(err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
