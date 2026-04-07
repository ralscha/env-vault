package vault

import (
	"context"
	"errors"
)

var ErrConflict = errors.New("backend version conflict")

type BlobKind string

const (
	BlobIdentity BlobKind = "identity"
	BlobVault    BlobKind = "vault"
)

type Blob struct {
	Data    []byte
	Version string
}

type SaveOptions struct {
	CreateOnly      bool
	ExpectedVersion string
}

type BlobBackend interface {
	Init(ctx context.Context) error
	Stat(ctx context.Context, kind BlobKind) (exists bool, version string, err error)
	Load(ctx context.Context, kind BlobKind) (Blob, error)
	Save(ctx context.Context, kind BlobKind, blob Blob, opts SaveOptions) (string, error)
}
