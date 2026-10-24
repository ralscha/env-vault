// Package secretio provides helpers for reading secrets from caller-owned files.
package secretio

import (
	"fmt"
	"os"
)

// DuplicateFD returns an independently owned, non-inheritable copy of fd.
// The caller must close the returned file. Descriptors 0, 1 and 2 refer to the
// standard streams; other descriptors on Windows are native file handles.
func DuplicateFD(fd int) (*os.File, error) {
	if fd < 0 {
		return nil, fmt.Errorf("invalid file descriptor %d", fd)
	}
	duplicate, err := duplicateFileDescriptor(fd)
	if err != nil {
		return nil, fmt.Errorf("duplicate file descriptor %d: %w", fd, err)
	}
	return os.NewFile(duplicate, fmt.Sprintf("fd-%d", fd)), nil
}
