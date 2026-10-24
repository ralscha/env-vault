//go:build !windows

package secretio

import "golang.org/x/sys/unix"

func duplicateFileDescriptor(fd int) (uintptr, error) {
	duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	return uintptr(duplicate), nil
}
