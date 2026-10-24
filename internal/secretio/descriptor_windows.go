//go:build windows

package secretio

import (
	"os"

	"golang.org/x/sys/windows"
)

func duplicateFileDescriptor(fd int) (uintptr, error) {
	source := uintptr(fd)
	switch fd {
	case 0:
		source = os.Stdin.Fd()
	case 1:
		source = os.Stdout.Fd()
	case 2:
		source = os.Stderr.Fd()
	}
	var duplicate windows.Handle
	process := windows.CurrentProcess()
	if err := windows.DuplicateHandle(process, windows.Handle(source), process, &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return 0, err
	}
	return uintptr(duplicate), nil
}
