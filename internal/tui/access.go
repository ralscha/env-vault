package tui

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"env-vault/internal/vault"

	"github.com/awnumar/memguard"
	"golang.org/x/term"
)

type UnlockOptions struct {
	PasswordStdin bool
	PasswordFile  string
	PasswordFD    int
	PasswordFDSet bool
}

const maxIntValue = int(^uint(0) >> 1)

func (o UnlockOptions) Validate() error {
	selected := 0
	if o.PasswordStdin {
		selected++
	}
	if o.PasswordFile != "" {
		selected++
	}
	if o.PasswordFDSet {
		selected++
	}
	if selected > 1 {
		return fmt.Errorf("choose only one of --password-stdin, --password-file, or --password-fd")
	}
	if o.PasswordFDSet && o.PasswordFD < 0 {
		return fmt.Errorf("--password-fd must be a non-negative file descriptor")
	}
	return nil
}

func OpenStore(dir string, unlock UnlockOptions) (*vault.Opened, error) {
	password, err := readMasterPassword(unlock)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(password)

	store := vault.NewStore(dir)
	return store.Open(password)
}

func DefaultVaultDir() string {
	if fromEnv := os.Getenv("ENV_VAULT_DIR"); fromEnv != "" {
		return fromEnv
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".env-vault"
	}
	return filepath.Join(home, ".env-vault")
}

func AddUnlockFlags(fs interface {
	BoolVar(p *bool, name string, value bool, usage string)
	StringVar(p *string, name string, value string, usage string)
	Func(name, usage string, fn func(string) error)
}) *UnlockOptions {
	options := &UnlockOptions{PasswordFD: -1}
	fs.BoolVar(&options.PasswordStdin, "password-stdin", false, "read the master password from standard input")
	fs.StringVar(&options.PasswordFile, "password-file", "", "read the master password from a file")
	fs.Func("password-fd", "read the master password from an already-open file descriptor", func(value string) error {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("parse --password-fd: %w", err)
		}
		options.PasswordFD = parsed
		options.PasswordFDSet = true
		return nil
	})
	return options
}

func readMasterPassword(unlock UnlockOptions) ([]byte, error) {
	if unlock.PasswordStdin || unlock.PasswordFile != "" || unlock.PasswordFDSet {
		return readNonInteractiveMasterPassword(unlock)
	}

	if _, err := fmt.Fprint(os.Stderr, "Master password: "); err != nil {
		return nil, err
	}
	stdinFD, err := intFromUintptr(os.Stdin.Fd())
	if err != nil {
		return nil, err
	}
	password, err := term.ReadPassword(stdinFD)
	if _, writeErr := fmt.Fprintln(os.Stderr); writeErr != nil && err == nil {
		err = writeErr
	}
	if err != nil {
		return nil, err
	}
	password = bytes.TrimRight(password, "\r\n")
	if len(password) == 0 {
		return nil, fmt.Errorf("empty input is not allowed")
	}
	return append([]byte(nil), password...), nil
}

func readNonInteractiveMasterPassword(unlock UnlockOptions) ([]byte, error) {
	switch {
	case unlock.PasswordStdin:
		return readSecretFromReader(os.Stdin, "master password from stdin")
	case unlock.PasswordFile != "":
		contents, err := os.ReadFile(unlock.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("read master password file: %w", err)
		}
		defer vault.Wipe(contents)
		secret := append([]byte(nil), bytes.TrimRight(contents, "\r\n")...)
		if len(secret) == 0 {
			return nil, fmt.Errorf("empty input is not allowed")
		}
		return secret, nil
	case unlock.PasswordFDSet:
		passwordFD, err := uintptrFromInt(unlock.PasswordFD)
		if err != nil {
			return nil, err
		}
		file := os.NewFile(passwordFD, fmt.Sprintf("fd-%d", unlock.PasswordFD))
		if file == nil {
			return nil, fmt.Errorf("open --password-fd %d", unlock.PasswordFD)
		}
		return readSecretFromReader(file, fmt.Sprintf("master password from fd %d", unlock.PasswordFD))
	default:
		return nil, fmt.Errorf("internal error: no non-interactive unlock source selected")
	}
}

func readSecretFromReader(reader io.Reader, source string) ([]byte, error) {
	buffer, err := memguard.NewBufferFromEntireReader(reader)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", source, err)
	}
	defer buffer.Destroy()

	secret := append([]byte(nil), bytes.TrimRight(buffer.Bytes(), "\r\n")...)
	if len(secret) == 0 {
		return nil, fmt.Errorf("empty input is not allowed")
	}
	return secret, nil
}

func intFromUintptr(value uintptr) (int, error) {
	if value > uintptr(maxIntValue) {
		return 0, fmt.Errorf("file descriptor %d exceeds platform int size", value)
	}
	return int(value), nil
}

func uintptrFromInt(value int) (uintptr, error) {
	if value < 0 {
		return 0, fmt.Errorf("file descriptor must be non-negative")
	}
	return uintptr(value), nil
}
