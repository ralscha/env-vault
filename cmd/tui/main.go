package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"env-vault/internal/tui"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("env-vault-tui", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", tui.DefaultVaultDir(), "vault directory")
	unlock := tui.AddUnlockFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("env-vault-tui does not accept positional arguments")
	}
	if err := unlock.Validate(); err != nil {
		return err
	}

	opened, err := tui.OpenStore(*dir, *unlock)
	if err != nil {
		return err
	}
	defer opened.Close()

	model, err := tui.NewModel(opened, *dir)
	if err != nil {
		return err
	}

	program := tea.NewProgram(model, tea.WithAltScreen())
	_, err = program.Run()
	return err
}
