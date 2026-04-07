package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"env-vault/internal/vault"

	"github.com/awnumar/memguard"
	"golang.org/x/term"
)

const defaultScryptWorkFactor = 18

const (
	envVaultActiveVar  = "ENV_VAULT"
	envVaultProfileVar = "ENV_VAULT_PROFILE"
	envVaultShellVar   = "ENV_VAULT_SHELL"
	commandHelp        = "help"
	commandCompletion  = "completion"
	commandEdit        = "edit"
	commandInit        = "init"
	commandUnlock      = "unlock"
	commandShow        = "show"
	commandLink        = "link"
	commandList        = "list"
	commandSet         = "set"
	commandRename      = "rename"
	commandCopy        = "copy"
	commandExport      = "export"
	commandUnlink      = "unlink"
	commandUnset       = "unset"
	commandRemove      = "remove"
	commandExec        = "exec"
	commandShell       = "shell"
	commandInfo        = "info"
	exportFormatJSON   = "json"
	goosWindows        = "windows"
)

var errOperationCanceled = errors.New("operation canceled")

type unlockOptions struct {
	passwordStdin bool
	passwordFile  string
	passwordFD    int
	passwordFDSet bool
	unlockWindow  time.Duration
}

type unlockAuditEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	PID          int       `json:"pid"`
	Command      string    `json:"command"`
	Target       string    `json:"target,omitempty"`
	UnlockSource string    `json:"unlock_source"`
	ReusedWindow bool      `json:"reused_window"`
}

type environ []string

func main() {
	memguard.CatchInterrupt()
	os.Exit(runMain(os.Args[1:]))
}

func runMain(args []string) int {
	defer memguard.Purge()

	if err := run(args); err != nil {
		if writeErr := writeLine(os.Stderr, "Error:", err); writeErr != nil {
			return 1
		}
		return 1
	}

	return 0
}

func run(args []string) error {
	if len(args) == 0 {
		return printUsage(os.Stderr)
	}
	if args[0] == unlockHelperCommand {
		return runUnlockHelper(args[1:])
	}

	command, ok := canonicalCommand(args[0])
	if !ok {
		if err := printUsage(os.Stderr); err != nil {
			return err
		}
		return fmt.Errorf("unknown command %q", args[0])
	}

	switch command {
	case commandHelp:
		return printUsage(os.Stdout)
	case commandCompletion:
		return runCompletion(args[1:])
	case commandEdit:
		return runEdit(args[1:])
	case commandInit:
		return runInit(args[1:])
	case commandUnlock:
		return runUnlock(args[1:])
	case commandShow:
		return runShow(args[1:])
	case commandLink:
		return runLink(args[1:])
	case commandList:
		return runList(args[1:])
	case commandSet:
		return runSet(args[1:])
	case commandRename:
		return runRename(args[1:])
	case commandCopy:
		return runCopy(args[1:])
	case commandExport:
		return runExport(args[1:])
	case commandUnlink:
		return runUnlink(args[1:])
	case commandUnset:
		return runUnset(args[1:])
	case commandRemove:
		return runRemove(args[1:])
	case commandExec:
		return runExec(args[1:])
	case commandShell:
		return runShell(args[1:])
	case commandInfo:
		return runInfo(args[1:])
	}

	if err := printUsage(os.Stderr); err != nil {
		return err
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func printUsage(w io.Writer) error {
	return writeText(w, `env-vault stores named sets of environment variables in a local encrypted vault.

usage: env-vault [shared flags] <command> [<args> ...]

Minimal local secret vault for grouped application environment variables.

Shared flags:
	--dir PATH
	  Vault directory.
	--password-stdin
	  Read the master password from standard input.
	--password-file PATH
	  Read the master password from a file.
	--password-fd N
	  Read the master password from an open file descriptor.
	--unlock-window DURATION
	  Start or extend a short-lived unlock helper for later automatic reuse.

Argument names:
	NAME
	  An app or group name, depending on the command.
	NAME[,NAME...]
	  A comma-separated selection of app and/or group names.
	APP
	  An app name.
	GROUP
	  A group name.
	KEY
	  An environment variable key inside an app or group.

Commands:
	help
	  Show help.
	completion <shell>
	  Print shell completion for bash, zsh, fish, or powershell.
	init [--dir PATH] [--work-factor N] [--password-stdin|--password-file PATH|--password-fd N]
	  Initialize a new vault.
	info [--dir PATH]
	  Show the vault and identity file locations.
	unlock [--dir PATH] status|clear
	  Inspect or clear the local unlock helper.
	edit [shared flags] [--editor PATH] NAME
	  Edit direct key/value pairs in your editor.
	list [shared flags] [--json] [NAME[,NAME...]]
	  List entities or keys for a resolved selection.
	show [shared flags] [--resolved] [--json] [app|group] NAME[,NAME...]
	  Show one entity or a resolved selection.
	set [shared flags] [--stdin|--interactive] [--app|--group] NAME [KEY [VALUE]]
	  Set one key or start an interactive edit session.
	link [shared flags] APP GROUP
	  Link a group to an app.
	rename [shared flags] OLD_NAME NEW_NAME
	  Rename a group or app.
	copy [shared flags] SOURCE_NAME DEST_NAME
	  Copy a group or app.
	export [shared flags] [--format env|export-env|json|dotenv] [--metadata] [--output FILE] [--force-stdout] NAME[,NAME...]
	  Export plaintext secrets.
	unlink [shared flags] APP GROUP
	  Remove a group link from an app.
	unset [shared flags] [--force] NAME KEY
	  Remove a direct key from an app or group.
	remove [shared flags] [--force] NAME
	  Remove a group or app.
	exec [shared flags] NAME[,NAME...] -- COMMAND [ARGS...]
	  Run a command with injected secrets.
	shell [shared flags] [--shell PATH] [--allow-nested] NAME[,NAME...] [-- SHELL_ARGS...]
	  Start a subshell with injected secrets.

Notes:
	- The master password protects a local encrypted age identity file.
	- The vault data itself is encrypted with age post-quantum hybrid recipients.
	- Groups and apps share one global entity-name namespace.
	- Selection arguments can mix apps and groups as comma-separated names.
	- Later selector entries override earlier selector entries.
	- Within an app, direct app env vars override linked group values.
	- list --json emits machine-friendly inventory or selection data.
	- show --json emits machine-friendly metadata instead of text.
	- export --format json --metadata wraps one app or group with metadata plus direct and resolved env maps.
	- set without VALUE prompts for a hidden value.
	- set --interactive prompts for multiple keys in one session.
	- set --stdin reads the value from standard input.
	- unset and remove prompt for confirmation unless --force is used.
		- shell marks the child shell session and refuses nested env-vault shells by default.
		- active unlock helpers are reused automatically; --unlock-window is only needed to start or extend one.
`)
}

func writeText(w io.Writer, text string) error {
	_, err := fmt.Fprint(w, text)
	return err
}

func writeTextf(w io.Writer, format string, args ...any) error {
	_, err := fmt.Fprintf(w, format, args...)
	return err
}

func writeLine(w io.Writer, args ...any) error {
	_, err := fmt.Fprintln(w, args...)
	return err
}

func canonicalCommand(name string) (string, bool) {
	switch name {
	case commandHelp, "-h", "--help":
		return commandHelp, true
	case commandCompletion:
		return commandCompletion, true
	case commandEdit:
		return commandEdit, true
	case commandInit:
		return commandInit, true
	case commandUnlock:
		return commandUnlock, true
	case commandLink:
		return commandLink, true
	case commandList, "ls":
		return commandList, true
	case commandShow, "inspect":
		return commandShow, true
	case commandSet:
		return commandSet, true
	case commandRename:
		return commandRename, true
	case commandCopy:
		return commandCopy, true
	case commandExport:
		return commandExport, true
	case commandUnlink:
		return commandUnlink, true
	case commandUnset:
		return commandUnset, true
	case commandRemove, "rm":
		return commandRemove, true
	case commandExec:
		return commandExec, true
	case commandShell:
		return commandShell, true
	case commandInfo:
		return commandInfo, true
	default:
		return "", false
	}
}

func runCompletion(args []string) error {
	fs := flag.NewFlagSet("completion", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: env-vault completion bash|zsh|fish|powershell")
	}

	script, err := renderCompletion(fs.Arg(0))
	if err != nil {
		return err
	}
	return writeText(os.Stdout, script)
}

func renderCompletion(shell string) (string, error) {
	commands := completionCommands()
	subcommands := completionSubcommands()
	flags := completionFlags()
	switch strings.ToLower(shell) {
	case "bash":
		return renderBashCompletion(commands, subcommands, flags), nil
	case "zsh":
		return renderZshCompletion(commands, subcommands, flags), nil
	case "fish":
		return renderFishCompletion(commands, subcommands, flags), nil
	case "powershell", "pwsh":
		return renderPowerShellCompletion(commands, subcommands, flags), nil
	default:
		return "", fmt.Errorf("unsupported shell %q", shell)
	}
}

func completionCommands() []string {
	return []string{
		"help",
		"completion",
		"edit",
		"init",
		"info",
		"unlock",
		"list",
		"ls",
		"show",
		"inspect",
		"set",
		"link",
		"rename",
		"copy",
		"export",
		"unlink",
		"unset",
		"remove",
		"rm",
		"exec",
		"shell",
	}
}

func completionSubcommands() map[string][]string {
	return map[string][]string{
		"completion": {"bash", "zsh", "fish", "powershell"},
		"unlock":     {"status", "clear"},
		"show":       {"app", "group"},
		"inspect":    {"app", "group"},
	}
}

func completionFlags() map[string][]string {
	unlockFlags := []string{"--dir", "--password-stdin", "--password-file", "--password-fd", "--unlock-window"}
	listFlags := append(append([]string{}, unlockFlags...), "--json")
	showFlags := append(append([]string{}, unlockFlags...), "--resolved", "--json")
	setFlags := append(append([]string{}, unlockFlags...), "--stdin", "--interactive", "--app", "--group")
	exportFlags := append(append([]string{}, unlockFlags...), "--format", "--metadata", "--output", "--force-stdout")
	removeFlags := append(append([]string{}, unlockFlags...), "--force")
	shellFlags := append(append([]string{}, unlockFlags...), "--shell", "--allow-nested")
	return map[string][]string{
		"init":       {"--dir", "--work-factor", "--password-stdin", "--password-file", "--password-fd"},
		"info":       {"--dir"},
		"unlock":     {"--dir"},
		"list":       listFlags,
		"ls":         listFlags,
		"edit":       append(append([]string{}, unlockFlags...), "--editor"),
		"show":       showFlags,
		"inspect":    showFlags,
		"set":        setFlags,
		"link":       unlockFlags,
		"rename":     unlockFlags,
		"copy":       unlockFlags,
		"export":     exportFlags,
		"unlink":     unlockFlags,
		"unset":      removeFlags,
		"remove":     removeFlags,
		"rm":         removeFlags,
		"exec":       unlockFlags,
		"shell":      shellFlags,
		"completion": nil,
	}
}

func renderBashCompletion(commands []string, subcommands map[string][]string, flags map[string][]string) string {
	var builder strings.Builder
	builder.WriteString("_env_vault_completion() {\n")
	builder.WriteString("  local cur prev words cword\n")
	builder.WriteString("  _init_completion -n : || return\n")
	builder.WriteString("  local commands=\"")
	builder.WriteString(strings.Join(commands, " "))
	builder.WriteString("\"\n")
	builder.WriteString("  if [[ $cword -eq 1 ]]; then\n")
	builder.WriteString("    COMPREPLY=( $(compgen -W \"$commands\" -- \"$cur\") )\n")
	builder.WriteString("    return\n")
	builder.WriteString("  fi\n")
	builder.WriteString("  case \"${words[1]}\" in\n")
	for _, command := range commands {
		options := append([]string{}, flags[command]...)
		options = append(options, subcommands[command]...)
		builder.WriteString("    ")
		builder.WriteString(command)
		builder.WriteString(")\n")
		builder.WriteString("      COMPREPLY=( $(compgen -W \"")
		builder.WriteString(strings.Join(options, " "))
		builder.WriteString("\" -- \"$cur\") )\n")
		builder.WriteString("      return\n")
		builder.WriteString("      ;;\n")
	}
	builder.WriteString("  esac\n")
	builder.WriteString("}\n")
	builder.WriteString("complete -F _env_vault_completion env-vault\n")
	return builder.String()
}

func renderZshCompletion(commands []string, subcommands map[string][]string, flags map[string][]string) string {
	var builder strings.Builder
	builder.WriteString("#compdef env-vault\n\n")
	builder.WriteString("_env_vault() {\n")
	builder.WriteString("  local -a commands\n")
	builder.WriteString("  commands=(")
	for _, command := range commands {
		builder.WriteString("\"")
		builder.WriteString(command)
		builder.WriteString("\" ")
	}
	builder.WriteString(")\n")
	builder.WriteString("  if (( CURRENT == 2 )); then\n")
	builder.WriteString("    _describe 'command' commands\n")
	builder.WriteString("    return\n")
	builder.WriteString("  fi\n")
	builder.WriteString("  case $words[2] in\n")
	for _, command := range commands {
		builder.WriteString("    ")
		builder.WriteString(command)
		builder.WriteString(")\n")
		options := append([]string{}, flags[command]...)
		options = append(options, subcommands[command]...)
		if len(options) == 0 {
			builder.WriteString("      _message 'no further completions'\n")
		} else {
			builder.WriteString("      _values 'arguments' ")
			for _, option := range options {
				builder.WriteString("\"")
				builder.WriteString(option)
				builder.WriteString("\" ")
			}
			builder.WriteString("\n")
		}
		builder.WriteString("      ;;\n")
	}
	builder.WriteString("  esac\n")
	builder.WriteString("}\n\n")
	builder.WriteString("_env_vault \"$@\"\n")
	return builder.String()
}

func renderFishCompletion(commands []string, subcommands map[string][]string, flags map[string][]string) string {
	var builder strings.Builder
	builder.WriteString("complete -c env-vault -f\n")
	for _, command := range commands {
		builder.WriteString("complete -c env-vault -n '__fish_use_subcommand' -a '")
		builder.WriteString(command)
		builder.WriteString("'\n")
	}
	for command, options := range flags {
		for _, option := range options {
			builder.WriteString("complete -c env-vault -n '__fish_seen_subcommand_from ")
			builder.WriteString(command)
			builder.WriteString("' -l ")
			builder.WriteString(strings.TrimPrefix(option, "--"))
			builder.WriteString("\n")
		}
	}
	for command, values := range subcommands {
		for _, value := range values {
			builder.WriteString("complete -c env-vault -n '__fish_seen_subcommand_from ")
			builder.WriteString(command)
			builder.WriteString("' -a '")
			builder.WriteString(value)
			builder.WriteString("'\n")
		}
	}
	return builder.String()
}

func renderPowerShellCompletion(commands []string, subcommands map[string][]string, flags map[string][]string) string {
	var builder strings.Builder
	builder.WriteString("Register-ArgumentCompleter -Native -CommandName env-vault -ScriptBlock {\n")
	builder.WriteString("  param($wordToComplete, $commandAst, $cursorPosition)\n")
	builder.WriteString("  $tokens = $commandAst.CommandElements | ForEach-Object { $_.Extent.Text }\n")
	builder.WriteString("  $commands = @(")
	for index, command := range commands {
		if index > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString("'")
		builder.WriteString(command)
		builder.WriteString("'")
	}
	builder.WriteString(")\n")
	builder.WriteString("  if ($tokens.Count -le 1) {\n")
	builder.WriteString("    $commands | Where-Object { $_ -like \"$wordToComplete*\" } | ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }\n")
	builder.WriteString("    return\n")
	builder.WriteString("  }\n")
	builder.WriteString("  switch ($tokens[1]) {\n")
	for _, command := range commands {
		values := append([]string{}, flags[command]...)
		values = append(values, subcommands[command]...)
		builder.WriteString("    '")
		builder.WriteString(command)
		builder.WriteString("' {\n")
		builder.WriteString("      @(")
		for index, value := range values {
			if index > 0 {
				builder.WriteString(", ")
			}
			builder.WriteString("'")
			builder.WriteString(value)
			builder.WriteString("'")
		}
		builder.WriteString(") | Where-Object { $_ -like \"$wordToComplete*\" } | ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }\n")
		builder.WriteString("      break\n")
		builder.WriteString("    }\n")
	}
	builder.WriteString("  }\n")
	builder.WriteString("}\n")
	return builder.String()
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", defaultVaultDir(), "vault directory")
	workFactor := fs.Int("work-factor", defaultScryptWorkFactor, "age scrypt work factor")
	unlock := addUnlockFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := unlock.Validate(); err != nil {
		return err
	}
	if unlock.unlockWindow > 0 {
		return fmt.Errorf("init does not support --unlock-window")
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("init does not accept positional arguments")
	}

	return withConfirmedMasterPassword(*unlock, func(password []byte) error {
		store := vault.NewStore(*dir)
		_, err := store.Init(password, *workFactor)
		if err != nil {
			return err
		}

		if err := writeTextf(os.Stdout, "Initialized vault at %s\n", store.Dir()); err != nil {
			return err
		}
		return nil
	})
}

func runInfo(args []string) error {
	fs := flag.NewFlagSet("info", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", defaultVaultDir(), "vault directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("info does not accept positional arguments")
	}

	if err := writeTextf(os.Stdout, "Vault directory: %s\n", *dir); err != nil {
		return err
	}
	if err := writeTextf(os.Stdout, "Identity file: %s\n", filepath.Join(*dir, "identity.age")); err != nil {
		return err
	}
	if err := writeTextf(os.Stdout, "Vault file: %s\n", filepath.Join(*dir, "vault.age")); err != nil {
		return err
	}
	return nil
}

func runList(args []string) error {
	args, jsonOutput := extractBoolFlag(args, "--json")
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", defaultVaultDir(), "vault directory")
	unlock := addUnlockFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := unlock.Validate(); err != nil {
		return err
	}

	target := ""
	if fs.NArg() == 1 {
		target = fs.Arg(0)
	}
	return withOpenedStore(*dir, *unlock, newUnlockAuditEvent("list", target), func(opened *vault.Opened) error {
		entries, err := buildListInventory(opened)
		if err != nil {
			return err
		}
		if jsonOutput {
			if fs.NArg() == 0 {
				payload, err := renderListInventoryJSON(entries)
				if err != nil {
					return err
				}
				return writeText(os.Stdout, string(payload))
			}
			if fs.NArg() > 1 {
				return fmt.Errorf("list accepts at most one selection")
			}
			payload, err := renderListSelectionJSON(opened, fs.Arg(0))
			if err != nil {
				return err
			}
			return writeText(os.Stdout, string(payload))
		}
		if fs.NArg() == 0 {
			for _, entry := range entries {
				line := formatListEntityLine(entry)
				if err := writeLine(os.Stdout, line); err != nil {
					return err
				}
			}
			return nil
		}
		if fs.NArg() > 1 {
			return fmt.Errorf("list accepts at most one selection")
		}

		profile, err := opened.ResolveSelection(fs.Arg(0))
		if err != nil {
			return err
		}
		defer opened.WipeProfile(profile)

		keys := profile.Keys()
		for _, key := range keys {
			if err := writeLine(os.Stdout, key); err != nil {
				return err
			}
		}
		return nil
	})
}

func runSet(args []string) error {
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", defaultVaultDir(), "vault directory")
	unlock := addUnlockFlags(fs)
	readFromStdin := fs.Bool("stdin", false, "read value from standard input")
	interactive := fs.Bool("interactive", false, "prompt for multiple key/value pairs")
	asApp := fs.Bool("app", false, "set a direct app env var")
	asGroup := fs.Bool("group", false, "set a group env var")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := unlock.Validate(); err != nil {
		return err
	}
	if *readFromStdin && *interactive {
		return fmt.Errorf("--stdin and --interactive cannot be used together")
	}
	if *readFromStdin && unlock.passwordStdin {
		return fmt.Errorf("--stdin and --password-stdin cannot be used together")
	}
	if *interactive {
		if fs.NArg() != 1 {
			return fmt.Errorf("usage: env-vault set [--dir PATH] [--interactive] [--app|--group] NAME")
		}
	} else if fs.NArg() < 2 || fs.NArg() > 3 {
		return fmt.Errorf("usage: env-vault set [--dir PATH] [--stdin|--interactive] [--app|--group] NAME [KEY [VALUE]]")
	}

	name := fs.Arg(0)
	targetKind, err := requestedEntityKind(*asApp, *asGroup)
	if err != nil {
		return err
	}

	auditTarget := name
	if !*interactive {
		auditTarget = fmt.Sprintf("%s:%s", name, fs.Arg(1))
	}
	return withOpenedStore(*dir, *unlock, newUnlockAuditEvent("set", auditTarget), func(opened *vault.Opened) error {
		resolvedKind, err := resolveSetKind(opened, name, targetKind)
		if err != nil {
			return err
		}
		if *interactive {
			storedCount, err := runInteractiveSet(opened, name, resolvedKind)
			if err != nil {
				return err
			}
			if err := opened.Save(); err != nil {
				return err
			}

			if err := writeTextf(os.Stdout, "Stored %d key(s) in %s %s\n", storedCount, resolvedKind, name); err != nil {
				return err
			}
			return nil
		}

		key := fs.Arg(1)
		value, err := secretValueInput(*readFromStdin, fs.Args()[2:])
		if err != nil {
			return err
		}
		defer vault.Wipe(value)
		switch resolvedKind {
		case vault.EntityKindGroup:
			err = opened.SetGroup(name, key, value)
		case vault.EntityKindApp:
			err = opened.SetApp(name, key, value)
		case vault.EntityKindUnknown:
			return fmt.Errorf("internal error: unsupported entity kind %q", resolvedKind)
		default:
			return fmt.Errorf("internal error: unsupported entity kind %q", resolvedKind)
		}
		if err != nil {
			return err
		}
		if err := opened.Save(); err != nil {
			return err
		}

		if err := writeTextf(os.Stdout, "Stored %s in %s %s\n", key, resolvedKind, name); err != nil {
			return err
		}
		return nil
	})
}

func runEdit(args []string) error {
	fs := flag.NewFlagSet("edit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", defaultVaultDir(), "vault directory")
	unlock := addUnlockFlags(fs)
	editorPath := fs.String("editor", "", "editor executable path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := unlock.Validate(); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: env-vault edit [--dir PATH] [--editor PATH] NAME")
	}

	name := fs.Arg(0)
	return withOpenedStore(*dir, *unlock, newUnlockAuditEvent("edit", name), func(opened *vault.Opened) error {
		kind := opened.Kind(name)
		if kind == vault.EntityKindUnknown {
			return vault.ErrNameNotFound
		}
		directKeys, err := directKeyValues(opened, name, kind)
		if err != nil {
			return err
		}
		warning := "Warning: edit writes plaintext direct key values to a temporary file while the editor is open."
		if err := writeLine(os.Stderr, warning); err != nil {
			return err
		}
		edited, changed, err := editEntityInEditor(name, kind, directKeys, *editorPath)
		if err != nil {
			return err
		}
		if !changed {
			return writeTextf(os.Stdout, "No changes for %s %s\n", kind, name)
		}
		if err := applyEditedEntity(opened, name, kind, edited); err != nil {
			return err
		}
		if err := opened.Save(); err != nil {
			return err
		}
		return writeTextf(os.Stdout, "Updated %s %s\n", kind, name)
	})
}

func runShow(args []string) error {
	args, resolved := extractBoolFlag(args, "--resolved")
	args, jsonOutput := extractBoolFlag(args, "--json")
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", defaultVaultDir(), "vault directory")
	unlock := addUnlockFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := unlock.Validate(); err != nil {
		return err
	}
	explicitKind, target, err := parseShowTarget(fs.Args())
	if err != nil {
		return err
	}

	return withOpenedStore(*dir, *unlock, newUnlockAuditEvent("show", target), func(opened *vault.Opened) error {
		if explicitKind != vault.EntityKindUnknown {
			if actualKind := opened.Kind(target); actualKind == vault.EntityKindUnknown {
				return vault.ErrNameNotFound
			} else if actualKind != explicitKind {
				return fmt.Errorf("name %s is a %s, not a %s", target, actualKind, explicitKind)
			}
		}

		if !resolved {
			if strings.Contains(target, ",") {
				return fmt.Errorf("showing a mixed selection requires --resolved")
			}
			if jsonOutput {
				return printEntityShowJSON(opened, target)
			}
			return printEntityShow(opened, target)
		}
		if jsonOutput {
			return printResolvedShowJSON(opened, target)
		}

		return printResolvedShow(opened, target)
	})
}

func formatListEntityLine(entry listJSONEntry) string {
	return fmt.Sprintf("%s\t%s", entry.Kind, entry.Name)
}

func renderListInventoryJSON(entries []listJSONEntry) ([]byte, error) {
	return marshalJSONLine(listJSONInventory{Entries: entries})
}

func buildListInventory(opened *vault.Opened) ([]listJSONEntry, error) {
	names := opened.ListNames()
	entries := make([]listJSONEntry, 0, len(names))
	for _, name := range names {
		entry, err := buildListJSONEntry(opened, name)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Name != entries[j].Name {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].Kind < entries[j].Kind
	})
	return entries, nil
}

func renderListSelectionJSON(opened *vault.Opened, selection string) ([]byte, error) {
	profile, err := opened.ResolveSelection(selection)
	if err != nil {
		return nil, err
	}
	defer opened.WipeProfile(profile)
	return marshalJSONLine(listJSONSelection{Selection: selection, Keys: profile.Keys()})
}

func buildListJSONEntry(opened *vault.Opened, name string) (listJSONEntry, error) {
	kind := opened.Kind(name)
	if kind == vault.EntityKindUnknown {
		return listJSONEntry{}, vault.ErrNameNotFound
	}
	metadata, err := opened.Metadata(name)
	if err != nil {
		return listJSONEntry{}, err
	}
	keys, err := opened.ListKeys(name)
	if err != nil {
		return listJSONEntry{}, err
	}
	entry := listJSONEntry{
		Name:           name,
		Kind:           kind,
		CreatedAt:      metadataTimeValue(metadata.CreatedAt),
		ModifiedAt:     metadataTimeValue(metadata.ModifiedAt),
		DirectKeyCount: len(keys),
	}
	if kind == vault.EntityKindApp {
		app, err := opened.App(name)
		if err != nil {
			return listJSONEntry{}, err
		}
		entry.LinkedGroupCount = len(app.Groups)
	}
	return entry, nil
}

type editableMetadata struct {
	Keys map[string]string `json:"keys,omitempty"`
}

type listJSONEntry struct {
	Name             string           `json:"name"`
	Kind             vault.EntityKind `json:"kind"`
	CreatedAt        string           `json:"created_at,omitempty"`
	ModifiedAt       string           `json:"modified_at,omitempty"`
	DirectKeyCount   int              `json:"direct_key_count"`
	LinkedGroupCount int              `json:"linked_group_count,omitempty"`
}

type listJSONInventory struct {
	Entries []listJSONEntry `json:"entries"`
}

type listJSONSelection struct {
	Selection string   `json:"selection"`
	Keys      []string `json:"keys"`
}

type showJSONEntry struct {
	Name       string           `json:"name"`
	Kind       vault.EntityKind `json:"kind"`
	CreatedAt  string           `json:"created_at,omitempty"`
	ModifiedAt string           `json:"modified_at,omitempty"`
}

type showJSONEntity struct {
	Name         string           `json:"name"`
	Kind         vault.EntityKind `json:"kind"`
	CreatedAt    string           `json:"created_at,omitempty"`
	ModifiedAt   string           `json:"modified_at,omitempty"`
	DirectKeys   []string         `json:"direct_keys"`
	LinkedGroups []string         `json:"linked_groups,omitempty"`
}

type showJSONResolved struct {
	Selection    string               `json:"selection"`
	Entries      []showJSONEntry      `json:"entries"`
	ResolvedKeys []string             `json:"resolved_keys"`
	Provenance   []showJSONProvenance `json:"provenance,omitempty"`
}

type showJSONProvenance struct {
	Key        string           `json:"key"`
	SourceName string           `json:"source_name"`
	SourceKind vault.EntityKind `json:"source_kind"`
}

type exportJSONMetadata struct {
	Name         string            `json:"name"`
	Kind         vault.EntityKind  `json:"kind"`
	CreatedAt    string            `json:"created_at,omitempty"`
	ModifiedAt   string            `json:"modified_at,omitempty"`
	DirectEnv    map[string]string `json:"direct_env"`
	LinkedGroups []string          `json:"linked_groups,omitempty"`
	ResolvedEnv  map[string]string `json:"resolved_env"`
}

type exportJSONSelectionMetadata struct {
	Selection   string               `json:"selection"`
	Entries     []exportJSONMetadata `json:"entries"`
	ResolvedEnv map[string]string    `json:"resolved_env"`
}

func runRename(args []string) error {
	fs := flag.NewFlagSet("rename", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", defaultVaultDir(), "vault directory")
	unlock := addUnlockFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := unlock.Validate(); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: env-vault rename [--dir PATH] OLD_NAME NEW_NAME")
	}

	oldName := fs.Arg(0)
	newName := fs.Arg(1)

	return withOpenedStore(*dir, *unlock, newUnlockAuditEvent("rename", fmt.Sprintf("%s->%s", oldName, newName)), func(opened *vault.Opened) error {
		kind, err := opened.RenameName(oldName, newName)
		if err != nil {
			return err
		}
		if err := opened.Save(); err != nil {
			return err
		}

		if err := writeTextf(os.Stdout, "Renamed %s %s to %s\n", kind, oldName, newName); err != nil {
			return err
		}
		return nil
	})
}

func runCopy(args []string) error {
	fs := flag.NewFlagSet("copy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", defaultVaultDir(), "vault directory")
	unlock := addUnlockFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := unlock.Validate(); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: env-vault copy [--dir PATH] SOURCE_NAME DEST_NAME")
	}

	sourceName := fs.Arg(0)
	destinationName := fs.Arg(1)

	return withOpenedStore(*dir, *unlock, newUnlockAuditEvent("copy", fmt.Sprintf("%s->%s", sourceName, destinationName)), func(opened *vault.Opened) error {
		kind, err := opened.CopyName(sourceName, destinationName)
		if err != nil {
			return err
		}
		if err := opened.Save(); err != nil {
			return err
		}

		if err := writeTextf(os.Stdout, "Copied %s %s to %s\n", kind, sourceName, destinationName); err != nil {
			return err
		}
		return nil
	})
}

func runLink(args []string) error {
	fs := flag.NewFlagSet("link", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", defaultVaultDir(), "vault directory")
	unlock := addUnlockFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := unlock.Validate(); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: env-vault link [--dir PATH] APP GROUP")
	}

	appName := fs.Arg(0)
	groupName := fs.Arg(1)

	return withOpenedStore(*dir, *unlock, newUnlockAuditEvent("link", fmt.Sprintf("%s+%s", appName, groupName)), func(opened *vault.Opened) error {
		if err := opened.LinkAppGroup(appName, groupName); err != nil {
			return err
		}
		if err := opened.Save(); err != nil {
			return err
		}

		if err := writeTextf(os.Stdout, "Linked group %s to app %s\n", groupName, appName); err != nil {
			return err
		}
		return nil
	})
}

func runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", defaultVaultDir(), "vault directory")
	unlock := addUnlockFlags(fs)
	format := fs.String("format", "env", "output format: env, export-env, json, dotenv")
	metadata := fs.Bool("metadata", false, "wrap json export with entity metadata")
	outputPath := fs.String("output", "", "write plaintext output to a file")
	forceStdout := fs.Bool("force-stdout", false, "allow printing plaintext secrets directly to a terminal")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := unlock.Validate(); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: env-vault export [--dir PATH] [--format env|export-env|json|dotenv] [--output FILE] [--force-stdout] NAME[,NAME...]")
	}
	if *metadata && *format != "json" {
		return fmt.Errorf("--metadata requires --format json")
	}

	return withOpenedStore(*dir, *unlock, newUnlockAuditEvent("export", fs.Arg(0)), func(opened *vault.Opened) error {
		profile, err := opened.ResolveSelection(fs.Arg(0))
		if err != nil {
			return err
		}
		defer opened.WipeProfile(profile)

		var content []byte
		if *metadata {
			content, err = renderExportMetadataJSON(opened, fs.Arg(0), profile)
		} else {
			content, err = renderExport(profile, *format)
		}
		if err != nil {
			return err
		}

		stdoutIsTerminal, err := isTerminalFile(os.Stdout)
		if err != nil {
			return err
		}
		warning, err := exportTargetWarning(*outputPath, *forceStdout, stdoutIsTerminal)
		if err != nil {
			return err
		}
		if warning != "" {
			if err := writeLine(os.Stderr, warning); err != nil {
				return err
			}
		}

		if *outputPath != "" {
			if err := vault.WriteFileAtomic(*outputPath, content, 0o600); err != nil {
				return err
			}
			if err := writeTextf(os.Stdout, "Exported %s to %s\n", fs.Arg(0), *outputPath); err != nil {
				return err
			}
			return nil
		}

		_, err = os.Stdout.Write(content)
		return err
	})
}

func runUnlink(args []string) error {
	fs := flag.NewFlagSet("unlink", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", defaultVaultDir(), "vault directory")
	unlock := addUnlockFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := unlock.Validate(); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: env-vault unlink [--dir PATH] APP GROUP")
	}

	appName := fs.Arg(0)
	groupName := fs.Arg(1)

	return withOpenedStore(*dir, *unlock, newUnlockAuditEvent("unlink", fmt.Sprintf("%s-%s", appName, groupName)), func(opened *vault.Opened) error {
		if err := opened.UnlinkAppGroup(appName, groupName); err != nil {
			return err
		}
		if err := opened.Save(); err != nil {
			return err
		}

		if err := writeTextf(os.Stdout, "Unlinked group %s from app %s\n", groupName, appName); err != nil {
			return err
		}
		return nil
	})
}

func runUnset(args []string) error {
	fs := flag.NewFlagSet("unset", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", defaultVaultDir(), "vault directory")
	unlock := addUnlockFlags(fs)
	force := fs.Bool("force", false, "remove without confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := unlock.Validate(); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: env-vault unset [--dir PATH] [--force] NAME KEY")
	}

	name := fs.Arg(0)
	key := fs.Arg(1)

	return withOpenedStore(*dir, *unlock, newUnlockAuditEvent("unset", fmt.Sprintf("%s:%s", name, key)), func(opened *vault.Opened) error {
		if _, err := keyDetails(opened, name, key); err != nil {
			return err
		}
		kind := opened.Kind(name)
		if kind == vault.EntityKindUnknown {
			return vault.ErrNameNotFound
		}
		if err := confirmDestructiveAction(*force, fmt.Sprintf("Remove %s from %s %s?", key, kind, name)); err != nil {
			return err
		}

		if err := opened.Unset(name, key); err != nil {
			return err
		}
		if err := opened.Save(); err != nil {
			return err
		}

		if err := writeTextf(os.Stdout, "Removed %s from %s %s\n", key, kind, name); err != nil {
			return err
		}
		return nil
	})
}

func runRemove(args []string) error {
	fs := flag.NewFlagSet("remove", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", defaultVaultDir(), "vault directory")
	unlock := addUnlockFlags(fs)
	force := fs.Bool("force", false, "remove without confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := unlock.Validate(); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: env-vault remove [--dir PATH] [--force] NAME")
	}

	name := fs.Arg(0)

	return withOpenedStore(*dir, *unlock, newUnlockAuditEvent("remove", name), func(opened *vault.Opened) error {
		kind := opened.Kind(name)
		if kind == vault.EntityKindUnknown {
			return vault.ErrNameNotFound
		}
		keyCount, groupCount, err := entityDetails(opened, name)
		if err != nil {
			return err
		}
		prompt := fmt.Sprintf("Remove %s %s with %d direct key(s)", kind, name, keyCount)
		if kind == vault.EntityKindApp {
			prompt += fmt.Sprintf(" and %d linked group(s)", groupCount)
		}
		prompt += "?"
		if err := confirmDestructiveAction(*force, prompt); err != nil {
			return err
		}

		if err := opened.RemoveName(name); err != nil {
			return err
		}
		if err := opened.Save(); err != nil {
			return err
		}

		if err := writeTextf(os.Stdout, "Removed %s %s\n", kind, name); err != nil {
			return err
		}
		return nil
	})
}

func runExec(args []string) error {
	separator := -1
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator == -1 {
		return fmt.Errorf("usage: env-vault exec [--dir PATH] NAME[,NAME...] -- COMMAND [ARGS...]")
	}

	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", defaultVaultDir(), "vault directory")
	unlock := addUnlockFlags(fs)
	if err := fs.Parse(args[:separator]); err != nil {
		return err
	}
	if err := unlock.Validate(); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: env-vault exec [--dir PATH] NAME[,NAME...] -- COMMAND [ARGS...]")
	}

	commandArgs := args[separator+1:]
	if len(commandArgs) == 0 {
		return fmt.Errorf("exec requires a command after --")
	}

	return withOpenedSelection(*dir, fs.Arg(0), *unlock, newUnlockAuditEvent("exec", fs.Arg(0)), func(profile vault.Profile) error {
		//nolint:gosec // executing the user-provided command is the purpose of this subcommand.
		cmd := exec.Command(commandArgs[0], commandArgs[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = buildExecEnv(fs.Arg(0), profile)
		return runChildProcess(cmd)
	})
}

func runShell(args []string) error {
	separator := -1
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}

	parseArgs := args
	shellArgs := []string{}
	if separator != -1 {
		parseArgs = args[:separator]
		shellArgs = args[separator+1:]
	}

	fs := flag.NewFlagSet("shell", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", defaultVaultDir(), "vault directory")
	unlock := addUnlockFlags(fs)
	shellPath := fs.String("shell", "", "shell executable")
	allowNested := fs.Bool("allow-nested", false, "allow running env-vault shell inside another env-vault shell")
	if err := fs.Parse(parseArgs); err != nil {
		return err
	}
	if err := unlock.Validate(); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: env-vault shell [--dir PATH] [--shell PATH] [--allow-nested] NAME[,NAME...] [-- SHELL_ARGS...]")
	}
	if err := ensureShellAllowed(os.Getenv(envVaultShellVar), *allowNested); err != nil {
		return err
	}

	resolvedShell := *shellPath
	if resolvedShell == "" {
		resolvedShell = defaultShellPath(runtime.GOOS, os.Getenv("COMSPEC"), os.Getenv("SHELL"))
	}

	return withOpenedSelection(*dir, fs.Arg(0), *unlock, newUnlockAuditEvent("shell", fs.Arg(0)), func(profile vault.Profile) error {
		if err := writeTextf(os.Stderr, "Starting shell for %s. Exit the shell to remove injected secrets.\n", fs.Arg(0)); err != nil {
			return err
		}
		//nolint:gosec // shell execution is explicitly requested by the user.
		cmd := exec.Command(resolvedShell, shellArgs...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = buildShellEnv(fs.Arg(0), profile)
		return runChildProcess(cmd)
	})
}

func buildExecEnv(profileName string, profile vault.Profile) []string {
	env := environ(os.Environ())
	keys := make([]string, 0, len(profile))
	for key := range profile {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		env.Set(key, string(profile[key]))
	}
	env.Set(envVaultActiveVar, "1")
	env.Set(envVaultProfileVar, profileName)
	return env
}

func buildShellEnv(profileName string, profile vault.Profile) []string {
	env := environ(buildExecEnv(profileName, profile))
	env.Set(envVaultShellVar, "1")
	return env
}

func renderExport(profile vault.Profile, format string) ([]byte, error) {
	keys := profile.Keys()
	switch format {
	case "env", "dotenv", "export-env":
		lines := make([]string, 0, len(keys))
		for _, key := range keys {
			assignment := key + "=" + strconv.Quote(string(profile[key]))
			if format == "export-env" {
				assignment = "export " + assignment
			}
			lines = append(lines, assignment)
		}
		if len(lines) == 0 {
			return []byte{}, nil
		}
		return []byte(strings.Join(lines, "\n") + "\n"), nil
	case exportFormatJSON:
		payload := make(map[string]string, len(profile))
		for _, key := range keys {
			payload[key] = string(profile[key])
		}
		encoded, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(encoded, '\n'), nil
	default:
		return nil, fmt.Errorf("unsupported export format %q", format)
	}
}

func extractBoolFlag(args []string, flagName string) ([]string, bool) {
	filtered := make([]string, 0, len(args))
	found := false
	for _, arg := range args {
		if arg == flagName {
			found = true
			continue
		}
		filtered = append(filtered, arg)
	}
	return filtered, found
}

func extractStringFlag(args []string, flagName string) ([]string, string, error) {
	filtered := make([]string, 0, len(args))
	value := ""
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if after, ok := strings.CutPrefix(arg, flagName+"="); ok {
			value = strings.TrimSpace(after)
			if value == "" {
				return nil, "", fmt.Errorf("%s requires a value", flagName)
			}
			continue
		}
		if arg == flagName {
			remaining := args[index+1:]
			if len(remaining) == 0 {
				return nil, "", fmt.Errorf("%s requires a value", flagName)
			}
			next := strings.TrimSpace(remaining[0])
			if next == "" || strings.HasPrefix(next, "--") {
				return nil, "", fmt.Errorf("%s requires a value", flagName)
			}
			value = next
			index++
			continue
		}
		filtered = append(filtered, arg)
	}
	return filtered, value, nil
}

func parseShowTarget(args []string) (vault.EntityKind, string, error) {
	if len(args) == 1 {
		return vault.EntityKindUnknown, args[0], nil
	}
	if len(args) == 2 {
		switch args[0] {
		case "app":
			return vault.EntityKindApp, args[1], nil
		case "group":
			return vault.EntityKindGroup, args[1], nil
		}
	}
	return vault.EntityKindUnknown, "", fmt.Errorf("usage: env-vault show [--dir PATH] [--resolved] [--json] [app|group] NAME[,NAME...]")
}

func runInteractiveSet(opened *vault.Opened, name string, kind vault.EntityKind) (int, error) {
	stdinIsTerminal, err := isTerminalFile(os.Stdin)
	if err != nil {
		return 0, err
	}
	if !stdinIsTerminal {
		return 0, fmt.Errorf("--interactive requires stdin to be a terminal")
	}

	reader := bufio.NewReader(os.Stdin)
	storedCount := 0
	for {
		if err := writeText(os.Stderr, "Key (blank to finish): "); err != nil {
			return 0, err
		}
		key, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, err
		}
		key = strings.TrimSpace(key)
		if key == "" {
			if storedCount == 0 {
				return 0, fmt.Errorf("no keys were provided")
			}
			return storedCount, nil
		}

		value, err := promptSecretBuffer(fmt.Sprintf("Value for %s: ", key), "use set --stdin for non-interactive secret input")
		if err != nil {
			return 0, err
		}
		cloned := cloneBytes(value.Bytes())
		value.Destroy()

		switch kind {
		case vault.EntityKindGroup:
			err = opened.SetGroup(name, key, cloned)
		case vault.EntityKindApp:
			err = opened.SetApp(name, key, cloned)
		case vault.EntityKindUnknown:
			err = fmt.Errorf("internal error: unsupported entity kind %q", kind)
		default:
			err = fmt.Errorf("internal error: unsupported entity kind %q", kind)
		}
		vault.Wipe(cloned)
		if err != nil {
			return 0, err
		}
		storedCount++
	}
}

func printEntityShow(opened *vault.Opened, name string) error {
	kind := opened.Kind(name)
	if kind == vault.EntityKindUnknown {
		return vault.ErrNameNotFound
	}
	metadata, err := opened.Metadata(name)
	if err != nil {
		return err
	}
	keys, err := opened.ListKeys(name)
	if err != nil {
		return err
	}

	if err := writeTextf(os.Stdout, "name: %s\n", name); err != nil {
		return err
	}
	if err := writeTextf(os.Stdout, "kind: %s\n", kind); err != nil {
		return err
	}
	if err := writeTextf(os.Stdout, "created: %s\n", formatMetadataTime(metadata.CreatedAt)); err != nil {
		return err
	}
	if err := writeTextf(os.Stdout, "modified: %s\n", formatMetadataTime(metadata.ModifiedAt)); err != nil {
		return err
	}
	if err := writeTextf(os.Stdout, "direct keys: %d\n", len(keys)); err != nil {
		return err
	}
	if kind == vault.EntityKindApp {
		app, err := opened.App(name)
		if err != nil {
			return err
		}
		if err := writeTextf(os.Stdout, "linked groups: %d\n", len(app.Groups)); err != nil {
			return err
		}
		if err := writeLine(os.Stdout, "groups:"); err != nil {
			return err
		}
		for _, groupName := range app.Groups {
			if err := writeTextf(os.Stdout, "  - %s\n", groupName); err != nil {
				return err
			}
		}
	}
	if err := writeLine(os.Stdout, "keys:"); err != nil {
		return err
	}
	for _, key := range keys {
		if err := writeTextf(os.Stdout, "  - %s\n", key); err != nil {
			return err
		}
	}
	return nil
}

func printEntityShowJSON(opened *vault.Opened, name string) error {
	payload, err := renderEntityShowJSON(opened, name)
	if err != nil {
		return err
	}
	return writeText(os.Stdout, string(payload))
}

func printResolvedShow(opened *vault.Opened, selection string) error {
	names, err := vault.ParseSelection(selection)
	if err != nil {
		return err
	}
	kinds, err := opened.SelectionKinds(selection)
	if err != nil {
		return err
	}
	profile, err := opened.ResolveSelection(selection)
	if err != nil {
		return err
	}
	defer opened.WipeProfile(profile)

	if err := writeTextf(os.Stdout, "selection: %s\n", selection); err != nil {
		return err
	}
	if err := writeTextf(os.Stdout, "resolved keys: %d\n", len(profile)); err != nil {
		return err
	}
	if err := writeLine(os.Stdout, "entries:"); err != nil {
		return err
	}
	for _, name := range names {
		if err := writeTextf(os.Stdout, "  - %s (%s)\n", name, kinds[name]); err != nil {
			return err
		}
	}
	if err := writeLine(os.Stdout, "keys:"); err != nil {
		return err
	}
	for _, key := range profile.Keys() {
		if err := writeTextf(os.Stdout, "  - %s\n", key); err != nil {
			return err
		}
	}
	provenance := buildResolvedProvenance(opened, names)
	if len(provenance) > 0 {
		if err := writeLine(os.Stdout, "provenance:"); err != nil {
			return err
		}
		for _, item := range provenance {
			if err := writeTextf(os.Stdout, "  - %s <- %s %s\n", item.Key, item.SourceKind, item.SourceName); err != nil {
				return err
			}
		}
	}
	return nil
}

func printResolvedShowJSON(opened *vault.Opened, selection string) error {
	payload, err := renderResolvedShowJSON(opened, selection)
	if err != nil {
		return err
	}
	return writeText(os.Stdout, string(payload))
}

func renderEntityShowJSON(opened *vault.Opened, name string) ([]byte, error) {
	kind := opened.Kind(name)
	if kind == vault.EntityKindUnknown {
		return nil, vault.ErrNameNotFound
	}
	metadata, err := opened.Metadata(name)
	if err != nil {
		return nil, err
	}
	keys, err := opened.ListKeys(name)
	if err != nil {
		return nil, err
	}
	payload := showJSONEntity{
		Name:       name,
		Kind:       kind,
		CreatedAt:  metadataTimeValue(metadata.CreatedAt),
		ModifiedAt: metadataTimeValue(metadata.ModifiedAt),
		DirectKeys: keys,
	}
	if kind == vault.EntityKindApp {
		app, err := opened.App(name)
		if err != nil {
			return nil, err
		}
		payload.LinkedGroups = append([]string(nil), app.Groups...)
	}
	return marshalJSONLine(payload)
}

func renderResolvedShowJSON(opened *vault.Opened, selection string) ([]byte, error) {
	names, err := vault.ParseSelection(selection)
	if err != nil {
		return nil, err
	}
	payload := showJSONResolved{
		Selection: selection,
		Entries:   make([]showJSONEntry, 0, len(names)),
	}
	for _, name := range names {
		entry, err := buildShowJSONEntry(opened, name)
		if err != nil {
			return nil, err
		}
		payload.Entries = append(payload.Entries, entry)
	}
	if len(names) > 0 {
		profile, err := opened.ResolveSelection(strings.Join(names, ","))
		if err != nil {
			return nil, err
		}
		defer opened.WipeProfile(profile)
		payload.ResolvedKeys = profile.Keys()
		payload.Provenance = buildResolvedProvenance(opened, names)
	}
	return marshalJSONLine(payload)
}

func buildResolvedProvenance(opened *vault.Opened, names []string) []showJSONProvenance {
	if len(names) == 0 {
		return nil
	}
	type source struct {
		name string
		kind vault.EntityKind
	}
	resolved := map[string]source{}
	for _, name := range names {
		switch opened.Kind(name) {
		case vault.EntityKindGroup:
			profile, err := opened.Group(name)
			if err != nil {
				continue
			}
			for key := range profile {
				resolved[key] = source{name: name, kind: vault.EntityKindGroup}
			}
			opened.WipeProfile(profile)
		case vault.EntityKindApp:
			app, err := opened.App(name)
			if err != nil {
				continue
			}
			for _, groupName := range app.Groups {
				group, err := opened.Group(groupName)
				if err != nil {
					continue
				}
				for key := range group {
					resolved[key] = source{name: groupName, kind: vault.EntityKindGroup}
				}
				opened.WipeProfile(group)
			}
			for key := range app.Env {
				resolved[key] = source{name: name, kind: vault.EntityKindApp}
			}
			app.Wipe()
		case vault.EntityKindUnknown:
			continue
		}
	}
	keys := make([]string, 0, len(resolved))
	for key := range resolved {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	provenance := make([]showJSONProvenance, 0, len(keys))
	for _, key := range keys {
		source := resolved[key]
		provenance = append(provenance, showJSONProvenance{
			Key:        key,
			SourceName: source.name,
			SourceKind: source.kind,
		})
	}
	return provenance
}

func renderExportMetadataJSON(opened *vault.Opened, selection string, profile vault.Profile) ([]byte, error) {
	names, err := vault.ParseSelection(selection)
	if err != nil {
		return nil, err
	}
	if len(names) != 1 {
		entries := make([]exportJSONMetadata, 0, len(names))
		for _, name := range names {
			entry, err := buildExportMetadataEntry(opened, name)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry)
		}
		return marshalJSONLine(exportJSONSelectionMetadata{
			Selection:   selection,
			Entries:     entries,
			ResolvedEnv: profileToStringMap(profile),
		})
	}
	payload, err := buildExportMetadataEntry(opened, names[0])
	if err != nil {
		return nil, err
	}
	payload.ResolvedEnv = profileToStringMap(profile)
	return marshalJSONLine(payload)
}

func buildExportMetadataEntry(opened *vault.Opened, name string) (exportJSONMetadata, error) {
	kind := opened.Kind(name)
	if kind == vault.EntityKindUnknown {
		return exportJSONMetadata{}, vault.ErrNameNotFound
	}
	metadata, err := opened.Metadata(name)
	if err != nil {
		return exportJSONMetadata{}, err
	}
	directEnv, err := directKeyValues(opened, name, kind)
	if err != nil {
		return exportJSONMetadata{}, err
	}
	payload := exportJSONMetadata{
		Name:        name,
		Kind:        kind,
		CreatedAt:   metadataTimeValue(metadata.CreatedAt),
		ModifiedAt:  metadataTimeValue(metadata.ModifiedAt),
		DirectEnv:   directEnv,
		ResolvedEnv: map[string]string{},
	}
	resolved, err := opened.ResolveSelection(name)
	if err != nil {
		return exportJSONMetadata{}, err
	}
	payload.ResolvedEnv = profileToStringMap(resolved)
	opened.WipeProfile(resolved)
	if kind == vault.EntityKindApp {
		app, err := opened.App(name)
		if err != nil {
			return exportJSONMetadata{}, err
		}
		payload.LinkedGroups = append([]string(nil), app.Groups...)
		app.Wipe()
	}
	return payload, nil
}

func profileToStringMap(profile vault.Profile) map[string]string {
	result := make(map[string]string, len(profile))
	for key, value := range profile {
		result[key] = string(value)
	}
	return result
}

func buildShowJSONEntry(opened *vault.Opened, name string) (showJSONEntry, error) {
	kind := opened.Kind(name)
	if kind == vault.EntityKindUnknown {
		return showJSONEntry{}, vault.ErrNameNotFound
	}
	metadata, err := opened.Metadata(name)
	if err != nil {
		return showJSONEntry{}, err
	}
	return showJSONEntry{
		Name:       name,
		Kind:       kind,
		CreatedAt:  metadataTimeValue(metadata.CreatedAt),
		ModifiedAt: metadataTimeValue(metadata.ModifiedAt),
	}, nil
}

func marshalJSONLine(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, '\n')
	return encoded, nil
}

func metadataTimeValue(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func editEntityInEditor(name string, kind vault.EntityKind, directKeys map[string]string, editorOverride string) (editableMetadata, bool, error) {
	original := editableMetadata{}
	original.Keys = cloneStringMap(directKeys)
	contents, err := renderEditableEntity(original)
	if err != nil {
		return editableMetadata{}, false, err
	}
	path, err := writeTempMetadataFile(contents)
	if err != nil {
		return editableMetadata{}, false, err
	}
	defer func() {
		_ = os.Remove(path)
	}()

	command, commandArgs := resolveEditor(editorOverride)
	commandArgs = append(commandArgs, path)
	// #nosec G204 -- editor execution is explicitly requested by the local user.
	cmd := exec.Command(command, commandArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return editableMetadata{}, false, fmt.Errorf("run editor for %s %s: %w", kind, name, err)
	}
	// #nosec G304 -- reading the temporary editor file is required to apply local edits.
	updatedContents, err := os.ReadFile(path)
	if err != nil {
		return editableMetadata{}, false, err
	}
	updated, err := parseEditableEntity(updatedContents)
	if err != nil {
		return editableMetadata{}, false, err
	}
	return updated, !maps.Equal(original.Keys, updated.Keys), nil
}

func applyEditedEntity(opened *vault.Opened, name string, kind vault.EntityKind, edited editableMetadata) error {
	currentKeys, err := directKeyValues(opened, name, kind)
	if err != nil {
		return err
	}
	for key := range currentKeys {
		if _, ok := edited.Keys[key]; ok {
			continue
		}
		if err := opened.Unset(name, key); err != nil {
			return err
		}
	}
	for key, value := range edited.Keys {
		if currentValue, ok := currentKeys[key]; ok && currentValue == value {
			continue
		}
		data := []byte(value)
		switch kind {
		case vault.EntityKindGroup:
			err = opened.SetGroup(name, key, data)
		case vault.EntityKindApp:
			err = opened.SetApp(name, key, data)
		case vault.EntityKindUnknown:
			err = fmt.Errorf("internal error: unsupported entity kind %q", kind)
		default:
			err = fmt.Errorf("internal error: unsupported entity kind %q", kind)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func renderEditableEntity(entity editableMetadata) ([]byte, error) {
	return marshalJSONLine(entity)
}

func parseEditableEntity(data []byte) (editableMetadata, error) {
	var metadata editableMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return editableMetadata{}, fmt.Errorf("parse edited metadata: %w", err)
	}
	keys, err := normalizeEditableKeys(metadata.Keys)
	if err != nil {
		return editableMetadata{}, err
	}
	metadata.Keys = keys
	return metadata, nil
}

func normalizeEditableKeys(keys map[string]string) (map[string]string, error) {
	if len(keys) == 0 {
		return map[string]string{}, nil
	}
	normalized := make(map[string]string, len(keys))
	for key, value := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("key names cannot be empty")
		}
		normalized[key] = value
	}
	return normalized, nil
}

func directKeyValues(opened *vault.Opened, name string, kind vault.EntityKind) (map[string]string, error) {
	values := map[string]string{}
	switch kind {
	case vault.EntityKindGroup:
		profile, err := opened.Group(name)
		if err != nil {
			return nil, err
		}
		defer opened.WipeProfile(profile)
		for key, value := range profile {
			values[key] = string(value)
		}
	case vault.EntityKindApp:
		app, err := opened.App(name)
		if err != nil {
			return nil, err
		}
		defer app.Wipe()
		for key, value := range app.Env {
			values[key] = string(value)
		}
	case vault.EntityKindUnknown:
		return nil, vault.ErrNameNotFound
	default:
		return nil, vault.ErrNameNotFound
	}
	return values, nil
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return map[string]string{}
	}
	clone := make(map[string]string, len(src))
	maps.Copy(clone, src)
	return clone
}

func writeTempMetadataFile(contents []byte) (string, error) {
	tmp, err := os.CreateTemp("", "env-vault-edit-*.json")
	if err != nil {
		return "", err
	}
	path := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(path)
		return "", err
	}
	if _, err := tmp.Write(contents); err != nil {
		_ = tmp.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func resolveEditor(override string) (string, []string) {
	if strings.TrimSpace(override) != "" {
		return override, nil
	}
	for _, candidate := range []string{os.Getenv("VISUAL"), os.Getenv("EDITOR")} {
		parts := strings.Fields(candidate)
		if len(parts) == 0 {
			continue
		}
		return parts[0], parts[1:]
	}
	if runtime.GOOS == goosWindows {
		return "notepad", nil
	}
	return "vi", nil
}

func formatMetadataTime(value time.Time) string {
	if value.IsZero() {
		return "unknown"
	}
	return value.UTC().Format(time.RFC3339)
}

func exportTargetWarning(outputPath string, forceStdout, stdoutIsTerminal bool) (string, error) {
	if outputPath != "" {
		return fmt.Sprintf("Warning: writing plaintext secrets to %s; protect or delete that file promptly.", outputPath), nil
	}
	if stdoutIsTerminal && !forceStdout {
		return "", fmt.Errorf("refusing to print plaintext secrets to an interactive terminal; rerun with --force-stdout or use --output")
	}
	if stdoutIsTerminal && forceStdout {
		return "Warning: printing plaintext secrets directly to the terminal.", nil
	}
	return "", nil
}

func (e *environ) Set(key, value string) {
	e.Unset(key)
	*e = append(*e, key+"="+value)
}

func (e *environ) Unset(key string) {
	prefix := strings.ToUpper(key) + "="
	filtered := (*e)[:0]
	for _, entry := range *e {
		if strings.HasPrefix(strings.ToUpper(entry), prefix) {
			continue
		}
		filtered = append(filtered, entry)
	}
	*e = filtered
}

func addUnlockFlags(fs *flag.FlagSet) *unlockOptions {
	options := &unlockOptions{}
	fs.BoolVar(&options.passwordStdin, "password-stdin", false, "read the master password from standard input")
	fs.StringVar(&options.passwordFile, "password-file", "", "read the master password from a file")
	fs.DurationVar(&options.unlockWindow, "unlock-window", 0, "start or extend a short-lived unlock helper for later automatic reuse")
	options.passwordFD = -1
	fs.Func("password-fd", "read the master password from an already-open file descriptor", func(value string) error {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("parse --password-fd: %w", err)
		}
		options.passwordFD = parsed
		options.passwordFDSet = true
		return nil
	})
	return options
}

func (o unlockOptions) Validate() error {
	selected := 0
	if o.passwordStdin {
		selected++
	}
	if o.passwordFile != "" {
		selected++
	}
	if o.passwordFDSet {
		selected++
	}
	if selected > 1 {
		return fmt.Errorf("choose only one of --password-stdin, --password-file, or --password-fd")
	}
	if o.passwordFDSet && o.passwordFD < 0 {
		return fmt.Errorf("--password-fd must be a non-negative file descriptor")
	}
	if o.unlockWindow < 0 {
		return fmt.Errorf("--unlock-window must not be negative")
	}
	return nil
}

func newUnlockAuditEvent(command, target string) unlockAuditEvent {
	return unlockAuditEvent{
		PID:     os.Getpid(),
		Command: command,
		Target:  target,
	}
}

func unlockSourceName(unlock unlockOptions) string {
	switch {
	case unlock.passwordStdin:
		return "password-stdin"
	case unlock.passwordFile != "":
		return "password-file"
	case unlock.passwordFDSet:
		return "password-fd"
	default:
		return "prompt"
	}
}

func withMasterPassword(unlock unlockOptions, fn func([]byte) error) error {
	materialized, err := readMasterPassword(unlock, false)
	if err != nil {
		return err
	}
	defer vault.Wipe(materialized)

	return fn(materialized)
}

func withConfirmedMasterPassword(unlock unlockOptions, fn func([]byte) error) error {
	materialized, err := readMasterPassword(unlock, true)
	if err != nil {
		return err
	}
	defer vault.Wipe(materialized)

	return fn(materialized)
}

func readMasterPassword(unlock unlockOptions, confirm bool) ([]byte, error) {
	if unlock.passwordStdin || unlock.passwordFile != "" || unlock.passwordFDSet {
		return readNonInteractiveMasterPassword(unlock)
	}

	prompt := "Master password: "
	if confirm {
		prompt = "Create master password: "
	}
	first, err := promptSecretBuffer(prompt, "use --password-stdin, --password-file, or --password-fd for non-interactive master password input")
	if err != nil {
		return nil, err
	}
	defer first.Destroy()

	if !confirm {
		return cloneBytes(first.Bytes()), nil
	}

	second, err := promptSecretBuffer("Confirm master password: ", "use --password-stdin, --password-file, or --password-fd for non-interactive master password input")
	if err != nil {
		return nil, err
	}
	defer second.Destroy()

	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		return nil, fmt.Errorf("passwords do not match")
	}

	return cloneBytes(first.Bytes()), nil
}

func readNonInteractiveMasterPassword(unlock unlockOptions) ([]byte, error) {
	switch {
	case unlock.passwordStdin:
		return readSecretFromReader(os.Stdin, "master password from stdin")
	case unlock.passwordFile != "":
		return readSecretFromFile(unlock.passwordFile)
	case unlock.passwordFDSet:
		file, err := openFileDescriptor(unlock.passwordFD)
		if err != nil {
			return nil, err
		}
		if file == nil {
			return nil, fmt.Errorf("open --password-fd %d", unlock.passwordFD)
		}
		return readSecretFromReader(file, fmt.Sprintf("master password from fd %d", unlock.passwordFD))
	default:
		return nil, fmt.Errorf("internal error: no non-interactive unlock source selected")
	}
}

func readSecretFromFile(path string) ([]byte, error) {
	// #nosec G304 -- reading the user-selected password file is an explicit CLI feature.
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read master password file: %w", err)
	}
	defer vault.Wipe(contents)

	secret := cloneBytes(bytes.TrimRight(contents, "\r\n"))
	if len(secret) == 0 {
		return nil, fmt.Errorf("empty input is not allowed")
	}
	return secret, nil
}

func readSecretFromReader(reader io.Reader, source string) ([]byte, error) {
	data, err := memguard.NewBufferFromEntireReader(reader)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", source, err)
	}
	defer data.Destroy()

	secret := cloneBytes(bytes.TrimRight(data.Bytes(), "\r\n"))
	if len(secret) == 0 {
		return nil, fmt.Errorf("empty input is not allowed")
	}
	return secret, nil
}

func withOpenedSelection(dir, selection string, unlock unlockOptions, audit unlockAuditEvent, fn func(vault.Profile) error) error {
	return withOpenedStore(dir, unlock, audit, func(opened *vault.Opened) error {
		profile, err := opened.ResolveSelection(selection)
		if err != nil {
			return err
		}
		defer opened.WipeProfile(profile)

		return fn(profile)
	})
}

func entityDetails(opened *vault.Opened, name string) (int, int, error) {
	keys, err := opened.ListKeys(name)
	if err != nil {
		return 0, 0, err
	}
	if opened.Kind(name) != vault.EntityKindApp {
		return len(keys), 0, nil
	}
	app, err := opened.App(name)
	if err != nil {
		return 0, 0, err
	}
	return len(keys), len(app.Groups), nil
}

func keyDetails(opened *vault.Opened, profileName, key string) (int, error) {
	keys, err := opened.ListKeys(profileName)
	if err != nil {
		return 0, err
	}
	for index, existingKey := range keys {
		if existingKey == key {
			return index, nil
		}
	}
	return 0, vault.ErrKeyNotFound
}

func requestedEntityKind(asApp, asGroup bool) (vault.EntityKind, error) {
	if asApp && asGroup {
		return vault.EntityKindUnknown, fmt.Errorf("--app and --group cannot be used together")
	}
	if asApp {
		return vault.EntityKindApp, nil
	}
	if asGroup {
		return vault.EntityKindGroup, nil
	}
	return vault.EntityKindUnknown, nil
}

func resolveSetKind(opened *vault.Opened, name string, requested vault.EntityKind) (vault.EntityKind, error) {
	existing := opened.Kind(name)
	if existing != vault.EntityKindUnknown {
		if requested != vault.EntityKindUnknown && requested != existing {
			return vault.EntityKindUnknown, fmt.Errorf("name %s already exists as %s", name, existing)
		}
		return existing, nil
	}
	if requested == vault.EntityKindUnknown {
		return vault.EntityKindUnknown, fmt.Errorf("name %s does not exist; use --app or --group to create it", name)
	}
	return requested, nil
}

func confirmDestructiveAction(force bool, prompt string) error {
	if force {
		return nil
	}
	stdinIsTerminal, err := isTerminalFile(os.Stdin)
	if err != nil {
		return err
	}
	if !stdinIsTerminal {
		return fmt.Errorf("confirmation required; rerun with --force in non-interactive mode")
	}

	if err := writeTextf(os.Stderr, "%s [y/N]: ", prompt); err != nil {
		return err
	}
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if !isAffirmativeResponse(response) {
		return errOperationCanceled
	}
	return nil
}

func isAffirmativeResponse(response string) bool {
	switch strings.ToLower(strings.TrimSpace(response)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

func ensureShellAllowed(shellMarker string, allowNested bool) error {
	if allowNested || shellMarker == "" || shellMarker == "0" {
		return nil
	}
	return fmt.Errorf("refusing to start a nested env-vault shell; rerun with --allow-nested if you really want one")
}

func secretValueInput(readFromStdin bool, positional []string) ([]byte, error) {
	if readFromStdin {
		if len(positional) != 0 {
			return nil, fmt.Errorf("VALUE cannot be used together with --stdin")
		}
		data, err := memguard.NewBufferFromEntireReader(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read value from stdin: %w", err)
		}
		defer data.Destroy()
		return cloneBytes(bytes.TrimRight(data.Bytes(), "\r\n")), nil
	}
	if len(positional) == 1 {
		if err := writeLine(os.Stderr, "Warning: passing secrets as command-line arguments exposes them in the process table and shell history. Use --stdin or omit VALUE to be prompted securely."); err != nil {
			return nil, err
		}
		return []byte(positional[0]), nil
	}
	value, err := promptSecretBuffer("Value: ", "use set --stdin for non-interactive secret input")
	if err != nil {
		return nil, err
	}
	defer value.Destroy()
	return cloneBytes(value.Bytes()), nil
}

func promptSecretBuffer(prompt, nonInteractiveHint string) (*memguard.LockedBuffer, error) {
	stdinIsTerminal, err := isTerminalFile(os.Stdin)
	if err != nil {
		return nil, err
	}
	if !stdinIsTerminal {
		return nil, fmt.Errorf("stdin is not a terminal; %s", nonInteractiveHint)
	}
	if err := writeText(os.Stderr, prompt); err != nil {
		return nil, err
	}
	secret, err := readPasswordFromFile(os.Stdin)
	if writeErr := writeLine(os.Stderr); writeErr != nil && err == nil {
		err = writeErr
	}
	if err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		memguard.WipeBytes(secret)
		return nil, fmt.Errorf("empty input is not allowed")
	}
	locked := memguard.NewBufferFromBytes(secret)
	memguard.WipeBytes(secret)
	return locked, nil
}

func runChildProcess(cmd *exec.Cmd) error {
	err := cmd.Run()
	if err == nil {
		return nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			os.Exit(status.ExitStatus())
		}
		os.Exit(exitErr.ExitCode())
	}
	return err
}

func isTerminalFile(file *os.File) (bool, error) {
	fd, err := intFileDescriptor(file)
	if err != nil {
		return false, err
	}
	return term.IsTerminal(fd), nil
}

func readPasswordFromFile(file *os.File) ([]byte, error) {
	fd, err := intFileDescriptor(file)
	if err != nil {
		return nil, err
	}
	return term.ReadPassword(fd)
}

func intFileDescriptor(file *os.File) (int, error) {
	fd := file.Fd()
	maxInt := int(^uint(0) >> 1)
	if fd > uintptr(maxInt) {
		return 0, fmt.Errorf("file descriptor out of range")
	}
	//nolint:gosec // range check above guarantees the conversion is safe on this platform.
	return int(fd), nil
}

func openFileDescriptor(fd int) (*os.File, error) {
	if fd < 0 {
		return nil, fmt.Errorf("open --password-fd %d", fd)
	}
	return os.NewFile(uintptr(fd), fmt.Sprintf("fd-%d", fd)), nil
}

func cloneBytes(src []byte) []byte {
	return append([]byte(nil), src...)
}

func defaultShellPath(goos, comspec, shell string) string {
	if goos == "windows" {
		if comspec != "" {
			return comspec
		}
		return `C:\Windows\System32\cmd.exe`
	}
	if shell != "" {
		return shell
	}
	return "/bin/sh"
}

func defaultVaultDir() string {
	if fromEnv := os.Getenv("ENV_VAULT_DIR"); fromEnv != "" {
		return fromEnv
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".env-vault"
	}
	return filepath.Join(home, ".env-vault")
}
