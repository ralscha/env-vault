package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBashCompletionWithoutBashCompletionPackage(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if runtime.GOOS == goosWindows {
		// Windows' system bash may be a launcher for an uninstalled WSL distro.
		bash = filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe")
		_, err = os.Stat(bash)
	}
	if err != nil {
		t.Skip("Bash is unavailable")
	}
	script, err := renderCompletion("bash")
	if err != nil {
		t.Fatal(err)
	}
	script += `
unset -f _init_completion
COMP_WORDS=(env-vault ex)
COMP_CWORD=1
_env_vault_completion
[[ " ${COMPREPLY[*]} " == *" exec "* ]] || exit 1
[[ " ${COMPREPLY[*]} " == *" export "* ]] || exit 2
COMP_WORDS=(env-vault set --pass)
COMP_CWORD=2
_env_vault_completion
[[ " ${COMPREPLY[*]} " == *" --password-stdin "* ]] || exit 3
`
	cmd := exec.Command(bash, "--noprofile", "--norc")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Bash completion failed: %v\n%s", err, output)
	}
}

func TestPowerShellCompletionAtCursor(t *testing.T) {
	var executable string
	for _, name := range []string{"pwsh", "powershell"} {
		if path, err := exec.LookPath(name); err == nil {
			executable = path
			break
		}
	}
	if executable == "" {
		t.Skip("PowerShell is unavailable")
	}
	completion, err := renderCompletion("powershell")
	if err != nil {
		t.Fatal(err)
	}
	// Capture the registered script and invoke it with real parsed command ASTs.
	script := `
$ErrorActionPreference = 'Stop'
function Register-ArgumentCompleter {
  param([switch]$Native, $CommandName, $ScriptBlock)
  $script:completer = $ScriptBlock
}
` + completion + `
function Check-Completion($line, $cursor, $word, $expected) {
  $ast = [System.Management.Automation.Language.Parser]::ParseInput($line, [ref]$null, [ref]$null)
  $command = $ast.Find({param($node) $node -is [System.Management.Automation.Language.CommandAst]}, $true)
  $matches = @(& $script:completer $word $command $cursor | ForEach-Object { $_.CompletionText })
  if ($matches -notcontains $expected) { throw "Missing $expected for $line at $cursor; got $matches" }
}
Check-Completion 'env-vault ' 10 '' 'exec'
Check-Completion 'env-vault ex' 12 'ex' 'exec'
Check-Completion 'env-vault ex later' 12 'ex' 'export'
Check-Completion 'env-vault exec ' 15 '' '--dir'
Check-Completion 'env-vault set --pass' 19 '--pass' '--password-file'
`
	path := filepath.Join(t.TempDir(), "completion.ps1")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("PowerShell completion failed: %v\n%s", err, output)
	}
}

func TestParseEditableEntityAllowsExplicitEmptyKeys(t *testing.T) {
	metadata, err := parseEditableEntity([]byte(`{"keys":{}}`))
	if err != nil || metadata.Keys == nil || len(metadata.Keys) != 0 {
		t.Fatalf("explicit empty keys must remain supported: %v", err)
	}
}

func TestCommandHelpSucceedsWithoutOpeningVault(t *testing.T) {
	for _, command := range completionCommands() {
		if code := runMain([]string{command, "--help"}); code != 0 {
			t.Errorf("%s --help exited %d", command, code)
		}
	}
}
