package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"env-vault/internal/vault"
)

const (
	testSelectionChatLLM = "chat,llm"
	testModelGPT54       = "gpt-5.4"
)

func TestBuildExecEnvReplacesExistingKeys(t *testing.T) {
	profile := vault.Profile{
		"DB_USER":     []byte("admin"),
		"DB_PASSWORD": []byte("secret"),
	}

	env := buildExecEnv(testSelectionChatLLM, profile)
	entries := map[string][]string{}
	for _, entry := range env {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		entries[strings.ToUpper(parts[0])] = append(entries[strings.ToUpper(parts[0])], parts[1])
	}

	if got := entries["DB_USER"]; len(got) != 1 || got[0] != "admin" {
		t.Fatalf("unexpected DB_USER entries: %#v", got)
	}
	if got := entries["DB_PASSWORD"]; len(got) != 1 || got[0] != "secret" {
		t.Fatalf("unexpected DB_PASSWORD entries: %#v", got)
	}
	if got := entries[envVaultActiveVar]; len(got) != 1 || got[0] != "1" {
		t.Fatalf("unexpected %s entries: %#v", envVaultActiveVar, got)
	}
	if got := entries[envVaultProfileVar]; len(got) != 1 || got[0] != testSelectionChatLLM {
		t.Fatalf("unexpected %s entries: %#v", envVaultProfileVar, got)
	}
}

func TestBuildShellEnvMarksShellSession(t *testing.T) {
	profile := vault.Profile{"TOKEN": []byte("secret")}
	env := buildShellEnv("chat", profile)
	entries := map[string]string{}
	for _, entry := range env {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		entries[strings.ToUpper(parts[0])] = parts[1]
	}

	if got := entries[envVaultShellVar]; got != "1" {
		t.Fatalf("unexpected %s value: %q", envVaultShellVar, got)
	}
}

func TestCanonicalCommandAliases(t *testing.T) {
	tests := map[string]string{
		"completion": "completion",
		"copy":       "copy",
		"edit":       "edit",
		"export":     "export",
		"inspect":    "show",
		"link":       "link",
		"ls":         "list",
		"list":       "list",
		"rename":     "rename",
		"rm":         "remove",
		"remove":     "remove",
		"show":       "show",
		"unlock":     "unlock",
		"unlink":     "unlink",
		"--help":     "help",
		"help":       "help",
		"shell":      "shell",
		"unknown":    "",
	}

	for input, want := range tests {
		got, ok := canonicalCommand(input)
		if want == "" {
			if ok {
				t.Fatalf("expected %q to be rejected, got %q", input, got)
			}
			continue
		}
		if !ok || got != want {
			t.Fatalf("canonicalCommand(%q) = (%q, %t), want (%q, true)", input, got, ok, want)
		}
	}
}

func TestRenderExportEnvFormats(t *testing.T) {
	profile := vault.Profile{
		"ALPHA": []byte("one two"),
		"BETA":  []byte("line1\nline2"),
	}

	tests := map[string][]string{
		"env": {
			`ALPHA="one two"`,
			`BETA="line1\nline2"`,
		},
		"dotenv": {
			`ALPHA="one two"`,
			`BETA="line1\nline2"`,
		},
		"export-env": {
			`export ALPHA="one two"`,
			`export BETA="line1\nline2"`,
		},
	}

	for format, wantLines := range tests {
		got, err := renderExport(profile, format)
		if err != nil {
			t.Fatalf("renderExport(%q) returned error: %v", format, err)
		}
		gotLines := strings.Split(strings.TrimSpace(string(got)), "\n")
		if len(gotLines) != len(wantLines) {
			t.Fatalf("renderExport(%q) returned %d lines, want %d", format, len(gotLines), len(wantLines))
		}
		for index, want := range wantLines {
			if gotLines[index] != want {
				t.Fatalf("renderExport(%q) line %d = %q, want %q", format, index, gotLines[index], want)
			}
		}
	}
}

func TestRenderExportJSON(t *testing.T) {
	profile := vault.Profile{"ALPHA": []byte("one"), "BETA": []byte("two")}
	encoded, err := renderExport(profile, exportFormatJSON)
	if err != nil {
		t.Fatalf("renderExport(%s) returned error: %v", exportFormatJSON, err)
	}

	decoded := map[string]string{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal json export: %v", err)
	}
	if decoded["ALPHA"] != "one" || decoded["BETA"] != "two" {
		t.Fatalf("unexpected json export payload: %#v", decoded)
	}
}

func TestRenderExportRejectsUnknownFormat(t *testing.T) {
	if _, err := renderExport(vault.Profile{"ALPHA": []byte("one")}, "yaml"); err == nil {
		t.Fatal("expected unsupported export format to fail")
	}
}

func TestRenderCompletionIncludesKnownCommands(t *testing.T) {
	tests := []struct {
		name       string
		shell      string
		needle     string
		flagNeedle string
		jsonNeedle string
		metaNeedle string
	}{
		{name: "bash", shell: "bash", needle: "complete -F _env_vault_completion env-vault", flagNeedle: "--unlock-window", jsonNeedle: "--json", metaNeedle: "--metadata"},
		{name: "zsh", shell: "zsh", needle: "#compdef env-vault", flagNeedle: "--unlock-window", jsonNeedle: "--json", metaNeedle: "--metadata"},
		{name: "fish", shell: "fish", needle: "complete -c env-vault -f", flagNeedle: "-l unlock-window", jsonNeedle: "-l json", metaNeedle: "-l metadata"},
		{name: "powershell", shell: "powershell", needle: "Register-ArgumentCompleter -Native -CommandName env-vault", flagNeedle: "--unlock-window", jsonNeedle: "--json", metaNeedle: "--metadata"},
	}

	for _, test := range tests {
		rendered, err := renderCompletion(test.shell)
		if err != nil {
			t.Fatalf("%s: renderCompletion() error = %v", test.name, err)
		}
		if !strings.Contains(rendered, test.needle) {
			t.Fatalf("%s: expected completion output to contain %q", test.name, test.needle)
		}
		if !strings.Contains(rendered, "unlock") || !strings.Contains(rendered, test.flagNeedle) {
			t.Fatalf("%s: expected completion output to contain known commands and flags", test.name)
		}
		if strings.Contains(rendered, "annotate") || strings.Contains(rendered, "tag") {
			t.Fatalf("%s: removed commands should not appear in completion output", test.name)
		}
		if !strings.Contains(rendered, "edit") || !strings.Contains(rendered, test.jsonNeedle) {
			t.Fatalf("%s: expected completion output to include edit and json support", test.name)
		}
		if !strings.Contains(rendered, test.metaNeedle) || strings.Contains(rendered, "metadata-only") || strings.Contains(rendered, "keys-only") {
			t.Fatalf("%s: expected completion output to reflect current edit/export flags", test.name)
		}
	}
}

func TestExtractStringFlag(t *testing.T) {
	filtered, value, err := extractStringFlag([]string{"export", "--format", exportFormatJSON, "chat"}, "--format")
	if err != nil {
		t.Fatalf("extractStringFlag() error = %v", err)
	}
	if value != exportFormatJSON {
		t.Fatalf("unexpected flag value: %q", value)
	}
	if len(filtered) != 2 || filtered[0] != "export" || filtered[1] != "chat" {
		t.Fatalf("unexpected filtered args: %#v", filtered)
	}

	if _, _, err := extractStringFlag([]string{"export", "--format"}, "--format"); err == nil {
		t.Fatal("expected missing flag value to fail")
	}
}

func TestFormatListEntityLine(t *testing.T) {
	entry := listJSONEntry{Name: "llm", Kind: vault.EntityKindGroup}
	line := formatListEntityLine(entry)
	if line != "group\tllm" {
		t.Fatalf("unexpected list line: %q", line)
	}
}

func TestRenderListInventoryJSON(t *testing.T) {
	dir := t.TempDir()
	store := vault.NewStore(filepath.Join(dir, "vault"))
	password := []byte("correct horse battery staple")
	if _, err := store.Init(password, 14); err != nil {
		t.Fatalf("init: %v", err)
	}

	opened, err := store.Open(password)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer opened.Close()
	if err := opened.SetGroup("llm", "TOKEN", []byte("secret")); err != nil {
		t.Fatalf("set group: %v", err)
	}
	if err := opened.SetApp("chat", "MODEL", []byte(testModelGPT54)); err != nil {
		t.Fatalf("set app: %v", err)
	}

	entries, err := buildListInventory(opened)
	if err != nil {
		t.Fatalf("buildListInventory() error = %v", err)
	}
	payload, err := renderListInventoryJSON(entries)
	if err != nil {
		t.Fatalf("renderListInventoryJSON() error = %v", err)
	}
	decoded := listJSONInventory{}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal inventory json: %v", err)
	}
	if len(decoded.Entries) != 2 {
		t.Fatalf("unexpected inventory entries: %#v", decoded.Entries)
	}
}

func TestRenderListSelectionJSON(t *testing.T) {
	dir := t.TempDir()
	store := vault.NewStore(filepath.Join(dir, "vault"))
	password := []byte("correct horse battery staple")
	if _, err := store.Init(password, 14); err != nil {
		t.Fatalf("init: %v", err)
	}

	opened, err := store.Open(password)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer opened.Close()
	if err := opened.SetGroup("llm", "TOKEN", []byte("secret")); err != nil {
		t.Fatalf("set group: %v", err)
	}
	if err := opened.SetApp("chat", "MODEL", []byte(testModelGPT54)); err != nil {
		t.Fatalf("set app: %v", err)
	}
	if err := opened.LinkAppGroup("chat", "llm"); err != nil {
		t.Fatalf("link app group: %v", err)
	}

	payload, err := renderListSelectionJSON(opened, testSelectionChatLLM)
	if err != nil {
		t.Fatalf("renderListSelectionJSON() error = %v", err)
	}
	decoded := listJSONSelection{}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal selection json: %v", err)
	}
	if decoded.Selection != testSelectionChatLLM {
		t.Fatalf("unexpected selection: %q", decoded.Selection)
	}
	if len(decoded.Keys) != 2 || decoded.Keys[0] != "MODEL" || decoded.Keys[1] != "TOKEN" {
		t.Fatalf("unexpected selection keys: %#v", decoded.Keys)
	}
}

func TestRenderEntityShowJSON(t *testing.T) {
	dir := t.TempDir()
	store := vault.NewStore(filepath.Join(dir, "vault"))
	password := []byte("correct horse battery staple")
	if _, err := store.Init(password, 14); err != nil {
		t.Fatalf("init: %v", err)
	}

	opened, err := store.Open(password)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer opened.Close()
	if err := opened.SetGroup("llm", "TOKEN", []byte("secret")); err != nil {
		t.Fatalf("set group: %v", err)
	}

	payload, err := renderEntityShowJSON(opened, "llm")
	if err != nil {
		t.Fatalf("renderEntityShowJSON() error = %v", err)
	}
	decoded := showJSONEntity{}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal entity json: %v", err)
	}
	if decoded.Name != "llm" || decoded.Kind != vault.EntityKindGroup {
		t.Fatalf("unexpected entity payload: %#v", decoded)
	}
	if len(decoded.DirectKeys) != 1 || decoded.DirectKeys[0] != "TOKEN" {
		t.Fatalf("unexpected direct keys: %#v", decoded.DirectKeys)
	}
}

func TestRenderResolvedShowJSON(t *testing.T) {
	dir := t.TempDir()
	store := vault.NewStore(filepath.Join(dir, "vault"))
	password := []byte("correct horse battery staple")
	if _, err := store.Init(password, 14); err != nil {
		t.Fatalf("init: %v", err)
	}

	opened, err := store.Open(password)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer opened.Close()
	if err := opened.SetGroup("llm", "TOKEN", []byte("group-secret")); err != nil {
		t.Fatalf("set group: %v", err)
	}
	if err := opened.SetApp("chat", "MODEL", []byte(testModelGPT54)); err != nil {
		t.Fatalf("set app: %v", err)
	}
	if err := opened.LinkAppGroup("chat", "llm"); err != nil {
		t.Fatalf("link app group: %v", err)
	}
	if err := opened.SetGroup("remote-db", "DB_HOST", []byte("db.example.com")); err != nil {
		t.Fatalf("set remote db: %v", err)
	}

	payload, err := renderResolvedShowJSON(opened, "chat,llm,remote-db")
	if err != nil {
		t.Fatalf("renderResolvedShowJSON() error = %v", err)
	}
	decoded := showJSONResolved{}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal resolved json: %v", err)
	}
	if decoded.Selection != "chat,llm,remote-db" {
		t.Fatalf("unexpected selection: %q", decoded.Selection)
	}
	if len(decoded.Entries) != 3 {
		t.Fatalf("unexpected entries: %#v", decoded.Entries)
	}
	if len(decoded.Provenance) != 3 {
		t.Fatalf("unexpected provenance: %#v", decoded.Provenance)
	}
	if len(decoded.ResolvedKeys) != 3 {
		t.Fatalf("unexpected resolved keys: %#v", decoded.ResolvedKeys)
	}
}

func TestRenderExportMetadataJSON(t *testing.T) {
	dir := t.TempDir()
	store := vault.NewStore(filepath.Join(dir, "vault"))
	password := []byte("correct horse battery staple")
	if _, err := store.Init(password, 14); err != nil {
		t.Fatalf("init: %v", err)
	}

	opened, err := store.Open(password)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer opened.Close()
	if err := opened.SetGroup("llm", "TOKEN", []byte("group-secret")); err != nil {
		t.Fatalf("set group: %v", err)
	}
	if err := opened.SetApp("chat", "MODEL", []byte(testModelGPT54)); err != nil {
		t.Fatalf("set app: %v", err)
	}
	if err := opened.LinkAppGroup("chat", "llm"); err != nil {
		t.Fatalf("link app group: %v", err)
	}
	profile, err := opened.ResolveSelection("chat")
	if err != nil {
		t.Fatalf("resolve selection: %v", err)
	}
	defer opened.WipeProfile(profile)

	payload, err := renderExportMetadataJSON(opened, "chat", profile)
	if err != nil {
		t.Fatalf("renderExportMetadataJSON() error = %v", err)
	}
	decoded := exportJSONMetadata{}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal export metadata json: %v", err)
	}
	if decoded.Name != "chat" || decoded.Kind != vault.EntityKindApp {
		t.Fatalf("unexpected export metadata payload: %#v", decoded)
	}
	if decoded.DirectEnv["MODEL"] != testModelGPT54 {
		t.Fatalf("unexpected direct env: %#v", decoded.DirectEnv)
	}
	if decoded.ResolvedEnv["TOKEN"] != "group-secret" || decoded.ResolvedEnv["MODEL"] != testModelGPT54 {
		t.Fatalf("unexpected resolved env: %#v", decoded.ResolvedEnv)
	}
	if len(decoded.LinkedGroups) != 1 || decoded.LinkedGroups[0] != "llm" {
		t.Fatalf("unexpected linked groups: %#v", decoded.LinkedGroups)
	}
}

func TestRenderExportMetadataJSONSelectionWrapper(t *testing.T) {
	dir := t.TempDir()
	store := vault.NewStore(filepath.Join(dir, "vault"))
	password := []byte("correct horse battery staple")
	if _, err := store.Init(password, 14); err != nil {
		t.Fatalf("init: %v", err)
	}

	opened, err := store.Open(password)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer opened.Close()
	if err := opened.SetGroup("llm", "TOKEN", []byte("group-secret")); err != nil {
		t.Fatalf("set group: %v", err)
	}
	if err := opened.SetApp("chat", "MODEL", []byte(testModelGPT54)); err != nil {
		t.Fatalf("set app: %v", err)
	}
	if err := opened.LinkAppGroup("chat", "llm"); err != nil {
		t.Fatalf("link app group: %v", err)
	}
	profile, err := opened.ResolveSelection(testSelectionChatLLM)
	if err != nil {
		t.Fatalf("resolve selection: %v", err)
	}
	defer opened.WipeProfile(profile)

	payload, err := renderExportMetadataJSON(opened, testSelectionChatLLM, profile)
	if err != nil {
		t.Fatalf("renderExportMetadataJSON(selection) error = %v", err)
	}
	decoded := exportJSONSelectionMetadata{}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal export selection metadata json: %v", err)
	}
	if decoded.Selection != testSelectionChatLLM {
		t.Fatalf("unexpected selection wrapper: %#v", decoded)
	}
	if len(decoded.Entries) != 2 {
		t.Fatalf("unexpected wrapped entries: %#v", decoded.Entries)
	}
	if decoded.ResolvedEnv["TOKEN"] != "group-secret" || decoded.ResolvedEnv["MODEL"] != testModelGPT54 {
		t.Fatalf("unexpected wrapped resolved env: %#v", decoded.ResolvedEnv)
	}
}

func TestParseEditableEntity(t *testing.T) {
	metadata, err := parseEditableEntity([]byte(`{"keys":{"TOKEN":"secret"}}`))
	if err != nil {
		t.Fatalf("parseEditableEntity() error = %v", err)
	}
	if metadata.Keys["TOKEN"] != "secret" {
		t.Fatalf("unexpected editable keys: %#v", metadata.Keys)
	}

	if _, err := parseEditableEntity([]byte(`{"keys":{" ":"value"}}`)); err == nil {
		t.Fatal("expected invalid editable key to fail")
	}
}

func TestExportTargetWarning(t *testing.T) {
	tests := []struct {
		name           string
		outputPath     string
		forceStdout    bool
		stdoutTerminal bool
		wantWarning    string
		wantErr        bool
	}{
		{name: "stdout pipe no warning", stdoutTerminal: false},
		{name: "terminal requires force", stdoutTerminal: true, wantErr: true},
		{name: "forced terminal warning", forceStdout: true, stdoutTerminal: true, wantWarning: "Warning: printing plaintext secrets directly to the terminal."},
		{name: "file warning", outputPath: "secrets.env", wantWarning: "Warning: writing plaintext secrets to secrets.env; protect or delete that file promptly."},
	}

	for _, test := range tests {
		warning, err := exportTargetWarning(test.outputPath, test.forceStdout, test.stdoutTerminal)
		if test.wantErr {
			if err == nil {
				t.Fatalf("%s: expected error", test.name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", test.name, err)
		}
		if warning != test.wantWarning {
			t.Fatalf("%s: warning = %q, want %q", test.name, warning, test.wantWarning)
		}
	}
}

func TestRequestedEntityKind(t *testing.T) {
	if _, err := requestedEntityKind(true, true); err == nil {
		t.Fatal("expected mutually exclusive flags to fail")
	}
	if kind, err := requestedEntityKind(true, false); err != nil || kind != vault.EntityKindApp {
		t.Fatalf("unexpected app kind result: %q, %v", kind, err)
	}
	if kind, err := requestedEntityKind(false, true); err != nil || kind != vault.EntityKindGroup {
		t.Fatalf("unexpected group kind result: %q, %v", kind, err)
	}
	if kind, err := requestedEntityKind(false, false); err != nil || kind != vault.EntityKindUnknown {
		t.Fatalf("unexpected default kind result: %q, %v", kind, err)
	}
}

func TestUnlockOptionsValidate(t *testing.T) {
	if err := (unlockOptions{passwordStdin: true, passwordFile: "pw.txt"}).Validate(); err == nil {
		t.Fatal("expected conflicting unlock sources to fail")
	}
	if err := (unlockOptions{passwordFD: -2, passwordFDSet: true}).Validate(); err == nil {
		t.Fatal("expected invalid password fd to fail")
	}
	if err := (unlockOptions{unlockWindow: -time.Second}).Validate(); err == nil {
		t.Fatal("expected negative unlock window to fail")
	}
	if err := (unlockOptions{passwordFile: "pw.txt"}).Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestDefaultVaultDirUsesEnvOverride(t *testing.T) {
	want := filepath.Join(t.TempDir(), "vault")
	if err := os.Setenv("ENV_VAULT_DIR", want); err != nil {
		t.Fatalf("set env: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("ENV_VAULT_DIR")
	}()

	if got := defaultVaultDir(); got != want {
		t.Fatalf("defaultVaultDir() = %q, want %q", got, want)
	}
}

func TestCurrentExecutablePathIsAbsolute(t *testing.T) {
	got, err := currentExecutablePath()
	if err != nil {
		t.Fatalf("currentExecutablePath() error = %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("currentExecutablePath() = %q, want absolute path", got)
	}
	if _, err := os.Stat(got); err != nil {
		t.Fatalf("stat executable %q: %v", got, err)
	}
	if filepath.Base(strings.ToLower(got)) != filepath.Base(strings.ToLower(os.Args[0])) {
		t.Fatalf("currentExecutablePath() base = %q, want %q", filepath.Base(got), filepath.Base(os.Args[0]))
	}
	if runtime.GOOS == "windows" && !strings.Contains(got, ":") {
		t.Fatalf("currentExecutablePath() = %q, want drive-qualified path on Windows", got)
	}
}
