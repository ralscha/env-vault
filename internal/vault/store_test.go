package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	testGroupRemoteDB = "remotedb"
	testModelGPT54    = "gpt-5.4"
)

func TestStoreRoundTripWithGroupsAndApps(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "vault"))
	password := []byte("correct horse battery staple")

	publicKey, err := store.Init(password, 14)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if publicKey == "" {
		t.Fatal("expected a public key")
	}

	opened, err := store.Open(password)
	if err != nil {
		t.Fatalf("open after init: %v", err)
	}
	if err := opened.SetGroup("llm", "OPENAI_API_KEY", []byte("group-key")); err != nil {
		t.Fatalf("set group key: %v", err)
	}
	if err := opened.SetGroup("llm", "OPENAI_MODEL", []byte("gpt-5")); err != nil {
		t.Fatalf("set group model: %v", err)
	}
	if err := opened.SetGroup(testGroupRemoteDB, "DB_HOST", []byte("db.example.com")); err != nil {
		t.Fatalf("set db host: %v", err)
	}
	if err := opened.SetGroup(testGroupRemoteDB, "DB_USER", []byte("appuser")); err != nil {
		t.Fatalf("set db user: %v", err)
	}
	if err := opened.LinkAppGroup("chat", "llm"); err != nil {
		t.Fatalf("link llm: %v", err)
	}
	if err := opened.LinkAppGroup("chat", testGroupRemoteDB); err != nil {
		t.Fatalf("link remotedb: %v", err)
	}
	if err := opened.SetApp("chat", "OPENAI_API_KEY", []byte("app-key")); err != nil {
		t.Fatalf("set app override: %v", err)
	}
	if err := opened.Save(); err != nil {
		opened.Close()
		t.Fatalf("save: %v", err)
	}
	opened.Close()

	reopened, err := store.Open(password)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	groups := reopened.ListGroups()
	if len(groups) != 2 || groups[0] != "llm" || groups[1] != testGroupRemoteDB {
		t.Fatalf("unexpected groups: %#v", groups)
	}
	apps := reopened.ListApps()
	if len(apps) != 1 || apps[0] != "chat" {
		t.Fatalf("unexpected apps: %#v", apps)
	}

	app, err := reopened.App("chat")
	if err != nil {
		t.Fatalf("app: %v", err)
	}
	chatMetadata, err := reopened.Metadata("chat")
	if err != nil {
		t.Fatalf("chat metadata: %v", err)
	}
	if chatMetadata.CreatedAt.IsZero() || chatMetadata.ModifiedAt.IsZero() {
		t.Fatal("expected app metadata timestamps to be set")
	}
	if len(app.Groups) != 2 || app.Groups[0] != "llm" || app.Groups[1] != testGroupRemoteDB {
		t.Fatalf("unexpected linked groups: %#v", app.Groups)
	}

	resolved, err := reopened.ResolveSelection("chat")
	if err != nil {
		t.Fatalf("resolve chat: %v", err)
	}
	if got := string(resolved["OPENAI_API_KEY"]); got != "app-key" {
		t.Fatalf("unexpected app override: %q", got)
	}
	if got := string(resolved["DB_HOST"]); got != "db.example.com" {
		t.Fatalf("unexpected db host: %q", got)
	}
	resolved.Wipe()

	if err := reopened.Unset("chat", "OPENAI_API_KEY"); err != nil {
		t.Fatalf("unset app override: %v", err)
	}
	if err := reopened.Save(); err != nil {
		t.Fatalf("save after unset: %v", err)
	}
	fallback, err := reopened.ResolveSelection("chat")
	if err != nil {
		t.Fatalf("resolve chat after unset: %v", err)
	}
	if got := string(fallback["OPENAI_API_KEY"]); got != "group-key" {
		t.Fatalf("expected group fallback, got %q", got)
	}
	fallback.Wipe()

	if err := reopened.RemoveName("llm"); err != nil {
		t.Fatalf("remove group: %v", err)
	}
	if err := reopened.Save(); err != nil {
		t.Fatalf("save after group removal: %v", err)
	}
	postRemoveApp, err := reopened.App("chat")
	if err != nil {
		t.Fatalf("app after group removal: %v", err)
	}
	if len(postRemoveApp.Groups) != 1 || postRemoveApp.Groups[0] != testGroupRemoteDB {
		t.Fatalf("unexpected linked groups after removal: %#v", postRemoveApp.Groups)
	}
}

func TestRenameAndCopyPreserveDataAndMetadata(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "vault"))
	password := []byte("correct horse battery staple")

	if _, err := store.Init(password, 14); err != nil {
		t.Fatalf("init: %v", err)
	}

	opened, err := store.Open(password)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer opened.Close()

	if err := opened.SetGroup("llm", "OPENAI_API_KEY", []byte("group-key")); err != nil {
		t.Fatalf("set group: %v", err)
	}
	if err := opened.LinkAppGroup("chat", "llm"); err != nil {
		t.Fatalf("link app: %v", err)
	}
	if err := opened.SetApp("chat", "OPENAI_MODEL", []byte(testModelGPT54)); err != nil {
		t.Fatalf("set app: %v", err)
	}
	beforeRename, err := opened.Metadata("llm")
	if err != nil {
		t.Fatalf("metadata before rename: %v", err)
	}

	if kind, err := opened.RenameName("llm", "shared-llm"); err != nil {
		t.Fatalf("rename: %v", err)
	} else if kind != EntityKindGroup {
		t.Fatalf("unexpected renamed kind: %q", kind)
	}

	app, err := opened.App("chat")
	if err != nil {
		t.Fatalf("app after rename: %v", err)
	}
	if len(app.Groups) != 1 || app.Groups[0] != "shared-llm" {
		t.Fatalf("expected linked group rename to propagate, got %#v", app.Groups)
	}
	afterRename, err := opened.Metadata("shared-llm")
	if err != nil {
		t.Fatalf("metadata after rename: %v", err)
	}
	if !afterRename.CreatedAt.Equal(beforeRename.CreatedAt) {
		t.Fatal("expected rename to preserve creation time")
	}
	if afterRename.ModifiedAt.Before(beforeRename.ModifiedAt) {
		t.Fatal("expected rename to move modified time forward")
	}

	time.Sleep(10 * time.Millisecond)
	if kind, err := opened.CopyName("chat", "chat-copy"); err != nil {
		t.Fatalf("copy: %v", err)
	} else if kind != EntityKindApp {
		t.Fatalf("unexpected copied kind: %q", kind)
	}

	copyApp, err := opened.App("chat-copy")
	if err != nil {
		t.Fatalf("copied app: %v", err)
	}
	if len(copyApp.Groups) != 1 || copyApp.Groups[0] != "shared-llm" {
		t.Fatalf("unexpected copied linked groups: %#v", copyApp.Groups)
	}
	if got := string(copyApp.Env["OPENAI_MODEL"]); got != testModelGPT54 {
		t.Fatalf("unexpected copied env value: %q", got)
	}
	copyMetadata, err := opened.Metadata("chat-copy")
	if err != nil {
		t.Fatalf("copy metadata: %v", err)
	}
	if copyMetadata.CreatedAt.IsZero() || copyMetadata.ModifiedAt.IsZero() {
		t.Fatal("expected copied entity metadata timestamps to be set")
	}
	if !copyMetadata.CreatedAt.Equal(copyMetadata.ModifiedAt) {
		t.Fatal("expected copied entity to start with matching created and modified timestamps")
	}
}

func TestSetRejectsConflictingNameKinds(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "vault"))
	password := []byte("password-one")
	if _, err := store.Init(password, 14); err != nil {
		t.Fatalf("init: %v", err)
	}

	opened, err := store.Open(password)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer opened.Close()

	if err := opened.SetGroup("shared", "TOKEN", []byte("value")); err != nil {
		t.Fatalf("set group: %v", err)
	}
	if err := opened.SetApp("shared", "TOKEN", []byte("value")); err == nil {
		t.Fatal("expected name conflict when reusing a group name for an app")
	}
}

func TestCreateNameCreatesEmptyEntities(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "vault"))
	password := []byte("password-one")
	if _, err := store.Init(password, 14); err != nil {
		t.Fatalf("init: %v", err)
	}

	opened, err := store.Open(password)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer opened.Close()

	if err := opened.CreateName(EntityKindGroup, "shared"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := opened.CreateName(EntityKindApp, "chat"); err != nil {
		t.Fatalf("create app: %v", err)
	}

	if err := opened.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	if got := opened.Kind("shared"); got != EntityKindGroup {
		t.Fatalf("unexpected group kind: %q", got)
	}
	if got := opened.Kind("chat"); got != EntityKindApp {
		t.Fatalf("unexpected app kind: %q", got)
	}

	keys, err := opened.ListKeys("shared")
	if err != nil {
		t.Fatalf("list group keys: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected no direct group keys, got %#v", keys)
	}

	app, err := opened.App("chat")
	if err != nil {
		t.Fatalf("app: %v", err)
	}
	if len(app.Env) != 0 || len(app.Groups) != 0 {
		t.Fatalf("expected empty app, got %#v", app)
	}
}

func TestResolveSelectionHonorsSelectorOrder(t *testing.T) {
	file := NewFile()
	file.Groups["base"] = Profile{"TOKEN": []byte("base")}
	file.Groups["override"] = Profile{"TOKEN": []byte("override")}
	file.Apps["chat"] = App{
		Groups: []string{"base"},
		Env:    Profile{"TOKEN": []byte("app")},
	}

	opened := &Opened{file: file}
	resolved, err := opened.ResolveSelection("override,chat")
	if err != nil {
		t.Fatalf("resolve selection: %v", err)
	}
	defer resolved.Wipe()
	if got := string(resolved["TOKEN"]); got != "app" {
		t.Fatalf("expected app env to win last, got %q", got)
	}
}

func TestLoadFileReadsInitialVersion(t *testing.T) {
	payload, err := json.Marshal(struct {
		Version int                `json:"version"`
		Groups  map[string]Profile `json:"groups"`
		Apps    map[string]App     `json:"apps"`
	}{
		Version: currentVersion,
		Groups: map[string]Profile{
			"llm": {"TOKEN": []byte("group-token")},
		},
		Apps: map[string]App{
			"chat": {
				Groups: []string{"llm"},
				Env:    Profile{"TOKEN": []byte("app-token")},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal initial-version payload: %v", err)
	}

	file, err := LoadFile(payload)
	if err != nil {
		t.Fatalf("load initial-version file: %v", err)
	}
	if file.Version != currentVersion {
		t.Fatalf("unexpected file version: %d", file.Version)
	}
	if _, ok := file.Metadata["llm"]; !ok {
		t.Fatal("expected metadata placeholder for group")
	}
	if _, ok := file.Metadata["chat"]; !ok {
		t.Fatal("expected metadata placeholder for app")
	}
}

func TestLoadFilePreservesMetadata(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	payload, err := json.Marshal(struct {
		Version  int                       `json:"version"`
		Groups   map[string]Profile        `json:"groups"`
		Apps     map[string]App            `json:"apps"`
		Metadata map[string]EntityMetadata `json:"metadata"`
	}{
		Version: currentVersion,
		Groups: map[string]Profile{
			"llm": {"TOKEN": []byte("group-token")},
		},
		Apps: map[string]App{
			"chat": {
				Groups: []string{"llm"},
				Env:    Profile{"TOKEN": []byte("app-token")},
			},
		},
		Metadata: map[string]EntityMetadata{
			"llm":  {CreatedAt: now, ModifiedAt: now},
			"chat": {CreatedAt: now, ModifiedAt: now},
		},
	})
	if err != nil {
		t.Fatalf("marshal payload with metadata: %v", err)
	}

	file, err := LoadFile(payload)
	if err != nil {
		t.Fatalf("load payload with metadata: %v", err)
	}
	if !file.Metadata["llm"].CreatedAt.Equal(now) {
		t.Fatalf("unexpected llm created time: %v", file.Metadata["llm"].CreatedAt)
	}
	if !file.Metadata["chat"].ModifiedAt.Equal(now) {
		t.Fatalf("unexpected chat modified time: %v", file.Metadata["chat"].ModifiedAt)
	}
}

func TestLoadFileRejectsMissingVersion(t *testing.T) {
	payload, err := json.Marshal(struct {
		Groups map[string]Profile `json:"groups"`
	}{
		Groups: map[string]Profile{
			"llm": {"TOKEN": []byte("secret")},
		},
	})
	if err != nil {
		t.Fatalf("marshal payload without version: %v", err)
	}

	if _, err := LoadFile(payload); err == nil {
		t.Fatal("expected missing version to fail")
	}
}

func TestLoadFileRejectsUnsupportedVersion(t *testing.T) {
	payload, err := json.Marshal(struct {
		Version int                `json:"version"`
		Groups  map[string]Profile `json:"groups"`
	}{
		Version: currentVersion + 1,
		Groups: map[string]Profile{
			"llm": {"TOKEN": []byte("secret")},
		},
	})
	if err != nil {
		t.Fatalf("marshal unsupported-version payload: %v", err)
	}

	if _, err := LoadFile(payload); err == nil {
		t.Fatal("expected unsupported version to fail")
	}
}

func TestStoreRoundTripPersistsVersionedFormat(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "vault"))
	password := []byte("correct horse battery staple")

	if _, err := store.Init(password, 14); err != nil {
		t.Fatalf("init: %v", err)
	}

	opened, err := store.Open(password)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := opened.SetGroup("llm", "TOKEN", []byte("secret")); err != nil {
		opened.Close()
		t.Fatalf("set group: %v", err)
	}
	if err := opened.Save(); err != nil {
		opened.Close()
		t.Fatalf("save: %v", err)
	}
	opened.Close()

	reopened, err := store.Open(password)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if reopened.file.Version != currentVersion {
		t.Fatalf("unexpected file version: %d", reopened.file.Version)
	}
	if _, ok := reopened.file.Groups["llm"]; !ok {
		t.Fatal("expected persisted group after reopen")
	}
}

func TestOpenWithWrongPassword(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "vault"))
	if _, err := store.Init([]byte("password-one"), 14); err != nil {
		t.Fatalf("init: %v", err)
	}

	if _, err := store.Open([]byte("password-two")); err == nil {
		t.Fatal("expected wrong password error")
	}
}

func TestInitCreatesEncryptedFiles(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "vault"))
	if _, err := store.Init([]byte("password-one"), 14); err != nil {
		t.Fatalf("init: %v", err)
	}

	identityPath := filepath.Join(store.Dir(), identityFileName)
	vaultPath := filepath.Join(store.Dir(), vaultFileName)

	// #nosec G304 -- test reads back files created under its own temp directory.
	identityContents, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatalf("read identity file: %v", err)
	}
	// #nosec G304 -- test reads back files created under its own temp directory.
	vaultContents, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read vault file: %v", err)
	}

	if len(identityContents) == 0 || len(vaultContents) == 0 {
		t.Fatal("expected encrypted file contents")
	}
	if string(identityContents) == "AGE-SECRET-KEY-PQ" || string(vaultContents) == "{" {
		t.Fatal("files should not contain plaintext")
	}
	if string(identityContents[:len("age-encryption.org/")]) != "age-encryption.org/" {
		t.Fatal("identity file should be age encrypted")
	}
	if string(vaultContents[:len("age-encryption.org/")]) != "age-encryption.org/" {
		t.Fatal("vault file should be age encrypted")
	}
}

func TestOpenWithIdentityMatchesPasswordOpen(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "vault"))
	password := []byte("password-one")
	if _, err := store.Init(password, 14); err != nil {
		t.Fatalf("init: %v", err)
	}

	opened, err := store.Open(password)
	if err != nil {
		t.Fatalf("open with password: %v", err)
	}
	if err := opened.SetGroup("shared", "TOKEN", []byte("value")); err != nil {
		opened.Close()
		t.Fatalf("set group: %v", err)
	}
	if err := opened.Save(); err != nil {
		opened.Close()
		t.Fatalf("save: %v", err)
	}
	opened.Close()

	identity, err := store.DecryptIdentity(password)
	if err != nil {
		t.Fatalf("decrypt identity: %v", err)
	}

	byIdentity, err := store.OpenWithIdentity(identity)
	if err != nil {
		t.Fatalf("open with identity: %v", err)
	}
	defer byIdentity.Close()

	keys, err := byIdentity.ListKeys("shared")
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}
	if len(keys) != 1 || keys[0] != "TOKEN" {
		t.Fatalf("unexpected keys: %#v", keys)
	}
	profile, err := byIdentity.ResolveSelection("shared")
	if err != nil {
		t.Fatalf("resolve selection: %v", err)
	}
	defer profile.Wipe()
	if got := string(profile["TOKEN"]); got != "value" {
		t.Fatalf("unexpected value: %q", got)
	}

	identityBytes := MarshalIdentity(identity)
	parsedIdentity, err := ParseIdentity(identityBytes)
	if err != nil {
		t.Fatalf("parse marshaled identity: %v", err)
	}
	if parsedIdentity.Recipient().String() != identity.Recipient().String() {
		t.Fatalf("unexpected parsed identity recipient: %q", parsedIdentity.Recipient().String())
	}
}
