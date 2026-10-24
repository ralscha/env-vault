package vault

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestLoadFileNormalizesNullProfiles(t *testing.T) {
	file, err := LoadFile([]byte(`{"version":1,"groups":{"shared":null},"apps":{"chat":{"groups":["shared"],"env":null}}}`))
	if err != nil {
		t.Fatal(err)
	}
	opened := &Opened{file: file}
	defer opened.Close()
	if err := opened.SetGroup("shared", "TOKEN", []byte("group")); err != nil {
		t.Fatal(err)
	}
	if err := opened.SetApp("chat", "TOKEN", []byte("app")); err != nil {
		t.Fatal(err)
	}
	resolved, err := opened.ResolveSelection("chat")
	if err != nil {
		t.Fatal(err)
	}
	defer resolved.Wipe()
	if got := string(resolved["TOKEN"]); got != "app" {
		t.Fatalf("resolved TOKEN = %q, want app", got)
	}
}

func TestLoadFileRejectsInvalidEntityNames(t *testing.T) {
	for _, kind := range []EntityKind{EntityKindGroup, EntityKindApp} {
		for _, name := range []string{"", " padded", "comma,name", "control\x1b"} {
			t.Run(string(kind)+"/"+name, func(t *testing.T) {
				file := NewFile()
				if kind == EntityKindGroup {
					file.Groups[name] = Profile{"TOKEN": []byte("secret")}
				} else {
					file.Apps[name] = App{Env: Profile{"TOKEN": []byte("secret")}}
				}
				payload, err := json.Marshal(file)
				if err != nil {
					t.Fatal(err)
				}
				loaded, err := LoadFile(payload)
				if err == nil || loaded != nil {
					t.Fatalf("LoadFile returned %v, %v; want nil file and validation error", loaded, err)
				}
			})
		}
	}
}

func TestValidateRetainsSecretsForWiping(t *testing.T) {
	secret := SecretValue("sensitive")
	file := NewFile()
	file.Apps["chat"] = App{Env: Profile{"TOKEN": secret}}
	if err := file.Validate(); err != nil {
		t.Fatal(err)
	}
	file.Wipe()
	if !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Fatal("validation left an unwiped copy of the app secret")
	}
	if len(file.Metadata) != 0 {
		t.Fatal("wiping the file retained entity metadata")
	}
}

func TestSecretValueUnmarshalWipesPreviousValue(t *testing.T) {
	secret := SecretValue("long-sensitive-value")
	previous := secret
	if err := json.Unmarshal([]byte(`"new"`), &secret); err != nil {
		t.Fatal(err)
	}
	if string(secret) != "new" {
		t.Fatalf("decoded secret = %q", secret)
	}
	if !bytes.Equal(previous[len(secret):], make([]byte, len(previous)-len(secret))) {
		t.Fatal("shorter replacement left the previous secret in its backing buffer")
	}
}
