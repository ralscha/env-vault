package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSetRejectsInvalidValuesWithoutChangingEntity(t *testing.T) {
	for _, kind := range []EntityKind{EntityKindApp, EntityKindGroup} {
		t.Run(string(kind), func(t *testing.T) {
			opened := &Opened{file: NewFile()}
			defer opened.Close()
			set := opened.SetApp
			if kind == EntityKindGroup {
				set = opened.SetGroup
			}
			if err := set("existing", "TOKEN", []byte("original")); err != nil {
				t.Fatal(err)
			}
			before, err := json.Marshal(opened.file)
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range [][]byte{[]byte("secret\x00value"), []byte("secret\xffvalue")} {
				for _, name := range []string{"existing", "new"} {
					err := set(name, "TOKEN", value)
					if err == nil || strings.Contains(err.Error(), "secret") {
						t.Fatalf("expected validation error without secret data, got %v", err)
					}
				}
			}
			after, err := json.Marshal(opened.file)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("rejected values changed the vault: %v", err)
			}
		})
	}
}

func TestSecretValueJSONRoundTrip(t *testing.T) {
	for _, value := range []string{"", "  spaced  ", "line one\nline two\r\n", "Grüezi 世界", "\x1b[31m"} {
		encoded, err := json.Marshal(SecretValue(value))
		if err != nil {
			t.Fatal(err)
		}
		var decoded SecretValue
		if err := json.Unmarshal(encoded, &decoded); err != nil || string(decoded) != value {
			t.Fatalf("round trip changed %q to %q: %v", value, decoded, err)
		}
	}
}

func TestLoadFileRejectsNonEnvironmentValues(t *testing.T) {
	for _, value := range []string{`null`, `"before\u0000after"`, `42`} {
		payload := []byte(`{"version":1,"groups":{"shared":{"TOKEN":` + value + `}}}`)
		if file, err := LoadFile(payload); file != nil || err == nil {
			t.Fatalf("LoadFile accepted %s: %v", value, err)
		}
	}
	if err := ValidateEntityName("invalid\xffname"); err == nil {
		t.Fatal("accepted an entity name that JSON would silently change")
	}
}

func TestResolveSelectionDoesNotAliasOrWipeStoredValues(t *testing.T) {
	opened := &Opened{file: NewFile()}
	defer opened.Close()
	opened.file.Groups["shared"] = Profile{"TOKEN": []byte("group"), "OTHER": []byte("retained")}
	opened.file.Apps["chat"] = App{Groups: []string{"shared"}, Env: Profile{"TOKEN": []byte("app")}}
	if _, err := opened.ResolveSelection("chat,missing"); !errors.Is(err, ErrNameNotFound) {
		t.Fatalf("expected missing name, got %v", err)
	}
	for range 2 {
		resolved, err := opened.ResolveSelection("shared,chat")
		if err != nil {
			t.Fatal(err)
		}
		if string(resolved["TOKEN"]) != "app" || string(resolved["OTHER"]) != "retained" {
			t.Fatalf("stored values were changed: %v", resolved)
		}
		resolved.Wipe()
	}
	if string(opened.file.Groups["shared"]["TOKEN"]) != "group" {
		t.Fatal("overridden value was wiped")
	}
}

func TestSaveClosedVault(t *testing.T) {
	opened := &Opened{file: NewFile()}
	opened.Close()
	if err := opened.Save(); err == nil {
		t.Fatal("Save after Close must return an error")
	}
}

func BenchmarkResolveSelectionOverrides(b *testing.B) {
	opened := &Opened{file: NewFile()}
	defer opened.Close()
	app := App{Env: Profile{}}
	for group := range 20 {
		name := fmt.Sprintf("group%d", group)
		profile := Profile{}
		for key := range 100 {
			profile[fmt.Sprintf("KEY_%d", key)] = bytes.Repeat([]byte("s"), 128)
		}
		opened.file.Groups[name] = profile
		app.Groups = append(app.Groups, name)
	}
	opened.file.Apps["app"] = app
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		resolved, err := opened.ResolveSelection("app")
		if err != nil {
			b.Fatal(err)
		}
		resolved.Wipe()
	}
}
