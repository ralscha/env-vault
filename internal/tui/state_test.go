package tui

import (
	"testing"

	"env-vault/internal/vault"
)

func TestFilterEntitiesMatchesAcrossNameKindAndKeys(t *testing.T) {
	items := []EntitySummary{
		{Name: "chat", Kind: vault.EntityKindApp, SearchText: "chat app openai_api_key llm"},
		{Name: "shared", Kind: vault.EntityKindGroup, SearchText: "shared group database_url"},
	}

	filtered := FilterEntities(items, "app openai")
	if len(filtered) != 1 || filtered[0].Name != "chat" {
		t.Fatalf("unexpected filter result: %#v", filtered)
	}

	filtered = FilterEntities(items, "database")
	if len(filtered) != 1 || filtered[0].Name != "shared" {
		t.Fatalf("unexpected filter result: %#v", filtered)
	}
}

func TestMaskValueKeepsSecretsHidden(t *testing.T) {
	if got := maskValue("secret-value"); got != "********" {
		t.Fatalf("unexpected mask: %q", got)
	}
	if got := maskValue("abc"); got != "***" {
		t.Fatalf("unexpected short mask: %q", got)
	}
}
