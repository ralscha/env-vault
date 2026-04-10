package tui

import (
	"path/filepath"
	"testing"

	"env-vault/internal/vault"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

func TestUpdateSearchFocusedConsumesCharacterCommands(t *testing.T) {
	search := textinput.New()
	search.CharLimit = 120
	search.Focus()

	model := Model{search: search}
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	got := updated.(Model)

	if got.form != nil {
		t.Fatal("expected search input to consume typed command character")
	}
	if got.search.Value() != "n" {
		t.Fatalf("expected search value to update, got %q", got.search.Value())
	}
}

func TestUpdateSearchBlurredAllowsGlobalCommands(t *testing.T) {
	search := textinput.New()
	search.CharLimit = 120

	model := Model{search: search}
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	got := updated.(Model)

	if got.form == nil || got.form.kind != formCreate {
		t.Fatalf("expected create form, got %#v", got.form)
	}
}

func TestNewModelStartsWithSearchBlurred(t *testing.T) {
	dir := t.TempDir()
	store := vault.NewStore(filepath.Join(dir, "vault"))
	password := []byte("correct horse battery staple")

	if _, err := store.Init(password, 14); err != nil {
		t.Fatalf("init store: %v", err)
	}

	opened, err := store.Open(password)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer opened.Close()

	model, err := NewModel(opened, store.Dir())
	if err != nil {
		t.Fatalf("new model: %v", err)
	}

	if model.search.Focused() {
		t.Fatal("expected search to start blurred")
	}
}
