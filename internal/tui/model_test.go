package tui

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"env-vault/internal/vault"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

func TestUpdateSearchFocusedConsumesCharacterCommands(t *testing.T) {
	search := textinput.New()
	search.CharLimit = 120
	search.Focus()

	model := Model{search: search}
	updated, _ := model.Update(tea.KeyPressMsg{Code: 'n', Text: "n"})
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
	updated, _ := model.Update(tea.KeyPressMsg{Code: 'n', Text: "n"})
	got := updated.(Model)

	if got.form == nil || got.form.kind != formCreate {
		t.Fatalf("expected create form, got %#v", got.form)
	}
}

func TestCtrlCQuitsFromDialogs(t *testing.T) {
	for name, model := range map[string]Model{
		"form":         {form: newCreateForm()},
		"confirmation": {confirming: true},
	} {
		t.Run(name, func(t *testing.T) {
			updated, cmd := model.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
			if !updated.(Model).quitting || cmd == nil {
				t.Fatal("Ctrl+C must quit from every dialog")
			}
			if _, ok := cmd().(tea.QuitMsg); !ok {
				t.Fatal("expected quit command")
			}
		})
	}
}

func TestSearchFocusStartsBlinking(t *testing.T) {
	model := Model{search: textinput.New()}
	updated, cmd := model.Update(tea.KeyPressMsg{Code: '/', Text: "/"})
	if !updated.(Model).search.Focused() || cmd == nil {
		t.Fatal("search must focus and start the cursor when opened")
	}
}

func TestFormOptionFilterAcceptsNavigationLetters(t *testing.T) {
	model := Model{form: newOptionForm(formLink, "Link", "", []string{"jack", "other"})}
	for _, letter := range "jack" {
		_, _ = model.Update(tea.KeyPressMsg{Code: letter, Text: string(letter)})
	}
	if got := model.form.optionFilter.Value(); got != "jack" {
		t.Fatalf("filter = %q, want jack", got)
	}
	if got := filteredFormOptions(model.form); len(got) != 1 || got[0] != "jack" {
		t.Fatalf("matches = %v, want [jack]", got)
	}
}

func TestFormReceivesPasteMessages(t *testing.T) {
	for name, form := range map[string]*formState{
		"field":  newCreateForm(),
		"filter": newOptionForm(formLink, "Link", "", []string{"jack"}),
	} {
		t.Run(name, func(t *testing.T) {
			model := Model{form: form, search: textinput.New()}
			_, _ = model.Update(tea.PasteMsg{Content: "jack"})
			got := form.optionFilter.Value()
			if len(form.fields) > 0 {
				got = form.fields[0].input.Value()
			}
			if got != "jack" || model.search.Value() != "" {
				t.Fatalf("paste must go to active dialog, got %q", got)
			}
		})
	}
}

func TestFormArrowKeysEditText(t *testing.T) {
	for name, form := range map[string]*formState{
		"rename": newSingleValueForm(formRename, "Rename", "Name", "ac"),
		"create": newCreateForm(),
	} {
		t.Run(name, func(t *testing.T) {
			form.fields[0].input.SetValue("ac")
			model := Model{form: form}
			_, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyLeft})
			_, _ = model.Update(tea.KeyPressMsg{Code: 'b', Text: "b"})
			if got := form.fields[0].input.Value(); got != "abc" {
				t.Fatalf("editing text with arrow keys produced %q, want abc", got)
			}
		})
	}
}

func TestCreateKindHasSeparateShortcut(t *testing.T) {
	model := Model{form: newCreateForm()}
	_, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyRight, Mod: tea.ModCtrl})
	if model.form.choice != vault.EntityKindGroup {
		t.Fatal("Ctrl+Right must switch entity kind")
	}
}

func TestFormValidationKeepsInput(t *testing.T) {
	model := Model{form: newCreateForm()}
	updated, _ := model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	got := updated.(*Model)
	if got.form == nil || got.status != "name is required" {
		t.Fatalf("invalid input must leave form open with error, got %#v", got)
	}
}

func TestPlaceOverlayFitsBackground(t *testing.T) {
	background := strings.Repeat(strings.Repeat(".", 30)+"\n", 9) + strings.Repeat(".", 30)
	got := placeOverlay(background, "dialog")
	if lipgloss.Width(got) != 30 || lipgloss.Height(got) != 10 {
		t.Fatalf("overlay changed screen dimensions to %dx%d", lipgloss.Width(got), lipgloss.Height(got))
	}
	if !strings.Contains(strings.Split(got, "\n")[4], "dialog") {
		t.Fatal("dialog must be centered over background")
	}
}

func TestViewUsesAlternateScreen(t *testing.T) {
	if !((Model{}).View().AltScreen) {
		t.Fatal("TUI must request the alternate screen through its view")
	}
}

func TestViewKeepsSelectedEntityVisibleWithinScreen(t *testing.T) {
	model := Model{width: 120, height: 30, styles: defaultStyles(), search: textinput.New()}
	for index := range 40 {
		model.filtered = append(model.filtered, EntitySummary{Name: fmt.Sprintf("group-%02d", index), Kind: vault.EntityKindGroup})
	}
	model.selected = len(model.filtered) - 1
	model.selectedName = model.filtered[model.selected].Name
	got := model.renderView()
	if lipgloss.Width(got) > model.width || lipgloss.Height(got) > model.height {
		t.Fatalf("view is %dx%d, exceeds %dx%d terminal", lipgloss.Width(got), lipgloss.Height(got), model.width, model.height)
	}
	if !strings.Contains(got, model.selectedName) {
		t.Fatal("selected entity must remain visible after scrolling")
	}
}

func TestFormSaveConflictReloadsAndCanRetry(t *testing.T) {
	model, other := newModelsForConcurrentEdit(t)
	model.form = newCreateForm()
	model.form.fields[0].input.SetValue("new-app")
	if err := other.CreateName(vault.EntityKindGroup, "external"); err != nil {
		t.Fatal(err)
	}
	if err := other.Save(); err != nil {
		t.Fatal(err)
	}

	updated, _ := model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	got := updated.(*Model)
	if got.form == nil || !strings.Contains(got.status, vault.ErrConflict.Error()) {
		t.Fatalf("conflict must retain dialog input and report failure: form=%v status=%q", got.form, got.status)
	}
	if got.opened.Kind("new-app") != vault.EntityKindUnknown || got.opened.Kind("external") != vault.EntityKindGroup {
		t.Fatal("failed save must discard pending creation and load external changes")
	}

	updated, _ = got.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	got = updated.(*Model)
	if got.form != nil || got.status != "Created app new-app" {
		t.Fatalf("retry failed: form=%v status=%q", got.form, got.status)
	}
	if err := other.Reload(); err != nil {
		t.Fatal(err)
	}
	if other.Kind("new-app") != vault.EntityKindApp || other.Kind("external") != vault.EntityKindGroup {
		t.Fatal("retry must persist the edit and preserve external changes")
	}
}

func TestRefreshLoadsExternalChanges(t *testing.T) {
	model, other := newModelsForConcurrentEdit(t)
	if err := other.CreateName(vault.EntityKindGroup, "external"); err != nil {
		t.Fatal(err)
	}
	if err := other.Save(); err != nil {
		t.Fatal(err)
	}
	updated, _ := model.Update(tea.KeyPressMsg{Code: 'r', Mod: tea.ModCtrl})
	got := updated.(Model)
	if got.status != "" || len(got.items) != 1 || got.items[0].Name != "external" {
		t.Fatalf("refresh did not load external change: items=%v status=%q", got.items, got.status)
	}
}

func TestFormRetryDoesNotEditReplacementSelection(t *testing.T) {
	model, other := newModelsForConcurrentEdit(t)
	if err := model.opened.CreateName(vault.EntityKindGroup, "original"); err != nil {
		t.Fatal(err)
	}
	if err := model.opened.Save(); err != nil {
		t.Fatal(err)
	}
	if err := model.reloadSelection("original"); err != nil {
		t.Fatal(err)
	}
	if err := other.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := other.RemoveName("original"); err != nil {
		t.Fatal(err)
	}
	if err := other.CreateName(vault.EntityKindGroup, "replacement"); err != nil {
		t.Fatal(err)
	}
	if err := other.Save(); err != nil {
		t.Fatal(err)
	}
	model.form = newKeyValueForm("Set key")
	model.form.fields[0].input.SetValue("SECRET")
	model.form.fields[1].input.SetValue("value")
	updated, _ := model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	got := updated.(*Model)
	if got.selectedName != "replacement" {
		t.Fatalf("expected reload to select replacement, got %q", got.selectedName)
	}
	updated, _ = got.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	got = updated.(*Model)
	if got.form == nil || got.status != "no entity selected" {
		t.Fatalf("retry must fail after original entity was removed, status=%q", got.status)
	}
	keys, err := model.opened.ListKeys("replacement")
	if err != nil || len(keys) != 0 {
		t.Fatalf("retry must not set key on replacement entity, keys=%v err=%v", keys, err)
	}
}

func newModelsForConcurrentEdit(t *testing.T) (Model, *vault.Opened) {
	t.Helper()
	store := vault.NewStore(t.TempDir())
	password := []byte("test-password")
	if _, err := store.Init(password, 14); err != nil {
		t.Fatal(err)
	}
	opened, err := store.Open(password)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(opened.Close)
	other, err := store.Open(password)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	model, err := NewModel(opened, store.Dir())
	if err != nil {
		t.Fatal(err)
	}
	return model, other
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
