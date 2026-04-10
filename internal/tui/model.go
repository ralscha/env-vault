package tui

import (
	"fmt"
	"strings"
	"time"

	"env-vault/internal/vault"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type formKind string

const (
	keyEscape = "esc"

	formCreate formKind = "create"
	formRename formKind = "rename"
	formCopy   formKind = "copy"
	formSetKey formKind = "set-key"
	formUnset  formKind = "unset-key"
	formLink   formKind = "link"
	formUnlink formKind = "unlink"
)

type formField struct {
	label string
	input textinput.Model
}

type formState struct {
	kind           formKind
	title          string
	message        string
	fields         []formField
	options        []string
	optionFilter   textinput.Model
	focus          int
	selectedOption int
	choice         vault.EntityKind
}

type Model struct {
	opened       *vault.Opened
	dir          string
	width        int
	height       int
	search       textinput.Model
	items        []EntitySummary
	filtered     []EntitySummary
	selected     int
	selectedName string
	details      EntityDetails
	revealValues bool
	status       string
	form         *formState
	confirming   bool
	quitting     bool

	styles styles
}

type styles struct {
	appBadge        lipgloss.Style
	groupBadge      lipgloss.Style
	header          lipgloss.Style
	border          lipgloss.Style
	selectedItem    lipgloss.Style
	selectedMeta    lipgloss.Style
	item            lipgloss.Style
	muted           lipgloss.Style
	status          lipgloss.Style
	value           lipgloss.Style
	warning         lipgloss.Style
	footer          lipgloss.Style
	actionBar       lipgloss.Style
	actionKey       lipgloss.Style
	actionText      lipgloss.Style
	modal           lipgloss.Style
	modalTitle      lipgloss.Style
	inputLabel      lipgloss.Style
	modalField      lipgloss.Style
	modalFieldFocus lipgloss.Style
	modalHelp       lipgloss.Style
	section         lipgloss.Style
	selectionBorder lipgloss.Style
}

func NewModel(opened *vault.Opened, dir string) (Model, error) {
	items, err := LoadInventory(opened)
	if err != nil {
		return Model{}, err
	}

	search := textinput.New()
	search.Placeholder = "Search names, kinds, keys, groups"
	search.Prompt = "/ "
	search.CharLimit = 120
	search.Width = 32

	m := Model{
		opened:   opened,
		dir:      dir,
		search:   search,
		items:    items,
		filtered: append([]EntitySummary(nil), items...),
		styles:   defaultStyles(),
	}
	if len(m.filtered) > 0 {
		m.selectedName = m.filtered[0].Name
		if err := m.syncDetails(); err != nil {
			return Model{}, err
		}
	}
	return m, nil
}

func defaultStyles() styles {
	borderColor := lipgloss.Color("63")
	panelColor := lipgloss.Color("238")
	selectedColor := lipgloss.Color("69")
	return styles{
		appBadge:        lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("25")).Padding(0, 1),
		groupBadge:      lipgloss.NewStyle().Foreground(lipgloss.Color("232")).Background(lipgloss.Color("221")).Padding(0, 1),
		header:          lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")),
		border:          lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(panelColor).Padding(0, 1),
		selectedItem:    lipgloss.NewStyle().Foreground(lipgloss.Color("255")).Background(selectedColor).Padding(0, 1),
		selectedMeta:    lipgloss.NewStyle().Foreground(lipgloss.Color("255")).Background(selectedColor).Faint(false),
		item:            lipgloss.NewStyle().Padding(0, 1),
		muted:           lipgloss.NewStyle().Foreground(lipgloss.Color("245")),
		status:          lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("29")).Padding(0, 1),
		value:           lipgloss.NewStyle().Foreground(lipgloss.Color("151")),
		warning:         lipgloss.NewStyle().Foreground(lipgloss.Color("223")).Background(lipgloss.Color("52")).Padding(0, 1),
		footer:          lipgloss.NewStyle().Foreground(lipgloss.Color("248")),
		actionBar:       lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Background(lipgloss.Color("237")).Padding(0, 1),
		actionKey:       lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("24")).Padding(0, 1),
		actionText:      lipgloss.NewStyle().Foreground(lipgloss.Color("252")),
		modal:           lipgloss.NewStyle().Border(lipgloss.DoubleBorder()).BorderForeground(borderColor).Padding(1, 2).Background(lipgloss.Color("236")),
		modalTitle:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")),
		inputLabel:      lipgloss.NewStyle().Foreground(lipgloss.Color("252")),
		modalField:      lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("240")).Padding(0, 1),
		modalFieldFocus: lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(selectedColor).Padding(0, 1),
		modalHelp:       lipgloss.NewStyle().Foreground(lipgloss.Color("248")),
		section:         lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("153")),
		selectionBorder: lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(borderColor).Padding(0, 1),
	}
}

func (m Model) Init() tea.Cmd {
	return textinput.Blink
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.quitting {
		return m, tea.Quit
	}

	var cmd tea.Cmd
	switch typed := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = typed.Width
		m.height = typed.Height
		m.search.Width = max(12, typed.Width-10)
		return m, nil
	case tea.KeyMsg:
		if m.form != nil {
			return m.updateForm(typed)
		}
		if m.confirming {
			return m.updateConfirm(typed)
		}
		if m.search.Focused() {
			switch typed.String() {
			case "ctrl+c":
				m.quitting = true
				return m, tea.Quit
			case keyEscape:
				m.search.Blur()
				return m, nil
			}
			m.search, cmd = m.search.Update(msg)
			m.applyFilter()
			return m, cmd
		}
		switch typed.String() {
		case "ctrl+c", "q":
			m.quitting = true
			return m, tea.Quit
		case "up", "k":
			m.moveSelection(-1)
			return m, nil
		case "down", "j":
			m.moveSelection(1)
			return m, nil
		case "/":
			m.search.Focus()
			return m, nil
		case keyEscape:
			m.search.Blur()
			return m, nil
		case "n":
			m.form = newCreateForm()
			return m, nil
		case "r":
			if m.hasSelection() {
				m.form = newSingleValueForm(formRename, "Rename entity", "New name", m.selectedName)
			}
			return m, nil
		case "y":
			if m.hasSelection() {
				m.form = newSingleValueForm(formCopy, "Copy entity", "Destination name", m.selectedName+"-copy")
			}
			return m, nil
		case "a":
			if m.hasSelection() {
				m.form = newKeyValueForm("Set direct key")
			}
			return m, nil
		case "d":
			if m.hasSelection() {
				keys := directKeys(m.details.Direct)
				if len(keys) == 0 {
					m.status = "No direct keys to remove"
					return m, nil
				}
				m.form = newOptionForm(formUnset, "Unset direct key", "Choose a direct key to remove.", keys)
			}
			return m, nil
		case "l":
			if m.hasSelection() && m.details.Summary.Kind == vault.EntityKindApp {
				groups := availableLinkGroups(m.items, m.details.LinkedGroups)
				if len(groups) == 0 {
					m.status = "No groups available to link"
					return m, nil
				}
				m.form = newOptionForm(formLink, "Link group to app", "Choose a group to add to the app.", groups)
			}
			return m, nil
		case "u":
			if m.hasSelection() && m.details.Summary.Kind == vault.EntityKindApp {
				if len(m.details.LinkedGroups) == 0 {
					m.status = "No linked groups to unlink"
					return m, nil
				}
				m.form = newOptionForm(formUnlink, "Unlink group from app", "Choose a linked group to remove from the app.", append([]string(nil), m.details.LinkedGroups...))
			}
			return m, nil
		case "x":
			if m.hasSelection() {
				m.confirming = true
			}
			return m, nil
		case "v":
			m.revealValues = !m.revealValues
			return m, nil
		case "ctrl+r":
			m.status = ""
			_ = m.reloadSelection(m.selectedName)
			return m, nil
		}
		m.search, cmd = m.search.Update(msg)
		m.applyFilter()
		return m, cmd
	}

	m.search, cmd = m.search.Update(msg)
	m.applyFilter()
	return m, cmd
}

func (m Model) View() string {
	if m.width == 0 || m.height == 0 {
		return "Loading..."
	}

	header := m.renderHeader()
	body := m.renderBody()
	footer := m.renderFooter()
	content := lipgloss.JoinVertical(lipgloss.Left, header, body, footer)

	if m.form != nil {
		return placeOverlay(content, m.renderForm())
	}
	if m.confirming {
		return placeOverlay(content, m.renderConfirm())
	}
	return content
}

func (m *Model) updateForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	form := m.form
	if form == nil {
		return m, nil
	}

	switch msg.String() {
	case keyEscape:
		m.form = nil
		return m, nil
	case "j", "down":
		if len(form.options) > 0 {
			filtered := filteredFormOptions(form)
			if len(filtered) == 0 {
				return m, nil
			}
			form.selectedOption = (form.selectedOption + 1) % len(filtered)
			return m, nil
		}
	case "k", "up":
		if len(form.options) > 0 {
			filtered := filteredFormOptions(form)
			if len(filtered) == 0 {
				return m, nil
			}
			form.selectedOption = (form.selectedOption - 1 + len(filtered)) % len(filtered)
			return m, nil
		}
	case "tab", "shift+tab":
		if len(form.options) > 0 {
			filtered := filteredFormOptions(form)
			if len(filtered) == 0 {
				return m, nil
			}
			delta := -1
			if msg.String() == "tab" {
				delta = 1
			}
			form.selectedOption = (form.selectedOption + delta + len(filtered)) % len(filtered)
			return m, nil
		}
		delta := 1
		if msg.String() == "shift+tab" {
			delta = -1
		}
		form.focus = (form.focus + delta + len(form.fields)) % len(form.fields)
		for index := range form.fields {
			if index == form.focus {
				form.fields[index].input.Focus()
			} else {
				form.fields[index].input.Blur()
			}
		}
		return m, nil
	case "left", "right":
		if form.kind == formCreate {
			if form.choice == vault.EntityKindApp {
				form.choice = vault.EntityKindGroup
			} else {
				form.choice = vault.EntityKindApp
			}
		}
		return m, nil
	case "ctrl+s":
		if len(form.options) > 0 {
			return m, nil
		}
		if err := m.submitForm(); err != nil {
			m.status = err.Error()
			m.form = nil
			return m, nil
		}
		m.form = nil
		return m, nil
	case "enter":
		if err := m.submitForm(); err != nil {
			m.status = err.Error()
			m.form = nil
			return m, nil
		}
		m.form = nil
		return m, nil
	}

	if len(form.options) > 0 {
		updated, cmd := form.optionFilter.Update(msg)
		form.optionFilter = updated
		clampSelectedOption(form)
		return m, cmd
	}

	current := &form.fields[form.focus].input
	updated, cmd := current.Update(msg)
	form.fields[form.focus].input = updated
	return m, cmd
}

func (m *Model) updateConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case keyEscape, "n":
		m.confirming = false
		return m, nil
	case "y", "enter":
		name := m.selectedName
		if err := m.opened.RemoveName(name); err != nil {
			m.status = err.Error()
			m.confirming = false
			return m, nil
		}
		if err := m.opened.Save(); err != nil {
			m.status = err.Error()
			m.confirming = false
			return m, nil
		}
		m.confirming = false
		if err := m.reloadSelection(""); err != nil {
			m.status = err.Error()
			return m, nil
		}
		m.status = fmt.Sprintf("Removed %s", name)
		return m, nil
	default:
		return m, nil
	}
}

func (m *Model) submitForm() error {
	if m.form == nil {
		return nil
	}
	values := make([]string, 0, len(m.form.fields))
	for _, field := range m.form.fields {
		values = append(values, strings.TrimSpace(field.input.Value()))
	}
	selectedOption := ""
	if len(m.form.options) > 0 {
		filtered := filteredFormOptions(m.form)
		if len(filtered) > 0 {
			selectedOption = filtered[m.form.selectedOption]
		}
	}

	selected := m.selectedName
	var status string
	switch m.form.kind {
	case formCreate:
		if values[0] == "" {
			return fmt.Errorf("name is required")
		}
		if err := m.opened.CreateName(m.form.choice, values[0]); err != nil {
			return err
		}
		status = fmt.Sprintf("Created %s %s", m.form.choice, values[0])
		selected = values[0]
	case formRename:
		if values[0] == "" {
			return fmt.Errorf("new name is required")
		}
		kind, err := m.opened.RenameName(selected, values[0])
		if err != nil {
			return err
		}
		status = fmt.Sprintf("Renamed %s %s to %s", kind, selected, values[0])
		selected = values[0]
	case formCopy:
		if values[0] == "" {
			return fmt.Errorf("destination name is required")
		}
		kind, err := m.opened.CopyName(selected, values[0])
		if err != nil {
			return err
		}
		status = fmt.Sprintf("Copied %s %s to %s", kind, selected, values[0])
		selected = values[0]
	case formSetKey:
		if values[0] == "" {
			return fmt.Errorf("key is required")
		}
		switch m.details.Summary.Kind {
		case vault.EntityKindUnknown:
			return fmt.Errorf("no entity selected")
		case vault.EntityKindApp:
			if err := m.opened.SetApp(selected, values[0], []byte(m.form.fields[1].input.Value())); err != nil {
				return err
			}
		case vault.EntityKindGroup:
			if err := m.opened.SetGroup(selected, values[0], []byte(m.form.fields[1].input.Value())); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported entity kind %q", m.details.Summary.Kind)
		}
		status = fmt.Sprintf("Stored %s in %s", values[0], selected)
	case formUnset:
		if selectedOption == "" {
			return fmt.Errorf("key is required")
		}
		if err := m.opened.Unset(selected, selectedOption); err != nil {
			return err
		}
		status = fmt.Sprintf("Removed %s from %s", selectedOption, selected)
	case formLink:
		if selectedOption == "" {
			return fmt.Errorf("group name is required")
		}
		if err := m.opened.LinkAppGroup(selected, selectedOption); err != nil {
			return err
		}
		status = fmt.Sprintf("Linked %s to %s", selectedOption, selected)
	case formUnlink:
		if selectedOption == "" {
			return fmt.Errorf("group name is required")
		}
		if err := m.opened.UnlinkAppGroup(selected, selectedOption); err != nil {
			return err
		}
		status = fmt.Sprintf("Unlinked %s from %s", selectedOption, selected)
	default:
		return fmt.Errorf("unsupported form %q", m.form.kind)
	}

	if err := m.opened.Save(); err != nil {
		return err
	}
	if err := m.reloadSelection(selected); err != nil {
		return err
	}
	m.status = status
	return nil
}

func (m *Model) reloadSelection(selected string) error {
	items, err := LoadInventory(m.opened)
	if err != nil {
		return err
	}
	m.items = items
	m.applyFilter()
	if selected != "" {
		m.selectByName(selected)
	}
	return m.syncDetails()
}

func (m *Model) applyFilter() {
	m.filtered = FilterEntities(m.items, m.search.Value())
	if len(m.filtered) == 0 {
		m.selected = 0
		m.selectedName = ""
		m.details = EntityDetails{}
		return
	}
	if m.selectedName != "" {
		for index, item := range m.filtered {
			if item.Name == m.selectedName {
				m.selected = index
				return
			}
		}
	}
	m.selected = 0
	m.selectedName = m.filtered[0].Name
	_ = m.syncDetails()
}

func (m *Model) selectByName(name string) {
	for index, item := range m.filtered {
		if item.Name == name {
			m.selected = index
			m.selectedName = name
			return
		}
	}
	if len(m.filtered) > 0 {
		m.selected = 0
		m.selectedName = m.filtered[0].Name
	}
}

func (m *Model) moveSelection(delta int) {
	if len(m.filtered) == 0 {
		return
	}
	m.selected = (m.selected + delta + len(m.filtered)) % len(m.filtered)
	m.selectedName = m.filtered[m.selected].Name
	if err := m.syncDetails(); err != nil {
		m.status = err.Error()
	}
}

func (m *Model) syncDetails() error {
	if m.selectedName == "" {
		m.details = EntityDetails{}
		return nil
	}
	details, err := LoadDetails(m.opened, m.selectedName)
	if err != nil {
		return err
	}
	m.details = details
	return nil
}

func (m Model) renderHeader() string {
	title := m.styles.header.Render("env-vault-tui")
	compact := m.height > 0 && m.height < 22
	searchStyle := m.styles.modalField
	if m.search.Focused() {
		searchStyle = m.styles.modalFieldFocus
	}
	searchBox := searchStyle.Render(m.search.View())
	lines := []string{title}
	if !compact {
		lines = append(lines, m.styles.muted.Render(m.dir))
	}
	lines = append(lines, searchBox)
	return lipgloss.NewStyle().Width(m.width).Padding(0, 1).Render(strings.Join(lines, "\n"))
}

func (m Model) renderBody() string {
	headerHeight := 3
	if m.height >= 22 {
		headerHeight = 4
	}
	footerHeight := m.footerLineCount(max(12, m.width-4))
	bodyHeight := max(9, m.height-headerHeight-footerHeight-1)
	leftWidth := max(26, min(40, m.width/3))
	rightWidth := max(40, m.width-leftWidth-3)
	left := m.styles.border.Width(leftWidth).Height(bodyHeight).Render(m.renderList(leftWidth - 4))
	right := m.styles.selectionBorder.Width(rightWidth).Height(bodyHeight).Render(m.renderDetails(bodyHeight - 2))
	return lipgloss.NewStyle().Padding(0, 1).Render(lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right))
}

func (m Model) renderFooter() string {
	lines := []string{}
	if m.status != "" {
		lines = append(lines, lipgloss.NewStyle().Width(m.width).Padding(0, 1).Render(m.styles.footer.Render(m.status)))
	}
	for _, line := range m.actionBarLines(max(12, m.width-4)) {
		lines = append(lines, lipgloss.NewStyle().Width(m.width).Padding(0, 1).Render(m.styles.actionBar.Render(line)))
	}
	return strings.Join(lines, "\n")
}

func (m Model) renderList(width int) string {
	lines := []string{m.styles.section.Render("Entities")}
	if len(m.filtered) == 0 {
		lines = append(lines, m.styles.muted.Render("No matching apps or groups."))
		return strings.Join(lines, "\n")
	}
	compact := m.height > 0 && m.height < 22
	for index, item := range m.filtered {
		badge := m.styles.groupBadge.Render("GROUP")
		meta := fmt.Sprintf("%d keys", item.DirectKeyCount)
		if item.Kind == vault.EntityKindApp {
			badge = m.styles.appBadge.Render("APP")
			meta = fmt.Sprintf("%d keys, %d groups", item.DirectKeyCount, item.LinkedGroupCount)
		}
		var line string
		if compact {
			metaInline := m.styles.muted.Render("(" + meta + ")")
			line = lipgloss.JoinHorizontal(lipgloss.Top, badge, " ", item.Name, " ", metaInline)
		} else {
			nameLine := lipgloss.JoinHorizontal(lipgloss.Top, badge, " ", item.Name)
			metaLine := m.styles.muted.Render(meta)
			line = lipgloss.JoinVertical(lipgloss.Left, nameLine, metaLine)
			if index == m.selected {
				line = lipgloss.JoinVertical(lipgloss.Left, nameLine, m.styles.selectedMeta.Render(meta))
			}
		}
		if index == m.selected {
			lines = append(lines, m.styles.selectedItem.Width(width).Render(line))
			continue
		}
		lines = append(lines, m.styles.item.Width(width).Render(line))
	}
	return strings.Join(lines, "\n")
}

func (m Model) renderDetails(height int) string {
	if !m.hasSelection() {
		return m.styles.muted.Render("Select an entity to inspect and edit it.")
	}
	details := m.details
	badge := m.styles.groupBadge.Render(strings.ToUpper(string(details.Summary.Kind)))
	if details.Summary.Kind == vault.EntityKindApp {
		badge = m.styles.appBadge.Render(strings.ToUpper(string(details.Summary.Kind)))
	}
	sections := []string{
		lipgloss.JoinHorizontal(lipgloss.Top, badge, " ", m.styles.header.Render(details.Summary.Name)),
		m.styles.muted.Render(formatTimestampLine(details.Summary.CreatedAt, details.Summary.ModifiedAt)),
		"",
		m.styles.section.Render("Direct"),
		renderKeyValues(details.Direct, m.revealValues, m.styles),
	}
	if details.Summary.Kind == vault.EntityKindApp {
		sections = append(sections, "", m.styles.section.Render("Linked Groups"), renderLinkedGroups(details.LinkedGroups, m.styles))
		sections = append(sections, "", m.styles.section.Render("Resolved Preview"), renderKeyValues(details.Resolved, m.revealValues, m.styles))
	}
	content := strings.Join(sections, "\n")
	return truncateLines(content, height)
}

func (m Model) renderForm() string {
	lines := []string{m.styles.modalTitle.Render(m.form.title)}
	if m.form.kind == formCreate {
		lines = append(lines, "", m.styles.inputLabel.Render("Kind"), renderKindChoice(m.form.choice, m.styles))
	}
	if m.form.message != "" {
		lines = append(lines, "", m.styles.muted.Render(m.form.message))
	}
	if len(m.form.options) > 0 {
		lines = append(lines, "", m.styles.inputLabel.Render("Filter"), m.styles.modalFieldFocus.Render(m.form.optionFilter.View()))
		lines = append(lines, renderFormOptions(filteredFormOptions(m.form), m.form.selectedOption, m.styles))
	}
	for index, field := range m.form.fields {
		fieldStyle := m.styles.modalField
		if index == m.form.focus {
			fieldStyle = m.styles.modalFieldFocus
		}
		lines = append(lines, "", m.styles.inputLabel.Render(field.label), fieldStyle.Render(field.input.View()))
	}
	lines = append(lines, "", m.styles.modalHelp.Render(m.renderModalHelp()))
	return m.styles.modal.Width(min(72, max(40, m.width/2))).Render(strings.Join(lines, "\n"))
}

func (m Model) renderConfirm() string {
	message := fmt.Sprintf("Remove %s %s?\n\nThis cannot be undone from the TUI.\n\nPress y to confirm or Esc to cancel.", m.details.Summary.Kind, m.selectedName)
	return m.styles.modal.Width(min(72, max(40, m.width/2))).Render(strings.Join([]string{
		m.styles.modalTitle.Render("Remove entity"),
		"",
		message,
	}, "\n"))
}

func newCreateForm() *formState {
	name := textinput.New()
	name.Placeholder = "chat"
	name.Focus()
	return &formState{
		kind:   formCreate,
		title:  "Create entity",
		choice: vault.EntityKindApp,
		fields: []formField{{label: "Name", input: name}},
	}
}

func newSingleValueForm(kind formKind, title, label, value string) *formState {
	input := textinput.New()
	input.SetValue(value)
	input.Focus()
	return &formState{kind: kind, title: title, fields: []formField{{label: label, input: input}}}
}

func newOptionForm(kind formKind, title, message string, options []string) *formState {
	filter := textinput.New()
	filter.Placeholder = "Type to filter options"
	filter.Prompt = "> "
	filter.CharLimit = 120
	filter.Focus()
	return &formState{kind: kind, title: title, message: message, options: options, optionFilter: filter}
}

func newKeyValueForm(title string) *formState {
	keyInput := textinput.New()
	keyInput.Placeholder = "DATABASE_URL"
	keyInput.Focus()
	valueInput := textinput.New()
	valueInput.Placeholder = "secret"
	valueInput.EchoMode = textinput.EchoPassword
	valueInput.EchoCharacter = '•'
	return &formState{
		kind:  formSetKey,
		title: title,
		fields: []formField{
			{label: "Key", input: keyInput},
			{label: "Value", input: valueInput},
		},
	}
}

func renderKindChoice(kind vault.EntityKind, styles styles) string {
	container := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("240")).
		Padding(0, 0)

	baseSegment := lipgloss.NewStyle().
		Width(12).
		Align(lipgloss.Center).
		Padding(0, 1).
		Foreground(lipgloss.Color("248"))

	selectedApp := baseSegment.
		Foreground(lipgloss.Color("255")).
		Background(lipgloss.Color("25")).
		Bold(true)

	selectedGroup := baseSegment.
		Foreground(lipgloss.Color("232")).
		Background(lipgloss.Color("221")).
		Bold(true)

	divider := lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("│")

	app := baseSegment.Render("APP")
	group := baseSegment.Render("GROUP")
	if kind == vault.EntityKindApp {
		app = selectedApp.Render("APP")
	} else {
		group = selectedGroup.Render("GROUP")
	}

	control := lipgloss.JoinHorizontal(lipgloss.Top, app, divider, group)
	help := styles.muted.Render("Left/Right switches the selection")
	return lipgloss.JoinVertical(lipgloss.Left, container.Render(control), help)
}

func (m Model) actionBarLines(width int) []string {
	actions := m.contextActions()
	parts := make([]string, 0, len(actions))
	for _, action := range actions {
		parts = append(parts, lipgloss.JoinHorizontal(lipgloss.Center, m.styles.actionKey.Render(action.key), " ", m.styles.actionText.Render(action.label)))
	}
	if len(parts) == 0 {
		return []string{""}
	}

	lines := []string{}
	current := ""
	for _, part := range parts {
		candidate := part
		if current != "" {
			candidate = current + "   " + part
		}
		if current != "" && lipgloss.Width(candidate) > width {
			lines = append(lines, current)
			current = part
			continue
		}
		current = candidate
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

func (m Model) renderModalHelp() string {
	if m.form != nil && len(m.form.options) > 0 {
		return strings.Join([]string{
			shortAction("Type", "filter"),
			shortAction("↑↓", "choose"),
			shortAction("J/K", "move"),
			shortAction("Enter", "confirm"),
			shortAction("Esc", "cancel"),
		}, "   ")
	}

	parts := []string{
		shortAction("Tab", "next field"),
		shortAction("Shift+Tab", "previous"),
		shortAction("Enter", "save"),
		shortAction("Ctrl+S", "save"),
		shortAction("Esc", "cancel"),
	}
	if m.form != nil && m.form.kind == formCreate {
		parts = append(parts, shortAction("Left/Right", "switch kind"))
	}
	return strings.Join(parts, "   ")
}

type actionItem struct {
	key   string
	label string
}

func (m Model) contextActions() []actionItem {
	if m.form != nil {
		if len(m.form.options) > 0 {
			return []actionItem{
				{key: "Type", label: "filter"},
				{key: "↑↓", label: "choose"},
				{key: "J/K", label: "move"},
				{key: "Enter", label: "confirm"},
				{key: "Esc", label: "cancel"},
			}
		}
		return []actionItem{
			{key: "Tab", label: "next field"},
			{key: "Shift+Tab", label: "previous field"},
			{key: "Enter", label: "save"},
			{key: "Ctrl+S", label: "save"},
			{key: "Esc", label: "cancel"},
		}
	}
	if m.confirming {
		return []actionItem{
			{key: "Y", label: "confirm remove"},
			{key: "Esc", label: "cancel"},
		}
	}
	if m.search.Focused() {
		return []actionItem{
			{key: "Type", label: "filter"},
			{key: "Esc", label: "leave search"},
			{key: "Ctrl+C", label: "quit"},
		}
	}
	if !m.hasSelection() {
		return []actionItem{
			{key: "/", label: "search"},
			{key: "N", label: "new entity"},
			{key: "Q", label: "quit"},
		}
	}

	actions := []actionItem{
		{key: "↑↓", label: "move"},
		{key: "/", label: "search"},
		{key: "N", label: "new"},
		{key: "A", label: "set key"},
		{key: "D", label: "unset key"},
		{key: "R", label: "rename"},
		{key: "Y", label: "copy"},
		{key: "X", label: "remove"},
		{key: "V", label: toggleLabel(m.revealValues)},
		{key: "Ctrl+R", label: "refresh"},
	}
	if m.details.Summary.Kind == vault.EntityKindApp {
		actions = append(actions,
			actionItem{key: "L", label: "link group"},
			actionItem{key: "U", label: "unlink group"},
		)
	}
	return actions
}

func toggleLabel(reveal bool) string {
	if reveal {
		return "hide values"
	}
	return "show values"
}

func shortAction(key, label string) string {
	return key + " " + label
}

func (m Model) footerLineCount(width int) int {
	count := len(m.actionBarLines(width))
	if count == 0 {
		count = 1
	}
	if m.status != "" {
		count++
	}
	return count
}

func renderKeyValues(values []KeyValue, reveal bool, styles styles) string {
	if len(values) == 0 {
		return styles.muted.Render("No keys")
	}
	lines := make([]string, 0, len(values))
	for _, pair := range values {
		value := maskValue(pair.Value)
		if reveal {
			value = pair.Value
		}
		lines = append(lines, fmt.Sprintf("%s = %s", pair.Key, styles.value.Render(value)))
	}
	return strings.Join(lines, "\n")
}

func renderLinkedGroups(groups []string, styles styles) string {
	if len(groups) == 0 {
		return styles.muted.Render("No linked groups")
	}
	return strings.Join(groups, "\n")
}

func renderFormOptions(options []string, selected int, styles styles) string {
	if len(options) == 0 {
		return styles.muted.Render("No matching options")
	}

	start, end := optionWindow(len(options), selected, 6)
	visible := options[start:end]
	lines := make([]string, 0, len(visible)+2)
	if start > 0 {
		lines = append(lines, styles.muted.Render(fmt.Sprintf("%d earlier matches", start)))
	}
	for offset, option := range visible {
		index := start + offset
		prefix := "  "
		style := styles.modalField
		if index == selected {
			prefix = "› "
			style = styles.modalFieldFocus
		}
		lines = append(lines, style.Render(prefix+option))
	}
	if end < len(options) {
		lines = append(lines, styles.muted.Render(fmt.Sprintf("%d more matches", len(options)-end)))
	}
	return strings.Join(lines, "\n")
}

func directKeys(values []KeyValue) []string {
	keys := make([]string, 0, len(values))
	for _, value := range values {
		keys = append(keys, value.Key)
	}
	return keys
}

func availableLinkGroups(items []EntitySummary, linkedGroups []string) []string {
	linked := make(map[string]struct{}, len(linkedGroups))
	for _, group := range linkedGroups {
		linked[group] = struct{}{}
	}

	groups := make([]string, 0, len(items))
	for _, item := range items {
		if item.Kind != vault.EntityKindGroup {
			continue
		}
		if _, exists := linked[item.Name]; exists {
			continue
		}
		groups = append(groups, item.Name)
	}
	return groups
}

func filteredFormOptions(form *formState) []string {
	if form == nil {
		return nil
	}
	query := strings.TrimSpace(strings.ToLower(form.optionFilter.Value()))
	if query == "" {
		return append([]string(nil), form.options...)
	}
	terms := strings.Fields(query)
	filtered := make([]string, 0, len(form.options))
	for _, option := range form.options {
		candidate := strings.ToLower(option)
		matched := true
		for _, term := range terms {
			if !strings.Contains(candidate, term) {
				matched = false
				break
			}
		}
		if matched {
			filtered = append(filtered, option)
		}
	}
	return filtered
}

func clampSelectedOption(form *formState) {
	filtered := filteredFormOptions(form)
	if len(filtered) == 0 {
		form.selectedOption = 0
		return
	}
	if form.selectedOption >= len(filtered) {
		form.selectedOption = len(filtered) - 1
	}
	if form.selectedOption < 0 {
		form.selectedOption = 0
	}
}

func optionWindow(total, selected, limit int) (int, int) {
	if total <= limit {
		return 0, total
	}
	half := limit / 2
	start := max(selected-half, 0)
	end := start + limit
	if end > total {
		end = total
		start = end - limit
	}
	return start, end
}

func formatTimestampLine(createdAt, modifiedAt time.Time) string {
	parts := []string{}
	if !createdAt.IsZero() {
		parts = append(parts, "created "+createdAt.Format("2006-01-02 15:04"))
	}
	if !modifiedAt.IsZero() {
		parts = append(parts, "updated "+modifiedAt.Format("2006-01-02 15:04"))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " • ")
}

func truncateLines(content string, maxLines int) string {
	lines := strings.Split(content, "\n")
	if len(lines) <= maxLines {
		return content
	}
	if maxLines < 2 {
		return strings.Join(lines[:maxLines], "\n")
	}
	trimmed := append([]string(nil), lines[:maxLines-1]...)
	trimmed = append(trimmed, "...")
	return strings.Join(trimmed, "\n")
}

func maskValue(value string) string {
	if value == "" {
		return ""
	}
	return strings.Repeat("*", min(8, max(3, len(value))))
}

func placeOverlay(background, overlay string) string {
	return lipgloss.Place(lipgloss.Width(background), lipgloss.Height(background), lipgloss.Center, lipgloss.Center, background+"\n"+overlay)
}

func (m Model) hasSelection() bool {
	return m.selectedName != ""
}
