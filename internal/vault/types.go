package vault

import (
	"encoding/json"
	"fmt"
	"maps"
	"sort"
	"time"
)

const currentVersion = 1

type EntityKind string

const (
	EntityKindUnknown EntityKind = ""
	EntityKindGroup   EntityKind = "group"
	EntityKindApp     EntityKind = "app"
)

type SecretValue []byte

func (s SecretValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(s))
}

func (s *SecretValue) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	*s = append((*s)[:0], []byte(text)...)
	return nil
}

func (s SecretValue) Clone() SecretValue {
	return SecretValue(append([]byte(nil), s...))
}

func (s SecretValue) Wipe() {
	for i := range s {
		s[i] = 0
	}
}

type Profile map[string]SecretValue

type EntityMetadata struct {
	CreatedAt  time.Time `json:"created_at"`
	ModifiedAt time.Time `json:"modified_at"`
}

func normalizeMetadata(metadata EntityMetadata) EntityMetadata {
	return metadata
}

func (p Profile) Clone() Profile {
	clone := make(Profile, len(p))
	for key, value := range p {
		clone[key] = value.Clone()
	}
	return clone
}

func (p Profile) Keys() []string {
	keys := make([]string, 0, len(p))
	for key := range p {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (p Profile) Wipe() {
	for key, value := range p {
		value.Wipe()
		delete(p, key)
	}
}

type File struct {
	Version  int                       `json:"version"`
	Groups   map[string]Profile        `json:"groups"`
	Apps     map[string]App            `json:"apps"`
	Metadata map[string]EntityMetadata `json:"metadata,omitempty"`
}

type App struct {
	Groups []string `json:"groups"`
	Env    Profile  `json:"env"`
}

type fileDisk struct {
	Version  int                       `json:"version"`
	Groups   map[string]Profile        `json:"groups,omitempty"`
	Apps     map[string]App            `json:"apps,omitempty"`
	Metadata map[string]EntityMetadata `json:"metadata,omitempty"`
}

func NewFile() *File {
	return &File{
		Version:  currentVersion,
		Groups:   map[string]Profile{},
		Apps:     map[string]App{},
		Metadata: map[string]EntityMetadata{},
	}
}

func (a App) Clone() App {
	clone := App{
		Groups: append([]string(nil), a.Groups...),
		Env:    a.Env.Clone(),
	}
	return clone
}

func (a App) Wipe() {
	a.Env.Wipe()
}

func LoadFile(data []byte) (*File, error) {
	disk := fileDisk{}
	if err := json.Unmarshal(data, &disk); err != nil {
		return nil, err
	}
	if disk.Version == 0 {
		return nil, fmt.Errorf("missing vault version")
	}
	if disk.Version != currentVersion {
		return nil, fmt.Errorf("unsupported vault version %d", disk.Version)
	}
	if disk.Groups == nil {
		disk.Groups = map[string]Profile{}
	}
	if disk.Apps == nil {
		disk.Apps = map[string]App{}
	}
	if disk.Metadata == nil {
		disk.Metadata = map[string]EntityMetadata{}
	}

	file := NewFile()
	for name, profile := range disk.Groups {
		file.Groups[name] = profile.Clone()
	}
	for name, app := range disk.Apps {
		file.Apps[name] = app.Clone()
	}
	maps.Copy(file.Metadata, disk.Metadata)
	return file, file.Validate()
}

func (f *File) Wipe() {
	for name, profile := range f.Groups {
		profile.Wipe()
		delete(f.Groups, name)
	}
	for name, app := range f.Apps {
		app.Wipe()
		delete(f.Apps, name)
	}
	if f.Groups == nil {
		f.Groups = map[string]Profile{}
	}
	if f.Apps == nil {
		f.Apps = map[string]App{}
	}
	if f.Metadata == nil {
		f.Metadata = map[string]EntityMetadata{}
	}
	f.Version = currentVersion
}

func (f *File) Validate() error {
	if f.Groups == nil {
		f.Groups = map[string]Profile{}
	}
	if f.Apps == nil {
		f.Apps = map[string]App{}
	}
	if f.Metadata == nil {
		f.Metadata = map[string]EntityMetadata{}
	}
	f.Version = currentVersion
	for name := range f.Metadata {
		if f.Kind(name) == EntityKindUnknown {
			delete(f.Metadata, name)
			continue
		}
		f.Metadata[name] = normalizeMetadata(f.Metadata[name])
	}
	for name := range f.Groups {
		if _, ok := f.Apps[name]; ok {
			return fmt.Errorf("name %q is used by both a group and an app", name)
		}
		if _, ok := f.Metadata[name]; !ok {
			f.Metadata[name] = EntityMetadata{}
			continue
		}
		f.Metadata[name] = normalizeMetadata(f.Metadata[name])
	}
	for appName, app := range f.Apps {
		if _, ok := f.Metadata[appName]; !ok {
			f.Metadata[appName] = EntityMetadata{}
		} else {
			f.Metadata[appName] = normalizeMetadata(f.Metadata[appName])
		}
		app = app.Clone()
		seen := make(map[string]struct{}, len(app.Groups))
		uniqueGroups := make([]string, 0, len(app.Groups))
		for _, groupName := range app.Groups {
			if _, ok := f.Groups[groupName]; !ok {
				return fmt.Errorf("app %q references missing group %q", appName, groupName)
			}
			if _, ok := seen[groupName]; ok {
				continue
			}
			seen[groupName] = struct{}{}
			uniqueGroups = append(uniqueGroups, groupName)
		}
		app.Groups = uniqueGroups
		if app.Env == nil {
			app.Env = Profile{}
		}
		f.Apps[appName] = app
	}
	return nil
}

func (f *File) HasName(name string) bool {
	return f.Kind(name) != EntityKindUnknown
}

func (f *File) Kind(name string) EntityKind {
	if _, ok := f.Groups[name]; ok {
		return EntityKindGroup
	}
	if _, ok := f.Apps[name]; ok {
		return EntityKindApp
	}
	return EntityKindUnknown
}

func (f *File) ensureGroup(name string) Profile {
	if f.Groups == nil {
		f.Groups = map[string]Profile{}
	}
	if profile, ok := f.Groups[name]; ok {
		return profile
	}
	profile := Profile{}
	f.Groups[name] = profile
	return profile
}

func (f *File) MetadataFor(name string) EntityMetadata {
	if f.Metadata == nil {
		f.Metadata = map[string]EntityMetadata{}
	}
	return normalizeMetadata(f.Metadata[name])
}

func (f *File) TouchEntity(name string, now time.Time) {
	if f.Metadata == nil {
		f.Metadata = map[string]EntityMetadata{}
	}
	metadata := f.Metadata[name]
	if metadata.CreatedAt.IsZero() {
		metadata.CreatedAt = now
	}
	metadata.ModifiedAt = now
	f.Metadata[name] = metadata
}

func (f *File) SetMetadata(name string, metadata EntityMetadata) {
	if f.Metadata == nil {
		f.Metadata = map[string]EntityMetadata{}
	}
	f.Metadata[name] = normalizeMetadata(metadata)
}

func (f *File) DeleteMetadata(name string) {
	if f.Metadata == nil {
		return
	}
	delete(f.Metadata, name)
}

func (f *File) ensureApp(name string) App {
	if f.Apps == nil {
		f.Apps = map[string]App{}
	}
	if app, ok := f.Apps[name]; ok {
		if app.Env == nil {
			app.Env = Profile{}
			f.Apps[name] = app
		}
		return app
	}
	app := App{Env: Profile{}}
	f.Apps[name] = app
	return app
}

func (f *File) removeGroupReferences(groupName string) []string {
	affected := []string{}
	for appName, app := range f.Apps {
		filtered := app.Groups[:0]
		removed := false
		for _, existing := range app.Groups {
			if existing != groupName {
				filtered = append(filtered, existing)
				continue
			}
			removed = true
		}
		app.Groups = filtered
		f.Apps[appName] = app
		if removed {
			affected = append(affected, appName)
		}
	}
	sort.Strings(affected)
	return affected
}

func (f *File) selectorNames() []string {
	names := make([]string, 0, len(f.Groups)+len(f.Apps))
	for name := range f.Groups {
		names = append(names, name)
	}
	for name := range f.Apps {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
