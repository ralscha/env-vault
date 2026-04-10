package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
)

var (
	ErrAlreadyInitialized = errors.New("vault already initialized")
	ErrNotInitialized     = errors.New("vault is not initialized")
	ErrNameNotFound       = errors.New("name not found")
	ErrGroupNotFound      = errors.New("group not found")
	ErrAppNotFound        = errors.New("app not found")
	ErrNameInUse          = errors.New("name already exists")
	ErrKeyNotFound        = errors.New("key not found")
)

const (
	identityFileName = "identity.age"
	vaultFileName    = "vault.age"
)

type Store struct {
	backend BlobBackend
}

type Opened struct {
	store        *Store
	identity     *ageIdentityHandle
	file         *File
	vaultVersion string
}

type ageIdentityHandle struct {
	recipient string
	identity  *age.HybridIdentity
}

func NewStore(dir string) *Store {
	return &Store{backend: NewFileBackend(dir)}
}

func NewStoreWithBackend(backend BlobBackend) *Store {
	return &Store{backend: backend}
}

func (s *Store) Dir() string {
	if backend, ok := s.backend.(*FileBackend); ok {
		return backend.Dir()
	}
	return ""
}

func (s *Store) Init(password []byte, workFactor int) (string, error) {
	if workFactor < 14 || workFactor > 30 {
		return "", fmt.Errorf("work factor must be between 14 and 30")
	}
	ctx := context.Background()
	if err := s.backend.Init(ctx); err != nil {
		return "", err
	}
	initialized, err := s.isInitialized(ctx)
	if err != nil {
		return "", err
	}
	if initialized {
		return "", ErrAlreadyInitialized
	}

	identity, plaintextIdentity, err := generateIdentityFile()
	if err != nil {
		return "", err
	}
	defer Wipe(plaintextIdentity)

	encryptedIdentity, err := encryptWithPassphrase(plaintextIdentity, password, workFactor)
	if err != nil {
		return "", err
	}
	defer Wipe(encryptedIdentity)

	if _, err := s.backend.Save(ctx, BlobIdentity, Blob{Data: encryptedIdentity}, SaveOptions{CreateOnly: true}); err != nil {
		return "", err
	}

	file := NewFile()
	if _, err := s.saveFile(ctx, file, identity, ""); err != nil {
		return "", err
	}
	return identity.Recipient().String(), nil
}

func (s *Store) Open(password []byte) (*Opened, error) {
	initialized, err := s.isInitialized(context.Background())
	if err != nil {
		return nil, err
	}
	if !initialized {
		return nil, ErrNotInitialized
	}

	identity, err := s.DecryptIdentity(password)
	if err != nil {
		return nil, err
	}
	return s.OpenWithIdentity(identity)
}

func (s *Store) DecryptIdentity(password []byte) (*age.HybridIdentity, error) {
	ctx := context.Background()
	initialized, err := s.isInitialized(ctx)
	if err != nil {
		return nil, err
	}
	if !initialized {
		return nil, ErrNotInitialized
	}

	blob, err := s.backend.Load(ctx, BlobIdentity)
	if err != nil {
		return nil, err
	}
	identityCiphertext := blob.Data
	defer Wipe(identityCiphertext)

	identityPlaintext, err := decryptWithPassphrase(identityCiphertext, password)
	if err != nil {
		if isIncorrectPassphrase(err) {
			return nil, fmt.Errorf("decrypt identity file: incorrect master password")
		}
		return nil, fmt.Errorf("decrypt identity file: %w", err)
	}
	defer Wipe(identityPlaintext)

	identity, err := parseIdentityFile(identityPlaintext)
	if err != nil {
		return nil, fmt.Errorf("parse identity file: %w", err)
	}
	return identity, nil
}

func (s *Store) OpenWithIdentity(identity *age.HybridIdentity) (*Opened, error) {
	initialized, err := s.isInitialized(context.Background())
	if err != nil {
		return nil, err
	}
	if !initialized {
		return nil, ErrNotInitialized
	}
	return s.openWithIdentityHandle(&ageIdentityHandle{
		recipient: identity.Recipient().String(),
		identity:  identity,
	})
}

func (s *Store) openWithIdentityHandle(handle *ageIdentityHandle) (*Opened, error) {
	blob, err := s.backend.Load(context.Background(), BlobVault)
	if err != nil {
		return nil, err
	}
	vaultCiphertext := blob.Data
	defer Wipe(vaultCiphertext)

	vaultPlaintext, err := decryptWithIdentity(vaultCiphertext, handle.identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt vault file with %s: %w", redactRecipient(handle.recipient), err)
	}
	defer Wipe(vaultPlaintext)

	file, err := LoadFile(vaultPlaintext)
	if err != nil {
		return nil, fmt.Errorf("parse vault file: %w", err)
	}

	return &Opened{
		store:        s,
		identity:     handle,
		file:         file,
		vaultVersion: blob.Version,
	}, nil
}

func (o *Opened) Save() error {
	if err := o.file.Validate(); err != nil {
		return err
	}
	version, err := o.store.saveFile(context.Background(), o.file, o.identity.identity, o.vaultVersion)
	if err != nil {
		return err
	}
	o.vaultVersion = version
	return nil
}

func (o *Opened) SetGroup(groupName, key string, value []byte) error {
	now := time.Now().UTC()
	switch o.file.Kind(groupName) {
	case EntityKindUnknown:
		if o.file.HasName(groupName) {
			return fmt.Errorf("%w: %s", ErrNameInUse, groupName)
		}
	case EntityKindGroup:
	case EntityKindApp:
		return fmt.Errorf("%w: %s is an app", ErrNameInUse, groupName)
	}
	profile := o.file.ensureGroup(groupName)
	if existing, ok := profile[key]; ok {
		existing.Wipe()
	}
	profile[key] = append(SecretValue(nil), value...)
	o.file.TouchEntity(groupName, now)
	return nil
}

func (o *Opened) SetApp(appName, key string, value []byte) error {
	now := time.Now().UTC()
	switch o.file.Kind(appName) {
	case EntityKindUnknown:
		if o.file.HasName(appName) {
			return fmt.Errorf("%w: %s", ErrNameInUse, appName)
		}
	case EntityKindApp:
	case EntityKindGroup:
		return fmt.Errorf("%w: %s is a group", ErrNameInUse, appName)
	}
	app := o.file.ensureApp(appName)
	if existing, ok := app.Env[key]; ok {
		existing.Wipe()
	}
	app.Env[key] = append(SecretValue(nil), value...)
	o.file.Apps[appName] = app
	o.file.TouchEntity(appName, now)
	return nil
}

func (o *Opened) LinkAppGroup(appName, groupName string) error {
	now := time.Now().UTC()
	if _, ok := o.file.Groups[groupName]; !ok {
		return ErrGroupNotFound
	}
	switch o.file.Kind(appName) {
	case EntityKindApp:
	case EntityKindGroup:
		return fmt.Errorf("%w: %s is a group", ErrNameInUse, appName)
	case EntityKindUnknown:
		app := o.file.ensureApp(appName)
		app.Groups = append(app.Groups, groupName)
		o.file.Apps[appName] = app
		o.file.TouchEntity(appName, now)
		return o.file.Validate()
	}

	app := o.file.ensureApp(appName)
	if slices.Contains(app.Groups, groupName) {
		return nil
	}
	app.Groups = append(app.Groups, groupName)
	o.file.Apps[appName] = app
	o.file.TouchEntity(appName, now)
	return o.file.Validate()
}

func (o *Opened) UnlinkAppGroup(appName, groupName string) error {
	app, ok := o.file.Apps[appName]
	if !ok {
		return ErrAppNotFound
	}
	filtered := make([]string, 0, len(app.Groups))
	removed := false
	for _, existing := range app.Groups {
		if existing == groupName {
			removed = true
			continue
		}
		filtered = append(filtered, existing)
	}
	if !removed {
		return ErrGroupNotFound
	}
	app.Groups = filtered
	o.file.Apps[appName] = app
	o.file.TouchEntity(appName, time.Now().UTC())
	return nil
}

func (o *Opened) Unset(name, key string) error {
	switch o.file.Kind(name) {
	case EntityKindGroup:
		profile := o.file.Groups[name]
		value, ok := profile[key]
		if !ok {
			return ErrKeyNotFound
		}
		value.Wipe()
		delete(profile, key)
		o.file.TouchEntity(name, time.Now().UTC())
		return nil
	case EntityKindApp:
		app := o.file.Apps[name]
		value, ok := app.Env[key]
		if !ok {
			return ErrKeyNotFound
		}
		value.Wipe()
		delete(app.Env, key)
		o.file.Apps[name] = app
		o.file.TouchEntity(name, time.Now().UTC())
		return nil
	case EntityKindUnknown:
		return ErrNameNotFound
	default:
		return ErrNameNotFound
	}
}

func (o *Opened) RemoveName(name string) error {
	now := time.Now().UTC()
	switch o.file.Kind(name) {
	case EntityKindGroup:
		profile := o.file.Groups[name]
		profile.Wipe()
		delete(o.file.Groups, name)
		for _, appName := range o.file.removeGroupReferences(name) {
			o.file.TouchEntity(appName, now)
		}
		o.file.DeleteMetadata(name)
		return nil
	case EntityKindApp:
		app := o.file.Apps[name]
		app.Wipe()
		delete(o.file.Apps, name)
		o.file.DeleteMetadata(name)
		return nil
	case EntityKindUnknown:
		return ErrNameNotFound
	default:
		return ErrNameNotFound
	}
}

func (o *Opened) ListNames() []string {
	return o.file.selectorNames()
}

func (o *Opened) ListGroups() []string {
	groups := make([]string, 0, len(o.file.Groups))
	for name := range o.file.Groups {
		groups = append(groups, name)
	}
	sort.Strings(groups)
	return groups
}

func (o *Opened) ListApps() []string {
	apps := make([]string, 0, len(o.file.Apps))
	for name := range o.file.Apps {
		apps = append(apps, name)
	}
	sort.Strings(apps)
	return apps
}

func (o *Opened) ListKeys(name string) ([]string, error) {
	switch o.file.Kind(name) {
	case EntityKindGroup:
		return o.file.Groups[name].Keys(), nil
	case EntityKindApp:
		return o.file.Apps[name].Env.Keys(), nil
	case EntityKindUnknown:
		return nil, ErrNameNotFound
	default:
		return nil, ErrNameNotFound
	}
}

func (o *Opened) Group(groupName string) (Profile, error) {
	profile, ok := o.file.Groups[groupName]
	if !ok {
		return nil, ErrGroupNotFound
	}
	return profile.Clone(), nil
}

func (o *Opened) App(appName string) (App, error) {
	app, ok := o.file.Apps[appName]
	if !ok {
		return App{}, ErrAppNotFound
	}
	return app.Clone(), nil
}

func (o *Opened) Metadata(name string) (EntityMetadata, error) {
	if o.file.Kind(name) == EntityKindUnknown {
		return EntityMetadata{}, ErrNameNotFound
	}
	return o.file.MetadataFor(name), nil
}

func (o *Opened) RenameName(oldName, newName string) (EntityKind, error) {
	kind := o.file.Kind(oldName)
	if kind == EntityKindUnknown {
		return EntityKindUnknown, ErrNameNotFound
	}
	if o.file.HasName(newName) {
		return EntityKindUnknown, fmt.Errorf("%w: %s", ErrNameInUse, newName)
	}

	now := time.Now().UTC()
	metadata := o.file.MetadataFor(oldName)
	if metadata.CreatedAt.IsZero() {
		metadata.CreatedAt = now
	}
	metadata.ModifiedAt = now

	switch kind {
	case EntityKindGroup:
		profile := o.file.Groups[oldName]
		delete(o.file.Groups, oldName)
		o.file.Groups[newName] = profile
		for appName, app := range o.file.Apps {
			updated := false
			for index, groupName := range app.Groups {
				if groupName == oldName {
					app.Groups[index] = newName
					updated = true
				}
			}
			if updated {
				o.file.Apps[appName] = app
				o.file.TouchEntity(appName, now)
			}
		}
	case EntityKindApp:
		app := o.file.Apps[oldName]
		delete(o.file.Apps, oldName)
		o.file.Apps[newName] = app
	case EntityKindUnknown:
		return EntityKindUnknown, ErrNameNotFound
	}

	o.file.DeleteMetadata(oldName)
	o.file.SetMetadata(newName, metadata)
	return kind, o.file.Validate()
}

func (o *Opened) CopyName(sourceName, destinationName string) (EntityKind, error) {
	kind := o.file.Kind(sourceName)
	if kind == EntityKindUnknown {
		return EntityKindUnknown, ErrNameNotFound
	}
	if o.file.HasName(destinationName) {
		return EntityKindUnknown, fmt.Errorf("%w: %s", ErrNameInUse, destinationName)
	}

	now := time.Now().UTC()
	sourceMetadata := o.file.MetadataFor(sourceName)
	sourceMetadata.CreatedAt = now
	sourceMetadata.ModifiedAt = now
	switch kind {
	case EntityKindGroup:
		o.file.Groups[destinationName] = o.file.Groups[sourceName].Clone()
	case EntityKindApp:
		o.file.Apps[destinationName] = o.file.Apps[sourceName].Clone()
	case EntityKindUnknown:
		return EntityKindUnknown, ErrNameNotFound
	}
	o.file.SetMetadata(destinationName, sourceMetadata)
	return kind, o.file.Validate()
}

func (o *Opened) CreateName(kind EntityKind, name string) error {
	if o.file.HasName(name) {
		return fmt.Errorf("%w: %s", ErrNameInUse, name)
	}

	now := time.Now().UTC()
	switch kind {
	case EntityKindGroup:
		o.file.Groups[name] = Profile{}
	case EntityKindApp:
		o.file.Apps[name] = App{Groups: []string{}, Env: Profile{}}
	case EntityKindUnknown:
		return fmt.Errorf("unsupported entity kind %q", kind)
	default:
		return fmt.Errorf("unsupported entity kind %q", kind)
	}

	o.file.SetMetadata(name, EntityMetadata{CreatedAt: now, ModifiedAt: now})
	return o.file.Validate()
}

func (o *Opened) Kind(name string) EntityKind {
	return o.file.Kind(name)
}

func (o *Opened) ResolveSelection(spec string) (Profile, error) {
	names, err := ParseSelection(spec)
	if err != nil {
		return nil, err
	}
	resolved := Profile{}
	for _, name := range names {
		switch o.file.Kind(name) {
		case EntityKindGroup:
			mergeProfile(resolved, o.file.Groups[name])
		case EntityKindApp:
			app := o.file.Apps[name]
			for _, groupName := range app.Groups {
				mergeProfile(resolved, o.file.Groups[groupName])
			}
			mergeProfile(resolved, app.Env)
		case EntityKindUnknown:
			resolved.Wipe()
			return nil, fmt.Errorf("%w: %s", ErrNameNotFound, name)
		default:
			resolved.Wipe()
			return nil, fmt.Errorf("%w: %s", ErrNameNotFound, name)
		}
	}
	return resolved, nil
}

func (o *Opened) SelectionKinds(spec string) (map[string]EntityKind, error) {
	names, err := ParseSelection(spec)
	if err != nil {
		return nil, err
	}
	kinds := make(map[string]EntityKind, len(names))
	for _, name := range names {
		kind := o.file.Kind(name)
		if kind == EntityKindUnknown {
			return nil, fmt.Errorf("%w: %s", ErrNameNotFound, name)
		}
		kinds[name] = kind
	}
	return kinds, nil
}

func (o *Opened) Profile(profileName string) (Profile, error) {
	return o.ResolveSelection(profileName)
}

func ParseSelection(spec string) ([]string, error) {
	parts := strings.Split(spec, ",")
	names := make([]string, 0, len(parts))
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" {
			return nil, fmt.Errorf("invalid empty name in selection %q", spec)
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("selection cannot be empty")
	}
	return names, nil
}

func mergeProfile(dst Profile, src Profile) {
	for key, value := range src {
		if existing, ok := dst[key]; ok {
			existing.Wipe()
		}
		dst[key] = value.Clone()
	}
}

func (o *Opened) WipeProfile(profile Profile) {
	profile.Wipe()
}

func (o *Opened) Close() {
	if o.file != nil {
		o.file.Wipe()
		o.file = nil
	}
	if o.identity != nil {
		o.identity = nil
	}
}

func (s *Store) saveFile(ctx context.Context, file *File, identity *age.HybridIdentity, expectedVersion string) (string, error) {
	plaintext, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return "", err
	}
	defer Wipe(plaintext)

	ciphertext, err := encryptWithRecipient(plaintext, identity.Recipient())
	if err != nil {
		return "", err
	}
	defer Wipe(ciphertext)

	return s.backend.Save(ctx, BlobVault, Blob{Data: ciphertext}, SaveOptions{ExpectedVersion: expectedVersion})
}

func (s *Store) isInitialized(ctx context.Context) (bool, error) {
	identityExists, _, err := s.backend.Stat(ctx, BlobIdentity)
	if err != nil {
		return false, err
	}
	vaultExists, _, err := s.backend.Stat(ctx, BlobVault)
	if err != nil {
		return false, err
	}
	return identityExists && vaultExists, nil
}

func Wipe(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
