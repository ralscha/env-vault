package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"env-vault/internal/vault"
)

type EntitySummary struct {
	Name             string
	Kind             vault.EntityKind
	DirectKeyCount   int
	LinkedGroupCount int
	CreatedAt        time.Time
	ModifiedAt       time.Time
	SearchText       string
}

type KeyValue struct {
	Key   string
	Value string
}

type EntityDetails struct {
	Summary      EntitySummary
	Direct       []KeyValue
	LinkedGroups []string
	Resolved     []KeyValue
}

func LoadInventory(opened *vault.Opened) ([]EntitySummary, error) {
	names := opened.ListNames()
	items := make([]EntitySummary, 0, len(names))
	for _, name := range names {
		kind := opened.Kind(name)
		if kind == vault.EntityKindUnknown {
			continue
		}

		metadata, err := opened.Metadata(name)
		if err != nil {
			return nil, err
		}
		keys, err := opened.ListKeys(name)
		if err != nil {
			return nil, err
		}

		summary := EntitySummary{
			Name:           name,
			Kind:           kind,
			DirectKeyCount: len(keys),
			CreatedAt:      metadata.CreatedAt,
			ModifiedAt:     metadata.ModifiedAt,
		}

		searchParts := []string{name, string(kind)}
		searchParts = append(searchParts, keys...)
		if kind == vault.EntityKindApp {
			app, err := opened.App(name)
			if err != nil {
				return nil, err
			}
			summary.LinkedGroupCount = len(app.Groups)
			searchParts = append(searchParts, app.Groups...)
		}
		summary.SearchText = strings.ToLower(strings.Join(searchParts, " "))
		items = append(items, summary)
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return items[i].Name < items[j].Name
	})
	return items, nil
}

func LoadDetails(opened *vault.Opened, name string) (EntityDetails, error) {
	var details EntityDetails
	kind := opened.Kind(name)
	if kind == vault.EntityKindUnknown {
		return details, vault.ErrNameNotFound
	}

	metadata, err := opened.Metadata(name)
	if err != nil {
		return details, err
	}
	keys, err := opened.ListKeys(name)
	if err != nil {
		return details, err
	}

	details.Summary = EntitySummary{
		Name:       name,
		Kind:       kind,
		CreatedAt:  metadata.CreatedAt,
		ModifiedAt: metadata.ModifiedAt,
	}

	switch kind {
	case vault.EntityKindUnknown:
		return details, vault.ErrNameNotFound
	case vault.EntityKindGroup:
		profile, err := opened.Group(name)
		if err != nil {
			return details, err
		}
		defer opened.WipeProfile(profile)
		details.Direct = keyValuesFromProfile(profile, keys)
		details.Resolved = keyValuesFromProfile(profile, keys)
	case vault.EntityKindApp:
		app, err := opened.App(name)
		if err != nil {
			return details, err
		}
		details.Summary.LinkedGroupCount = len(app.Groups)
		details.LinkedGroups = append([]string(nil), app.Groups...)
		details.Direct = keyValuesFromProfile(app.Env, keys)

		resolved, err := opened.ResolveSelection(name)
		if err != nil {
			return details, err
		}
		defer opened.WipeProfile(resolved)
		details.Resolved = keyValuesFromProfile(resolved, resolved.Keys())
	default:
		return details, fmt.Errorf("unsupported entity kind %q", kind)
	}

	details.Summary.DirectKeyCount = len(details.Direct)
	return details, nil
}

func FilterEntities(items []EntitySummary, query string) []EntitySummary {
	query = strings.TrimSpace(strings.ToLower(query))
	if query == "" {
		return append([]EntitySummary(nil), items...)
	}
	terms := strings.Fields(query)
	filtered := make([]EntitySummary, 0, len(items))
	for _, item := range items {
		matched := true
		for _, term := range terms {
			if !strings.Contains(item.SearchText, term) {
				matched = false
				break
			}
		}
		if matched {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func keyValuesFromProfile(profile vault.Profile, orderedKeys []string) []KeyValue {
	values := make([]KeyValue, 0, len(orderedKeys))
	for _, key := range orderedKeys {
		values = append(values, KeyValue{Key: key, Value: string(profile[key])})
	}
	return values
}
