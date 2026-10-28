package main

import (
	"context"
	"fmt"
	"strings"
)

func (a *app) attachmentEntries(ctx context.Context, it item, targets []target) ([]entry, error) {
	var result []entry
	for _, file := range it.Files {
		// Strip all extensions: SIGNING_KEY.pem.txt becomes SIGNING_KEY.
		name, _, _ := strings.Cut(file.Name, ".")
		name = strings.ToUpper(name)
		if !namePattern.MatchString(name) || strings.HasPrefix(name, "GITHUB_") {
			return nil, fmt.Errorf("item %q attachment %q: invalid GitHub secret name after removing extensions", it.Title, file.Name)
		}
		if file.Size > 48*1024 {
			return nil, fmt.Errorf("item %q attachment %q exceeds GitHub's 48 KB limit", it.Title, file.Name)
		}
		if it.Vault.ID == "" || it.ID == "" || file.ID == "" {
			return nil, fmt.Errorf("item %q attachment %q: missing 1Password vault, item or file ID", it.Title, file.Name)
		}
		parts := []string{it.Vault.ID, it.ID}
		if file.Section != nil && file.Section.ID != "" {
			parts = append(parts, file.Section.ID)
		}
		parts = append(parts, file.ID)
		args := []string{"read", "op://" + strings.Join(parts, "/"), "--no-newline"}
		if a.cfg.Account != "" {
			args = append(args, "--account", a.cfg.Account)
		}
		contents, err := a.run(ctx, "op", args, nil)
		if err != nil {
			return nil, fmt.Errorf("read attachment %q on item %q: %w", file.Name, it.Title, err)
		}
		// Check the actual length too; metadata may be missing or stale.
		if len(contents) > 48*1024 {
			return nil, fmt.Errorf("item %q attachment %q exceeds GitHub's 48 KB limit", it.Title, file.Name)
		}
		for _, target := range targets {
			result = append(result, entry{Target: target, Kind: "secrets", Name: name, Value: string(contents)})
		}
	}
	return result, nil
}
