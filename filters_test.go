package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestDestinationFilter(t *testing.T) {
	for _, scope := range scopes {
		for _, dry := range []bool{false, true} {
			t.Run(scope+map[bool]string{false: "/apply", true: "/dry"}[dry], func(t *testing.T) {
				a, f, out := fixture(t)
				a.filter = target{scope, map[string]string{"repo": "acme/app", "org": "acme", "env": "acme/app/release"}[scope]}
				f.items[0].Tags = []string{"ghsecrets/repo:Acme/App", "ghsecrets/org:Acme", "ghsecrets/env:Acme/App/Release", "ghsecrets/env:acme/app/staging", "ghsecrets/repo:other/app"}
				f.items = append(f.items, item{ID: "unrelated", Tags: []string{"ghsecrets/repo:unrelated/app"}, Fields: []field{{Type: "OTP", Label: "invalid"}}})
				original := a.run
				a.run = func(ctx context.Context, name string, args []string, input []byte) ([]byte, error) {
					if name == "op" && args[1] == "get" && args[2] == "unrelated" {
						t.Fatal("read unrelated item")
					}
					if name == "gh" && !strings.HasPrefix(args[5], a.filter.path()+"/") {
						t.Fatal("accessed unselected destination", args)
					}
					return original(ctx, name, args, input)
				}
				if err := a.sync(context.Background(), dry); err != nil {
					t.Fatal(err)
				}
				want := 2
				if dry {
					want = 0
				}
				if f.writes != want {
					t.Fatalf("writes = %d, want %d", f.writes, want)
				}
				if !strings.Contains(out.String(), "Destination: "+a.filter.String()) {
					t.Fatal("filter missing from preview")
				}
			})
		}
	}
}

func TestUnmatchedDestination(t *testing.T) {
	a, _, out := fixture(t)
	a.filter = target{"repo", "missing/repo"}
	original := a.run
	a.run = func(ctx context.Context, name string, args []string, input []byte) ([]byte, error) {
		if name != "op" || args[1] != "list" {
			t.Fatal("unmatched filter accessed item or GitHub")
		}
		return original(ctx, name, args, input)
	}
	if err := a.sync(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No configured entries match") || strings.Contains(out.String(), "Apply these changes?") {
		t.Fatal(out.String())
	}
}

func TestInvalidDestinationFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--repo", "acme/app", "--org", "acme"}, {"--repo", "acme"}, {"--repo", ""}, {"--org", ""}, {"--org", "acme/app"}, {"--repo", "https://github.com/acme/app"},
		{"--env", "acme/app/release", "--repo", "acme/app"}, {"--env", "acme/app"}, {"--env", ""}, {"--env", "acme/app/release/x"}, {"--env", "acme/app/.."},
	} {
		if err := runCLI(context.Background(), args, new(bytes.Buffer), new(bytes.Buffer)); err == nil {
			t.Fatalf("accepted invalid flags %v", args)
		}
	}
}

func TestAttachmentDestinationFilter(t *testing.T) {
	a, f, _ := attachmentFixture(t)
	a.filter = target{"repo", "acme/app"}
	f.items[0].Tags = append(f.items[0].Tags, "ghsecrets/org:acme")
	entries, err := a.plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Target != a.filter {
		t.Fatal("attachment not filtered")
	}
}

func TestDestinationTags(t *testing.T) {
	ts, err := targets([]string{"ghsecrets/env:Acme/App/Release", "ghsecrets/repo:acme/app", "other"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 2 || ts[0] != (target{"env", "acme/app/release"}) {
		t.Fatal(ts)
	}
	if got := ts[0].path(); got != "repos/acme/app/environments/release" {
		t.Fatal(got)
	}
	for _, tag := range []string{"ghsecrets/env:acme/app", "ghsecrets/env:acme/app/", "ghsecrets/env:acme/app/..", "ghsecrets/env:acme/app/a/b", "ghsecrets/env:acme/app/with space"} {
		if _, err := targets([]string{tag}); err == nil {
			t.Fatalf("accepted %q", tag)
		}
	}
}

func TestConflictingFlagsMessage(t *testing.T) {
	err := runCLI(context.Background(), []string{"--org", "acme", "--repo", "acme/app"}, new(bytes.Buffer), new(bytes.Buffer))
	// The Homebrew formula's test asserts this exact message.
	if err == nil || err.Error() != "--repo and --org cannot be used together" {
		t.Fatal(err)
	}
}
