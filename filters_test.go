package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestDestinationFilter(t *testing.T) {
	for _, scope := range []string{"repo", "org"} {
		for _, dry := range []bool{false, true} {
			t.Run(scope+map[bool]string{false: "/apply", true: "/dry"}[dry], func(t *testing.T) {
				a, f, out := fixture(t)
				a.filter = target{scope, "acme"}
				if scope == "repo" {
					a.filter.Name = "acme/app"
				}
				f.items[0].Tags = []string{"ghsecrets/repo:Acme/App", "ghsecrets/org:Acme", "ghsecrets/repo:other/app"}
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
