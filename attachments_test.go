package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func attachmentFixture(t *testing.T) (*app, *fakeService, *string) {
	t.Helper()
	a, f, _ := fixture(t)
	f.items[0].Vault.ID = "vault-id"
	f.items[0].Fields = nil
	f.items[0].Files = []attachment{{ID: "file-id", Name: "signing_key.pem.txt", Section: &struct{ ID string }{"section-id"}}}
	a.cfg.Account = "team"
	contents := "-----BEGIN KEY-----\r\nexample\n\n"
	original := a.run
	a.run = func(ctx context.Context, name string, args []string, input []byte) ([]byte, error) {
		if name == "op" && args[0] == "read" {
			want := []string{"read", "op://vault-id/item1/section-id/file-id", "--no-newline", "--account", "team"}
			if !reflect.DeepEqual(args, want) {
				t.Fatalf("read args: %v", args)
			}
			return []byte(contents), nil
		}
		return original(ctx, name, args, input)
	}
	return a, f, &contents
}

func TestAttachmentSync(t *testing.T) {
	a, f, contents := attachmentFixture(t)
	ctx := context.Background()
	if err := a.sync(ctx, true); err != nil {
		t.Fatal(err)
	}
	if f.writes != 0 {
		t.Fatal("dry run wrote")
	}
	if err := a.sync(ctx, false); err != nil {
		t.Fatal(err)
	}
	if f.values["SIGNING_KEY"] != *contents {
		t.Fatal("attachment bytes changed")
	}
	if err := a.sync(ctx, false); err != nil {
		t.Fatal(err)
	}
	if f.writes != 1 {
		t.Fatal("unchanged attachment rewritten")
	}
	*contents = "rotated\n"
	if err := a.sync(ctx, false); err != nil {
		t.Fatal(err)
	}
	if f.writes != 2 || f.values["SIGNING_KEY"] != *contents {
		t.Fatal("changed attachment not synced")
	}
}

func TestAttachmentValidation(t *testing.T) {
	for _, scenario := range []string{"metadata-size", "actual-size", "invalid-name", "missing-id", "field-conflict", "file-conflict", "read-failure"} {
		t.Run(scenario, func(t *testing.T) {
			a, f, contents := attachmentFixture(t)
			switch scenario {
			case "metadata-size":
				f.items[0].Files[0].Size = 48*1024 + 1
			case "actual-size":
				*contents = strings.Repeat("x", 48*1024+1)
			case "invalid-name":
				f.items[0].Files[0].Name = "bad-name.pem"
			case "missing-id":
				f.items[0].Vault.ID = ""
			case "field-conflict":
				f.items[0].Fields = []field{{Label: "SIGNING_KEY", Type: "CONCEALED", Value: "different"}}
			case "file-conflict":
				f.items[0].Files = append(f.items[0].Files, f.items[0].Files[0])
				original := a.run
				reads := 0
				a.run = func(ctx context.Context, name string, args []string, input []byte) ([]byte, error) {
					if name == "op" && args[0] == "read" {
						reads++
						if reads == 2 {
							return []byte("different"), nil
						}
					}
					return original(ctx, name, args, input)
				}
			case "read-failure":
				original := a.run
				a.run = func(ctx context.Context, name string, args []string, input []byte) ([]byte, error) {
					if name == "op" && args[0] == "read" {
						return nil, errors.New("read failed")
					}
					return original(ctx, name, args, input)
				}
			}
			if err := a.sync(context.Background(), false); err == nil {
				t.Fatal("expected failure")
			}
			if f.writes != 0 {
				t.Fatal("wrote before validation")
			}
		})
	}
}

func TestAttachmentNamesAndEmptyContents(t *testing.T) {
	for _, name := range []string{"KEY", "KEY.pem", "KEY.pem.txt"} {
		t.Run(name, func(t *testing.T) {
			a, f, contents := attachmentFixture(t)
			f.items[0].Files[0].Name = name
			*contents = ""
			if err := a.sync(context.Background(), false); err != nil {
				t.Fatal(err)
			}
			if value, ok := f.values["KEY"]; !ok || value != "" {
				t.Fatal("empty attachment not preserved")
			}
		})
	}
}
