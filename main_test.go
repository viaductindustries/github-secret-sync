package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

type fakeService struct {
	t               *testing.T
	items           []item
	rows            map[string]remote
	writes          int
	fail            bool
	public, private *[32]byte
	values          map[string]string
}

func fixture(t *testing.T) (*app, *fakeService, *bytes.Buffer) {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeService{t: t, public: pub, private: priv, rows: map[string]remote{}, values: map[string]string{}, items: []item{{ID: "item1", Title: "Deploy", Tags: []string{"ghsecrets/repo:acme/app"}, Fields: []field{{Label: "TOKEN", Type: "CONCEALED", Value: "super secret\n\n"}, {Label: "REGION", Type: "STRING", Value: "eu-west-1\n"}}}}}
	out := new(bytes.Buffer)
	a := &app{cfg: config{Vault: "GitHub Actions", Host: "github.com", StateFile: filepath.Join(t.TempDir(), "state", "state.json"), OrgVisibility: "private"}, run: f.run, out: out, in: yesReader{}}
	return a, f, out
}
func (f *fakeService) run(_ context.Context, name string, args []string, input []byte) ([]byte, error) {
	f.t.Helper()
	encode := func(v any) ([]byte, error) { return json.Marshal(v) }
	if name == "op" {
		if args[1] == "list" {
			return encode(f.items)
		}
		for _, it := range f.items {
			if args[2] == it.ID {
				return encode(it)
			}
		}
		f.t.Fatal("unknown item")
	}
	method, path := args[4], args[5]
	if method != "GET" {
		if f.fail {
			return nil, errors.New("simulated write failure")
		}
		var body map[string]any
		if err := json.Unmarshal(input, &body); err != nil {
			f.t.Fatal(err)
		}
		value, _ := body["value"].(string)
		name, _ := body["name"].(string)
		kind := "variables"
		if encrypted, ok := body["encrypted_value"].(string); ok {
			kind = "secrets"
			name = path[strings.LastIndex(path, "/")+1:]
			raw, err := base64.StdEncoding.DecodeString(encrypted)
			if err != nil {
				f.t.Fatal(err)
			}
			plain, ok := box.OpenAnonymous(nil, raw, f.public, f.private)
			if !ok {
				f.t.Fatal("invalid ciphertext")
			}
			value = string(plain)
			if strings.Contains(string(input), "super secret") {
				f.t.Fatal("plaintext secret in API payload")
			}
		}
		f.writes++
		f.rows[kind+"/"+name] = remote{Name: name, Value: value, Updated: "2026-10-28T12:00:00Z"}
		f.values[name] = value
		return nil, nil
	}
	if strings.HasSuffix(path, "/public-key") {
		return encode(map[string]string{"key": base64.StdEncoding.EncodeToString(f.public[:]), "key_id": "key1"})
	}
	if strings.Contains(path, "?per_page=") {
		kind := "variables"
		if strings.Contains(path, "/secrets?") {
			kind = "secrets"
		}
		var rows []remote
		for key, r := range f.rows {
			if strings.HasPrefix(key, kind+"/") {
				rows = append(rows, r)
			}
		}
		// Two pages exercise pagination aggregation.
		return encode([]any{map[string]any{kind: []remote{}}, map[string]any{kind: rows}})
	}
	name = path[strings.LastIndex(path, "/")+1:]
	return encode(f.rows["secrets/"+name])
}
func TestSyncAndDrift(t *testing.T) {
	a, f, out := fixture(t)
	ctx := context.Background()
	if err := a.sync(ctx, false); err != nil {
		t.Fatal(err)
	}
	if f.writes != 2 || f.values["TOKEN"] != "super secret\n\n" || f.values["REGION"] != "eu-west-1\n" {
		t.Fatal("values not preserved", f.writes)
	}
	if strings.Contains(out.String(), "super secret") || strings.Contains(out.String(), "eu-west-1") {
		t.Fatal("values leaked")
	}
	b, err := os.ReadFile(a.cfg.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("super secret")) {
		t.Fatal("plaintext in state")
	}
	info, _ := os.Stat(a.cfg.StateFile)
	if info.Mode().Perm() != 0600 {
		t.Fatal("state permissions", info.Mode())
	}
	if err = a.sync(ctx, false); err != nil {
		t.Fatal(err)
	}
	if f.writes != 2 {
		t.Fatal("unchanged entries were written")
	}
	r := f.rows["secrets/TOKEN"]
	r.Updated = "2026-10-28T13:00:00Z"
	f.rows["secrets/TOKEN"] = r
	r = f.rows["variables/REGION"]
	r.Value = "drift"
	f.rows["variables/REGION"] = r
	if err = a.sync(ctx, false); err != nil {
		t.Fatal(err)
	}
	if f.writes != 4 {
		t.Fatal("external changes not repaired")
	}
	delete(f.rows, "secrets/TOKEN")
	if err = a.sync(ctx, false); err != nil {
		t.Fatal(err)
	}
	if f.writes != 5 {
		t.Fatal("deleted secret not recreated")
	}
	f.items[0].Fields[0].Value = "rotated"
	if err = a.sync(ctx, false); err != nil {
		t.Fatal(err)
	}
	if f.writes != 6 {
		t.Fatal("changed source not synced")
	}
}
func TestDryRun(t *testing.T) {
	a, f, out := fixture(t)
	if err := a.sync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if f.writes != 0 {
		t.Fatal("dry run wrote")
	}
	if _, err := os.Stat(filepath.Dir(a.cfg.StateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dry run created state directory")
	}
	if !strings.Contains(out.String(), "+ create    secret   TOKEN") {
		t.Fatal(out.String())
	}
}
func TestFailedWriteNotCached(t *testing.T) {
	a, f, _ := fixture(t)
	f.fail = true
	if err := a.sync(context.Background(), false); err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(a.cfg.StateFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed write cached")
	}
	f.fail = false
	if err := a.sync(context.Background(), false); err != nil {
		t.Fatal(err)
	}
}
func TestValidationBeforeWrites(t *testing.T) {
	for _, scenario := range []string{"user", "conflict", "invalid-name", "unsupported"} {
		t.Run(scenario, func(t *testing.T) {
			a, f, _ := fixture(t)
			switch scenario {
			case "user":
				f.items[0].Tags = append(f.items[0].Tags, "ghsecrets/user:adamcooke")
			case "conflict":
				f.items = append(f.items, item{ID: "item2", Tags: []string{"ghsecrets/repo:acme/app"}, Fields: []field{{Label: "token", Type: "CONCEALED", Value: "other"}}})
			case "invalid-name":
				f.items[0].Fields[0].Label = "GITHUB_TOKEN"
			case "unsupported":
				f.items[0].Fields[0].Type = "OTP"
			}
			if err := a.sync(context.Background(), false); err == nil {
				t.Fatal("expected validation failure")
			}
			if f.writes != 0 {
				t.Fatal("wrote before validation")
			}
		})
	}
}
func TestFields(t *testing.T) {
	it := item{Fields: []field{{ID: "notesPlain", Type: "STRING", Value: "ignore"}, {Label: "empty", Type: "CONCEALED"}, {Label: "config", Type: "STRING", Value: "text"}}}
	entries, err := itemEntries(it, []target{{"org", "acme"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Kind != "secrets" || entries[0].Value != "" || entries[1].Kind != "variables" {
		t.Fatalf("unexpected entries: %#v", entries)
	}
}
func TestStateLock(t *testing.T) {
	a, _, _ := fixture(t)
	os.MkdirAll(a.cfg.StateFile+".lock", 0700)
	if err := a.sync(context.Background(), false); err == nil || !strings.Contains(err.Error(), "lock") {
		t.Fatal("missing lock failure", err)
	}
}
func TestConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	c, err := loadConfig(path)
	if err != nil || c.Vault != "GitHub Actions" {
		t.Fatal(c, err)
	}
	for _, input := range []string{`{"unknown":true}`, `{"vault":""}`, `{} {}`, `{"org_visibility":"selected"}`} {
		os.WriteFile(path, []byte(input), 0600)
		if _, err = loadConfig(path); err == nil {
			t.Fatal("accepted invalid config", input)
		}
	}
	os.WriteFile(path, []byte(`{"vault":"Deployment","account":"team","github_host":"github.example.com"}`), 0600)
	c, err = loadConfig(path)
	if err != nil || c.Account != "team" || c.Vault != "Deployment" {
		t.Fatal(c, err)
	}
}

func TestOrganizationVisibilityAndVariableMethods(t *testing.T) {
	for _, tc := range []struct {
		exists                                 bool
		visibility, wantMethod, wantVisibility string
	}{
		{false, "", "POST", "private"}, {true, "all", "PATCH", "all"}, {true, "selected", "PATCH", "selected"},
	} {
		t.Run(tc.wantVisibility, func(t *testing.T) {
			a, _, _ := fixture(t)
			a.run = func(_ context.Context, name string, args []string, input []byte) ([]byte, error) {
				if name != "gh" || args[4] != tc.wantMethod {
					t.Fatalf("unexpected call: %s %v", name, args)
				}
				var body map[string]any
				if err := json.Unmarshal(input, &body); err != nil {
					t.Fatal(err)
				}
				if body["visibility"] != tc.wantVisibility {
					t.Fatal("visibility changed", body)
				}
				if _, ok := body["selected_repository_ids"]; ok {
					t.Fatal("selected policy overwritten")
				}
				if body["value"] != "" {
					t.Fatal("empty variable not preserved")
				}
				return nil, nil
			}
			err := a.set(context.Background(), entry{Target: target{"org", "acme"}, Kind: "variables", Name: "EMPTY"}, remote{Visibility: tc.visibility}, tc.exists)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDryRunExistingStateUnchanged(t *testing.T) {
	a, f, _ := fixture(t)
	ctx := context.Background()
	if err := a.sync(ctx, false); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(a.cfg.StateFile)
	f.items[0].Fields[0].Value = "new value"
	if err := a.sync(ctx, true); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(a.cfg.StateFile)
	if !bytes.Equal(before, after) || f.writes != 2 {
		t.Fatal("dry run modified state or GitHub")
	}
}

func TestUnfilledTemplateFields(t *testing.T) {
	a, f, out := fixture(t)
	var it item
	err := json.Unmarshal([]byte(`{
  "id":"template", "tags":["ghsecrets/org:viaductindustries"],
  "fields":[
   {"id":"password","label":"password","type":"CONCEALED","purpose":"PASSWORD"},
   {"id":"username","label":"username","type":"STRING","purpose":"USERNAME","value":""},
   {"id":"custom","label":"API_TOKEN","type":"CONCEALED","value":"token"},
   {"id":"custom-empty","label":"EMPTY","type":"CONCEALED","value":""}
  ]
 }`), &it)
	if err != nil {
		t.Fatal(err)
	}
	f.items = []item{it}
	if err = a.sync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "PASSWORD") || strings.Contains(out.String(), "USERNAME") {
		t.Fatal("unfilled template fields were planned", out.String())
	}
	if !strings.Contains(out.String(), "API_TOKEN") || !strings.Contains(out.String(), "EMPTY") {
		t.Fatal("custom fields were skipped", out.String())
	}
	it.Fields[0].Value = "populated"
	entries, err := itemEntries(it, []target{{"org", "viaductindustries"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[0].Name != "PASSWORD" {
		t.Fatal("populated built-in field skipped")
	}
}

type yesReader struct{}

func (yesReader) Read(p []byte) (int, error) { return copy(p, "yes\n"), nil }

func TestConfirmationRequired(t *testing.T) {
	for _, answer := range []string{"", "\n", "n\n", "no\n", "maybe\n", "y\n", "YES\n"} {
		t.Run(strings.TrimSpace(answer), func(t *testing.T) {
			a, f, out := fixture(t)
			a.in = strings.NewReader(answer)
			original := a.run
			a.run = func(ctx context.Context, name string, args []string, input []byte) ([]byte, error) {
				if name == "gh" && args[4] != "GET" {
					if !strings.Contains(out.String(), "2 to create") || !strings.Contains(out.String(), "Apply these changes? [y/N]") {
						t.Fatal("write before complete preview and confirmation")
					}
				}
				return original(ctx, name, args, input)
			}
			if err := a.sync(context.Background(), false); err != nil {
				t.Fatal(err)
			}
			approved := strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes")
			if approved {
				if f.writes != 2 {
					t.Fatal("approved changes not applied")
				}
			} else {
				if f.writes != 0 {
					t.Fatal("unapproved write")
				}
				if _, err := os.Stat(a.cfg.StateFile); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("state saved without approval")
				}
				if !strings.Contains(out.String(), "Cancelled") {
					t.Fatal("missing cancellation")
				}
			}
		})
	}
}

func TestNoPromptForDryRunOrUnchanged(t *testing.T) {
	a, _, out := fixture(t)
	if err := a.sync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "Apply these changes?") {
		t.Fatal("dry run prompted")
	}
	if err := a.sync(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := a.sync(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "Apply these changes?") || !strings.Contains(out.String(), "Everything is up to date") {
		t.Fatal(out.String())
	}
}

func TestPreviewColors(t *testing.T) {
	a, _, out := fixture(t)
	changes := []change{
		{entry: entry{Target: target{"org", "acme"}, Kind: "secrets", Name: "TOKEN", Value: "hidden"}, action: "create"},
		{entry: entry{Target: target{"org", "acme"}, Kind: "variables", Name: "REGION"}, action: "update"},
		{entry: entry{Target: target{"repo", "acme/app"}, Kind: "secrets", Name: "KEY"}, action: "unchanged"},
	}
	for _, color := range []bool{false, true} {
		out.Reset()
		a.color = color
		if a.preview(changes, false) != 2 {
			t.Fatal("wrong change count")
		}
		if strings.Contains(out.String(), "hidden") {
			t.Fatal("value leaked")
		}
		if strings.Count(out.String(), "org:acme") != 1 {
			t.Fatal("destination not grouped")
		}
		if strings.Contains(out.String(), "\x1b[") != color {
			t.Fatal("wrong color mode")
		}
		if color {
			for _, code := range []string{"\x1b[32m", "\x1b[33m", "\x1b[90m"} {
				if !strings.Contains(out.String(), code) {
					t.Fatal("missing color", code)
				}
			}
		}
	}
	if useColor(out) {
		t.Fatal("color enabled for redirected output")
	}
	t.Setenv("NO_COLOR", "1")
	if useColor(os.Stdout) {
		t.Fatal("NO_COLOR ignored")
	}
}

func TestEmptyBuiltInCredential(t *testing.T) {
	for _, value := range []string{"", "populated"} {
		t.Run(value, func(t *testing.T) {
			a, f, out := fixture(t)
			f.items[0].Fields = []field{
				{ID: "credential", Label: "credential", Type: "CONCEALED", Value: value},
				{ID: "custom-credential", Label: "CUSTOM_CREDENTIAL", Type: "CONCEALED", Value: ""},
			}
			if err := a.sync(context.Background(), true); err != nil {
				t.Fatal(err)
			}
			entries, err := itemEntries(f.items[0], []target{{"org", "acme"}})
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if value != "" {
				want = 2
			}
			if len(entries) != want {
				t.Fatalf("got %d entries, want %d", len(entries), want)
			}
			if value == "" && strings.Contains(out.String(), "secret   CREDENTIAL") {
				t.Fatal("blank built-in credential planned")
			}
			if entries[len(entries)-1].Name != "CUSTOM_CREDENTIAL" {
				t.Fatal("empty custom field skipped")
			}
		})
	}
}
