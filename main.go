package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"
)

type config struct {
	Vault         string `json:"vault"`
	Account       string `json:"account"`
	Host          string `json:"github_host"`
	StateFile     string `json:"state_file"`
	OrgVisibility string `json:"org_visibility"`
}
type runner func(context.Context, string, []string, []byte) ([]byte, error)

// Never forward subprocess output on failure: it may contain secret values.
func command(ctx context.Context, name string, args []string, input []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(input)
	cmd.Env = append(os.Environ(), "GH_PROMPT_DISABLED=1", "GH_DEBUG=", "OP_DEBUG=false")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s command failed (check authentication and permissions): %w", name, err)
	}
	return out, nil
}
func decode(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return errors.New("invalid JSON response (contents suppressed)")
	}
	return nil
}
func loadConfig(path string) (config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return config{}, err
	}
	c := config{Vault: "GitHub Actions", Host: "github.com", StateFile: filepath.Join(home, ".local", "state", "ghsecretsync", "state.json"), OrgVisibility: "private"}
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return c, err
	}
	if err == nil {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err = dec.Decode(&c); err != nil {
			return c, errors.New("invalid config JSON or unknown configuration key")
		}
		if dec.Decode(new(any)) != io.EOF {
			return c, errors.New("config must contain one JSON object")
		}
	}
	if strings.HasPrefix(c.StateFile, "~/") {
		c.StateFile = filepath.Join(home, c.StateFile[2:])
	}
	if c.Vault == "" || c.Host == "" || c.StateFile == "" {
		return c, errors.New("vault, github_host and state_file cannot be empty")
	}
	if c.OrgVisibility != "private" && c.OrgVisibility != "all" {
		return c, errors.New("org_visibility must be private or all (used for new entries only)")
	}
	return c, nil
}

type field struct {
	ID, Label, Type, Purpose, Value string
	Section                         *struct{ ID string }
}
type item struct {
	ID, Title string
	Vault     struct{ ID string }
	Tags      []string
	Fields    []field
	Files     []attachment
	Sections  []struct{ ID, Label string }
}
type attachment struct {
	ID, Name string
	Size     int64
	Section  *struct{ ID string }
}
type target struct{ Scope, Name string }

func (t target) String() string { return t.Scope + ":" + t.Name }
func (t target) path() string {
	switch t.Scope {
	case "repo":
		return "repos/" + t.Name + "/actions"
	case "org":
		return "orgs/" + t.Name + "/actions"
	default:
		panic("invalid target scope")
	}
}

type entry struct {
	Target            target
	Kind, Name, Value string
}

func (e entry) key() string { return e.Target.String() + "/" + e.Kind + "/" + e.Name }

var ownerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)
var repoPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+$`)
var namePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func targets(tags []string) ([]target, error) {
	var result []target
	for _, tag := range tags {
		if !strings.HasPrefix(tag, "ghsecrets/") {
			continue
		}
		scope, name, ok := strings.Cut(strings.TrimPrefix(tag, "ghsecrets/"), ":")
		if !ok || (scope != "repo" && scope != "org") || (scope == "repo" && !repoPattern.MatchString(name)) || (scope != "repo" && !ownerPattern.MatchString(name)) {
			return nil, fmt.Errorf("invalid destination tag %q", tag)
		}
		result = append(result, target{scope, strings.ToLower(name)})
	}
	return result, nil
}
func itemEntries(it item, ts []target) ([]entry, error) {
	var result []entry
	for _, f := range it.Fields {
		if f.ID == "notesPlain" || f.Purpose == "NOTES" {
			continue
		}
		// Item templates can include unfilled username/password/credential fields.
		// Keep empty custom fields: those can intentionally clear a value.
		if f.Value == "" && (f.Purpose == "PASSWORD" || f.Purpose == "USERNAME" || f.ID == "password" || f.ID == "username" || f.ID == "credential") {
			continue
		}
		if f.Type != "STRING" && f.Type != "CONCEALED" {
			return nil, fmt.Errorf("item %q field %q: unsupported type %q; use text or concealed fields", it.Title, f.Label, f.Type)
		}
		name := strings.ToUpper(f.Label)
		if !namePattern.MatchString(name) || strings.HasPrefix(name, "GITHUB_") {
			return nil, fmt.Errorf("item %q: invalid GitHub field name %q", it.Title, f.Label)
		}
		kind := "secrets"
		if f.Type == "STRING" {
			kind = "variables"
		}
		if len(f.Value) > 48*1024 {
			return nil, fmt.Errorf("item %q field %q exceeds GitHub's 48 KB limit", it.Title, f.Label)
		}
		for _, t := range ts {
			result = append(result, entry{t, kind, name, f.Value})
		}
	}
	return result, nil
}

type app struct {
	cfg    config
	run    runner
	out    io.Writer
	in     io.Reader
	color  bool
	filter target
}

func (a *app) selectedTargets(ts []target) []target {
	if a.filter.Scope == "" {
		return ts
	}
	var selected []target
	for _, t := range ts {
		if t.Scope == a.filter.Scope && strings.EqualFold(t.Name, a.filter.Name) {
			selected = append(selected, t)
		}
	}
	return selected
}

func (a *app) api(ctx context.Context, method, path string, body any, paginate bool) ([]byte, error) {
	args := []string{"api", "--hostname", a.cfg.Host, "--method", method, path}
	var b []byte
	if body != nil {
		var err error
		b, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
		args = append(args, "--input", "-")
	}
	if paginate {
		args = append(args, "--paginate", "--slurp")
	}
	return a.run(ctx, "gh", args, b)
}
func (a *app) op(ctx context.Context, args ...string) ([]byte, error) {
	args = append(args, "--vault", a.cfg.Vault, "--format", "json")
	if a.cfg.Account != "" {
		args = append(args, "--account", a.cfg.Account)
	}
	return a.run(ctx, "op", args, nil)
}
func (a *app) plan(ctx context.Context) ([]entry, error) {
	b, err := a.op(ctx, "item", "list")
	if err != nil {
		return nil, err
	}
	var items []item
	if err = decode(b, &items); err != nil {
		return nil, err
	}
	all := map[string]entry{}
	for _, summary := range items {
		ts, err := targets(summary.Tags)
		if err != nil {
			return nil, err
		}
		ts = a.selectedTargets(ts)
		if len(ts) == 0 {
			continue
		}
		b, err = a.op(ctx, "item", "get", summary.ID, "--reveal")
		if err != nil {
			return nil, err
		}
		var it item
		if err = decode(b, &it); err != nil {
			return nil, err
		}
		ts, err = targets(it.Tags)
		if err != nil {
			return nil, err
		}
		ts = a.selectedTargets(ts)
		if len(ts) == 0 {
			continue
		}
		entries, err := itemEntries(it, ts)
		if err != nil {
			return nil, err
		}
		files, err := a.attachmentEntries(ctx, it, ts)
		if err != nil {
			return nil, err
		}
		entries = append(entries, files...)
		for _, e := range entries {
			if old, ok := all[e.key()]; ok && old.Value != e.Value {
				return nil, fmt.Errorf("conflicting values for %s", e.key())
			}
			all[e.key()] = e
		}
	}
	result := make([]entry, 0, len(all))
	for _, e := range all {
		result = append(result, e)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].key() < result[j].key() })
	return result, nil
}

type remote struct {
	Name, Value, Visibility string
	Updated                 string `json:"updated_at"`
}

func (a *app) list(ctx context.Context, e entry) (map[string]remote, error) {
	b, err := a.api(ctx, "GET", e.Target.path()+"/"+e.Kind+"?per_page=100", nil, true)
	if err != nil {
		return nil, err
	}
	var pages []map[string]json.RawMessage
	if err = decode(b, &pages); err != nil {
		return nil, err
	}
	result := map[string]remote{}
	for _, page := range pages {
		raw, ok := page[e.Kind]
		if !ok {
			return nil, errors.New("GitHub response missing entries")
		}
		var rows []remote
		if err = decode(raw, &rows); err != nil {
			return nil, err
		}
		for _, r := range rows {
			result[strings.ToUpper(r.Name)] = r
		}
	}
	return result, nil
}
func (a *app) set(ctx context.Context, e entry, existing remote, exists bool) error {
	path := e.Target.path() + "/" + e.Kind
	body := map[string]any{}
	method := "PUT"
	if e.Kind == "variables" {
		body["name"] = e.Name
		body["value"] = e.Value
		method = "POST"
		if exists {
			method = "PATCH"
			path += "/" + e.Name
		}
	} else {
		b, err := a.api(ctx, "GET", path+"/public-key", nil, false)
		if err != nil {
			return err
		}
		var key struct {
			Key string
			ID  string `json:"key_id"`
		}
		if err = decode(b, &key); err != nil {
			return err
		}
		raw, err := base64.StdEncoding.DecodeString(key.Key)
		if err != nil || len(raw) != 32 || key.ID == "" {
			return errors.New("invalid GitHub encryption key")
		}
		var pk [32]byte
		copy(pk[:], raw)
		encrypted, err := box.SealAnonymous(nil, []byte(e.Value), &pk, rand.Reader)
		if err != nil {
			return err
		}
		body["encrypted_value"] = base64.StdEncoding.EncodeToString(encrypted)
		body["key_id"] = key.ID
		path += "/" + e.Name
	}
	if e.Target.Scope == "org" {
		visibility := a.cfg.OrgVisibility
		if exists {
			visibility = existing.Visibility
		}
		if visibility != "all" && visibility != "private" && visibility != "selected" {
			return errors.New("invalid organization visibility returned by GitHub")
		}
		body["visibility"] = visibility
	}
	// Omitting selected_repository_ids preserves an existing access policy.
	_, err := a.api(ctx, method, path, body, false)
	return err
}

type stamp struct{ Fingerprint, Updated string }
type state struct {
	Version int
	Key     []byte
	Entries map[string]stamp
}

func readState(path string) (state, error) {
	s := state{Version: 1, Entries: map[string]stamp{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		s.Key = make([]byte, 32)
		_, err = rand.Read(s.Key)
		return s, err
	}
	if err != nil {
		return s, err
	}
	if err = decode(b, &s); err != nil {
		return s, err
	}
	if s.Version != 1 || len(s.Key) != 32 || s.Entries == nil {
		return s, errors.New("invalid state file")
	}
	return s, nil
}
func saveState(path string, s state) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func fingerprint(key []byte, e entry) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(e.key()))
	h.Write([]byte{0})
	h.Write([]byte(e.Value))
	return hex.EncodeToString(h.Sum(nil))
}
func (a *app) sync(ctx context.Context, dry bool) error {
	if !dry {
		if err := os.MkdirAll(filepath.Dir(a.cfg.StateFile), 0700); err != nil {
			return err
		}
		lock := a.cfg.StateFile + ".lock"
		if err := os.Mkdir(lock, 0700); err != nil {
			return fmt.Errorf("cannot acquire state lock %s (another run may be active): %w", lock, err)
		}
		defer os.Remove(lock)
	}
	s, err := readState(a.cfg.StateFile)
	if err != nil {
		return err
	}
	entries, err := a.plan(ctx)
	if err != nil {
		return err
	}
	// Read and validate every destination before the first write.
	snapshots := map[string]map[string]remote{}
	for _, e := range entries {
		key := e.Target.String() + "/" + e.Kind
		if _, ok := snapshots[key]; !ok {
			rows, err := a.list(ctx, e)
			if err != nil {
				return fmt.Errorf("read %s: %w", key, err)
			}
			snapshots[key] = rows
		}
	}
	var changes []change
	for _, e := range entries {
		old, exists := snapshots[e.Target.String()+"/"+e.Kind][e.Name]
		key := a.cfg.Host + "/" + e.key()
		cached := s.Entries[key]
		same := exists && ((e.Kind == "variables" && old.Value == e.Value) || (e.Kind == "secrets" && cached.Fingerprint == fingerprint(s.Key, e) && cached.Updated != "" && cached.Updated == old.Updated))
		action := "create"
		if exists {
			action = "update"
		}
		if same {
			action = "unchanged"
		}
		changes = append(changes, change{e, old, exists, action})
	}
	changed := a.preview(changes, dry)
	if dry {
		fmt.Fprintln(a.out, "\nDry run complete. No changes applied.")
		return nil
	}
	if changed == 0 {
		fmt.Fprintln(a.out, "\nEverything is up to date.")
		return nil
	}
	ok, err := a.confirm(ctx)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintln(a.out, "Cancelled. No changes applied.")
		return nil
	}
	fmt.Fprintln(a.out)
	for _, c := range changes {
		if c.action == "unchanged" {
			continue
		}
		e, old, exists := c.entry, c.old, c.exists
		key := a.cfg.Host + "/" + e.key()
		fp := fingerprint(s.Key, e)
		if err = a.set(ctx, e, old, exists); err != nil {
			return fmt.Errorf("write %s: %w", e.key(), err)
		}
		if e.Kind == "secrets" {
			b, err := a.api(ctx, "GET", e.Target.path()+"/secrets/"+e.Name, nil, false)
			if err != nil {
				return fmt.Errorf("secret written but cannot read metadata for %s: %w", e.key(), err)
			}
			var updated remote
			if err = decode(b, &updated); err != nil {
				return err
			}
			if updated.Updated == "" {
				return errors.New("secret written but GitHub response missing update timestamp")
			}
			s.Entries[key] = stamp{fp, updated.Updated}
			if err = saveState(a.cfg.StateFile, s); err != nil {
				return fmt.Errorf("secret written but cannot save state: %w", err)
			}
		}
		fmt.Fprintf(a.out, "  %s %s\n", a.paint("32", "✓ Applied"), e.key())
	}
	fmt.Fprintf(a.out, "\n%s %d changes applied.\n", a.paint("32", "Done."), changed)
	return nil
}
func runCLI(ctx context.Context, args []string, out, errOut io.Writer) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("ghsecretsync", flag.ContinueOnError)
	flags.SetOutput(errOut)
	path := flags.String("config", filepath.Join(home, ".config", "ghsecretsync"), "configuration file (JSON)")
	dry := flags.Bool("dry-run", false, "preview changes without writing to GitHub or local state")
	repo := flags.String("repo", "", "sync only this tagged repository (OWNER/REPO)")
	org := flags.String("org", "", "sync only this tagged organization")
	if err = flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	var repoSet, orgSet bool
	flags.Visit(func(f *flag.Flag) {
		repoSet = repoSet || f.Name == "repo"
		orgSet = orgSet || f.Name == "org"
	})
	if repoSet && orgSet {
		return errors.New("--repo and --org cannot be used together")
	}
	var filter target
	if repoSet {
		if !repoPattern.MatchString(*repo) {
			return errors.New("--repo must be OWNER/REPO")
		}
		filter = target{"repo", strings.ToLower(*repo)}
	}
	if orgSet {
		if !ownerPattern.MatchString(*org) {
			return errors.New("--org must be an organization name")
		}
		filter = target{"org", strings.ToLower(*org)}
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	a := app{cfg: cfg, run: command, out: out, in: os.Stdin, color: useColor(out), filter: filter}
	return a.sync(ctx, *dry)
}
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := runCLI(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
