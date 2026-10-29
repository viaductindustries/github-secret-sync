# ghsecretsync

A small Go CLI that copies 1Password item fields into GitHub Actions secrets and variables, using `op` and the authentication already configured for `gh`.

## Build and run

Install Go, [1Password CLI 2](https://developer.1password.com/docs/cli/), and [GitHub CLI](https://cli.github.com/). Authenticate `op` using your usual account, desktop integration, or `OP_SERVICE_ACCOUNT_TOKEN`, and authenticate GitHub with `gh auth login` (existing `GH_TOKEN` authentication also works).

```sh
go build -o ghsecretsync .
./ghsecretsync --dry-run
./ghsecretsync
```

The GitHub identity needs permission to manage Actions secrets and variables at each destination. Organization access may require additional scopes/permissions; the program does not change authentication or request scopes automatically.

Limit a run to one destination:

```sh
./ghsecretsync --repo adam/whatever --dry-run
./ghsecretsync --org viaduct
./ghsecretsync --env adam/whatever/release
```

`--repo`, `--org` and `--env` are mutually exclusive, case-insensitive filters on the existing 1Password destination tags. Only entries tagged for that exact destination are synced; items tagged for multiple destinations are applied only to the selected one. `--org` selects organization-level secrets and variables, not every repository owned by the organization, and `--repo` does not include that repository's environments. Without any of these flags, all tagged destinations are included. The preview shows the selected destination and reports when no entries match. Normal runs still ask for confirmation.

## 1Password items

Create items in the **GitHub Actions** vault, or the vault configured below. A Secure Note with custom fields works well. Add one or more destination tags:

- `ghsecrets/org:viaductindustries`
- `ghsecrets/repo:viaductindustries/nifty`
- `ghsecrets/env:viaductindustries/nifty/release`

`env:` tags target a [deployment environment](https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/managing-environments-for-deployment) in a repository, so only jobs that declare `environment: release` can read its secrets and variables, after any protection rules (required reviewers, branch or tag restrictions) pass. Use one to keep release credentials out of ordinary CI runs. The environment must already exist: create it under the repository's **Settings → Environments**. A missing environment fails the run before any GitHub writes. Environment names may contain letters, digits, `-`, `_` and `.`, and are case-insensitive.

Every eligible field is copied to every tagged destination. Other tags are ignored. `ghsecrets/user:...` and malformed `ghsecrets/` tags are rejected: user-level Actions secrets do not exist.

Use each field's **label** as its GitHub name, for example `API_TOKEN` or `DEPLOY_REGION`:

- **Concealed/password fields** (`CONCEALED`) become secrets.
- **Text fields** (`STRING`) become variables. Variables are readable through GitHub, so use concealed fields for sensitive values.

Names are normalized to uppercase and must contain only letters, numbers, and underscores, cannot begin with a digit, and cannot start with `GITHUB_`. Values, including empty custom-field values and trailing newlines, are preserved exactly. Notes and unfilled built-in username/password/credential fields are ignored. Populated built-in fields are synced normally. Other field types are rejected to avoid silently skipping intended configuration. Sections have no special meaning.

File attachments become **secrets**, using their name with all extensions removed and converted to uppercase: `SIGNING_KEY.pem` and `signing_key.pem.txt` both become `SIGNING_KEY`. The resulting name must meet the same GitHub naming rules as fields. Attachment contents are read using `op read` and preserved exactly, including trailing newlines; they are never printed or saved to temporary files. Empty attachments are supported. Files larger than 48 KB are rejected before any GitHub writes. Attachments participate in previews, confirmation, duplicate detection, and unchanged-secret detection just like concealed fields.

Multiple items can target the same name if their values agree. Conflicting values abort the run before any GitHub writes. Secrets and variables have separate namespaces. Removing an item, tag, or field does **not** delete anything from GitHub; changing a field's type creates the other kind without deleting the original.

## Configuration

The optional file `~/.config/ghsecretsync` contains JSON (it is a file, not a directory). Missing configuration uses these defaults:

```json
{
  "vault": "GitHub Actions",
  "account": "",
  "github_host": "github.com",
  "state_file": "~/.local/state/ghsecretsync/state.json",
  "org_visibility": "private"
}
```

`account` selects a 1Password account through `op --account`; leave it empty to use the CLI's existing account selection or service account. `github_host` selects the host for `gh api`. `org_visibility` accepts `private` or `all` and applies only to newly created organization secrets/variables. Existing visibility and selected-repository policies are preserved. Manage selected repositories in GitHub.

Use another config file with:

```sh
./ghsecretsync --config /path/to/config --dry-run
```

## Change detection and output

```text
ghsecretsync · Sync preview (dry run)
Vault: GitHub Actions  →  github.com

repo:viaductindustries/nifty
  + create    secret   API_TOKEN
  = unchanged variable DEPLOY_REGION

1 to create · 0 to update · 1 unchanged

Dry run complete. No changes applied.
```

Every run shows a complete preview grouped by destination, with green creates, amber updates, muted unchanged entries, and a summary. Colour is enabled only when output is a terminal; set `NO_COLOR=1` to disable it. Values are never printed.

Normal runs ask `Apply these changes? [y/N]` before making any GitHub writes. Enter `y` or `yes` to apply the displayed plan; empty input, EOF without approval, or any other response cancels. Runs with no changes finish without prompting. There is no automatic confirmation flag. Dry runs never prompt or apply changes. After confirmation, each completed write is reported. Command errors suppress subprocess output because it could contain values. Run `op whoami` or `gh auth status` separately to diagnose authentication failures.

GitHub does not return secret values. The first run therefore writes each configured secret, even if it already has the same value on GitHub. Subsequent runs compare a local keyed fingerprint and GitHub's `updated_at` metadata. A changed source value, changed timestamp, or deleted remote secret triggers a write. Variables are compared directly with GitHub's current values.

The state file contains fingerprints, their local key, and remote timestamps, but no plaintext values. It is saved atomically with mode `0600`, after each successful secret update. Keep it private: the key and fingerprints together can be used to test guesses of values. Removing the file causes secrets to be written again. Timestamp-based detection cannot prove equality or reliably detect competing writes within GitHub's timestamp resolution; avoid concurrent external writers.

`--dry-run` reads 1Password, GitHub, and existing state but performs no GitHub mutations and creates or updates no application state or lock files. The underlying CLIs may maintain their own authentication/cache files.

Normal runs lock the state path to prevent overlapping runs using the same state file. After a forced termination, remove `state.json.lock` only after confirming no sync is still running. Failures exit nonzero; already completed writes remain applied, and saved progress allows the next run to skip them. GitHub writes are not transactional.

## Development

```sh
go test -race ./...
go vet ./...
```

Tests simulate both CLIs and decrypt uploaded payloads to verify encryption and exact value preservation. They do not access real accounts.

## CI and releases

GitHub Actions tests pull requests on Linux and macOS, checks formatting and module files, runs the race detector and `go vet`, and builds all four release archives without publishing. Every push to `main` runs the same checks through the Release workflow before running Release Please.

[Release Please](https://github.com/googleapis/release-please-action) maintains a release PR with a changelog and version manifest. The first release is `v0.1.0`. Use Conventional Commit messages (or squash-merge PR titles), for example:

```text
feat: add repository filters
fix: ignore empty template credentials
feat!: change configuration format
```

While the version is below 1.0, features and fixes bump the patch version, and breaking changes bump the minor version. Documentation and CI-only changes do not normally trigger releases; include a `feat:` or `fix:` commit for the initial release, such as `feat: add 1Password to GitHub sync`.

Merging the release PR into `main` creates a tag and a draft GitHub release. In the same workflow, GoReleaser checks out that exact tag, tests it, builds the binaries, uploads assets, and publishes the release while preserving Release Please's notes. Each release contains:

- `ghsecretsync_<version>_darwin_amd64.tar.gz`
- `ghsecretsync_<version>_darwin_arm64.tar.gz`
- `ghsecretsync_<version>_linux_amd64.tar.gz`
- `ghsecretsync_<version>_linux_arm64.tar.gz`
- `checksums.txt` (SHA-256)

Each archive includes the executable and this README. Install `op` and `gh` separately; they remain runtime requirements. macOS binaries are not signed or notarized.

### Repository setup

Release Please authenticates as the [Viaduct Releaser](https://github.com/apps/viaduct-releaser) GitHub App, so its release PRs trigger CI like any other PR and their commits come from `viaduct-releaser[bot]`. The app needs Contents, Issues and Pull requests read/write; Issues covers the `autorelease:` labels. The **Allow GitHub Actions to create and approve pull requests** setting is not needed.

The app's credentials live in the `release-please` environment, which only `main` may use, so workflows on other branches cannot read the key:

```sh
repo=viaductindustries/github-secret-sync
gh api -X PUT repos/$repo/environments/release-please \
  --input - <<<'{"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}'
gh api -X POST repos/$repo/environments/release-please/deployment-branch-policies -f name=main -f type=branch
gh variable set RELEASE_PLEASE_APP_CLIENT_ID --env release-please --repo $repo --body <client-id>
gh secret set RELEASE_PLEASE_APP_PRIVATE_KEY --env release-please --repo $repo < path/to/key.pem
```

The app must also be installed on this repository. The private key is the complete PEM, not base64. The Release Please job receives no `GITHUB_TOKEN` permissions; everything else in the workflow, including asset publishing, still uses `GITHUB_TOKEN`.

If release PR checks don't start, or show `action_required`, the PR was pushed without the app token: check the environment's variable and secret, and the app's repository access.

### Retrying a release

If publishing fails after Release Please creates the tag, fix the underlying problem and run **Actions → Release → Run workflow** on `main`, setting `tag` to the existing tag, such as `v0.1.0`. This reuses the existing release and replaces partially uploaded assets. It builds the tagged source, so source/build fixes require a new release rather than a retry. A published immutable release cannot have its assets replaced.

### Local release checks

With GoReleaser v2.19.0 installed, run these inside a Git checkout with at least one commit:

```sh
goreleaser check
goreleaser release --snapshot --clean --skip=publish
```

Snapshot archives appear in `dist/`; nothing is published. Action references are pinned to commit SHAs, and Dependabot checks for GitHub Actions and Go module updates weekly. Update the GoReleaser version in both workflow files together when upgrading it.
