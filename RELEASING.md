# Releasing

Releases are started by a human and published by automation. Creating and
publishing a GitHub Release is the only trigger; the workflow does not create
the release.

| Channel                | Package name                    | Audience                                       |
| ---------------------- | ------------------------------- | ---------------------------------------------- |
| GitHub Release tarball | `@r0cky20/dsh-sensitive-guard`  | users                                          |
| npmjs                  | `@r0cky20/dsh-sensitive-guard`  | users, when `NPM_TOKEN` exists                 |
| GitHub Packages        | `@gythialy/dsh-sensitive-guard` | authenticated mirror published by the workflow |

The canonical package name is `@r0cky20/dsh-sensitive-guard`; the repository
stays `gythialy/dsh-sensitive-guard`. GitHub Packages requires the package scope
to match the repository owner, so the mirror is republished under the
`@gythialy` scope by a per-step rename; do not install from it and do not treat
its name as canonical. Renaming the plugin from the pre-0.2 `@gythialy` name
means an existing profile must remove the old plugin id before adding the new
one.

## 0. Prerequisites

- Repository secret `NPM_TOKEN`: a **granular** token owned by the npm account that
  owns the canonical scope, with `Read and write (publish and stage)` and
  **`Bypass two-factor authentication` checked**. Without the bypass, `npm whoami`
  still succeeds but `npm publish` fails in CI with `EOTP` (the run happened, the
  package was never published).
- Run the `npm token check` workflow first; it authenticates with the secret and
  reports whether either candidate name is already on npmjs.

## 1. Prepare the release commit

```bash
pnpm install
pnpm version <version> --no-git-tag-version
# move CHANGELOG [Unreleased] items into [<version>] - YYYY-MM-DD
pnpm verify
pnpm test:e2e
pnpm pack --dry-run
```

Commit and push the version/changelog change to `main` (after the first
release, use the PR flow in `CONTRIBUTING.md`). Wait for CI and CodeQL.

## 2. Local preflight

```bash
TMP_HOME="$(mktemp -d)"
pnpm pack --pack-destination .tmp
python3 -m http.server 18765 --directory .tmp >/tmp/sg-http.log 2>&1 &
SERVER=$!
sleep 1
DSH_HOME="$TMP_HOME" dsh plugin --profile web add \
  http://127.0.0.1:18765/r0cky20-dsh-sensitive-guard-<version>.tgz
DSH_HOME="$TMP_HOME" dsh --profile web --dump-config | grep -A3 sensitive-guard
kill "$SERVER"
rm -rf "$TMP_HOME" .tmp/*.tgz
```

The scoped package must appear in `dsh.profile.bundles` and the
`sensitive-guard` row must be present in `--dump-config`.

## 3. Create and publish the Release

Draft first, review the notes, then publish:

```bash
gh release create v<version> --draft \
  --title "v<version>" \
  --notes-file .tmp/release-notes.md
```

Or use the GitHub UI: **Releases → Draft a new release**, choose/create the
`v<version>` tag, review, then **Publish release**.

Publishing emits `release: published` and runs
`.github/workflows/release.yml`:

1. checkout the release tag;
2. require `v<package.json version>` to equal the tag;
3. `pnpm verify`;
4. if `NPM_TOKEN` is configured, publish `@r0cky20/dsh-sensitive-guard` to npmjs
   with `--provenance` (`id-token: write`);
5. republish the same build to GitHub Packages under the `@gythialy` scope with
   the workflow `GITHUB_TOKEN` (`packages: write`); the rename is confined to
   that step and `package.json` is restored afterwards;
6. pack `dsh-sensitive-guard.tgz` and `SHA256SUMS`;
7. upload both assets to the already-published release.

A missing or broken `NPM_TOKEN` does not fail the job: the npmjs step logs a
warning and skips, so the release then reaches GitHub Packages only. Read the log
instead of assuming npmjs was published. No repository secret is needed for
GitHub Packages.

Re-running a failed release run is safe **only** when nothing reached either
registry; the log prints one `+ <name>@<version>` line per successful publish.

## 4. Verify

### Tarball (anonymous)

```bash
TMP_HOME="$(mktemp -d)"
DSH_HOME="$TMP_HOME" dsh plugin --profile web add \
  https://github.com/gythialy/dsh-sensitive-guard/releases/download/v<version>/dsh-sensitive-guard.tgz
DSH_HOME="$TMP_HOME" dsh --profile web --dump-config | grep -A3 sensitive-guard
rm -rf "$TMP_HOME"
```

Checksums:

```bash
curl -LO https://github.com/gythialy/dsh-sensitive-guard/releases/download/v<version>/SHA256SUMS
curl -LO https://github.com/gythialy/dsh-sensitive-guard/releases/download/v<version>/dsh-sensitive-guard.tgz
shasum -a 256 -c SHA256SUMS   # macOS; use sha256sum -c on Linux
```

`latest/download/dsh-sensitive-guard.tgz` stays stable because the asset name
has no version.

The workflow log prints `+ @r0cky20/dsh-sensitive-guard@<version>` after the
npmjs step and `+ @gythialy/dsh-sensitive-guard@<version>` after the GitHub
Packages mirror step; both lines together are the publication check.

### npmjs (when enabled)

```bash
npm view @r0cky20/dsh-sensitive-guard version dist.tarball --registry https://registry.npmjs.org
npm audit signatures --registry https://registry.npmjs.org
```

## 5. Failure and rollback

| Failure                                   | Action                                                         |
| ----------------------------------------- | -------------------------------------------------------------- |
| Draft release has a bad tag or version    | edit the draft/tag before publishing                           |
| Workflow fails before any publication     | fix, delete the release/tag, publish a new release             |
| GitHub Packages published, assets missing | rerun the job; do not republish the same version               |
| Only npmjs failed                         | fix `NPM_TOKEN`, bump the patch version, publish a new release |
| Broken version already published          | publish a patch version; deprecate the old one                 |

Never reuse a published version number, and never re-run a workflow that
already published to one registry without checking the other.

## References

- `.github/workflows/release.yml`
- `.github/workflows/npm-token-check.yml` — `NPM_TOKEN` preflight
- `CONTRIBUTING.md`
