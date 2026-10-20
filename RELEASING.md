# Releasing

Releases are started by a human and published by automation. Creating and
publishing a GitHub Release is the only trigger; the workflow does not create
the release.

| Channel                | Audience                                       |
| ---------------------- | ---------------------------------------------- |
| GitHub Release tarball | users                                          |
| GitHub Packages        | authenticated mirror published by the workflow |
| npmjs                  | optional, when `NPM_TOKEN` exists              |

The canonical package name is `@gythialy/dsh-sensitive-guard`; the repository
stays `gythialy/dsh-sensitive-guard`.

## 1. Prepare the release commit

```bash
pnpm install
pnpm version 0.1.0 --no-git-tag-version
# move CHANGELOG [Unreleased] items into [0.1.0] - YYYY-MM-DD
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
  http://127.0.0.1:18765/gythialy-dsh-sensitive-guard-0.1.0.tgz
DSH_HOME="$TMP_HOME" dsh --profile web --dump-config | grep -A3 sensitive-guard
kill "$SERVER"
rm -rf "$TMP_HOME" .tmp/*.tgz
```

The scoped package must appear in `dsh.profile.bundles` and the
`sensitive-guard` row must be present in `--dump-config`.

## 3. Create and publish the Release

Draft first, review the notes, then publish:

```bash
gh release create v0.1.0 --draft \
  --title "v0.1.0" \
  --notes-file .tmp/release-notes.md
```

Or use the GitHub UI: **Releases → Draft a new release**, choose/create the
`v0.1.0` tag, review, then **Publish release**.

Publishing emits `release: published` and runs
`.github/workflows/release.yml`:

1. checkout the release tag;
2. require `v<package.json version>` to equal the tag;
3. `pnpm verify`;
4. publish to GitHub Packages with the workflow `GITHUB_TOKEN`
   (`packages: write`);
5. if `NPM_TOKEN` is configured, publish the same version to npmjs with
   `--provenance` (`id-token: write`);
6. pack `dsh-sensitive-guard.tgz` and `SHA256SUMS`;
7. upload both assets to the already-published release.

A missing `NPM_TOKEN` is not an error: the npmjs step logs a skip. No
repository secret is needed for GitHub Packages.

## 4. Verify

### Tarball (anonymous)

```bash
TMP_HOME="$(mktemp -d)"
DSH_HOME="$TMP_HOME" dsh plugin --profile web add \
  https://github.com/gythialy/dsh-sensitive-guard/releases/download/v0.1.0/dsh-sensitive-guard.tgz
DSH_HOME="$TMP_HOME" dsh --profile web --dump-config | grep -A3 sensitive-guard
rm -rf "$TMP_HOME"
```

Checksums:

```bash
curl -LO https://github.com/gythialy/dsh-sensitive-guard/releases/download/v0.1.0/SHA256SUMS
curl -LO https://github.com/gythialy/dsh-sensitive-guard/releases/download/v0.1.0/dsh-sensitive-guard.tgz
shasum -a 256 -c SHA256SUMS   # macOS; use sha256sum -c on Linux
```

`latest/download/dsh-sensitive-guard.tgz` stays stable because the asset name
has no version.

The workflow log prints `+ @gythialy/dsh-sensitive-guard@<version>` after the
GitHub Packages step; that is the publication check.

### npmjs (when enabled)

```bash
npm view @gythialy/dsh-sensitive-guard version dist.tarball --registry https://registry.npmjs.org
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
- [#7](https://github.com/gythialy/dsh-sensitive-guard/issues/7) — first dual-channel release
- [#6](https://github.com/gythialy/dsh-sensitive-guard/issues/6) — npmjs tracking
- `CONTRIBUTING.md`
