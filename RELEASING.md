# Releasing

The plugin ships through two channels from the same tag:

| Channel                                           | Audience                                              | Auth on install              |
| ------------------------------------------------- | ----------------------------------------------------- | ---------------------------- |
| GitHub Release tarball                            | everyone                                              | none                         |
| GitHub Packages (`@gythialy/dsh-sensitive-guard`) | users with a GitHub token                             | classic PAT, `read:packages` |
| npmjs                                             | deferred until an account is available; tracked in #6 | none                         |

GitHub Packages requires a scoped package name, so the canonical name is
`@gythialy/dsh-sensitive-guard` everywhere. The repository keeps its name
`gythialy/dsh-sensitive-guard`, so the GitHub Release URL stays unchanged.

## 1. Prepare the release commit

```bash
pnpm install
pnpm version 0.1.0 --no-git-tag-version
# move CHANGELOG [Unreleased] items into [0.1.0] - YYYY-MM-DD
pnpm verify
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

## 3. Tag and publish

```bash
git tag -a v0.1.0 -m "dsh-sensitive-guard v0.1.0"
git push origin v0.1.0
gh run list --workflow=release.yml
gh run watch <run-id> --exit-status
```

`.github/workflows/release.yml` performs:

1. `pnpm verify`;
2. `npm publish --access public` to `https://npm.pkg.github.com` using the
   workflow `GITHUB_TOKEN` (`packages: write`);
3. `pnpm pack`, renamed to version-free `dsh-sensitive-guard.tgz`, plus
   `SHA256SUMS`;
4. `gh release create` with both assets.

No `NPM_TOKEN` secret is needed.

## 4. Make the package public

The first GitHub Packages publication is **private**. In
`Repository → Packages → @gythialy/dsh-sensitive-guard → Package settings →
Danger Zone → Change visibility`, choose **Public**. This cannot be undone.
Installation still requires a token after the package is public.

## 5. Verify

### Tarball (anonymous)

```bash
TMP_HOME="$(mktemp -d)"
DSH_HOME="$TMP_HOME" dsh plugin --profile web add \
  https://github.com/gythialy/dsh-sensitive-guard/releases/download/v0.1.0/dsh-sensitive-guard.tgz
DSH_HOME="$TMP_HOME" dsh --profile web --dump-config | grep -A3 sensitive-guard
rm -rf "$TMP_HOME"
```

Also verify `SHA256SUMS`:

```bash
curl -LO https://github.com/gythialy/dsh-sensitive-guard/releases/download/v0.1.0/SHA256SUMS
curl -LO https://github.com/gythialy/dsh-sensitive-guard/releases/download/v0.1.0/dsh-sensitive-guard.tgz
shasum -a 256 -c SHA256SUMS   # macOS; use sha256sum -c on Linux
```

`latest/download/dsh-sensitive-guard.tgz` is stable because the asset name has
no version in it.

### GitHub Packages (token)

```ini
# ~/.dsh/profiles/web/.npmrc
@gythialy:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_PACKAGES_TOKEN}
```

```bash
export GITHUB_PACKAGES_TOKEN=ghp_xxx   # classic PAT, read:packages
DSH_HOME="$(mktemp -d)" dsh plugin --profile web add @gythialy/dsh-sensitive-guard
```

## 6. npmjs (later)

Issue #6 tracks the npmjs release. GitHub Packages requires a scope, but npmjs
also accepts scoped packages, so no rename is needed. When an npm account is
available, add a separate manual or tag-driven publish step with
`npm publish --registry https://registry.npmjs.org --access public` (do not
change `publishConfig.registry` blindly; override the registry explicitly).
npm provenance is only available on npmjs.

## 7. Failure and rollback

| Failure                                         | Action                                                                            |
| ----------------------------------------------- | --------------------------------------------------------------------------------- |
| Before tag                                      | fix and re-run `pnpm verify`; no release exists                                   |
| Tag pushed, workflow failed before publish      | fix, delete/recreate the tag, retry                                               |
| GitHub Packages published, release asset failed | rerun the job or create the release manually; do not republish the same version   |
| Broken version already published                | publish a patch version; use `npm deprecate` for GitHub Packages where applicable |
| Leaked token                                    | revoke it immediately and update the workflow/secret                              |

Never reuse a published version number.

## References

- `.github/workflows/release.yml`
- [#7](https://github.com/gythialy/dsh-sensitive-guard/issues/7) — first dual-channel release
- [#6](https://github.com/gythialy/dsh-sensitive-guard/issues/6) — future npmjs release
- `CONTRIBUTING.md`
