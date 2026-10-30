# Market listing

What the DSH plugin market shows for this plugin, which file owns each string,
and the catalog entry this repository submits.

## Where each surface gets its text

| Surface                                  | Title / description source                                                                                                                    | Owner                  |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| Installed plugin card (plugin manager)   | `locale/<lang>.json` → `meta.title`, `meta.description`; falls back to `package.json` `name` / `description`                                  | this repository        |
| Icon on that card                        | `package.json` `icon`, else the `icon` resource / `icon.svg`                                                                                  | this repository        |
| `dsh plugin add`, npm page               | `package.json` `description`                                                                                                                  | this repository        |
| Market **Discover** list and detail page | the configured market index (`dsh-plugin-catalog`), generated from `awesome-dsh-plugin/awesome-dsh-plugin` `data/plugins/<owner>__<repo>.yml` | the catalog repository |

The first three are read by DSH's `readPluginMeta`, so a missing locale file
still leaves a description: the manifest's own `description` fills it in. The
Discover card is different — it renders the catalog entry's `description`, and a
package the catalog does not list has no Discover card at all.

## Catalog entry

Submit this as one file, `data/plugins/gythialy__dsh-sensitive-guard.yml`, in a
pull request to [awesome-dsh-plugin](https://github.com/awesome-dsh-plugin/awesome-dsh-plugin)
(their `contributing.md` is the authority; the READMEs are generated and must
not be edited by hand):

```yaml
url: https://github.com/gythialy/dsh-sensitive-guard
name: gythialy/dsh-sensitive-guard
category: security
description:
  en: 'Sensitive-data guard for DeepSeek Harness: blocks credential reads and outbound secrets, and redacts secrets, tokens, and PII before they reach the model, the session log, or a spill file.'
  zh: 面向 DeepSeek Harness 的敏感信息守卫：拦截凭据读取与外发密钥，并在密钥、令牌与 PII 进入模型、会话日志或 spill 文件前替换为占位符。
```

- `description.en` is required and must end with a period; the `zh` line is
  optional but already written here.
- Any description containing `: ` (colon plus space) must be single-quoted,
  as `en` is above.
- `icon` is optional and must be a GitHub-hosted **raster** image. This
  package ships `icon.svg`, so the field is omitted and the market falls back
  to the owner's avatar.
- `package.json` declares `dsh.bundle`, which is the installability requirement
  the catalog checks.

## Status

As of 2026-10-30 this plugin is **not** in the catalog — the published index
(3,993 entries, authors A–z, 108 starting with `g`) and the catalog repository's
`data/plugins/` both have no entry for `gythialy`, `sensitive-guard`, or
`r0cky20`. Until that pull request lands, the Discover page has nothing to show;
the installed-card description comes from `locale/en.json` and `locale/zh.json`
and is unaffected.
