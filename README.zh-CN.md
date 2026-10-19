# dsh-sensitive-guard

[![CI](https://github.com/gythialy/dsh-sensitive-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/gythialy/dsh-sensitive-guard/actions/workflows/ci.yml)
[![CodeQL](https://github.com/gythialy/dsh-sensitive-guard/actions/workflows/codeql.yml/badge.svg)](https://github.com/gythialy/dsh-sensitive-guard/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

面向 [DeepSeek Harness](https://github.com/deepseek-ai/dsh) 的 host-only 安全插件：**拦截凭据读取与外发密钥**，并在密钥、令牌与 PII 进入模型、会话日志或 spill 文件前替换为占位符。

> 状态：**0.0.0 预发布**。拦截与脱敏垂直切片已实现并有测试；状态表中标记为 _planned_ 的能力尚未实现，请勿当作可用功能。

## 覆盖范围

| #   | 泄露路径                        | 覆盖                                                                      |
| --- | ------------------------------- | ------------------------------------------------------------------------- |
| 1   | 用户粘贴 → 模型请求             | ✅ `agent/pre-step`（提交的 `user/message` 也是脱敏版）                   |
| 2   | 工具读取 → 模型                 | ✅ `tools/pre-execute` 路径/argv/URL 拦截 + `tools/post-execute` 结果脱敏 |
| 3   | 工具结果 → spill 文件           | ✅ 命中时 post-execute 短路，下游 spill 看不到原文                        |
| 4   | PTC 子调用日志副本              | ✅ `tools/ptc-dispatch-log`                                               |
| 5   | system prompt / runtime context | ✅ `system-prompt/assemble`                                               |
| 6   | 会话 inbox 原文                 | ⚠️ 部分：`agent/inbox/spliced` 仍保留用户原文                             |
| 7   | assistant 复述                  | ❌ 无公开改写钩子                                                         |
| 8   | 图片 / 截图                     | ❌ 无 OCR                                                                 |
| 9   | 第三方插件 / MCP 内部           | ❌ 不在 DSH 工具管线内                                                    |
| 10  | 模型 provider 留存              | ❌ 合同/选型问题                                                          |

插件只能约束经过 DSH 工具管线与消息管线的内容。

## 功能

- **两层能力**：fail-closed 的 allow/deny/ask 拦截层 + 脱敏层。
- **五个钩子**：pre-step、pre-execute、post-execute、PTC dispatch log、system-prompt assemble。
- **规则**：用户 YAML 规则 + 生成的路径策略 + vendor 的高危基线（破坏性命令、RCE、凭据路径）。
- **检测**：分层密钥规则（PEM、各厂商 key、JWT、URL 凭据、赋值）与 PII（邮箱、手机、身份证、Luhn 银行卡、SSN），附高熵 fallback。
- **稳定占位符**：密钥 `[SECRET:<category>:<id>]`（不可逆）；PII `[[PII_<TYPE>_<hash8>]]`（跨会话稳定）。
- **审计**：JSONL，只含规则 id、计数与 hash，不含原文、密钥或完整路径。
- **先观察**：`mode: monitor` 只审计不拦截。

## 状态

| 能力                                                       | 状态      |
| ---------------------------------------------------------- | --------- |
| 配置 schema 与校验                                         | ✅        |
| 路径/argv/参数/网络规则引擎                                | ✅        |
| 内置高危基线                                               | ✅ vendor |
| 密钥/PII 脱敏、`value` + content、幂等                     | ✅        |
| 五个生命周期钩子                                           | ✅        |
| hash-only 审计与轮转                                       | ✅        |
| 单元 + 集成测试、CI（格式/lint/typecheck/test/build/pack） | ✅        |
| `/guard status\|on\|off\|restore` 命令                     | planned   |
| 仅计数的提示消息（`redact.notify`）                        | planned   |
| `bin/scan.mjs` 仓库/CI 扫描器                              | planned   |
| 端到端 profile + mock provider 测试                        | planned   |
| 进程级 HTTP 代理                                           | v1 不做   |

## 要求

- Node.js `^22.19.0 || >=24.0.0`
- DeepSeek Harness `0.2.1-rc.2`（peer 范围 `>=0.2.1-rc.2 <0.3.0-0`）
- 启用了 `tools` 服务的 profile（base bundle）

## 安装（开发期）

```bash
pnpm install
pnpm verify

# 链接到某个 profile；会写 ~/.dsh，需要批准
dsh plugin --profile web add link:"$PWD"
```

包内 `cordis.patch.yml` 通过 `dsh.bundle.patch` 自动挂载。profile 可用行 id `sensitive-guard` 覆盖配置：

```yaml
# ~/.dsh/profiles/web/cordis.patch.yml
- id: sensitive-guard
  name: dsh-sensitive-guard
  config:
    mode: monitor
```

安装后重启 `dsh web`；不要在会话内自行重启当前 GUI。

## 配置

完整配置见 [docs/configuration.md](docs/configuration.md)。关键项：

```yaml
mode: monitor # monitor 只审计；enforce 生效
defaultDecision: allow
failClosed: true
levels:
  input: aggressive
  output: balanced
policy:
  rulesFile: .dsh/rules.yaml
  builtin: true
paths:
  deny: ['**/.env', '**/.ssh/**', '**/*.pem']
  allow: ['**/.env.example', '**/.env.sample', '**/.env.template']
audit:
  path: ~/.dsh/audit/sensitive-guard.jsonl
```

> **`defaultDecision` 注意**：schema 默认是 `ask`（与设计文档一致）。因此 `mode: enforce` 下，**没有命中任何规则**的调用也会询问批准。请先跑 `monitor` 看审计，再改成 `allow` 或补显式 allow 规则。`monitor` 下该值不影响行为。

项目规则文件位于 `<project>/.dsh/rules.yaml`，格式见 [docs/rules-format.md](docs/rules-format.md)。敏感凭据路径在 enforce 下默认 `deny`；`.env.example` / `.env.sample` / `.env.template` 默认放行。

PII key 文件为 32 字节随机值，权限 `0600`（父目录 `0700`）。不可用时退化为进程内随机 key：仍能脱敏，但跨重启占位符不稳定。密钥永不可逆；`pii.restore` 预留但当前不支持。

## 审计

目录 `0700`、文件 `0600`，超过 `rotateBytes` 轮转，保留 5 份。写失败只 warn 一次，不影响工具调用。记录示例见英文 README。

## 已知边界

- 无法改写 DSH 的 `agent/inbox/spliced` 原文与 assistant 输出。
- 安装前的历史会话不会自动重写。
- 工具**参数**中的密钥只能阻止执行，无法改写参数（host 在 pre-execute 前已记录）。
- v1 不做进程级 HTTP/CONNECT 代理、不做 OCR/图片脱敏。
- 脱敏隐私优先：误报可能去掉正常文本；先 `monitor` 再收敛规则。

## 开发

```bash
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm test:coverage
pnpm build
pnpm pack:check
```

`src` 为 TypeScript，1:1 转译到 `lib`（不打包），发布产物可逐文件审计。

## 许可证

Apache-2.0。规则基线派生自 `dsh-permission-rules`（Apache-2.0, Copyright 2026 PerryLink）；密钥规则表派生自 `dsh-secret-scrub`（MIT, Copyright (c) 2026 jkt-check）。详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 与设计文档 [docs/sensitive-guard-integration.md](docs/sensitive-guard-integration.md)。

安全问题报告：[SECURITY.md](SECURITY.md)。
