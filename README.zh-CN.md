# dsh-sensitive-guard

🇨🇳 简体中文 · 🇬🇧 [English](README.md)

[![CI](https://github.com/gythialy/dsh-sensitive-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/gythialy/dsh-sensitive-guard/actions/workflows/ci.yml)
[![CodeQL](https://github.com/gythialy/dsh-sensitive-guard/actions/workflows/codeql.yml/badge.svg)](https://github.com/gythialy/dsh-sensitive-guard/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

面向 [DeepSeek Harness](https://github.com/deepseek-ai/dsh) 的 host-only 安全插件：**拦截凭据读取与外发密钥**，并在密钥、令牌与 PII 进入模型、会话日志或 spill 文件前替换为占位符。

> 状态：**0.0.0 预发布**。拦截与脱敏垂直切片已实现并有测试；计划中的工作统一由 GitHub Issues 跟踪（见[路线图](#路线图)），尚未实现的能力请勿当作可用功能。

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
- **可选提示**：`redact.notify` 在被脱敏的 step 追加一条仅含计数的消息。

## 路线图

所有计划中的工作都通过 GitHub Issues 管理。入口是
[roadmap 标签](https://github.com/gythialy/dsh-sensitive-guard/issues?q=is%3Aissue+is%3Aopen+label%3Aroadmap)，
issue 列表是唯一来源。

## 要求

- Node.js `^22.19.0 || >=24.0.0`
- DeepSeek Harness `0.2.1-rc.2`（peer 范围 `>=0.2.1-rc.2 <0.3.0-0`）
- 启用了 `tools` 服务的 profile（base bundle）

## 安装

### 从 GitHub Release 安装

先用同一 release 的 `SHA256SUMS` 校验下载文件，然后：

```bash
dsh plugin --profile web add \
  https://github.com/gythialy/dsh-sensitive-guard/releases/latest/download/dsh-sensitive-guard.tgz
```

### 交给 agent 安装

把 [docs/agent-install.md](docs/agent-install.md) 交给 coding agent，或直接给它这段提示：

> Install dsh-sensitive-guard into my DSH web profile by following
> https://github.com/gythialy/dsh-sensitive-guard/blob/main/docs/agent-install.md

指南包含一条安装命令、挂载验证、重启、可选的 `enforce` 配置与回滚。

### 从 npm 安装（计划中）

由 [#6](https://github.com/gythialy/dsh-sensitive-guard/issues/6) 跟踪；未来 npmjs 发布使用同一个 scoped 名。

### 从源码安装（开发期）

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
  name: '@gythialy/dsh-sensitive-guard'
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

PII key 文件为 32 字节随机值，权限 `0600`（父目录 `0700`）。不可用时退化为进程内随机 key：仍能脱敏，但跨重启占位符不稳定。

### `/guard` 命令

- `/guard status`：模式、等级、规则数、审计与 PII/restore 状态；不含明文或匹配值。
- `/guard on` / `/guard off`：仅对当前进程切换 `enforce`/`monitor`，不持久化。
- `/guard restore <placeholder> <file>`：需 `pii.restore: true`；把原始 PII 写入新的 `0600` 文件，拒绝覆盖，绝不回显原值。映射只在内存中，只有开启 restore 后在本进程内生成的占位符可恢复；密钥仍不可逆。

审批提示会说明工具、简短风险类别（如 `高风险命令`、`敏感路径`）以及脱敏后的具体操作；密钥会替换为占位符，URL 凭据会打码。拒绝原因会说明拦截理由并给出一条安全的下一步。`/guard status` 输出带标签的键值块，而不是 `key=value` 行。守卫提示跟随 DSH 语言设置（`en` / `zh`）；未设置时依次回退到进程 locale 和英文。

## 扫描

包内附带独立扫描器，复用同一套规则，只输出类别、相对路径、计数和行号：

```bash
pnpm build
node bin/scan.mjs --staged          # 当前仓库已 staged 的文件
node bin/scan.mjs src test          # 指定路径
node bin/scan.mjs --json --no-exit-code .
```

退出码：`0` 干净、`1` 有命中、`2` 用法/IO 错误。超过 `--max-bytes`
（默认 8 MiB）和二进制文件会跳过；绝不打印匹配到的原值。

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
pnpm test:e2e   # 临时 headless profile + 本地 mock provider
pnpm build
pnpm pack:check
```

`src` 为 TypeScript，1:1 转译到 `lib`（不打包），发布产物可逐文件审计。

## 许可证

Apache-2.0。规则基线派生自 `dsh-permission-rules`（Apache-2.0, Copyright 2026 PerryLink）；密钥规则表派生自 `dsh-secret-scrub`（MIT, Copyright (c) 2026 jkt-check）。详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 与设计文档 [docs/sensitive-guard-integration.md](docs/sensitive-guard-integration.md)。

安全问题报告：[SECURITY.md](SECURITY.md)。
