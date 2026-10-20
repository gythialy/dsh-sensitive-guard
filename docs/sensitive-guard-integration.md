---
title: DSH 敏感信息防泄露插件（自研）设计与第三方优点整合
status: draft-for-review
date: 2026-10-19
owner: gythialy
repo: /Users/gythialy/Developer/GitHub/sensitive-guard-integration
target_dsh: 0.2.1-rc.2
license: Apache-2.0
---

# DSH 敏感信息防泄露插件设计与第三方优点整合

> 本文是设计文档，不是实现。代码尚未开始；所有改动先在本仓库 review，不 commit/push。

## 0. 结论摘要

- **自研一个 host-only 插件**：`dsh-sensitive-guard`，许可证 **Apache-2.0**。
- **两层能力**：
  1. **拦截层**（`tools/pre-execute`）：按工具名、参数、路径、argv、网络目标做 `allow / deny / ask`，fail-closed。
  2. **脱敏层**（`agent/pre-step`、`tools/post-execute`、`tools/ptc-dispatch-log`、`system-prompt/assemble`）：在内容进入模型请求与持久日志前替换为占位符。
- **整合策略**：规则模型、内置基线、脱敏规则表、HMAC 假名、参数检查等**优点吸收**；只对少量规则表/基线做 **vendor**，其余**重写**，避免被上游 API 漂移拖死。
- **补齐现成插件共同的短板**：spill 落盘顺序、`value` 同步脱敏、system prompt 覆盖、assistant 输出、inbox 原文边界。

---

## 1. 背景与目标

### 1.1 问题

DSH 当前没有内置的“敏感信息防泄露”能力：

- `dsh-client-ui-secret-mask` 只遮挡 Web 显示，**发给模型的原文不变**。
- 会话日志、工具结果、用户粘贴的 token 都可能进入模型请求、本地日志、spill 文件或 git 仓库。
- 现成插件各有覆盖，但没有一个同时做到“拦截读取 + 模型边界脱敏 + spill 保护 + value 脱敏”。

### 1.2 目标

| 编号 | 目标 | 验收方式 |
|---|---|---|
| G1 | 用户消息进入模型前脱敏 | 粘贴 `sk-…` 后会话 `user/message` 与请求体均为占位符 |
| G2 | 工具结果进入模型前脱敏 | `read`/`bash`/`web_fetch` 结果命中规则时被替换 |
| G3 | 敏感路径读取被拒绝或询问 | `read ~/.ssh/id_rsa`、`bash cat .env` 被 deny |
| G4 | 出站参数中的密钥被拦截 | `bash curl -H "Authorization: Bearer …"`、`web_fetch ?token=…` 被 deny/ask |
| G5 | 不把未脱敏内容写入 spill 文件 | 大结果命中规则时短路 spill 或先脱敏 |
| G6 | PTC 子调用日志副本脱敏 | `tools/ptc-dispatch-log` 覆盖 |
| G7 | system prompt / runtime context 脱敏 | `system-prompt/assemble` 覆盖 |
| G8 | 审计可追溯且不含明文 | JSONL 只记 hash/规则/计数 |
| G9 | 可先观察后强制 | `monitor` 模式只记录不拦截 |

### 1.3 非目标

- v1 不做进程级 HTTP/CONNECT 代理（只做 URL/命令级网络规则）；v2 只做**目的地址级**出站守卫，不做 TLS 中间人（见 §2.4 D4b–D4e、§19）。
- 不做图像 OCR（截图中的密钥不在 v1 范围）。
- 不改 DSH core，不 patch 客户端输入框（Web 端粘贴拦截需要 client 插件，另立项目）。
- 不承诺覆盖“第三方插件绕过 DSH 工具管线直接读文件”的行为。
- 不做会话日志的历史重写（另提供独立 `scan`/`sanitize` CLI，须单独评审）。

### 1.4 术语

| 术语 | 含义 |
|---|---|
| 拦截层 | `tools/pre-execute` 上的 allow/deny/ask 规则 |
| 脱敏层 | 把文本中的敏感片段替换为占位符 |
| 占位符 | `[SECRET:<category>:<id>]` 或 `[[PII_<TYPE>_<hash8>]]` |
| 假名 | keyed HMAC 生成的稳定短 ID，用于 PII |
| spill | 大结果被 `dsh-spill-policy` 截断并把完整内容写入本地文件 |
| PTC | `run_code` 子调用模式 |

---

## 2. 现成插件评估与决策

### 2.1 评估矩阵（DSH 0.2.1-rc.2）

| 插件 | 能力 | 兼容性 | 主要短板 |
|---|---|---|---|
| `dsh-permission-rules` 0.7.20 | 工具/参数/路径/argv/网络 allow-deny-ask、审计、内置基线、dry-run | ✅ | 内置敏感路径是 `ask`，auto-approval 可能放行；网络代理重 |
| `dsh-secret-scrub` 0.1.2 | 密钥/令牌/私钥/JWT/env 赋值/高熵，三段脱敏 | ⚠️ peer `<0.2.0`，需豁免 | 先 `next()` 再脱敏（spill 风险）；不改 `value`；无 system prompt |
| `dsh-mask` 0.2.22 | PII + 基础 key，可逆占位符 | ✅ | key 覆盖窄；默认只遮 messages；先 `next()` |
| `dsh-pii-anonymizer` 0.2.0 | PII + API key 前缀，system prompt 覆盖，HMAC 假名 | ✅ | 无 PEM/JWT；不改 `value` |
| `@mkaliezz/dsh-secret-guard` 0.2.1 | 工具参数密钥检查 | ✅ | 不做结果脱敏 |
| `dsh-tool-policy` 0.1.1 | 声明式规则 | ❌ 旧 payload，静默失效 | 不要用 |
| `dsh-secret-paste` 0.2.0 | 粘贴 → credentials seam | ❌ peer 旧 + client 依赖 | 等更新 |

### 2.2 决策

**采用“自研 + 吸收优点”**，理由：

1. 现成插件没有一家同时覆盖拦截与脱敏；组合安装会引入多个上游、多个升级面。
2. `dsh-tool-policy` 的教训说明“README 兼容”不等于“代码兼容”；自研可以自己控制 API 适配。
3. 我们有明确要补的四个点（spill、`value`、system prompt、assistant），现成插件都不做。
4. 许可证全是 MIT/Apache-2.0，吸收成本低。

### 2.3 为什么不直接 fork

- fork 仍需跟随上游 API 变更；上游的 client UI、网络代理、存储栈对我们是负担。
- 只取“规则表/基线”这类稳定资产，核心逻辑自己写，维护面最小。

### 2.4 关键决策记录（ADR）

| 编号 | 决策 | 理由 | 被否决的替代方案 |
|---|---|---|---|
| D1 | 自研 host-only 插件，而不是组合安装现成插件 | 需要同时覆盖拦截与脱敏，并补齐 spill/value/system prompt；减少上游数量 | 只用 `permission-rules` + `mask`（覆盖不全）；fork 上游（维护面大） |
| D2 | 项目许可证 Apache-2.0 | 兼容 MIT；含专利授权；便于 vendor Apache-2.0 基线 | MIT（含 Apache 代码时义务更绕） |
| D3 | 只 vendor 规则表/基线，核心逻辑重写 | 规则表稳定、价值高；核心 API 易漂移 | 整体 fork；只学思想不 vendor（重复劳动） |
| D4 | v1 不做进程级 HTTP 代理 | 实现重、平台相关；先做 URL/命令级规则 | 复用 `permission-rules` 的 `network.ts` |
| D4b | v2 提供 opt-in 的**目的地址级出站守卫**：本机 CONNECT 代理，复用 DSH 的 `http_proxy` 缝隙（**已实现，默认关闭**，见 §6.6.1 与 §19.5） | 覆盖第三方插件/MCP 子进程这类不经过 DSH 钩子的出站；不需要 CA 分发 | 自建进程级 MITM 代理（D4c 否决）；只写文档不提供执行点（无法证明生效） |
| D4c | 不做 TLS 中间人、不生成/安装 CA | 成本在分发不在代码：必须在启动前就绪的 `NODE_EXTRA_CA_CERTS`、钥匙串管理员授权、JVM/rustls/静态 Go/容器绕过；且守卫会变成凭据持有者 | 生成并安装 CA（macOS/Linux/Windows 全平台信任库） |
| D4d | 不在插件内 patch `fetch` / 包装全局 dispatcher | 实测 `web_fetch` 两个分支都绕过包装（未代理时自 pin `Agent`，代理时用安装时捕获的 dispatcher）；DSH disposer 会还原 dispatcher；undici 槽位非契约 | monkey-patch `globalThis.fetch`（假安全：恰漏掉模型自选目标那条路径） |
| D4e | 不做透明/系统级拦截（pf、NetworkExtension、WFP） | 需要 root/管理员与签名扩展，原生客户端仍可绕过，超出插件边界 | 系统级透明代理（另立项目，需 OS 级隔离评估） |
| D5 | Secrets 不可逆；PII 可选可逆（0600 文件） | 避免明文恢复表二次泄露 | 全部可逆（`dsh-mask` 模式） |
| D6 | 默认 `monitor`，观察后再 `enforce` | 先量误报，避免阻断开发 | 默认直接 enforce |
| D7 | `tools/post-execute` 命中即短路下游 | 阻止 spill 把原文写盘 | 先 `next()` 再脱敏（现成插件的做法） |

---

## 3. 威胁模型

### 3.1 泄露路径与覆盖

| # | 路径 | 覆盖 | 说明 |
|---|---|---|---|
| 1 | 用户粘贴 → 模型请求 | ✅ pre-step | 会话 `user/message` 同步变脱敏 |
| 2 | 工具读取 → 模型 | ✅ pre-execute + post-execute | 路径拦截 + 结果脱敏 |
| 3 | 工具结果 → spill 文件 | ✅ post-execute 短路 | 命中即不委派下游 |
| 4 | PTC 子调用日志 | ✅ ptc-dispatch-log | 日志副本脱敏 |
| 5 | system prompt / runtime context | ✅ system-prompt/assemble | 其他插件不覆盖 |
| 6 | 会话日志 inbox 原文 | ⚠️ 部分 | 公开 API 无“入 inbox 前改写”钩子 |
| 7 | assistant 复述 | ❌ | 无公开改写钩子 |
| 8 | 图片/截图 | ❌ | v1 无 OCR |
| 9 | 第三方插件/MCP 内部 | ❌ | 进程内/外部进程不可控 |
| 10 | 模型 provider 留存 | ❌ | 合同/选型问题 |

### 3.2 防护边界

- 插件只能约束**经过 DSH 工具管线与消息管线**的内容。
- `agent/inbox/spliced` 会保留用户原文；本地磁盘保护依赖 `~/.dsh` 权限与 FileVault。
- 已存在的历史会话不会自动重写；如确认含密钥，建议删除该会话目录或走独立清理流程。

---

## 4. 总体架构

### 4.1 三层

```text
┌──────────────────────────────────────────────────────────────┐
│ 1. 拦截层  tools/pre-execute                                 │
│    - 路径 / 命令 / argv / 参数 / URL                         │
│    - allow / deny / ask，fail-closed                         │
├──────────────────────────────────────────────────────────────┤
│ 2. 脱敏层  pre-step / post-execute / ptc-log / system-prompt │
│    - 规则表 + 假阳性过滤 + 占位符                            │
│    - content 与 value 同步                                   │
├──────────────────────────────────────────────────────────────┤
│ 3. 审计层  JSONL                                             │
│    - 规则 / 工具 / 路径 hash / 计数，不含明文                │
└──────────────────────────────────────────────────────────────┘
```

### 4.2 请求数据流

```text
用户输入
  │  agent/inbox（原文仍在此）
  ▼
agent/pre-step ──► 脱敏 messages ──► 提交 user/message（脱敏）
  │
  ├─ system-prompt/assemble ──► 脱敏 sections/contexts/variables
  │
  ▼
模型请求（只含占位符）
  │
  ▼
工具调用 ──► tools/pre-execute ──► allow / deny / ask
  │
  ├─ allow ──► 工具执行 ──► tools/post-execute
  │                           │
  │                           ├─ 命中：脱敏 content/value，短路下游（spill 不落原文）
  │                           └─ 未命中：next() 正常下游
  │
  └─ deny/ask ──► 模型看到拒绝原因（原因本身不含明文）
```

### 4.3 模块图

```text
sensitive-guard-integration/       # 仓库根；npm 包名仍是 dsh-sensitive-guard
├── package.json
├── LICENSE                       # Apache-2.0
├── THIRD_PARTY_NOTICES.md
├── lib/
│   ├── index.js                  # apply(ctx, config)
│   ├── policy/
│   │   ├── evaluator.js          # 规则求值、first-match、dry-run
│   │   ├── matcher.js            # glob / params / paths / argv
│   │   └── baseline.yaml         # vendor 自 permission-rules（Apache-2.0）
│   ├── redact/
│   │   ├── rules.js              # vendor/裁剪自 secret-scrub（MIT）
│   │   ├── engine.js             # 扫描、占位符、幂等
│   │   └── filters.js            # 假阳性过滤
│   ├── pseudonym/
│   │   ├── hmac.js               # PII keyed 假名
│   │   └── key.js                # key 文件 0600
│   ├── argguard/
│   │   └── inspect.js            # 参数检查、size bound
│   ├── audit.js
│   ├── config.js                 # schemastery schema
│   └── context.js                # system-prompt/assemble
├── bin/
│   └── scan.mjs                  # 参考 secret-scan（MIT）
└── test/
```

---

## 5. 插件挂载点与行为

### 5.1 `agent/pre-step`

**签名**：`(payload: {agent, messages, turn, step, signal}, next) => Promise<PreStepDecision>`

**行为**：

1. `await next()`，拿到下游决策。
2. 若 `kind !== 'enter'`，原样返回。
3. 对 `decision.messages` 逐条脱敏：
   - 只处理 `content` 中的 `text` 块；
   - 保留 `id`、`role`、`source`；
   - 非文本块原样保留。
4. 返回 `{...decision, messages}`。

**关键事实**：`step()` 会把 `decision.messages` 作为 `user/message` 提交，所以**会话消息也是脱敏版**；原始文本仍留在 `agent/inbox/spliced` 事件。

**可选通知**：追加一条 `source.kind = 'plugin'` 的 user 消息（只含类型与计数），由 `notify` 开关控制。

### 5.2 `tools/pre-execute`

**签名**：`(exec: ToolExecution, next) => Promise<PreToolDecision>`

**执行顺序**：`prepend: true` → 最先执行；命中 `deny` 直接返回，不再 `next()`。

**检查维度**：

1. `exec.name` 工具名。
2. `exec.arguments` 递归遍历：
   - 路径键：`path`、`file_path`、`filepath`、`file`、`dir`、`directory`、`target`；
   - 命令键：`command`、`cmd`、`shell`、`script`；
   - URL 键：`url`、`uri`、`endpoint`。
3. 路径：规范化 `~`、绝对路径、`realpath`（防 symlink 绕过）。
4. bash：argv 分解（引号/管道/重定向感知），匹配命令词与参数 token。
5. 网络：URL host/port/scheme，匹配 allow/deny。
6. 参数中的高置信度密钥：`ask` 或 `deny`（可配置）。

**决策**：

| 条件 | 决策 |
|---|---|
| 敏感路径（默认 deny 列表） | `deny`，原因可操作 |
| 危险命令（`printenv`、`cat .env`、`security dump-keychain`…） | `deny` |
| 未知但疑似（参数含 `sk-`、JWT、PEM） | `ask` |
| 出站 URL 带 `token=`/`password=`/userinfo | `deny` 或 `ask` |
| 写文件含 PEM/高置信度密钥 | `deny` |
| 其他 | `next()` |

**注意**：参数在 pre-execute 之前已入日志，**不能改写参数**；只能阻止执行。需要“日志也不出现”的写入，必须在 write 之前就避免（skill 层约束）。

### 5.3 `tools/post-execute`

**签名**：`(exec, result, next) => Promise<PostToolDecision>`

**核心流程**：

```js
const hit = scan(exec, result, rules)   // 扫描 result.content + result.value
if (hit) {
  // 不调用 next()：短路下游，避免 spill 把原文写盘
  return {
    kind: 'accept',
    value: redactValue(result.value, rules),   // 优先替换 value
    // 注意：accept 不能同时带 content 和 value
  }
}
const decision = await next()
// 下游可能替换了 content/value；对最终 decision 再脱敏一次
return redactDecision(decision, result, rules)
```

**设计要点**：

- **短路**：命中时绕过 spill / 其他 post-execute 策略。代价是这些策略对该结果不生效；对“含密钥的结果”可接受。
- **value 优先**：`PostToolDecision` 的 `accept` 不能同时替换 `content` 与 `value`；选择 `value` 让工具的 `render` 重新生成内容，PTC 程序也拿到脱敏值。
- **`read` 特例**：`value` 是 `{path, offset, lines:[{number,text}], totalLines}`，递归替换 `lines[].text` 保持 schema。
- **错误结果**：`isError` 时 `value` 不存在，只替换 `content`。
- **图片**：跳过，不破坏附件。

### 5.4 `tools/ptc-dispatch-log`

**签名**：`(dispatch, next) => Promise<ContentBlock[]>`

**行为**：先扫描 `dispatch.content`；命中则直接返回脱敏后的 blocks（不 `next()`，避免 spill 的日志副本写入原文）；未命中再 `next()`，并对返回内容再脱敏一次。

### 5.5 `system-prompt/assemble`

**签名**：`(assembly, context, next) => Promise<assembly>`

**行为**：`await next()` 后，对以下字符串做脱敏：

- `assembly.sections[].text`
- `assembly.contexts[].text`
- `assembly.variables` 中的字符串值

**不处理**：tool schemas（工具名/描述/参数 schema）。

> 该钩子来自 `dsh-system-prompt`；若宿主未加载该服务，监听器不会触发，插件应容忍（不报错）。

### 5.6 事件顺序与 spill 短路

已确认：

- cordis 的 `prepend` 是 `unshift`，后注册的监听器在最前面。
- `dsh-spill-policy` 的 `tools/post-execute` 也是 `prepend`。
- 自研插件在 base bundle 之后加载，所以我们的 `post-execute` 会排在 spill 之前。

因此“扫描 → 命中短路”可以阻止 spill 看到原文。若未来加载顺序变化，需在测试中固定该假设，或在 `post-execute` 内检测 spill 是否已运行（不可靠，优先用测试约束）。

---

## 6. 规则引擎

### 6.1 规则模型

```yaml
rules:
  - id: deny-env-read
    action: deny            # allow | deny | ask
    priority: 100           # 高者先；同优先级按声明顺序
    match:
      tools: [read, grep, bash, pwsh]     # glob
      params:                             # 参数键值匹配
        file_path: ["**/.env", "**/.env.*"]
      paths: ["**/.env", "**/.ssh/**"]    # 从任意嵌套参数提取
      argv:                               # bash 分解
        command: "cat"
        anyArg: ["**/.env"]
      agents: [main, subagent]            # 可选
      when:
        platform: [darwin, linux]
    reason: "读取 .env 被拦截；请改用 .env.example"
    enabled: true
```

### 6.2 匹配语义

- `tools` / `params` / `paths` / `argv` / `agents` / `when` 之间是 **AND**；每个维度内部是 **OR**。
- 规则没有约束维度时**不匹配**（空证据不算命中）。
- 排序：`priority` 降序，稳定；first-match wins。
- 无规则命中 → `defaultDecision`（默认 `ask`，可配 `allow`）。
- 求值异常 → `failClosed: true` 时 `deny`。

### 6.3 内置基线

vendor 自 `dsh-permission-rules` 的 `rules/builtin-high-risk.yaml`（Apache-2.0，保留归属），追加在用户规则之后，因此用户规则可覆盖。

基线内容：

- 破坏性命令：`rm -rf /`、`mkfs`、`dd of=/dev/*`、`chmod -R 777`、fork bomb；
- 提权/宿主控制：`chmod u+s`、`shutdown`、`reboot`；
- RCE：`curl|sh`、`wget|bash`；
- 敏感路径：`.ssh`、`.env`、`.aws`、`.gnupg`、`.kube`、`*.pem`、`*.key`、`credentials`、`kubeconfig`、`id_rsa*`、`id_ed25519*`。

**本地覆盖**：默认把敏感路径从基线 `ask` 改成 `deny`（项目 `.dsh/rules.yaml` 覆盖），因为 auto-approval 可能批准 `ask`。

### 6.4 路径解析与防绕过

- 支持 `~` 展开、环境变量展开（白名单变量）。
- 相对路径按 `agent.session.header.cwd` 解析。
- 同时匹配“原始字符串”和 `realpathSync` 结果；symlink 指向敏感路径同样拦截。
- Windows 路径统一为 `/`，大小写按配置处理。
- 只读不存在的路径：`realpath` 失败时用规范化绝对路径匹配。

### 6.5 bash argv 分解

- 自己实现轻量 tokenizer：处理单/双引号、反斜杠、`|`、`&&`、`;`、重定向。
- 输出：`command`（第一个词）、`args[]`（token）、`pipeline`（规范化管道串）。
- 不做变量展开、不执行任何命令。
- 对 `bash -c "..."`：递归解析内层字符串（最多 3 层）。
- 对 `sudo`/`env` 前缀：剥离后取真实命令词。

### 6.6 网络规则（v1）

- 覆盖 `web_fetch`/`web_search` 的 URL，以及 bash 命令中的 URL。
- 规则：`domains`（glob）、`ports`、`schemes`、`allow/deny/ask`。
- URL 带 userinfo（`http://user:pass@host`）一律 `deny`。
- 查询参数名命中 `token|key|secret|password|sig|auth` → `ask`。
- **不做**进程级代理（v1）；v2 的决策见下。

#### 6.6.1 v2 出站守卫（目的地址级，已实现，默认关闭）

- **机制**：插件在 `127.0.0.1:<egress.port>`（默认 41999）起一个 `node:http` 监听，同时处理 CONNECT 隧道与明文 HTTP 转发；用户在 `$DSH_HOME/.env`（或 shell）里设置 `https_proxy=http://127.0.0.1:<port>`，由 DSH 启动器在**插件加载前**装成进程级 dispatcher，并下发给子进程（`@deepseek-ai/dsh-http-proxy`）。守卫不改造该缝隙，只做它的**端点**。
- **可见性**：HTTPS 只有 `host:port`（不解析 SNI、不需要 CA）；明文 HTTP 可见请求行/头/正文，但审计只记 host/port/decision/bytes。
- **策略**：`egress.allow` / `egress.deny`（`host`、`host:port`，host 位置支持 glob；IPv6 必须加括号；`deny` 优先）；未命中按 `egress.unknown`，默认 `allow`（allow-with-audit，先收集 deny 清单）。
- **模式**：`monitor` 一律放行、只审计；`enforce` 只拒绝命中 deny 的目标（`unknown: deny` 时才是白名单）。
- **挂载**：端口写死（env 是启动快照），绑定失败在 `failClosed: true` 时让插件挂载失败，不静默降级；`upstream` 可串联企业代理。
- **审计**：`phase: "egress"`，事件 `mount`/`connect`/`close`/`deny`/`canary`/`error`，只记 host/port/decision/rule id/bytes/duration。
- **拒绝语义**：CONNECT 返回 `403` + `X-Guard-Reason`（`denied-by-rule`、`unknown-destination-blocked`、`invalid-target`、`upstream-failure`），调用侧呈现为 `fetch failed`；不做交互式 `ask`（隧道没有会话上下文，挂起握手等于卡死）。
- **doctor**：`/guard egress status` 报告监听、`https_proxy` 是否指向本进程、规则数、隧道/拦截/字节计数与最近目标；`/guard egress canary` 用回环回显探针证明隧道可用；挂载时自动跑一次并写审计。
- **失败语义**：代用量不正确时 DSH **fail-open**（报告后直连），所以守卫不宣称 enforce，只把"env 未接线"如实写进 status、启动告警与审计。
- **已知盲区**（必须写进用户文档）：DSH 对 loopback 强制直连；telemetry 走 `node:http`、不认代理；PTC/workflow worker 按设计不下发代理；Node 22.19/22.20 子进程直连；JVM、rustls（`webpki-roots`）、静态 Go、容器不认 env；SSH/22、原始套接字、HTTP/3 不在范围内。守卫不是沙箱。

### 6.7 dry-run / monitor

```yaml
mode: monitor   # monitor = 只审计不拦截；enforce = 生效
```

- `monitor` 下 `deny`/`ask` 只写审计，仍 `next()`。
- 建议先跑 3–7 天，收集误报，再切 `enforce`。
- 单条规则支持 `enforce: false` 做灰度。

---

## 7. 脱敏引擎

### 7.1 规则分层

采用 `dsh-secret-scrub` 的三层模型：

| Tier | 内容 | 默认 |
|---|---|---|
| 0 | 核心密钥：PEM、AWS、GitHub、OpenAI/Anthropic/DeepSeek、GitLab、Stripe、Slack、npm、PyPI、JWT、URL 凭据 | 永远启用 |
| 1 | 赋值与云厂商：`AWS_SECRET_ACCESS_KEY=…`、Azure、阿里云、通用 `key/secret/token/password=…` | `balanced` 起 |
| 2 | PII 与高熵 fallback：邮箱、手机、身份证、银行卡（Luhn）、SSN、高熵 token | `aggressive` |

**输入与输出分离**：

- `inputLevel`：用户消息，默认 `aggressive`。
- `outputLevel`：工具结果，默认 `balanced`（可调）。

### 7.2 检测器

- 正则为主；校验和类型额外验证（Luhn、mod-97）。
- 规则表来源：vendor `dsh-secret-scrub` 的 `lib/rules.js`（MIT），保留版权与修改说明；补充：
  - `AIza` Google key（secret-scrub 未列）；
  - `xox[baprs]-` Slack（已有）；
  - Bearer token（已有 `generic-bearer`）；
  - 更多云厂商（按需）。
- 自定义规则：`extra: [{category, pattern}]`，加载时编译并验证。

### 7.3 假阳性过滤

吸收 secret-scrub 的过滤器：

- 安全 env 名：`PASSWORD_STORE_DIR` 等；
- 文档占位符：`xxx`、`example`、`your_`、`placeholder`、`redacted`；
- 代码属性链：`password=req.body.password`；
- 字符类多样性、去重字符数、纯字母长度下限；
- 常见英文词粘连检测（高熵 fallback）。

PII 额外过滤：

- 手机号排除 ISO 日期、版本号；
- 银行卡 Luhn；
- 身份证校验位（可选）。

### 7.4 占位符与假名

**Secrets**：

```text
[SECRET:<category>:<id>]
例：[SECRET:aws_access_key:7Q2F]
```

- `id` 是会话内随机 4 位 base32，按“唯一原文”复用。
- 映射只在内存；不落盘；不可恢复。

**PII**：

```text
[[PII_<TYPE>_<hash8>]]
例：[[PII_EMAIL_3f9a2c1d]]
```

- `hash8` = HMAC-SHA256(key, type + normalized value) 前 8 hex。
- key 文件：`$DSH_HOME/sensitive-guard-pii.key`，32 字节，0600。
- 跨会话/重启稳定；无 key 时用进程内随机 key（不稳定但可用）。

### 7.5 可逆性策略

| 类型 | 可逆 | 原因 |
|---|---|---|
| Secrets | ❌ 不可逆 | 明文恢复表落盘是二次泄露风险 |
| PII | ✅ 可选 | 业务可能需要还原；通过 `/guard restore` 写 0600 文件，绝不回显 |

### 7.6 `value` 与 `content` 同步

- `tools/post-execute` 命中时优先替换 `value`，由工具 renderer 生成脱敏 content。
- 若工具没有 value（错误）或 value 不是 JSON，替换 `content`。
- 递归替换 JSON 字符串，保持对象/数组结构，满足输出 schema。
- `read` 的 `lines[].text` 单独处理。

### 7.7 幂等与性能

- 已存在的占位符不再二次检测（正则前缀排除）。
- 单次扫描上限：`maxScanBytes`（默认 4 MiB）；超限时分段扫描首尾 + 抽样中段，并审计 `scan-truncated`。
- 规则按类别预编译；避免灾难性回溯（限制重复/回溯，加载时拒绝可疑模式）。
- 大结果先扫描，命中即短路；未命中交给 spill。

---

## 8. 配置

### 8.1 Schema（schemastery）

```js
{
  mode: 'monitor' | 'enforce',          // 默认 monitor
  defaultDecision: 'ask' | 'allow' | 'deny',
  failClosed: true,
  redact: {
    userMessages: true,
    toolResults: true,
    systemPrompt: true,
    ptcLog: true,
    notify: false,
  },
  levels: {
    input: 'minimal' | 'balanced' | 'aggressive',
    output: 'minimal' | 'balanced' | 'aggressive',
  },
  policy: {
    rulesFile: '.dsh/rules.yaml',
    builtin: true,
    maxRules: 256,
  },
  paths: {
    deny: [ '**/.env', ... ],
    allow: [ '**/.env.example', ... ],
  },
  network: {
    enabled: true,
    default: 'ask',
  },
  pii: {
    enabled: true,
    keyFile: '',
    restore: false,
  },
  limits: {
    maxScanBytes: 4 * 1024 * 1024,
    maxArgsBytes: 128 * 1024,
  },
  audit: {
    enabled: true,
    path: '~/.dsh/audit/sensitive-guard.jsonl',
    rotateBytes: 5 * 1024 * 1024,
  },
}
```

### 8.2 Profile patch 示例

```yaml
# ~/.dsh/profiles/web/cordis.patch.yml
- insert:
    - id: sensitive-guard
      name: dsh-sensitive-guard
      config:
        mode: monitor
        redact:
          userMessages: true
          toolResults: true
          systemPrompt: true
          ptcLog: true
        policy:
          rulesFile: .dsh/rules.yaml
          builtin: true
        levels:
          input: aggressive
          output: balanced
```

### 8.3 项目规则文件示例

```yaml
# <project>/.dsh/rules.yaml
rules:
  - id: allow-env-example
    action: allow
    priority: 200
    match:
      paths: ["**/.env.example", "**/.env.sample", "**/.env.template"]

  - id: deny-credential-paths
    action: deny
    priority: 190
    match:
      paths:
        - "**/.env"
        - "**/.env.*"
        - "**/.ssh/**"
        - "**/.aws/**"
        - "**/.gnupg/**"
        - "**/.kube/**"
        - "**/.npmrc"
        - "**/.netrc"
        - "**/*.pem"
        - "**/*.key"
        - "**/id_rsa*"
        - "**/id_ed25519*"
        - "**/.dsh/.credentials.yaml"
    reason: "敏感凭据路径；请改用 .env.example 或让用户提供"

  - id: deny-env-dump
    action: deny
    priority: 180
    match:
      tools: [bash, pwsh]
      argv:
        command: [printenv, env]
    reason: "禁止导出环境变量；需要某个变量时请只读取该变量名"
```

---

## 9. 审计

### 9.1 记录内容

```json
{"ts":1760000000000,"phase":"decision","session":"…","tool":"read","args_hash":"3f9a…","decision":"deny","rule":"deny-credential-paths","path_hash":"ab12…","action":"blocked"}
{"ts":1760000000001,"phase":"redact","session":"…","tool":"bash","rule":"aws-access-key","count":1,"placeholder_id":"7Q2F"}
```

- 不含原文、不含路径明文（路径 hash）。
- `args_hash`：规范化 JSON 的 SHA-256 前 16 hex。
- 写失败只 warn 一次，不影响工具调用。

### 9.2 轮转与权限

- 默认 `~/.dsh/audit/sensitive-guard.jsonl`，目录 700，文件 600。
- 5 MiB 轮转为 `.1`，保留最近 5 份。

### 9.3 隐私

- 审计可用于回答“为什么被拦/被脱敏”，但不提供原文。
- 不记录占位符→原文映射。

---

## 10. 失败与降级

| 场景 | 行为 |
|---|---|
| 规则文件 YAML 无效 | 启动失败（fail loud），不静默放行 |
| 正则编译失败 | 启动失败 |
| 求值异常 | `failClosed: true` → deny；否则 `ask` |
| 脱敏器异常 | 默认 **block**（返回脱敏失败占位 + 审计），绝不透传原文 |
| 审计写失败 | warn 一次，不影响主流程 |
| spill 短路导致内容未截断 | 记录 `spill-bypassed` 审计；超大结果仍受模型上下文限制 |
| system prompt 服务缺失 | 监听器不注册，启动不报错 |
| 配置 `mode: monitor` | 所有拦截只审计，不改变行为 |

**原则**：安全路径 fail-closed；可用性路径 fail-open 只用于审计等非关键副作用。

---

## 11. 第三方优点整合与许可证

### 11.1 来源与许可

| 来源 | 版本 | 许可证 | 版权 |
|---|---|---|---|
| `dsh-permission-rules` | 0.7.20 | Apache-2.0 | Copyright 2026 PerryLink |
| `dsh-secret-scrub` | 0.1.2 | MIT | Copyright (c) 2026 jkt-check |
| `dsh-mask` | 0.2.22 | Apache-2.0 | PerryLink |
| `dsh-pii-anonymizer` | 0.2.0 | MIT | Copyright (c) 2026 JWE24-code |
| `@mkaliezz/dsh-secret-guard` | 0.2.1 | MIT | Copyright (c) 2026 MkaliezZ |
| `dsh-secret-scan` | 0.2.0 | MIT | Copyright (c) 2026 DeepWhale (深鲸) |

### 11.2 吸收方式

| 优点 | 来源 | 方式 |
|---|---|---|
| 三维规则模型、优先级、dry-run、审计、内置基线、glob 上限 | permission-rules | **重写**引擎；**vendor** `baseline.yaml`（Apache-2.0） |
| tier 0/1/2、input/output level、假阳性过滤、分类占位符、ptc 日志 | secret-scrub | **vendor** 规则表与 `scrubText`（MIT），补 `value`/spill/system prompt |
| 可逆 restore table、0600 恢复文件、计数审计 | dsh-mask | **只吸收思想**；secrets 不做可逆 |
| HMAC keyed 稳定假名、system prompt 覆盖、校验和、notice | pii-anonymizer | **参考/重写** |
| 参数检查、size bound、protectedTools、reason 不含明文 | mk-guard | **重写** |
| 仓库扫描、打码输出、pre-commit/CI | secret-scan | **独立 CLI**（MIT） |

### 11.3 文件归属与修改声明

- MIT 来源文件：保留原版权行 + MIT 全文；文件头加：

  ```text
  Derived from dsh-secret-scrub v0.1.2 (MIT, Copyright (c) 2026 jkt-check).
  Modified by <owner>, 2026-10-19: adapted for dsh-sensitive-guard.
  ```

- Apache-2.0 来源文件：保留 `Copyright 2026 PerryLink`、Apache-2.0 声明；修改处加“Modified by …”。无 NOTICE 文件，无需额外 NOTICE 内容。
- `THIRD_PARTY_NOTICES.md` 列出：名称、版本、许可证、版权、来源 URL、修改说明。
- 不使用原作者/插件名作为我们插件的名称、logo、商标。

### 11.4 合规清单

- [ ] 项目 `LICENSE` = Apache-2.0。
- [ ] `package.json` `license: "Apache-2.0"`，`files` 包含 `LICENSE`、`THIRD_PARTY_NOTICES.md`。
- [ ] MIT 文件的版权与许可声明完整。
- [ ] Apache-2.0 文件的归属与修改声明完整。
- [ ] README 注明“规则基线/规则表派生自 …”。
- [ ] 对外发布前法务复核。

> 说明：以上是工程合规建议，不构成法律意见；对外分发前建议让法务确认。

---

## 12. 测试计划

### 12.1 单元

| 模块 | 用例 |
|---|---|
| `matcher` | glob、路径规范化、symlink、argv 引号/管道 |
| `evaluator` | first-match、优先级、空证据不匹配、dry-run |
| `rules` | 正/负样本、Luhn、假阳性过滤、幂等 |
| `pseudonym` | HMAC 稳定性、key 轮换、无 key 降级 |
| `argguard` | size bound、protectedTools、reason 不含明文 |
| `audit` | hash、轮转、写失败不抛 |

### 12.2 集成（fake ctx）

- 构造 fake `ctx.on`，断言：
  - pre-step 返回的 messages 已脱敏；
  - pre-execute 对 `.env` 返回 deny；
  - post-execute 命中时**没有调用** `next()`（spill 短路）；
  - ptc-log 返回脱敏 blocks；
  - system-prompt 返回脱敏 sections。

### 12.3 e2e（可选）

- 临时 profile + 本地 mock provider（OpenAI-compatible），捕获请求体，断言：
  - 不含 `sk-…`/PEM/`.env` 内容；
  - 含占位符；
  - 审计有记录。
- 需要写 `~/.dsh`，单独申请权限。

### 12.4 验收用例

1. 粘贴 `sk-ant-…` → 请求与会话 `user/message` 均无明文。
2. `read ~/.ssh/id_rsa` → deny，原因不含路径明文。
3. `bash: cat .env` → deny；`cat .env.example` → allow。
4. 读取含 `password: hunter2` 的 `config.yaml` → 模型看到占位符，spill 文件无明文。
5. `web_fetch https://x/?token=…` → ask/deny。
6. PTC `run_code` 子调用读敏感文件 → 日志副本脱敏。
7. system prompt 中的自定义段落含邮箱 → 被替换。
8. `monitor` 模式只审计、不改变行为。
9. 正常 `read/write/bash` 无回归。

---

## 13. 部署与回滚

### 13.1 安装（需批准，写 `~/.dsh`）

```bash
# 开发期用 link，避免发布
dsh plugin --profile web add link:/Users/gythialy/Developer/GitHub/sensitive-guard-integration
```

- 依赖安装后，在 `~/.dsh/profiles/web/cordis.patch.yml` 增加 `sensitive-guard` 行（或包内 `dsh.bundle.patch` 自动挂载）。
- 重启 `dsh web` 生效（不自行重启当前 GUI）。

### 13.2 配置

- 全局：profile patch。
- 项目级：`<project>/.dsh/rules.yaml`。
- 先 `mode: monitor`，观察审计 3–7 天。

### 13.3 回滚

- 删除 patch 行或 `dsh plugin remove dsh-sensitive-guard`。
- 回滚不影响历史会话；已脱敏的消息保持脱敏。

---

## 14. 里程碑

| 阶段 | 内容 | 产出 |
|---|---|---|
| M0 | 本文档 review | 设计定稿 |
| M1 | 规则引擎 + 测试 | `policy/`、`matcher/`、单测 |
| M2 | 脱敏引擎 + 四个钩子 | `redact/`、`index.js`、集成测试 |
| M3 | 假名/参数检查/审计 | `pseudonym/`、`argguard/`、`audit/` |
| M4 | 安装 + monitor 观察 | profile patch、审计报告 |
| M5 | enforce + 调参 | 误报清单、规则收敛 |
| M6（可选） | `bin/scan.mjs` + skill | pre-commit/CI |

---

## 15. 风险与开放问题

| 风险 | 影响 | 缓解 |
|---|---|---|
| 误报阻断正常开发 | 高 | monitor 先行、allowPaths、按规则灰度 |
| spill 短路导致超大结果未截断 | 中 | 记录审计；对含密钥结果优先安全 |
| 上游 API 变更 | 中 | 只用稳定事件；集成测试锁定签名 |
| `realpath` 性能 | 低 | 仅对路径参数调用；缓存 |
| 高熵规则误报 git SHA | 中 | 默认 `balanced`，高熵仅 `aggressive` |
| 历史会话含密钥 | 高 | 独立清理流程，不在本插件自动改日志 |
| 第三方插件绕过 | 中 | 文档声明边界；必要时用 OS 级隔离 |

**开放问题**：

1. 是否需要在 v1 提供 `/guard status|on|off|restore` 命令？
2. PII 可逆恢复是否默认关闭？
3. 是否把 `builtin.yaml` 直接 vendor，还是重写一份更小的基线？
4. ~~是否需要在 v2 做本地 HTTP 代理（参考 permission-rules）？~~ **已决**：v2 做目的地址级 CONNECT 守卫，不做 TLS 中间人（D4b–D4e；预研见 §19，讨论见 issue #5）。
5. 审计文件是否要加密或写到 `DSH_HOME` 之外？

---

## 16. 参考

- DSH 插件 API：`@deepseek-ai/dsh-agent`、`@deepseek-ai/dsh-tools`、`@deepseek-ai/dsh-system-prompt` 包内 README（0.2.1-rc.2）。
- `dsh-permission-rules`：https://github.com/PerryLink/dsh-permission-rules （Apache-2.0）
- `dsh-secret-scrub`：https://github.com/jkt-check/dsh-secret-scrub （MIT）
- `dsh-mask`：https://github.com/PerryLink/dsh-mask （Apache-2.0）
- `dsh-pii-anonymizer`：https://github.com/JWE24-code/dsh-pii-anonymizer （MIT）
- `@mkaliezz/dsh-secret-guard`：https://github.com/MkaliezZ/dsh-secret-guard （MIT）
- `dsh-secret-scan`：https://github.com/feely0208/dsh-secret-scan （MIT）

---

## 17. 评审关注点

请重点 review 以下 6 点，确认后再进入 M1：

1. **默认策略**：`mode: monitor` + 敏感路径 `deny` 是否符合预期？是否要一开始就 `enforce`？
2. **路径范围**：默认 deny 列表是否过宽/过窄？是否要把 `~/.config/gh`、浏览器 Cookie、Keychain 也纳入？
3. **可逆性**：PII 是否需要 `/guard restore`？Secrets 确认永不可逆？
4. **短路代价**：命中密钥的结果跳过 spill 截断，是否可以接受？
5. **许可证**：项目用 Apache-2.0、vendor `secret-scrub` 规则表、vendor `permission-rules` 基线，是否认可？
6. **部署范围**：只装 `web` profile，还是所有 profile（home patch）？

## 18. 交付物清单（M1 起）

| 文件 | 内容 |
|---|---|
| `sensitive-guard-integration/package.json` | 名称（`dsh-sensitive-guard`）、入口、`dsh.compatibility`、license |
| `sensitive-guard-integration/lib/index.js` | 插件入口与五个监听器 |
| `sensitive-guard-integration/lib/policy/*` | 规则引擎 |
| `sensitive-guard-integration/lib/redact/*` | 脱敏引擎 |
| `sensitive-guard-integration/lib/audit.js` | 审计 |
| `sensitive-guard-integration/test/*.test.js` | `node --test` |
| `sensitive-guard-integration/THIRD_PARTY_NOTICES.md` | 许可证归属 |
| `sensitive-guard-integration/docs/sensitive-guard-integration.md` | 本文 |

---

## 19. v2 出站守卫：预研结论（2026-10-20）

预研对象：issue #5「evaluate a process-level HTTP proxy」。方法：只读检查已安装的 DSH `0.2.1-rc.2`、在本机跑 CONNECT 代理与 dispatcher 拦截器 PoC（Node 26.12.0 / macOS），并对候选实现做复用评估。结论落在 D4b–D4e，§6.6.1 为实现约束。

### 19.1 结论

1. **缝隙已存在且归启动器所有。** `@deepseek-ai/dsh-http-proxy`（MIT）在任何插件加载前安装进程级 undici dispatcher，并把同一策略下发给子进程。v2 不重造它，只做它的**端点**。
2. **插件内拦截不可用。** 包装全局 dispatcher 能截到普通 `fetch`，但 `web_fetch` 两个分支都绕过：未代理时它自 pin 一个 `Agent`，代理时用 `proxyRouteFor` 在安装时捕获的 dispatcher。DSH 的 disposer 还会在卸载时还原 dispatcher。
3. **只做目的地址级。** CONNECT 隧道只能看到 `host:port`，这正是第三方插件/MCP 子进程缺口的控制点；正文级控制留在工具管线——那里本来就是明文。
4. **不做 CA。** TLS 中间人的成本在分发而非代码：启动前必须就绪的 `NODE_EXTRA_CA_CERTS`、各平台信任库、JVM/rustls/静态 Go/容器绕过；而且守卫会因此持有 provider 凭据。

### 19.2 可见性与覆盖

| 层级 | 可见内容 | 需要 CA |
|---|---|---|
| CONNECT 隧道 | `host:port`（SNI 需解析 ClientHello） | 否 |
| 明文 HTTP | 方法、URL、头、正文 | 否 |
| TLS 终止 | 全部（含 `Authorization`） | 是，且必须在启动前就绪 |

| 路径 | 现状 | 出站守卫的增量 |
|---|---|---|
| 1 粘贴 / 2 工具读 / 3 spill / 4 PTC / 5 system prompt | 钩子已覆盖 | 无（本就是进程内明文） |
| 2b 子进程（`curl`/`gh`/`git`/`npx`/`pip`） | argv/URL 规则部分覆盖 | **目的地址强制**，含"脚本自己读 `.env`"的情况 |
| 9 第三方插件 / MCP 内部 | 未覆盖 | **host 级覆盖**（MCP stdio 子进程、走 `fetch` 的 SDK） |
| 7 assistant 复述 / 8 图像 / 10 provider 留存 | 未覆盖 | 无 |

### 19.3 实现约束（来自 PoC 与 DSH 设计）

- 端口必须在启动前确定（env 是启动快照），冲突必须报错，不能悄悄换端口。
- 拒绝在调用侧呈现为 `fetch failed` / `403`，需带回可读原因（`X-Guard-Reason` 一类），由工具级规则向模型解释阻断。
- CONNECT 阶段无法做交互式 `ask`：隧道没有会话上下文，挂起握手等于卡死（`permission-rules` 同样受此限制）。
- 归因：env 是进程级的，"哪个子进程"需要 per-spawn 代理用户名，留作后续研究。
- 守卫只对"配置正确且客户端遵守代理"的场景有效；恶意插件可以直接开 socket，这不是沙箱（与 §1.3 的边界一致）。

### 19.4 未决问题（已决）

1. `enforce` 下未知主机：**allow-with-audit**（`egress.unknown: allow`，默认）。理由：先让守卫可观测、低噪音地跑一段，用 `connect` 审计攒出 deny 清单；需要白名单时改 `unknown: deny`。
2. 端口**写死在 config**（`egress.port`，默认 41999）。env 是启动快照，端口文件会和它竞争；端口被占用时 `failClosed` 让挂载失败，绝不悄悄换端口。
3. 审计字段够用：host/port/decision/rule/bytes/duration。明文 HTTP **不记** path/query，避免把 URL 里的标识写进日志。
4. loopback 盲区只在文档声明（`docs/configuration.md` 的 `egress` 节），工具级规则不特殊处理 `127.0.0.1`。

### 19.5 实现与验证

- **代码**：`src/egress/policy.ts`（host/port 规则与解析）、`server.ts`（CONNECT + 明文 HTTP 转发、upstream 串联、字节计数）、`canary.ts`（回环回显探针）、`index.ts`（挂载、env 校验、计数与快照）；配置 `egress.*`；审计 `phase: "egress"`；命令 `/guard egress [status|canary]`。`apply()` 在 `egress.enabled` 时异步挂载，并把关闭监听的 disposer 交给 cordis；绑定失败即插件挂载失败。
- **测试**：规则单测；真实 listener 的 CONNECT/明文 HTTP（allow、deny、monitor、unknown-deny、缺端口 authority、端口占用、upstream 串联与 502）；canary 的 ok/denied/refused/timeout；`apply()` 全链路（审计落盘 + 命令输出 + dispose 关监听 + fail-closed 拒载）；真实子进程 `curl -x` 的放行与 403；审计报告（窗口、轮转、坏行、YAML 建议）。
- **e2e**：`test/e2e/egress.mjs` 用临时 `DSH_HOME` 启动 headless profile，把 `http(s)_proxy` 指向守卫，让 mock provider 触发 `bash` 工具，验证主机派生子进程的请求确实经过守卫并写入 `phase: "egress"` 审计；deny 场景验证 `enforced: true` 且目标服务器零请求。监听器 `unref()`，headless 一次性运行结束即可退出。
- **实测**：macOS / Node 26.12.0。拒绝 CONNECT 时 curl 退出码 7，stderr 为 `CONNECT tunnel failed, response 403`；放行路径正常转发。
- **未做**：TLS 中间人（D4c 维持否决，门槛见 §19.7）、per-child 归因（env 是进程级，结论见 §19.6）、系统级透明拦截（D4e）。

### 19.6 归因研究：per-spawn 代理身份（issue #20）

**结论：当前插件缝隙无法实现 per-child 归因**。守卫能回答"某个客户端访问了哪个目标"，不能回答"是哪个子进程/工具/会话"。改变这一点需要宿主支持，不是插件改动。

只读检查已安装 DSH `0.2.1-rc.2` 得到的证据：

| 缝隙 | 事实 | 结论 |
|---|---|---|
| `tools/pre-execute` | `dsh-tools` README 明确 **deliberately cannot rewrite `exec.arguments`**；该事件只做 allow/deny/ask，`ctx.tools.guard()` 是单调 deny | 插件既改不了命令，也够不到 spawn env |
| `@deepseek-ai/dsh-subprocess` | `scrubbedParentEnv()` 去掉凭据形状的变量与 `DSH_*`，再用 `proxyEnvironmentForChild()` 合并代理值 | 每个子进程拿到**同一套**代理值 |
| `@deepseek-ai/dsh-mcp-client` | stdio 子进程的 `env` 是 profile 里的静态配置，合并覆盖 scrubbed parent env | 只能按"服务器条目"区分配置，不是运行时归因 |
| PTC / workflow worker | 设计上不下发代理 | 本来就不在守卫覆盖范围内 |

候选路径，按代价从低到高：

1. **宿主提供 child 标识**：`SubprocessRuntime` / `proxyEnvironmentForChild()` 接受一个 child id，把代理写成 `http://<id>:<token>@127.0.0.1:<port>`；守卫按 userinfo 拆分身份，审计补 `client` 字段。需要上游 DSH 变更。
2. **per-child 端口池**：守卫监听多个端口，宿主按 child 分配。同样要宿主支持，并与"端口写死在启动快照里"的约束冲突（D4b）。
3. **工具级包装**：给每个工具注入不同 env —— 只有工具自己声明 env 才行，`pre-execute` 改不了，不可行。

**建议**：向 DSH 提交 feature request（附本节）；插件侧先把审计字段留成可扩展（`phase: "egress"` 已有 host/port/decision/rule/bytes，加 `client` 向后兼容），等宿主给出 child 标识再补。在此之前，文档继续声明"审计无归因"。
