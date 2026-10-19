# Third-party notices

dsh-sensitive-guard is licensed under Apache-2.0 (see `LICENSE`). It contains
code and rule data derived from the following projects. The original copyright
notices are retained in the derived files, and the full license texts are
reproduced below where the upstream license requires it.

## Vendored rule baseline

### dsh-permission-rules 0.7.20

- File: `src/policy/baseline.yaml`
- Copyright 2026 PerryLink
- License: Apache-2.0
- Source: https://github.com/PerryLink/dsh-permission-rules
- Modification: the file is retained verbatim as the built-in high-risk
  baseline; only a provenance header was added. The Apache-2.0 license text is
  the project's `LICENSE`. The upstream package contains no NOTICE file.
- Usage: destructive-command, privilege-escalation, RCE, and credential-path
  rules appended after user rules.

## Derived rule table

### dsh-secret-scrub 0.1.2

- Files: `src/redact/rules.ts`, `src/redact/filters.ts`
- Copyright (c) 2026 jkt-check
- License: MIT (full text below)
- Source: https://github.com/jkt-check/dsh-secret-scrub
- Modification: converted from JavaScript to TypeScript and adapted so the
  engine supplies `[SECRET:...]` and `[[PII_...]]` placeholders instead of the
  upstream fixed placeholder. Tier ordering, patterns, validators, and
  false-positive filters are preserved.
- Usage: secret/PII detection rule table and false-positive filtering.

## Runtime dependencies

These packages are installed by the package manager rather than copied into
this repository; each retains its own license.

| Package | License | Role |
|---|---|---|
| `@deepseek-ai/schemastery` | MIT | configuration schema |
| `picomatch` | MIT | glob matching |
| `yaml` | ISC | project rule parsing |

## MIT license text

```text
MIT License

Copyright (c) 2026 jkt-check

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
