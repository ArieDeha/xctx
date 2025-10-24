<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: Copyright © 2025 Arieditya Pramadyana Deha <arieditya.prdh@live.com> -->
<!-- License: Apache-2.0 -->
<!-- License-Text: 
Copyright © 2025 Arieditya Pramadyana Deha <arieditya.prdh@live.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->
<!-- file: DEVELOPERS.md -->
<!-- author: Arieditya Pramadyana Deha <arieditya.prdh@live.com> -->
# xctx – Developers Guide

This document is for maintainers and contributors.

## Repository layout

- `xctx.go`, `xctx_config.go` — Go core
- `src/Xctx/*` — PHP core (PSR-4: `ArieDeha\Xctx\`)
- `example/` — Go & PHP caller/callee demos
- `test/` — PHP unit tests (incl. crypto overrides)
- `go.mod`, `composer.json`, `phpunit.xml.dist`

## Building & Testing

### Go

```bash
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out
```

### PHP

```bash
composer install
composer test
# Coverage (Xdebug or PCOV required)
composer coverage
# Clover written to clover.xml
```

#### PHP coverage in JetBrains IDEs
- Use the **Clover** report (`clover.xml`). PHPStorm reads Clover natively.
- Alternatively, use Xdebug/PCOV runtime coverage run configs.

## Test overrides

`test/overrides/crypto_overrides.php` provides deterministic branches by overriding `openssl_*` at runtime. Tests that mutate override state must be **isolated**:

- Annotate with `@runInSeparateProcess` and `@preserveGlobalState disabled`.
- Reset state in `setUp()` / `tearDown()`.

## Style & Docs

- **Go:** Godoc comments must start with the identifier name. Unexported helpers should still be documented (why they exist, constraints, return).
- **PHP:** Every public method needs a `/** ... */` docblock with param/return types and semantics.
- See **DOCS_REPORT.md** (generated) for missing items.

## CI ideas

- Lint Go (`golangci-lint`) and PHP (`phpstan`, `php-cs-fixer`).
- Require `go test -cover` ≥ 90% for core and `phpunit --coverage-clover` ≥ 90% for `src/`.
- Run interop smoke tests: Go caller → PHP callee and PHP caller → Go callee.

## Licensing

- Root license: **Apache‑2.0** (`LICENSE-APACHE-2.0.txt`).
- Add SPDX headers to new files:
  - Go: `// SPDX-License-Identifier: Apache-2.0`
  - PHP: `// SPDX-License-Identifier: Apache-2.0`
