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
# xctx – File Structure

This document describes the structure of `xctx` repository.

## File Structure
```text
xctx/                                                      — Monorepo root: Go + PHP + Node implementations
│
│ ## SOURCE
├── src/
│   ├── Xctx/                                               — PHP library (PSR-4: ArieDeha\Xctx\…)
│   │   ├── Codec.php                                       — Seal/parse header, AEAD, claims, PSR-7 helpers
│   │   ├── Config.php                                      — Env loader, user overrides, validation
│   │   ├── Exception/
│   │   │   ├── CryptoException.php                         — Crypto failures (auth/tag/nonce/etc.)
│   │   │   ├── ValidationException.php                     — Input/config/claim validation errors
│   │   │   └── XctxException.php                           — Base exception type
│   │   ├── Keyring.php                                     — Current/other keys; integrity checks; KID lookup
│   │   └── Util/
│   │       └── Base64Url.php                               — URL-safe Base64 helpers (no padding)
│   └── nodejs/                                             — Node/TypeScript library (ESM; interop with Go/PHP)
│       ├── index.ts                                        — Public exports barrel (re-exports from files below)
│       ├── types.ts                                        — Envelope/claims/config types
│       ├── util/
│       │   ├── base64url.ts                                — URL-safe Base64 helpers
│       │   └── claims.ts                                   — Claim builder (iat/nbf/exp/jti)
│       ├── keyring.ts                                      — Keyring (current/other keys; validation)
│       ├── codec.ts                                        — AES-256-GCM envelope (seal/parse; AAD support)
│       ├── validation.ts                                   — TTL/keys parsing validation
│       └── express.ts                                      — Optional Express middleware (parse + attach to req)
│
│ ## TESTS
├── test/
│   ├── CodecExceptionBranchesTest.php                      — PHP negative/branch tests for Codec
│   ├── CodecTest.php                                       — PHP round-trip, tamper, PSR-7 helpers, expiry
│   ├── ConfigTest.php                                      — PHP config/env/merge/validation tests
│   ├── overrides/
│   │   └── crypto_overrides.php                            — Deterministic openssl overrides for failure cases
│   └── nodejs/                                             — Node/TS unit tests (Vitest or Jest)
│       ├── codec.spec.ts                                   — Round-trip, tamper, AAD mismatch, expiry
│       ├── config.spec.ts                                  — Env/merge/TTL/keys parsing validation
│       ├── claims.spec.ts                                  — Claim builder (iat/nbf/exp/jti)
│       ├── base64url.spec.ts                               — URL-safe Base64 helpers
│       ├── express.spec.ts                                 — Optional Express middleware (parse + attach to req)
│       └── keyring.spec.ts                                 — Key invariants and KID lookups
│
│ ## EXAMPLES
├── example/
│   ├── callee/                                             — Callee servers (parse/mutate/relay context)
│   │   ├── go.mod                                          — Go module for callee
│   │   ├── main.go                                         — Go callee (HTTP :8081)
│   │   ├── main.ts                                         — Node callee (Express :8083, optional)
│   │   └── main.php                                        — PHP callee (built-in server :8082/router.php)
│   └── caller/                                             — Caller clients (create + send context)
│       ├── go.mod                                          — Go module for caller
│       ├── main.go                                         — Go caller (calls all callees; relay chains)
│       ├── main.ts                                         — Node caller (optional CLI/http client)
│       └── main.php                                        — PHP caller (curl/PSR-7)
│
│ ## License and Other Docs
├── LICENSE-APACHE-2.0.txt                                  — Root license (Apache-2.0)
├── DEVELOPERS.md                                           — Building, testing, coverage, CI tips
├── USAGE.md                                                — How to configure and use Go/PHP/Node libraries
├── README.md                                               — Overview and quick starts
├── STRUCTURE.md                                            — This annotated tree (keep in sync post-changes)
│
│ ## PHP
├── clover.xml                                              — PHPUnit coverage (Clover) for IDEs (PHPStorm)
├── composer.json                                           — PHP package metadata/autoload
├── composer.lock                                           — Locked PHP deps
├── phpunit.xml.dist                                        — PHPUnit config (bootstrap, coverage)
│
│ ## NodeJS
├── package.json                                            — Node package manifest (build/test/exports)
├── package.lock.json                                            — Node package manifest (build/test/exports)
├── tsconfig.base.json                                           — TypeScript compiler options
├── tsconfig.cjs.json                                           — TypeScript compiler options
├── tsconfig.esm.json                                           — TypeScript compiler options
├── vitest.config.json                                           — TypeScript compiler options
│
│ ## Golang
├── go.mod                                                  — Go module (module github.com/ArieDeha/xctx)
├── xctx.go                                                 — Go core: envelope/AEAD/claims/extractor+injector
├── xctx_blackbox_test.go                                   — Go public behavior tests
├── xctx_config.go                                          — Go config/builders (env, keyring, AAD, typed key)
├── xctx_config_blackbox_test.go                            — Go config black-box tests
├── xctx_config_whitebox_test.go                            — Go config white-box tests
├── xctx_whitebox_test.go                                   — Go white-box tests (internals/nonce/time/errors)
└── coverage.out                                            — Go coverage profile (from `go test -coverprofile`)
```
