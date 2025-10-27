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
<!-- file: README.md -->
<!-- author: Arieditya Pramadyana Deha <arieditya.prdh@live.com> -->
# xctx - Cross Context

Encrypted, signed, **typed** context propagation over a single HTTP header (`X-Context`) with **Go** and **PHP** reference implementations.

- **Single header** transport (`v1.<base64url(JSON)>`)
- **AEAD (AES‑256‑GCM)** with per‑message nonce, versioning, and key IDs (KID) for rotation
- **Claims** (`iss`, `aud`, `iat`, `nbf`, `exp`, `jti`) validated on the callee
- **Typed payload** `T` (Go generics) / associative array (PHP) — the library is schema‑agnostic
- **AAD binding** for tenant/env binding (non‑secret but must match on both sides)
- **Cross‑language** interop (Go ↔ PHP) proven in examples

> License: Apache‑2.0 (see `LICENSE-APACHE-2.0.txt`). Composer package declares `Apache-2.0`.

## Why

Passing many fields across services via body/query/headers is brittle and leaky (and sometimes plain-text). `xctx` gives you a single, encrypted, signed envelope carrying exactly the **system-defined** context you want — no more, no less — without the library knowing your field schema.

## File Structure
```text
xctx
├── LICENSE-APACHE-2.0.txt
├── README.md
├── clover.xml
├── composer.json
├── composer.lock
├── coverage.out
├── example
│   ├── callee
│   │   ├── go.mod
│   │   ├── main.go
│   │   └── main.php
│   └── caller
│       ├── go.mod
│       ├── main.go
│       └── main.php
├── go.mod
├── phpunit.xml.dist
├── src
│   └── Xctx
│       ├── Codec.php
│       ├── Config.php
│       ├── Exception
│       │   ├── CryptoException.php
│       │   ├── ValidationException.php
│       │   └── XctxException.php
│       ├── Keyring.php
│       └── Util
│           └── Base64Url.php
├── test
│   ├── CodecExceptionBranchesTest.php
│   ├── CodecTest.php
│   ├── ConfigTest.php
│   └── overrides
│       └── crypto_overrides.php
├── xctx.go
├── xctx_blackbox_test.go
├── xctx_config.go
├── xctx_config_blackbox_test.go
├── xctx_config_whitebox_test.go
└── xctx_whitebox_test.go
```

## Quick Start

See **[USAGE.md](USAGE.md)** for comprehensive instructions. TL;DR:

### Go

```go
type PassingContext struct {
    UserID   int32  `json:"user_id"`
    UserName string `json:"user_name"`
    Role     string `json:"role,omitempty"`
}

user := xctx.Config{ /* header, issuer, audience, TTL, keys... */ }
aad  := func() []byte { return []byte("TENANT=blue|ENV=dev") }

codec, typedKey, err := xctx.BuildCodecFromEnvWithKey[PassingContext](user, nil, aad)
if err != nil { /* handle */ }

// Caller: inject typed payload into context and seal
ctx := xctx.DefaultInjector[PassingContext](typedKey)(context.Background(), PassingContext{UserID:7, UserName:"arie"})
name, value, _ := codec.EmbedHeaderCtx(ctx) // ("X-Context", "v1.<...>")

// Callee: parse from *http.Request
newCtx, payload, err := codec.ParseCtx(r)
```

### PHP

```php
use ArieDeha\Xctx\{Config, Codec};

$user = new Config(headerName: 'X-Context', issuer: 'svc-caller', audience: 'svc-callee',
                   ttlSeconds: 120, currentKid: 'kid-demo',
                   currentKey: '0123456789abcdef0123456789abcdef');
$aad  = fn() => 'TENANT=blue|ENV=dev';

$codec = Codec::buildFromEnv($user, $aad);

// Caller: seal
[$name, $value] = $codec->embedHeader(['user_id'=>7,'user_name'=>'arie']);

// Callee: parse
[$payload, $claims] = $codec->parseHeaderValue($value);
```

## Examples

- **Go callee** at `:8081` and **PHP callee** at `:8082` with mutual relays/mutations.
- **Go** and **PHP** callers demonstrate cross‑language portability and chained updates.

Run order:

```bash
# Terminal A
go run ./example/callee

# Terminal B
php -S 127.0.0.1:8082 -t example/callee example/callee/router.php  # or: php -S 127.0.0.1:8082 example/callee/main.php

# Terminal C
go run ./example/caller

# Terminal D
php example/caller/main.php
```

## Envelope

`X-Context: v1.<base64url(json)>` where `json` has lowercase keys:

```json
{ "v":1, "alg":"AES256-GCM", "kid":"kid-demo", "n":"...", "ct":"..." }
```

Both implementations accept `AES256-GCM`/`AES-256-GCM` and lowercase/uppercase keys on parse. Emit is canonicalized to **lowercase keys** for interop with Go.

## Configuration

See **[USAGE.md](USAGE.md)** for environment variables, key formats (raw/hex/base64), and AAD binding guidance.

## Development

- See **[DEVELOPERS.md](DEVELOPERS.md)** for building, testing, and coverage (Go & PHP).
- Security notes: short TTLs, rotation with `OtherKeys`, replay mitigation with `jti`, strict claim checks.
