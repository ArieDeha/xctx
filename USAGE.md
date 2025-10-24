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
<!-- file: USAGE.md -->
<!-- author: Arieditya Pramadyana Deha <arieditya.prdh@live.com> -->
# xctx Usage

This guide shows how to configure and use xctx in **Go** and **PHP**, including caller/callee wiring, AAD, and rotation.

## Configuration (shared concepts)

### Required (unless provided via overrides)
- `XCTX_CURRENT_KID` — key id string, e.g. `kid-demo`
- `XCTX_CURRENT_KEY` — **32‑byte key** for AES‑256‑GCM
  - Accepted encodings (PHP & Go loaders):
    - raw 32‑byte string (length 32)
    - hex (64 hex chars)
    - base64 or base64url (std/raw)

### Optional
- `XCTX_HEADER_NAME` — default `X-Context`
- `XCTX_ISSUER`      — string
- `XCTX_AUDIENCE`    — string
- `XCTX_TTL`         — duration (`30s`, `2m`, `1h`)
- `XCTX_OTHER_KEYS`  — rotation accept list: `kid1=KEY1,kid2=KEY2`
- `XCTX_TYPED_KEY`   — Go: typed key identity (safer per‑process name)
- `XCTX_AAD`         — optional AAD binder value; **must match** both sides

### Additional Authenticated Data (AAD)

AAD binds non‑secret context (e.g., tenant/environment) into the AEAD tag. Decryption **fails** if producers/consumers disagree. Treat AAD like **salt** in purpose (bind), but unlike salt it **must be the same** across all parties for a given message.

## Go

### Building a codec

```go
codec, typedKey, err := xctx.BuildCodecFromEnvWithKey[PassingContext](userOverrides, nil, aad)
```

- Merges env + `userOverrides`, validates, creates/loads `Keyring`.
- Wires `DefaultExtractor/Injector` using the returned `typedKey`.
- Returns `Codec[T]` and the `TypedKey[T]` you must use to inject before sealing.

### Caller side (seal)

```go
payload := PassingContext{UserID:7, UserName:"arie", Role:"admin"}
ctx := xctx.DefaultInjector[PassingContext](typedKey)(context.Background(), payload)
name, value, err := codec.EmbedHeaderCtx(ctx)  // -> ("X-Context","v1.<...>")
req.Header.Set(name, value)
```

### Callee side (parse)

```go
newCtx, payload, err := codec.ParseCtx(r) // returns derived context + typed value
```

### Rotating keys

- Produce with `CurrentKID/CurrentKey`.
- Accept older tokens by setting `OtherKeys: map[string][]byte{"old": <32B>}` on callees.

## PHP

### Building a codec

```php
use ArieDeha\Xctx\{Config, Codec};

$user = new Config(
  headerName: 'X-Context',
  issuer:     'svc-caller',
  audience:   'svc-callee',
  ttlSeconds: 120,
  currentKid: 'kid-demo',
  currentKey: '0123456789abcdef0123456789abcdef',
  otherKeys:  ['old-kid' => '<32B KEY HERE>']
);
$aad = fn() => 'TENANT=blue|ENV=dev';

$codec = Codec::buildFromEnv($user, $aad);
```

### Caller side (seal)

```php
[$name, $value] = $codec->embedHeader(['user_id'=>7,'user_name'=>'arie','role'=>'admin']);
$req->withHeader($name, $value); // or curl_setopt header, etc.
```

### Callee side (parse)

```php
[$payload, $claims] = $codec->parseHeaderValue($value);
// or: [$payload, $claims] = $codec->parseFromRequest($psr7Request);
```

### PSR-7 helpers

- `Codec::setHeader(RequestInterface $req, array|object $payload): RequestInterface`
- `Codec::parseFromRequest(RequestInterface $req): array{0: array, 1: array}`

If `psr/http-message` is not installed, the helpers throw `ValidationException`;
call `embedHeader()` / `parseHeaderValue()` directly instead.

## Envelope compatibility

- Emit: lowercase keys (`v`, `alg`, `kid`, `n`, `ct`) to match Go.
- Parse: tolerant to lowercase/UPPERCASE and `AES256-GCM`/`AES-256-GCM`.

## Security notes

- Keep TTL short (≤ 2m). Enforce `iss`/`aud` strictly.
- Use `jti` and server-side session/nonce caches if you need hard replay protection.
- Prefer rotation via `OtherKeys` on accepting services; roll producers last.
