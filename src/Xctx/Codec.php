<?php
// SPDX-License-Identifier: Apache-2.0

// Copyright 2025 Arieditya Pramadyana Deha <arieditya.prdh@live.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// file: ./src/Xctx/Codec.php

declare(strict_types=1);

/**
 * xctx – Encrypted, authenticated, typed context over a single HTTP header.
 *
 * This file implements the PHP codec that is wire-compatible with your Go xctx:
 * - Header name: configurable (default "X-Context")
 * - Header value: "v1." + base64url(JSON envelope)
 * - Envelope (JSON):
 *     {
 *       "V":   1,
 *       "Alg": "AES256-GCM",
 *       "KID": "<kid>",
 *       "N":   base64url(nonce12),
 *       "CT":  base64url(ciphertext || tag16)   // GCM tag appended to ciphertext
 *     }
 * - Payload (JSON, encrypted):
 *     {
 *       "iss": "...", "aud": "...",
 *       "iat": <unix>, "nbf": <unix>, "exp": <unix>, "jti": "<rand>",
 *       "ctx": <your typed data as array/object>
 *     }
 * - Cryptography: AES-256-GCM (nonce 12B, tag 16B). Integrity + confidentiality.
 * - AAD (Additional Authenticated Data): optional, not sent; must match exactly
 *   on caller and callee or decryption fails (tag mismatch).
 *
 * Design goals:
 *   • Struct-first ergonomics (your code owns the schema; the library never reflects it)
 *   • Single header transport
 *   • Explicit claims + TTL
 *   • Key rotation via KID + accepted old keys
 *
 * PHP 8.2 notes:
 *   • Properties cannot be typed as `callable`. We store AAD as `?\Closure`,
 *     and convert any incoming callable to a Closure at construction.
 *   • PSR-7 is optional. To avoid fatal parse-time errors when PSR is absent,
 *     this file does NOT typehint RequestInterface in method signatures. The
 *     helpers do runtime checks instead.
 */

namespace ArieDeha\Xctx;

use ArieDeha\Xctx\Exception\CryptoException;
use ArieDeha\Xctx\Exception\ValidationException;
use ArieDeha\Xctx\Util\Base64Url;

final class Codec
{
    /** Wire version this codec produces/accepts. */
    private const VERSION  = 1;

    /** Declared algorithm in the envelope. */
    // Old:
    // public const ALG = 'AES256-GCM';
    // Better to match Go (and still accept both on parse):
    public const ALG = 'AES256-GCM';

    /** OpenSSL cipher name for AES-256-GCM. */
    private const CIPHER   = 'aes-256-gcm';
    /** GCM nonce size in bytes. */
    private const NONCE_SZ = 12;
    /** GCM tag size in bytes. */
    private const TAG_SZ   = 16;

    /**
     * Optional AAD supplier stored as a Closure.
     * @var null|\Closure():string
     */
    private readonly ?\Closure $aadBinder;

    /**
     * Build a codec.
     *
     * @param Config        $cfg       Validated configuration (header name, TTL, claims).
     * @param Keyring       $keys      Current + accepted decryption keys.
     * @param null|callable $aadBinder Optional function that returns AAD bytes; must be
     *                                 identical on caller and callee. Not secret; used for
     *                                 binding tokens to a deployment/tenant/etc.
     *
     * @throws ValidationException if $cfg fails validation.
     */
    public function __construct(
        private readonly Config $cfg,
        private readonly Keyring $keys,
        ?callable $aadBinder = null
    ) {
        // Validate immediately so later operations can assume invariants hold.
        $this->cfg->validate();

        // PHP 8.2: properties cannot be callable; store as Closure if provided.
        $this->aadBinder = $aadBinder !== null ? \Closure::fromCallable($aadBinder) : null;
    }

    /**
     * Resolve AAD bytes (empty string if unset). Centralized to keep call sites clean.
     */
    private function aad(): string
    {
        return $this->aadBinder ? ($this->aadBinder)() : '';
    }

    /**
     * Seal a typed payload into an X-Context header.
     *
     * Steps:
     *   1) Build claims (iat/nbf/exp/jti + optional iss/aud).
     *   2) JSON-encode payload.
     *   3) AEAD-encrypt with AES-256-GCM using current key (from Keyring::encKey).
     *   4) Build envelope {V, Alg, KID, N, CT} and base64url-encode it.
     *   5) Prefix with "v1." and return [headerName, headerValue].
     *
     * @param array|object $payload Your typed context (array/object). Library does not inspect it.
     * @return array{0:string,1:string} [header name, header value]
     *
     * @throws CryptoException on JSON or crypto failure.
     */
    public function embedHeader(array|object $payload): array
    {
        [$kid, $key] = $this->keys->encKey();

        $now = time();
        $claims = [
            'iss' => $this->cfg->issuer,
            'aud' => $this->cfg->audience,
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + $this->cfg->ttlSeconds,
            'jti' => bin2hex(random_bytes(8)),
            'ctx' => $payload,
        ];
        $pt = json_encode($claims, JSON_UNESCAPED_SLASHES);
        if ($pt === false) {
            throw new CryptoException('xctx: payload json encode failed');
        }

        $nonce = random_bytes(self::NONCE_SZ);
        $aad   = $this->aad();

        $tag = '';
        $ct  = openssl_encrypt($pt, self::CIPHER, $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
        if ($ct === false || strlen($tag) !== self::TAG_SZ) {
            throw new CryptoException('xctx: openssl_encrypt failed');
        }

        $envelope = [
            'V'   => self::VERSION,
            'Alg' => self::ALG,
            'KID' => $kid,
            'N'   => Base64Url::encode($nonce),
            // Append tag to ciphertext to match the Go v1 format.
            'CT'  => Base64Url::encode($ct . $tag),
        ];
        $envJson = json_encode($envelope, JSON_UNESCAPED_SLASHES);
        if ($envJson === false) {
            throw new CryptoException('xctx: envelope json encode failed');
        }

        $value = 'v1.' . Base64Url::encode($envJson);
        return [$this->cfg->headerName, $value];
    }

    /**
     * Convenience: set the header on a PSR-7 Request (if PSR-7 is installed).
     *
     * This method does NOT hard-require PSR-7 at parse time. It performs a runtime
     * check to ensure the RequestInterface exists and the provided object is a PSR-7
     * request. If your project does not use PSR-7, you can simply call embedHeader()
     * and add the header using your framework’s API.
     *
     * @param mixed        $req     A PSR-7 request instance.
     * @param array|object $payload Typed payload to seal.
     * @return mixed                 The PSR-7 request with header attached.
     *
     * @throws ValidationException if PSR-7 is unavailable or $req is not a RequestInterface.
     * @throws CryptoException     on JSON or crypto failure (from embedHeader()).
     */
    public function setHeader(mixed $req, array|object $payload): mixed
    {
        $iface = 'Psr\\Http\\Message\\RequestInterface';
        if (!interface_exists($iface)) {
            throw new ValidationException('xctx: PSR-7 not installed; call embedHeader() and set the header with your HTTP client.');
        }
        if (!$req instanceof \Psr\Http\Message\RequestInterface) {
            throw new ValidationException('xctx: setHeader expects a PSR-7 RequestInterface instance.');
        }

        [$name, $val] = $this->embedHeader($payload);
        return $req->withHeader($name, $val);
    }

    /**
     * Parse and verify an X-Context header value.
     *
     * Steps:
     *   1) Version check ("v1." prefix), base64url-decode envelope.
     *   2) Extract KID/nonce/CT and find the decryption key (current or old).
     *   3) Split CT into ciphertext + tag; AEAD-decrypt with AAD.
     *   4) JSON-decode plaintext, verify claims:
     *        - iat/nbf/exp w/ optional clock skew
     *        - optional issuer/audience equality
     *   5) Return [payload, claims] where payload is whatever was in "ctx".
     *
     * @param string $headerValue Raw header value (e.g., from $_SERVER or PSR-7).
     * @return array{0:mixed,1:array} [ctxPayload, claims{iss,aud,iat,nbf,exp,jti}]
     *
     * @throws CryptoException     on malformed envelope, unknown KID, decrypt failure,
     *                             or JSON parsing errors.
     * @throws ValidationException on claims violations (expired, not yet valid, mismatched iss/aud).
     */
    public function parseHeaderValue(string $headerValue): array
    {
        if (!str_starts_with($headerValue, 'v1.')) {
            throw new CryptoException('xctx: unsupported or missing version');
        }

        $json = Base64Url::decode(substr($headerValue, 3));
        $env  = json_decode($json, true, flags: JSON_THROW_ON_ERROR);

        $v   = $env['v']   ?? $env['V']   ?? null;
        $alg = $env['alg'] ?? $env['Alg'] ?? '';
        $kid = $env['kid'] ?? $env['KID'] ?? '';
        $n   = $env['n']   ?? $env['N']   ?? '';
        $ct  = $env['ct']  ?? $env['CT']  ?? '';

        if ($v === '1') {
            $v = 1; // handle string-typed version from other stacks
        }
        $algCanon = self::canonAlg($alg);
        $okAlg    = ($algCanon === 'AES256GCM'); // accept both AES-256-GCM and AES256-GCM

        if (!is_array($env) || $v !== self::VERSION || !$okAlg) {
            throw new CryptoException('xctx: bad envelope');
        }

        if ($kid === '' || $n === '' || $ct === '') {
            throw new CryptoException('xctx: incomplete envelope');
        }

        $key = $this->keys->decKey($kid);
        if ($key === null) {
            throw new CryptoException('xctx: unknown KID');
        }

        $nonce = Base64Url::decode($n);
        $blob  = Base64Url::decode($ct);
        if (strlen($nonce) !== self::NONCE_SZ || strlen($blob) < self::TAG_SZ) {
            throw new CryptoException('xctx: invalid nonce or ciphertext');
        }

        $tag   = substr($blob, -self::TAG_SZ);
        $ctRaw = substr($blob, 0, -self::TAG_SZ);

        $pt = openssl_decrypt($ctRaw, self::CIPHER, $key, OPENSSL_RAW_DATA, $nonce, $tag, $this->aad());
        if ($pt === false) {
            throw new CryptoException('xctx: decrypt failed (tag mismatch or key/AAD wrong)');
        }

        $pl = json_decode($pt, true);
        if (!is_array($pl)) {
            throw new CryptoException('xctx: payload json parse failed');
        }

        // ---- Claims verification ----
        $now  = time();
        $skew = $this->cfg->clockSkewSec;

        $iat = (int)($pl['iat'] ?? 0);
        $nbf = (int)($pl['nbf'] ?? 0);
        $exp = (int)($pl['exp'] ?? 0);

        if ($iat > $now + $skew) {
            throw new ValidationException('xctx: iat in future');
        }
        if ($nbf > $now + $skew) {
            throw new ValidationException('xctx: not yet valid');
        }
        if ($exp < $now - $skew) {
            throw new ValidationException('xctx: expired');
        }

        $iss = $pl['iss'] ?? null;
        $aud = $pl['aud'] ?? null;

        if ($this->cfg->issuer !== null && $iss !== $this->cfg->issuer) {
            throw new ValidationException('xctx: issuer mismatch');
        }
        if ($this->cfg->audience !== null && $aud !== $this->cfg->audience) {
            throw new ValidationException('xctx: audience mismatch');
        }

        $ctx = $pl['ctx'] ?? null;
        if ($ctx === null) {
            throw new CryptoException('xctx: missing ctx');
        }

        $claims = [
            'iss' => $iss,
            'aud' => $aud,
            'iat' => $iat,
            'nbf' => $nbf,
            'exp' => $exp,
            'jti' => $pl['jti'] ?? '',
        ];

        return [$ctx, $claims];
    }

    /**
     * PSR-7 helper: parse the configured header from a Request.
     *
     * This uses runtime checks to avoid a hard dependency on PSR-7 at parse time.
     * If your project does not use PSR-7, read the header value using your HTTP
     * framework and call parseHeaderValue() directly.
     *
     * @param mixed $req PSR-7 request instance.
     * @return array{0:mixed,1:array}
     *
     * @throws ValidationException if PSR-7 is unavailable or $req is not a RequestInterface.
     * @throws CryptoException|ValidationException see parseHeaderValue().
     */
    public function parseFromRequest(mixed $req): array
    {
        $iface = 'Psr\\Http\\Message\\RequestInterface';
        if (!interface_exists($iface)) {
            throw new ValidationException('xctx: PSR-7 not installed; read the header and call parseHeaderValue().');
        }
        if (!$req instanceof \Psr\Http\Message\RequestInterface) {
            throw new ValidationException('xctx: parseFromRequest expects a PSR-7 RequestInterface instance.');
        }

        $vals = $req->getHeader($this->cfg->headerName);
        if (count($vals) === 0) {
            throw new CryptoException('xctx: header not found');
        }
        return $this->parseHeaderValue($vals[0]);
    }

    // ---------------------------------------------------------------------
    // Builder (env → merge(user) → validate → codec)
    // ---------------------------------------------------------------------

    /**
     * Build a Codec from environment + user overrides.
     *
     * - Loads env with Config::fromEnv()
     * - Merges $user (non-empty fields override env)
     * - Validates config
     * - Constructs Keyring with current + other keys
     * - Returns Codec with optional AAD binder
     *
     * @param Config        $user      User overrides (issuer/audience/ttl/keys…).
     * @param null|callable $aadBinder Optional deployment-level AAD supplier.
     * @return self
     *
     * @throws ValidationException on invalid config or key lengths.
     */
    public static function buildFromEnv(Config $user, ?callable $aadBinder = null): self
    {
        $env = Config::fromEnv();
        $cfg = $env->merge($user);
        $cfg->validate();

        $kr = new Keyring($cfg->currentKid, $cfg->currentKey, $cfg->otherKeys);
        return new self($cfg, $kr, $aadBinder);
    }

    /** Canonicalize algorithm names so Go/PHP variants match. */
    private static function canonAlg(string $alg): string
    {
        // Uppercase, drop spaces, remove dashes/underscores.
        $a = strtoupper($alg);
        $a = str_replace([' ', '-', '_'], '', $a); // e.g. AES-256-GCM -> AES256GCM
        return $a;
    }}