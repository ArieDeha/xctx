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

// file: ./src/Xctx/Config.php

declare(strict_types=1);

namespace ArieDeha\Xctx;

use ArieDeha\Xctx\Exception\ValidationException;
use ArieDeha\Xctx\Util\Base64Url;

/**
 * Config drives header name, claims, TTL, and key material.
 * Use Config::fromEnv() to load from environment, then merge overrides.
 */
final class Config
{
    public function __construct(
        public string  $headerName   = 'X-Context',
        public ?string $issuer       = null,
        public ?string $audience     = null,
        public int     $ttlSeconds   = 300,              // default 5m
        public string  $currentKid   = '',
        public string  $currentKey   = '',               // binary 32B
        public array   $otherKeys    = [],               // map<kid => binary>
        public string  $typedKeyName = 'xctx',           // local-only, for frameworks
        public int     $clockSkewSec = 0                 // skew leeway; default 0
    ) {}

    /** Load config from environment variables (all optional unless noted). */
    public static function fromEnv(): self
    {
        $cfg = new self();
        $cfg->headerName   = getenv('XCTX_HEADER_NAME')     ?: $cfg->headerName;
        $cfg->issuer       = getenv('XCTX_ISSUER')          ?: $cfg->issuer;
        $cfg->audience     = getenv('XCTX_AUDIENCE')        ?: $cfg->audience;
        if ($ttl = getenv('XCTX_TTL')) {
            $cfg->ttlSeconds = self::parseDurationSeconds($ttl);
        }
        $cfg->currentKid   = getenv('XCTX_CURRENT_KID')     ?: $cfg->currentKid;
        if ($s = getenv('XCTX_CURRENT_KEY')) {
            $cfg->currentKey = self::decodeKeyString($s);
        }
        if ($s = getenv('XCTX_OTHER_KEYS')) {
            $cfg->otherKeys = self::parseOtherKeys($s);
        }
        $cfg->typedKeyName = getenv('XCTX_TYPED_KEY_NAME')  ?: $cfg->typedKeyName;
        if ($skew = getenv('XCTX_CLOCK_SKEW_SEC')) {
            $cfg->clockSkewSec = (int)$skew;
        }
        return $cfg;
    }

    /** Merge user overrides (non-empty / non-null fields win). */
    public function merge(Config $user): self
    {
        $out = clone $this;
        foreach (get_object_vars($user) as $k => $v) {
            if ($v === null) continue;
            if (is_string($v) && $v === '') continue;
            if (is_array($v) && $v === []) continue;
            if (is_int($v) && $v === 0 && $k !== 'clockSkewSec') continue;
            $out->$k = $v;
        }
        return $out;
    }

    /** Validate presence/length constraints. */
    public function validate(): void
    {
        if ($this->headerName === '') throw new ValidationException('xctx: HeaderName required');
        if ($this->ttlSeconds <= 0)   throw new ValidationException('xctx: TTL must be > 0');
        if ($this->currentKid === '') throw new ValidationException('xctx: CurrentKID required');
        if (strlen($this->currentKey) !== 32) throw new ValidationException('xctx: CurrentKey must be 32 bytes');
        foreach ($this->otherKeys as $kid => $k) {
            if (!is_string($kid) || $kid === '' || !is_string($k) || strlen($k) !== 32) {
                throw new ValidationException('xctx: OtherKeys invalid; each must be 32 bytes with non-empty kid');
            }
        }
    }

    // --- helpers ---

    /** Accepts hex (64), base64/base64url (==32B), or raw 32-byte string. */
    public static function decodeKeyString(string $s): string
    {
        $s = trim($s);

        // hex?
        if (preg_match('/^[0-9a-fA-F]{64}$/', $s)) {
            $bin = hex2bin($s);
            return $bin !== false ? $bin : '';
        }

        // base64url or std
        $try = function(string $enc): ?string {
            try { return Base64Url::decode($enc); } catch (\Throwable) {}
            $raw = base64_decode($enc, true);
            return $raw === false ? null : $raw;
        };
        foreach ([$s] as $cand) {
            $bin = $try($cand);
            if (is_string($bin) && strlen($bin) === 32) return $bin;
        }

        // raw 32-char
        if (strlen($s) === 32) return $s;

        throw new ValidationException('xctx: key string must decode to 32 bytes');
    }

    /** Parse CSV of kid=key, supports hex/base64/raw forms. */
    public static function parseOtherKeys(string $csv): array
    {
        $out = [];
        foreach (explode(',', $csv) as $part) {
            $part = trim($part);
            if ($part === '') continue;
            $kv = explode('=', $part, 2);
            if (count($kv) !== 2) throw new ValidationException('xctx: OTHER_KEYS malformed entry: '.$part);
            [$kid, $ks] = $kv;
            $kid = trim($kid);
            $key = self::decodeKeyString(trim($ks));
            if ($kid === '') throw new ValidationException('xctx: OTHER_KEYS empty kid');
            $out[$kid] = $key;
        }
        return $out;
    }

    /** Very small duration parser: accepts integer seconds or golang-like "2m", "30s". */
    public static function parseDurationSeconds(string $s): int
    {
        $s = trim($s);
        if (ctype_digit($s)) return (int)$s;
        if (preg_match('/^([0-9]+)s$/', $s, $m)) return (int)$m[1];
        if (preg_match('/^([0-9]+)m$/', $s, $m)) return (int)$m[1] * 60;
        if (preg_match('/^([0-9]+)h$/', $s, $m)) return (int)$m[1] * 3600;
        throw new ValidationException('xctx: TTL format must be seconds or Ns/Nm/Nh');
    }
}