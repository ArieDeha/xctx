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

// file: ./test/overrides/crypto_overrides.php

declare(strict_types=1);

/**
 * Test-only overrides for namespaced functions used by ArieDeha\Xctx\Codec.
 * This file MUST be loaded only inside @runInSeparateProcess tests.
 */

namespace ArieDeha\Xctx;

final class TestOverrides
{
    /** @var array<string,mixed> */
    private static array $s = [
        'encrypt_fail'       => false,
        'json_fail_envelope' => false,
        'decrypt_override'   => null,   // null|'not_json'|'nbf_future'|'missing_ctx'
        'psr_off'            => false,
        'time'               => null,   // null or int
    ];

    public static function set(string $k, mixed $v): void { self::$s[$k] = $v; }
    public static function get(string $k): mixed { return self::$s[$k] ?? null; }
    public static function reset(): void
    {
        self::$s = [
            'encrypt_fail'       => false,
            'json_fail_envelope' => false,
            'decrypt_override'   => null,
            'psr_off'            => false,
            'time'               => null,
        ];
    }
}

/** Namespaced wrappers that consult TestOverrides before delegating. */
function time(): int
{
    $t = TestOverrides::get('time');
    return is_int($t) ? $t : \time();
}

function interface_exists(string $iface, bool $autoload = true): bool
{
    if (TestOverrides::get('psr_off') && $iface === 'Psr\\Http\\Message\\RequestInterface') {
        return false;
    }
    return \interface_exists($iface, $autoload);
}

function openssl_encrypt($data, $cipher, $key, $options = 0, $iv = '', &$tag = null, $aad = '', $tag_length = 16)
{
    if (TestOverrides::get('encrypt_fail')) {
        $tag = ''; // also trip tag-length check
        return false;
    }
    return \openssl_encrypt($data, $cipher, $key, $options, $iv, $tag, $aad, $tag_length);
}

function json_encode($value, $flags = 0, $depth = 512)
{
    if (
        TestOverrides::get('json_fail_envelope') &&
        is_array($value) &&
        isset($value['V'], $value['Alg'], $value['KID'], $value['N'], $value['CT'])
    ) {
        return false; // fail only for envelope object
    }
    return \json_encode($value, $flags, $depth);
}

function openssl_decrypt($data, $cipher, $key, $options = 0, $iv = '', $tag = '', $aad = '' /* no tag_length for decrypt */)
{
    $mode = TestOverrides::get('decrypt_override');
    if ($mode === 'not_json') {
        return 'not json';
    }
    if ($mode === 'nbf_future') {
        $now = time();
        return \json_encode([
            'iss' => 'svc-caller',
            'aud' => 'svc-callee',
            'iat' => $now,
            'nbf' => $now + 99999,
            'exp' => $now + 999999,
            'jti' => 'x',
            'ctx' => ['ok' => true],
        ], JSON_UNESCAPED_SLASHES);
    }
    if ($mode === 'missing_ctx') {
        $now = time();
        return \json_encode([
            'iss' => 'svc-caller',
            'aud' => 'svc-callee',
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + 60,
            'jti' => 'x',
            // deliberately no 'ctx'
        ], JSON_UNESCAPED_SLASHES);
    }

    // IMPORTANT: only 7 args to the real function
    return \openssl_decrypt($data, $cipher, $key, $options, $iv, $tag, $aad);
}