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

// file: ./example/caller/main.php

/**
 * The PHP “caller” mirrors the Go caller. It constructs a typed context,
 * embeds it as an encrypted/signed X-Context header, and exercises both
 * callee stacks (Go and PHP), including both relay chains.
 *
 * Behavior
 *  - Prints raw response bodies for every call.
 *  - For Chain A and B, extracts and prints “prev” and “updated” contexts to
 *    verify both the mutation contract and cross-language interop.
 */

declare(strict_types=1);

require_once __DIR__ . '/../../vendor/autoload.php';

use ArieDeha\Xctx\Config;
use ArieDeha\Xctx\Codec;

/**
 * Construct a Codec with the same parameters as the callees.
 * Replace with env-based wiring in production as appropriate.
 */
$user = new Config(
    headerName: 'X-Context',
    issuer:     'svc-caller',
    audience:   'svc-callee',
    ttlSeconds: 120,
    currentKid: 'kid-demo',
    currentKey: '0123456789abcdef0123456789abcdef'
);
$aad = fn() => 'TENANT=blue|ENV=dev';
$codec = Codec::buildFromEnv($user, $aad);

/** @var array<string,mixed> $payload The typed context in array form. */
$payload = ['user_id' => 7, 'user_name' => 'arie', 'role' => 'admin'];
[$name, $value] = $codec->embedHeader($payload);

/**
 * get_with_header performs an HTTP GET with the X-Context header set and
 * prints the response body to stdout.
 *
 * @param string $url   Target URL.
 * @param string $name  Header name (e.g., "X-Context").
 * @param string $value Header value (sealed, versioned envelope).
 * @return string Raw response body (empty on transport error).
 */
function get_with_header(string $url, string $name, string $value): string {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [$name . ': ' . $value],
    ]);
    $body = curl_exec($ch) ?: '';
    $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);

    echo "\n== $url [$code] ==\n$body\n";
    return $body;
}

// Simple calls
get_with_header('http://127.0.0.1:8081/whoami', $name, $value);
get_with_header('http://127.0.0.1:8082/whoami', $name, $value);
get_with_header('http://127.0.0.1:8083/whoami', $name, $value);
get_with_header('http://127.0.0.1:8081/relay/php', $name, $value);
get_with_header('http://127.0.0.1:8082/relay/go',  $name, $value);
get_with_header('http://127.0.0.1:8083/relay/go',  $name, $value);
get_with_header('http://127.0.0.1:8083/relay/php', $name, $value);

// Chain A: caller → go → php(update) → go(update) → caller
$bodyA = get_with_header('http://127.0.0.1:8081/relay/php/update', $name, $value);
$A = json_decode($bodyA, true);
if (is_array($A) && ($A['server'] ?? '') !== '') {
    echo "\n[Chain A] prev        = " . json_encode($A['prev_ctx'] ?? []) . "\n";
    echo "[Chain A] php-updated = " . json_encode($A['php_updated_ctx'] ?? []) . "\n";
    echo "[Chain A] go-updated  = " . json_encode($A['go_updated_ctx'] ?? []) . "\n";
}

// Chain B: caller → php → go(update) → php → caller
$bodyB = get_with_header('http://127.0.0.1:8082/relay/go/update', $name, $value);
$B = json_decode($bodyB, true);
if (is_array($B) && ($B['server'] ?? '') !== '') {
    echo "\n[Chain B] prev    = " . json_encode($B['prev_ctx'] ?? []) . "\n";
    echo "[Chain B] updated = " . json_encode($B['updated_ctx'] ?? []) . "\n";
}

// Chain D: caller → php → node(update) → php(update) → caller
$bodyD = get_with_header('http://127.0.0.1:8082/relay/node/update', $name, $value);
$D = json_decode($bodyD, true);
if (is_array($D) && ($D['server'] ?? '') !== '') {
    echo "\n[Chain D] prev        = " . json_encode($D['prev_ctx'] ?? []) . "\n";
    echo "[Chain D] node-updated = " . json_encode($D['node_updated_ctx'] ?? []) . "\n";
    echo "[Chain D] php-updated  = " . json_encode($D['php_updated_ctx'] ?? []) . "\n";
}
