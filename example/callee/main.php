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

// file: ./example/callee/main.php

/**
 * PHP “callee” for the xctx demonstration. This service accepts requests that
 * carry an encrypted/signed X-Context header, verifies & decodes the typed
 * payload, optionally mutates it, and replies in JSON. It also supports relays
 * to the Go callee for cross-language verification.
 *
 * Ports & Endpoints
 *  - :8082/whoami
 *      Parse X-Context and return {"server":"php-callee","ctx":{...},"claims":{...}}.
 *  - :8082/update
 *      Parse X-Context, mutate it (add “+php” to user_name, “|php” to role), and
 *      return {"server":"php-callee","prev_ctx":{...},"updated_ctx":{...}}.
 *  - :8082/relay/go
 *      Parse X-Context, re-embed it, call Go callee /whoami, and stream response.
 *  - :8082/relay/go/update     (Chain B)
 *      Parse original X-Context, re-embed to Go /update (Go mutates), then return
 *      Go’s JSON verbatim to the caller. The caller can compare prev vs. updated.
 *
 * Logging
 *  - Every handler logs the incoming context via error_log() for transparency.
 *
 * Run with PHP’s built-in server:
 *      php -S 127.0.0.1:8082 -t example/callee/php
 */

declare(strict_types=1);

require_once __DIR__ . '/../../vendor/autoload.php';

use ArieDeha\Xctx\Config;
use ArieDeha\Xctx\Codec;
use ArieDeha\Xctx\Exception\CryptoException;
use ArieDeha\Xctx\Exception\ValidationException;

/**
 * Build a Codec with the same cryptographic parameters as the Go callee.
 * These must match for cross-language interop to work consistently.
 */
$user = new Config(
    headerName: 'X-Context',
    issuer:     'svc-caller',
    audience:   'svc-callee',
    ttlSeconds: 120,
    currentKid: 'kid-demo',
    currentKey: '0123456789abcdef0123456789abcdef' // raw 32 bytes
);
/** @var callable():string $aad Non-secret binding that must match Go. */
$aad = fn() => 'TENANT=blue|ENV=dev';

/** @var Codec $codec AEAD codec instance for encrypt/decrypt+claims. */
$codec = Codec::buildFromEnv($user, $aad);

/**
 * json_out writes a JSON response with the provided HTTP status.
 *
 * @param int   $status HTTP status code to emit.
 * @param array $body   Serializable structure for JSON encoding.
 */
function json_out(int $status, array $body): void {
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($body, JSON_UNESCAPED_SLASHES);
}

/**
 * get_header_value fetches a header using PHP’s built-in server variable mapping.
 *
 * @param string $name Canonical header name (e.g., "X-Context").
 * @return string|null The value if set, otherwise null.
 */
function get_header_value(string $name): ?string {
    $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
    return $_SERVER[$key] ?? null;
}

/**
 * log_ctx writes a one-line summary of the incoming context into the server log.
 *
 * @param string $where A tag naming the handler (e.g., "php:/update").
 * @param array  $ctx   The decoded typed payload (associative array form).
 */
function log_ctx(string $where, array $ctx): void {
    $uid = $ctx['user_id']   ?? null;
    $un  = $ctx['user_name'] ?? null;
    $ro  = $ctx['role']      ?? null;
    error_log(sprintf('[%s] incoming ctx: user_id=%s user_name="%s" role="%s"',
        $where, (string)$uid, (string)$un, (string)$ro));
}

/**
 * php_update applies the PHP-side mutation used by /update and Chain B.
 *
 * Contract (mirrors the Go side’s deterministic style):
 *  - Append “+php” to user_name (or set to "php" if empty).
 *  - Append “|php” to role      (or set to "php" if empty).
 *
 * @param array $in Input context (associative array).
 * @return array Updated context.
 */
function php_update(array $in): array {
    $out = $in;
    $out['user_name'] = ($out['user_name'] ?? '') !== '' ? $out['user_name'] . '+php' : 'php';
    $out['role']      = ($out['role'] ?? '') !== '' ? $out['role'] . '|php' : 'php';
    return $out;
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';

if ($path === '/whoami') {
    // Parse and echo back the context + claims.
    $raw = get_header_value($user->headerName);
    if (!$raw) {
        json_out(400, ['error' => 'missing X-Context', 'server' => 'php-callee']);
        exit;
    }
    try {
        [$ctx, $claims] = $codec->parseHeaderValue($raw);
        log_ctx('php:/whoami', $ctx);
        json_out(200, ['server' => 'php-callee', 'ctx' => $ctx, 'claims' => $claims]);
    } catch (CryptoException|ValidationException $e) {
        json_out(401, ['error' => 'parse failed: ' . $e->getMessage(), 'server' => 'php-callee']);
    }
    exit;
}

if ($path === '/update') {
    // Parse, log, mutate, return both previous and updated.
    $raw = get_header_value($user->headerName);
    if (!$raw) {
        json_out(400, ['error' => 'missing X-Context', 'server' => 'php-callee']);
        exit;
    }
    try {
        [$prev, ] = $codec->parseHeaderValue($raw);
        log_ctx('php:/update', $prev);
        $updated = php_update($prev);
        json_out(200, ['server' => 'php-callee', 'prev_ctx' => $prev, 'updated_ctx' => $updated]);
    } catch (CryptoException|ValidationException $e) {
        json_out(401, ['error' => 'parse failed: ' . $e->getMessage(), 'server' => 'php-callee']);
    }
    exit;
}

if ($path === '/relay/go') {
    // Simple relay to Go /whoami after re-embedding the same payload.
    $raw = get_header_value($user->headerName);
    if (!$raw) {
        json_out(400, ['error' => 'missing X-Context', 'server' => 'php-callee']);
        exit;
    }
    try {
        [$ctx, ] = $codec->parseHeaderValue($raw);
        log_ctx('php:/relay/go', $ctx);
        [$name, $value] = $codec->embedHeader($ctx);

        $ch = curl_init('http://127.0.0.1:8081/whoami');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [$name . ': ' . $value],
        ]);
        $body = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        http_response_code($code ?: 200);
        header('Content-Type: application/json');
        echo $body ?: '';
    } catch (CryptoException|ValidationException $e) {
        json_out(401, ['error' => 'parse/relay failed: ' . $e->getMessage(), 'server' => 'php-callee']);
    }
    exit;
}

if ($path === '/relay/go/update') {
    // Chain B: caller → php → go(update) → php → caller.
    $raw = get_header_value($user->headerName);
    if (!$raw) {
        json_out(400, ['error' => 'missing X-Context', 'server' => 'php-callee']);
        exit;
    }
    try {
        [$prev, ] = $codec->parseHeaderValue($raw);
        log_ctx('php:/relay/go/update original', $prev);
        [$name, $value] = $codec->embedHeader($prev);

        $ch = curl_init('http://127.0.0.1:8081/update');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [$name . ': ' . $value],
        ]);
        $body = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        http_response_code($code ?: 200);
        header('Content-Type: application/json');
        echo $body ?: '';
    } catch (CryptoException|ValidationException $e) {
        json_out(401, ['error' => 'parse/relay failed: ' . $e->getMessage(), 'server' => 'php-callee']);
    }
    exit;
}

// Fallback for unknown routes.
json_out(404, ['error' => 'not found', 'server' => 'php-callee']);
