<?php
// SPDX-License-Identifier: Apache-2.0

/**
 * file: ./example/callee/main.php
 *
 * PHP “callee” for the xctx demonstration. This service accepts requests that
 * carry an encrypted/signed `X-Context` header, verifies & decodes the typed
 * payload, optionally mutates it, and replies in JSON. It also supports relays
 * to the Go and Node callees for cross-language verification and chaining.
 *
 * ──────────────────────────────────────────────────────────────────────────────
 * Ports & Endpoints
 * ──────────────────────────────────────────────────────────────────────────────
 *  - :8082/whoami
 *      Parse X-Context and return {"server":"php-callee","ctx":{...},"claims":{...}}.
 *
 *  - :8082/update
 *      Parse X-Context, mutate it (add “+php” to user_name, “|php” to role), and
 *      return {"server":"php-callee","prev_ctx":{...},"updated_ctx":{...}}.
 *
 *  - :8082/relay/go
 *      Parse X-Context, re-embed it, call Go callee /whoami, and stream response.
 *
 *  - :8082/relay/go/update       (Chain B in examples)
 *      Parse original X-Context, re-embed to Go /update (Go mutates), then return
 *      {"server":"php-callee","prev_ctx":{...},"updated_ctx":{...}} with Go’s
 *      updated payload echoed back to the caller.
 *
 *  - :8082/relay/node
 *      Parse X-Context, re-embed it, call Node callee /whoami, and stream response.
 *
 *  - :8082/relay/node/update     (Chain D in examples)
 *      Parse original X-Context, re-embed to Node /update (Node mutates), then
 *      apply PHP’s own update and return
 *      {"server":"php-callee","prev_ctx":{...},"node_updated_ctx":{...},
 *       "php_updated_ctx":{...}} so caller can compare both steps.
 *
 * ──────────────────────────────────────────────────────────────────────────────
 * Run with PHP’s built-in server (from repo root):
 *     php -S 127.0.0.1:8082 example/callee/main.php
 *
 * Pre-conditions:
 *  - `composer install` has been run (autoload available).
 *  - Go callee listening on :8081 if you use /relay/go* routes.
 *  - Node callee listening on :8083 if you use /relay/node* routes.
 */

declare(strict_types=1);

require_once __DIR__ . '/../../vendor/autoload.php';

use ArieDeha\Xctx\Config;
use ArieDeha\Xctx\Codec;
use ArieDeha\Xctx\Exception\ValidationException;
use ArieDeha\Xctx\Exception\CryptoException;

/**
 * Typed payload carried between services.
 *
 * @psalm-type PassingContext = array{
 *   user_id: int,
 *   user_name: string,
 *   role?: string
 * }
 */

/** **************************************************************************
 * Utilities
 * **************************************************************************/

/**
 * Sends a JSON response and terminates.
 *
 * @param int   $status  HTTP status code.
 * @param array $payload JSON-encodable payload.
 * @return never
 */
function json_out(int $status, array $payload): never
{
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * Simple stderr log of the context for visibility during the demo.
 *
 * @param string $label
 * @param mixed  $ctx
 * @return void
 */
function log_ctx(string $label, mixed $ctx): void
{
    error_log(sprintf('[%s] %s', $label, json_encode($ctx, JSON_UNESCAPED_SLASHES)));
}

/**
 * Reads the X-Context header value (case-insensitive).
 *
 * @param string $headerName
 * @return string|null
 */
function read_xctx_header(string $headerName = 'X-Context'): ?string
{
    // Built-in server maps headers to $_SERVER as HTTP_<NAME>
    $key = 'HTTP_' . strtoupper(str_replace('-', '_', $headerName));
    return $_SERVER[$key] ?? null;
}

/**
 * HTTP GET helper with custom headers.
 *
 * @param string       $url
 * @param array<string,string> $headers
 * @return array{status:int, body:string}
 */
function http_get(string $url, array $headers = []): array
{
    $curl = curl_init($url);
    $hdrs = [];
    foreach ($headers as $k => $v) {
        $hdrs[] = $k . ': ' . $v;
    }
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_HTTPHEADER     => $hdrs,
    ]);
    $body = curl_exec($curl);
    $code = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    if ($body === false) {
        $err = curl_error($curl);
        curl_close($curl);
        return ['status' => 502, 'body' => json_encode(['error' => 'curl: ' . $err])];
    }
    curl_close($curl);
    return ['status' => $code, 'body' => (string)$body];
}

/**
 * Returns the demo codec using the same config/key as the Go/Node examples.
 *
 * @return Codec
 */
function build_codec(): Codec
{
    $user = new Config(
        headerName: 'X-Context',
        issuer:     'svc-caller',
        audience:   'svc-callee',
        ttlSeconds: 120,
        currentKid: 'kid-demo',
        currentKey: '0123456789abcdef0123456789abcdef', // 32 bytes
    );
    $aad = fn (): string => 'TENANT=blue|ENV=dev';
    return Codec::buildFromEnv($user, $aad);
}

/**
 * PHP mutation used by /update (adds +php and |php).
 *
 * @param array $inCtx @psalm-param PassingContext $inCtx
 * @return array       @psalm-return PassingContext
 */
function php_update(array $inCtx): array
{
    $out = $inCtx;
    $out['user_name'] = ($out['user_name'] ?? '') !== '' ? $out['user_name'] . '+php' : 'php';
    $out['role']      = ($out['role']      ?? '') !== '' ? $out['role']      . '|php' : 'php';
    return $out;
}

/** **************************************************************************
 * Router
 * **************************************************************************/

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path   = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

// Only GET is used in the demo flows; reject others early.
if ($method !== 'GET') {
    json_out(405, ['server' => 'php-callee', 'error' => 'method not allowed']);
}

$codec = build_codec();

switch ($path) {
    case '/whoami': {
        try {
            $val = read_xctx_header($codec->getHeaderName());
            if ($val === null || $val === '') {
                json_out(400, ['server' => 'php-callee', 'error' => 'missing X-Context']);
            }
            // Parse the header value to obtain typed payload + claims.
            /** @var array{payload: array, claims: array} $parsed */
            $parsed = $codec->parseHeaderValue($val);
            log_ctx('php:/whoami', $parsed['payload']);
            json_out(200, [
                'server' => 'php-callee',
                'ctx'    => $parsed['payload'],
                'claims' => $parsed['claims'],
            ]);
        } catch (CryptoException|ValidationException $e) {
            json_out(401, ['server' => 'php-callee', 'error' => 'parse failed: ' . $e->getMessage()]);
        }
    }

    case '/update': {
        try {
            $val = read_xctx_header($codec->getHeaderName());
            if ($val === null || $val === '') {
                json_out(400, ['server' => 'php-callee', 'error' => 'missing X-Context']);
            }
            /** @var array{payload: array, claims: array} $parsed */
            $parsed = $codec->parseHeaderValue($val);
            $prev   = $parsed['payload'];
            log_ctx('php:/update prev', $prev);
            $updated = php_update($prev);
            json_out(200, [
                'server'     => 'php-callee',
                'prev_ctx'   => $prev,
                'updated_ctx'=> $updated,
            ]);
        } catch (CryptoException|ValidationException $e) {
            json_out(401, ['server' => 'php-callee', 'error' => 'parse failed: ' . $e->getMessage()]);
        }
    }

    case '/relay/go': {
        try {
            $val = read_xctx_header($codec->getHeaderName());
            if ($val === null || $val === '') {
                json_out(400, ['server' => 'php-callee', 'error' => 'missing X-Context']);
            }
            $parsed = $codec->parseHeaderValue($val);
            log_ctx('php:/relay/go', $parsed['payload']);
            // Re-embed to normalize/enforce claims/AAD for the hop.
            [$name, $sealed] = $codec->embedHeader($parsed['payload']);
            $r = http_get('http://127.0.0.1:8081/whoami', [$name => $sealed]);
            http_response_code($r['status']);
            header('Content-Type: application/json');
            echo $r['body'];
            exit;
        } catch (CryptoException|ValidationException $e) {
            json_out(401, ['server' => 'php-callee', 'error' => 'parse/relay failed: ' . $e->getMessage()]);
        }
    }

    case '/relay/go/update': {
        // Chain B: caller → php → go(update) → php → caller
        try {
            $val = read_xctx_header($codec->getHeaderName());
            if ($val === null || $val === '') {
                json_out(400, ['server' => 'php-callee', 'error' => 'missing X-Context']);
            }
            $parsed = $codec->parseHeaderValue($val);
            $original = $parsed['payload'];
            log_ctx('php:/relay/go/update original', $original);

            [$name, $sealed] = $codec->embedHeader($original);
            $r = http_get('http://127.0.0.1:8081/update', [$name => $sealed]);
            if ($r['status'] !== 200) {
                json_out(502, ['server' => 'php-callee', 'error' => 'forward to go failed', 'code' => $r['status']]);
            }

            /** @var array<string,mixed> $goOut */
            $goOut = json_decode($r['body'], true) ?: [];
            if (($goOut['server'] ?? '') === '') {
                json_out(502, ['server' => 'php-callee', 'error' => 'go returned bad json']);
            }

            // Echo what Go produced as "updated".
            json_out(200, [
                'server'      => 'php-callee',
                'prev_ctx'    => $original,
                'updated_ctx' => $goOut['updated_ctx'] ?? null,
            ]);
        } catch (\Throwable $e) {
            json_out(502, ['server' => 'php-callee', 'error' => 'chain go/update failed: ' . $e->getMessage()]);
        }
    }

    case '/relay/node': {
        try {
            $val = read_xctx_header($codec->getHeaderName());
            if ($val === null || $val === '') {
                json_out(400, ['server' => 'php-callee', 'error' => 'missing X-Context']);
            }
            $parsed = $codec->parseHeaderValue($val);
            log_ctx('php:/relay/node', $parsed['payload']);

            [$name, $sealed] = $codec->embedHeader($parsed['payload']);
            $r = http_get('http://127.0.0.1:8083/whoami', [$name => $sealed]);
            http_response_code($r['status']);
            header('Content-Type: application/json');
            echo $r['body'];
            exit;
        } catch (CryptoException|ValidationException $e) {
            json_out(401, ['server' => 'php-callee', 'error' => 'parse/relay failed: ' . $e->getMessage()]);
        }
    }

    case '/relay/node/update': {
        // Chain D: caller → php → node(update) → php(update) → caller
        try {
            $val = read_xctx_header($codec->getHeaderName());
            if ($val === null || $val === '') {
                json_out(400, ['server' => 'php-callee', 'error' => 'missing X-Context']);
            }
            $parsed   = $codec->parseHeaderValue($val);
            $original = $parsed['payload'];
            log_ctx('php:/relay/node/update original', $original);

            [$name, $sealed] = $codec->embedHeader($original);
            $r = http_get('http://127.0.0.1:8083/update', [$name => $sealed]);
            if ($r['status'] !== 200) {
                json_out(502, ['server' => 'php-callee', 'error' => 'node update failed', 'code' => $r['status']]);
            }

            /** @var array<string,mixed> $nodeOut */
            $nodeOut = json_decode($r['body'], true) ?: [];
            if (($nodeOut['server'] ?? '') === '') {
                json_out(502, ['server' => 'php-callee', 'error' => 'bad json from node']);
            }

            $nodeUpdated = $nodeOut['updated_ctx'] ?? null;
            log_ctx('php:/relay/node/update node-updated', $nodeUpdated);

            $phpUpdated = is_array($nodeUpdated) ? php_update($nodeUpdated) : null;

            json_out(200, [
                'server'           => 'php-callee',
                'prev_ctx'         => $original,
                'node_updated_ctx' => $nodeUpdated,
                'php_updated_ctx'  => $phpUpdated,
            ]);
        } catch (\Throwable $e) {
            json_out(502, ['server' => 'php-callee', 'error' => 'chain node/update failed: ' . $e->getMessage()]);
        }
    }

    default:
        json_out(404, ['server' => 'php-callee', 'error' => 'not found', 'path' => $path]);
}
