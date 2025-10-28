<?php
/**
 * xctx example — PHP Callee (port 8082)
 *
 * Purpose:
 *   Demonstrate consuming the published "ariedeha/xctx" package (Composer)
 *   as a 3rd-party dependency. This callee:
 *     - reads & verifies the X-Context header,
 *     - optionally mutates the context (+php / |php),
 *     - relays to Go(:8081), Node(:8083), Node-Express(:8084) by re-sealing the context.
 *
 * Endpoints:
 *   GET /whoami
 *   GET /update
 *   GET /relay/go
 *   GET /relay/go/update
 *   GET /relay/node
 *   GET /relay/node/update
 *   GET /relay/node-express
 *   GET /relay/node-express/update
 */

declare(strict_types=1);

use ArieDeha\Xctx\Config;
use ArieDeha\Xctx\Codec;

// -------------------- Configuration (demo defaults; use env/secret store in real apps) --------------------

/** @var string HEADER_NAME The single HTTP header name used to carry the sealed envelope. */
const HEADER_NAME = 'X-Context';

/** @var Config $config Runtime configuration mirrored across languages for wire compatibility. */
$config = new Config(
    headerName: HEADER_NAME,
    issuer: 'svc-caller',
    audience: 'svc-callee',
    ttlSeconds: 120,
    currentKid: 'kid-demo',
    currentKey: '0123456789abcdef0123456789abcdef', // 32-byte demo key — DO NOT hardcode in production
);

/** @var Codec $codec The PHP codec constructed from config + AAD binder. */
$codec = Codec::buildFromEnv($config, fn () => 'TENANT=blue|ENV=dev');

// -------------------- Utilities --------------------

/**
 * Send a JSON response with a given HTTP status.
 *
 * @param int   $status HTTP status code
 * @param mixed $body   Any value encodable to JSON
 * @return void
 */
function send_json(int $status, mixed $body): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

/**
 * Read a header value from the PHP built-in server environment, case-insensitive.
 *
 * @param string $name Logical header name, e.g., "X-Context"
 * @return string|null The header value if present, otherwise null
 */
function read_header(string $name): ?string
{
    $key = 'HTTP_' . str_replace('-', '_', strtoupper($name));
    return $_SERVER[$key] ?? null;
}

/**
 * Apply a business-level mutation for /update on the PHP callee.
 * Adds "+php" to user_name and "|php" to role.
 *
 * @param array<string,mixed> $inCtx
 * @return array<string,mixed>
 */
function php_update(array $inCtx): array
{
    $out = $inCtx;
    $out['user_name'] = isset($out['user_name']) && $out['user_name'] !== ''
        ? ($out['user_name'] . '+php')
        : 'php';
    $out['role'] = isset($out['role']) && $out['role'] !== ''
        ? ($out['role'] . '|php')
        : 'php';
    return $out;
}

/**
 * Relay helper: re-embed payload and proxy the response from a target URL.
 *
 * @param Codec               $codec
 * @param array<string,mixed> $payload
 * @param string              $url
 * @return void
 */
function relay(Codec $codec, array $payload, string $url): void
{
    [$name, $value] = $codec->embedHeader($payload);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => [$name . ': ' . $value],
        CURLOPT_HEADER         => false,
    ]);
    $respBody = curl_exec($ch);
    $status   = curl_getinfo($ch, CURLINFO_RESPONSE_CODE) ?: 500;
    if ($respBody === false) {
        send_json(502, ['server' => 'php-callee', 'error' => 'proxy failure']);
        return;
    }
    http_response_code((int)$status);
    header('Content-Type: application/json');
    echo $respBody;
}

// -------------------- Routing --------------------

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method !== 'GET') {
    send_json(405, ['server' => 'php-callee', 'error' => 'method not allowed']);
    exit;
}

switch ($path) {
    case '/whoami': {
        $val = read_header(HEADER_NAME);
        if ($val === null || $val === '') {
            send_json(400, ['server' => 'php-callee', 'error' => 'missing ' . HEADER_NAME]);
            break;
        }
        [$payload, $claims] = $codec->parseHeaderValue($val);
        send_json(200, ['server' => 'php-callee', 'ctx' => $payload, 'claims' => $claims]);
        break;
    }

    case '/update': {
        $val = read_header(HEADER_NAME);
        if ($val === null || $val === '') {
            send_json(400, ['server' => 'php-callee', 'error' => 'missing ' . HEADER_NAME]);
            break;
        }
        [$payload] = $codec->parseHeaderValue($val);
        $updated = php_update($payload);
        send_json(200, ['server' => 'php-callee', 'prev_ctx' => $payload, 'updated_ctx' => $updated]);
        break;
    }

    // -------- Relays --------

    case '/relay/go': {
        $val = read_header(HEADER_NAME);
        if (!$val) { send_json(400, ['server' => 'php-callee', 'error' => 'missing ' . HEADER_NAME]); break; }
        [$payload] = $codec->parseHeaderValue($val);
        relay($codec, $payload, 'http://127.0.0.1:8081/whoami');
        break;
    }
    case '/relay/go/update': {
        $val = read_header(HEADER_NAME);
        if (!$val) { send_json(400, ['server' => 'php-callee', 'error' => 'missing ' . HEADER_NAME]); break; }
        [$payload] = $codec->parseHeaderValue($val);
        relay($codec, $payload, 'http://127.0.0.1:8081/update');
        break;
    }

    case '/relay/node': {
        $val = read_header(HEADER_NAME);
        if (!$val) { send_json(400, ['server' => 'php-callee', 'error' => 'missing ' . HEADER_NAME]); break; }
        [$payload] = $codec->parseHeaderValue($val);
        relay($codec, $payload, 'http://127.0.0.1:8083/whoami');
        break;
    }
    case '/relay/node/update': {
        $val = read_header(HEADER_NAME);
        if (!$val) { send_json(400, ['server' => 'php-callee', 'error' => 'missing ' . HEADER_NAME]); break; }
        [$payload] = $codec->parseHeaderValue($val);
        relay($codec, $payload, 'http://127.0.0.1:8083/update');
        break;
    }

    case '/relay/node-express': {
        $val = read_header(HEADER_NAME);
        if (!$val) { send_json(400, ['server' => 'php-callee', 'error' => 'missing ' . HEADER_NAME]); break; }
        [$payload] = $codec->parseHeaderValue($val);
        relay($codec, $payload, 'http://127.0.0.1:8084/whoami');
        break;
    }
    case '/relay/node-express/update': {
        $val = read_header(HEADER_NAME);
        if (!$val) { send_json(400, ['server' => 'php-callee', 'error' => 'missing ' . HEADER_NAME]); break; }
        [$payload] = $codec->parseHeaderValue($val);
        relay($codec, $payload, 'http://127.0.0.1:8084/update');
        break;
    }

    default: {
        send_json(404, ['server' => 'php-callee', 'error' => 'not found', 'path' => $path]);
    }
}
