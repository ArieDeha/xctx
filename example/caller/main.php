<?php
/**
 * xctx example — PHP Caller
 *
 * Purpose:
 *   Demonstrates consuming the published "ariedeha/xctx" package (Composer)
 *   to embed a typed payload into X-Context and call four callees:
 *   Go(:8081), PHP(:8082), Node(:8083), Node-Express(:8084).
 *
 * Run: (inside example/caller)  composer install && composer run start
 */

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use ArieDeha\Xctx\Config;
use ArieDeha\Xctx\Codec;

/** @var Config $config Example configuration aligned with other language demos. */
$config = new Config(
    headerName: 'X-Context',
    issuer: 'svc-caller',
    audience: 'svc-callee',
    ttlSeconds: 120,
    currentKid: 'kid-demo',
    currentKey: '0123456789abcdef0123456789abcdef',
);

/** @var Codec $codec Constructed from config + AAD binder (tenant/env). */
$codec = Codec::buildFromEnv($config, fn () => 'TENANT=blue|ENV=dev');

/**
 * Pretty print a log section.
 *
 * @param string $title
 * @param int    $status
 * @param mixed  $body
 * @return void
 */
function log_block(string $title, int $status, mixed $body): void
{
    echo "\n== {$title} [{$status}] ==\n";
    if (is_string($body)) {
        echo $body, "\n";
    } else {
        echo json_encode($body, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), "\n";
    }
}

/**
 * Perform a GET with a sealed header for the given payload.
 *
 * @param Codec               $codec
 * @param string              $url
 * @param array<string,mixed> $payload
 * @return array{status:int, body:mixed}
 */
function http_get_with_ctx(Codec $codec, string $url, array $payload): array
{
    [$name, $value] = $codec->embedHeader($payload);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => [$name . ': ' . $value],
        CURLOPT_HEADER         => false,
    ]);
    $respBody = curl_exec($ch);
    $status   = (int) (curl_getinfo($ch, CURLINFO_RESPONSE_CODE) ?: 0);
    curl_close($ch);

    $decoded = null;
    if (is_string($respBody)) {
        $tmp = json_decode($respBody, true);
        $decoded = $tmp === null ? $respBody : $tmp;
    }
    return ['status' => $status, 'body' => $decoded];
}

// Initial context (your app would derive this from auth/session/etc.)
$ctx = ['user_id' => 7, 'user_name' => 'arie', 'role' => 'admin'];

// Callee targets
$GO    = 'http://127.0.0.1:8081';
$PHP   = 'http://127.0.0.1:8082';
$NODE  = 'http://127.0.0.1:8083';
$NODEE = 'http://127.0.0.1:8084';

// whoami / update on all four callees
foreach ([['go',$GO], ['php',$PHP], ['node',$NODE], ['node-express',$NODEE]] as [$name, $base]) {
    $r = http_get_with_ctx($codec, "{$base}/whoami", $ctx);
    log_block("{$name} /whoami", $r['status'], $r['body']);

    $r = http_get_with_ctx($codec, "{$base}/update", $ctx);
    log_block("{$name} /update", $r['status'], $r['body']);
}

// Chains via Node(:8083) including relays to Node-Express(:8084)
foreach ([
             ['node → go /whoami', "{$NODE}/relay/go"],
             ['node → go /update', "{$NODE}/relay/go/update"],
             ['node → php /whoami', "{$NODE}/relay/php"],
             ['node → php /update', "{$NODE}/relay/php/update"],
             ['node → node-express /whoami', "{$NODE}/relay/node-express"],
             ['node → node-express /update', "{$NODE}/relay/node-express/update"],
         ] as [$title, $url]) {
    $r = http_get_with_ctx($codec, $url, $ctx);
    log_block($title, $r['status'], $r['body']);
}
