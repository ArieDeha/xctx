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

// file: ./test/CodecTest.php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use ArieDeha\Xctx\Codec;
use ArieDeha\Xctx\Config;
use ArieDeha\Xctx\Exception\CryptoException;
use ArieDeha\Xctx\Exception\ValidationException;
use ArieDeha\Xctx\Util\Base64Url;
use GuzzleHttp\Psr7\Request;

/**
 * CodecTest
 *
 * Purpose:
 *   Maximize coverage for Codec sealing/parsing without any test-state leakage
 *   from namespaced function overrides used in other tests.
 *
 * Isolation:
 *   We hard-reset Xctx’s test toggles in setUp() and tearDown() to guarantee a
 *   clean crypto path (no decrypt overrides, no PSR-7 disabling, etc.).
 */
final class CodecTest extends TestCase
{
    /** 32-byte binary key of repeated byte $b. */
    private static function kb(int $b): string
    {
        return str_repeat(chr($b & 0xFF), 32);
    }

    /** Minimal valid config (merge sentinels avoided here). */
    private static function cfg(array $over = []): Config
    {
        return new Config(
            headerName: $over['headerName'] ?? 'X-Context',
            issuer:     $over['issuer']     ?? 'svc-caller',
            audience:   $over['audience']   ?? 'svc-callee',
            ttlSeconds: $over['ttlSeconds'] ?? 120,
            currentKid: $over['currentKid'] ?? 'kid-demo',
            currentKey: $over['currentKey'] ?? self::kb(1),
            otherKeys:  $over['otherKeys']  ?? [],
            typedKeyName: $over['typedKeyName'] ?? 'xctx',
            clockSkewSec: $over['clockSkewSec'] ?? 0,
        );
    }

//    /** Ensure NO override toggles are active before each test. */
//    protected function setUp(): void
//    {
//        if (function_exists('\\ArieDeha\Xctx\\__xctx_test_reset')) {
//            \ArieDeha\Xctx\__xctx_test_reset();
//        }
//    }
//
//    /** And also after, in case a test fails before cleanup. */
//    protected function tearDown(): void
//    {
//        if (function_exists('\\ArieDeha\Xctx\\__xctx_test_reset')) {
//            \ArieDeha\Xctx\__xctx_test_reset();
//        }
//    }
//
    // ---------------------------------------------------------------------
    // Happy path
    // ---------------------------------------------------------------------

    /** Round-trip success with matching AAD on caller/callee. */
    public function testRoundTripWithAADSuccess(): void
    {
        $aad    = fn() => 'TENANT=blue|ENV=dev';
        $caller = Codec::buildFromEnv(self::cfg(), $aad);
        $callee = Codec::buildFromEnv(self::cfg(), $aad);

        $payload = ['uid' => 42, 'un' => 'arie', 'role' => 'admin'];
        [$name, $val] = $caller->embedHeader($payload);
        $this->assertSame('X-Context', $name);

        [$got, $claims] = $callee->parseHeaderValue($val);
        $this->assertSame($payload, $got);
        $this->assertSame('svc-caller', $claims['iss']);
        $this->assertSame('svc-callee', $claims['aud']);
    }

    // ---------------------------------------------------------------------
    // Version / envelope errors
    // ---------------------------------------------------------------------

    /** Reject headers without the "v1." prefix. */
    public function testRejectsMissingVersionPrefix(): void
    {
        $codec = Codec::buildFromEnv(self::cfg());
        $this->expectException(CryptoException::class);
        $codec->parseHeaderValue('not-a-versioned-header');
    }

    /** Invalid base64url tail after "v1." → InvalidArgumentException. */
    public function testRejectsInvalidBase64Envelope(): void
    {
        $codec = Codec::buildFromEnv(self::cfg());
        $this->expectException(\InvalidArgumentException::class);
        $codec->parseHeaderValue('v1.***');
    }

    /** Bad JSON inside the envelope → JsonException. */
    public function testRejectsInvalidJsonEnvelope(): void
    {
        $codec = Codec::buildFromEnv(self::cfg());
        $bad = 'v1.' . Base64Url::encode('not json');
        $this->expectException(\JsonException::class);
        $codec->parseHeaderValue($bad);
    }

    /** Missing KID/N/CT → CryptoException. */
    public function testRejectsIncompleteEnvelope(): void
    {
        $codec = Codec::buildFromEnv(self::cfg());
        $env = ['V'=>1,'Alg'=>'AES256-GCM'];
        $val = 'v1.' . Base64Url::encode(json_encode($env));
        $this->expectException(CryptoException::class);
        $codec->parseHeaderValue($val);
    }

    /** Nonce length != 12 or CT < tag length → CryptoException. */
    public function testRejectsInvalidNonceOrCiphertextLengths(): void
    {
        $codec = Codec::buildFromEnv(self::cfg());
        $env = [
            'V'   => 1,
            'Alg' => 'AES256-GCM',
            'KID' => 'kid-demo',
            'N'   => Base64Url::encode(random_bytes(4)),
            'CT'  => Base64Url::encode(random_bytes(16)),
        ];
        $val = 'v1.' . Base64Url::encode(json_encode($env));
        $this->expectException(CryptoException::class);
        $codec->parseHeaderValue($val);
    }

    // ---------------------------------------------------------------------
    // Decrypt failures & claims
    // ---------------------------------------------------------------------

    /** Unknown KID is rejected before decrypt. */
    public function testUnknownKidRejected(): void
    {
        $codec = Codec::buildFromEnv(self::cfg());
        $env = [
            'V'   => 1,
            'Alg' => 'AES256-GCM',
            'KID' => 'kidX',
            'N'   => Base64Url::encode(random_bytes(12)),
            'CT'  => Base64Url::encode(random_bytes(32)),
        ];
        $val = 'v1.' . Base64Url::encode(json_encode($env));
        $this->expectException(CryptoException::class);
        $codec->parseHeaderValue($val);
    }

    /** TTL/expiry is enforced: expired tokens are rejected. */
    public function testExpiredTokenRejected(): void
    {
        $cfg = self::cfg(['ttlSeconds'=>1, 'clockSkewSec'=>0]);
        $caller = Codec::buildFromEnv($cfg);
        $callee = Codec::buildFromEnv($cfg);
        [, $value] = $caller->embedHeader(['x'=>1]);

        sleep(2);
        $this->expectException(ValidationException::class);
        $callee->parseHeaderValue($value);
    }

    // ---------------------------------------------------------------------
    // PSR-7 helpers (setHeader/parseFromRequest)
    // ---------------------------------------------------------------------

    /** End-to-end using PSR-7 helpers. */
    public function testPsr7HelpersSetAndParse(): void
    {
        $caller = Codec::buildFromEnv(self::cfg());
        $callee = Codec::buildFromEnv(self::cfg());
        $payload = ['uid'=>7];

        $req = new Request('GET', 'http://example.com/');
        $req = $caller->setHeader($req, $payload);

        [$got, ] = $callee->parseFromRequest($req);
        $this->assertSame($payload, $got);
    }

    /** setHeader() must reject non-PSR-7 objects. */
    public function testPsr7SetHeaderRejectsNonRequest(): void
    {
        $codec = Codec::buildFromEnv(self::cfg());
        $this->expectException(ValidationException::class);
        /** @phpstan-ignore-next-line */
        $codec->setHeader(new stdClass(), ['x'=>1]);
    }

    /** parseFromRequest() must fail if the configured header is missing. */
    public function testPsr7ParseMissingHeader(): void
    {
        $codec = Codec::buildFromEnv(self::cfg());
        $req = new Request('GET', 'http://example.com/');
        $this->expectException(CryptoException::class);
        $codec->parseFromRequest($req);
    }

    // ---------------------------------------------------------------------
    // embedHeader(): JSON failure path (invalid UTF-8 in payload)
    // ---------------------------------------------------------------------

    /** json_encode(false) branch in embedHeader() must be covered (invalid UTF-8). */
    public function testEmbedHeaderJsonFailure(): void
    {
        $codec = Codec::buildFromEnv(self::cfg());
        $badStr = "\xF0\x28\x8C\x28"; // invalid UTF-8
        $this->expectException(CryptoException::class);
        $codec->embedHeader(['bad' => $badStr]);
    }
}
