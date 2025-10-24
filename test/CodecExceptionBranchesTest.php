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

// file: ./test/CodecExceptionBranchesTest.php

declare(strict_types=1);

namespace {

    use PHPUnit\Framework\TestCase;
    use ArieDeha\Xctx\Codec;
    use ArieDeha\Xctx\Config;
    use ArieDeha\Xctx\Exception\CryptoException;
    use ArieDeha\Xctx\Exception\ValidationException;
    use ArieDeha\Xctx\Util\Base64Url;
    use ArieDeha\Xctx\TestOverrides;

    /**
     * CodecExceptionBranchesTest
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     *
     * Purpose:
     *   Exercise exception branches in Codec using namespaced function overrides
     *   that are loaded ONLY inside this isolated process.
     */
    final class CodecExceptionBranchesTest extends TestCase
    {
        protected function setUp(): void
        {
            // Load overrides only for this isolated test process.
            require_once __DIR__ . '/overrides/crypto_overrides.php';
            TestOverrides::reset();
        }

        protected function tearDown(): void
        {
            TestOverrides::reset();
        }

        private static function kb(int $b): string
        {
            return str_repeat(chr($b & 0xFF), 32);
        }

        private static function cfg(): Config
        {
            return new Config(
                headerName: 'X-Context',
                issuer:     'svc-caller',
                audience:   'svc-callee',
                ttlSeconds: 120,
                currentKid: 'kid-demo',
                currentKey: self::kb(1),
            );
        }

        // --- embedHeader() failures ---

        public function testEmbedHeader_EncryptFailure(): void
        {
            TestOverrides::reset();
            TestOverrides::set('encrypt_fail', true);
            try {
                $codec = Codec::buildFromEnv(self::cfg());
                $this->expectException(CryptoException::class);
                $this->expectExceptionMessage('openssl_encrypt failed');
                $codec->embedHeader(['x' => 1]);
            } finally {
                TestOverrides::reset();
            }
        }

        public function testEmbedHeader_EnvelopeJsonFailure(): void
        {
            TestOverrides::reset();
            TestOverrides::set('json_fail_envelope', true);
            try {
                $codec = Codec::buildFromEnv(self::cfg());
                $this->expectException(CryptoException::class);
                $this->expectExceptionMessage('envelope json encode failed');
                $codec->embedHeader(['x' => 1]);
            } finally {
                TestOverrides::reset();
            }
        }

        // --- parseHeaderValue() envelope errors ---

        public function testParseHeaderValue_BadEnvelope(): void
        {
            $codec = Codec::buildFromEnv(self::cfg());
            $env = [
                'V'   => 2,
                'Alg' => 'BAD',
                'KID' => 'kid-demo',
                'N'   => Base64Url::encode(random_bytes(12)),
                'CT'  => Base64Url::encode(random_bytes(32)),
            ];
            $val = 'v1.' . Base64Url::encode(\json_encode($env));
            $this->expectException(CryptoException::class);
            $this->expectExceptionMessage('bad envelope');
            $codec->parseHeaderValue($val);
        }

        // --- parseHeaderValue() payload/claims failures ---

        public function testParseHeaderValue_PayloadJsonParseFailure(): void
        {
            TestOverrides::reset();
            TestOverrides::set('decrypt_override', 'not_json');
            try {
                $caller = Codec::buildFromEnv(self::cfg());
                [, $val] = $caller->embedHeader(['ok' => true]);

                $callee = Codec::buildFromEnv(self::cfg());
                $this->expectException(CryptoException::class);
                $this->expectExceptionMessage('payload json parse failed');
                $callee->parseHeaderValue($val);
            } finally {
                TestOverrides::reset();
            }
        }

        public function testParseHeaderValue_IatInFuture(): void
        {
            // Embed with future clock
            TestOverrides::reset();
            TestOverrides::set('time', 1000);
            try {
                $caller = Codec::buildFromEnv(self::cfg());
                [, $val] = $caller->embedHeader(['ok' => 1]);
            } finally {
                TestOverrides::reset();
            }

            // Parse with present clock
            TestOverrides::set('time', 0);
            try {
                $callee = Codec::buildFromEnv(self::cfg());
                $this->expectException(ValidationException::class);
                $this->expectExceptionMessage('iat in future');
                $callee->parseHeaderValue($val);
            } finally {
                TestOverrides::reset();
            }
        }

        public function testParseHeaderValue_NotYetValid(): void
        {
            TestOverrides::reset();
            TestOverrides::set('decrypt_override', 'nbf_future');
            try {
                $caller = Codec::buildFromEnv(self::cfg());
                [, $val] = $caller->embedHeader(['ok' => true]);

                $callee = Codec::buildFromEnv(self::cfg());
                $this->expectException(ValidationException::class);
                $this->expectExceptionMessage('not yet valid');
                $callee->parseHeaderValue($val);
            } finally {
                TestOverrides::reset();
            }
        }

        public function testParseHeaderValue_MissingCtx(): void
        {
            TestOverrides::reset();
            TestOverrides::set('decrypt_override', 'missing_ctx');
            try {
                $caller = Codec::buildFromEnv(self::cfg());
                [, $val] = $caller->embedHeader(['ok' => true]);

                $callee = Codec::buildFromEnv(self::cfg());
                $this->expectException(CryptoException::class);
                $this->expectExceptionMessage('missing ctx');
                $callee->parseHeaderValue($val);
            } finally {
                TestOverrides::reset();
            }
        }

        public function testSetHeader_Psr7NotInstalled(): void
        {
            TestOverrides::reset();
            TestOverrides::set('psr_off', true);
            try {
                $codec = Codec::buildFromEnv(self::cfg());
                $this->expectException(ValidationException::class);
                $this->expectExceptionMessage('PSR-7 not installed');
                $codec->setHeader(new \stdClass(), ['x' => 1]);
            } finally {
                TestOverrides::reset();
            }
        }

        public function testParseFromRequest_Psr7NotInstalled(): void
        {
            TestOverrides::reset();
            TestOverrides::set('psr_off', true);
            try {
                $codec = Codec::buildFromEnv(self::cfg());
                $this->expectException(ValidationException::class);
                $this->expectExceptionMessage('PSR-7 not installed');
                $codec->parseFromRequest(new \stdClass());
            } finally {
                TestOverrides::reset();
            }
        }
    }
}
