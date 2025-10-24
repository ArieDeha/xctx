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

// file: ./test/ConfigTest.php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use ArieDeha\Xctx\Config;
use ArieDeha\Xctx\Exception\ValidationException;
use ArieDeha\Xctx\Keyring;
use ArieDeha\Xctx\Util\Base64Url;

/**
 * ConfigTest
 *
 * Purpose:
 *   Thoroughly cover configuration behavior: environment loading, TTL parsing,
 *   key string decoding (hex/base64/base64url/raw), other-keys parsing,
 *   merge precedence, and validate() error branches. Also covers Base64Url
 *   helpers and Keyring’s enc/dec behavior and validations.
 *
 * How:
 *   Manipulate env vars with putenv() for fromEnv() cases. A tearDown() cleans
 *   up all XCTX_* variables after each test so state never leaks between tests.
 */
final class ConfigTest extends TestCase
{
    /** Env vars to reset after each test. */
    private array $envKeys = [
        'XCTX_HEADER_NAME',
        'XCTX_ISSUER',
        'XCTX_AUDIENCE',
        'XCTX_TTL',
        'XCTX_CURRENT_KID',
        'XCTX_CURRENT_KEY',
        'XCTX_OTHER_KEYS',
        'XCTX_TYPED_KEY_NAME',
        'XCTX_CLOCK_SKEW_SEC',
        'XCTX_AAD',
    ];

    /** 32-byte binary with repeated byte. */
    private static function kb(int $b): string
    {
        return str_repeat(chr($b & 0xFF), 32);
    }

    /** Ensure no env leakage across tests (runs even if a test throws). */
    protected function tearDown(): void
    {
        foreach ($this->envKeys as $k) {
            putenv($k); // unsets
        }
    }

    // ---------------------------------------------------------------------
    // fromEnv(): TTL parsing variants & key decoding from env
    // ---------------------------------------------------------------------

    /**
     * Purpose:
     *   Confirm fromEnv() reads TTL in forms: seconds, "Xs", "Xm", "Xh".
     * How:
     *   Set XCTX_TTL to several forms and assert ttlSeconds equals expected.
     */
    public function testFromEnvReadsVariousTtlForms(): void
    {
        // seconds (numeric)
        putenv('XCTX_TTL=90');
        $c = Config::fromEnv();
        $this->assertSame(90, $c->ttlSeconds);

        // Xm
        putenv('XCTX_TTL=2m');
        $c = Config::fromEnv();
        $this->assertSame(120, $c->ttlSeconds);

        // Xh
        putenv('XCTX_TTL=1h');
        $c = Config::fromEnv();
        $this->assertSame(3600, $c->ttlSeconds);
    }

    /**
     * Purpose:
     *   Invalid TTL format in env should throw.
     * How:
     *   XCTX_TTL="oops"; call fromEnv(); expect ValidationException.
     */
    public function testFromEnvInvalidTtlThrows(): void
    {
        putenv('XCTX_TTL=oops');
        $this->expectException(ValidationException::class);
        Config::fromEnv();
    }

    /**
     * Purpose:
     *   Current key/string decode from env supports hex/base64/raw.
     * How:
     *   Set XCTX_CURRENT_KEY to each form; assert 32-byte currentKey. Do not set TTL here.
     */
    public function testFromEnvCurrentKeyDecodeVariants(): void
    {
        $bin = self::kb(0xAB);
        $hex = bin2hex($bin);
        $b64 = base64_encode($bin);
        $raw = str_repeat('x', 32);

        // hex
        putenv("XCTX_CURRENT_KEY=$hex");
        $c = Config::fromEnv();
        $this->assertSame(32, strlen($c->currentKey));

        // base64
        putenv("XCTX_CURRENT_KEY=$b64");
        $c = Config::fromEnv();
        $this->assertSame(32, strlen($c->currentKey));

        // raw 32
        putenv("XCTX_CURRENT_KEY=$raw");
        $c = Config::fromEnv();
        $this->assertSame(32, strlen($c->currentKey));
    }

    /**
     * Purpose:
     *   OTHER_KEYS CSV parsing from env (mixed encodings) works.
     * How:
     *   kid1=hex,kid2=base64url with whitespace; assert two entries, both 32 bytes.
     */
    public function testFromEnvOtherKeysParsing(): void
    {
        $hex  = bin2hex(self::kb(1));
        $b64u = rtrim(strtr(base64_encode(self::kb(2)), '+/', '-_'), '=');
        putenv("XCTX_OTHER_KEYS= kid1=$hex , kid2=$b64u ");
        $c = Config::fromEnv();
        $this->assertArrayHasKey('kid1', $c->otherKeys);
        $this->assertArrayHasKey('kid2', $c->otherKeys);
        $this->assertSame(32, strlen($c->otherKeys['kid1']));
        $this->assertSame(32, strlen($c->otherKeys['kid2']));
    }

    // ---------------------------------------------------------------------
    // merge(): precedence env→user; defaults retained when user omits
    // ---------------------------------------------------------------------

    /**
     * Purpose:
     *   User overrides beat env values; blanks/zeros ignored by merge().
     * How:
     *   Set env issuer/audience; merge user overrides with different values.
     */
    public function testMergePrecedenceOverridesWin(): void
    {
        putenv('XCTX_ISSUER=env-iss');
        putenv('XCTX_AUDIENCE=env-aud');

        $env = Config::fromEnv();
        $user = new Config(
            headerName: '',
            issuer:     'user-iss',
            audience:   'user-aud',
            ttlSeconds: 0,
            currentKid: '',
            currentKey: ''
        );
        $merged = $env->merge($user);

        $this->assertSame('user-iss', $merged->issuer);
        $this->assertSame('user-aud', $merged->audience);
    }

    // ---------------------------------------------------------------------
    // decodeKeyString variants & failures
    // ---------------------------------------------------------------------

    /**
     * Purpose:
     *   decodeKeyString accepts hex/base64/base64url/raw.
     * How:
     *   Round-trip known inputs; each must produce 32 bytes.
     */
    public function testDecodeKeyStringVariants(): void
    {
        $bin  = self::kb(0xCD);
        $hex  = bin2hex($bin);
        $b64  = base64_encode($bin);
        $b64u = rtrim(strtr($b64, '+/', '-_'), '=');
        $raw  = str_repeat('y', 32);

        $this->assertSame(32, strlen(Config::decodeKeyString($hex)));
        $this->assertSame(32, strlen(Config::decodeKeyString($b64)));
        $this->assertSame(32, strlen(Config::decodeKeyString($b64u)));
        $this->assertSame(32, strlen(Config::decodeKeyString($raw)));
    }

    /**
     * Purpose:
     *   decodeKeyString rejects malformed encodings or wrong lengths.
     * How:
     *   Short string → ValidationException.
     */
    public function testDecodeKeyStringInvalidThrows(): void
    {
        $this->expectException(ValidationException::class);
        Config::decodeKeyString('short');
    }

    // ---------------------------------------------------------------------
    // OTHER_KEYS parsing: good/bad/missing kid
    // ---------------------------------------------------------------------

    /** Accepts multiple entries with whitespace: kid1=hex,kid2=base64url. */
    public function testParseOtherKeysMultiple(): void
    {
        $hex  = bin2hex(self::kb(1));
        $b64u = rtrim(strtr(base64_encode(self::kb(2)), '+/', '-_'), '=');
        $csv  = " kid1=$hex , kid2=$b64u ";
        $map = Config::parseOtherKeys($csv);
        $this->assertArrayHasKey('kid1', $map);
        $this->assertArrayHasKey('kid2', $map);
    }

    /** Malformed entry without '=' is rejected. */
    public function testParseOtherKeysMalformed(): void
    {
        $this->expectException(ValidationException::class);
        Config::parseOtherKeys('novalue');
    }

    /** Empty kid is rejected. */
    public function testParseOtherKeysEmptyKid(): void
    {
        $raw = str_repeat('z', 32);
        $this->expectException(ValidationException::class);
        Config::parseOtherKeys('= '.$raw);
    }

    // ---------------------------------------------------------------------
    // validate(): all error branches
    // ---------------------------------------------------------------------

    /** headerName required. */
    public function testValidateHeaderNameRequired(): void
    {
        $cfg = new Config(
            headerName: '',
            issuer:     null,
            audience:   null,
            ttlSeconds: 60,
            currentKid: 'kid',
            currentKey: self::kb(3)
        );
        $this->expectException(ValidationException::class);
        $cfg->validate();
    }

    /** currentKid required. */
    public function testValidateCurrentKidRequired(): void
    {
        $cfg = new Config(
            headerName: 'X-Context',
            issuer:     null,
            audience:   null,
            ttlSeconds: 60,
            currentKid: '',
            currentKey: self::kb(3)
        );
        $this->expectException(ValidationException::class);
        $cfg->validate();
    }

    /** currentKey must be exactly 32 bytes. */
    public function testValidateCurrentKeyLen(): void
    {
        $cfg = new Config(
            headerName: 'X-Context',
            issuer:     null,
            audience:   null,
            ttlSeconds: 60,
            currentKid: 'kid',
            currentKey: 'short'
        );
        $this->expectException(ValidationException::class);
        $cfg->validate();
    }

    /** ttlSeconds must be > 0. */
    public function testValidateTtlPositive(): void
    {
        $cfg = new Config(
            headerName: 'X-Context',
            issuer:     null,
            audience:   null,
            ttlSeconds: 0,
            currentKid: 'kid',
            currentKey: self::kb(3)
        );
        $this->expectException(ValidationException::class);
        $cfg->validate();
    }

    /** otherKeys entries must be 32 bytes with non-empty kid. */
    public function testValidateOtherKeysLen(): void
    {
        $cfg = new Config(
            headerName: 'X-Context',
            issuer:     null,
            audience:   null,
            ttlSeconds: 60,
            currentKid: 'kid',
            currentKey: self::kb(3),
            otherKeys:  ['old' => 'short']
        );
        $this->expectException(ValidationException::class);
        $cfg->validate();
    }

    // ---------------------------------------------------------------------
    // Base64Url helpers
    // ---------------------------------------------------------------------

    /** Base64Url encode/decode round-trip and padding removal. */
    public function testBase64UrlHelpers(): void
    {
        $bin = random_bytes(64);
        $enc = Base64Url::encode($bin);
        $this->assertStringNotContainsString('=', $enc);
        $dec = Base64Url::decode($enc);
        $this->assertSame($bin, $dec);
    }

    /** Base64Url::decode rejects invalid alphabet. */
    public function testBase64UrlDecodeInvalid(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Base64Url::decode('***');
    }

    // ---------------------------------------------------------------------
    // Keyring coverage: enc/dec paths and validations
    // ---------------------------------------------------------------------

    /** encKey returns current; decKey finds both current and other; unknown→null. */
    public function testKeyringEncDec(): void
    {
        $kr = new Keyring('kid', self::kb(1), ['old'=>self::kb(2)]);
        [$kid, $key] = $kr->encKey();
        $this->assertSame('kid', $kid);
        $this->assertSame(32, strlen($key));
        $this->assertSame(self::kb(1), $kr->decKey('kid'));
        $this->assertSame(self::kb(2), $kr->decKey('old'));
        $this->assertNull($kr->decKey('unknown'));
    }

    /** Keyring validates key lengths and kid presence. */
    public function testKeyringValidations(): void
    {
        // missing current kid
        $this->expectException(ValidationException::class);
        new Keyring('', self::kb(1));

        // wrong current key length
        try {
            new Keyring('kid', 'short');
            $this->fail('expected ValidationException for short current key');
        } catch (ValidationException $e) {
            $this->assertStringContainsString('CurrentKey', $e->getMessage());
        }

        // other key wrong length
        try {
            new Keyring('kid', self::kb(1), ['old' => 'short']);
            $this->fail('expected ValidationException for short other key');
        } catch (ValidationException $e) {
            $this->assertStringContainsString('OtherKeys', $e->getMessage());
        }
    }

    // ---------------------------------------------------------------------
    // EXTRA Keyring validation branches (to push coverage >90%)
    // ---------------------------------------------------------------------

    /**
     * Purpose:
     *   Validate that Keyring rejects an OtherKeys entry whose array key
     *   (the KID) is not a string (e.g., an integer). This hits the branch:
     *   `if (!is_string($kid) || $kid === '')`.
     *
     * How:
     *   Construct Keyring with otherKeys having an integer KID => valid 32B value.
     *   Expect ValidationException mentioning "OtherKeys".
     */
    public function testKeyringOtherKeysInvalidKidTypeInteger(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('OtherKeys');
        // Note: PHP arrays can have integer keys; we exploit that here.
        // 123 => 32B string triggers the non-string KID branch.
        new Keyring('kid', self::kb(1), [123 => self::kb(2)]);
    }

    /**
     * Purpose:
     *   Validate that Keyring rejects an OtherKeys entry whose KID is an empty string.
     *   This exercises the second part of the same condition: `$kid === ''`.
     *
     * How:
     *   Construct Keyring with otherKeys having '' => valid 32B value.
     *   Expect ValidationException mentioning "OtherKeys".
     */
    public function testKeyringOtherKeysInvalidKidEmptyString(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('OtherKeys');
        new Keyring('kid', self::kb(1), ['' => self::kb(2)]);
    }

    /**
     * Purpose:
     *   Validate that Keyring rejects an OtherKeys entry whose value is NOT a string
     *   (e.g., an integer). This hits the branch:
     *   `if (!is_string($k) || strlen($k) !== 32)`.
     *
     * How:
     *   Construct Keyring with otherKeys having a proper string KID but integer value.
     *   Expect ValidationException mentioning "OtherKeys".
     */
    public function testKeyringOtherKeysInvalidValueNonString(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('OtherKeys');
        /** @var array<string,mixed> $bad */
        $bad = ['old' => 12345]; // not a string
        new Keyring('kid', self::kb(1), $bad);
    }

    /**
     * Purpose:
     *   Positive control: a Keyring with multiple valid OtherKeys entries passes
     *   validation, encKey returns [currentKid,currentKey], and decKey resolves both
     *   the current KID and accepted old KIDs correctly.
     *
     * How:
     *   Construct Keyring with two valid old keys; assert encKey and decKey behavior.
     */
    public function testKeyringConstructorAcceptsMultipleValidOtherKeys(): void
    {
        $kr = new Keyring('kid-cur', self::kb(9), [
            'oldA' => self::kb(10),
            'oldB' => self::kb(11),
        ]);

        [$kid, $key] = $kr->encKey();
        $this->assertSame('kid-cur', $kid);
        $this->assertSame(self::kb(9), $key);

        $this->assertSame(self::kb(9),  $kr->decKey('kid-cur')); // current
        $this->assertSame(self::kb(10), $kr->decKey('oldA'));    // accepted
        $this->assertSame(self::kb(11), $kr->decKey('oldB'));    // accepted
        $this->assertNull($kr->decKey('nope'));                  // unknown
    }

    /**
     * Purpose:
     *   Hit Keyring::validate() branch that enforces the current key length:
     *   `if (strlen($this->currentKey) !== 32) { throw ... }`.
     *
     * How:
     *   Construct a Keyring with a 31-byte current key (one byte short).
     *   Expect a ValidationException with the specific message fragment.
     *
     * Why:
     *   Although other tests may indirectly cover invalid key lengths,
     *   this test targets the exact failure line to guarantee coverage.
     */
    public function testKeyringValidateRejectsShortCurrentKey(): void
    {
        $shortKey = str_repeat('A', 31); // 31 bytes, should fail
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('CurrentKey must be 32 bytes');
        new Keyring('kid-cur', $shortKey);
    }
}
