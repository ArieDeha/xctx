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

// file: ./src/Xctx/Util/Base64Url.php

declare(strict_types=1);

namespace ArieDeha\Xctx\Util;

/**
 * RFC 7515-compatible Base64URL (no padding).
 */
final class Base64Url
{
    /**
     * encode
     * encode binary to base64url string.
     * @param string $bin
     * @return string
     */
    public static function encode(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    /**
     * decode
     * decode base64url string to binary.
     * @param string $b64url
     * @return string
     */
    public static function decode(string $b64url): string
    {
        $s = strtr($b64url, '-_', '+/');
        $pad = strlen($s) % 4;
        if ($pad) { $s .= str_repeat('=', 4 - $pad); }
        $out = base64_decode($s, true);
        if ($out === false) {
            throw new \InvalidArgumentException('invalid base64url string');
        }
        return $out;
    }
}