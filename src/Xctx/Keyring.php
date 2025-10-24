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

// file: ./src/Xctx/Keyring.php

declare(strict_types=1);

namespace ArieDeha\Xctx;

use ArieDeha\Xctx\Exception\ValidationException;
final class Keyring
{
    public function __construct(
        public readonly string $currentKid,
        public readonly string $currentKey,           // binary, 32 bytes
        public readonly array $otherKeys = []         // map<kid => binary 32B>
    ) {
        $this->validate();
    }

    private function validate(): void
    {
        if ($this->currentKid === '') {
            throw new ValidationException('xctx: CurrentKID is required');
        }
        if (strlen($this->currentKey) !== 32) {
            throw new ValidationException('xctx: CurrentKey must be 32 bytes');
        }
        foreach ($this->otherKeys as $kid => $k) {
            if (!is_string($kid) || $kid === '') {
                throw new ValidationException('xctx: OtherKeys must have non-empty string kid');
            }
            if (!is_string($k) || strlen($k) !== 32) {
                throw new ValidationException(sprintf('xctx: OtherKeys[%s] must be 32 bytes (got %d)', (string)$kid, is_string($k) ? strlen($k) : -1));
            }
        }
    }

    /** Key used for encryption (current). */
    public function encKey(): array { return [$this->currentKid, $this->currentKey]; }

    /** Lookup decryption key by KID (current or accepted-old). */
    public function decKey(string $kid): ?string
    {
        if ($kid === $this->currentKid) return $this->currentKey;
        return $this->otherKeys[$kid] ?? null;
    }
}