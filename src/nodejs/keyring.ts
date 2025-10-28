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

// file: ./src/nodejs/keyring.ts

import { ValidationError } from './validation.js';

export class Keyring {
    constructor(
        public readonly currentKid: string,
        public readonly currentKey: Uint8Array,
        public readonly otherKeys: Record<string, Uint8Array> = {}
    ) {
        this.validate();
    }

    private validate(): void {
        if (!this.currentKid) throw new ValidationError('xctx: CurrentKID required');
        if (this.currentKey.length !== 32) throw new ValidationError('xctx: CurrentKey must be 32 bytes');
        for (const [kid, key] of Object.entries(this.otherKeys)) {
            if (key.length !== 32) {
                throw new ValidationError(`xctx: OtherKeys[${kid}] must be 32 bytes (got ${key.length})`);
            }
        }
    }

    /** Returns the (kid,key) to use for sealing. */
    encKey(): { kid: string; key: Uint8Array } {
        return { kid: this.currentKid, key: this.currentKey };
    }

    /** Returns the key by KID for opening. */
    decKey(kid: string): Uint8Array | null {
        if (kid === this.currentKid) return this.currentKey;
        return this.otherKeys[kid] || null;
    }
}

/** Parse a key string that may be raw(32), hex(64), base64, base64url */
export function decodeKeyString(s: string): Uint8Array {
    const raw = new TextEncoder().encode(s);
    if (raw.length === 32) return raw;

    const hex = /^[0-9a-fA-F]{64}$/.test(s);
    if (hex) {
        const out = new Uint8Array(32);
        for (let i = 0; i < 32; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
        return out;
    }
    // try base64 or base64url
    try {
        const b = Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        if (b.length === 32) return new Uint8Array(b);
    } catch { /* fallthrough */ }

    throw new ValidationError('xctx: key must be 32 bytes (raw/hex/base64/base64url)');
}
