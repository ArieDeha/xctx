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

// file: ./src/nodejs/util/claims.ts

import type { Claims } from '../types.js';

export function nowSec(): number {
    return Math.floor(Date.now() / 1000);
}

export function buildClaims(issuer: string, audience: string, ttlSeconds: number): Claims {
    const n = nowSec();
    return {
        iss: issuer,
        aud: audience,
        iat: n,
        nbf: n,
        exp: n + ttlSeconds,
        jti: cryptoRandomId()
    };
}

// 96-bit random id as b64url (or hex is fine; b64url is shorter)
export function cryptoRandomId(): string {
    const b = cryptoGetRandom(12);
    return Buffer.from(b).toString('hex'); // 12 bytes -> 24 hex chars
}

// Thin abstraction so tests can stub randomness if desired.
export function cryptoGetRandom(n: number): Uint8Array {
    const buf = new Uint8Array(n);
    // Node 18+: globalThis.crypto is present; fallback to require('crypto') if needed.
    if (typeof globalThis.crypto?.getRandomValues === 'function') {
        globalThis.crypto.getRandomValues(buf);
        return buf;
    }
    const { randomBytes } = require('node:crypto') as typeof import('node:crypto');
    return new Uint8Array(randomBytes(n));
}
