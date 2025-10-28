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

// file: ./src/nodejs/codec.ts

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { b64url } from './util/base64url.js';
import { buildClaims, nowSec } from './util/claims.js';
import type { AADBinder, Claims, EnvelopeV1, ParseResult, ResolvedOptions } from './types.js';
import { CryptoError, ValidationError } from './validation.js';

/**
 * Codec<T> performs AEAD seal/open of a typed payload T in an envelope:
 *   X-Context: v1.<base64url(json)>
 * where json is:
 *   { "v":1, "alg":"AES256-GCM", "kid":KID, "n":<nonce>, "ct":<ciphertext||tag> }
 *
 * - Nonce length: 12 bytes
 * - Tag length:   16 bytes (appended to ciphertext in `ct`)
 * - Alg string:   "AES256-GCM"
 * - All JSON keys are lowercase to match the Go implementation.
 */
export class Codec<T extends object> {
    static readonly VERSION = 1;
    static readonly ALG = 'AES256-GCM';
    static readonly NONCE_SZ = 12;
    static readonly TAG_SZ = 16;

    constructor(readonly opts: ResolvedOptions) {}

    /** Seals `payload` + `claims` into ("X-Context", "v1.<...>"). */
    embedHeader(payload: T): [name: string, value: string] {
        const { headerName, issuer, audience, ttlSeconds, currentKid, currentKey, aadBinder } = this.opts;

        const claims = buildClaims(issuer, audience, ttlSeconds);
        // Encrypt raw JSON bytes (Go/PHP compatible), not base64url of JSON.
        const ptObj = { ctx: payload, ...claims };
        const pt    = new TextEncoder().encode(JSON.stringify(ptObj));

        const nonce = randomBytes(Codec.NONCE_SZ);
        const [ct, tag] = this.aesGcmSeal(currentKey, nonce, pt, aadBytes(aadBinder));
        const env: EnvelopeV1 = {
            v: Codec.VERSION,
            alg: Codec.ALG,
            kid: currentKid,
            n: b64url.encode(nonce),
            ct: b64url.encode(concat(ct, tag)) // ciphertext || tag
        };

        return [headerName, `v${Codec.VERSION}.` + b64url.encodeJson(env)];
    }

    /** Parses a header value (v1) and returns the typed payload + claims. */
    parseHeaderValue(value: string): ParseResult<T> {
        if (!value.startsWith('v1.')) {
            throw new CryptoError('xctx: bad version');
        }

        // Decode the envelope JSON (lowercase keys). If tampered, JSON.parse may throw.
        let env: Partial<EnvelopeV1>;
        try {
            env = b64url.decodeJson<Partial<EnvelopeV1>>(value.slice(3));
        } catch (e) {
            // Map any syntax/decoding error to a semantic xctx error so tests (and callers)
            // see a consistent failure instead of a raw SyntaxError string.
            throw new CryptoError('xctx: bad envelope [env]');
        }

        // Accept lowercase (our canonical) strictly; caller may choose to tolerate variants here if needed.
        if (!env || env.v !== 1 || env.alg !== Codec.ALG) {
            throw new CryptoError('xctx: bad envelope [missmatch]');
        }
        const kid = env.kid ?? '';
        const n = env.n ?? '';
        const ct = env.ct ?? '';
        if (!kid || !n || !ct) throw new CryptoError('xctx: incomplete envelope');

        const key = this.findKey(kid);
        if (!key) throw new ValidationError('xctx: unknown kid');

        const nonce = b64url.decode(n);
        const cttag = b64url.decode(ct);
        if (nonce.length !== Codec.NONCE_SZ || cttag.length < Codec.TAG_SZ + 1) {
            throw new CryptoError('xctx: bad nonce/tag');
        }
        const tag = cttag.slice(cttag.length - Codec.TAG_SZ);
        const ciph = cttag.slice(0, cttag.length - Codec.TAG_SZ);

        const pt = this.aesGcmOpen(key, nonce, ciph, tag, aadBytes(this.opts.aadBinder));
        const decoded = JSON.parse(new TextDecoder().decode(pt));
        if (!decoded || typeof decoded !== 'object' || !decoded.ctx) {
            throw new CryptoError('xctx: payload json parse failed');
        }

        this.validateClaims(decoded);
        return { payload: decoded.ctx, claims: decoded };
    }

    private validateClaims(c: Claims): void {
        const now = nowSec();
        if (c.iss !== this.opts.issuer) throw new ValidationError('xctx: bad issuer');
        if (c.aud !== this.opts.audience) throw new ValidationError('xctx: bad audience');
        if (c.iat > now + 5) throw new ValidationError('xctx: iat in future');
        if (c.nbf > now + 5) throw new ValidationError('xctx: not yet valid');
        if (c.exp <= now) throw new ValidationError('xctx: token expired');
    }

    private findKey(kid: string): Uint8Array | null {
        if (kid === this.opts.currentKid) return this.opts.currentKey;
        return this.opts.otherKeys[kid] ?? null;
    }

    private aesGcmSeal(key: Uint8Array, nonce: Uint8Array, pt: Uint8Array, aad?: Uint8Array): [ct: Uint8Array, tag: Uint8Array] {
        const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: Codec.TAG_SZ });
        if (aad && aad.length) cipher.setAAD(aad);
        const c1 = cipher.update(pt);
        const c2 = cipher.final();
        const tag = cipher.getAuthTag();
        return [concat(c1, c2), new Uint8Array(tag)];
    }

    private aesGcmOpen(key: Uint8Array, nonce: Uint8Array, ct: Uint8Array, tag: Uint8Array, aad?: Uint8Array): Uint8Array {
        const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: Codec.TAG_SZ });
        if (aad && aad.length) decipher.setAAD(aad);
        decipher.setAuthTag(tag);
        const p1 = decipher.update(ct);
        try {
            const p2 = decipher.final();
            return concat(p1, p2);
        } catch {
            throw new CryptoError('xctx: auth failed');
        }
    }
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0); out.set(b, a.length);
    return out;
}

function aadBytes(aad: AADBinder): Uint8Array | undefined {
    if (!aad) return undefined;
    const v = aad();
    return v && v.length ? v : undefined;
}
