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

// file: ./test/nodejs/config.spec.ts

import { describe, it, expect } from 'vitest';
import { loadEnvConfig, resolveConfig, parseTTL, mergeConfig } from '../../src/nodejs/config';
import { decodeKeyString } from '../../src/nodejs/keyring';
import { ValidationError } from '../../src/nodejs/validation';

describe('config & helpers', () => {
    it('parseTTL accepts seconds and Ns/Nm/Nh', () => {
        expect(parseTTL('60')).toBe(60);
        expect(parseTTL('2m')).toBe(120);
        expect(parseTTL('1h')).toBe(3600);
        expect(() => parseTTL('5x')).toThrow(/TTL format/i);
    });

    it('decodeKeyString supports raw/hex/base64/base64url and rejects bad', () => {
        const raw = '0123456789abcdef0123456789abcdef';
        expect(decodeKeyString(raw).length).toBe(32);
        const hex = '00'.repeat(32);
        expect(decodeKeyString(hex).length).toBe(32);
        const b64 = Buffer.from(raw).toString('base64');
        expect(decodeKeyString(b64).length).toBe(32);
        const b64u = b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
        expect(decodeKeyString(b64u).length).toBe(32);
        expect(() => decodeKeyString('short')).toThrow(/32 bytes/i);
    });

    it('resolveConfig success and aad binder nullable', () => {
        const cfg = resolveConfig({
            headerName: 'X-Context',
            issuer: 'i',
            audience: 'a',
            ttlSeconds: 30,
            currentKid: 'kid',
            currentKey: '00'.repeat(32),
            otherKeys: { old: 'ff'.repeat(32) },
            aadBinder: null,
        } as any);
        expect(cfg.currentKey.length).toBe(32);
        expect(cfg.otherKeys.old.length).toBe(32);
    });

    it('resolveConfig errors for missing fields and bad otherKeys', () => {
        expect(() => resolveConfig({} as any)).toThrow(ValidationError);
        expect(() => resolveConfig({
            headerName: 'X-Context',
            issuer: 'i', audience: 'a', ttlSeconds: 30,
            currentKid: 'kid', currentKey: '00'.repeat(32),
            otherKeys: { bad: '01' }, // too short
        })).toThrow(/32 bytes/);
    });

    it('loadEnvConfig, merge precedence, aad from env', () => {
        const save = { ...process.env };
        process.env.XCTX_HEADER_NAME = 'X-Context';
        process.env.XCTX_ISSUER = 'env-iss';
        process.env.XCTX_AUDIENCE = 'env-aud';
        process.env.XCTX_TTL = '45s';
        process.env.XCTX_CURRENT_KID = 'env-kid';
        process.env.XCTX_CURRENT_KEY = '00'.repeat(32);
        process.env.XCTX_OTHER_KEYS = 'old=' + 'ff'.repeat(32);
        process.env.XCTX_AAD = 'TENANT=env|ENV=dev';

        const env = loadEnvConfig();
        const user = { issuer: 'user-iss' }; // user overrides issuer
        const merged = mergeConfig(env, user);
        const cfg = resolveConfig(merged);

        expect(cfg.issuer).toBe('user-iss');  // user override wins
        expect(cfg.audience).toBe('env-aud'); // from env
        expect(cfg.ttlSeconds).toBe(45);
        expect(cfg.otherKeys.old.length).toBe(32);
        expect(cfg.aadBinder && cfg.aadBinder()?.length).toBeGreaterThan(0);

        process.env = save;
    });
});
