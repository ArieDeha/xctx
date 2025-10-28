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

// file: ./test/nodejs/express.spec.ts

import { describe, it, expect } from 'vitest';
import { xctxMiddleware } from '../../src/nodejs/express';
import { Codec } from '../../src/nodejs/codec';
import { resolveConfig } from '../../src/nodejs/config';

type P = { user_id: number; user_name: string };

function mkCodec() {
    const cfg = resolveConfig({
        headerName: 'X-Context',
        issuer: 'svc-caller',
        audience: 'svc-callee',
        ttlSeconds: 30,
        currentKid: 'kid-demo',
        currentKey: '0123456789abcdef0123456789abcdef',
    });
    return new Codec<P>(cfg);
}

function mkRes() {
    const res: any = { statusCode: 200, body: null };
    res.status = (code: number) => { res.statusCode = code; return res; };
    res.json = (obj: unknown) => { res.body = obj; return res; };
    return res;
}

describe('express middleware', () => {
    it('400 when header missing', () => {
        const codec = mkCodec();
        const req: any = { header: () => null };
        const res = mkRes();
        let nextCalled = false;
        xctxMiddleware(codec)(req as any, res as any, () => { nextCalled = true; });
        expect(nextCalled).toBe(false);
        expect(res.statusCode).toBe(400);
        expect(res.body).toMatchObject({ error: /missing/i });
    });

    it('401 when parse fails', () => {
        const codec = mkCodec();
        const req: any = { header: () => 'v1.bad' }; // malformed
        const res = mkRes();
        xctxMiddleware(codec)(req as any, res as any, () => {});
        expect(res.statusCode).toBe(401);
        expect(String(res.body.error)).toMatch(/bad envelope|bad version/i);
    });

    it('success attaches payload and claims', () => {
        const codec = mkCodec();
        const [name, val] = codec.embedHeader({ user_id: 1, user_name: 'arie' });
        const req: any = { header: (h: string) => (h === name ? val : null) };
        const res = mkRes();
        let nextCalled = false;
        xctxMiddleware(codec)(req as any, res as any, () => { nextCalled = true; });
        expect(nextCalled).toBe(true);
        expect((req as any).xctxPayload.user_name).toBe('arie');
        expect((req as any).xctxClaims.iss).toBe('svc-caller');
    });
});
