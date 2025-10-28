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
// file: ./test/nodejs/claims.spec.ts
import { describe, it, expect } from 'vitest';
import { buildClaims, nowSec, cryptoRandomId } from '../../src/nodejs/util/claims';
describe('claims', () => {
    it('buildClaims sets monotonic times and jti', () => {
        const c = buildClaims('i', 'a', 10);
        expect(c.iss).toBe('i');
        expect(c.aud).toBe('a');
        expect(c.exp).toBeGreaterThan(c.iat);
        expect(c.nbf).toBe(c.iat);
        expect(c.jti).toMatch(/^[0-9a-f]{24}$/); // 12 bytes hex
    });
    it('nowSec is near current time', () => {
        const n = nowSec();
        const approx = Math.floor(Date.now() / 1000);
        expect(Math.abs(n - approx)).toBeLessThan(2);
    });
    it('cryptoRandomId length/charset', () => {
        const id = cryptoRandomId();
        expect(id).toMatch(/^[0-9a-f]{24}$/);
    });
});
