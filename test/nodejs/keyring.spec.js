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
// file: ./test/nodejs/keyring.spec.ts
import { describe, it, expect } from 'vitest';
import { Keyring } from '../../src/nodejs/keyring';
describe('keyring', () => {
    it('encKey/decKey and rotation acceptance', () => {
        const kr = new Keyring('kid', new TextEncoder().encode('0'.repeat(32)), {
            old: new TextEncoder().encode('1'.repeat(32)),
        });
        expect(kr.encKey().kid).toBe('kid');
        expect(kr.decKey('kid').length).toBe(32);
        expect(kr.decKey('old').length).toBe(32);
        expect(kr.decKey('none')).toBeNull();
    });
    it('validation failures', () => {
        expect(() => new Keyring('', new Uint8Array(32))).toThrow(/CurrentKID/);
        expect(() => new Keyring('kid', new Uint8Array(10))).toThrow(/32 bytes/);
        expect(() => new Keyring('kid', new Uint8Array(32), { bad: new Uint8Array(31) }))
            .toThrow(/OtherKeys\[bad].*32 bytes/);
    });
});
