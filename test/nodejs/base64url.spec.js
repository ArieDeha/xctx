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
// file: ./test/nodejs/base64url.spec.ts
import { describe, it, expect } from 'vitest';
import { b64url } from '../../src/nodejs/util/base64url';
describe('base64url', () => {
    it('encode/decode roundtrip bytes', () => {
        const data = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
        const s = b64url.encode(data);
        const d = b64url.decode(s);
        expect(d).toEqual(data);
    });
    it('encodeJson/decodeJson roundtrip', () => {
        const obj = { a: 1, s: 'x', arr: [1, 2] };
        const s = b64url.encodeJson(obj);
        const back = b64url.decodeJson(s);
        expect(back).toEqual(obj);
    });
});
