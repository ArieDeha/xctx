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

// file: ./src/nodejs/util/base64url.ts

/**
 * Base64URL with no padding. Compatible with Go/PHP implementations.
 */
export const b64url = {
    encode(buf: Uint8Array): string {
        const s = Buffer.from(buf).toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/g, '');
        return s;
    },
    decode(s: string): Uint8Array {
        const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : '';
        const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
        return new Uint8Array(Buffer.from(b64, 'base64'));
    },
    encodeJson(obj: unknown): string {
        return this.encode(new TextEncoder().encode(JSON.stringify(obj)));
    },
    decodeJson<T = unknown>(s: string): T {
        const bytes = this.decode(s);
        return JSON.parse(new TextDecoder().decode(bytes), this.lowercaseKeysReviver) as T;
    },

    lowercaseKeysReviver(key: string, value: any): object {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
        const newObject: {[key:string]:any} = {};
        for (const prop in value) {
            if (Object.prototype.hasOwnProperty.call(value, prop)) {
                newObject[prop.toLowerCase()] = value[prop];
            }
        }
        return newObject;
    }
    return value;
}
};
