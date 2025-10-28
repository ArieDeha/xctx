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

// file: ./src/nodejs/config.ts

import { decodeKeyString, Keyring } from './keyring.js';
import type { ResolvedOptions, AADBinder } from './types.js';
import { ValidationError } from './validation.js';

export interface UserConfig {
    headerName?: string;
    issuer?: string;
    audience?: string;
    ttlSeconds?: number;
    currentKid?: string;
    currentKey?: string | Uint8Array;
    otherKeys?: Record<string, string | Uint8Array>;
    aadBinder?: (() => Uint8Array) | null;
}

export function loadEnvConfig(): UserConfig {
    const env = process.env;
    const out: UserConfig = {};
    if (env.XCTX_HEADER_NAME) out.headerName = env.XCTX_HEADER_NAME;
    if (env.XCTX_ISSUER) out.issuer = env.XCTX_ISSUER;
    if (env.XCTX_AUDIENCE) out.audience = env.XCTX_AUDIENCE;
    if (env.XCTX_TTL) out.ttlSeconds = parseTTL(env.XCTX_TTL);
    if (env.XCTX_CURRENT_KID) out.currentKid = env.XCTX_CURRENT_KID;
    if (env.XCTX_CURRENT_KEY) out.currentKey = env.XCTX_CURRENT_KEY;
    if (env.XCTX_OTHER_KEYS) out.otherKeys = parseOtherKeys(env.XCTX_OTHER_KEYS);
    if (env.XCTX_AAD) {
        const v = env.XCTX_AAD;
        out.aadBinder = () => new TextEncoder().encode(v);
    }
    return out;
}

export function mergeConfig(env: UserConfig, user: UserConfig): UserConfig {
    return { ...env, ...user };
}

export function resolveConfig(user: UserConfig): ResolvedOptions {
    const headerName = user.headerName ?? 'X-Context';
    const issuer = must(user.issuer, 'xctx: Issuer required');
    const audience = must(user.audience, 'xctx: Audience required');
    const ttlSeconds = must(user.ttlSeconds, 'xctx: TTL required');

    const kid = must(user.currentKid, 'xctx: CurrentKID required');
    const k = toKey(user.currentKey, 'xctx: CurrentKey required');

    const otherKeys: Record<string, Uint8Array> = {};
    for (const [okid, v] of Object.entries(user.otherKeys ?? {})) {
        otherKeys[okid] = toKey(v, `xctx: OtherKeys[${okid}] required`);
    }

    const kr = new Keyring(kid, k, otherKeys);
    const aadBinder = (user.aadBinder ?? null) as AADBinder;

    return {
        headerName,
        issuer,
        audience,
        ttlSeconds,
        currentKid: kr.currentKid,
        currentKey: kr.currentKey,
        otherKeys: kr.otherKeys,
        aadBinder
    };
}

function toKey(
    v: string | Uint8Array | null | undefined,
    msg: string
): Uint8Array {
    const val = must(v, msg);

    // 1) If it's a string, decode (raw/hex/base64/base64url all supported)
    if (typeof val === 'string') {
        return decodeKeyString(val);
    }

    // 2) Otherwise it must be Uint8Array (no instanceof needed for narrowing)
    //    You can still assert defensively if you want:
    //    if (!(val instanceof Uint8Array)) throw new ValidationError('xctx: key must be string or Uint8Array');
    if (val.length !== 32) {
        throw new ValidationError('xctx: key length must be 32 bytes');
    }
    return val;
}
// Prefer this simple helper (keeps proper narrowing)
function must<T>(v: T | null | undefined, msg: string): NonNullable<T> {
    if (v == null) throw new ValidationError(msg);
    return v as NonNullable<T>;
}

export function parseTTL(s: string): number {
    // Accept: seconds or Ns/Nm/Nh
    if (/^\d+$/.test(s)) return parseInt(s, 10);
    const m = s.match(/^(\d+)([smh])$/i);
    if (!m) throw new ValidationError('xctx: TTL format must be seconds or Ns/Nm/Nh');
    const n = parseInt(m[1], 10);
    const u = m[2].toLowerCase();
    return u === 's' ? n : u === 'm' ? n * 60 : n * 3600;
}

function parseOtherKeys(s: string): Record<string, string> {
    // kid1=KEY1,kid2=KEY2
    const out: Record<string, string> = {};
    for (const part of s.split(',')) {
        const [k, v] = part.split('=');
        if (k && v) out[k.trim()] = v.trim();
    }
    return out;
}
