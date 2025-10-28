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

// file: ./src/nodejs/types.ts

/**
 * Wire-level envelope (lowercase keys) to exactly match Go & PHP v1.
 */
export interface EnvelopeV1 {
    v: 1;
    alg: 'AES256-GCM';
    kid: string;
    n: string;   // nonce (b64url)
    ct: string;  // ciphertext || tag (b64url)
}

/**
 * Claims associated with the payload, validated on the consumer.
 */
export interface Claims {
    iss: string;
    aud: string;
    iat: number; // seconds
    nbf: number; // seconds
    exp: number; // seconds
    jti: string; // unique ID
}

/**
 * Non-secret Additional Authenticated Data provider.
 * Must return identical bytes on both producer & consumer.
 */
export type AADBinder = (() => Uint8Array) | null;

/**
 * Codec options after config resolution.
 */
export interface ResolvedOptions {
    headerName: string;     // e.g., "X-Context"
    issuer: string;
    audience: string;
    ttlSeconds: number;     // e.g., 120
    currentKid: string;
    currentKey: Uint8Array; // length = 32
    otherKeys: Record<string, Uint8Array>;
    aadBinder: AADBinder;
}

/**
 * Result of parsing.
 */
export interface ParseResult<T> {
    payload: T;
    claims: Claims;
}
