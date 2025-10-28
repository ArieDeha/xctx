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

// file: ./src/nodejs/express.ts

import type { Request, Response, NextFunction } from 'express';
import type { Codec } from './codec.js';

/**
 * Middleware factory: parses X-Context; attaches to req.xctxPayload / req.xctxClaims.
 */
export function xctxMiddleware<T extends object>(codec: Codec<T>) {
    return (req: Request, res: Response, next: NextFunction) => {
        const val = req.header(codec.opts.headerName);
        if (!val) return res.status(400).json({ error: 'missing X-Context' });
        try {
            const { payload, claims } = codec.parseHeaderValue(val);
            (req as any).xctxPayload = payload;
            (req as any).xctxClaims = claims;
            next();
        } catch (e: any) {
            res.status(401).json({ error: String(e?.message || e) });
        }
    };
}
