// SPDX-License-Identifier: Apache-2.0
/**
 * xctx example — Node.js Callee (native http) on port 8083
 *
 * Endpoints:
 *   GET /whoami
 *   GET /update
 *   GET /relay/go
 *   GET /relay/go/update
 *   GET /relay/php
 *   GET /relay/php/update
 *   GET /relay/node-express
 *   GET /relay/node-express/update
 */

import { createServer } from 'node:http';
import { resolveConfig, Codec } from 'xctx';

/** @typedef {{ user_id: number, user_name: string, role?: string }} PassingContext */

const cfg = resolveConfig({
    headerName: 'X-Context',
    issuer: 'svc-caller',
    audience: 'svc-callee',
    ttlSeconds: 120,
    currentKid: 'kid-demo',
    currentKey: '0123456789abcdef0123456789abcdef',
    aadBinder: () => new TextEncoder().encode('TENANT=blue|ENV=dev'),
});
/** @type {Codec<PassingContext>} */
const codec = new Codec(cfg);
const HEADER_NAME = cfg.headerName;

function sendJson(res, status, body) {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(body));
}
function readHeader(req, name) {
    const v = req.headers[name.toLowerCase()];
    if (v == null) return null;
    return Array.isArray(v) ? v[0] : String(v);
}
function nodeUpdate(inCtx) {
    const out = { ...inCtx };
    out.user_name = out.user_name ? `${out.user_name}+node` : 'node';
    out.role = out.role ? `${out.role}|node` : 'node';
    return out;
}
async function relay(res, payload, url) {
    const [name, value] = codec.embedHeader(payload);
    const r = await fetch(url, { headers: { [name]: value } });
    const text = await r.text();
    res.statusCode = r.status;
    res.setHeader('Content-Type', 'application/json');
    res.end(text);
}

const server = createServer(async (req, res) => {
    try {
        const url = new URL(req.url ?? '/', 'http://127.0.0.1');
        const path = url.pathname;
        if (req.method !== 'GET') {
            return sendJson(res, 405, { server: 'node-callee', error: 'method not allowed' });
        }

        if (path === '/whoami') {
            const val = readHeader(req, HEADER_NAME);
            if (!val) return sendJson(res, 400, { server: 'node-callee', error: 'missing X-Context' });
            const { payload, claims } = codec.parseHeaderValue(val);
            return sendJson(res, 200, { server: 'node-callee', ctx: payload, claims });
        }

        if (path === '/update') {
            const val = readHeader(req, HEADER_NAME);
            if (!val) return sendJson(res, 400, { server: 'node-callee', error: 'missing X-Context' });
            const { payload } = codec.parseHeaderValue(val);
            const updated = nodeUpdate(payload);
            return sendJson(res, 200, { server: 'node-callee', prev_ctx: payload, updated_ctx: updated });
        }

        if (path === '/relay/go') {
            const val = readHeader(req, HEADER_NAME);
            if (!val) return sendJson(res, 400, { server: 'node-callee', error: 'missing X-Context' });
            const { payload } = codec.parseHeaderValue(val);
            return relay(res, payload, 'http://127.0.0.1:8081/whoami');
        }
        if (path === '/relay/go/update') {
            const val = readHeader(req, HEADER_NAME);
            if (!val) return sendJson(res, 400, { server: 'node-callee', error: 'missing X-Context' });
            const { payload } = codec.parseHeaderValue(val);
            return relay(res, payload, 'http://127.0.0.1:8081/update');
        }

        if (path === '/relay/php') {
            const val = readHeader(req, HEADER_NAME);
            if (!val) return sendJson(res, 400, { server: 'node-callee', error: 'missing X-Context' });
            const { payload } = codec.parseHeaderValue(val);
            return relay(res, payload, 'http://127.0.0.1:8082/whoami');
        }
        if (path === '/relay/php/update') {
            const val = readHeader(req, HEADER_NAME);
            if (!val) return sendJson(res, 400, { server: 'node-callee', error: 'missing X-Context' });
            const { payload } = codec.parseHeaderValue(val);
            return relay(res, payload, 'http://127.0.0.1:8082/update');
        }

        // NEW: relay to Express callee on :8084
        if (path === '/relay/node-express') {
            const val = readHeader(req, HEADER_NAME);
            if (!val) return sendJson(res, 400, { server: 'node-callee', error: 'missing X-Context' });
            const { payload } = codec.parseHeaderValue(val);
            return relay(res, payload, 'http://127.0.0.1:8084/whoami');
        }
        if (path === '/relay/node-express/update') {
            const val = readHeader(req, HEADER_NAME);
            if (!val) return sendJson(res, 400, { server: 'node-callee', error: 'missing X-Context' });
            const { payload } = codec.parseHeaderValue(val);
            return relay(res, payload, 'http://127.0.0.1:8084/update');
        }

        return sendJson(res, 404, { server: 'node-callee', error: 'not found', path });
    } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return sendJson(res, 500, { server: 'node-callee', error: msg });
    }
});

server.listen(8083, () => {
    console.log('[node-callee] listening on http://127.0.0.1:8083');
});
