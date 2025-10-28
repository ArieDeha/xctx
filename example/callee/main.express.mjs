// SPDX-License-Identifier: Apache-2.0
/**
 * xctx example — Node.js Callee (Express) on port 8084
 *
 * Purpose:
 *   Demonstrates using the published `xctx` npm package (as a 3rd-party)
 *   inside an Express app. It verifies/parses the {X-Context} header,
 *   mutates the typed payload on /update, and can relay (re-sealed) to
 *   the other callees (Go:8081, PHP:8082, Node-HTTP:8083).
 *
 * Endpoints:
 *   GET /whoami
 *   GET /update
 *   GET /relay/go
 *   GET /relay/go/update
 *   GET /relay/php
 *   GET /relay/php/update
 *   GET /relay/node
 *   GET /relay/node/update
 *
 * Run:
 *   cd example/callee
 *   npm install
 *   npm run start:express
 */

import express from 'express';
import { resolveConfig, Codec } from 'xctx';

/** @typedef {{ user_id: number, user_name: string, role?: string }} PassingContext */

// ---- Codec bootstrap (demo defaults; replace with env/secret-store in real apps)
const cfg = resolveConfig({
    headerName: 'X-Context',
    issuer: 'svc-caller',
    audience: 'svc-callee',
    ttlSeconds: 120,
    currentKid: 'kid-demo',
    currentKey: '0123456789abcdef0123456789abcdef', // 32 bytes demo key
    aadBinder: () => new TextEncoder().encode('TENANT=blue|ENV=dev'),
});
/** @type {Codec<PassingContext>} */
const codec = new Codec(cfg);
const HEADER_NAME = cfg.headerName;

// ---- Helpers
/** @param {express.Response} res @param {number} status @param {unknown} body
 * @param {string} status
 * @param {string} body *
 * */
function json(res, status, body) { res.status(status).json(body); }

/** @param {PassingContext} inCtx @returns {PassingContext} */
function nodeUpdate(inCtx) {
    const out = { ...inCtx };
    out.user_name = out.user_name ? `${out.user_name}+node` : 'node';
    out.role = out.role ? `${out.role}|node` : 'node';
    return out;
}

/** Relay helper: reseal then fetch target, return its body/status */
async function relay(res, payload, url) {
    const [name, value] = codec.embedHeader(payload);
    const r = await fetch(url, { headers: { [name]: value } });
    const text = await r.text();
    res.status(r.status).type('application/json').send(text);
}

// ---- App
const app = express();

app.get('/whoami', (req, res) => {
    const val = req.get(HEADER_NAME);
    if (!val) return json(res, 400, { server: 'node-express-callee', error: 'missing X-Context' });
    const { payload, claims } = codec.parseHeaderValue(val);
    json(res, 200, { server: 'node-express-callee', ctx: payload, claims });
});

app.get('/update', (req, res) => {
    const val = req.get(HEADER_NAME);
    if (!val) return json(res, 400, { server: 'node-express-callee', error: 'missing X-Context' });
    const { payload } = codec.parseHeaderValue(val);
    const updated = nodeUpdate(payload);
    json(res, 200, { server: 'node-express-callee', prev_ctx: payload, updated_ctx: updated });
});

// ---- Relays
app.get('/relay/go', async (req, res) => {
    const val = req.get(HEADER_NAME);
    if (!val) return json(res, 400, { server: 'node-express-callee', error: 'missing X-Context' });
    const { payload } = codec.parseHeaderValue(val);
    await relay(res, payload, 'http://127.0.0.1:8081/whoami');
});

app.get('/relay/go/update', async (req, res) => {
    const val = req.get(HEADER_NAME);
    if (!val) return json(res, 400, { server: 'node-express-callee', error: 'missing X-Context' });
    const { payload } = codec.parseHeaderValue(val);
    await relay(res, payload, 'http://127.0.0.1:8081/update');
});

app.get('/relay/php', async (req, res) => {
    const val = req.get(HEADER_NAME);
    if (!val) return json(res, 400, { server: 'node-express-callee', error: 'missing X-Context' });
    const { payload } = codec.parseHeaderValue(val);
    await relay(res, payload, 'http://127.0.0.1:8082/whoami');
});

app.get('/relay/php/update', async (req, res) => {
    const val = req.get(HEADER_NAME);
    if (!val) return json(res, 400, { server: 'node-express-callee', error: 'missing X-Context' });
    const { payload } = codec.parseHeaderValue(val);
    await relay(res, payload, 'http://127.0.0.1:8082/update');
});

app.get('/relay/node', async (req, res) => {
    const val = req.get(HEADER_NAME);
    if (!val) return json(res, 400, { server: 'node-express-callee', error: 'missing X-Context' });
    const { payload } = codec.parseHeaderValue(val);
    await relay(res, payload, 'http://127.0.0.1:8083/whoami');
});

app.get('/relay/node/update', async (req, res) => {
    const val = req.get(HEADER_NAME);
    if (!val) return json(res, 400, { server: 'node-express-callee', error: 'missing X-Context' });
    const { payload } = codec.parseHeaderValue(val);
    await relay(res, payload, 'http://127.0.0.1:8083/update');
});

app.listen(8084, () => {
    console.log('[node-express-callee] listening on http://127.0.0.1:8084');
});
