// SPDX-License-Identifier: Apache-2.0
/**
 * file: ./example/callee/main.node.mjs
 *
 * NodeJS xctx “callee” service (listens on :8083).
 *
 * What this file demonstrates
 * --------------------------
 *  1. How to construct a typed xctx Codec with explicit config using the
 *     same key material across languages (Go, PHP, Node).
 *  2. How to parse an inbound header straight from an Express Request with
 *     `codec.parseHeaderValue(req.get('X-Context'))`.
 *  3. How to re-embed a typed payload by calling `codec.embedHeader(payload)`
 *     and forward it to another callee (relay).
 *  4. Plain “whoami” and “update” endpoints plus two relay flows to Go and PHP:
 *       /relay/go, /relay/php               – simple relays to /whoami
 *       /relay/go/update, /relay/php/update – Chain flows that update in the
 *                                             other callee then update back in Node.
 *
 * Ports & Endpoints
 * -----------------
 *  - :8083/whoami
 *      Parse X-Context and return {"server":"node-callee","ctx":{...},"claims":{...}}.
 *  - :8083/update
 *      Parse X-Context, mutate it (add “+node” to user_name, “|node” to role), and
 *      return {"server":"node-callee","prev_ctx":{...},"updated_ctx":{...}}.
 *  - :8083/relay/go
 *      Parse X-Context, re-embed it, call Go callee /whoami, and stream response.
 *  - :8083/relay/php
 *      Parse X-Context, re-embed it, call PHP callee /whoami, and stream response.
 *  - :8083/relay/go/update
 *      Parse original X-Context, call Go /update (Go mutates), then apply Node
 *      mutation and return {"server":"node-callee","prev_ctx":{...},
 *      "go_updated_ctx":{...},"node_updated_ctx":{...}}.
 *  - :8083/relay/php/update
 *      Same as above but relay to PHP first.
 *
 * Build & Run
 * -----------
 *    npm install
 *    npm run build           # generate ./dist/nodejs/esm
 *    node example/callee/main.node.mjs
 *
 * Test manually with the example callers (Go/PHP/Node).
 */

import express from 'express';
import { resolveConfig, Codec } from '../../dist/nodejs/esm/index.js';

/** @typedef {{ user_id: number, user_name: string, role?: string }} PassingContext */

/** Build a Codec with the same config/key as Go & PHP examples. */
const cfg = resolveConfig({
  headerName: 'X-Context',
  issuer: 'svc-caller',
  audience: 'svc-callee',
  ttlSeconds: 120,
  currentKid: 'kid-demo',
  currentKey: '0123456789abcdef0123456789abcdef', // 32 bytes; string is decoded
  aadBinder: () => new TextEncoder().encode('TENANT=blue|ENV=dev'),
});
/** @type {Codec<PassingContext>} */
const codec = new Codec(cfg);

/** Mutate helper mirroring Go/PHP update semantics. */
function nodeUpdate(inCtx) {
  const out = { ...inCtx };
  out.user_name = out.user_name ? out.user_name + '+node' : 'node';
  out.role = out.role ? out.role + '|node' : 'node';
  return out;
}

/** Pretty stderr logging for visibility. */
function logCtx(label, ctx) {
  console.error(`[${label}]`, ctx);
}

/** Convenience: parse inbound header, returning {payload, claims}. */
function parseFromReq(req) {
  const val = req.get(cfg.headerName);
  if (!val) throw new Error('missing X-Context');
  return codec.parseHeaderValue(val);
}

const app = express();

// GET /whoami — decode and echo
app.get('/whoami', (req, res) => {
  try {
    const { payload, claims } = parseFromReq(req);
    logCtx('node:/whoami', payload);
    res.json({ server: 'node-callee', ctx: payload, claims });
  } catch (e) {
    res.status(401).json({ server: 'node-callee', error: `parse failed: ${e.message || e}` });
  }
});

// GET /update — decode, mutate (+node |node), echo prev/updated
app.get('/update', (req, res) => {
  try {
    const { payload } = parseFromReq(req);
    logCtx('node:/update prev', payload);
    const updated = nodeUpdate(payload);
    res.json({ server: 'node-callee', prev_ctx: payload, updated_ctx: updated });
  } catch (e) {
    res.status(401).json({ server: 'node-callee', error: `parse failed: ${e.message || e}` });
  }
});

/** Forward helper using global fetch (Node 18+). */
async function forward(url, name, value) {
  const r = await fetch(url, { headers: { [name]: value } });
  const body = await r.text();
  return { status: r.status, body };
}

// GET /relay/go — simple whoami relay to Go
app.get('/relay/go', async (req, res) => {
  try {
    const { payload } = parseFromReq(req);
    logCtx('node:/relay/go', payload);
    const [name, value] = codec.embedHeader(payload);
    const { status, body } = await forward('http://127.0.0.1:8081/whoami', name, value);
    res.status(status).type('application/json').send(body);
  } catch (e) {
    res.status(502).json({ server: 'node-callee', error: `forward to go failed: ${e.message || e}` });
  }
});

// GET /relay/php — simple whoami relay to PHP
app.get('/relay/php', async (req, res) => {
  try {
    const { payload } = parseFromReq(req);
    logCtx('node:/relay/php', payload);
    const [name, value] = codec.embedHeader(payload);
    const { status, body } = await forward('http://127.0.0.1:8082/whoami', name, value);
    res.status(status).type('application/json').send(body);
  } catch (e) {
    res.status(502).json({ server: 'node-callee', error: `forward to php failed: ${e.message || e}` });
  }
});

// GET /relay/go/update — Chain: caller → node → go(update) → node(update) → caller
app.get('/relay/go/update', async (req, res) => {
  try {
    const { payload: original } = parseFromReq(req);
    logCtx('node:/relay/go/update original', original);
    const [name, value] = codec.embedHeader(original);
    const r = await fetch('http://127.0.0.1:8081/update', { headers: { [name]: value } });
    const goOut = await r.json();
    if (!goOut?.server) throw new Error('bad json from go');
    logCtx('node:/relay/go/update go-updated', goOut.updated_ctx);
    const nodeUpdated = nodeUpdate(goOut.updated_ctx);
    res.json({ server: 'node-callee', prev_ctx: original, go_updated_ctx: goOut.updated_ctx, node_updated_ctx: nodeUpdated });
  } catch (e) {
    res.status(502).json({ server: 'node-callee', error: `chain go/update failed: ${e.message || e}` });
  }
});

// GET /relay/php/update — Chain: caller → node → php(update) → node(update) → caller
app.get('/relay/php/update', async (req, res) => {
  try {
    const { payload: original } = parseFromReq(req);
    logCtx('node:/relay/php/update original', original);
    const [name, value] = codec.embedHeader(original);
    const r = await fetch('http://127.0.0.1:8082/update', { headers: { [name]: value } });
    const phpOut = await r.json();
    if (!phpOut?.server) throw new Error('bad json from php');
    logCtx('node:/relay/php/update php-updated', phpOut.updated_ctx);
    const nodeUpdated = nodeUpdate(phpOut.updated_ctx);
    res.json({ server: 'node-callee', prev_ctx: original, php_updated_ctx: phpOut.updated_ctx, node_updated_ctx: nodeUpdated });
  } catch (e) {
    res.status(502).json({ server: 'node-callee', error: `chain php/update failed: ${e.message || e}` });
  }
});

app.listen(8083, () => {
  console.error('node-callee listening on :8083');
});
