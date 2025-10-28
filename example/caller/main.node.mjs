// SPDX-License-Identifier: Apache-2.0
/**
 * file: ./example/caller/main.node.mjs
 *
 * NodeJS xctx “caller” program.
 *
 * What this file demonstrates
 * --------------------------
 *  1) Build a Codec and seal a typed payload into ("X-Context", "v1.<...>").
 *  2) Call the three callees (Go, PHP, Node) /whoami with that header.
 *  3) Simple relays across languages.
 *  4) Two chain flows that perform mutation in a second callee and then in the origin:
 *       - Chain A (Go→PHP→Go)
 *       - Chain B (PHP→Go→PHP)
 *       - Chain C (Go→Node→Go)
 *       - Chain D (PHP→Node→PHP)
 *
 * Build & Run
 * -----------
 *    npm install
 *    npm run build           # generate ./dist/nodejs/esm
 *    node example/caller/main.node.mjs
 */

import { resolveConfig, Codec } from '../../dist/nodejs/esm/index.js';

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

/** Simple GET with header helper. */
async function getWithHeader(url, name, value) {
  try {
    const r = await fetch(url, { headers: { [name]: value } });
    const body = await r.text();
    console.log(`\n== ${url} [${r.status}] ==\n${body}`);
    return body;
  } catch (e) {
    console.error(`GET ${url}:`, e);
    return '';
  }
}

// 1) Seal typed payload
const payload = { user_id: 7, user_name: 'arie', role: 'admin' };
const [name, value] = codec.embedHeader(payload);

// 2) Basics + simple relays
await getWithHeader('http://127.0.0.1:8081/whoami', name, value); // go
await getWithHeader('http://127.0.0.1:8082/whoami', name, value); // php
await getWithHeader('http://127.0.0.1:8083/whoami', name, value); // node
await getWithHeader('http://127.0.0.1:8081/relay/php', name, value); // go → php
await getWithHeader('http://127.0.0.1:8082/relay/go',  name, value); // php → go
await getWithHeader('http://127.0.0.1:8083/relay/go',  name, value); // node → go
await getWithHeader('http://127.0.0.1:8083/relay/php', name, value); // node → php

// 3) Chains
// Chain A: caller → go → php(update) → go(update) → caller
{
  const body = await getWithHeader('http://127.0.0.1:8081/relay/php/update', name, value);
  try {
    const out = JSON.parse(body);
    if (out?.server) {
      console.log(`\n[Chain A] prev        =`, out.prev_ctx);
      console.log(`[Chain A] php-updated =`, out.php_updated_ctx);
      console.log(`[Chain A] go-updated  =`, out.go_updated_ctx);
    }
  } catch {}
}
// Chain B: caller → php → go(update) → php → caller
{
  const body = await getWithHeader('http://127.0.0.1:8082/relay/go/update', name, value);
  try {
    const out = JSON.parse(body);
    if (out?.server) {
      console.log(`\n[Chain B] prev    =`, out.prev_ctx);
      console.log(`[Chain B] updated =`, out.updated_ctx);
    }
  } catch {}
}
// Chain C: caller → go → node(update) → go(update) → caller
{
  const body = await getWithHeader('http://127.0.0.1:8081/relay/node/update', name, value);
  try {
    const out = JSON.parse(body);
    if (out?.server) {
      console.log(`\n[Chain C] prev        =`, out.prev_ctx);
      console.log(`[Chain C] node-updated =`, out.node_updated_ctx);
      console.log(`[Chain C] go-updated   =`, out.go_updated_ctx);
    }
  } catch {}
}
// Chain D: caller → php → node(update) → php(update) → caller
{
  const body = await getWithHeader('http://127.0.0.1:8082/relay/node/update', name, value);
  try {
    const out = JSON.parse(body);
    if (out?.server) {
      console.log(`\n[Chain D] prev        =`, out.prev_ctx);
      console.log(`[Chain D] node-updated =`, out.node_updated_ctx);
      console.log(`[Chain D] php-updated  =`, out.php_updated_ctx);
    }
  } catch {}
}
