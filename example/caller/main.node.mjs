// SPDX-License-Identifier: Apache-2.0
/**
 * xctx example — Node.js Caller
 * Now targets 4 callees:
 *   - Go    :8081
 *   - PHP   :8082
 *   - Node  :8083 (native http)
 *   - NodeE :8084 (Express)
 */

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

function logBlock(title, status, body) {
    console.log(`\n== ${title} [${status}] ==`);
    console.log(typeof body === 'string' ? body : JSON.stringify(body, null, 2));
}

async function call(url, payload) {
    const [name, value] = codec.embedHeader(payload);
    const r = await fetch(url, { headers: { [name]: value } });
    let body;
    const text = await r.text();
    try { body = JSON.parse(text); } catch { body = text; }
    return { status: r.status, body };
}

async function main() {
    /** @type {PassingContext} */
    const ctx = { user_id: 7, user_name: 'arie', role: 'admin' };

    const GO    = 'http://127.0.0.1:8081';
    const PHP   = 'http://127.0.0.1:8082';
    const NODE  = 'http://127.0.0.1:8083';
    const NODEE = 'http://127.0.0.1:8084';

    // whoami/update on all four callees
    for (const [name, base] of [['go', GO], ['php', PHP], ['node', NODE], ['node-express', NODEE]]) {
        let r = await call(`${base}/whoami`, ctx);
        logBlock(`${name} /whoami`, r.status, r.body);
        r = await call(`${base}/update`, ctx);
        logBlock(`${name} /update`, r.status, r.body);
    }

    // Existing chains via node(:8083)
    let r = await call(`${NODE}/relay/go`, ctx);
    logBlock(`node → go /whoami`, r.status, r.body);
    r = await call(`${NODE}/relay/go/update`, ctx);
    logBlock(`node → go /update`, r.status, r.body);

    r = await call(`${NODE}/relay/php`, ctx);
    logBlock(`node → php /whoami`, r.status, r.body);
    r = await call(`${NODE}/relay/php/update`, ctx);
    logBlock(`node → php /update`, r.status, r.body);

    // NEW: chains via node(:8083) → node-express(:8084)
    r = await call(`${NODE}/relay/node-express`, ctx);
    logBlock(`node → node-express /whoami`, r.status, r.body);
    r = await call(`${NODE}/relay/node-express/update`, ctx);
    logBlock(`node → node-express /update`, r.status, r.body);
}

main().catch((err) => {
    console.error('[caller] fatal:', err);
    process.exitCode = 1;
});
