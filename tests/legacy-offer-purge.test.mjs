// The reference-QR flow used to persist whole session offers — SDP with every
// ICE candidate, both public keys, the session salt and the SAS code — under
// `qr_offer_<id>`, and nothing ever deleted them. Removing the writer stops the
// bleeding; these assertions cover the other half, that an upgrade also clears
// what earlier versions already wrote to disk.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const bootSource = readFileSync(new URL('../src/scripts/app-boot.js', import.meta.url), 'utf8');
const appSource = readFileSync(new URL('../src/app.jsx', import.meta.url), 'utf8');

// ── nothing writes offer payloads to localStorage any more ───────────────────
assert.equal(
    /localStorage\.setItem\(\s*[`'"]qr_offer_/.test(appSource),
    false,
    'no code may persist a session offer to localStorage'
);
// Match a definition, not the identifier: the explanatory note left in its place
// names the removed function on purpose, and that note is worth keeping.
assert.equal(
    /(const|let|var|function)\s+createQRReference\b/.test(appSource),
    false,
    'the reference-QR writer must stay removed'
);

// ── and the purge runs at startup ────────────────────────────────────────────
assert.ok(bootSource.includes('purgeLegacyOfferRecords'), 'startup must purge legacy records');

// Exercise the real behaviour against a localStorage stand-in.
const store = new Map([
    ['qr_offer_offer_1700000000000_abc123', '{"sdp":"v=0...","salt":[1,2,3]}'],
    ['qr_offer_offer_1700000000001_def456', '{"sdp":"v=0..."}'],
    ['securebit_my_status', 'available'],
    ['securebit_relay_only_mode', 'true'],
    ['app_version', '5.6.1']
]);

globalThis.localStorage = {
    get length() { return store.size; },
    key: (i) => Array.from(store.keys())[i] ?? null,
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => { store.set(k, String(v)); },
    removeItem: (k) => { store.delete(k); }
};

// Extract and run the purge exactly as shipped, rather than reimplementing it —
// a copy in the test would keep passing after the real one drifted.
const fnSource = bootSource.slice(
    bootSource.indexOf('const purgeLegacyOfferRecords'),
    bootSource.indexOf('// Mount application once DOM and modules are ready')
);
const purge = new Function(`${fnSource}; return purgeLegacyOfferRecords;`)();

purge();

assert.deepEqual(
    Array.from(store.keys()).filter((k) => k.startsWith('qr_offer_')),
    [],
    'every legacy offer record must be removed'
);
// Deleting while iterating by index is easy to get wrong — it shifts the
// remaining entries and silently skips every other key. Assert survivors too.
assert.equal(store.get('securebit_my_status'), 'available', 'user settings must survive');
assert.equal(store.get('securebit_relay_only_mode'), 'true', 'user settings must survive');
assert.equal(store.get('app_version'), '5.6.1', 'version tracking must survive');

console.log('legacy-offer-purge.test.mjs: all assertions passed');
