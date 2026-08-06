// A scanned QR code is fully attacker-controlled input, and DEFLATE compresses
// repetitive data ~1000:1 — so a QR small enough to print on a sticker can
// expand to hundreds of megabytes and OOM-kill the tab, taking the live session
// and its keys with it.
//
// The subtlety this file exists for: pako documents a `maxOutputLength` option,
// and pako 2.1.0 SILENTLY IGNORES IT. Passing it looks like a fix, passes review
// and does nothing. These assertions pin the behaviour we actually depend on.

import assert from 'node:assert/strict';
import pako from 'pako';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('../src/crypto/cose-qr.js', import.meta.url), 'utf8');

// ── the option we cannot rely on ─────────────────────────────────────────────
{
    const bomb = pako.deflate(new Uint8Array(8 * 1024 * 1024)); // 8 MB of zeros
    assert.ok(bomb.length < 64 * 1024, 'sanity: the bomb really is small compressed');

    const ignored = pako.inflate(bomb, { maxOutputLength: 256 * 1024 });
    // If this ever starts throwing (or truncating), pako has gained real support
    // and inflateBounded could be simplified — but only then, deliberately.
    assert.equal(ignored.length, 8 * 1024 * 1024,
        'pako still ignores maxOutputLength; the streaming guard is load-bearing');
}

// ── the QR path must not use the one-shot helper ─────────────────────────────
assert.equal(
    /pako\.inflate\(/.test(source), false,
    'the one-shot pako.inflate does not bound output and must not be used on QR input'
);
assert.ok(/new pako\.Inflate\(/.test(source), 'the streaming API is what enforces the bound');

// ── the real helper, exercised as shipped ────────────────────────────────────
const helperSource = source.slice(
    source.indexOf('const MAX_INFLATED_QR_BYTES'),
    source.indexOf('// Generate UUID for chunking')
);
const inflateBounded = new Function('pako', `${helperSource}; return inflateBounded;`)(pako);

{
    const bomb = pako.deflate(new Uint8Array(8 * 1024 * 1024));
    assert.throws(
        () => inflateBounded(bomb, 'test'),
        /expands beyond/,
        'a zip bomb must be refused'
    );
}

// A normal offer still round-trips — a bound that breaks decompression would be
// removed by the next person who hits it.
{
    const payload = JSON.stringify({ type: 'enhanced_secure_offer', sdp: 'v=0\r\n'.repeat(200) });
    const restored = inflateBounded(pako.deflate(new TextEncoder().encode(payload)), 'test');
    assert.equal(new TextDecoder().decode(restored), payload, 'a real offer must decompress intact');
}

// Right below the ceiling is fine; just above it is not.
{
    const under = new Uint8Array(200 * 1024).map((_, i) => i % 251);
    assert.equal(inflateBounded(pako.deflate(under), 'test').length, under.length);

    const over = new Uint8Array(300 * 1024).map((_, i) => i % 251);
    assert.throws(() => inflateBounded(pako.deflate(over), 'test'), /expands beyond/);
}

// Garbage input fails cleanly rather than hanging or returning junk.
{
    assert.throws(
        () => inflateBounded(new Uint8Array([1, 2, 3, 4, 5]), 'test'),
        /could not be decompressed/
    );
}

console.log('qr-zip-bomb.test.mjs: all assertions passed');
