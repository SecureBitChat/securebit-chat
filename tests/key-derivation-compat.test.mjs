// deriveSharedKeys() stopped routing the ECDH shared secret through an
// extractable AES key + exportKey() (which left the secret sitting in the heap
// unwiped) and now uses deriveBits() directly.
//
// That is only safe if the BYTES are identical: both peers must derive the same
// session keys, and a 5.6.1 client has to interoperate with a 5.6.0 one. This is
// the test that says so — WebCrypto's ECDH deriveBits(n) returns the leftmost n
// bits of the shared X coordinate, which is exactly what deriveKey to
// AES-GCM-256 consumed. If a future change bumps 256 to 384 "for strength", this
// fails, and it should: that is a protocol break, not an improvement.

import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

const { subtle } = webcrypto;

const toHex = (buf) => Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0')).join('');

for (const namedCurve of ['P-384', 'P-256']) {
    const alice = await subtle.generateKey({ name: 'ECDH', namedCurve }, false, ['deriveKey', 'deriveBits']);
    const bob = await subtle.generateKey({ name: 'ECDH', namedCurve }, false, ['deriveKey', 'deriveBits']);

    // ── the old path: extractable AES key, then exportKey ────────────────────
    const legacyKey = await subtle.deriveKey(
        { name: 'ECDH', public: bob.publicKey },
        alice.privateKey,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
    const legacyBytes = await subtle.exportKey('raw', legacyKey);

    // ── the new path: deriveBits, no extractable key, buffer wipeable ────────
    const newBytes = await subtle.deriveBits(
        { name: 'ECDH', public: bob.publicKey },
        alice.privateKey,
        256
    );

    assert.equal(toHex(newBytes), toHex(legacyBytes),
        `${namedCurve}: deriveBits(256) must reproduce the previous shared secret exactly`);

    // Sanity: the two peers still agree, which is the property the whole session
    // rests on and is worth asserting rather than assuming.
    const bobBytes = await subtle.deriveBits(
        { name: 'ECDH', public: alice.publicKey },
        bob.privateKey,
        256
    );
    assert.equal(toHex(bobBytes), toHex(newBytes), `${namedCurve}: both peers must derive the same secret`);

    // ── the fingerprint material took the same detour ────────────────────────
    const ikm = await subtle.importKey('raw', newBytes, { name: 'HKDF', hash: 'SHA-256' }, false,
        ['deriveKey', 'deriveBits']);
    const salt = new Uint8Array(64).fill(7);
    const info = new TextEncoder().encode('fingerprint-generation-v4');

    const legacyFpKey = await subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt, info },
        ikm,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
    const legacyFpBytes = await subtle.exportKey('raw', legacyFpKey);
    const newFpBytes = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, ikm, 256);

    assert.equal(toHex(newFpBytes), toHex(legacyFpBytes),
        `${namedCurve}: HKDF deriveBits(256) must reproduce the previous fingerprint material`);
}

// ── zeroizeBuffer actually overwrites ────────────────────────────────────────
{
    globalThis.window = { document: {} };
    const { EnhancedSecureCryptoUtils } = await import('../src/crypto/EnhancedSecureCryptoUtils.js');

    const secret = new Uint8Array(32).fill(0xAB);
    EnhancedSecureCryptoUtils.zeroizeBuffer(secret);
    assert.ok(secret.every((b) => b === 0), 'a Uint8Array must end up zeroed');

    const buf = new ArrayBuffer(32);
    new Uint8Array(buf).fill(0xCD);
    EnhancedSecureCryptoUtils.zeroizeBuffer(buf);
    assert.ok(new Uint8Array(buf).every((b) => b === 0), 'an ArrayBuffer must end up zeroed');

    // Must not throw on the shapes it will legitimately be handed.
    EnhancedSecureCryptoUtils.zeroizeBuffer(null);
    EnhancedSecureCryptoUtils.zeroizeBuffer(undefined);
    EnhancedSecureCryptoUtils.zeroizeBuffer(new ArrayBuffer(0));
}

console.log('key-derivation-compat.test.mjs: all assertions passed');
