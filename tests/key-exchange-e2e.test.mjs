// End-to-end key agreement, using the REAL key generator and the REAL
// derivation — no hand-rolled CryptoKeys.
//
// This exists because key-derivation-compat.test.mjs did not catch a bug that
// broke every connection: it generated its own key pairs with
// ['deriveKey','deriveBits'] usages, while generateECDHKeyPair() produced keys
// with only ['deriveKey']. deriveBits() then failed with an InvalidAccessError
// on the real object, and no session could be established. A test that builds
// its own inputs verifies the algorithm; only a test that uses the shipped
// factory verifies the code.

import assert from 'node:assert/strict';

globalThis.window = { document: {} };

const { EnhancedSecureCryptoUtils } = await import('../src/crypto/EnhancedSecureCryptoUtils.js');

// ── the generated key pair must carry the usages the derivation needs ────────
{
    const pair = await EnhancedSecureCryptoUtils.generateECDHKeyPair();
    assert.ok(pair.privateKey.usages.includes('deriveBits'),
        'deriveSharedKeys() calls deriveBits — the private key must permit it');
    assert.equal(pair.privateKey.extractable, false, 'the private key must stay non-extractable');
}

// ── two peers derive identical session material ──────────────────────────────
{
    const alice = await EnhancedSecureCryptoUtils.generateECDHKeyPair();
    const bob = await EnhancedSecureCryptoUtils.generateECDHKeyPair();
    const salt = EnhancedSecureCryptoUtils.generateSalt();
    assert.equal(salt.length, 64, 'the derivation requires a 64-byte salt');

    const aliceKeys = await EnhancedSecureCryptoUtils.deriveSharedKeys(alice.privateKey, bob.publicKey, salt);
    const bobKeys = await EnhancedSecureCryptoUtils.deriveSharedKeys(bob.privateKey, alice.publicKey, salt);

    // The fingerprint is what the SAS is built from: if the two sides disagree
    // here, the safety codes differ and the users cannot complete verification.
    assert.equal(aliceKeys.fingerprint, bobKeys.fingerprint,
        'both peers must derive the same key fingerprint');
    assert.match(aliceKeys.fingerprint, /^([0-9a-f]{2}:){11}[0-9a-f]{2}$/,
        'fingerprint format must stay stable (it is displayed and fed to _computeSAS)');

    for (const [name, keys] of [['alice', aliceKeys], ['bob', bobKeys]]) {
        for (const field of ['messageKey', 'macKey', 'pfsKey', 'metadataKey']) {
            assert.ok(keys[field] instanceof CryptoKey, `${name}.${field} must be a CryptoKey`);
            assert.equal(keys[field].extractable, false, `${name}.${field} must be non-extractable`);
        }
    }

    // ── and the derived keys actually interoperate ───────────────────────────
    // Matching fingerprints could in principle come from matching inputs to a
    // broken derivation; encrypting on one side and decrypting on the other is
    // the property the chat depends on.
    const encrypted = await EnhancedSecureCryptoUtils.encryptMessage(
        'hello from alice', aliceKeys.messageKey, aliceKeys.macKey, aliceKeys.metadataKey, 'msg_1', 0
    );
    const decrypted = await EnhancedSecureCryptoUtils.decryptMessage(
        encrypted, bobKeys.messageKey, bobKeys.macKey, bobKeys.metadataKey, 0
    );
    assert.equal(decrypted.message, 'hello from alice', 'bob must decrypt what alice encrypted');
    assert.equal(decrypted.messageId, 'msg_1');
}

// ── a different salt must give different keys ────────────────────────────────
// Guards against the salt being dropped from the HKDF inputs, which would make
// every session with the same peer derive the same keys.
{
    const alice = await EnhancedSecureCryptoUtils.generateECDHKeyPair();
    const bob = await EnhancedSecureCryptoUtils.generateECDHKeyPair();

    const first = await EnhancedSecureCryptoUtils.deriveSharedKeys(
        alice.privateKey, bob.publicKey, EnhancedSecureCryptoUtils.generateSalt());
    const second = await EnhancedSecureCryptoUtils.deriveSharedKeys(
        alice.privateKey, bob.publicKey, EnhancedSecureCryptoUtils.generateSalt());

    assert.notEqual(first.fingerprint, second.fingerprint,
        'a fresh salt must produce fresh session material');
}

// ── a mismatched peer key must not yield a shared secret ─────────────────────
{
    const alice = await EnhancedSecureCryptoUtils.generateECDHKeyPair();
    const bob = await EnhancedSecureCryptoUtils.generateECDHKeyPair();
    const mallory = await EnhancedSecureCryptoUtils.generateECDHKeyPair();
    const salt = EnhancedSecureCryptoUtils.generateSalt();

    const aliceWithBob = await EnhancedSecureCryptoUtils.deriveSharedKeys(alice.privateKey, bob.publicKey, salt);
    const aliceWithMallory = await EnhancedSecureCryptoUtils.deriveSharedKeys(alice.privateKey, mallory.publicKey, salt);

    assert.notEqual(aliceWithBob.fingerprint, aliceWithMallory.fingerprint,
        'a substituted public key must change the fingerprint — this is what the SAS surfaces');
}

// ── the derivation rejects malformed inputs rather than degrading ────────────
{
    const alice = await EnhancedSecureCryptoUtils.generateECDHKeyPair();
    const bob = await EnhancedSecureCryptoUtils.generateECDHKeyPair();

    await assert.rejects(
        () => EnhancedSecureCryptoUtils.deriveSharedKeys(alice.privateKey, bob.publicKey, new Array(32).fill(1)),
        /64 bytes/,
        'a short salt must be refused'
    );
    await assert.rejects(
        () => EnhancedSecureCryptoUtils.deriveSharedKeys('not-a-key', bob.publicKey, EnhancedSecureCryptoUtils.generateSalt()),
        /private key/i
    );
}

console.log('key-exchange-e2e.test.mjs: all assertions passed');
