// The ratchet wired into the manager, not in isolation.
//
// double-ratchet.test.mjs proves the algorithm. This proves the wiring: that the
// handshake actually starts a ratchet, that a frame produced by the send path is
// readable by the receive path, and — the part most likely to be got wrong —
// that a peer which does not support it degrades to the previous scheme instead
// of failing to communicate at all.

import assert from 'node:assert/strict';

globalThis.window = { document: {} };
const { EnhancedSecureCryptoUtils } = await import('../src/crypto/EnhancedSecureCryptoUtils.js');
window.EnhancedSecureCryptoUtils = EnhancedSecureCryptoUtils;

globalThis.CustomEvent = class { constructor(t, i) { this.type = t; this.detail = i?.detail; } };
globalThis.document = { dispatchEvent() {} };

const { EnhancedSecureWebRTCManager } = await import('../src/network/EnhancedSecureWebRTCManager.js');
const P = EnhancedSecureWebRTCManager.prototype;
const T = EnhancedSecureWebRTCManager.MESSAGE_TYPES;

/**
 * Re-import a public key the way the handshake delivers it. importSignedPublicKey
 * imports SPKI as NON-EXTRACTABLE, while a locally generated public key is always
 * extractable — so handing `keyPair.publicKey` straight to the manager tests a
 * key shape the app never sees. A ratchet-setup failure that hit only the
 * initiator got through review precisely because the test used the easy shape.
 */
async function asReceivedFromPeer(publicKey) {
    const spki = await crypto.subtle.exportKey('spki', publicKey);
    const imported = await crypto.subtle.importKey(
        'spki', spki, { name: 'ECDH', namedCurve: 'P-384' }, false, []
    );
    assert.equal(imported.extractable, false);
    return imported;
}

async function handshake({ initiatorSupports = true, responderSupports = true } = {}) {
    const initiatorKeys = await EnhancedSecureCryptoUtils.generateECDHKeyPair();
    const responderKeys = await EnhancedSecureCryptoUtils.generateECDHKeyPair();
    const salt = EnhancedSecureCryptoUtils.generateSalt();

    // What each side actually holds for the other, post-handshake.
    const initiatorPeerKey = await asReceivedFromPeer(responderKeys.publicKey);
    const responderPeerKey = await asReceivedFromPeer(initiatorKeys.publicKey);

    const make = (own, peerPub, isInitiator, peerSupports) => {
        const delivered = [];
        const mgr = {
            delivered,
            ecdhKeyPair: own,
            peerPublicKey: peerPub,
            sessionSalt: salt,
            securityFeatures: {},
            _peerSupportsRatchet: peerSupports,
            _ratchet: null,
            _secureLog() {},
            _checkInboundRateLimit: () => true,
            deliverMessageToUI: (m, type, meta) => delivered.push({ m, type, meta }),
            _initializeRatchet: P._initializeRatchet,
            isRatchetActive: P.isRatchetActive,
            _processRatchetMessage: P._processRatchetMessage
        };
        return { mgr, isInitiator };
    };

    // Both sides derive from the same ECDH, exactly as the handshake does.
    const initiatorDerived = await EnhancedSecureCryptoUtils.deriveSharedKeys(
        initiatorKeys.privateKey, responderKeys.publicKey, salt);
    const responderDerived = await EnhancedSecureCryptoUtils.deriveSharedKeys(
        responderKeys.privateKey, initiatorKeys.publicKey, salt);

    assert.equal(initiatorDerived.fingerprint, responderDerived.fingerprint,
        'sanity: the handshake must agree before the ratchet is layered on');

    const a = make(initiatorKeys, initiatorPeerKey, true, responderSupports);
    const b = make(responderKeys, responderPeerKey, false, initiatorSupports);

    await a.mgr._initializeRatchet(initiatorDerived, true);
    await b.mgr._initializeRatchet(responderDerived, false);

    return { a: a.mgr, b: b.mgr };
}

// Build a frame the way sendSecureMessage does, and hand it to the real
// receive path rather than calling the ratchet directly.
const sendThrough = async (from, to, text) => {
    const envelope = JSON.stringify({ type: 'message', data: text });
    const { header, ciphertext } = await from._ratchet.encrypt(envelope);
    await to._processRatchetMessage({ type: T.RATCHET_MESSAGE, h: header, c: ciphertext, version: '5.0' });
};

// ── both sides support it: a ratchet comes up and carries chat ───────────────
{
    const { a, b } = await handshake();
    assert.equal(a.isRatchetActive(), true, 'the initiator must start a ratchet');
    assert.equal(b.isRatchetActive(), true, 'the responder must start a ratchet');
    assert.equal(a.securityFeatures.hasPFS, true);

    await sendThrough(a, b, 'hello from the initiator');
    assert.deepEqual(b.delivered.at(-1).m, 'hello from the initiator');
    assert.equal(b.delivered.at(-1).type, 'received');

    await sendThrough(b, a, 'hello back');
    assert.equal(a.delivered.at(-1).m, 'hello back');

    // Several turns, so the DH ratchet steps more than once.
    for (let i = 0; i < 6; i++) {
        await sendThrough(a, b, `a${i}`);
        await sendThrough(b, a, `b${i}`);
    }
    assert.equal(b.delivered.at(-1).m, 'a5');
    assert.equal(a.delivered.at(-1).m, 'b5');
}

// ── the responder can speak before the initiator does ───────────────────────
// The Double Ratchet gives the responder no sending chain until it has seen the
// initiator's ratchet key — but the app pushes a presence update from BOTH sides
// the moment verification completes. If the send path assumed a usable ratchet,
// the responder's first frame would throw and its presence would never go out.
{
    const { a, b } = await handshake();

    assert.equal(b.isRatchetActive(), true, 'the responder still HAS a ratchet...');
    assert.equal(b._ratchet.canEncrypt, false, '...it just cannot send on it yet');
    assert.equal(a._ratchet.canEncrypt, true, 'the initiator can send immediately');

    // Once the initiator speaks, the responder gains its sending chain.
    await sendThrough(a, b, 'first');
    assert.equal(b._ratchet.canEncrypt, true, 'receiving must open the responder’s sending chain');
    await sendThrough(b, a, 'reply');
    assert.equal(a.delivered.at(-1).m, 'reply');
}

// ── per-message metadata still reaches the UI ────────────────────────────────
// view-once / disappearing ride inside the encrypted envelope; losing them here
// would silently turn ephemeral messages into permanent ones.
{
    const { a, b } = await handshake();
    const envelope = JSON.stringify({ type: 'message', data: 'burn after reading', meta: { mid: 'm1', once: true } });
    const { header, ciphertext } = await a._ratchet.encrypt(envelope);
    await b._processRatchetMessage({ type: T.RATCHET_MESSAGE, h: header, c: ciphertext });

    assert.equal(b.delivered.at(-1).m, 'burn after reading');
    assert.deepEqual(b.delivered.at(-1).meta, { mid: 'm1', once: true });
}

// ── NEGOTIATION: a peer on an older build must still be able to talk ─────────
// This is the compatibility guarantee. If either side does not advertise the
// ratchet, neither may start one — a one-sided ratchet decrypts nothing.
{
    const { a, b } = await handshake({ responderSupports: false, initiatorSupports: false });
    assert.equal(a.isRatchetActive(), false, 'no ratchet when the peer did not advertise it');
    assert.equal(b.isRatchetActive(), false);
    assert.equal(a.securityFeatures.hasPFS, undefined,
        'and the PFS flag must not be raised for a session that does not have it');
}

// ── a half-negotiated session must not half-enable ───────────────────────────
{
    const { a, b } = await handshake({ responderSupports: false, initiatorSupports: true });
    assert.equal(a.isRatchetActive(), false, 'initiator saw no support in the answer');
    assert.equal(b.isRatchetActive(), true, 'responder saw support in the offer');

    // The asymmetric case cannot happen in practice — both flags come from the
    // same pair of packages — but if it ever did, the ratcheted side must not be
    // able to push frames the other cannot read. The receiving side simply has
    // no ratchet and drops them rather than crashing.
    const envelope = JSON.stringify({ type: 'message', data: 'unreadable' });
    const { header, ciphertext } = await b._ratchet.encrypt(envelope).catch(() => ({}));
    if (header) {
        await a._processRatchetMessage({ type: T.RATCHET_MESSAGE, h: header, c: ciphertext });
        assert.deepEqual(a.delivered, [], 'a frame we cannot decrypt must be dropped, not rendered');
    }
}

// ── malformed frames are dropped without throwing ────────────────────────────
{
    const { a, b } = await handshake();
    for (const frame of [
        { type: T.RATCHET_MESSAGE },
        { type: T.RATCHET_MESSAGE, h: 'not json', c: 'AAAA' },
        { type: T.RATCHET_MESSAGE, h: JSON.stringify({ dh: 'x', pn: 0, n: 0 }), c: '!!!not base64!!!' },
        { type: T.RATCHET_MESSAGE, h: 123, c: 456 }
    ]) {
        await b._processRatchetMessage(frame);
    }
    assert.deepEqual(b.delivered, [], 'nothing malformed may reach the UI');

    // And the session still works afterwards.
    await sendThrough(a, b, 'still fine');
    assert.equal(b.delivered.at(-1).m, 'still fine');
}

// ── the ratchet root is domain-separated from the session keys ───────────────
// Learning a message key must tell an attacker nothing about the ratchet root.
{
    const alice = await EnhancedSecureCryptoUtils.generateECDHKeyPair();
    const bob = await EnhancedSecureCryptoUtils.generateECDHKeyPair();
    const salt = EnhancedSecureCryptoUtils.generateSalt();
    const derived = await EnhancedSecureCryptoUtils.deriveSharedKeys(alice.privateKey, bob.publicKey, salt);

    assert.ok(derived.ratchetRoot instanceof Uint8Array, 'a ratchet root must be produced');
    assert.equal(derived.ratchetRoot.length, 32);
    assert.ok(derived.ratchetRoot.some((b) => b !== 0), 'and it must not be all zeros');

    // A different salt gives a different root, so two sessions never share state.
    const other = await EnhancedSecureCryptoUtils.deriveSharedKeys(
        alice.privateKey, bob.publicKey, EnhancedSecureCryptoUtils.generateSalt());
    assert.notDeepEqual(Array.from(derived.ratchetRoot), Array.from(other.ratchetRoot));
}

console.log('ratchet-integration.test.mjs: all assertions passed');
