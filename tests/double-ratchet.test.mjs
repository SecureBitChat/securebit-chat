// Double Ratchet correctness and its security properties.
//
// The point of the ratchet is that a key recovered at time T must not open
// anything sent before T, and that one exchange in each direction must lock out
// an attacker who captured the whole state. Both are asserted here directly,
// not inferred from the code shape.

import assert from 'node:assert/strict';

globalThis.window = { document: {} };

const { DoubleRatchet, RATCHET_LIMITS } = await import('../src/crypto/DoubleRatchet.js');

const subtle = crypto.subtle;

/**
 * The peer's key must arrive the way production delivers it: through
 * importSignedPublicKey, which imports SPKI as NON-EXTRACTABLE. A generated
 * public key is always extractable regardless of the flag, so a test that passes
 * `keyPair.publicKey` straight through exercises a key shape that never occurs
 * in the app — and misses anything that tries to export it. That is exactly how
 * a ratchet-setup failure on the initiator reached production.
 */
async function asReceivedFromPeer(publicKey) {
    const spki = await subtle.exportKey('spki', publicKey);
    const imported = await subtle.importKey('spki', spki, { name: 'ECDH', namedCurve: 'P-384' }, false, []);
    assert.equal(imported.extractable, false, 'the stand-in must be non-extractable, like the real one');
    return imported;
}

async function makePair() {
    const alice = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, false, ['deriveKey', 'deriveBits']);
    const bob = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, false, ['deriveKey', 'deriveBits']);

    const shared = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: bob.publicKey }, alice.privateKey, 256));
    const sessionSalt = crypto.getRandomValues(new Uint8Array(64));

    const a = new DoubleRatchet();
    const b = new DoubleRatchet();
    await a.init({
        sharedSecret: shared.slice(), sessionSalt, selfPrivateKey: alice.privateKey,
        remotePublicKey: await asReceivedFromPeer(bob.publicKey), isInitiator: true
    });
    await b.init({
        sharedSecret: shared.slice(), sessionSalt, selfPrivateKey: bob.privateKey,
        remotePublicKey: await asReceivedFromPeer(alice.publicKey), isInitiator: false
    });
    return { a, b };
}

const send = async (from, to, text) => {
    const { header, ciphertext } = await from.encrypt(text);
    return { header, ciphertext, open: () => to.decrypt(header, ciphertext) };
};

// ── the basic round trip, in both directions ─────────────────────────────────
{
    const { a, b } = await makePair();

    // The responder cannot speak first: it has no sending chain until the
    // initiator's first message arrives. This is by design, not a bug.
    await assert.rejects(() => b.encrypt('too early'), /no sending chain/);

    const m1 = await send(a, b, 'hello bob');
    assert.equal(await m1.open(), 'hello bob');

    // Now Bob can reply, and doing so introduces his own ratchet key.
    const m2 = await send(b, a, 'hello alice');
    assert.equal(await m2.open(), 'hello alice');

    const m3 = await send(a, b, 'how are you');
    assert.equal(await m3.open(), 'how are you');
}

// ── every message uses a different key ───────────────────────────────────────
// Identical plaintexts must not produce identical ciphertexts; if they did, the
// chain would not be advancing at all.
{
    const { a, b } = await makePair();
    const seen = new Set();
    for (let i = 0; i < 20; i++) {
        const { header, ciphertext } = await a.encrypt('same text every time');
        assert.equal(seen.has(ciphertext), false, `ciphertext repeated at message ${i}`);
        seen.add(ciphertext);
        assert.equal(await b.decrypt(header, ciphertext), 'same text every time');
    }
}

// ── FORWARD SECRECY: the current state cannot open earlier messages ──────────
// This is the property the audit found missing. Capture a ciphertext, let the
// conversation move on, then hand the receiver's live state the old frame: it
// must fail, because the key that opened it was destroyed on use.
{
    const { a, b } = await makePair();

    const early = await a.encrypt('the secret from the start of the session');
    assert.equal(await b.decrypt(early.header, early.ciphertext), 'the secret from the start of the session');

    for (let i = 0; i < 10; i++) {
        const m = await a.encrypt(`later message ${i}`);
        await b.decrypt(m.header, m.ciphertext);
    }

    await assert.rejects(
        () => b.decrypt(early.header, early.ciphertext),
        /behind the current chain|authentication failed/,
        'a compromised current state must not reopen an earlier message'
    );
}

// ── replay is refused ────────────────────────────────────────────────────────
{
    const { a, b } = await makePair();
    const m = await a.encrypt('deliver once');
    assert.equal(await b.decrypt(m.header, m.ciphertext), 'deliver once');
    await assert.rejects(() => b.decrypt(m.header, m.ciphertext), /behind the current chain/);
}

// ── POST-COMPROMISE SECURITY: the DH ratchet re-keys the root ────────────────
// After a full exchange in each direction the sending chain must derive from a
// DH secret the attacker never saw. Observable proxy: the ratchet public key in
// the header changes when the direction turns.
{
    const { a, b } = await makePair();

    const first = await a.encrypt('one');
    await b.decrypt(first.header, first.ciphertext);
    const aliceKey1 = JSON.parse(first.header).dh;

    const reply = await b.encrypt('two');
    await a.decrypt(reply.header, reply.ciphertext);
    const bobKey1 = JSON.parse(reply.header).dh;
    assert.notEqual(bobKey1, aliceKey1, 'each side contributes its own ratchet key');

    const third = await a.encrypt('three');
    await b.decrypt(third.header, third.ciphertext);
    const aliceKey2 = JSON.parse(third.header).dh;
    assert.notEqual(aliceKey2, aliceKey1,
        'replying must adopt a fresh ratchet key — this is what recovers from compromise');

    // Message numbering restarts per chain, and the previous length is carried.
    assert.equal(JSON.parse(third.header).n, 0);
    assert.equal(JSON.parse(third.header).pn, 1);
}

// ── out-of-order delivery inside a chain ─────────────────────────────────────
{
    const { a, b } = await makePair();
    const frames = [];
    for (let i = 0; i < 5; i++) frames.push(await a.encrypt(`m${i}`));

    // Arrive 4, 0, 2, 1, 3.
    assert.equal(await b.decrypt(frames[4].header, frames[4].ciphertext), 'm4');
    assert.equal(await b.decrypt(frames[0].header, frames[0].ciphertext), 'm0');
    assert.equal(await b.decrypt(frames[2].header, frames[2].ciphertext), 'm2');
    assert.equal(await b.decrypt(frames[1].header, frames[1].ciphertext), 'm1');
    assert.equal(await b.decrypt(frames[3].header, frames[3].ciphertext), 'm3');
    assert.equal(b.getState().skippedKeys, 0, 'every retained key must be consumed');
}

// ── out-of-order ACROSS a ratchet step ───────────────────────────────────────
// A message from the previous chain arriving after the direction changed is the
// case that breaks naive implementations.
{
    const { a, b } = await makePair();

    const straggler = await a.encrypt('sent before the turn');
    const delivered = await a.encrypt('delivered first');
    await b.decrypt(delivered.header, delivered.ciphertext);

    const reply = await b.encrypt('bob replies');
    await a.decrypt(reply.header, reply.ciphertext);
    const after = await a.encrypt('new chain');
    await b.decrypt(after.header, after.ciphertext);

    assert.equal(await b.decrypt(straggler.header, straggler.ciphertext), 'sent before the turn',
        'a message from the previous chain must still open after a ratchet step');
}

// ── DoS: an attacker cannot make us retain unbounded keys ────────────────────
{
    const { a, b } = await makePair();
    const m = await a.encrypt('probe');
    const header = JSON.parse(m.header);

    // A single frame claiming a huge message number would otherwise force us to
    // derive and hold that many keys.
    const absurd = JSON.stringify({ ...header, n: 5_000_000 });
    await assert.rejects(
        () => b.decrypt(absurd, m.ciphertext),
        /refusing to skip/,
        'a large forward jump must be refused, not honoured'
    );

    // Just past the limit is still refused; the limit itself is workable.
    const overLimit = JSON.stringify({ ...header, n: RATCHET_LIMITS.MAX_SKIP_PER_CHAIN + 1 });
    await assert.rejects(() => b.decrypt(overLimit, m.ciphertext), /refusing to skip/);

    assert.equal(b.getState().skippedKeys, 0, 'a refused frame must leave no keys behind');
}

// ── the retained-key cache is bounded ────────────────────────────────────────
{
    const { a, b } = await makePair();
    const frames = [];
    const gap = 200;
    for (let round = 0; round < 8; round++) {
        for (let i = 0; i < gap; i++) frames.push(await a.encrypt(`x${round}-${i}`));
        const marker = await a.encrypt(`marker-${round}`);
        await b.decrypt(marker.header, marker.ciphertext);
    }
    assert.ok(b.getState().skippedKeys <= RATCHET_LIMITS.MAX_SKIPPED_KEYS,
        `retained keys (${b.getState().skippedKeys}) must stay within the cap`);
}

// ── a tampered header is rejected AND leaves the ratchet intact ──────────────
// The header is plaintext on the wire, so this is reachable. The session must
// survive it: a bad frame that desynchronised the chains would be a remote
// denial of service against an established chat.
{
    const { a, b } = await makePair();
    const m = await a.encrypt('authentic');
    const forged = JSON.stringify({ ...JSON.parse(m.header), pn: 99 });

    await assert.rejects(() => b.decrypt(forged, m.ciphertext), /authentication failed/);

    // The genuine frame must still open afterwards.
    assert.equal(await b.decrypt(m.header, m.ciphertext), 'authentic');

    // And the conversation continues normally.
    const next = await a.encrypt('still working');
    assert.equal(await b.decrypt(next.header, next.ciphertext), 'still working');
}

// ── a tampered body is rejected, likewise without side effects ───────────────
{
    const { a, b } = await makePair();
    const m = await a.encrypt('authentic body');
    const flipped = Buffer.from(m.ciphertext, 'base64');
    flipped[flipped.length - 1] ^= 0xff;

    await assert.rejects(
        () => b.decrypt(m.header, flipped.toString('base64')),
        /authentication failed/
    );
    assert.equal(await b.decrypt(m.header, m.ciphertext), 'authentic body',
        'the genuine frame must still open after a forged one');
}

// ── two independent sessions never share ratchet state ───────────────────────
{
    const one = await makePair();
    const two = await makePair();
    const m = await one.a.encrypt('for session one');
    await assert.rejects(
        () => two.b.decrypt(m.header, m.ciphertext),
        /authentication failed|behind the current chain|no receiving chain/
    );
}

// ── destroy() clears the state ───────────────────────────────────────────────
{
    const { a, b } = await makePair();
    const m = await a.encrypt('before destroy');
    await b.decrypt(m.header, m.ciphertext);

    b.destroy();
    assert.equal(b.getState().initialised, false);
    assert.equal(b.getState().skippedKeys, 0);
    const after = await a.encrypt('after destroy');
    await assert.rejects(() => b.decrypt(after.header, after.ciphertext), /not initialised/);
}

// ── a long conversation stays in sync ────────────────────────────────────────
// Ratchet bugs love to appear at chain boundaries rather than on message two.
{
    const { a, b } = await makePair();
    let expected = 0;
    for (let turn = 0; turn < 30; turn++) {
        const from = turn % 2 === 0 ? a : b;
        const to = turn % 2 === 0 ? b : a;
        const burst = 1 + (turn % 4);
        for (let i = 0; i < burst; i++) {
            const text = `turn ${turn} message ${i}`;
            const { header, ciphertext } = await from.encrypt(text);
            assert.equal(await to.decrypt(header, ciphertext), text);
            expected += 1;
        }
    }
    assert.ok(expected > 60, 'the exchange should have covered many chain switches');
}

console.log('double-ratchet.test.mjs: all assertions passed');
