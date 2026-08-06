// SBQ2 in-band key exchange: the commitment gate, transcript coverage, and the
// identity proof that replaced authProof.
//
// The property under test throughout is that the descriptor the user carried by
// hand is what pins the key material: substituting the blob must fail before the
// blob is parsed, and anything that changes anywhere in the handshake must move
// the SAS digits the two people read to each other.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const {
    parseSdp, pruneCandidates, encodeDescriptor, decodeDescriptor,
    bindingTag, commitBlob, TYPE, LIMITS,
} = await import('../src/network/descriptor/sbq2.js');
const {
    ROLE, KEY_BLOB_VERSION, BLOB_LIMITS,
    encodeKeyBlob, decodeKeyBlob, buildTranscript, deriveTranscriptSalt,
    proofPayload, computeTranscriptSas, verifyBlobCommitment, KeyExchangeError,
} = await import('../src/network/descriptor/keyexchange.js');

const subtle = crypto.subtle;
const chrome = JSON.parse(readFileSync(new URL('./fixtures/sdp-chrome.json', import.meta.url)));
const digest = async (b) => new Uint8Array(await subtle.digest('SHA-256', b));

const rejects = (fn, match, label) => assert.throws(fn, (e) => {
    assert.ok(e instanceof KeyExchangeError, `${label}: wrong error type ${e.name}`);
    assert.match(e.message, match, `${label}: unexpected message "${e.message}"`);
    return true;
}, label);

const rejectsAsync = async (fn, match, label) => {
    await assert.rejects(fn, (e) => {
        assert.ok(e instanceof KeyExchangeError, `${label}: wrong error type ${e.name}`);
        assert.match(e.message, match, `${label}: unexpected message "${e.message}"`);
        return true;
    }, label);
};

async function makePeer(role) {
    const ecdh = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveKey', 'deriveBits']);
    const ecdsa = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify']);
    const blob = encodeKeyBlob({
        role,
        ecdhSpki: new Uint8Array(await subtle.exportKey('spki', ecdh.publicKey)),
        ecdsaSpki: new Uint8Array(await subtle.exportKey('spki', ecdsa.publicKey)),
    });
    return { ecdh, ecdsa, blob, commitment: await commitBlob(digest, blob) };
}

async function makeDescriptor(sdp, type, commitment, tag) {
    const raw = parseSdp(sdp);
    return encodeDescriptor({
        type, expiresAtMs: Date.now() + 600000,
        sdpFields: { ...raw, candidates: pruneCandidates(raw.candidates) },
        commitment,
        ...(type === TYPE.ANSWER ? { bindingTag: tag } : {}),
    });
}

/** A full two-sided handshake, as the manager runs it. */
async function handshake() {
    const A = await makePeer(ROLE.OFFER);
    const B = await makePeer(ROLE.ANSWER);
    const offerDescriptor = await makeDescriptor(chrome.turn_all.offer, TYPE.OFFER, A.commitment);
    const answerDescriptor = await makeDescriptor(
        chrome.turn_all.answer, TYPE.ANSWER, B.commitment, await bindingTag(digest, offerDescriptor));
    const transcript = buildTranscript({
        offerDescriptor, answerDescriptor, offerBlob: A.blob, answerBlob: B.blob,
    });
    return { A, B, offerDescriptor, answerDescriptor, transcript };
}

// ---------------------------------------------------------------------------
// key blob encoding
// ---------------------------------------------------------------------------
{
    const A = await makePeer(ROLE.OFFER);
    const decoded = decodeKeyBlob(A.blob);
    assert.equal(decoded.version, KEY_BLOB_VERSION);
    assert.equal(decoded.role, ROLE.OFFER);
    // Both keys must survive to a usable CryptoKey — a blob that decodes but
    // cannot be imported is no better than one that fails outright.
    await subtle.importKey('spki', decoded.ecdhSpki, { name: 'ECDH', namedCurve: 'P-384' }, false, []);
    await subtle.importKey('spki', decoded.ecdsaSpki, { name: 'ECDSA', namedCurve: 'P-384' }, false, ['verify']);

    rejects(() => decodeKeyBlob(new Uint8Array(0)), /empty/, 'empty blob');
    rejects(() => decodeKeyBlob(A.blob.subarray(0, A.blob.length - 1)), /truncated/, 'truncated blob');

    for (const v of [0x00, 0x01, 0x03, 0xff]) {
        const x = Uint8Array.from(A.blob); x[0] = v;
        rejects(() => decodeKeyBlob(x), /unsupported key blob version/, `blob version 0x${v.toString(16)}`);
    }

    const badRole = Uint8Array.from(A.blob); badRole[1] = 2;
    rejects(() => decodeKeyBlob(badRole), /reserved key blob role/, 'reserved role');

    const trailing = new Uint8Array(A.blob.length + 2);
    trailing.set(A.blob); trailing.set([9, 9], A.blob.length);
    rejects(() => decodeKeyBlob(trailing), /trailing byte/, 'trailing bytes');

    const huge = Uint8Array.from(A.blob); huge[2] = 0xff; huge[3] = 0xff;
    rejects(() => decodeKeyBlob(huge), /SPKI length out of range/, 'absurd SPKI length');

    rejects(() => decodeKeyBlob(new Uint8Array(BLOB_LIMITS.MAX_BLOB_BYTES + 1)), /size limit/, 'oversized blob');
    rejects(() => encodeKeyBlob({ role: 7, ecdhSpki: new Uint8Array(60), ecdsaSpki: new Uint8Array(60) }),
        /invalid role/, 'encode with a bad role');
    rejects(() => encodeKeyBlob({ role: ROLE.OFFER, ecdhSpki: new Uint8Array(4), ecdsaSpki: new Uint8Array(60) }),
        /ecdh SPKI length out of range/, 'encode with a stub key');
}

// ---------------------------------------------------------------------------
// the commitment gate
// ---------------------------------------------------------------------------
{
    const { A, B, offerDescriptor, answerDescriptor } = await handshake();

    // The honest case: each side's descriptor commits to its own blob.
    await verifyBlobCommitment(subtle, A.blob, decodeDescriptor(offerDescriptor).commitment);
    await verifyBlobCommitment(subtle, B.blob, decodeDescriptor(answerDescriptor).commitment);

    // Substitution: an attacker who can rewrite the in-band blob but not the
    // scanned descriptor is caught before the blob is ever parsed.
    const M = await makePeer(ROLE.ANSWER);
    await rejectsAsync(
        () => verifyBlobCommitment(subtle, M.blob, decodeDescriptor(answerDescriptor).commitment),
        /does not match the commitment/, 'substituted blob');

    // A single flipped bit anywhere in the blob is enough.
    for (const idx of [0, 1, 5, 40, A.blob.length - 1]) {
        const tampered = Uint8Array.from(A.blob); tampered[idx] ^= 0x01;
        await rejectsAsync(
            () => verifyBlobCommitment(subtle, tampered, decodeDescriptor(offerDescriptor).commitment),
            /does not match the commitment/, `blob byte ${idx} flipped`);
    }

    // Swapping the two peers' blobs is also a mismatch.
    await rejectsAsync(
        () => verifyBlobCommitment(subtle, B.blob, decodeDescriptor(offerDescriptor).commitment),
        /does not match the commitment/, 'blobs swapped');

    // A descriptor with no commitment cannot be used to admit a blob.
    await rejectsAsync(() => verifyBlobCommitment(subtle, A.blob, null),
        /no usable commitment/, 'missing commitment');
    await rejectsAsync(() => verifyBlobCommitment(subtle, A.blob, new Uint8Array(8)),
        /no usable commitment/, 'short commitment');
}

// ---------------------------------------------------------------------------
// transcript, salt, SAS
// ---------------------------------------------------------------------------
{
    const h = await handshake();

    // Both peers derive the same salt and the same digits from their own side.
    const salt = await deriveTranscriptSalt(subtle, h.transcript);
    assert.equal(salt.length, 64, 'deriveSharedKeys requires exactly 64 bytes');
    assert.ok(salt.every((b) => Number.isInteger(b) && b >= 0 && b <= 255));

    const sasA = await computeTranscriptSas(subtle, {
        ecdhPrivateKey: h.A.ecdh.privateKey, peerEcdhPublicKey: h.B.ecdh.publicKey, transcript: h.transcript,
    });
    const sasB = await computeTranscriptSas(subtle, {
        ecdhPrivateKey: h.B.ecdh.privateKey, peerEcdhPublicKey: h.A.ecdh.publicKey, transcript: h.transcript,
    });
    assert.equal(sasA, sasB, 'both sides must read the same digits');
    assert.match(sasA, /^\d{7}$/, 'SAS is 7 digits');

    // Every component of the transcript must move the digits and the salt.
    const variants = {
        'offer descriptor': { offerDescriptor: (x) => { const y = Uint8Array.from(x); y[6] ^= 0xff; return y; } },
        'answer descriptor': { answerDescriptor: (x) => { const y = Uint8Array.from(x); y[6] ^= 0xff; return y; } },
        'offer blob': { offerBlob: (x) => { const y = Uint8Array.from(x); y[10] ^= 0x01; return y; } },
        'answer blob': { answerBlob: (x) => { const y = Uint8Array.from(x); y[10] ^= 0x01; return y; } },
    };
    for (const [label, mut] of Object.entries(variants)) {
        const parts = {
            offerDescriptor: h.offerDescriptor, answerDescriptor: h.answerDescriptor,
            offerBlob: h.A.blob, answerBlob: h.B.blob,
        };
        for (const [k, fn] of Object.entries(mut)) parts[k] = fn(parts[k]);
        const t2 = buildTranscript(parts);
        const sas2 = await computeTranscriptSas(subtle, {
            ecdhPrivateKey: h.A.ecdh.privateKey, peerEcdhPublicKey: h.B.ecdh.publicKey, transcript: t2,
        });
        assert.notEqual(sas2, sasA, `SAS must change when the ${label} changes`);
        assert.notDeepEqual(await deriveTranscriptSalt(subtle, t2), salt,
            `the HKDF salt must change when the ${label} changes`);
    }

    // Role order, not call order: a peer that assembled the transcript with the
    // sides swapped must not land on the same digits.
    const swapped = buildTranscript({
        offerDescriptor: h.answerDescriptor, answerDescriptor: h.offerDescriptor,
        offerBlob: h.B.blob, answerBlob: h.A.blob,
    });
    assert.notDeepEqual(swapped, h.transcript, 'transcript is role-ordered');

    rejects(() => buildTranscript({
        offerDescriptor: h.offerDescriptor, answerDescriptor: h.answerDescriptor, offerBlob: h.A.blob,
    }), /transcript component answerBlob is missing/, 'incomplete transcript');
}

// ---------------------------------------------------------------------------
// identity proof (replaces authProof)
// ---------------------------------------------------------------------------
{
    const h = await handshake();
    const payload = proofPayload(h.transcript);

    const sigA = new Uint8Array(await subtle.sign(
        { name: 'ECDSA', hash: 'SHA-384' }, h.A.ecdsa.privateKey, payload));
    assert.equal(await subtle.verify(
        { name: 'ECDSA', hash: 'SHA-384' }, h.A.ecdsa.publicKey, sigA, payload), true, 'honest proof verifies');

    // Wrong identity key: a peer that did not commit to this ECDSA key cannot
    // produce the proof.
    const M = await makePeer(ROLE.OFFER);
    const sigM = new Uint8Array(await subtle.sign(
        { name: 'ECDSA', hash: 'SHA-384' }, M.ecdsa.privateKey, payload));
    assert.equal(await subtle.verify(
        { name: 'ECDSA', hash: 'SHA-384' }, h.A.ecdsa.publicKey, sigM, payload), false, 'foreign key is rejected');

    // A proof over a different transcript does not transfer: this is what stops
    // a signature captured from one session being replayed into another.
    const other = await handshake();
    assert.equal(await subtle.verify(
        { name: 'ECDSA', hash: 'SHA-384' }, h.A.ecdsa.publicKey, sigA, proofPayload(other.transcript)),
        false, 'proof does not transfer across sessions');

    // The domain-separation label is part of what is signed, so a raw-transcript
    // signature is not a valid proof.
    assert.equal(await subtle.verify(
        { name: 'ECDSA', hash: 'SHA-384' }, h.A.ecdsa.publicKey, sigA, h.transcript),
        false, 'proof is domain-separated from the bare transcript');
}

// ---------------------------------------------------------------------------
// end-to-end: the sequence the manager performs, including a MITM attempt
// ---------------------------------------------------------------------------
{
    const h = await handshake();

    // Each side checks the peer's commitment, then derives.
    await verifyBlobCommitment(subtle, h.B.blob, decodeDescriptor(h.answerDescriptor).commitment);
    await verifyBlobCommitment(subtle, h.A.blob, decodeDescriptor(h.offerDescriptor).commitment);

    const salt = await deriveTranscriptSalt(subtle, h.transcript);
    const bits = async (priv, pub) => new Uint8Array(
        await subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256));
    assert.deepEqual(
        await bits(h.A.ecdh.privateKey, h.B.ecdh.publicKey),
        await bits(h.B.ecdh.privateKey, h.A.ecdh.publicKey),
        'both sides reach the same ECDH secret');
    assert.equal(salt.length, 64);

    // MITM: an attacker who terminates DTLS to each side and forwards the
    // descriptors unchanged still has to present key material matching a
    // commitment it cannot recompute, because the commitment travelled inside
    // the descriptor the user carried.
    const M = await makePeer(ROLE.ANSWER);
    await rejectsAsync(
        () => verifyBlobCommitment(subtle, M.blob, decodeDescriptor(h.answerDescriptor).commitment),
        /does not match the commitment/, 'MITM key substitution');

    // If the attacker rewrites the descriptor too — which requires control of
    // the out-of-band channel — the commitment check passes, and the SAS is
    // what catches it.
    const forged = await makeDescriptor(
        chrome.turn_all.answer, TYPE.ANSWER, M.commitment, await bindingTag(digest, h.offerDescriptor));
    await verifyBlobCommitment(subtle, M.blob, decodeDescriptor(forged).commitment);
    const forgedTranscript = buildTranscript({
        offerDescriptor: h.offerDescriptor, answerDescriptor: forged,
        offerBlob: h.A.blob, answerBlob: M.blob,
    });
    const honest = await computeTranscriptSas(subtle, {
        ecdhPrivateKey: h.A.ecdh.privateKey, peerEcdhPublicKey: h.B.ecdh.publicKey, transcript: h.transcript,
    });
    const attacked = await computeTranscriptSas(subtle, {
        ecdhPrivateKey: h.A.ecdh.privateKey, peerEcdhPublicKey: M.ecdh.publicKey, transcript: forgedTranscript,
    });
    assert.notEqual(attacked, honest, 'a fully rewritten handshake still changes the SAS digits');
}

console.log('sbq2-key-exchange: all assertions passed');
