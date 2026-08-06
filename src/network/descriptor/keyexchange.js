// In-band key exchange for SBQ2.
//
// The out-of-band descriptor carries only what brings up DTLS, plus a 16-byte
// commitment. The key material itself — ECDH key, ECDSA identity key — travels
// as the FIRST frame on the DataChannel, and is checked against that commitment
// before a single byte of it is used for anything.
//
// Order of operations, and why it is this order:
//
//   1. Both sides send their key blob as soon as the channel opens.
//   2. Each verifies commitment(peer blob) against the commitment that arrived
//      in the peer's descriptor, over the channel the user authenticated by
//      looking at it. A mismatch tears the connection down. This happens BEFORE
//      the blob is parsed into keys, so a substituted blob never reaches
//      importKey.
//   3. Only now is the transcript defined: both descriptors verbatim and both
//      blobs, length-prefixed. The HKDF salt is SHA-512 of it, so the session
//      keys are bound to both DTLS fingerprints and every candidate — the salt
//      is never transmitted and cannot be influenced independently by either
//      side.
//   4. Each signs the transcript with its ECDSA key and sends the signature.
//      This replaces the old challenge/response authProof: one signature over
//      everything, instead of seven fields echoing a nonce back.
//   5. The SAS is HKDF over the ECDH shared secret salted with the transcript,
//      so any change anywhere in the handshake — either descriptor, either blob
//      — changes the digits the two people read to each other.
//
// This module is pure: it takes SubtleCrypto in, touches no DOM and no network.

import { sasTranscript, commitBlob, LIMITS } from './sbq2.js';

export const KEY_BLOB_VERSION = 0x02;

export const ROLE = Object.freeze({ OFFER: 0, ANSWER: 1 });

export const BLOB_LIMITS = Object.freeze({
    // A P-384 SPKI is 120 bytes; P-521 would be 158. The ceiling is generous
    // enough for a future curve and far below anything that could be used to
    // wedge the parser.
    MAX_SPKI: 256,
    MIN_SPKI: 40,
    // ECDSA P-384 signatures are 96 bytes raw; P-521 is 132.
    MAX_SIG: 160,
    MIN_SIG: 48,
    MAX_BLOB_BYTES: 1024,
});

class KeyExchangeError extends Error {
    constructor(message, code = 'key_exchange') {
        super(message);
        this.name = 'KeyExchangeError';
        this.code = code;
    }
}
const fail = (msg, code) => { throw new KeyExchangeError(msg, code); };

// ---------------------------------------------------------------------------
// key blob
// ---------------------------------------------------------------------------

/**
 * version u8 | role u8 | ecdhLen u16 | ecdh | ecdsaLen u16 | ecdsa
 *
 * No signature lives in here: the blob is what the commitment and the
 * transcript cover, and a signature over the transcript cannot be inside the
 * thing it signs. It travels separately, in the proof frame.
 */
export function encodeKeyBlob({ role, ecdhSpki, ecdsaSpki }) {
    if (role !== ROLE.OFFER && role !== ROLE.ANSWER) fail('invalid role');
    for (const [name, v] of [['ecdh', ecdhSpki], ['ecdsa', ecdsaSpki]]) {
        if (!(v instanceof Uint8Array)) fail(`${name} SPKI must be a Uint8Array`);
        if (v.length < BLOB_LIMITS.MIN_SPKI || v.length > BLOB_LIMITS.MAX_SPKI) {
            fail(`${name} SPKI length out of range`);
        }
    }
    const out = new Uint8Array(1 + 1 + 2 + ecdhSpki.length + 2 + ecdsaSpki.length);
    const dv = new DataView(out.buffer);
    let o = 0;
    out[o++] = KEY_BLOB_VERSION;
    out[o++] = role;
    dv.setUint16(o, ecdhSpki.length); o += 2;
    out.set(ecdhSpki, o); o += ecdhSpki.length;
    dv.setUint16(o, ecdsaSpki.length); o += 2;
    out.set(ecdsaSpki, o);
    return out;
}

/** Strict parser. Anything unexpected throws; there is no partial result. */
export function decodeKeyBlob(buf) {
    if (!(buf instanceof Uint8Array)) fail('key blob must be a Uint8Array');
    if (buf.length === 0) fail('key blob is empty');
    if (buf.length > BLOB_LIMITS.MAX_BLOB_BYTES) fail('key blob exceeds the size limit');

    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    let o = 0;
    const need = (n) => { if (o + n > buf.length) fail('key blob is truncated'); };

    need(1);
    const version = buf[o++];
    // Same rule as the descriptor: a version mismatch is an error, never an
    // attempt to parse a different shape.
    if (version !== KEY_BLOB_VERSION) fail(`unsupported key blob version 0x${version.toString(16)}`, 'version');

    need(1);
    const role = buf[o++];
    if (role !== ROLE.OFFER && role !== ROLE.ANSWER) fail('reserved key blob role');

    need(2);
    const ecdhLen = dv.getUint16(o); o += 2;
    if (ecdhLen < BLOB_LIMITS.MIN_SPKI || ecdhLen > BLOB_LIMITS.MAX_SPKI) fail('ECDH SPKI length out of range');
    need(ecdhLen);
    const ecdhSpki = buf.slice(o, o + ecdhLen); o += ecdhLen;

    need(2);
    const ecdsaLen = dv.getUint16(o); o += 2;
    if (ecdsaLen < BLOB_LIMITS.MIN_SPKI || ecdsaLen > BLOB_LIMITS.MAX_SPKI) fail('ECDSA SPKI length out of range');
    need(ecdsaLen);
    const ecdsaSpki = buf.slice(o, o + ecdsaLen); o += ecdsaLen;

    // Trailing bytes are malformed input, not padding to ignore — the same rule
    // the descriptor decoder applies, and for the same reason: what the
    // commitment covers must have exactly one reading.
    if (o !== buf.length) fail(`${buf.length - o} trailing byte(s) after the key blob`);

    return { version, role, ecdhSpki, ecdsaSpki };
}

// ---------------------------------------------------------------------------
// transcript
// ---------------------------------------------------------------------------

/**
 * Canonical transcript. Argument order is by ROLE, never by who is calling, so
 * both peers hash identical bytes.
 */
export function buildTranscript({ offerDescriptor, answerDescriptor, offerBlob, answerBlob }) {
    for (const [name, v] of Object.entries({ offerDescriptor, answerDescriptor, offerBlob, answerBlob })) {
        if (!(v instanceof Uint8Array) || v.length === 0) fail(`transcript component ${name} is missing`);
    }
    return sasTranscript(offerDescriptor, answerDescriptor, offerBlob, answerBlob);
}

/**
 * HKDF salt, derived rather than transmitted.
 *
 * deriveSharedKeys requires exactly 64 bytes, which SHA-512 supplies directly.
 * Deriving it here means the salt is bound to both DTLS fingerprints and every
 * candidate, and neither side can steer it: it is a hash of material the other
 * side already committed to.
 */
export async function deriveTranscriptSalt(subtle, transcript) {
    const h = await subtle.digest('SHA-512', transcript);
    return Array.from(new Uint8Array(h));
}

const enc = new TextEncoder();

/** Bytes an ECDSA identity key signs to prove possession and bind the transcript. */
export function proofPayload(transcript) {
    const label = enc.encode('sbq2/proof/v1\0');
    const out = new Uint8Array(label.length + transcript.length);
    out.set(label, 0);
    out.set(transcript, label.length);
    return out;
}

/**
 * SAS digits.
 *
 * IKM is the raw ECDH shared secret, so an observer who has the whole
 * transcript still cannot predict the digits. The salt is the transcript hash,
 * so nothing in the handshake can move without moving the digits.
 */
export async function computeTranscriptSas(subtle, { ecdhPrivateKey, peerEcdhPublicKey, transcript, digits = 7 }) {
    const shared = await subtle.deriveBits({ name: 'ECDH', public: peerEcdhPublicKey }, ecdhPrivateKey, 256);
    let ikm = null;
    try {
        ikm = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
        const salt = new Uint8Array(await subtle.digest('SHA-256', transcript));
        const bits = await subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('sbq2-sas-v1') },
            ikm, 64,
        );
        const dv = new DataView(bits);
        const n = (dv.getUint32(0) ^ dv.getUint32(4)) >>> 0;
        const mod = 10 ** digits;
        return String(n % mod).padStart(digits, '0');
    } finally {
        // The shared secret must not linger in the heap once the digits exist.
        try { new Uint8Array(shared).fill(0); } catch (_) { /* not a view we own */ }
    }
}

/**
 * Verify a peer blob against the commitment that arrived out of band.
 *
 * Constant-time comparison is not required — the commitment is public — but the
 * check must happen before the blob is interpreted, which is why this takes raw
 * bytes and not a parsed structure.
 */
export async function verifyBlobCommitment(subtle, blobBytes, expectedCommitment) {
    if (!(expectedCommitment instanceof Uint8Array) || expectedCommitment.length !== LIMITS.COMMITMENT_BYTES) {
        fail('descriptor carried no usable commitment', 'commitment_missing');
    }
    const digest = async (b) => new Uint8Array(await subtle.digest('SHA-256', b));
    const actual = await commitBlob(digest, blobBytes);
    if (actual.length !== expectedCommitment.length) fail('commitment length mismatch', 'commitment_mismatch');
    let diff = 0;
    for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expectedCommitment[i];
    if (diff !== 0) {
        fail('the key material does not match the commitment in the invitation', 'commitment_mismatch');
    }
    return true;
}

export { KeyExchangeError };
