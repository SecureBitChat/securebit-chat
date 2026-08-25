// Group cryptography for SecureBit.chat.
//
// WHY A SEPARATE IDENTITY KEY EXISTS
// ----------------------------------
// The pairwise handshake generates a fresh ECDSA key pair per CONNECTION
// (see createSecureOffer / createSecureAnswer). That is exactly right for 1:1 —
// there are no accounts, so there is nothing a long-term key should outlive —
// but it means Alice presents a different identity key to Bob than she presents
// to Carol. A group cannot be built on that: a membership operation signed
// toward Bob would be unverifiable by Carol, and there would be nothing stable
// to put in a group safety code.
//
// So a group gets its own ECDSA P-384 key pair, generated per group per device
// and destroyed with the group. It never touches the pairwise handshake, and it
// is published to the other members over the ALREADY VERIFIED pairwise channels.
// That keeps the 1:1 protocol untouched while giving the group one signing key
// per member for the epoch's lifetime.
//
// WHY THE SAFETY CODE IS COMMIT-THEN-REVEAL
// -----------------------------------------
// The obvious construction — hash the sorted set of member key fingerprints and
// show the digits, the way a Signal safety number works — is unsafe at the
// length a group can actually read aloud.
//
// The attacker here is a group member who introduces two others and sits in the
// middle of the pair they could not reach directly. They present key K_b to Bob
// and K_c to Carol. To go unnoticed they need Bob's digits and Carol's digits to
// match, and both sets are under their control: they can generate candidate key
// pairs until the two truncated hashes collide. That is a BIRTHDAY search, not a
// preimage search — roughly 10^(d/2) work for d digits. A 7-digit code falls in
// a few thousand tries. Signal answers this by making the safety number 60
// digits; nobody reads 60 digits aloud to seven other people.
//
// Commit-then-reveal removes the search instead of outrunning it. Every member
// commits to a secret nonce (publishing only its hash), and only once ALL
// commitments are in does anyone reveal. The attacker must fix both of their
// commitments before they can see a single honest nonce, so they cannot steer
// either digit string — they are reduced to guessing, once, at 10^-d. Seven
// digits is then genuinely safe, and it matches the pairwise SAS the users have
// already been trained to compare.
//
// The ordering is the whole security property: revealing before every commitment
// has arrived hands the attacker exactly the grinding freedom this construction
// exists to deny. GroupSasCeremony below enforces that transition; nothing else
// may.
//
// WHY GROUP MESSAGES ARE SIGNED
// -----------------------------
// Messages fan out over N-1 independent pairwise ratchets, so each recipient
// authenticates only that the sender's SESSION sent it. A malicious member could
// send different text to different people under one sequence number and no
// recipient could tell. A signature over (group, epoch, seq, body hash) with the
// sender's group identity key makes such a split provable: two valid signatures
// from one member on one seq are non-repudiable evidence. It does not prevent
// the split — nothing without a shared transcript can — it makes it detectable,
// which is what a group without a server can honestly offer.
//
// This module is pure: SubtleCrypto is injected, no DOM, no network, no state
// beyond the ceremony object. It parses attacker-controlled input, so every
// length and range is checked before the value is used.

export const GROUP_LIMITS = Object.freeze({
    // Eight is a mesh limit, not a crypto limit: it is where N(N-1)/2 pairwise
    // connections and N-1 fan-out copies stop being comfortable in a browser.
    MAX_MEMBERS: 8,
    MIN_MEMBERS: 2,
    GROUP_ID_BYTES: 16,
    NONCE_BYTES: 32,
    COMMIT_BYTES: 32,
    FINGERPRINT_BYTES: 32,
    // Matches the pairwise SAS. Safe at this length only because of the
    // commit-reveal ordering above — see the header.
    SAS_DIGITS: 7,
    // Bytes, not characters — and the gap between the two is a real trap. The
    // create dialog used to cap input at 64 CHARACTERS, so a 36-character
    // Cyrillic name ("Наша секретная группа для обсуждений") is 68 bytes and was
    // accepted by the UI and then rejected here, inside the admin's roster
    // signing, killing group formation with no visible cause. The dialog now
    // clamps by bytes, and the budget is generous enough that a normal name in
    // any script fits.
    MAX_NAME_BYTES: 128,
    // Epoch is a uint32 on the wire; a group that changes membership four
    // billion times has other problems.
    MAX_EPOCH: 0xffffffff,
    MAX_SPKI_BYTES: 256,
    MIN_SPKI_BYTES: 40,
    MAX_SIG_BYTES: 160,
    MIN_SIG_BYTES: 48,

    /**
     * Group frames travel as chat content on a pairwise session, and that path
     * ends in EnhancedSecureCryptoUtils.sanitizeMessage, which runs DOMPurify and
     * then truncates to 2000 characters. Truncation would corrupt a frame
     * silently, so every frame has to fit underneath it after base64 — see
     * FRAME_BUDGET_CHARS and the envelope in GroupSession.
     *
     * A frame's fixed overhead (group id, epoch, sequence, sender fingerprint,
     * timestamp, signature, envelope) is roughly 300 bytes, and base64 costs
     * another third. 1024 bytes of body leaves comfortable headroom, and it is
     * bytes rather than characters so a message in a non-Latin script is bounded
     * by the same real budget.
     */
    MAX_BODY_BYTES: 1024,
    FRAME_BUDGET_CHARS: 1800,

    /**
     * A mesh descriptor as it travels inside a group frame.
     *
     * SBQ2 caps a descriptor payload at 512 bytes (LIMITS.MAX_PAYLOAD_BYTES),
     * which is "SB2:" plus 683 base64url characters at the absolute worst. 768
     * bounds the allocation with room to spare and still leaves the whole frame
     * — descriptor, two fingerprints, a nonce and a signature, wrapped in a
     * relay envelope and base64'd — under FRAME_BUDGET_CHARS. A descriptor that
     * somehow does not fit is refused rather than truncated; the pair simply
     * stays on the relay path, which is the same thing that happens when the
     * mesh dial fails for any other reason.
     */
    MAX_DESCRIPTOR_CHARS: 768,
    /** Binds an answer to the one dial attempt that asked for it. */
    MESH_NONCE_BYTES: 16,
});

/** Which half of a mesh dial a signature covers. */
export const MESH_KINDS = Object.freeze({ OFFER: 'moffer', ANSWER: 'manswer' });

export const MEMBER_OPS = Object.freeze({
    CREATE: 'create',
    ADD: 'add',
    REMOVE: 'remove',
    RENAME: 'rename',
});

const ENC = new TextEncoder();

class GroupCryptoError extends Error {
    constructor(message, code = 'group_crypto') {
        super(message);
        this.name = 'GroupCryptoError';
        this.code = code;
    }
}
const fail = (msg, code) => { throw new GroupCryptoError(msg, code); };

// ---------------------------------------------------------------------------
// codecs
// ---------------------------------------------------------------------------

export function toHex(bytes) {
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let out = '';
    for (let i = 0; i < view.length; i++) out += view[i].toString(16).padStart(2, '0');
    return out;
}

export function fromHex(hex) {
    if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
        fail('not a hex string', 'bad_hex');
    }
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
}

export function toB64(bytes) {
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let binary = '';
    for (let i = 0; i < view.length; i++) binary += String.fromCharCode(view[i]);
    return btoa(binary);
}

export function fromB64(b64, { max = GROUP_LIMITS.MAX_SPKI_BYTES } = {}) {
    if (typeof b64 !== 'string') fail('not a base64 string', 'bad_b64');
    // Bound BEFORE decoding: base64 expands 3:4, so this caps the allocation.
    if (b64.length > Math.ceil((max * 4) / 3) + 4) fail('base64 payload exceeds its limit', 'bad_b64');
    let binary;
    try {
        binary = atob(b64);
    } catch (_) {
        fail('malformed base64', 'bad_b64');
    }
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
}

export function randomBytes(n) {
    return crypto.getRandomValues(new Uint8Array(n));
}

/** A fresh group id. Shared between members, unlike the local-only sessionId. */
export function newGroupId() {
    return toHex(randomBytes(GROUP_LIMITS.GROUP_ID_BYTES));
}

// ---------------------------------------------------------------------------
// canonical encoding
// ---------------------------------------------------------------------------

/**
 * Length-prefixed concatenation.
 *
 * Everything signed or hashed in this module goes through here, so that no two
 * distinct field sets can ever produce the same bytes. Plain concatenation would
 * let ("ab","c") and ("a","bc") sign the same payload, which is precisely how a
 * membership operation gets reinterpreted as a different one.
 */
function lp(label, ...parts) {
    const chunks = [ENC.encode(label + '\0')];
    let total = chunks[0].length;
    for (const part of parts) {
        const bytes = part instanceof Uint8Array ? part
            : typeof part === 'string' ? ENC.encode(part)
            : fail('unsupported payload component', 'bad_payload');
        const header = new Uint8Array(4);
        new DataView(header.buffer).setUint32(0, bytes.length);
        chunks.push(header, bytes);
        total += 4 + bytes.length;
    }
    const out = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) { out.set(c, o); o += c.length; }
    return out;
}

function u32(n) {
    if (!Number.isInteger(n) || n < 0 || n > GROUP_LIMITS.MAX_EPOCH) fail('value out of uint32 range', 'bad_u32');
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n);
    return b;
}

/** Constant-time byte comparison. Cheap, and keeps the habit uniform. */
function equalBytes(a, b) {
    if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}

// ---------------------------------------------------------------------------
// validation of attacker-supplied values
// ---------------------------------------------------------------------------

export function assertGroupId(groupId) {
    if (typeof groupId !== 'string' || groupId.length !== GROUP_LIMITS.GROUP_ID_BYTES * 2 || !/^[0-9a-f]+$/.test(groupId)) {
        fail('malformed group id', 'bad_group_id');
    }
    return groupId;
}

export function assertFingerprint(fp) {
    if (typeof fp !== 'string' || fp.length !== GROUP_LIMITS.FINGERPRINT_BYTES * 2 || !/^[0-9a-f]+$/.test(fp)) {
        fail('malformed member fingerprint', 'bad_fingerprint');
    }
    return fp;
}

export function assertEpoch(epoch) {
    if (!Number.isInteger(epoch) || epoch < 0 || epoch > GROUP_LIMITS.MAX_EPOCH) {
        fail('epoch out of range', 'bad_epoch');
    }
    return epoch;
}

export function assertName(name) {
    const value = typeof name === 'string' ? name : '';
    if (ENC.encode(value).length > GROUP_LIMITS.MAX_NAME_BYTES) fail('group name too long', 'bad_name');
    return value;
}

/**
 * Canonical member ordering.
 *
 * Sorting by fingerprint — never by join order, never by however the array
 * arrived — is what makes every device hash identical bytes. A set that two
 * members order differently produces two different safety codes and the group
 * fails to form for no visible reason.
 */
export function canonicalFingerprints(fps) {
    if (!Array.isArray(fps)) fail('member list is not an array', 'bad_members');
    if (fps.length < GROUP_LIMITS.MIN_MEMBERS) fail('a group needs at least two members', 'bad_members');
    if (fps.length > GROUP_LIMITS.MAX_MEMBERS) fail(`a group is limited to ${GROUP_LIMITS.MAX_MEMBERS} members`, 'too_many_members');
    const seen = new Set();
    for (const fp of fps) {
        assertFingerprint(fp);
        if (seen.has(fp)) fail('duplicate member fingerprint', 'duplicate_member');
        seen.add(fp);
    }
    return [...fps].sort();
}

// ---------------------------------------------------------------------------
// group identity key
// ---------------------------------------------------------------------------

/**
 * A group identity key pair for this device, in this group.
 *
 * Non-extractable private key: it signs and nothing else, and it must not be
 * reachable from a heap dump the way an exportable key is. The public half is
 * exported once, here, because it has to travel to the other members.
 */
export async function generateGroupIdentity(subtle) {
    const keyPair = await subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-384' },
        false,
        ['sign', 'verify'],
    );
    const spki = new Uint8Array(await subtle.exportKey('spki', keyPair.publicKey));
    const fingerprint = await fingerprintSpki(subtle, spki);
    return { keyPair, spki, fingerprint };
}

/** SHA-256 over the SPKI, hex. The stable name of a member inside a group. */
export async function fingerprintSpki(subtle, spki) {
    if (!(spki instanceof Uint8Array) || spki.length < GROUP_LIMITS.MIN_SPKI_BYTES || spki.length > GROUP_LIMITS.MAX_SPKI_BYTES) {
        fail('SPKI length out of range', 'bad_spki');
    }
    return toHex(new Uint8Array(await subtle.digest('SHA-256', spki)));
}

/**
 * Import a member's published verifying key.
 *
 * Returns the key AND the fingerprint computed from the bytes we were actually
 * given, never one the sender asserted. A member is identified by what their key
 * hashes to; accepting a claimed fingerprint would let a member occupy someone
 * else's slot in the safety code.
 */
export async function importMemberIdentity(subtle, spki) {
    const fingerprint = await fingerprintSpki(subtle, spki);
    let publicKey;
    try {
        publicKey = await subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-384' }, false, ['verify']);
    } catch (_) {
        fail('member identity key is not a valid P-384 public key', 'bad_spki');
    }
    return { publicKey, fingerprint };
}

// ---------------------------------------------------------------------------
// commit / reveal
// ---------------------------------------------------------------------------

/**
 * Commitment to a member's nonce for one epoch.
 *
 * The group id and epoch are inside the hash so a commitment cannot be replayed
 * into a different group or a later epoch, and the fingerprint is inside so one
 * member cannot claim another member's commitment as their own.
 */
export async function buildCommitment(subtle, { groupId, epoch, fingerprint, nonce }) {
    assertGroupId(groupId);
    assertEpoch(epoch);
    assertFingerprint(fingerprint);
    if (!(nonce instanceof Uint8Array) || nonce.length !== GROUP_LIMITS.NONCE_BYTES) {
        fail('nonce must be 32 bytes', 'bad_nonce');
    }
    const payload = lp('securebit/group/commit/v1', fromHex(groupId), u32(epoch), fromHex(fingerprint), nonce);
    return new Uint8Array(await subtle.digest('SHA-256', payload));
}

export async function verifyCommitment(subtle, commitment, fields) {
    if (!(commitment instanceof Uint8Array) || commitment.length !== GROUP_LIMITS.COMMIT_BYTES) return false;
    let expected;
    try {
        expected = await buildCommitment(subtle, fields);
    } catch (_) {
        return false;
    }
    return equalBytes(commitment, expected);
}

/**
 * The digits every member reads aloud.
 *
 * Inputs are the full member set with their revealed nonces, sorted by
 * fingerprint. Every member's key AND every member's nonce is covered, so a
 * substituted key or a substituted nonce anywhere in the group changes the code
 * for the members who received the substitution — and not for the others, which
 * is the mismatch the humans are there to notice.
 */
export async function computeGroupSas(subtle, { groupId, epoch, contributions, digits = GROUP_LIMITS.SAS_DIGITS }) {
    assertGroupId(groupId);
    assertEpoch(epoch);
    if (!Array.isArray(contributions)) fail('contributions must be an array', 'bad_contributions');
    if (!Number.isInteger(digits) || digits < 4 || digits > 12) fail('digit count out of range', 'bad_digits');

    canonicalFingerprints(contributions.map((c) => c && c.fingerprint));

    const ordered = [...contributions].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1));
    const parts = [];
    for (const c of ordered) {
        if (!(c.nonce instanceof Uint8Array) || c.nonce.length !== GROUP_LIMITS.NONCE_BYTES) {
            fail('every member must contribute a 32-byte nonce', 'bad_nonce');
        }
        parts.push(fromHex(c.fingerprint), c.nonce);
    }

    const ikm = lp('securebit/group/sas/v1', fromHex(groupId), u32(epoch), ...parts);
    const salt = new Uint8Array(await subtle.digest('SHA-256', lp('securebit/group/sas-salt/v1', fromHex(groupId), u32(epoch))));

    let key = null;
    try {
        key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
        const bits = await subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt, info: ENC.encode('securebit-group-sas-v1') },
            key, 64,
        );
        const dv = new DataView(bits);
        // 52 bits of entropy folded into the digits. Staying under 2^53 keeps
        // this exact in a JS Number; the modulo bias at 10^7 is ~1e-9.
        const n = dv.getUint32(0) * 2 ** 20 + (dv.getUint32(4) >>> 12);
        return String(n % 10 ** digits).padStart(digits, '0');
    } finally {
        try { ikm.fill(0); } catch (_) { /* not ours to wipe */ }
    }
}

/**
 * The commit-reveal state machine.
 *
 * This object exists so that the ordering rule has exactly one implementation.
 * `reveal()` throws until every expected commitment has arrived, and that refusal
 * is the entire security argument for a 7-digit group code — see the header.
 */
export class GroupSasCeremony {
    constructor({ groupId, epoch, selfFingerprint, memberFingerprints }) {
        this.groupId = assertGroupId(groupId);
        this.epoch = assertEpoch(epoch);
        this.selfFingerprint = assertFingerprint(selfFingerprint);
        this.members = canonicalFingerprints(memberFingerprints);
        if (!this.members.includes(this.selfFingerprint)) {
            fail('the local member is not in the member set', 'not_a_member');
        }
        this.nonce = randomBytes(GROUP_LIMITS.NONCE_BYTES);
        this.commitments = new Map(); // fp -> Uint8Array(32)
        this.nonces = new Map();      // fp -> Uint8Array(32)
        this.revealed = false;
        this.code = null;
    }

    /** Our own commitment, to be broadcast first. */
    async ownCommitment(subtle) {
        const commitment = await buildCommitment(subtle, {
            groupId: this.groupId, epoch: this.epoch,
            fingerprint: this.selfFingerprint, nonce: this.nonce,
        });
        this.commitments.set(this.selfFingerprint, commitment);
        return commitment;
    }

    /**
     * Record a peer commitment. Rejects anyone outside the member set, and
     * refuses to overwrite one already recorded — a second, different commitment
     * from the same member is an attempt to move after seeing more of the round.
     */
    acceptCommitment(fingerprint, commitment) {
        assertFingerprint(fingerprint);
        if (!this.members.includes(fingerprint)) fail('commitment from a non-member', 'not_a_member');
        if (!(commitment instanceof Uint8Array) || commitment.length !== GROUP_LIMITS.COMMIT_BYTES) {
            fail('malformed commitment', 'bad_commitment');
        }
        const existing = this.commitments.get(fingerprint);
        if (existing) {
            if (!equalBytes(existing, commitment)) fail('member changed their commitment', 'commitment_changed');
            return false;
        }
        this.commitments.set(fingerprint, commitment);
        return true;
    }

    get commitmentsComplete() {
        return this.members.every((fp) => this.commitments.has(fp));
    }

    /**
     * Our nonce — available ONLY once every commitment is in.
     *
     * This is the gate the whole construction rests on. Do not add a caller that
     * bypasses it, and do not "helpfully" relax it when a member is slow: a
     * timeout must fail the ceremony, never proceed without a commitment.
     */
    reveal() {
        if (!this.commitmentsComplete) {
            fail('cannot reveal before every member has committed', 'premature_reveal');
        }
        this.revealed = true;
        this.nonces.set(this.selfFingerprint, this.nonce);
        return this.nonce;
    }

    /** Record a peer nonce, checking it against the commitment they are bound to. */
    async acceptReveal(subtle, fingerprint, nonce) {
        assertFingerprint(fingerprint);
        if (!this.members.includes(fingerprint)) fail('reveal from a non-member', 'not_a_member');
        const commitment = this.commitments.get(fingerprint);
        if (!commitment) fail('reveal arrived before the commitment', 'reveal_without_commitment');
        const ok = await verifyCommitment(subtle, commitment, {
            groupId: this.groupId, epoch: this.epoch, fingerprint, nonce,
        });
        if (!ok) fail('revealed nonce does not match the commitment', 'commitment_mismatch');
        this.nonces.set(fingerprint, nonce);
        return true;
    }

    get revealsComplete() {
        return this.members.every((fp) => this.nonces.has(fp));
    }

    /** The digits, once every nonce is in and verified. */
    async finish(subtle) {
        if (!this.revealsComplete) fail('not every member has revealed', 'incomplete_reveal');
        this.code = await computeGroupSas(subtle, {
            groupId: this.groupId,
            epoch: this.epoch,
            contributions: this.members.map((fp) => ({ fingerprint: fp, nonce: this.nonces.get(fp) })),
        });
        return this.code;
    }

    /** Wipe the nonce material once the code exists or the ceremony is abandoned. */
    destroy() {
        try { this.nonce.fill(0); } catch (_) {}
        for (const n of this.nonces.values()) { try { n.fill(0); } catch (_) {} }
        this.nonces.clear();
        this.commitments.clear();
    }
}

// ---------------------------------------------------------------------------
// membership operations
// ---------------------------------------------------------------------------

/**
 * The bytes a membership change is signed over.
 *
 * The resulting member set is signed in full rather than the delta, so a
 * recipient never has to reconstruct state from a sequence of operations it may
 * have received out of order or incompletely. The epoch is what orders them, and
 * accepting only a strictly greater epoch is what refuses both a replay and a
 * rollback to a set that used to be valid.
 */
export function memberOpPayload({ groupId, epoch, op, memberFps, name = '' }) {
    assertGroupId(groupId);
    assertEpoch(epoch);
    if (!Object.values(MEMBER_OPS).includes(op)) fail('unknown membership operation', 'bad_op');
    const ordered = canonicalFingerprints(memberFps);
    return lp(
        'securebit/group/member-op/v1',
        fromHex(groupId), u32(epoch), op, assertName(name),
        ...ordered.map((fp) => fromHex(fp)),
    );
}

export async function signMemberOp(subtle, privateKey, fields) {
    const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-384' }, privateKey, memberOpPayload(fields));
    return new Uint8Array(sig);
}

export async function verifyMemberOp(subtle, publicKey, fields, signature) {
    if (!(signature instanceof Uint8Array)
        || signature.length < GROUP_LIMITS.MIN_SIG_BYTES
        || signature.length > GROUP_LIMITS.MAX_SIG_BYTES) {
        return false;
    }
    let payload;
    try {
        payload = memberOpPayload(fields);
    } catch (_) {
        return false;
    }
    try {
        return await subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, publicKey, signature, payload);
    } catch (_) {
        return false;
    }
}

// ---------------------------------------------------------------------------
// group messages
// ---------------------------------------------------------------------------

export async function hashBody(subtle, body) {
    const bytes = typeof body === 'string' ? ENC.encode(body) : body;
    if (!(bytes instanceof Uint8Array)) fail('message body must be a string or bytes', 'bad_body');
    if (bytes.length > GROUP_LIMITS.MAX_BODY_BYTES) fail('message body exceeds the group limit', 'body_too_large');
    return new Uint8Array(await subtle.digest('SHA-256', bytes));
}

/**
 * The bytes a group message is signed over.
 *
 * Only the hash of the body is signed, not the body: it keeps the payload a
 * fixed size regardless of message length, and the hash is what a later
 * consistency comparison needs anyway.
 */
export function groupMessagePayload({ groupId, epoch, seq, senderFp, bodyHash }) {
    assertGroupId(groupId);
    assertEpoch(epoch);
    assertEpoch(seq); // same uint32 range; a per-sender counter
    assertFingerprint(senderFp);
    if (!(bodyHash instanceof Uint8Array) || bodyHash.length !== 32) fail('body hash must be 32 bytes', 'bad_body_hash');
    return lp('securebit/group/message/v1', fromHex(groupId), u32(epoch), u32(seq), fromHex(senderFp), bodyHash);
}

export async function signGroupMessage(subtle, privateKey, fields) {
    const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-384' }, privateKey, groupMessagePayload(fields));
    return new Uint8Array(sig);
}

export async function verifyGroupMessage(subtle, publicKey, fields, signature) {
    if (!(signature instanceof Uint8Array)
        || signature.length < GROUP_LIMITS.MIN_SIG_BYTES
        || signature.length > GROUP_LIMITS.MAX_SIG_BYTES) {
        return false;
    }
    let payload;
    try {
        payload = groupMessagePayload(fields);
    } catch (_) {
        return false;
    }
    try {
        return await subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, publicKey, signature, payload);
    } catch (_) {
        return false;
    }
}

// ---------------------------------------------------------------------------
// mesh links
// ---------------------------------------------------------------------------
//
// WHY A MESH DESCRIPTOR IS SIGNED WITH THE GROUP IDENTITY KEY
// -----------------------------------------------------------
// Two members who have never met have no pairwise channel to introduce
// themselves over, so their WebRTC descriptors have to travel through a member
// who CAN reach both — in practice the admin. That relay is not trusted with
// the content of the group, and it must not become trusted with the shape of
// the group's transport either: a relay that could swap a descriptor for its
// own would sit in the middle of the very link that was built to route around
// it.
//
// The descriptor is therefore signed with the sender's group identity key —
// the same key whose fingerprint the signed roster names and whose presence the
// humans confirmed when they compared the group code. A relay can drop a dial
// or delay it, which costs availability and nothing else. It cannot substitute
// one, because it cannot produce that signature.
//
// The signature covers the direction (offer or answer), BOTH fingerprints and a
// per-attempt nonce as well as the descriptor bytes:
//
//   - the direction stops an offer being replayed back as an answer;
//   - both fingerprints stop a descriptor addressed to one member being
//     re-aimed at another;
//   - the nonce binds an answer to the one dial that asked for it, so an answer
//     captured from an earlier attempt cannot be replayed into a later one.
//
// SBQ2's own expiry check bounds how long a descriptor is usable at all, and
// the epoch is inside the payload so nothing survives a membership change.

export function meshDescriptorPayload({ groupId, epoch, kind, fromFp, toFp, descriptor, nonce }) {
    assertGroupId(groupId);
    assertEpoch(epoch);
    if (kind !== MESH_KINDS.OFFER && kind !== MESH_KINDS.ANSWER) {
        fail('unknown mesh descriptor kind', 'bad_mesh_kind');
    }
    assertFingerprint(fromFp);
    assertFingerprint(toFp);
    if (fromFp === toFp) fail('a member cannot dial itself', 'bad_mesh_peer');
    if (typeof descriptor !== 'string' || descriptor.length === 0
        || descriptor.length > GROUP_LIMITS.MAX_DESCRIPTOR_CHARS) {
        fail('mesh descriptor is missing or oversized', 'bad_descriptor');
    }
    if (!(nonce instanceof Uint8Array) || nonce.length !== GROUP_LIMITS.MESH_NONCE_BYTES) {
        fail('mesh nonce must be 16 bytes', 'bad_mesh_nonce');
    }
    return lp(
        'securebit/group/mesh-descriptor/v1',
        fromHex(groupId), u32(epoch), kind,
        fromHex(fromFp), fromHex(toFp),
        descriptor, nonce,
    );
}

export async function signMeshDescriptor(subtle, privateKey, fields) {
    const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-384' }, privateKey, meshDescriptorPayload(fields));
    return new Uint8Array(sig);
}

export async function verifyMeshDescriptor(subtle, publicKey, fields, signature) {
    if (!(signature instanceof Uint8Array)
        || signature.length < GROUP_LIMITS.MIN_SIG_BYTES
        || signature.length > GROUP_LIMITS.MAX_SIG_BYTES) {
        return false;
    }
    let payload;
    try {
        payload = meshDescriptorPayload(fields);
    } catch (_) {
        return false;
    }
    try {
        return await subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, publicKey, signature, payload);
    } catch (_) {
        return false;
    }
}

/**
 * The bytes a link probe is signed over.
 *
 * A probe is how a member says "the pairwise chat you are reading this on is
 * me, member <fp>". It exists because two members can perfectly well already
 * hold a verified 1:1 chat with each other before the group was formed, and
 * dialling a second connection between them would be pure waste.
 *
 * The claim has to be authenticated, and it has to be authenticated TO THIS
 * SESSION. A bare signed claim would be replayable: any member could capture
 * one and present it on their own link to impersonate its author, and group
 * traffic meant for that member would then be encrypted to the impersonator's
 * pairwise session, which is a plaintext disclosure and not merely a routing
 * mistake.
 *
 * `linkFp` is what closes that. It is the pairwise session's own key
 * fingerprint — derived from the ECDH shared secret, so it is known to exactly
 * the two endpoints of that session and to nobody else. A probe replayed onto
 * any other session carries the wrong one and fails to verify. The receiver
 * checks it against the fingerprint IT holds for the session the probe arrived
 * on, never against a value inside the frame.
 */
export function linkProbePayload({ groupId, epoch, fp, linkFp }) {
    assertGroupId(groupId);
    assertEpoch(epoch);
    assertFingerprint(fp);
    if (typeof linkFp !== 'string' || linkFp.length === 0 || linkFp.length > 256) {
        fail('link fingerprint is missing or oversized', 'bad_link_fp');
    }
    return lp('securebit/group/link-probe/v1', fromHex(groupId), u32(epoch), fromHex(fp), linkFp);
}

export async function signLinkProbe(subtle, privateKey, fields) {
    const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-384' }, privateKey, linkProbePayload(fields));
    return new Uint8Array(sig);
}

export async function verifyLinkProbe(subtle, publicKey, fields, signature) {
    if (!(signature instanceof Uint8Array)
        || signature.length < GROUP_LIMITS.MIN_SIG_BYTES
        || signature.length > GROUP_LIMITS.MAX_SIG_BYTES) {
        return false;
    }
    let payload;
    try {
        payload = linkProbePayload(fields);
    } catch (_) {
        return false;
    }
    try {
        return await subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, publicKey, signature, payload);
    } catch (_) {
        return false;
    }
}

export { GroupCryptoError };
