// GroupSession — the orchestrator that turns N pairwise sessions into a group.
//
// WHAT THIS IS AND IS NOT
// -----------------------
// It owns no transport. Every byte it sends leaves through an existing
// EnhancedSecureWebRTCManager, over a channel that is already SAS-verified and
// already ratcheted, and arrives having been authenticated by that session. This
// class adds the group layer on top: who is a member, what epoch it is, what
// code the humans compare, and which of the N-1 links a given frame should take.
//
// It holds the non-serializable half of a group — the ECDSA identity key pair,
// the running commit/reveal ceremony, the imported verifying keys — which is
// exactly why it lives in a ref-held Map in the app and never inside the
// reducer. See src/state/groupsStore.js.
//
// DELIVERY: DIRECT WHERE POSSIBLE, RELAYED WHERE NOT
// --------------------------------------------------
// A full mesh needs N(N-1)/2 pairwise links, and at the moment a group is
// created only the admin holds a link to everyone. Rather than block the group
// until every pair is introduced, a frame for a member we cannot reach directly
// is handed to a member who can reach both of us.
//
// That is the STARTING state, not the resting one. Once the group is ready and
// the safety code has been confirmed, every pair that has no link between it
// builds one — see "the mesh" below — and the relay becomes the exception this
// paragraph always described rather than the way the whole group runs. Until
// then, and for any pair that cannot connect directly, the relay carries it.
//
// This is safe because it is not a trust decision. Group messages and membership
// operations are signed with the sender's group identity key, and every member
// holds every other member's verifying key from the signed roster. A relaying
// member can therefore drop a frame or read a frame — they are a member of the
// group, so reading it is what membership already entitles them to — but they
// cannot forge one, alter one, or attribute one to somebody else. What relaying
// costs is metadata (the relay learns who is talking to the group and when) and
// availability (a relay that goes away takes the indirect paths with it), which
// is why a direct link is always preferred and the UI shows how many exist.
//
// Relaying is single-hop by construction. A frame carries `to`; a member that is
// not the addressee forwards it once, marked, and a marked frame is never
// forwarded again. There is no routing table to poison and no loop to form.
//
// ORDER OF OPERATIONS
// -------------------
//   1. invite    admin sends the group's name and its own identity key
//   2. hello     each invitee replies with its identity key
//   3. roster    admin signs the full member set for this epoch and broadcasts it
//   4. commit    every member commits to a secret nonce
//   5. reveal    ONLY once every commitment has arrived, nonces are published
//   6. code      every member computes the same digits and the humans compare
//   7. ready     group traffic flows
//   8. mesh      every pair without a link dials one, over the relay path
//
// Step 8 is the only one that can fail without the group noticing, and that is
// deliberate: a pair that cannot connect directly keeps working exactly as it
// did in step 7.
//
// Steps 4 and 5 are what make a seven-digit code safe; the reasoning is in
// groupCrypto.js and the ordering is enforced by GroupSasCeremony, not here.

import {
    GROUP_LIMITS,
    MEMBER_OPS,
    MESH_KINDS,
    GroupSasCeremony,
    generateGroupIdentity,
    importMemberIdentity,
    signMemberOp,
    verifyMemberOp,
    hashBody,
    signGroupMessage,
    verifyGroupMessage,
    computeGroupSas,
    signMeshDescriptor,
    verifyMeshDescriptor,
    signLinkProbe,
    verifyLinkProbe,
    randomBytes,
    canonicalFingerprints,
    assertGroupId,
    assertFingerprint,
    assertEpoch,
    assertName,
    newGroupId,
    toB64,
    fromB64,
} from './groupCrypto.js';

import { GROUP_PHASE, MEMBER_STATE } from '../state/groupsStore.js';

/** Wire frame types. All group traffic rides the ordinary chat message path. */
export const GROUP_FRAMES = Object.freeze({
    INVITE: 'g_invite',
    HELLO: 'g_hello',
    MEMBER: 'g_member',
    ROSTER: 'g_roster',
    COMMIT: 'g_commit',
    REVEAL: 'g_reveal',
    MESSAGE: 'g_msg',
    RELAY: 'g_relay',
    LEAVE: 'g_leave',
    // Mesh link establishment. These carry SBQ2 descriptors between two members
    // who have no link yet, over the relay path of a member who can reach both.
    MESH_OFFER: 'g_moffer',
    MESH_ANSWER: 'g_manswer',
    MESH_ABORT: 'g_mabort',
    // "The pairwise chat this arrived on is me, member <fp>."
    PROBE: 'g_probe',
});

/** The outer wrapper every group frame travels inside. See encodeEnvelope. */
export const GROUP_ENVELOPE = 'g_env';

/** Every type this module will act on. Anything else is dropped by default. */
export const GROUP_FRAME_TYPES = Object.freeze(new Set(Object.values(GROUP_FRAMES)));

export function isGroupFrame(parsed) {
    if (!parsed || typeof parsed !== 'object') return false;
    return parsed.type === GROUP_ENVELOPE || GROUP_FRAME_TYPES.has(parsed.type);
}

/**
 * The inner type of a frame, without decoding it.
 *
 * Callers outside this module need it for exactly one decision — whether an
 * arriving frame is an invitation to a group they do not have yet — and that
 * decision has to be made before any group state exists to decode with. It is a
 * routing hint only; decodeEnvelope re-checks it against the frame it wraps.
 */
export function groupFrameType(parsed) {
    if (!parsed || typeof parsed !== 'object') return null;
    if (parsed.type === GROUP_ENVELOPE) return typeof parsed.t === 'string' ? parsed.t : null;
    return GROUP_FRAME_TYPES.has(parsed.type) ? parsed.type : null;
}

/**
 * Wrap a frame so the pairwise chat path cannot alter it.
 *
 * Group frames ride sendMessage, which sanitises its payload before encrypting:
 * DOMPurify escapes `<`, `>` and `&`, control characters are stripped, runs of
 * blank lines are collapsed, the string is trimmed, and the result is cut to
 * 2000 characters. Every one of those is correct for chat text and fatal for a
 * signed frame — a body that came back HTML-escaped no longer matches the hash
 * its signature covers, and the message would be rejected as forged.
 *
 * Base64 sidesteps all of it: its alphabet contains nothing DOMPurify rewrites
 * and nothing the sanitiser strips, and it has no whitespace to trim. The group
 * id and the inner type stay outside the encoding so a frame can be routed —
 * and an invitation recognised — without decoding anything first. Neither
 * reveals more than the peer on that link already knows.
 */
export function encodeEnvelope(frame) {
    const json = JSON.stringify(frame);
    const encoded = toB64(new TextEncoder().encode(json));
    if (encoded.length > GROUP_LIMITS.FRAME_BUDGET_CHARS) {
        throw new GroupSessionError('group frame exceeds the transport budget', 'frame_too_large');
    }
    return { type: GROUP_ENVELOPE, gid: frame.gid, t: frame.type, d: encoded };
}

export function decodeEnvelope(envelope) {
    if (!envelope || envelope.type !== GROUP_ENVELOPE) return envelope;
    const raw = String(envelope.d || '');
    if (raw.length > GROUP_LIMITS.FRAME_BUDGET_CHARS) {
        throw new GroupSessionError('group frame exceeds the transport budget', 'frame_too_large');
    }
    const bytes = fromB64(raw, { max: GROUP_LIMITS.FRAME_BUDGET_CHARS });
    const frame = JSON.parse(new TextDecoder().decode(bytes));
    if (!frame || typeof frame !== 'object' || !GROUP_FRAME_TYPES.has(frame.type)) {
        throw new GroupSessionError('envelope carried no recognisable frame', 'bad_envelope');
    }
    // The routing hints outside the encoding are conveniences, not authority:
    // if they disagree with the frame they wrap, the frame was tampered with.
    if (envelope.gid && frame.gid !== envelope.gid) {
        throw new GroupSessionError('envelope group id does not match its frame', 'bad_envelope');
    }
    if (envelope.t && frame.type !== envelope.t) {
        throw new GroupSessionError('envelope type does not match its frame', 'bad_envelope');
    }
    return frame;
}

const TIMEOUTS = Object.freeze({
    // A member that has not committed by now is treated as absent and the
    // ceremony fails. It must FAIL rather than proceed: proceeding without a
    // commitment is exactly the grinding freedom the commit round removes.
    CEREMONY_MS: 60_000,
    // How long the admin waits for invitees to publish their identity keys.
    HELLO_MS: 45_000,
    // How long one mesh dial may stay in flight. It covers a descriptor going
    // out over a relay hop, an answer coming back, and the whole SBQ2 in-band
    // exchange completing on the new channel. Generous, because failing early
    // costs a direct link and gains nothing: the pair keeps working over the
    // relay the entire time the dial is running.
    MESH_DIAL_MS: 45_000,
    // Gap before a failed pair is dialled again, doubling per failure. A pair
    // that cannot connect is usually a network that will not allow it, and
    // retrying hard turns one unreachable member into a permanent load.
    MESH_RETRY_MS: 20_000,
});

/** How many mesh dials one member will have in flight at once. */
const MESH_MAX_CONCURRENT_DIALS = 2;
/** After this many consecutive failures a pair is left on the relay for good. */
const MESH_MAX_ATTEMPTS = 3;

export class GroupSessionError extends Error {
    constructor(message, code = 'group_session') {
        super(message);
        this.name = 'GroupSessionError';
        this.code = code;
    }
}

export class GroupSession {
    /**
     * @param {object} opts
     * @param {string} opts.groupId
     * @param {string} opts.name
     * @param {boolean} opts.isAdmin
     * @param {SubtleCrypto} opts.subtle
     * @param {(sessionId: string, frame: object) => Promise<void>} opts.send
     * @param {(event: string, payload: object) => void} opts.emit
     */
    constructor({ groupId, name, isAdmin, subtle, send, emit, mesh = null, log = () => {} }) {
        this.groupId = assertGroupId(groupId);
        this.name = assertName(name);
        this.isAdmin = !!isAdmin;
        this.subtle = subtle;
        this._send = send;
        this._emit = emit;
        this._log = log;

        /**
         * How this group builds a transport it does not have.
         *
         * Injected rather than imported, for the same reason SubtleCrypto is:
         * this class stays free of WebRTC, of the app's manager registry, and of
         * anything that needs a browser to exist. A group constructed without it
         * runs exactly as it did before — every indirect pair simply stays on
         * the relay path.
         *
         *   createOffer(fp)                 -> { sessionId, descriptor }
         *   createAnswer(fp, descriptor)    -> { sessionId, descriptor }
         *   acceptAnswer(sessionId, descriptor) -> void
         *   close(sessionId)                -> void
         *   linkFingerprint(sessionId)      -> string  (pairwise session's key fp)
         */
        this._mesh = mesh;

        this.identity = null;      // { keyPair, spki, fingerprint }
        this.epoch = 1;
        this.adminFp = '';
        this.phase = GROUP_PHASE.FORMING;

        /** fp -> { fp, name, spki, publicKey, sessionId, state } */
        this.members = new Map();
        /** sessionId -> fp, so an inbound frame can be attributed to a member. */
        this.sessionToFp = new Map();

        this.ceremony = null;
        this.sasCode = '';
        this.sasConfirmed = false;

        this.seq = 0;
        /**
         * Sender fingerprint -> Map(seq -> body hash). Does double duty: it
         * absorbs the duplicates that fan-out and relay inevitably produce, and
         * it is what catches a member sending two different bodies under one
         * sequence number. See _onMessage for why one structure has to do both.
         */
        this.transcript = new Map();

        this._timers = new Set();
        this._destroyed = false;
        /** Invitees the admin is still waiting on, by sessionId. */
        this._awaitingHello = new Map();

        /**
         * Commit and reveal frames that arrived before our own ceremony existed.
         *
         * Members start their ceremony when the roster reaches them, and the
         * roster does not reach everyone at the same instant — a member on a fast
         * link routinely broadcasts its commitment before a member on a slow one
         * has even adopted the roster. Dropping those frames deadlocks the round
         * for everyone, because the commit set never completes and the reveal
         * gate never opens. They are held here and drained when the ceremony
         * starts. Bounded, because the sender of these frames chooses how many to
         * send.
         */
        this._pendingCeremony = [];
        this._draining = false;

        /**
         * Member identity keys that arrived ahead of the roster that names them.
         *
         * A key frame on its own is an unverified claim, so nothing is applied
         * from here until the admin's signed roster says which fingerprints are
         * actually members. Bounded for the same reason as _pendingCeremony.
         */
        this._pendingKeys = new Map();

        /**
         * An in-flight "add members" round: which operation it is, the epoch it
         * will open, and who was already in the group when it started. Held so a
         * round that nobody answers can be abandoned without having touched the
         * epoch or the member set — the group carries on exactly as it was.
         */
        this._pendingAdd = null;

        /**
         * Mesh dials in flight, by peer fingerprint.
         *
         * fp -> { role, sessionId, nonce, epoch, timer }. One entry per PAIR,
         * never per direction: the dialling rule below means only one side of a
         * pair ever opens a dial, so a second entry for the same peer is a
         * duplicate to be refused rather than a second attempt to run.
         */
        this._meshDials = new Map();
        /** fp -> { attempts, nextAt }. Backoff for pairs that will not connect. */
        this._meshFailures = new Map();
        /** Sessions this group built itself, so destroy() can close them. */
        this._meshSessions = new Set();
        /** Sessions a probe has already been sent on, so it is sent once. */
        this._probed = new Set();
        /** The coalescing timer for _meshMaintain, or null when none is armed. */
        this._meshPass = null;
    }

    // -----------------------------------------------------------------------
    // lifecycle
    // -----------------------------------------------------------------------

    static newId() {
        return newGroupId();
    }

    async init() {
        if (this.identity) return this.identity;
        this.identity = await generateGroupIdentity(this.subtle);
        this.members.set(this.identity.fingerprint, {
            fp: this.identity.fingerprint,
            name: 'You',
            spki: this.identity.spki,
            publicKey: null, // our own key verifies nothing inbound
            sessionId: null,
            state: MEMBER_STATE.SELF,
        });
        if (this.isAdmin) this.adminFp = this.identity.fingerprint;
        return this.identity;
    }

    get selfFp() {
        return this.identity?.fingerprint || '';
    }

    destroy() {
        this._destroyed = true;
        for (const t of this._timers) clearTimeout(t);
        this._timers.clear();
        try { this.ceremony?.destroy(); } catch (_) {}
        this.ceremony = null;

        // Connections this group opened are this group's to close. They exist
        // nowhere in the app's chat list, so nothing else would ever reap them
        // and a torn-down group would leave live peer connections behind.
        for (const sessionId of this._meshSessions) {
            try { this._mesh?.close(sessionId); } catch (_) {}
        }
        this._meshSessions.clear();
        this._meshDials.clear();
        this._meshFailures.clear();
        this._probed.clear();

        this.members.clear();
        this.sessionToFp.clear();

        this.transcript.clear();
        this._pendingCeremony = [];
        this._pendingKeys.clear();
        this._pendingAdd = null;
        this.identity = null;
    }

    _timer(fn, ms) {
        const t = setTimeout(() => { this._timers.delete(t); if (!this._destroyed) fn(); }, ms);
        this._timers.add(t);
        return t;
    }

    _fail(code) {
        if (this._destroyed) return;
        this._log('warn', 'group ceremony failed', { code });
        this.phase = GROUP_PHASE.FAILED;
        try { this.ceremony?.destroy(); } catch (_) {}
        this.ceremony = null;
        this._emit('error', { error: code });
    }

    _setPhase(phase) {
        if (this.phase === phase) return;
        this.phase = phase;
        // Any phase other than READY means nothing is currently confirmed.
        if (phase !== GROUP_PHASE.READY) this.sasConfirmed = false;
        // The code itself only survives from the moment it is computed
        // (AWAITING_SAS) until the group leaves READY. Clearing it on the way
        // INTO AWAITING_SAS would erase the digits _maybeFinish just derived.
        if (phase !== GROUP_PHASE.READY && phase !== GROUP_PHASE.AWAITING_SAS) {
            this.sasCode = '';
        }
        this._emit('phase', { phase });
    }

    /** The member list in the shape the reducer stores. */
    _memberSnapshot() {
        return [...this.members.values()].map((m) => ({
            fp: m.fp, name: m.name, sessionId: m.sessionId, state: m.state,
        }));
    }

    _emitMembers() {
        this._emit('members', { members: this._memberSnapshot(), epoch: this.epoch });
    }

    // -----------------------------------------------------------------------
    // routing
    // -----------------------------------------------------------------------

    /** Members we can reach over their own pairwise link right now. */
    _directPeers() {
        return [...this.members.values()].filter(
            (m) => m.state === MEMBER_STATE.LINKED && m.sessionId,
        );
    }

    /**
     * Whoever can carry a frame to a member we cannot reach ourselves.
     *
     * The admin is preferred because by construction it holds a link to every
     * member; any other directly-linked member is a fallback for when the admin
     * is the one that has gone away.
     */
    _relayFor(toFp) {
        const admin = this.members.get(this.adminFp);
        if (admin && admin.state === MEMBER_STATE.LINKED && admin.sessionId && admin.fp !== toFp) {
            return admin;
        }
        return this._directPeers().find((m) => m.fp !== toFp) || null;
    }

    /**
     * Put a frame on the wire, wrapped.
     *
     * Every outbound frame goes through here so the envelope is applied in
     * exactly one place — a frame sent raw would be silently mangled by the
     * chat path's sanitiser rather than rejected, which is the worst way for
     * this to fail.
     */
    async _wire(sessionId, frame) {
        return this._send(sessionId, encodeEnvelope(frame));
    }

    /** Send one frame to one member, directly if we can and relayed if we cannot. */
    async _sendTo(toFp, frame) {
        const member = this.members.get(toFp);
        if (!member || member.fp === this.selfFp) return false;

        if (member.state === MEMBER_STATE.LINKED && member.sessionId) {
            await this._wire(member.sessionId, frame);
            return true;
        }
        const relay = this._relayFor(toFp);
        if (!relay) return false;
        await this._wire(relay.sessionId, {
            type: GROUP_FRAMES.RELAY,
            gid: this.groupId,
            to: toFp,
            hopped: false,
            inner: frame,
        });

        // A relay hop is unacknowledged — we hand the frame to a member who may
        // or may not be able to reach the target, and nothing comes back either
        // way. For a member we have never held a link to, that is simply the
        // normal path and the best that can be said. For one whose link we LOST,
        // it is a guess: reporting it as delivered would tell the sender their
        // message arrived when there is no reason to believe it did. The frame
        // still goes — the target may be reachable from elsewhere in the mesh —
        // it just does not count toward the delivery the sender is shown.
        return member.state !== MEMBER_STATE.LOST;
    }

    /**
     * Fan a frame out to every other member. Failures are per-recipient.
     *
     * Returns WHO could not be reached as well as how many could, because a
     * count on its own cannot tell "Alice is offline" from "Bob is offline" —
     * and the sender is the only person in a position to know the difference.
     */
    async _broadcast(frame, { exclude = [] } = {}) {
        const targets = [...this.members.keys()].filter(
            (fp) => fp !== this.selfFp && !exclude.includes(fp),
        );
        const results = await Promise.allSettled(targets.map((fp) => this._sendTo(fp, frame)));
        const unreachable = [];
        let delivered = 0;
        results.forEach((result, i) => {
            if (result.status === 'fulfilled' && result.value === true) {
                delivered += 1;
                return;
            }
            const member = this.members.get(targets[i]);
            unreachable.push({ fp: targets[i], name: member?.name || 'A member' });
        });
        return { delivered, unreachable };
    }

    // -----------------------------------------------------------------------
    // link bookkeeping (driven by the app as pairwise sessions come and go)
    // -----------------------------------------------------------------------

    /**
     * Bind a pairwise session to a member. Called for the admin's own invites and
     * whenever a member is reached over a session for the first time.
     */
    bindSession(fp, sessionId, state = MEMBER_STATE.LINKED) {
        const member = this.members.get(fp);
        if (!member) return false;
        // A member never holds two links at once. Rebinding to a new session —
        // a mesh dial that succeeded where an old link had dropped, or a chat
        // the user rebuilt by hand — has to drop the stale mapping, or a frame
        // arriving on the dead session id would still be attributed to them.
        if (member.sessionId && member.sessionId !== sessionId) {
            this.sessionToFp.delete(member.sessionId);
            this._closeMeshSession(member.sessionId);
        }
        member.sessionId = sessionId;
        member.state = state;
        if (sessionId) this.sessionToFp.set(sessionId, fp);
        this._emitMembers();
        return true;
    }

    /**
     * Detach a member from whatever link it was on, back to the relay path.
     *
     * Used when a mesh dial fails: the half-built session is closed and the
     * member returns to being reachable only through someone else, which is
     * where they were before the dial started. Deliberately does NOT change the
     * member's state to LOST — they are not offline, we just have no direct
     * route to them.
     */
    unbindSession(fp) {
        const member = this.members.get(fp);
        if (!member || !member.sessionId) return false;
        const sessionId = member.sessionId;
        this.sessionToFp.delete(sessionId);
        member.sessionId = null;
        if (member.state === MEMBER_STATE.LINKED || member.state === MEMBER_STATE.LOST) {
            member.state = MEMBER_STATE.PENDING;
        }
        this._closeMeshSession(sessionId);
        this._emitMembers();
        // The member has no route of their own now, so the mesh should look at
        // building one. This is what makes a link dying recoverable rather than
        // permanent: the pair goes back to the relay and dials again.
        this._scheduleMeshMaintain();
        return true;
    }

    /** A pairwise session changed state; reflect it on whichever member owns it. */
    setSessionState(sessionId, connected) {
        const fp = this.sessionToFp.get(sessionId);
        if (!fp) return;
        const member = this.members.get(fp);
        if (!member || member.state === MEMBER_STATE.SELF) return;
        const next = connected ? MEMBER_STATE.LINKED : MEMBER_STATE.LOST;
        if (member.state === next) return;
        member.state = next;
        this._emitMembers();

        // A dial that reached LINKED is finished; stop its timer before it fires
        // and tears down the very link it was guarding. A link that DROPPED is
        // also settled — the dial is over either way — but the failure counter
        // is left alone, because a link that worked and then died says nothing
        // about whether the pair can connect.
        if (connected) this._settleDial(fp);
        // Either edge changes the picture: a member who came up may be the relay
        // some other pair was waiting for, and a member who went down may have
        // been the only route to somebody.
        this._scheduleMeshMaintain();
    }

    // -----------------------------------------------------------------------
    // the mesh
    // -----------------------------------------------------------------------
    //
    // Every pair that has no link between it dials one, so that the relay path
    // becomes the exception it was always described as rather than the way the
    // whole group runs.
    //
    // WHO DIALS
    // ---------
    // The member with the smaller fingerprint. That is the entire glare
    // protocol: both sides compute it from the roster they already agree on, so
    // exactly one side opens each pair and there is no simultaneous-offer case
    // to resolve. A member that receives an offer from someone it should have
    // been dialling ITSELF refuses it — either the peer is confused or somebody
    // is trying to get two half-open dials fighting over one pair.
    //
    // WHEN
    // ----
    // Only once the group is READY and the safety code is confirmed. Before
    // that, the roster's identity keys are keys nobody has vouched for yet, and
    // a link authenticated by an unconfirmed key is a link authenticated by
    // nothing. Waiting costs a few seconds of relayed traffic.
    //
    // HOW IT IS AUTHENTICATED
    // -----------------------
    // The descriptors travel through a relay, so they are signed with the
    // sender's group identity key and checked against the roster — see
    // meshDescriptorPayload in groupCrypto.js for why that is enough and what
    // it deliberately does not defend against. Once the transport is up, the
    // SBQ2 in-band exchange runs on it exactly as it does for a 1:1 chat, with
    // one difference: nobody is asked to compare digits, because the group code
    // already authenticated the key that signed the descriptor. The app closes
    // that loop by marking the link verified on the group's authority.

    /**
     * Is this dial still worth finishing?
     *
     * Re-checked after EVERY await inside a dial, and that is not defensive
     * padding — both awaits are long. Building a descriptor means gathering ICE,
     * and verifying a signature is a trip through WebCrypto; either is ample time
     * for the answer to change.
     *
     * The case that made this necessary: a link probe adopts a chat the two
     * members already had while a dial for the same pair is mid-flight. The
     * probe binds a link that works. The dial then came back and bound its own
     * half-built session over the top, downgrading a live link to a pending one
     * and leaving the pair relaying to each other over a connection that was
     * never needed. Checking the member's session — not just our own dial
     * bookkeeping — is what catches that.
     */
    _dialStillWanted(fp, dial) {
        if (this._destroyed) return false;
        if (this._meshDials.get(fp) !== dial) return false;
        if (this.epoch !== dial.epoch) return false;
        const member = this.members.get(fp);
        if (!member) return false;
        if (member.sessionId && member.sessionId !== dial.sessionId) return false;
        return true;
    }

    /** Drop a dial that is no longer wanted, without recording it as a failure. */
    _abandonDial(fp, dial, sessionId) {
        if (this._meshDials.get(fp) === dial) {
            if (dial.timer) { clearTimeout(dial.timer); this._timers.delete(dial.timer); }
            this._meshDials.delete(fp);
        }
        this._meshSessions.delete(sessionId);
        try { this._mesh?.close(sessionId); } catch (_) {}
    }

    /** Close and forget a connection this group opened. Never touches a chat. */
    _closeMeshSession(sessionId) {
        if (!sessionId || !this._meshSessions.has(sessionId)) return;
        this._meshSessions.delete(sessionId);
        try { this._mesh?.close(sessionId); } catch (_) {}
    }

    /** A dial is over, one way or another. Stops its timer and frees the slot. */
    _settleDial(fp) {
        const dial = this._meshDials.get(fp);
        if (!dial) return;
        if (dial.timer) { clearTimeout(dial.timer); this._timers.delete(dial.timer); }
        this._meshDials.delete(fp);
        this._meshFailures.delete(fp);
    }

    /**
     * Give up on one pair, for now.
     *
     * The half-built connection is closed and the member goes back to being
     * reached through somebody else — which is where they were before the dial
     * started, so nothing the user can see gets worse. The backoff doubles per
     * attempt because a pair that cannot connect is usually a network that will
     * not allow it, and hammering at that produces load rather than links.
     */
    _meshFail(fp, code, { tellPeer = true } = {}) {
        const dial = this._meshDials.get(fp);
        if (dial) {
            if (dial.timer) { clearTimeout(dial.timer); this._timers.delete(dial.timer); }
            this._meshDials.delete(fp);
            const member = this.members.get(fp);
            // Only unbind if the member is still on THIS dial's session. If a
            // real link arrived in the meantime, it is not ours to tear down.
            if (dial.sessionId && member && member.sessionId === dial.sessionId) {
                this.unbindSession(fp);
            } else {
                this._closeMeshSession(dial.sessionId);
            }
        }

        const failure = this._meshFailures.get(fp) || { attempts: 0, nextAt: 0 };
        failure.attempts += 1;
        failure.nextAt = Date.now() + TIMEOUTS.MESH_RETRY_MS * 2 ** (failure.attempts - 1);
        this._meshFailures.set(fp, failure);
        this._log('warn', 'mesh dial failed', { code, attempts: failure.attempts });

        // Tell the peer so their half of the dial does not sit until it times
        // out. Best effort by definition — if we could reach them reliably we
        // would not be failing.
        if (tellPeer && this.members.has(fp)) {
            this._sendTo(fp, {
                type: GROUP_FRAMES.MESH_ABORT, gid: this.groupId, epoch: this.epoch,
                from: this.selfFp, to: fp,
            }).catch(() => {});
        }
        this._scheduleMeshMaintain();
    }

    /**
     * Cancel every dial in flight and forget every backoff.
     *
     * Called when the epoch moves. A dial signed against the old epoch will not
     * verify against the new one, and a pair that could not connect under the
     * old membership deserves a fresh chance under the new one. Links that are
     * already up are untouched — _onRoster carries them across.
     */
    _meshReset() {
        for (const fp of [...this._meshDials.keys()]) {
            const dial = this._meshDials.get(fp);
            if (dial?.timer) { clearTimeout(dial.timer); this._timers.delete(dial.timer); }
            this._meshDials.delete(fp);
            const member = this.members.get(fp);
            if (dial?.sessionId && member && member.sessionId === dial.sessionId) {
                this.unbindSession(fp);
            } else {
                this._closeMeshSession(dial?.sessionId);
            }
        }
        this._meshFailures.clear();
        this._probed.clear();
    }

    /**
     * Ask for a maintenance pass soon rather than now.
     *
     * Every edge that could change the answer calls this — a link coming up, a
     * dial failing, the code being confirmed — and several of them fire in a
     * burst. Coalescing them means one pass sees the settled picture instead of
     * several passes each acting on a half-updated one.
     */
    _scheduleMeshMaintain() {
        if (this._destroyed || !this._mesh || this._meshPass) return;
        this._meshPass = this._timer(() => {
            this._meshPass = null;
            this._meshMaintain();
        }, 0);
    }

    /** Open dials for whoever still has no link, within the concurrency limit. */
    _meshMaintain() {
        if (this._destroyed || !this._mesh) return;
        if (this.phase !== GROUP_PHASE.READY || !this.sasConfirmed) return;

        const now = Date.now();
        let inFlight = this._meshDials.size;
        let soonest = Infinity;

        // Fingerprint order, so every member walks the same list and the load of
        // being dialled is spread the same way everywhere.
        for (const fp of canonicalFingerprints([...this.members.keys()])) {
            if (inFlight >= MESH_MAX_CONCURRENT_DIALS) break;
            const member = this.members.get(fp);
            if (!member || member.state === MEMBER_STATE.SELF) continue;
            if (member.sessionId) continue;          // already on a link, or one is being built
            if (this._meshDials.has(fp)) continue;
            if (!(this.selfFp < fp)) continue;        // their turn to dial, not ours

            const failure = this._meshFailures.get(fp);
            if (failure) {
                if (failure.attempts >= MESH_MAX_ATTEMPTS) continue;
                if (now < failure.nextAt) { soonest = Math.min(soonest, failure.nextAt); continue; }
            }
            // Nothing can carry the offer, so there is no dial to make. When a
            // relay appears, that link coming up schedules another pass.
            if (!this._relayFor(fp)) continue;

            inFlight += 1;
            this._meshDial(fp).catch(() => {});
        }

        // Re-arm for the earliest pair whose backoff has not expired yet.
        if (soonest !== Infinity && !this._meshPass) {
            this._meshPass = this._timer(() => {
                this._meshPass = null;
                this._meshMaintain();
            }, Math.max(0, soonest - now) + 50);
        }
    }

    /** Build a descriptor for one peer, sign it, and put it on the relay path. */
    async _meshDial(fp) {
        const member = this.members.get(fp);
        if (!member || member.sessionId || this._meshDials.has(fp)) return;

        const epoch = this.epoch;
        const nonce = randomBytes(GROUP_LIMITS.MESH_NONCE_BYTES);
        // The slot is reserved BEFORE the first await. Creating an offer means
        // gathering ICE, which takes long enough for a second maintenance pass
        // to run and start a duplicate dial for the same peer.
        const dial = { role: 'offer', sessionId: null, nonce, epoch, timer: null };
        this._meshDials.set(fp, dial);

        try {
            const link = await this._mesh.createOffer(fp);
            const sessionId = link && link.sessionId;
            const descriptor = String((link && link.descriptor) || '');
            if (!sessionId || !descriptor) throw new GroupSessionError('mesh transport produced no descriptor', 'no_descriptor');

            // The world may have moved while ICE was gathering.
            if (!this._dialStillWanted(fp, dial)) return this._abandonDial(fp, dial, sessionId);
            dial.sessionId = sessionId;
            this._meshSessions.add(sessionId);
            // Bound now, as PENDING: it makes this member's link state
            // addressable the moment the transport reports in, and PENDING keeps
            // every frame on the relay path until it actually comes up.
            this.bindSession(fp, sessionId, MEMBER_STATE.PENDING);

            const sig = await signMeshDescriptor(this.subtle, this.identity.keyPair.privateKey, {
                groupId: this.groupId, epoch, kind: MESH_KINDS.OFFER,
                fromFp: this.selfFp, toFp: fp, descriptor, nonce,
            });
            const sent = await this._sendTo(fp, {
                type: GROUP_FRAMES.MESH_OFFER, gid: this.groupId, epoch,
                from: this.selfFp, to: fp, d: descriptor,
                n: toB64(nonce), sig: toB64(sig),
            });
            if (!sent) throw new GroupSessionError('no route to carry the dial', 'unreachable');

            dial.timer = this._timer(() => this._meshFail(fp, 'dial_timeout'), TIMEOUTS.MESH_DIAL_MS);
        } catch (error) {
            this._meshFail(fp, error?.code || 'dial_failed');
        }
    }

    async _onMeshOffer(frame) {
        if (!this._mesh || this._destroyed) return;
        const from = assertFingerprint(String(frame.from || ''));
        if (assertFingerprint(String(frame.to || '')) !== this.selfFp) return;
        if (assertEpoch(frame.epoch) !== this.epoch) return;
        if (this.phase !== GROUP_PHASE.READY || !this.sasConfirmed) return;

        const member = this.members.get(from);
        if (!member || !member.publicKey) {
            throw new GroupSessionError('mesh dial from a non-member', 'not_a_member');
        }
        if (member.sessionId) return;                 // already reachable directly
        if (this._meshDials.has(from)) return;        // one dial per pair
        // We are the smaller fingerprint, so dialling this pair is OUR job. An
        // offer arriving the wrong way round is refused rather than answered.
        if (this.selfFp < from) return;

        const descriptor = String(frame.d || '');
        if (!descriptor || descriptor.length > GROUP_LIMITS.MAX_DESCRIPTOR_CHARS) {
            throw new GroupSessionError('mesh descriptor is missing or oversized', 'bad_descriptor');
        }
        const nonce = fromB64(String(frame.n || ''), { max: GROUP_LIMITS.MESH_NONCE_BYTES });
        const ok = await verifyMeshDescriptor(this.subtle, member.publicKey, {
            groupId: this.groupId, epoch: this.epoch, kind: MESH_KINDS.OFFER,
            fromFp: from, toFp: this.selfFp, descriptor, nonce,
        }, fromB64(String(frame.sig || ''), { max: GROUP_LIMITS.MAX_SIG_BYTES }));
        if (!ok) throw new GroupSessionError('mesh dial signature did not verify', 'bad_signature');

        // Re-checked after the signature work: verifying is a trip through
        // WebCrypto, and a probe can adopt an existing chat for this member in
        // that window. Answering then would build a second connection to
        // somebody we are already talking to.
        if (this._destroyed || member.sessionId || this._meshDials.has(from)) return;
        if (assertEpoch(frame.epoch) !== this.epoch) return;

        const epoch = this.epoch;
        const dial = { role: 'answer', sessionId: null, nonce, epoch, timer: null };
        this._meshDials.set(from, dial);

        try {
            const link = await this._mesh.createAnswer(from, descriptor);
            const sessionId = link && link.sessionId;
            const answer = String((link && link.descriptor) || '');
            if (!sessionId || !answer) throw new GroupSessionError('mesh transport produced no answer', 'no_descriptor');

            if (!this._dialStillWanted(from, dial)) return this._abandonDial(from, dial, sessionId);
            dial.sessionId = sessionId;
            this._meshSessions.add(sessionId);
            this.bindSession(from, sessionId, MEMBER_STATE.PENDING);

            const sig = await signMeshDescriptor(this.subtle, this.identity.keyPair.privateKey, {
                groupId: this.groupId, epoch, kind: MESH_KINDS.ANSWER,
                fromFp: this.selfFp, toFp: from, descriptor: answer, nonce,
            });
            const sent = await this._sendTo(from, {
                type: GROUP_FRAMES.MESH_ANSWER, gid: this.groupId, epoch,
                from: this.selfFp, to: from, d: answer,
                n: toB64(nonce), sig: toB64(sig),
            });
            if (!sent) throw new GroupSessionError('no route to carry the answer', 'unreachable');

            dial.timer = this._timer(() => this._meshFail(from, 'answer_timeout'), TIMEOUTS.MESH_DIAL_MS);
        } catch (error) {
            this._meshFail(from, error?.code || 'answer_failed');
        }
    }

    async _onMeshAnswer(frame) {
        if (!this._mesh || this._destroyed) return;
        const from = assertFingerprint(String(frame.from || ''));
        if (assertFingerprint(String(frame.to || '')) !== this.selfFp) return;
        if (assertEpoch(frame.epoch) !== this.epoch) return;

        const dial = this._meshDials.get(from);
        if (!dial || dial.role !== 'offer' || !dial.sessionId || dial.epoch !== this.epoch) return;

        const member = this.members.get(from);
        if (!member || !member.publicKey) {
            throw new GroupSessionError('mesh answer from a non-member', 'not_a_member');
        }

        const descriptor = String(frame.d || '');
        if (!descriptor || descriptor.length > GROUP_LIMITS.MAX_DESCRIPTOR_CHARS) {
            throw new GroupSessionError('mesh descriptor is missing or oversized', 'bad_descriptor');
        }
        // The nonce we generated for THIS dial, or the answer belongs to another
        // attempt and is being replayed into this one.
        const nonce = fromB64(String(frame.n || ''), { max: GROUP_LIMITS.MESH_NONCE_BYTES });
        if (nonce.length !== dial.nonce.length || !nonce.every((b, i) => b === dial.nonce[i])) {
            throw new GroupSessionError('mesh answer does not match the dial it claims', 'bad_mesh_nonce');
        }

        const ok = await verifyMeshDescriptor(this.subtle, member.publicKey, {
            groupId: this.groupId, epoch: this.epoch, kind: MESH_KINDS.ANSWER,
            fromFp: from, toFp: this.selfFp, descriptor, nonce,
        }, fromB64(String(frame.sig || ''), { max: GROUP_LIMITS.MAX_SIG_BYTES }));
        if (!ok) throw new GroupSessionError('mesh answer signature did not verify', 'bad_signature');

        try {
            await this._mesh.acceptAnswer(dial.sessionId, descriptor);
        } catch (error) {
            this._meshFail(from, error?.code || 'answer_rejected');
        }
        // From here the transport finishes its own handshake; the link is
        // declared up by setSessionState when it does.
    }

    _onMeshAbort(frame) {
        const from = assertFingerprint(String(frame.from || ''));
        if (assertFingerprint(String(frame.to || '')) !== this.selfFp) return;
        if (!this._meshDials.has(from)) return;
        // No abort back — that is how two peers keep telling each other to stop.
        this._meshFail(from, 'peer_aborted', { tellPeer: false });
    }

    // -----------------------------------------------------------------------
    // link probes
    // -----------------------------------------------------------------------

    /**
     * Claim a pairwise chat we already hold as this group's link to a member.
     *
     * Two people who were already talking do not need a second connection built
     * between them, and dialling one anyway would spend a WebRTC negotiation to
     * arrive back where we started. The app calls this for every verified chat
     * that is not already carrying a member; whoever is on the other end and is
     * in this group binds it, and the pair is meshed without dialling anything.
     *
     * Sent once per session per epoch. It is a claim about identity, not a
     * request, so there is nothing to retry.
     */
    async probeSession(sessionId) {
        if (this._destroyed || !this._mesh || !sessionId) return false;
        if (this.phase !== GROUP_PHASE.READY || !this.sasConfirmed) return false;
        if (this.sessionToFp.has(sessionId)) return false;
        return this._sendProbe(sessionId);
    }

    /**
     * Sign and send one probe. Once per session per epoch, whatever asked for it.
     *
     * Split from probeSession because the two callers disagree about one check:
     * the app only offers sessions that carry nobody, while an ANSWERING probe
     * goes out on a session that has just been bound — by the very probe it is
     * answering.
     */
    async _sendProbe(sessionId) {
        if (this._destroyed || this._probed.has(sessionId)) return false;
        const linkFp = this._linkFingerprint(sessionId);
        if (!linkFp) return false;

        this._probed.add(sessionId);
        const sig = await signLinkProbe(this.subtle, this.identity.keyPair.privateKey, {
            groupId: this.groupId, epoch: this.epoch, fp: this.selfFp, linkFp,
        });
        await this._wire(sessionId, {
            type: GROUP_FRAMES.PROBE, gid: this.groupId, epoch: this.epoch,
            fp: this.selfFp, sig: toB64(sig),
        });
        return true;
    }

    _linkFingerprint(sessionId) {
        try {
            const fp = this._mesh?.linkFingerprint?.(sessionId);
            return typeof fp === 'string' && fp.length > 0 ? fp : '';
        } catch (_) {
            return '';
        }
    }

    async _onProbe(sessionId, frame) {
        if (this._destroyed) return;
        if (this.phase !== GROUP_PHASE.READY || !this.sasConfirmed) return;
        if (assertEpoch(frame.epoch) !== this.epoch) return;

        const fp = assertFingerprint(String(frame.fp || ''));
        if (fp === this.selfFp) return;
        const member = this.members.get(fp);
        if (!member || !member.publicKey) return;
        if (this.sessionToFp.has(sessionId)) return;  // this session carries someone else

        if (member.sessionId) {
            // A link that is already carrying traffic is not replaced.
            if (member.state === MEMBER_STATE.LINKED) return;
            // But a dial still being built loses to a chat that already works.
            // The dial is abandoned below; bindSession closes its half-open
            // connection. Without this the probe would arrive a moment too late
            // and we would finish building a second connection to somebody we
            // were already talking to.
            if (!this._meshDials.has(fp)) return;
        }

        // The fingerprint of the session the probe ARRIVED on, read locally.
        // Taking it from the frame would defeat the whole point — see
        // linkProbePayload for what this binding is defending against.
        const linkFp = this._linkFingerprint(sessionId);
        if (!linkFp) return;

        const ok = await verifyLinkProbe(this.subtle, member.publicKey, {
            groupId: this.groupId, epoch: this.epoch, fp, linkFp,
        }, fromB64(String(frame.sig || ''), { max: GROUP_LIMITS.MAX_SIG_BYTES }));
        if (!ok) throw new GroupSessionError('link probe signature did not verify', 'bad_signature');

        // A probe only ever arrives on a link that is already up and verified —
        // it travelled over it — so this one is LINKED, not PENDING.
        this._settleDial(fp);
        this.bindSession(fp, sessionId, MEMBER_STATE.LINKED);

        // Answer in kind, or the adoption is one-sided. The peer now routes to
        // us over this link, but we are the only ones who know that: without a
        // probe back they never learn who is on their end, and they would go on
        // relaying to us through somebody else forever. The once-per-session
        // guard in _sendProbe is what stops the two sides answering each other
        // indefinitely.
        this._sendProbe(sessionId).catch(() => { /* the link works either way */ });

        this._scheduleMeshMaintain();
    }

    // -----------------------------------------------------------------------
    // step 1-2: invite / hello
    // -----------------------------------------------------------------------

    /**
     * Admin: invite peers we already hold verified 1:1 sessions with.
     * @param {{sessionId: string, name: string}[]} peers
     */
    async invite(peers) {
        if (!this.isAdmin) throw new GroupSessionError('only the admin invites', 'not_admin');
        await this.init();
        if (peers.length + 1 > GROUP_LIMITS.MAX_MEMBERS) {
            throw new GroupSessionError(`a group is limited to ${GROUP_LIMITS.MAX_MEMBERS} members`, 'too_many_members');
        }
        this._setPhase(GROUP_PHASE.FORMING);

        for (const peer of peers) this._awaitingHello.set(peer.sessionId, peer.name || 'Member');

        const frame = {
            type: GROUP_FRAMES.INVITE,
            gid: this.groupId,
            epoch: this.epoch,
            name: this.name,
            adminSpki: toB64(this.identity.spki),
        };

        // Report what actually left the device.
        //
        // Swallowing these failures turned a dead link into forty-five seconds of
        // nothing followed by a generic timeout, which is indistinguishable from
        // an invitee who simply has not answered. A send that fails for everyone
        // failed now, and saying so now is the difference between a bug someone
        // can act on and a group that mysteriously never forms.
        const results = await Promise.allSettled(peers.map((p) => this._wire(p.sessionId, frame)));
        const failed = results.filter((r) => r.status === 'rejected');
        if (failed.length === peers.length) {
            this._fail('invitations_could_not_be_sent');
            throw new GroupSessionError(
                'the invitation could not be sent — the chat with that peer is not connected',
                'invitations_could_not_be_sent',
            );
        }
        if (failed.length > 0) {
            // Some links are down. Those invitees will never send a hello, so the
            // roster would wait on them forever; drop them from the round.
            const reachable = peers.filter((_, i) => results[i].status === 'fulfilled');
            for (const p of peers) {
                if (!reachable.includes(p)) this._awaitingHello.delete(p.sessionId);
            }
            this._emit('partial_invite', { sent: reachable.length, total: peers.length });
        }

        this._timer(() => {
            if (this.phase === GROUP_PHASE.FORMING) this._fail('invitees_did_not_respond');
        }, TIMEOUTS.HELLO_MS);
    }

    /** Invitee: adopt an invitation and publish our own identity key back. */
    async acceptInvite(sessionId, envelope) {
        // The app receives an invitation before any group exists to decode it
        // with, so it may hand back either the envelope or the frame inside.
        const frame = decodeEnvelope(envelope);
        await this.init();
        const adminSpki = fromB64(String(frame.adminSpki || ''));
        const { publicKey, fingerprint } = await importMemberIdentity(this.subtle, adminSpki);
        this.adminFp = fingerprint;
        this.epoch = assertEpoch(frame.epoch);
        this.name = assertName(frame.name);

        this.members.set(fingerprint, {
            fp: fingerprint,
            name: 'Admin',
            spki: adminSpki,
            publicKey,
            sessionId,
            state: MEMBER_STATE.LINKED,
        });
        this.sessionToFp.set(sessionId, fingerprint);
        this._setPhase(GROUP_PHASE.FORMING);
        this._emitMembers();

        await this._wire(sessionId, {
            type: GROUP_FRAMES.HELLO,
            gid: this.groupId,
            epoch: this.epoch,
            spki: toB64(this.identity.spki),
        });

        this._timer(() => {
            if (this.phase === GROUP_PHASE.FORMING) this._fail('roster_never_arrived');
        }, TIMEOUTS.HELLO_MS);
    }

    async _onHello(sessionId, frame) {
        if (!this.isAdmin) return; // only the admin collects identity keys

        // A hello is only ever an ANSWER to an invitation this admin sent, on
        // the very session it was sent over. Without that check the frame is an
        // open door: any member — or anyone else who holds a verified chat with
        // the admin and has learnt the group id — could publish an identity key
        // the admin never invited, and the branch at the end of this method
        // would then sign and broadcast a roster containing it. "Only the admin
        // invites" has to be enforced here, because this is the only place a
        // member is created from something that arrived on the wire.
        //
        // It also confines the frame to a DIRECT link. A hello can be wrapped in
        // a relay and handed to the admin by a third party, and _onRelay hands
        // the inner frame on with the RELAY's session id — which is never a
        // session an invitation went out on, so such a frame lands here and
        // stops.
        if (!this._awaitingHello.has(sessionId)) {
            this._log('warn', 'dropped an unsolicited group hello', { groupId: this.groupId });
            return;
        }

        const spki = fromB64(String(frame.spki || ''));
        const { publicKey, fingerprint } = await importMemberIdentity(this.subtle, spki);
        if (this.members.has(fingerprint) && fingerprint !== this.selfFp) return;
        if (this.members.size >= GROUP_LIMITS.MAX_MEMBERS) throw new GroupSessionError('group is full', 'too_many_members');

        this.members.set(fingerprint, {
            fp: fingerprint,
            name: this._awaitingHello.get(sessionId) || 'Member',
            spki,
            publicKey,
            sessionId,
            state: MEMBER_STATE.LINKED,
        });
        this.sessionToFp.set(sessionId, fingerprint);
        this._awaitingHello.delete(sessionId);
        this._emitMembers();

        if (this._awaitingHello.size === 0) {
            if (this._pendingAdd) return this._finishAdd();
            await this.publishRoster(MEMBER_OPS.CREATE);
        }
    }

    // -----------------------------------------------------------------------
    // step 3: the signed roster
    // -----------------------------------------------------------------------

    /** Admin: sign the current member set for this epoch and broadcast it. */
    async publishRoster(op = MEMBER_OPS.ADD) {
        if (!this.isAdmin) throw new GroupSessionError('only the admin publishes the roster', 'not_admin');
        const memberFps = canonicalFingerprints([...this.members.keys()]);
        const fields = { groupId: this.groupId, epoch: this.epoch, op, memberFps, name: this.name };
        const sig = await signMemberOp(this.subtle, this.identity.keyPair.privateKey, fields);

        // Member keys go out one frame each, BEFORE the roster that names them.
        //
        // They cannot ride inside the roster: eight members' SPKI would put the
        // frame past the 2000-character ceiling the chat path truncates at, and a
        // truncated roster fails in the most confusing way possible. Splitting
        // them costs nothing in security, because the signed roster commits to
        // the FINGERPRINTS — a key that arrives separately is checked against the
        // fingerprint it claims, so a substituted key is refused whichever frame
        // carried it.
        for (const fp of memberFps) {
            const m = this.members.get(fp);
            await this._broadcast({
                type: GROUP_FRAMES.MEMBER,
                gid: this.groupId,
                epoch: this.epoch,
                fp,
                name: m.name === 'You' ? 'Admin' : m.name,
                spki: toB64(m.spki),
            });
        }

        await this._broadcast({
            type: GROUP_FRAMES.ROSTER,
            gid: this.groupId,
            epoch: this.epoch,
            op,
            name: this.name,
            adminSpki: toB64(this.identity.spki),
            members: memberFps,
            sig: toB64(sig),
        });
        await this._startCeremony();
    }

    /**
     * A member's identity key, published ahead of the roster that names them.
     *
     * Held in a staging area rather than applied: until the admin's signed roster
     * arrives, a key frame is an unverified claim about who is in the group. The
     * fingerprint is derived from the bytes, never taken from the frame, so a
     * member cannot register a key under someone else's name.
     */
    async _onMemberKey(frame) {
        const epoch = assertEpoch(frame.epoch);
        if (epoch < this.epoch) return;
        if (this._pendingKeys.size > GROUP_LIMITS.MAX_MEMBERS * 2) return;

        const spki = fromB64(String(frame.spki || ''));
        const { publicKey, fingerprint } = await importMemberIdentity(this.subtle, spki);
        if (assertFingerprint(String(frame.fp || '')) !== fingerprint) {
            throw new GroupSessionError('member key does not match its fingerprint', 'fingerprint_mismatch');
        }
        this._pendingKeys.set(fingerprint, { spki, publicKey, name: assertName(frame.name) });
    }

    /**
     * Member: adopt a roster.
     *
     * The admin's signature is checked against the key whose fingerprint IS the
     * admin fingerprint we recorded at invite time — not against whatever key the
     * frame happens to carry — so a member cannot promote itself by attaching its
     * own key to a roster. The epoch must move forward, which refuses both a
     * replay and a rollback to a membership that used to be valid.
     */
    async _onRoster(sessionId, frame) {
        const epoch = assertEpoch(frame.epoch);
        if (this.isAdmin) return; // we authored it
        if (epoch < this.epoch) throw new GroupSessionError('roster epoch went backwards', 'stale_epoch');

        const adminSpki = fromB64(String(frame.adminSpki || ''));
        const { publicKey: adminKey, fingerprint: adminFp } = await importMemberIdentity(this.subtle, adminSpki);
        if (this.adminFp && adminFp !== this.adminFp) {
            throw new GroupSessionError('roster was signed by someone other than the admin', 'wrong_admin');
        }

        if (!Array.isArray(frame.members)) throw new GroupSessionError('roster carries no member list', 'bad_roster');
        if (frame.members.length > GROUP_LIMITS.MAX_MEMBERS) throw new GroupSessionError('roster exceeds the member limit', 'too_many_members');

        const memberFps = canonicalFingerprints(frame.members.map((fp) => String(fp || '')));
        if (!memberFps.includes(this.selfFp)) throw new GroupSessionError('roster does not include us', 'not_a_member');
        if (!memberFps.includes(adminFp)) throw new GroupSessionError('roster does not include its author', 'bad_roster');

        // Match each named member to the key frame that arrived ahead of the
        // roster. A member the admin names but whose key never arrived is a
        // member we could not verify a single message from, so the roster is
        // refused outright rather than adopted with a hole in it.
        const imported = [];
        for (const fp of memberFps) {
            if (fp === this.selfFp) {
                imported.push({ fp, name: 'You', spki: this.identity.spki, publicKey: null });
                continue;
            }
            const staged = this._pendingKeys.get(fp) || (fp === adminFp
                ? { spki: adminSpki, publicKey: adminKey, name: 'Admin' }
                : null);
            if (!staged) throw new GroupSessionError('roster names a member whose key never arrived', 'missing_member_key');
            imported.push({ fp, name: staged.name, spki: staged.spki, publicKey: staged.publicKey });
        }

        const ok = await verifyMemberOp(this.subtle, adminKey, {
            groupId: this.groupId, epoch, op: String(frame.op || ''),
            memberFps, name: assertName(frame.name),
        }, fromB64(String(frame.sig || ''), { max: GROUP_LIMITS.MAX_SIG_BYTES }));
        if (!ok) throw new GroupSessionError('roster signature did not verify', 'bad_signature');

        // Adopt. Existing links are preserved: the session we already hold with
        // the admin (and with anyone else) stays bound to the same fingerprint.
        this.epoch = epoch;
        this.name = assertName(frame.name);
        this.adminFp = adminFp;

        const previous = this.members;
        this.members = new Map();
        for (const m of imported) {
            const old = previous.get(m.fp);
            this.members.set(m.fp, {
                fp: m.fp,
                name: m.fp === this.selfFp ? 'You' : m.name,
                spki: m.spki,
                publicKey: m.fp === this.selfFp ? null : m.publicKey,
                sessionId: old?.sessionId || null,
                state: m.fp === this.selfFp ? MEMBER_STATE.SELF
                    : (old?.state === MEMBER_STATE.LINKED ? MEMBER_STATE.LINKED : MEMBER_STATE.PENDING),
            });
        }
        // Drop session bindings for members who left.
        for (const [sid, fp] of [...this.sessionToFp]) {
            if (!this.members.has(fp)) this.sessionToFp.delete(sid);
        }

        this._emit('roster', { name: this.name, epoch: this.epoch, adminFp });
        this._emitMembers();
        await this._startCeremony();
    }

    // -----------------------------------------------------------------------
    // steps 4-6: the safety code ceremony
    // -----------------------------------------------------------------------

    async _startCeremony() {
        try { this.ceremony?.destroy(); } catch (_) {}
        // A new round means a new epoch, and every dial in flight was signed
        // against the old one. Abandon them rather than let them arrive as
        // signatures that cannot verify; links already up are kept.
        this._meshReset();
        this.ceremony = new GroupSasCeremony({
            groupId: this.groupId,
            epoch: this.epoch,
            selfFingerprint: this.selfFp,
            memberFingerprints: [...this.members.keys()],
        });
        this._setPhase(GROUP_PHASE.COMMITTING);

        const commitment = await this.ceremony.ownCommitment(this.subtle);

        // Our commitment goes out BEFORE anything held is replayed, and the order
        // is load-bearing.
        //
        // Draining first can complete the commit round on the spot — every peer
        // commitment may already be waiting — which reveals our nonce and puts a
        // reveal on the wire ahead of our own commitment. A peer then has a reveal
        // it cannot check yet and has to hold it until our commitment turns up,
        // so the round only completes if that one later frame arrives. It made
        // correctness depend on a peer's buffer instead of on the protocol, and a
        // single dropped commitment left every member waiting on a nonce that had
        // already been sent.
        await this._broadcast({
            type: GROUP_FRAMES.COMMIT,
            gid: this.groupId,
            epoch: this.epoch,
            fp: this.selfFp,
            commit: toB64(commitment),
        });

        const epochAtStart = this.epoch;
        this._timer(() => {
            if (this.epoch !== epochAtStart) return;
            if (this.phase === GROUP_PHASE.COMMITTING || this.phase === GROUP_PHASE.REVEALING) {
                this._fail('ceremony_timed_out');
            }
        }, TIMEOUTS.CEREMONY_MS);

        // Only now replay what arrived before this ceremony existed. Our
        // commitment is already on the wire, so a reveal this produces can never
        // outrun it.
        await this._drainPendingCeremony();
        await this._maybeReveal();
    }

    /** Hold a ceremony frame that outran our own roster. See _pendingCeremony. */
    _holdCeremonyFrame(frame) {
        // Two frames per member per epoch is all that can legitimately be
        // outstanding; the cap keeps a chatty member from growing this without
        // bound while we wait for a roster.
        if (this._pendingCeremony.length >= GROUP_LIMITS.MAX_MEMBERS * 2) return;
        this._pendingCeremony.push(frame);
    }

    async _drainPendingCeremony() {
        // Re-entrancy guard: draining calls the same handlers that hold frames,
        // and a frame that is still premature is put back for the next drain.
        if (this._draining) return;
        this._draining = true;
        try {
            const held = this._pendingCeremony;
            this._pendingCeremony = [];
            for (const frame of held) {
                try {
                    if (frame.type === GROUP_FRAMES.COMMIT) await this._onCommit(frame);
                    else if (frame.type === GROUP_FRAMES.REVEAL) await this._onReveal(frame);
                } catch (error) {
                    // A held frame that no longer makes sense (wrong epoch, a
                    // member dropped from the roster) is discarded, not fatal.
                    this._log('warn', 'held ceremony frame discarded', { code: error?.code });
                }
            }
        } finally {
            this._draining = false;
        }
    }

    async _onCommit(frame) {
        if (!this.ceremony) return this._holdCeremonyFrame(frame);
        if (assertEpoch(frame.epoch) !== this.epoch) return;
        this.ceremony.acceptCommitment(
            assertFingerprint(String(frame.fp || '')),
            fromB64(String(frame.commit || ''), { max: GROUP_LIMITS.COMMIT_BYTES }),
        );
        // A reveal we had to hold may now have the commitment it needs.
        await this._drainPendingCeremony();
        await this._maybeReveal();
    }

    /**
     * Publish our nonce, but only once every commitment is in.
     *
     * The check lives in GroupSasCeremony.reveal(), which throws otherwise. This
     * method only asks whether the round is complete — it must never be changed
     * to reveal on a timer or on a partial round.
     */
    async _maybeReveal() {
        if (!this.ceremony || this.ceremony.revealed) return;
        if (!this.ceremony.commitmentsComplete) return;

        this._setPhase(GROUP_PHASE.REVEALING);
        const nonce = this.ceremony.reveal();
        await this._broadcast({
            type: GROUP_FRAMES.REVEAL,
            gid: this.groupId,
            epoch: this.epoch,
            fp: this.selfFp,
            nonce: toB64(nonce),
        });
        await this._maybeFinish();
    }

    async _onReveal(frame) {
        if (!this.ceremony) return this._holdCeremonyFrame(frame);
        if (assertEpoch(frame.epoch) !== this.epoch) return;
        // A reveal can also outrun the commitment it opens, on a link where the
        // two frames took different paths. Hold it rather than failing the
        // ceremony for an ordering the network chose.
        if (!this.ceremony.commitments.has(assertFingerprint(String(frame.fp || '')))) {
            return this._holdCeremonyFrame(frame);
        }
        await this.ceremony.acceptReveal(
            this.subtle,
            assertFingerprint(String(frame.fp || '')),
            fromB64(String(frame.nonce || ''), { max: GROUP_LIMITS.NONCE_BYTES }),
        );
        await this._maybeFinish();
    }

    async _maybeFinish() {
        if (!this.ceremony || !this.ceremony.revealsComplete) return;
        // Reached from both _onReveal and _maybeReveal, so it must be idempotent:
        // the round produces one code and computing it twice is not an error.
        if (this.sasCode) return;
        const code = await this.ceremony.finish(this.subtle);
        this._setPhase(GROUP_PHASE.AWAITING_SAS);
        this.sasCode = code;
        this._emit('sas', { code });
    }

    /**
     * The humans compared the digits and they matched.
     *
     * This is the only path to READY, and it is driven by a user action — never
     * by a frame arriving. It mirrors the 1:1 rule: completing a handshake proves
     * somebody completed it, and only the out-of-band comparison proves who.
     */
    confirmSas() {
        if (this.phase !== GROUP_PHASE.AWAITING_SAS || !this.sasCode) {
            throw new GroupSessionError('there is no group code to confirm', 'no_code');
        }
        this.sasConfirmed = true;
        this.phase = GROUP_PHASE.READY;
        try { this.ceremony?.destroy(); } catch (_) {}
        this.ceremony = null;
        this._emit('confirmed', { members: this._memberSnapshot() });
        // The moment the human vouches for the code, the roster's identity keys
        // become keys worth authenticating a transport with. This is the gate
        // the whole mesh waits behind.
        this._scheduleMeshMaintain();
    }

    /** Recompute the code for the current epoch — used only by tests and diagnostics. */
    async _recomputeSas(contributions) {
        return computeGroupSas(this.subtle, {
            groupId: this.groupId, epoch: this.epoch, contributions,
        });
    }

    // -----------------------------------------------------------------------
    // step 7: messages
    // -----------------------------------------------------------------------

    async sendText(text) {
        if (this.phase !== GROUP_PHASE.READY || !this.sasConfirmed) {
            throw new GroupSessionError('the group code has not been confirmed', 'not_ready');
        }
        const body = String(text ?? '');
        if (!body.trim()) throw new GroupSessionError('empty message', 'empty');

        const seq = ++this.seq;
        const bodyHash = await hashBody(this.subtle, body);
        const sig = await signGroupMessage(this.subtle, this.identity.keyPair.privateKey, {
            groupId: this.groupId, epoch: this.epoch, seq, senderFp: this.selfFp, bodyHash,
        });

        const frame = {
            type: GROUP_FRAMES.MESSAGE,
            gid: this.groupId,
            epoch: this.epoch,
            seq,
            fp: this.selfFp,
            ts: Date.now(),
            body,
            sig: toB64(sig),
        };
        const { delivered, unreachable } = await this._broadcast(frame);
        return { seq, delivered, total: this.members.size - 1, unreachable };
    }

    async _onMessage(frame, { relayed = false } = {}) {
        const epoch = assertEpoch(frame.epoch);
        const seq = assertEpoch(frame.seq);
        const senderFp = assertFingerprint(String(frame.fp || ''));

        if (senderFp === this.selfFp) return; // our own frame came back around
        const member = this.members.get(senderFp);
        if (!member || !member.publicKey) throw new GroupSessionError('message from a non-member', 'not_a_member');

        // A message from an epoch we have left is not applied: its signature is
        // valid but it belongs to a membership that no longer holds.
        if (epoch !== this.epoch) throw new GroupSessionError('message from another epoch', 'stale_epoch');

        const body = String(frame.body ?? '');
        const bodyHash = await hashBody(this.subtle, body);
        const ok = await verifyGroupMessage(this.subtle, member.publicKey, {
            groupId: this.groupId, epoch, seq, senderFp, bodyHash,
        }, fromB64(String(frame.sig || ''), { max: GROUP_LIMITS.MAX_SIG_BYTES }));
        if (!ok) throw new GroupSessionError('message signature did not verify', 'bad_signature');

        // Transcript consistency AND duplicate suppression, in that order —
        // which is the whole point. Fan-out plus relay means the same frame
        // legitimately arrives twice, so a repeat has to be absorbed silently.
        // But "same sender, same sequence number" is NOT enough to call something
        // a duplicate: a member telling two halves of the group different things
        // does exactly that, and deduplicating on the key alone would hide the
        // split this record exists to catch. The body hash is what separates the
        // two cases.
        const byMember = this.transcript.get(senderFp) || new Map();
        const hashHex = toB64(bodyHash);
        const previous = byMember.get(seq);
        if (previous !== undefined) {
            if (previous === hashHex) return; // the same message, arriving again
            this._emit('inconsistency', { fp: senderFp, seq, name: member.name });
            throw new GroupSessionError('member sent conflicting messages under one sequence number', 'transcript_split');
        }

        byMember.set(seq, hashHex);
        // Bounded per sender. The pairwise ratchet already refuses genuinely old
        // frames, so this window only has to outlast fan-out and one relay hop.
        if (byMember.size > 512) byMember.delete(byMember.keys().next().value);
        this.transcript.set(senderFp, byMember);

        this._emit('message', {
            fp: senderFp,
            name: member.name,
            body,
            seq,
            ts: Number.isFinite(frame.ts) ? frame.ts : Date.now(),
            // Whether this particular copy came straight from its author or was
            // carried by another member. Worth showing: a relayed message is one
            // a third member knew the timing of, and the reader is the only one
            // in a position to notice that is still happening.
            relayed,
        });
    }

    // -----------------------------------------------------------------------
    // inbound dispatch
    // -----------------------------------------------------------------------

    /**
     * Handle one frame that arrived on a pairwise session.
     *
     * Everything here is attacker-supplied in the sense that matters: it comes
     * from a verified peer, but a group member is only as trustworthy as the
     * group makes them. Types are matched against an explicit list and anything
     * unrecognised is dropped rather than passed on.
     */
    async handleFrame(sessionId, envelope, { relayed = false } = {}) {
        if (this._destroyed) return;
        if (!isGroupFrame(envelope)) return;
        const frame = decodeEnvelope(envelope);
        if (!frame || !GROUP_FRAME_TYPES.has(frame.type)) return;
        if (assertGroupId(String(frame.gid || '')) !== this.groupId) return;

        switch (frame.type) {
            case GROUP_FRAMES.RELAY:
                return this._onRelay(sessionId, frame);
            case GROUP_FRAMES.HELLO:
                return this._onHello(sessionId, frame);
            case GROUP_FRAMES.MEMBER:
                return this._onMemberKey(frame);
            case GROUP_FRAMES.ROSTER:
                return this._onRoster(sessionId, frame);
            case GROUP_FRAMES.COMMIT:
                return this._onCommit(frame);
            case GROUP_FRAMES.REVEAL:
                return this._onReveal(frame);
            case GROUP_FRAMES.MESSAGE:
                return this._onMessage(frame, { relayed });
            case GROUP_FRAMES.LEAVE:
                return this._onLeave(frame);
            case GROUP_FRAMES.MESH_OFFER:
                return this._onMeshOffer(frame);
            case GROUP_FRAMES.MESH_ANSWER:
                return this._onMeshAnswer(frame);
            case GROUP_FRAMES.MESH_ABORT:
                return this._onMeshAbort(frame);
            case GROUP_FRAMES.PROBE:
                // A probe is a claim about the link it arrived on, so it is only
                // meaningful on a direct one. Relayed, it says nothing.
                return relayed ? undefined : this._onProbe(sessionId, frame);
            case GROUP_FRAMES.INVITE:
                return; // handled by the app, which decides whether to join at all
            default:
                return;
        }
    }

    /**
     * Single-hop relay.
     *
     * A frame addressed to us is unwrapped and handled. A frame addressed to
     * someone else is forwarded exactly once — `hopped` makes a second forward
     * impossible, so there is no loop to form and no path to lengthen.
     */
    async _onRelay(sessionId, frame) {
        const to = assertFingerprint(String(frame.to || ''));
        const inner = frame.inner;
        if (!isGroupFrame(inner)) return;
        if (inner.type === GROUP_FRAMES.RELAY) return; // never nest

        if (to === this.selfFp) return this.handleFrame(sessionId, inner, { relayed: true });
        if (frame.hopped === true) return; // already relayed once; do not forward again

        const member = this.members.get(to);
        if (!member || member.state !== MEMBER_STATE.LINKED || !member.sessionId) return;
        await this._wire(member.sessionId, { ...frame, hopped: true });
    }

    async _onLeave(frame) {
        const fp = assertFingerprint(String(frame.fp || ''));
        const member = this.members.get(fp);
        if (!member || fp === this.selfFp) return;
        this._emit('left', { fp, name: member.name });

        // The admin leaving ends the group for everyone else. Nobody else can
        // sign a roster, so there is no next epoch and no safety code to compare
        // again — carrying on would leave a group that looks alive but can never
        // change membership. Say so and let the app tear it down, so the slot is
        // free when someone starts a new group with the same people.
        if (!this.isAdmin && fp === this.adminFp) {
            this.members.delete(fp);
            for (const [sid, f] of [...this.sessionToFp]) if (f === fp) this.sessionToFp.delete(sid);
            this._emit('ended', { reason: 'admin_left' });
            return;
        }

        // Only the admin rewrites membership; everyone else waits for the roster
        // that the admin will publish for the new epoch.
        if (!this.isAdmin) return;

        this.members.delete(fp);
        for (const [sid, f] of [...this.sessionToFp]) if (f === fp) this.sessionToFp.delete(sid);
        // Tell the UI immediately. Dropping the member from this map without
        // emitting left them on the admin's member strip until some later event
        // happened to refresh it — a member who had visibly left still shown as
        // present, which is exactly the wrong thing for a group to be vague about.
        this._emitMembers();

        // A group of one is not a group. Publishing a roster for it would throw
        // out of canonicalFingerprints and abort mid-teardown, leaving the group
        // stuck in a failed state that still occupies the member.
        if (this.members.size < GROUP_LIMITS.MIN_MEMBERS) {
            this._emit('ended', { reason: 'last_member_left' });
            return;
        }

        this.epoch += 1;
        await this.publishRoster(MEMBER_OPS.REMOVE);
    }

    /**
     * Tell the group we are leaving, best effort.
     *
     * Await this before destroy(): teardown clears the member map this walks to
     * find recipients, so a leave that is merely started can end up addressed to
     * nobody — and a peer that never hears it keeps a group nobody is in.
     */
    async leave() {
        try {
            await this._broadcast({ type: GROUP_FRAMES.LEAVE, gid: this.groupId, fp: this.selfFp });
        } catch (_) { /* leaving is best effort */ }
    }

    /**
     * Admin: invite more people into a group that is already running.
     *
     * The group stays usable throughout. Nothing about the membership changes
     * until the new members have published their identity keys and a roster for
     * the next epoch actually goes out — at which point every member, old and
     * new, runs a fresh commit/reveal round and compares a new code. That is not
     * ceremony for its own sake: the safety code covers the member set, so a set
     * that has changed has a different code, and the old one no longer says
     * anything about who is in the room.
     *
     * If nobody answers, the round is abandoned and the group is left exactly as
     * it was — which is why the epoch is not touched until the roster is sent.
     *
     * @param {{sessionId: string, name: string}[]} peers
     */
    async addMembers(peers) {
        if (!this.isAdmin) throw new GroupSessionError('only the admin invites', 'not_admin');
        if (!Array.isArray(peers) || peers.length === 0) return 0;
        if (this._pendingAdd) throw new GroupSessionError('an invitation round is already running', 'add_in_flight');
        if (this.members.size + peers.length > GROUP_LIMITS.MAX_MEMBERS) {
            throw new GroupSessionError(`a group is limited to ${GROUP_LIMITS.MAX_MEMBERS} members`, 'too_many_members');
        }

        // Refuse a session that is already carrying a member: inviting someone
        // twice would have them answer with a second identity key and occupy two
        // slots in the safety code.
        for (const peer of peers) {
            if (this.sessionToFp.has(peer.sessionId)) {
                throw new GroupSessionError('that chat is already a member of this group', 'already_a_member');
            }
        }

        this._pendingAdd = {
            op: MEMBER_OPS.ADD,
            epoch: this.epoch + 1,
            before: new Set(this.members.keys()),
        };
        for (const peer of peers) this._awaitingHello.set(peer.sessionId, peer.name || 'Member');

        // The invitation already names the epoch the new roster will open, so an
        // invitee adopts it before anything is signed against it.
        const frame = {
            type: GROUP_FRAMES.INVITE,
            gid: this.groupId,
            epoch: this._pendingAdd.epoch,
            name: this.name,
            adminSpki: toB64(this.identity.spki),
        };
        const round = this._pendingAdd;
        const results = await Promise.allSettled(peers.map((p) => this._wire(p.sessionId, frame)));
        const sent = results.filter((r) => r.status === 'fulfilled').length;

        // Judge "nothing was sent" by the SEND RESULTS, never by what is left in
        // _awaitingHello. On a fast link the invitee's hello comes back — and the
        // whole round completes — inside the very call that sent the invitation,
        // so by the time this line runs the queue is legitimately empty. Reading
        // emptiness as failure aborted rounds that had already succeeded.
        if (sent === 0) {
            for (const peer of peers) this._awaitingHello.delete(peer.sessionId);
            if (this._pendingAdd === round) this._pendingAdd = null;
            throw new GroupSessionError(
                'the invitation could not be sent — that chat is not connected',
                'invitations_could_not_be_sent',
            );
        }

        peers.forEach((peer, i) => {
            if (results[i].status === 'rejected') this._awaitingHello.delete(peer.sessionId);
        });

        // The round may already be finished; only arm the timer if it is not.
        if (this._pendingAdd === round) {
            this._timer(() => { if (this._pendingAdd === round) this._finishAdd(); }, TIMEOUTS.HELLO_MS);
        }
        return sent;
    }

    /**
     * Close an add round: publish the new roster, or abandon it.
     *
     * Reached either when every invitee has answered or when the wait runs out.
     * A partial answer is still worth publishing — the people who did join are
     * in — but if nobody joined, the group is left untouched rather than pushed
     * through a re-keying that would achieve nothing except making everyone
     * compare a new code.
     */
    async _finishAdd() {
        const round = this._pendingAdd;
        if (!round) return false;
        this._pendingAdd = null;
        this._awaitingHello.clear();

        const joined = [...this.members.keys()].filter((fp) => !round.before.has(fp));
        if (joined.length === 0) {
            this._emit('add_failed', { reason: 'nobody_joined' });
            return false;
        }

        this.epoch = round.epoch;
        this._emitMembers();
        await this.publishRoster(round.op);
        return true;
    }

    /**
     * Admin: remove a member and re-key the group.
     *
     * The new epoch is what makes the removal effective — a new safety code every
     * remaining member must compare again, and a member set the removed member is
     * not in. There is no shared group key to rotate because there never was one:
     * every message travels over pairwise ratchets, so a removed member simply
     * stops being sent anything.
     */
    async removeMember(fp) {
        if (!this.isAdmin) throw new GroupSessionError('only the admin removes members', 'not_admin');
        if (fp === this.selfFp) throw new GroupSessionError('the admin cannot remove themselves', 'bad_target');
        if (!this.members.has(fp)) return false;
        if (this.members.size - 1 < GROUP_LIMITS.MIN_MEMBERS) {
            throw new GroupSessionError('a group cannot drop below two members — leave it instead', 'would_empty_group');
        }
        this.members.delete(fp);
        for (const [sid, f] of [...this.sessionToFp]) if (f === fp) this.sessionToFp.delete(sid);
        this.epoch += 1;
        this._emitMembers();
        await this.publishRoster(MEMBER_OPS.REMOVE);
        return true;
    }
}
