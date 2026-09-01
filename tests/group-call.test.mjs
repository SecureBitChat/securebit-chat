// Group calls: the control plane and the media plane, separately.
//
// A group call in this app is N-1 ordinary 1:1 calls over links that were
// already SAS-verified, plus a signed roster saying who is in it. The two
// halves fail in different ways and are tested apart:
//
//   CONTROL (GroupSession + groupCrypto)
//     1. a call opened by one member is seen by every member, including one
//        who is only reachable through a relay;
//     2. a call frame from a non-member, or with a broken signature, is refused
//        — a relay carries these frames and must not be able to write one;
//     3. a captured frame cannot be replayed to drag somebody back into a call
//        or to end one that is running;
//     4. two calls opened at the same instant converge on one, so the group
//        does not split into two rooms;
//     5. a member who leaves the group leaves the call.
//
//   MEDIA (GroupCallMedia)
//     6. exactly one side of each pair places the call, so there is no glare;
//     7. one capture is shared across every leg, and no leg stops it;
//     8. a member with no direct link is IN the call and shown as connecting,
//        rather than dropped;
//     9. leaving releases the capture and every leg;
//    10. a member's voice plays from an element the controller owns, not from a
//        tile that unmounts the moment the user opens another chat;
//    11. the microphone is opened BEFORE the group is told a call exists, so a
//        device that cannot capture does not ring everybody else;
//    12. the speaking indicator holds through the pauses inside speech and drops
//        when someone actually stops, and never marks a muted microphone;
//    13. the gallery layout fills the room it is given rather than dividing the
//        width and hoping — which is what made tiles tiny on a desktop;
//    14. the spotlight view splits the stage without ever claiming more of it
//        than there is;
//    15. every hook in the call UI runs before its early returns — the one that
//        did not took the whole call down with React #310 the moment it started;
//    16. the stage is measured through a callback ref, so the person who JOINS a
//        call measures it too — an object ref only ever measured the person who
//        STARTED one;
//    17. a leg attached to a session that is already in a call is ACTIVE at once
//        rather than waiting at "connecting" for a state change that never comes;
//    18. the answering side dials for itself if the offer never arrives, so a
//        member cannot be stranded at "connecting" for the whole call.

import assert from 'node:assert/strict';

const { GroupSession, GROUP_FRAMES, groupFrameType, decodeEnvelope, encodeEnvelope } =
    await import('../src/group/GroupSession.js');
const { GROUP_PHASE, MEMBER_STATE } = await import('../src/state/groupsStore.js');
const { toB64, signGroupCall, CALL_ACTIONS, newCallId } = await import('../src/group/groupCrypto.js');
const { GroupCallMedia, LEG_STATE, SPEAKING, FALLBACK_DIAL_MS } =
    await import('../src/group/groupCallMedia.js');
const { gridLayout, spotlightLayout, TILE_GAP, TILE_ASPECT, MIN_TILE_W } =
    await import('../src/components/ui/callLayout.js');
const { readFileSync } = await import('node:fs');

const subtle = crypto.subtle;
const tick = async (n = 8) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0)); };

// ---------------------------------------------------------------------------
// the same incomplete mesh the e2e suite uses: Alice knows both, Bob and Carol
// know only each other's fingerprint. Every Bob↔Carol frame is relayed.
// ---------------------------------------------------------------------------

function makeMesh() {
    const links = new Map();
    const nodes = new Map();

    function makeNode(name, { isAdmin, groupId, groupName } = {}) {
        const events = [];
        const node = { name, session: null, events };
        const send = async (sessionId, frame) => {
            const pair = links.get(sessionId);
            if (!pair) throw new Error('no such link');
            const other = pair[0] === name ? pair[1] : pair[0];
            const target = nodes.get(other);
            if (!target) return;
            const wire = JSON.parse(JSON.stringify(frame));
            if (groupFrameType(wire) === GROUP_FRAMES.INVITE && !target.session) {
                const invite = decodeEnvelope(wire);
                target.session = new GroupSession({
                    groupId: invite.gid, name: invite.name, isAdmin: false,
                    subtle, send: target.send, emit: target.emit,
                });
                await target.session.acceptInvite(sessionId, invite);
                return;
            }
            if (!target.session) return;
            await target.session.handleFrame(sessionId, wire);
        };
        node.send = send;
        node.emit = (event, payload) => { events.push({ event, payload }); };
        if (isAdmin) node.session = new GroupSession({ groupId, name: groupName, isAdmin: true, subtle, send, emit: node.emit });
        nodes.set(name, node);
        return node;
    }

    return { connect: (a, b, sid) => links.set(sid, [a, b]), makeNode };
}

const last = (node, event) => [...node.events].reverse().find((e) => e.event === event)?.payload;

async function readyGroup() {
    const mesh = makeMesh();
    const gid = GroupSession.newId();
    const alice = mesh.makeNode('alice', { isAdmin: true, groupId: gid, groupName: 'Field team' });
    const bob = mesh.makeNode('bob');
    const carol = mesh.makeNode('carol');
    mesh.connect('alice', 'bob', 'A-B');
    mesh.connect('alice', 'carol', 'A-C');
    await alice.session.init();
    await alice.session.invite([
        { sessionId: 'A-B', name: 'Bob' },
        { sessionId: 'A-C', name: 'Carol' },
    ]);
    await tick(20);
    for (const n of [alice, bob, carol]) n.session.confirmSas();
    return { alice, bob, carol };
}

// ---------------------------------------------------------------------------
// 1. a call reaches every member, relayed ones included
// ---------------------------------------------------------------------------
{
    const { alice, bob, carol } = await readyGroup();

    const { callId } = await alice.session.startCall({ withVideo: false });
    await tick();

    for (const node of [bob, carol]) {
        const call = node.session.getCallSnapshot();
        assert.ok(call, `${node.name} must see the call`);
        assert.equal(call.callId, callId);
        assert.equal(call.joined, false, 'nobody is put into a call without joining it');
        assert.equal(call.startedBy, alice.session.selfFp);
        assert.deepEqual(call.participants.map((p) => p.fp), [alice.session.selfFp]);
        assert.ok(last(node, 'call'), 'the app is told a call exists');
    }
    // Carol has no link to Alice's caller... she has one; Bob↔Carol is the relayed
    // pair, so check that Carol learns about Bob joining through Alice.
    await bob.session.joinCall();
    await tick();
    assert.deepEqual(
        carol.session.getCallSnapshot().participants.map((p) => p.fp).sort(),
        [alice.session.selfFp, bob.session.selfFp].sort(),
        'a join relayed through the admin still counts',
    );

    // Leaving takes the member out everywhere, and the last one out ends it.
    await bob.session.leaveCall();
    await tick();
    assert.deepEqual(carol.session.getCallSnapshot().participants.map((p) => p.fp), [alice.session.selfFp]);
    await alice.session.leaveCall();
    await tick();
    assert.equal(carol.session.getCallSnapshot(), null, 'the call ends when the last member leaves');
    assert.equal(alice.session.call, null);
}

// ---------------------------------------------------------------------------
// 2. a relay cannot write a call frame
// ---------------------------------------------------------------------------
{
    const { alice, bob, carol } = await readyGroup();
    await alice.session.startCall({ withVideo: false });
    await tick();
    const callId = alice.session.call.callId;

    // Alice relays for Bob↔Carol. A forged "Carol joined", signed by Alice's own
    // key but claiming Carol's fingerprint, must not verify.
    const forged = {
        type: GROUP_FRAMES.CALL,
        gid: bob.session.groupId,
        epoch: bob.session.epoch,
        callId,
        action: CALL_ACTIONS.JOIN,
        fp: carol.session.selfFp,
        seq: 1,
        v: false,
        ts: Date.now(),
        sig: toB64(await signGroupCall(subtle, alice.session.identity.keyPair.privateKey, {
            groupId: bob.session.groupId, epoch: bob.session.epoch, callId,
            action: CALL_ACTIONS.JOIN, fp: carol.session.selfFp, seq: 1, withVideo: false,
        })),
    };
    await assert.rejects(
        () => bob.session.handleFrame('A-B', encodeEnvelope(forged)),
        /signature did not verify/,
        'a member cannot join somebody else to a call',
    );
    assert.deepEqual(bob.session.getCallSnapshot().participants.map((p) => p.fp), [alice.session.selfFp]);

    // A frame from someone who is not in the group at all is refused before the
    // signature is even relevant.
    const stranger = new GroupSession({ groupId: bob.session.groupId, name: 'x', isAdmin: false, subtle, send: async () => {}, emit: () => {} });
    await stranger.init();
    const outside = {
        ...forged,
        fp: stranger.selfFp,
        sig: toB64(await signGroupCall(subtle, stranger.identity.keyPair.privateKey, {
            groupId: bob.session.groupId, epoch: bob.session.epoch, callId,
            action: CALL_ACTIONS.JOIN, fp: stranger.selfFp, seq: 1, withVideo: false,
        })),
    };
    await assert.rejects(() => bob.session.handleFrame('A-B', encodeEnvelope(outside)), /non-member/);
}

// ---------------------------------------------------------------------------
// 3. a captured frame cannot be replayed
// ---------------------------------------------------------------------------
{
    const { alice, bob, carol } = await readyGroup();
    await alice.session.startCall({ withVideo: false });
    await tick();
    await carol.session.joinCall();
    await tick();

    const callId = alice.session.call.callId;
    // Capture Carol's join as Bob saw it, then replay it after she has left.
    const carolJoin = {
        type: GROUP_FRAMES.CALL,
        gid: bob.session.groupId, epoch: bob.session.epoch, callId,
        action: CALL_ACTIONS.JOIN, fp: carol.session.selfFp, seq: 1, v: false, ts: Date.now(),
        sig: toB64(await signGroupCall(subtle, carol.session.identity.keyPair.privateKey, {
            groupId: bob.session.groupId, epoch: bob.session.epoch, callId,
            action: CALL_ACTIONS.JOIN, fp: carol.session.selfFp, seq: 1, withVideo: false,
        })),
    };
    await carol.session.leaveCall();
    await tick();
    assert.ok(!bob.session.getCallSnapshot().participants.some((p) => p.fp === carol.session.selfFp));

    await bob.session.handleFrame('A-B', encodeEnvelope(carolJoin));
    assert.ok(
        !bob.session.getCallSnapshot().participants.some((p) => p.fp === carol.session.selfFp),
        'a replayed join must not put a member back into a call they left',
    );
}

// ---------------------------------------------------------------------------
// 4. two calls opened at once converge on one
// ---------------------------------------------------------------------------
{
    const { alice, bob, carol } = await readyGroup();

    // Open both locally without letting either announcement land first, which is
    // exactly what "at the same instant" means on a network with no server.
    const opened = await Promise.all([
        alice.session.startCall({ withVideo: false }),
        bob.session.startCall({ withVideo: true }),
    ]);
    await tick(20);

    const ids = [alice, bob, carol].map((n) => n.session.getCallSnapshot()?.callId);
    assert.equal(new Set(ids).size, 1, `the group must converge on one call, got ${ids.join(', ')}`);
    // And on the SAME one everywhere, by a rule every member can evaluate alone:
    // the lower call id wins. Nothing is negotiated and nobody arbitrates.
    const expected = opened.map((r) => r.callId).sort()[0];
    assert.equal(ids[0], expected, 'the lower call id is the one that survives');
}

// ---------------------------------------------------------------------------
// 5. a member who leaves the group leaves the call
// ---------------------------------------------------------------------------
{
    const { alice, bob, carol } = await readyGroup();
    await alice.session.startCall({ withVideo: false });
    await tick();
    await bob.session.joinCall();
    await tick();
    assert.equal(carol.session.getCallSnapshot().participants.length, 2);

    await bob.session.leave();
    await tick();
    assert.ok(
        !carol.session.getCallSnapshot()?.participants.some((p) => p.fp === bob.session.selfFp),
        'leaving the group leaves the call',
    );
}

// ---------------------------------------------------------------------------
// a fake pairwise manager, with just the surface a call leg uses
// ---------------------------------------------------------------------------

function makeManager(name) {
    return {
        name,
        groupContext: null,
        external: null,
        started: 0,
        startedWithVideo: null,
        ended: 0,
        addedVideo: [],
        replacedVideo: [],
        listeners: new Set(),
        callState: { phase: 'idle', quality: null, remoteHasVideo: false },
        setCallGroupContext(id) { this.groupContext = id; },
        setExternalMediaStream(stream) { this.external = stream; },
        addCallStateListener(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); },
        getCallState() { return { ...this.callState }; },
        remote: null,
        getRemoteMediaStream() { return this.remote || null; },
        async startCall(withVideo) { this.started += 1; this.startedWithVideo = withVideo; },
        endCall() { this.ended += 1; },
        setMicEnabled() {},
        setCameraEnabled() {},
        async addVideoTrack(track) { this.addedVideo.push(track); },
        async replaceVideoTrack(track) { this.replacedVideo.push(track); },
        emit(state) {
            this.callState = { ...this.callState, ...state };
            for (const fn of this.listeners) fn(this.getCallState());
        },
    };
}

function makeTrack(kind) {
    return { kind, enabled: true, stopped: false, stop() { this.stopped = true; } };
}

function makeStream(kinds) {
    const tracks = kinds.map(makeTrack);
    return {
        tracks,
        getTracks() { return [...this.tracks]; },
        getAudioTracks() { return this.tracks.filter((t) => t.kind === 'audio'); },
        getVideoTracks() { return this.tracks.filter((t) => t.kind === 'video'); },
        addTrack(t) { this.tracks.push(t); },
        removeTrack(t) { this.tracks = this.tracks.filter((x) => x !== t); },
    };
}

// Fingerprints only have to be comparable strings for the dialling rule.
const FP = {
    low: '1'.repeat(64),
    mid: '5'.repeat(64),
    high: 'a'.repeat(64),
};

// ---------------------------------------------------------------------------
// 6/7/8. one capture, one dialler per pair, and relayed members still counted
// ---------------------------------------------------------------------------
{
    const managers = { 's-mid': makeManager('mid'), 's-high': makeManager('high') };
    const captured = [];
    const media = new GroupCallMedia({
        getManager: (sid) => managers[sid] || null,
        getUserMedia: async (constraints) => {
            captured.push(constraints);
            const kinds = [];
            if (constraints.audio) kinds.push('audio');
            if (constraints.video) kinds.push('video');
            return makeStream(kinds);
        },
    });

    await media.join({
        callId: newCallId(),
        selfFp: FP.mid,
        withVideo: false,
        peers: [
            { fp: FP.mid, name: 'You', sessionId: null },
            { fp: FP.low, name: 'Ada', sessionId: 's-low' },      // no manager: relayed
            { fp: FP.high, name: 'Zoe', sessionId: 's-high' },
        ],
    });

    assert.equal(captured.length, 1, 'one capture for the whole call, never one per leg');

    // The dialling rule: we are FP.mid. Zoe (higher) we call; Ada (lower) would
    // call us — and in any case she has no direct link yet.
    assert.equal(managers['s-high'].started, 1, 'the lower fingerprint places the call');
    assert.equal(managers['s-high'].startedWithVideo, false);
    assert.equal(managers['s-mid'].started, 0, 'no leg is built to ourselves');

    // Every leg borrows the SAME capture, and is told which group call it is on
    // (which is what lets it answer without ringing the user a second time).
    assert.equal(managers['s-high'].external, media.getLocalStream());
    assert.ok(managers['s-high'].groupContext, 'the leg carries the group call id');

    // A member with no direct link is in the call, shown as unreachable, not dropped.
    const snap = media.snapshot();
    assert.deepEqual(snap.peers.map((p) => p.fp), [FP.low, FP.high]);
    assert.equal(snap.peers.find((p) => p.fp === FP.low).state, LEG_STATE.UNREACHABLE);
    assert.equal(snap.peers.find((p) => p.fp === FP.high).state, LEG_STATE.CONNECTING);

    // The leg going active is what the tile reads, per member.
    managers['s-high'].emit({ phase: 'active', quality: 'good', remoteHasVideo: true });
    const active = media.snapshot();
    assert.equal(active.peers.find((p) => p.fp === FP.high).state, LEG_STATE.ACTIVE);
    assert.equal(active.peers.find((p) => p.fp === FP.high).quality, 'good');
    assert.equal(active.connected, 1);

    // Ada's link comes up: a leg is built for her, and now WE do not dial (she is
    // the lower fingerprint) — so the pair still produces exactly one offer.
    managers['s-low'] = makeManager('low');
    media.setPeers([
        { fp: FP.mid, name: 'You', sessionId: null },
        { fp: FP.low, name: 'Ada', sessionId: 's-low' },
        { fp: FP.high, name: 'Zoe', sessionId: 's-high' },
    ]);
    await tick();
    assert.equal(managers['s-low'].started, 0, 'the higher fingerprint waits to be called');
    assert.ok(managers['s-low'].groupContext, 'but it must be ready to answer without ringing');
    assert.equal(managers['s-low'].external, media.getLocalStream());

    // Mid-call camera: one capture, added to every leg.
    await media.setCamera(true);
    assert.equal(captured.length, 2, 'the camera is captured once, not once per leg');
    assert.equal(managers['s-low'].addedVideo.length, 1);
    assert.equal(managers['s-high'].addedVideo.length, 1);
    assert.equal(managers['s-low'].addedVideo[0], managers['s-high'].addedVideo[0], 'the same track on every leg');

    // 9. Leaving releases the capture and every leg.
    const stream = media.getLocalStream();
    await media.leave();
    assert.ok(stream.getTracks().every((t) => t.stopped), 'the capture is released on leaving');
    for (const sid of ['s-low', 's-high']) {
        assert.equal(managers[sid].ended, 1, `${sid} was hung up`);
        assert.equal(managers[sid].groupContext, null, `${sid} is no longer a group leg`);
        assert.equal(managers[sid].external, null, `${sid} no longer holds the shared capture`);
    }
    assert.equal(media.active, false);
}

// ---------------------------------------------------------------------------
// a leg whose session moved is rebuilt on the new one, not left on the dead id
// ---------------------------------------------------------------------------
{
    const managers = { 'old': makeManager('old'), 'new': makeManager('new') };
    const media = new GroupCallMedia({
        getManager: (sid) => managers[sid] || null,
        getUserMedia: async () => makeStream(['audio']),
    });
    await media.join({
        callId: newCallId(), selfFp: FP.low, withVideo: false,
        peers: [{ fp: FP.high, name: 'Zoe', sessionId: 'old' }],
    });
    assert.equal(managers.old.started, 1);

    media.setPeers([{ fp: FP.high, name: 'Zoe', sessionId: 'new' }]);
    await tick();
    assert.equal(managers.old.ended, 1, 'the leg on the dead session is torn down');
    assert.equal(managers.old.groupContext, null);
    assert.equal(managers.new.started, 1, 'and rebuilt on the link that replaced it');
    await media.leave();
}

// ---------------------------------------------------------------------------
// a leg that could not be placed is retried, not written off for the call
// ---------------------------------------------------------------------------
{
    const manager = makeManager('zoe');
    // The pairwise session is mid-repair: the manager refuses the call.
    let refuse = true;
    manager.startCall = async function () {
        if (refuse) throw new Error('Calls require a connected, SAS-verified session.');
        this.started += 1;
    };
    const media = new GroupCallMedia({
        getManager: () => manager,
        getUserMedia: async () => makeStream(['audio']),
        createAudioSink: () => null,
    });
    const peers = [{ fp: FP.high, name: 'Zoe', sessionId: 's' }];
    await media.join({ callId: newCallId(), selfFp: FP.low, withVideo: false, peers });
    await tick();
    assert.equal(media.snapshot().peers[0].state, LEG_STATE.FAILED, 'a refused dial is reported as failed');

    // The link comes back. The next reconciliation — which happens on any group
    // event at all — has to try again rather than leave the member silent.
    refuse = false;
    media.setPeers(peers);
    await tick();
    assert.equal(manager.started, 1, 'the leg is retried once its session can carry a call');
    assert.equal(media.snapshot().peers[0].state, LEG_STATE.CONNECTING);
    await media.leave();
}

// ---------------------------------------------------------------------------
// a call cannot be opened before the humans confirmed the group code
// ---------------------------------------------------------------------------
{
    const mesh = makeMesh();
    const gid = GroupSession.newId();
    const alice = mesh.makeNode('alice', { isAdmin: true, groupId: gid, groupName: 'Unconfirmed' });
    mesh.makeNode('bob');
    mesh.connect('alice', 'bob', 'A-B');
    await alice.session.init();
    await alice.session.invite([{ sessionId: 'A-B', name: 'Bob' }]);
    await tick(20);
    assert.equal(alice.session.phase, GROUP_PHASE.AWAITING_SAS);
    await assert.rejects(() => alice.session.startCall({}), /group code has not been confirmed/);
}

// ---------------------------------------------------------------------------
// 10. audio plays from the controller, not from the tiles
// ---------------------------------------------------------------------------
{
    const managers = { 's-high': makeManager('high') };
    const sinks = [];
    const media = new GroupCallMedia({
        getManager: (sid) => managers[sid] || null,
        getUserMedia: async () => makeStream(['audio']),
        createAudioSink: () => {
            const sink = { srcObject: null, played: 0, paused: 0, play() { this.played += 1; }, pause() { this.paused += 1; } };
            sinks.push(sink);
            return sink;
        },
    });

    await media.join({
        callId: newCallId(), selfFp: FP.mid, withVideo: false,
        peers: [{ fp: FP.high, name: 'Zoe', sessionId: 's-high' }],
    });
    await tick();
    assert.equal(sinks.length, 1, 'one audio element per leg, owned by the controller');

    // The manager only produces an inbound stream once the leg is up, and it
    // hands back a NEW MediaStream whenever its receivers change.
    const first = makeStream(['audio']);
    managers['s-high'].remote = first;
    managers['s-high'].emit({ phase: 'active' });
    assert.equal(sinks[0].srcObject, first, 'the leg is audible as soon as it is active');
    assert.ok(sinks[0].played > 0, 'and playback is actually started');

    const rebuilt = makeStream(['audio', 'video']);
    managers['s-high'].remote = rebuilt;
    managers['s-high'].emit({ phase: 'active', remoteHasVideo: true });
    assert.equal(sinks[0].srcObject, rebuilt, 'a rebuilt inbound stream is picked up, not left behind');

    await media.leave();
    assert.equal(sinks[0].srcObject, null, 'the element is released with the leg');
    assert.ok(sinks[0].paused > 0);
}

// ---------------------------------------------------------------------------
// 11. the capture is opened before anybody is rung
// ---------------------------------------------------------------------------
{
    const { alice, bob, carol } = await readyGroup();

    const order = [];
    const originalSend = alice.session._sendCallFrame.bind(alice.session);
    alice.session._sendCallFrame = async (...args) => { order.push('announced'); return originalSend(...args); };

    await alice.session.startCall({
        withVideo: false,
        prepare: async () => { order.push('captured'); },
    });
    await tick();
    assert.deepEqual(order, ['captured', 'announced'], 'the microphone opens before the group is told');

    // And a capture that fails takes the call with it — nobody else is left with
    // a ringing group for a call that never opened.
    await alice.session.leaveCall();
    await tick();
    await assert.rejects(() => alice.session.startCall({
        prepare: async () => { throw Object.assign(new Error('no mic'), { name: 'NotAllowedError' }); },
    }), /no mic/);
    assert.equal(alice.session.call, null, 'the caller is not left in a call it cannot speak into');
    for (const node of [bob, carol]) {
        assert.equal(node.session.getCallSnapshot(), null, `${node.name} was never rung`);
    }
}

// ---------------------------------------------------------------------------
// 12. who is speaking: hysteresis, hold, and mute
// ---------------------------------------------------------------------------
{
    const manager = makeManager('zoe');
    const remote = makeStream(['audio']);
    manager.remote = remote;

    // One controllable level per stream, so the rule can be driven directly.
    const levels = new Map();
    const media = new GroupCallMedia({
        getManager: () => manager,
        getUserMedia: async () => makeStream(['audio']),
        createAudioSink: () => ({ srcObject: null, play() {}, pause() {} }),
        createLevelMeter: (stream) => ({ read: () => levels.get(stream) || 0, close() {} }),
    });

    await media.join({
        callId: newCallId(), selfFp: FP.low, withVideo: false,
        peers: [{ fp: FP.high, name: 'Zoe', sessionId: 's' }],
    });
    await tick();
    manager.emit({ phase: 'active' });   // the inbound stream (and its meter) appears

    const local = media.getLocalStream();
    const peerState = () => media.snapshot().peers[0].speaking;

    // Silence is silence.
    media._sampleLevels();
    assert.equal(peerState(), false);
    assert.equal(media.snapshot().selfSpeaking, false);

    // Above ON marks them immediately — an indicator that lagged the voice would
    // point at the wrong person in a fast exchange.
    levels.set(remote, SPEAKING.ON + 0.01);
    media._sampleLevels();
    assert.equal(peerState(), true, 'crossing the upper threshold marks someone as speaking');

    // A dip BETWEEN the thresholds is the gap between two words, not a stop.
    levels.set(remote, (SPEAKING.ON + SPEAKING.OFF) / 2);
    media._sampleLevels();
    assert.equal(peerState(), true, 'a syllable boundary must not clear the indicator');

    // Below OFF starts the hold, and the mark survives it.
    levels.set(remote, 0);
    media._sampleLevels();
    assert.equal(peerState(), true, 'the mark holds through a pause');

    // Only a pause longer than the hold clears it. Reach back in time rather
    // than waiting out the real duration.
    const leg = media._legs.get(FP.high);
    leg.quietSince = Date.now() - SPEAKING.HOLD_MS - 1;
    media._sampleLevels();
    assert.equal(peerState(), false, 'a real stop clears it');

    // Our own microphone runs the same rule...
    levels.set(local, SPEAKING.ON + 0.01);
    media._sampleLevels();
    assert.equal(media.snapshot().selfSpeaking, true);

    // ...except that a muted microphone is never speaking, whatever it hears.
    media.setMic(false);
    media._sampleLevels();
    assert.equal(media.snapshot().selfSpeaking, false, 'a muted mic must never look like it is talking');

    await media.leave();
    assert.equal(media.selfSpeaking, false, 'leaving clears the indicator');
}

// ---------------------------------------------------------------------------
// 13. the gallery fills the space it is given
// ---------------------------------------------------------------------------
{
    // Every tile keeps its shape, and the grid never claims more room than it has.
    const fits = (n, w, h) => {
        const l = gridLayout(n, w, h);
        assert.ok(l.cols >= 1 && l.cols <= n, `columns out of range for ${n}`);
        assert.equal(l.rows, Math.ceil(n / l.cols));
        assert.ok(Math.abs(l.tileW / l.tileH - TILE_ASPECT) < 1e-6, 'tiles keep their aspect ratio');
        const usedW = l.cols * l.tileW + TILE_GAP * (l.cols - 1);
        const usedH = l.rows * l.tileH + TILE_GAP * (l.rows - 1);
        assert.ok(usedW <= w + 0.5, `grid is ${usedW} wide in ${w}`);
        assert.ok(usedH <= h + 0.5, `grid is ${usedH} tall in ${h}`);
        return l;
    };

    // THE regression: three people on a desktop. Tiles must take up the room,
    // not sit tiny in the middle of it — this is what the old fixed cap broke.
    const desktop = fits(3, 1400, 760);
    assert.ok(desktop.tileW > 600, `three tiles on a desktop should be large, got ${Math.round(desktop.tileW)}px`);

    // Two people on a wide screen go side by side and get most of the width each.
    const pair = fits(2, 1400, 760);
    assert.equal(pair.cols, 2);
    assert.ok(pair.tileW > 650);

    // The same six people arrange differently on a wide screen and a tall one,
    // because the layout follows the room rather than the head count.
    assert.ok(fits(6, 1600, 700).cols > fits(6, 420, 780).cols,
        'a wide window takes more columns than a narrow one for the same call');

    // Alone in a call, the single tile fills the stage.
    const alone = fits(1, 1200, 600);
    assert.equal(alone.cols, 1);
    assert.ok(alone.tileW > 1000);

    // A phone: two people stack, and each still gets a real tile.
    const phone = fits(2, 390, 620);
    assert.equal(phone.cols, 1);
    assert.ok(phone.tileW > 300);

    // Too many for the space: tiles stop shrinking and the stage scrolls rather
    // than rendering thumbnails nobody can read.
    const crowded = gridLayout(8, 300, 220);
    assert.equal(crowded.tileW, MIN_TILE_W, 'tiles stop shrinking at the floor');

    // Before the container has been measured there is still a sane shape, and
    // never a zero-sized tile.
    const unmeasured = gridLayout(4, 0, 0);
    assert.ok(unmeasured.cols >= 1 && unmeasured.rows >= 1);
    assert.equal(unmeasured.tileW, 0, 'unmeasured falls back to CSS, not to a guessed pixel size');
    assert.deepEqual(gridLayout(0, 800, 600), { cols: 0, rows: 0, tileW: 0, tileH: 0 });
}

// ---------------------------------------------------------------------------
// 14. the spotlight splits the stage honestly
// ---------------------------------------------------------------------------
{
    const fits = (others, w, h) => {
        const l = spotlightLayout(others, w, h);
        if (l.main.w === 0) return l;   // correctly refused to split
        assert.ok(Math.abs(l.main.w / l.main.h - TILE_ASPECT) < 1e-6, 'the main tile keeps its shape');
        assert.ok(l.main.w <= w + 0.5, 'the main tile fits the width');
        assert.ok(l.main.h + (others > 0 ? l.stripH + TILE_GAP : 0) <= h + 0.5,
            'main tile plus strip fits the height');
        return l;
    };

    // The point of the view: the pinned person is far larger than they would be
    // in a gallery of the same call.
    const others = 3;
    const spot = fits(others, 1440, 760);
    const gallery = gridLayout(others + 1, 1440, 760);
    assert.ok(spot.main.w > gallery.tileW * 1.5,
        `spotlighting should be a real difference, got ${Math.round(spot.main.w)} vs ${Math.round(gallery.tileW)}`);
    assert.ok(spot.thumbW > 0 && spot.stripH > 0, 'and the others stay on screen');

    // Alone in a call there is nobody to strip, and the tile takes the stage.
    const solo = fits(0, 1200, 600);
    assert.equal(solo.stripH, 0);
    assert.ok(solo.main.w > 1000);

    // Phones: the strip is capped rather than proportional, or the thumbnails
    // would be unrecognisable on a short screen and absurd on a tall one.
    const phone = fits(4, 390, 620);
    assert.ok(phone.thumbW >= 92 && phone.thumbW <= 168, `thumb out of range: ${phone.thumbW}`);

    // A stage with no room to split says so instead of returning a negative tile.
    assert.equal(spotlightLayout(3, 300, 80).main.w, 0, 'no room to split is reported, not rendered');
    assert.deepEqual(spotlightLayout(2, 0, 0), { main: { w: 0, h: 0 }, stripH: 0, thumbW: 0 });
}

// ---------------------------------------------------------------------------
// 15. every hook runs before every early return
// ---------------------------------------------------------------------------
//
// React counts hooks per render and refuses a render that makes more calls than
// the one before it (#310). GroupCallUI returns early three times — no call, a
// call not joined, a call minimized — so a hook added below any of them is only
// reached sometimes, and the first render that reaches it takes the call down at
// the exact moment it starts. That is what happened, so it is worth a test that
// does not need a browser: read the component and check the ordering directly.
{
    const source = readFileSync(new URL('../src/components/ui/GroupCallUI.jsx', import.meta.url), 'utf8');
    const body = source.slice(source.indexOf('export function GroupCallUI('));

    const hookAt = [...body.matchAll(/React\.(useState|useEffect|useRef|useMemo|useCallback)\s*\(/g)]
        .map((m) => m.index);
    const returnAt = [...body.matchAll(/\n {4}(?:if \([^)]*\) )?return /g)].map((m) => m.index);

    assert.ok(hookAt.length >= 5, 'the scan found no hooks, so it is not scanning anything');
    assert.ok(returnAt.length >= 1, 'the scan found no early returns, so it proves nothing');
    assert.ok(
        Math.max(...hookAt) < Math.min(...returnAt),
        'a hook in GroupCallUI is placed after an early return — React will refuse the render (#310)',
    );

    // And the check has to be able to fail, or it is decoration: the shape of the
    // regression is a hook call appearing below the first return.
    const broken = body.slice(0, Math.min(...returnAt) + 20) + '\n    React.useRef(null);\n';
    const brokenHooks = [...broken.matchAll(/React\.(useState|useEffect|useRef|useMemo|useCallback)\s*\(/g)]
        .map((m) => m.index);
    assert.ok(Math.max(...brokenHooks) > Math.min(...returnAt),
        'the ordering check does not actually detect a hook below a return');
}

// ---------------------------------------------------------------------------
// 16. the stage is measured whenever it appears, not only when it appears first
// ---------------------------------------------------------------------------
//
// GroupCallUI renders the stage in one branch and a "somebody is calling you"
// prompt in another. Whoever JOINS a call mounts into the prompt, so on the
// render that first shows the stage the element is new — and an effect keyed on
// a `useRef` object, which never changes, does not run again to see it. The
// result was two people in one call looking at completely different layouts:
// the caller measured fine, the joiner measured 0x0 forever and got tiles
// collapsed to the width of their own labels.
//
// jsdom has no layout engine — clientWidth is always 0 there — so the honest
// thing to check is the mechanism rather than the pixels: the observed node has
// to be state, so that attaching it re-runs the effect.
{
    const source = readFileSync(new URL('../src/components/ui/GroupCallUI.jsx', import.meta.url), 'utf8');
    const hook = source.slice(source.indexOf('function useMeasuredSize'), source.indexOf('One member\'s tile'));

    assert.match(hook, /const \[node, setNode\] = React\.useState\(null\)/,
        'the measured node must be state, or the effect cannot re-run when it attaches');
    assert.match(hook, /\}, \[node\]\);/,
        'the measuring effect must depend on the node itself');
    assert.equal(/React\.useRef\(/.test(hook), false,
        'a useRef here is the regression: it never changes, so the effect runs once and misses the stage');

    // And the setter must actually be what the stage is attached with.
    assert.match(source, /const \[stageRef, stage\] = useMeasuredSize\(\)/);
    assert.match(source, /ref: stageRef,/);

    // Belt and braces: even unmeasured, a tile must not be able to shrink to its
    // own label. That collapse is what made the bug look like a broken call
    // rather than a slightly-off one.
    assert.match(source, /minWidth: tileW \? undefined : '\d+px'/,
        'the unmeasured tile needs a minimum width it cannot shrink through');
}

// ---------------------------------------------------------------------------
// 17. a leg starts from what the session is really doing
// ---------------------------------------------------------------------------
//
// The symptom this covers: a member sat at "connecting" forever. One of the ways
// in is a leg attached to a manager that is ALREADY carrying the call — the peer
// dialled before we had the leg. Nothing more will be emitted on that session, so
// a leg that assumes "connecting" until told otherwise never learns.
{
    const manager = makeManager('zoe');
    manager.callState = { phase: 'active', quality: 'good', remoteHasVideo: false };
    manager.remote = makeStream(['audio']);

    const media = new GroupCallMedia({
        getManager: () => manager,
        getUserMedia: async () => makeStream(['audio']),
        createAudioSink: () => ({ srcObject: null, play() {}, pause() {} }),
        createLevelMeter: () => ({ read: () => 0, close() {} }),
    });
    await media.join({
        callId: newCallId(), selfFp: FP.high, withVideo: false,   // higher fp: we answer
        peers: [{ fp: FP.low, name: 'Ada', sessionId: 's' }],
    });
    await tick();

    assert.equal(media.snapshot().peers[0].state, LEG_STATE.ACTIVE,
        'a leg on a session already in the call must not report "connecting"');
    assert.equal(manager.started, 0, 'and it must not dial over a call that is already up');
    await media.leave();
}

// ---------------------------------------------------------------------------
// 18. the answering side is not stranded if the offer never comes
// ---------------------------------------------------------------------------
{
    const manager = makeManager('ada');
    const media = new GroupCallMedia({
        getManager: () => manager,
        getUserMedia: async () => makeStream(['audio']),
        createAudioSink: () => ({ srcObject: null, play() {}, pause() {} }),
        createLevelMeter: () => ({ read: () => 0, close() {} }),
    });
    // We are the HIGHER fingerprint, so by the dialling rule we wait.
    await media.join({
        callId: newCallId(), selfFp: FP.high, withVideo: false,
        peers: [{ fp: FP.low, name: 'Ada', sessionId: 's' }],
    });
    await tick();
    assert.equal(manager.started, 0, 'the answering side does not dial first');

    const leg = media._legs.get(FP.low);
    assert.ok(leg.fallback, 'but it does arm a fallback rather than waiting forever');

    // Nothing ever arrives. Fire the fallback rather than waiting out the real delay.
    clearTimeout(leg.fallback);
    media._dialFallback(FP.low);
    await tick();
    assert.equal(manager.started, 1, 'the answering side eventually dials for itself');
    await media.leave();
}

// ...and it stands down the moment anything reaches the session, so two offers
// can never cross.
{
    const manager = makeManager('ada');
    const media = new GroupCallMedia({
        getManager: () => manager,
        getUserMedia: async () => makeStream(['audio']),
        createAudioSink: () => ({ srcObject: null, play() {}, pause() {} }),
        createLevelMeter: () => ({ read: () => 0, close() {} }),
    });
    await media.join({
        callId: newCallId(), selfFp: FP.high, withVideo: false,
        peers: [{ fp: FP.low, name: 'Ada', sessionId: 's' }],
    });
    await tick();

    // The peer's offer lands and is answered: the session is busy now.
    manager.emit({ phase: 'connecting' });
    assert.equal(media._legs.get(FP.low).fallback, null, 'the fallback is disarmed once the peer dials');

    manager.emit({ phase: 'active' });
    media._dialFallback(FP.low);   // even if it somehow fired, it must be a no-op
    await tick();
    assert.equal(manager.started, 0, 'no second offer is ever placed onto a live call');
    assert.equal(media.snapshot().peers[0].state, LEG_STATE.ACTIVE);
    await media.leave();
}

// ---------------------------------------------------------------------------
// the ordering that caused it: announce, THEN connect
// ---------------------------------------------------------------------------
//
// join() with no peers must capture and connect nothing, so the caller can put
// the group's "I joined" frame in between. Attaching a leg can place an offer
// immediately, and an offer that overtakes that frame arrives at a member who
// does not know the session is a call leg — they ring, and the dialler waits at
// "connecting" for the rest of the call.
{
    const manager = makeManager('zoe');
    const media = new GroupCallMedia({
        getManager: () => manager,
        getUserMedia: async () => makeStream(['audio']),
        createAudioSink: () => ({ srcObject: null, play() {}, pause() {} }),
        createLevelMeter: () => ({ read: () => 0, close() {} }),
    });
    await media.join({ callId: newCallId(), selfFp: FP.low, withVideo: false, peers: [] });
    await tick();
    assert.equal(manager.started, 0, 'capturing must not connect anything on its own');
    assert.ok(media.getLocalStream(), 'but the microphone is open, so a failure is caught before announcing');

    media.setPeers([{ fp: FP.high, name: 'Zoe', sessionId: 's' }]);
    await tick();
    assert.equal(manager.started, 1, 'connecting happens when the caller says so, after announcing');
    await media.leave();
}

// The app must actually use that order.
{
    const app = readFileSync(new URL('../src/app.jsx', import.meta.url), 'utf8');
    const join = app.slice(app.indexOf('const handleJoinGroupCall'), app.indexOf('const handleDismissGroupCall'));
    const openAt = join.indexOf('openGroupCallMedia');
    const announceAt = join.indexOf('runtime.joinCall()');
    const connectAt = join.indexOf('setPeers');
    assert.ok(openAt >= 0 && announceAt > openAt && connectAt > announceAt,
        'joining must capture, then announce, then connect — in that order');
    assert.match(app, /peers: \[\],\s*\/\/ legs are connected after the announcement/,
        'opening the controller must not hand it peers to connect straight away');
}

console.log('group-call: ok');
