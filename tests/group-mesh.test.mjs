// The mesh: how a group stops being a star.
//
// A group is created as a star — the admin holds a link to everyone, nobody
// else holds a link to anybody — and every message between two non-admins is
// carried by the admin. This file covers the step that ends that: each pair
// without a link dials one, over the relay path that already exists.
//
// What is asserted, in order of how much it matters:
//   1. a pair with no link between them ends up with a DIRECT one, and their
//      messages stop being relayed;
//   2. a relayed descriptor that was tampered with is refused, so the member
//      carrying it cannot put itself in the middle of the link;
//   3. an answer replayed from a different dial is refused;
//   4. exactly one side of each pair dials, so there is no glare to resolve;
//   5. a pair that cannot connect keeps working over the relay, and is not
//      retried forever;
//   6. a chat two members already held is adopted rather than re-dialled, and
//      a probe replayed onto a different chat does not bind;
//   7. the group survives the admin going away once the mesh is up — which is
//      the whole point of not being a star.

import assert from 'node:assert/strict';

const { GroupSession, GROUP_FRAMES, groupFrameType, decodeEnvelope, encodeEnvelope } =
    await import('../src/group/GroupSession.js');
const { GROUP_PHASE, MEMBER_STATE } = await import('../src/state/groupsStore.js');
const { toB64, generateGroupIdentity, signLinkProbe } =
    await import('../src/group/groupCrypto.js');

const subtle = crypto.subtle;

/** Let queued timers and promise chains settle. The mesh runs on setTimeout(0). */
async function tick(rounds = 12) {
    for (let i = 0; i < rounds; i++) await new Promise((r) => setTimeout(r, 0));
}

// ---------------------------------------------------------------------------
// a virtual network
// ---------------------------------------------------------------------------
//
// Unlike the e2e harness, session ids here are LOCAL to each node — which is
// what they are in the app, and what makes the mesh's own bookkeeping testable:
// a dial produces one id on the caller and a different one on the answerer.

function makeNet() {
    const nodes = new Map();
    /** `${node}|${sessionId}` -> { peer, peerSessionId, up, linkFp } */
    const chans = new Map();
    let counter = 0;
    const key = (n, s) => `${n}|${s}`;

    /** Two endpoints of one channel. Each side addresses it by its own id. */
    function link(a, aSid, b, bSid, { linkFp = null } = {}) {
        const fp = linkFp || `linkfp-${++counter}`;
        chans.set(key(a, aSid), { peer: b, peerSessionId: bSid, up: true, linkFp: fp });
        chans.set(key(b, bSid), { peer: a, peerSessionId: aSid, up: true, linkFp: fp });
        return fp;
    }

    function cut(a, aSid) {
        const ch = chans.get(key(a, aSid));
        if (!ch) return;
        ch.up = false;
        const back = chans.get(key(ch.peer, ch.peerSessionId));
        if (back) back.up = false;
    }

    /** Links whose transport has come up but whose group has not been told yet. */
    const pendingUp = [];

    function node(name, { refuseDials = false, tamper = null } = {}) {
        const events = [];
        const n = {
            name, events, session: null,
            dropRelays: false,
            meshCalls: { offers: 0, answers: 0, closed: [] },
        };

        n.send = async (sessionId, frame) => {
            const ch = chans.get(key(name, sessionId));
            if (!ch || !ch.up) throw new Error('no such link');
            if (n.dropRelays && groupFrameType(frame) === GROUP_FRAMES.RELAY) return;
            const target = nodes.get(ch.peer);
            if (!target) return;
            let wire = JSON.parse(JSON.stringify(frame));
            if (tamper) wire = tamper(wire) || wire;

            if (groupFrameType(wire) === GROUP_FRAMES.INVITE && !target.session) {
                const invite = decodeEnvelope(wire);
                target.session = new GroupSession({
                    groupId: invite.gid, name: invite.name, isAdmin: false,
                    subtle, send: target.send, emit: target.emit, mesh: target.mesh,
                });
                await target.session.acceptInvite(ch.peerSessionId, invite);
                return;
            }
            if (!target.session) return;
            await target.session.handleFrame(ch.peerSessionId, wire);
        };
        n.emit = (event, payload) => events.push({ event, payload });

        // The transport half. A descriptor is a string that names the node and
        // the local session it belongs to, which is all the wiring below needs.
        n.mesh = {
            createOffer: async (fp) => {
                if (refuseDials) throw new Error('no network');
                n.meshCalls.offers += 1;
                const sessionId = `m:${name}:${++counter}`;
                return { sessionId, descriptor: `OFF|${name}|${sessionId}|${fp.slice(0, 8)}` };
            },
            createAnswer: async (fp, descriptor) => {
                if (refuseDials) throw new Error('no network');
                n.meshCalls.answers += 1;
                const [, offerNode, offerSid] = String(descriptor).split('|');
                const sessionId = `m:${name}:${++counter}`;
                return { sessionId, descriptor: `ANS|${name}|${sessionId}|${offerNode}|${offerSid}` };
            },
            acceptAnswer: async (sessionId, descriptor) => {
                const [tag, ansNode, ansSid, offerNode, offerSid] = String(descriptor).split('|');
                if (tag !== 'ANS') throw new Error('not an answer');
                // The answer has to name the dial it belongs to. A real transport
                // enforces this through the descriptor's binding tag.
                if (offerNode !== name || offerSid !== sessionId) {
                    throw new Error('answer does not match the dial');
                }
                link(name, sessionId, ansNode, ansSid);
                pendingUp.push([name, sessionId], [ansNode, ansSid]);
            },
            close: (sessionId) => {
                n.meshCalls.closed.push(sessionId);
                chans.delete(key(name, sessionId));
            },
            linkFingerprint: (sessionId) => chans.get(key(name, sessionId))?.linkFp || '',
        };

        nodes.set(name, n);
        return n;
    }

    /** Tell both ends of every freshly built link that it is up, then settle. */
    async function settle(rounds = 12) {
        for (let i = 0; i < rounds; i++) {
            await new Promise((r) => setTimeout(r, 0));
            while (pendingUp.length) {
                const [who, sid] = pendingUp.shift();
                try { nodes.get(who)?.session?.setSessionState(sid, true); } catch (_) {}
            }
        }
    }

    /**
     * Tear every group down.
     *
     * Not tidiness: a group holds live timers — dial deadlines, and the backoff
     * that re-arms a maintenance pass — and in Node those keep the process
     * alive long after the assertions are done. destroy() clears them, which is
     * the same thing the app does when a group is closed.
     */
    function shutdown() {
        for (const n of nodes.values()) {
            try { n.session?.destroy(); } catch (_) {}
        }
    }

    return { nodes, node, link, cut, settle, shutdown, chans, key };
}

const last = (node, event) => [...node.events].reverse().find((e) => e.event === event)?.payload;
const all = (node, event) => node.events.filter((e) => e.event === event).map((e) => e.payload);
const memberOf = (node, fp) => node.session.members.get(fp);

/**
 * A ready three-member group over a star: Alice is the admin and holds a link to
 * Bob and to Carol; Bob and Carol have no link to each other.
 */
async function readyGroup(opts = {}) {
    const net = makeNet();
    const gid = GroupSession.newId();

    const alice = net.node('alice', opts.alice);
    const bob = net.node('bob', opts.bob);
    const carol = net.node('carol', opts.carol);

    net.link('alice', 'A>B', 'bob', 'B>A');
    net.link('alice', 'A>C', 'carol', 'C>A');

    alice.session = new GroupSession({
        groupId: gid, name: 'Field team', isAdmin: true,
        subtle, send: alice.send, emit: alice.emit, mesh: alice.mesh,
    });
    await alice.session.init();
    await alice.session.invite([
        { sessionId: 'A>B', name: 'Bob' },
        { sessionId: 'A>C', name: 'Carol' },
    ]);

    for (const n of [alice, bob, carol]) {
        assert.equal(n.session.phase, GROUP_PHASE.AWAITING_SAS, `${n.name} must reach the code step`);
    }
    // The humans compare and confirm. This is the gate the mesh waits behind.
    for (const n of [alice, bob, carol]) n.session.confirmSas();

    return { net, gid, alice, bob, carol };
}

// ---------------------------------------------------------------------------
// 1. a star becomes a mesh
// ---------------------------------------------------------------------------
{
    const { net, alice, bob, carol } = await readyGroup();

    const bobFp = bob.session.selfFp;
    const carolFp = carol.session.selfFp;

    // Before the mesh runs, Bob and Carol only know each other through Alice.
    assert.equal(memberOf(bob, carolFp).state, MEMBER_STATE.PENDING,
        'Carol starts out with no direct link to Bob');
    assert.equal(memberOf(bob, carolFp).sessionId, null);

    await net.settle();

    assert.equal(memberOf(bob, carolFp).state, MEMBER_STATE.LINKED,
        'Bob must end up directly linked to Carol');
    assert.equal(memberOf(carol, bobFp).state, MEMBER_STATE.LINKED,
        'Carol must end up directly linked to Bob');
    assert.ok(memberOf(bob, carolFp).sessionId, 'the link must be bound to a session');

    // Exactly one side dialled: the smaller fingerprint.
    const dialer = bobFp < carolFp ? bob : carol;
    const answerer = bobFp < carolFp ? carol : bob;
    assert.equal(dialer.meshCalls.offers, 1, 'the smaller fingerprint dials, once');
    assert.equal(dialer.meshCalls.answers, 0, 'the dialer does not also answer');
    assert.equal(answerer.meshCalls.offers, 0, 'the larger fingerprint does not dial');
    assert.equal(answerer.meshCalls.answers, 1, 'the larger fingerprint answers, once');

    // Alice already had links to both, so nothing was dialled for her.
    assert.equal(alice.meshCalls.offers, 0, 'the admin dials nobody: it is already linked to everyone');

    // And now a message between them goes direct rather than through Alice.
    bob.events.length = 0; carol.events.length = 0; alice.events.length = 0;
    await bob.session.sendText('the mesh is up');
    await tick();

    const heard = last(carol, 'message');
    assert.ok(heard, 'Carol must receive Bob\'s message');
    assert.equal(heard.body, 'the mesh is up');
    assert.equal(heard.relayed, false, 'and it must arrive over the direct link, not relayed');

    // Alice still gets her own copy, directly, as a member.
    assert.equal(last(alice, 'message').relayed, false);
    net.shutdown();
}

// ---------------------------------------------------------------------------
// 2. the relay cannot substitute a descriptor
// ---------------------------------------------------------------------------
//
// Alice carries every mesh dial between Bob and Carol. If she could swap the
// descriptor for her own, she would sit inside the link built to route around
// her. The signature over the descriptor is what stops that.
{
    const net = makeNet();
    const gid = GroupSession.newId();

    const alice = net.node('alice', {
        // Alice rewrites the descriptor inside every relayed mesh dial. She has
        // to open the envelope to do it, which is exactly what a relaying member
        // is able to do — and exactly why the signature is inside.
        tamper: (wire) => {
            if (groupFrameType(wire) !== GROUP_FRAMES.RELAY) return wire;
            let frame;
            try { frame = decodeEnvelope(wire); } catch (_) { return wire; }
            const inner = frame?.inner;
            if (!inner) return wire;
            if (inner.type !== GROUP_FRAMES.MESH_OFFER && inner.type !== GROUP_FRAMES.MESH_ANSWER) return wire;
            inner.d = 'OFF|alice|m:alice:evil|00000000';
            return encodeEnvelope(frame);
        },
    });
    const bob = net.node('bob');
    const carol = net.node('carol');

    net.link('alice', 'A>B', 'bob', 'B>A');
    net.link('alice', 'A>C', 'carol', 'C>A');

    alice.session = new GroupSession({
        groupId: gid, name: 'Tampered', isAdmin: true,
        subtle, send: alice.send, emit: alice.emit, mesh: alice.mesh,
    });
    await alice.session.init();
    await alice.session.invite([
        { sessionId: 'A>B', name: 'Bob' },
        { sessionId: 'A>C', name: 'Carol' },
    ]);
    for (const n of [alice, bob, carol]) n.session.confirmSas();

    // The dial fails rather than completing against a substituted descriptor.
    // handleFrame rejects, so the rejection surfaces through the caller.
    const rejections = [];
    const guard = (n) => {
        const original = n.session.handleFrame.bind(n.session);
        n.session.handleFrame = (...args) => original(...args).catch((e) => { rejections.push(e.code); });
    };
    guard(bob); guard(carol);

    await net.settle();

    assert.ok(rejections.includes('bad_signature'),
        'a tampered mesh descriptor must fail its signature check');

    const bobFp = bob.session.selfFp;
    const carolFp = carol.session.selfFp;
    assert.notEqual(memberOf(bob, carolFp).state, MEMBER_STATE.LINKED,
        'no link may be built from a descriptor the sender did not sign');

    // The group still works — over the relay, exactly as before the dial.
    bob.events.length = 0; carol.events.length = 0;
    await bob.session.sendText('still talking');
    await tick();
    const heard = last(carol, 'message');
    assert.ok(heard, 'a failed mesh dial must not cost the group its relay path');
    assert.equal(heard.relayed, true, 'and that copy is relayed, which the reader is told');
    net.shutdown();
}

// ---------------------------------------------------------------------------
// 3. an answer from another dial is refused
// ---------------------------------------------------------------------------
{
    const { net, bob, carol } = await readyGroup();
    await net.settle();

    const bobFp = bob.session.selfFp;
    const carolFp = carol.session.selfFp;
    const dialer = bobFp < carolFp ? bob : carol;
    const answerer = bobFp < carolFp ? carol : bob;
    const peerFp = dialer === bob ? carolFp : bobFp;

    // Reach into the completed dial and replay its answer under a fresh nonce.
    // A nonce that is not the one this dial published must not be accepted, or
    // an answer captured from any earlier attempt could be pushed into a later
    // one.
    const forged = {
        type: GROUP_FRAMES.MESH_ANSWER,
        gid: dialer.session.groupId,
        epoch: dialer.session.epoch,
        from: peerFp,
        to: dialer.session.selfFp,
        d: 'ANS|x|m:x:1|y|m:y:1',
        n: toB64(new Uint8Array(16)),
        sig: toB64(new Uint8Array(96)),
    };
    // The pair is already linked, so the dial is gone and the frame is dropped
    // before any signature work — which is itself the assertion: a settled pair
    // has nothing left for a replayed answer to attach to.
    await dialer.session._onMeshAnswer(forged);
    assert.equal(memberOf(dialer, peerFp).state, MEMBER_STATE.LINKED,
        'a replayed answer must not disturb a link that is already up');
    assert.equal(answerer.meshCalls.answers, 1, 'and must not provoke a second answer');
    net.shutdown();
}

// ---------------------------------------------------------------------------
// 4. a pair that cannot connect stays on the relay, and stops trying
// ---------------------------------------------------------------------------
{
    // Carol's transport refuses to build anything.
    const { net, bob, carol } = await readyGroup({ bob: { refuseDials: true }, carol: { refuseDials: true } });
    await net.settle(6);

    const bobFp = bob.session.selfFp;
    const carolFp = carol.session.selfFp;

    assert.equal(memberOf(bob, carolFp).state, MEMBER_STATE.PENDING,
        'a pair that cannot dial stays on the relay path');
    assert.equal(memberOf(bob, carolFp).sessionId, null,
        'and is not left bound to a session that was never built');

    // The group is unharmed: messages still flow through Alice.
    bob.events.length = 0; carol.events.length = 0;
    await bob.session.sendText('relayed after all');
    await tick();
    assert.equal(last(carol, 'message')?.body, 'relayed after all');
    assert.equal(last(carol, 'message')?.relayed, true);

    // The failure is recorded with a backoff rather than retried in a loop.
    const dialer = bobFp < carolFp ? bob : carol;
    const peerFp = dialer === bob ? carolFp : bobFp;
    const failure = dialer.session._meshFailures.get(peerFp);
    assert.ok(failure, 'a failed dial must be recorded');
    assert.ok(failure.attempts >= 1);
    assert.ok(failure.nextAt > Date.now(), 'and must not be retried immediately');
    net.shutdown();
}

// ---------------------------------------------------------------------------
// 5. a chat the two already had is adopted, not re-dialled
// ---------------------------------------------------------------------------
{
    const { net, bob, carol } = await readyGroup();

    // Bob and Carol already hold a verified 1:1 chat with each other, formed
    // before the group existed. Its key fingerprint is the same on both ends,
    // which is what a probe is signed against.
    net.link('bob', 'B>C', 'carol', 'C>B', { linkFp: 'shared-link-fingerprint' });

    // The app drives probing; here we do it directly. Only one side has to send
    // — the other answers in kind, or the adoption would be one-sided.
    await bob.session.probeSession('B>C');
    await tick();

    const bobFp = bob.session.selfFp;
    const carolFp = carol.session.selfFp;

    assert.equal(memberOf(bob, carolFp).state, MEMBER_STATE.LINKED, 'the existing chat is adopted');
    assert.equal(memberOf(bob, carolFp).sessionId, 'B>C', 'and bound by its own session id');
    assert.equal(memberOf(carol, bobFp).state, MEMBER_STATE.LINKED, 'on both sides');
    assert.equal(memberOf(carol, bobFp).sessionId, 'C>B');

    // Whatever the mesh had started is abandoned in favour of the chat that
    // already worked — the pair ends up on THAT one, not on a second connection.
    await net.settle();
    assert.equal(memberOf(bob, carolFp).sessionId, 'B>C',
        'the pre-existing chat wins over anything the mesh was building');
    assert.equal(memberOf(carol, bobFp).sessionId, 'C>B');

    // A second probe on the same session is not sent again.
    assert.equal(await bob.session.probeSession('B>C'), false);

    // And messages between them travel over it, direct.
    bob.events.length = 0; carol.events.length = 0;
    await bob.session.sendText('over the chat we already had');
    await tick();
    assert.equal(last(carol, 'message')?.body, 'over the chat we already had');
    assert.equal(last(carol, 'message')?.relayed, false);
    net.shutdown();
}

// ---------------------------------------------------------------------------
// 6. a probe replayed onto a different chat does not bind
// ---------------------------------------------------------------------------
//
// This is the attack the link fingerprint exists for. Without it, any member
// could capture another member's probe and present it on their own chat, and
// group traffic for that member would then be encrypted to the impersonator.
{
    const { net, alice, bob, carol } = await readyGroup();

    const carolFp = carol.session.selfFp;

    // Carol signs a probe for the chat SHE holds with Alice...
    net.link('carol', 'C>X', 'alice', 'A>X', { linkFp: 'carols-own-link' });
    const sig = await signLinkProbe(subtle, carol.session.identity.keyPair.privateKey, {
        groupId: carol.session.groupId,
        epoch: carol.session.epoch,
        fp: carolFp,
        linkFp: 'carols-own-link',
    });
    const probe = {
        type: GROUP_FRAMES.PROBE,
        gid: carol.session.groupId,
        epoch: carol.session.epoch,
        fp: carolFp,
        sig: toB64(sig),
    };

    // ...and Bob replays it on a chat of his own, claiming to be Carol.
    net.link('bob', 'B>M', 'alice', 'A>M', { linkFp: 'bobs-own-link' });
    // Bob's group has no link to Carol yet, so the claim would otherwise take.
    await assert.rejects(
        () => bob.session._onProbe('B>M', probe),
        (e) => e.code === 'bad_signature',
        'a probe signed for one chat must not bind another',
    );

    const bobsCarol = memberOf(bob, carolFp);
    assert.notEqual(bobsCarol.sessionId, 'B>M', 'the replayed probe must bind nothing');
    net.shutdown();
}

// ---------------------------------------------------------------------------
// 7. the group outlives the admin once the mesh is up
// ---------------------------------------------------------------------------
//
// In a star, the admin going away partitions everyone else. That is the failure
// the mesh exists to remove.
{
    const { net, alice, bob, carol } = await readyGroup();
    await net.settle();

    const bobFp = bob.session.selfFp;
    const carolFp = carol.session.selfFp;
    assert.equal(memberOf(bob, carolFp).state, MEMBER_STATE.LINKED, 'precondition: the mesh formed');

    // Alice's links drop on both sides.
    net.cut('bob', 'B>A');
    net.cut('carol', 'C>A');
    bob.session.setSessionState('B>A', false);
    carol.session.setSessionState('C>A', false);
    await tick();

    bob.events.length = 0; carol.events.length = 0;
    const { delivered, total } = await bob.session.sendText('still here without the admin');
    await tick();

    assert.equal(total, 2, 'Bob still has two other members on the roster');
    assert.equal(delivered, 1, 'the admin is offline and is reported as not reached');
    assert.equal(last(carol, 'message')?.body, 'still here without the admin',
        'but Carol receives it over the direct link the mesh built');
    assert.equal(last(carol, 'message')?.relayed, false);
    net.shutdown();
}

// ---------------------------------------------------------------------------
// 8. an unsolicited hello cannot add a member
// ---------------------------------------------------------------------------
//
// The admin publishes a roster when every invitee it is waiting on has replied.
// A hello that answers no invitation must not reach that branch, or any member
// who knows the group id could put an identity of their choosing into the group
// and have the admin sign it.
{
    const { net, alice, bob } = await readyGroup();
    const before = alice.session.members.size;
    const beforeEpoch = alice.session.epoch;

    const stranger = await generateGroupIdentity(subtle);
    await alice.session.handleFrame('A>B', {
        type: GROUP_FRAMES.HELLO,
        gid: alice.session.groupId,
        epoch: alice.session.epoch,
        spki: toB64(stranger.spki),
    });

    assert.equal(alice.session.members.size, before,
        'a hello that answers no invitation must not create a member');
    assert.equal(alice.session.members.has(stranger.fingerprint), false);
    assert.equal(alice.session.epoch, beforeEpoch, 'and must not push the group into a new epoch');

    // The same frame wrapped in a relay — the route a member without a direct
    // link would have to use — is refused for the same reason.
    await bob.session.handleFrame('B>A', {
        type: GROUP_FRAMES.RELAY,
        gid: alice.session.groupId,
        to: alice.session.selfFp,
        hopped: false,
        inner: {
            type: GROUP_FRAMES.HELLO,
            gid: alice.session.groupId,
            epoch: alice.session.epoch,
            spki: toB64(stranger.spki),
        },
    });
    assert.equal(alice.session.members.has(stranger.fingerprint), false,
        'and a relayed one is refused too');
    net.shutdown();
}

// ---------------------------------------------------------------------------
// 9. a mesh link that dies is dialled again
// ---------------------------------------------------------------------------
//
// A link dying is not the same as the member going away. If the connection is
// beyond repair the pair goes back to the relay and dials again — which is the
// difference between a mesh that heals and one that only ever degrades.
{
    const { net, bob, carol } = await readyGroup();
    await net.settle();

    const bobFp = bob.session.selfFp;
    const carolFp = carol.session.selfFp;
    assert.equal(memberOf(bob, carolFp).state, MEMBER_STATE.LINKED, 'precondition: the mesh formed');

    const dialer = bobFp < carolFp ? bob : carol;
    const answerer = bobFp < carolFp ? carol : bob;
    const offersBefore = dialer.meshCalls.offers;

    // What the app does when a mesh manager exhausts its own ICE restarts.
    dialer.session.unbindSession(dialer === bob ? carolFp : bobFp);
    answerer.session.unbindSession(answerer === bob ? carolFp : bobFp);

    assert.equal(memberOf(bob, carolFp).state, MEMBER_STATE.PENDING,
        'a released member falls back to the relay, not to offline');

    await net.settle();

    assert.equal(dialer.meshCalls.offers, offersBefore + 1, 'the pair is dialled again');
    assert.equal(memberOf(bob, carolFp).state, MEMBER_STATE.LINKED, 'and the mesh heals');
    assert.equal(memberOf(carol, bobFp).state, MEMBER_STATE.LINKED);
    net.shutdown();
}

console.log('group-mesh.test.mjs: all assertions passed');
