// A whole group, formed end to end over a virtual mesh.
//
// The topology is deliberately INCOMPLETE: Alice (the admin) holds a link to
// Bob and a link to Carol, and Bob and Carol have no link to each other. That is
// the real shape of a group at the moment it is created, and it is what forces
// the relay path — so this file covers both the happy case and the case the
// design actually has to survive.
//
// What is asserted, in order of how much it matters:
//   1. every member computes the SAME safety code, and only after a complete
//      commit round;
//   2. a member the admin relays for still receives and verifies messages;
//   3. a forged or tampered message does not verify;
//   4. a member who sends two different bodies under one sequence number is
//      caught.

import assert from 'node:assert/strict';

const { GroupSession, GROUP_FRAMES, groupFrameType, decodeEnvelope, encodeEnvelope } =
    await import('../src/group/GroupSession.js');
const { GROUP_PHASE, MEMBER_STATE } = await import('../src/state/groupsStore.js');
const { toB64, fromB64, hashBody, signGroupMessage, generateGroupIdentity } =
    await import('../src/group/groupCrypto.js');

const subtle = crypto.subtle;

// ---------------------------------------------------------------------------
// a virtual mesh
// ---------------------------------------------------------------------------

/**
 * Nodes are wired by named links. `send(sessionId, frame)` delivers to whichever
 * endpoint of that link is not the sender, awaiting the handler so the whole
 * cascade settles before the test continues.
 */
function makeMesh() {
    const links = new Map();   // sessionId -> [nodeA, nodeB]
    const nodes = new Map();   // name -> node
    const events = new Map();  // name -> [{ event, payload }]

    function connect(a, b, sessionId) {
        links.set(sessionId, [a, b]);
    }

    function makeNode(name, { isAdmin, groupId, groupName }) {
        const log = [];
        events.set(name, log);
        const node = {
            name,
            session: null,
            dropRelays: false,
            events: log,
        };
        const send = async (sessionId, frame) => {
            const pair = links.get(sessionId);
            // A link that does not exist rejects, exactly as sendGroupFrame does
            // for a session with no manager. Returning quietly would let a test
            // pass on a send that never happened.
            if (!pair) throw new Error('no such link');
            const other = pair[0] === name ? pair[1] : pair[0];
            const target = nodes.get(other);
            if (!target) return;
            if (node.dropRelays && groupFrameType(frame) === GROUP_FRAMES.RELAY) return;
            // A frame is JSON on the wire; round-trip it so nothing in the test
            // shares an object reference the real transport would have severed.
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
        const emit = (event, payload) => { log.push({ event, payload }); };
        node.send = send;
        node.emit = emit;
        if (isAdmin) {
            node.session = new GroupSession({ groupId, name: groupName, isAdmin: true, subtle, send, emit });
        }
        nodes.set(name, node);
        return node;
    }

    return { connect, makeNode, nodes };
}

const last = (node, event) => [...node.events].reverse().find((e) => e.event === event)?.payload;
const all = (node, event) => node.events.filter((e) => e.event === event).map((e) => e.payload);

// ---------------------------------------------------------------------------
// form a three-member group over an incomplete mesh
// ---------------------------------------------------------------------------

async function formGroup() {
    const mesh = makeMesh();
    const gid = GroupSession.newId();

    const alice = mesh.makeNode('alice', { isAdmin: true, groupId: gid, groupName: 'Field team' });
    const bob = mesh.makeNode('bob', {});
    const carol = mesh.makeNode('carol', {});

    // Alice knows both. Bob and Carol do not know each other — the relay case.
    mesh.connect('alice', 'bob', 'A-B');
    mesh.connect('alice', 'carol', 'A-C');

    await alice.session.init();
    await alice.session.invite([
        { sessionId: 'A-B', name: 'Bob' },
        { sessionId: 'A-C', name: 'Carol' },
    ]);

    return { mesh, gid, alice, bob, carol };
}

{
    const { alice, bob, carol } = await formGroup();

    // Everyone adopted the roster and reached the code.
    for (const node of [alice, bob, carol]) {
        assert.equal(node.session.phase, GROUP_PHASE.AWAITING_SAS,
            `${node.name} must reach the safety-code step`);
        assert.equal(node.session.members.size, 3, `${node.name} must see three members`);
    }

    // THE assertion: one group, one code.
    const codes = [alice, bob, carol].map((n) => n.session.sasCode);
    assert.equal(new Set(codes).size, 1, 'every member must read the same digits');
    assert.match(codes[0], /^\d{7}$/);

    // Bob and Carol learned about each other only through the admin's signed
    // roster, and neither has a direct link to the other.
    const bobsCarol = [...bob.session.members.values()].find((m) => m.fp === carol.session.selfFp);
    assert.ok(bobsCarol, 'Bob must know Carol from the roster');
    assert.equal(bobsCarol.state, MEMBER_STATE.PENDING, 'with no direct link, Carol is pending for Bob');
    assert.equal(bobsCarol.sessionId, null);

    // Nothing may be sent before the humans confirm.
    await assert.rejects(() => bob.session.sendText('too early'), /group code has not been confirmed/);

    // Confirm everywhere.
    for (const node of [alice, bob, carol]) node.session.confirmSas();
    for (const node of [alice, bob, carol]) {
        assert.equal(node.session.phase, GROUP_PHASE.READY);
        assert.equal(node.session.sasConfirmed, true);
        assert.ok(last(node, 'confirmed'), 'the app is told the group is ready');
    }

    // ---- delivery over a direct link ----
    await alice.session.sendText('roll call');
    assert.equal(last(bob, 'message').body, 'roll call');
    assert.equal(last(carol, 'message').body, 'roll call');
    assert.equal(last(bob, 'message').fp, alice.session.selfFp, 'attributed to the signer');

    // ---- delivery THROUGH the admin, between two members with no link ----
    const result = await bob.session.sendText('on my way');
    assert.equal(result.delivered, 2, 'Bob reaches both members: Alice directly, Carol relayed');
    assert.equal(last(alice, 'message').body, 'on my way');
    assert.equal(last(carol, 'message').body, 'on my way',
        'a relayed message must arrive and verify');
    assert.equal(last(carol, 'message').fp, bob.session.selfFp,
        'the relay does not become the author');

    // The relay is single-hop: Carol never forwards what she received.
    assert.equal(carol.session._pendingCeremony.length, 0);

    // ---- a duplicate is absorbed, not shown twice ----
    const before = all(carol, 'message').length;
    await bob.session._sendTo(carol.session.selfFp, {
        type: GROUP_FRAMES.MESSAGE,
        gid: bob.session.groupId,
        epoch: bob.session.epoch,
        seq: result.seq,
        fp: bob.session.selfFp,
        ts: Date.now(),
        body: 'on my way',
        sig: toB64(await signGroupMessage(subtle, bob.session.identity.keyPair.privateKey, {
            groupId: bob.session.groupId, epoch: bob.session.epoch, seq: result.seq,
            senderFp: bob.session.selfFp, bodyHash: await hashBody(subtle, 'on my way'),
        })),
    });
    assert.equal(all(carol, 'message').length, before, 'a repeated frame is absorbed');
}

// ---------------------------------------------------------------------------
// the reveal gate really is closed until every commitment is in
// ---------------------------------------------------------------------------
{
    const mesh = makeMesh();
    const gid = GroupSession.newId();
    const alice = mesh.makeNode('alice', { isAdmin: true, groupId: gid, groupName: 'Slow' });
    const bob = mesh.makeNode('bob', {});
    const carol = mesh.makeNode('carol', {});
    mesh.connect('alice', 'bob', 'A-B');
    mesh.connect('alice', 'carol', 'A-C');

    // Alice refuses to carry anything between Bob and Carol, so Carol's
    // commitment never reaches Bob and Bob's never reaches Carol.
    alice.dropRelays = true;

    await alice.session.init();
    await alice.session.invite([
        { sessionId: 'A-B', name: 'Bob' },
        { sessionId: 'A-C', name: 'Carol' },
    ]);

    assert.equal(bob.session.phase, GROUP_PHASE.COMMITTING,
        'an incomplete commit round leaves the member waiting, never revealing');
    assert.equal(bob.session.ceremony.revealed, false, 'no nonce left the device');
    assert.equal(bob.session.sasCode, '', 'and no code was produced');
    assert.throws(() => bob.session.confirmSas(), /no group code to confirm/);
}

// ---------------------------------------------------------------------------
// forged and tampered messages
// ---------------------------------------------------------------------------
{
    const { alice, bob, carol } = await formGroup();
    for (const node of [alice, bob, carol]) node.session.confirmSas();

    const gid = bob.session.groupId;
    const epoch = bob.session.epoch;

    // A body swapped after signing does not verify.
    const bodyHash = await hashBody(subtle, 'the real text');
    const sig = await signGroupMessage(subtle, bob.session.identity.keyPair.privateKey, {
        groupId: gid, epoch, seq: 40, senderFp: bob.session.selfFp, bodyHash,
    });
    await assert.rejects(
        () => carol.session._onMessage({
            type: GROUP_FRAMES.MESSAGE, gid, epoch, seq: 40, fp: bob.session.selfFp,
            ts: Date.now(), body: 'the SWAPPED text', sig: toB64(sig),
        }),
        /signature did not verify/,
    );

    // Alice cannot sign as Bob, however well placed she is to relay for him.
    const aliceSig = await signGroupMessage(subtle, alice.session.identity.keyPair.privateKey, {
        groupId: gid, epoch, seq: 41, senderFp: bob.session.selfFp, bodyHash,
    });
    await assert.rejects(
        () => carol.session._onMessage({
            type: GROUP_FRAMES.MESSAGE, gid, epoch, seq: 41, fp: bob.session.selfFp,
            ts: Date.now(), body: 'the real text', sig: toB64(aliceSig),
        }),
        /signature did not verify/,
    );

    // An outsider with a perfectly valid signature is still not a member.
    const outsider = await generateGroupIdentity(subtle);
    const outsiderSig = await signGroupMessage(subtle, outsider.keyPair.privateKey, {
        groupId: gid, epoch, seq: 1, senderFp: outsider.fingerprint, bodyHash,
    });
    await assert.rejects(
        () => carol.session._onMessage({
            type: GROUP_FRAMES.MESSAGE, gid, epoch, seq: 1, fp: outsider.fingerprint,
            ts: Date.now(), body: 'the real text', sig: toB64(outsiderSig),
        }),
        /message from a non-member/,
    );

    // A message from an epoch the group has left is refused even though it verifies.
    await assert.rejects(
        () => carol.session._onMessage({
            type: GROUP_FRAMES.MESSAGE, gid, epoch: epoch + 5, seq: 42, fp: bob.session.selfFp,
            ts: Date.now(), body: 'the real text', sig: toB64(sig),
        }),
        /another epoch/,
    );
}

// ---------------------------------------------------------------------------
// a member telling two halves of the group different things is detectable
// ---------------------------------------------------------------------------
{
    const { alice, bob, carol } = await formGroup();
    for (const node of [alice, bob, carol]) node.session.confirmSas();

    const gid = bob.session.groupId;
    const epoch = bob.session.epoch;
    const seq = 7;

    const signed = async (body) => toB64(await signGroupMessage(
        subtle, bob.session.identity.keyPair.privateKey,
        { groupId: gid, epoch, seq, senderFp: bob.session.selfFp, bodyHash: await hashBody(subtle, body) },
    ));

    const frame = (body, sig) => ({
        type: GROUP_FRAMES.MESSAGE, gid, epoch, seq, fp: bob.session.selfFp,
        ts: Date.now(), body, sig,
    });

    const sellFrame = frame('sell', await signed('sell'));
    const buyFrame = frame('buy', await signed('buy'));

    await carol.session._onMessage(sellFrame);
    assert.equal(last(carol, 'message').body, 'sell');

    // The second, differently-signed body under the same sequence number is the
    // split. Both signatures are valid, which is exactly what makes it provable.
    await assert.rejects(
        () => carol.session._onMessage(buyFrame),
        /conflicting messages under one sequence number/,
    );
    const flagged = last(carol, 'inconsistency');
    assert.ok(flagged, 'the app is told which member did it');
    assert.equal(flagged.fp, bob.session.selfFp);
    assert.equal(flagged.seq, seq);
}

// ---------------------------------------------------------------------------
// removing a member re-keys the group
// ---------------------------------------------------------------------------
{
    const { alice, bob, carol } = await formGroup();
    for (const node of [alice, bob, carol]) node.session.confirmSas();
    const codeBefore = alice.session.sasCode;
    const epochBefore = alice.session.epoch;

    await alice.session.removeMember(carol.session.selfFp);

    assert.equal(alice.session.epoch, epochBefore + 1, 'removal opens a new epoch');
    assert.equal(alice.session.members.size, 2);
    assert.equal(bob.session.members.size, 2, 'the remaining member adopted the new roster');
    assert.ok(!bob.session.members.has(carol.session.selfFp), 'Carol is gone from Bob’s roster');

    // A new epoch means a new code, and it must be compared again before
    // anything is sent.
    assert.equal(alice.session.phase, GROUP_PHASE.AWAITING_SAS);
    assert.equal(bob.session.phase, GROUP_PHASE.AWAITING_SAS);
    assert.notEqual(alice.session.sasCode, codeBefore, 're-keying must change the digits');
    assert.equal(alice.session.sasCode, bob.session.sasCode, 'and both remaining members agree');
    assert.equal(alice.session.sasConfirmed, false);
    await assert.rejects(() => alice.session.sendText('still here?'), /has not been confirmed/);
}

// ---------------------------------------------------------------------------
// relay hygiene
// ---------------------------------------------------------------------------
{
    const { alice, bob, carol } = await formGroup();
    for (const node of [alice, bob, carol]) node.session.confirmSas();

    // A relay envelope already marked as hopped is not forwarded again.
    let forwarded = 0;
    const realSend = alice.session._send;
    alice.session._send = async (sid, frame) => { forwarded++; return realSend(sid, frame); };
    await alice.session._onRelay('A-B', {
        type: GROUP_FRAMES.RELAY, gid: alice.session.groupId, to: carol.session.selfFp,
        hopped: true,
        inner: { type: GROUP_FRAMES.MESSAGE, gid: alice.session.groupId },
    });
    assert.equal(forwarded, 0, 'a second hop is refused');

    // A nested relay is refused outright.
    await alice.session._onRelay('A-B', {
        type: GROUP_FRAMES.RELAY, gid: alice.session.groupId, to: carol.session.selfFp,
        hopped: false,
        inner: { type: GROUP_FRAMES.RELAY, gid: alice.session.groupId, to: bob.session.selfFp },
    });
    assert.equal(forwarded, 0, 'relays do not nest');
    alice.session._send = realSend;

    // A frame for another group is ignored entirely.
    const otherGid = GroupSession.newId();
    await alice.session.handleFrame('A-B', { type: GROUP_FRAMES.MESSAGE, gid: otherGid, epoch: 1, seq: 1 });
    // (no throw, no message emitted)
    assert.equal(all(alice, 'message').length, 0);
}

// ---------------------------------------------------------------------------
// the envelope: what keeps a signature intact through the chat path
// ---------------------------------------------------------------------------
{
    /**
     * Stand-in for EnhancedSecureCryptoUtils.sanitizeMessage, which every group
     * frame passes through on its way out: DOMPurify escapes the HTML-significant
     * characters, control characters go, blank runs collapse, the string is
     * trimmed and then cut to 2000 characters.
     */
    const sanitizeLikeTheChatPath = (s) => String(s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, '')
        .replace(/\r\n?/g, '\n')
        .replace(/\n{3,}/g, '\n\n')
        .trim()
        .substring(0, 2000);

    const { alice, bob, carol } = await formGroup();
    for (const node of [alice, bob, carol]) node.session.confirmSas();

    // A body full of exactly the characters that path rewrites.
    const hostile = 'if a < b && c > d then "quote" \n\n\n   trailing   ';
    const gid = bob.session.groupId;
    const epoch = bob.session.epoch;
    const bodyHash = await hashBody(subtle, hostile);
    const sig = await signGroupMessage(subtle, bob.session.identity.keyPair.privateKey, {
        groupId: gid, epoch, seq: 99, senderFp: bob.session.selfFp, bodyHash,
    });
    const frame = {
        type: GROUP_FRAMES.MESSAGE, gid, epoch, seq: 99, fp: bob.session.selfFp,
        ts: Date.now(), body: hostile, sig: toB64(sig),
    };

    // Without the envelope the chat path would rewrite the body and the
    // signature would no longer match — the failure this design exists to avoid.
    const bare = JSON.parse(sanitizeLikeTheChatPath(JSON.stringify(frame)));
    assert.notEqual(bare.body, hostile, 'the chat path really does rewrite a raw body');

    // With it, every byte survives.
    const wrapped = encodeEnvelope(frame);
    const throughTheWire = JSON.parse(sanitizeLikeTheChatPath(JSON.stringify(wrapped)));
    assert.deepEqual(throughTheWire, wrapped, 'the envelope passes through untouched');
    const recovered = decodeEnvelope(throughTheWire);
    assert.equal(recovered.body, hostile, 'the body arrives byte for byte');

    // And it verifies on the far side.
    await carol.session._onMessage(recovered);
    assert.equal(last(carol, 'message').body, hostile);

    // The routing hints outside the encoding carry no authority.
    assert.throws(() => decodeEnvelope({ ...wrapped, gid: GroupSession.newId() }),
        /group id does not match/);
    assert.throws(() => decodeEnvelope({ ...wrapped, t: GROUP_FRAMES.ROSTER }),
        /type does not match/);
    assert.throws(() => decodeEnvelope({ type: 'g_env', gid, t: 'g_msg', d: 'bm90IGpzb24=' }),
        /Unexpected token|not valid JSON|no recognisable frame/);

    // A frame that would be truncated by the chat path is refused at the source,
    // where it is still a clear error rather than a corrupt payload.
    assert.throws(
        () => encodeEnvelope({ ...frame, body: 'x'.repeat(4000) }),
        /exceeds the transport budget/,
    );

    // Every frame the protocol actually emits fits the budget, including the
    // largest one: a roster for a full group.
    const bigRoster = {
        type: GROUP_FRAMES.ROSTER, gid, epoch: 1, op: 'create', name: 'x'.repeat(64),
        adminSpki: toB64(new Uint8Array(120)),
        members: Array.from({ length: 8 }, () => 'ab'.repeat(32)),
        sig: toB64(new Uint8Array(96)),
    };
    assert.doesNotThrow(() => encodeEnvelope(bigRoster), 'a full 8-member roster must fit');
}

// ---------------------------------------------------------------------------
// nobody reveals before their own commitment is on the wire
// ---------------------------------------------------------------------------
{
    // Ordering regression. Draining held frames before broadcasting our own
    // commitment could complete the round on the spot and put a reveal out ahead
    // of the commitment it belongs to. The peer then had a reveal it could not
    // check and had to hold it, so the ceremony only finished if that one later
    // frame arrived — and when it did not, every member sat at "exchanging
    // nonces" waiting on a nonce that had already been sent.
    const mesh = makeMesh();
    const gid = GroupSession.newId();
    const alice = mesh.makeNode('alice', { isAdmin: true, groupId: gid, groupName: 'Pair' });
    const bob = mesh.makeNode('bob', {});
    mesh.connect('alice', 'bob', 'A-B');

    const wire = [];
    for (const node of [alice, bob]) {
        const inner = node.send;
        node.send = async (sid, frame) => {
            wire.push(`${node.name}:${groupFrameType(frame)}`);
            return inner(sid, frame);
        };
    }
    // Bob's session is built later, from `bob.send`, so it picks the wrapper up
    // on its own. Alice's already exists and captured the original at
    // construction — spy on the session itself.
    alice.session._send = alice.send;

    await alice.session.init();
    await alice.session.invite([{ sessionId: 'A-B', name: 'Bob' }]);

    for (const node of [alice, bob]) {
        const commit = wire.indexOf(`${node.name}:${GROUP_FRAMES.COMMIT}`);
        const reveal = wire.indexOf(`${node.name}:${GROUP_FRAMES.REVEAL}`);
        assert.ok(commit >= 0, `${node.name} must broadcast a commitment`);
        assert.ok(reveal >= 0, `${node.name} must broadcast a reveal`);
        assert.ok(commit < reveal, `${node.name} must commit before revealing (wire: ${wire.join(' ')})`);
        assert.equal(node.session._pendingCeremony.length, 0,
            `${node.name} should not need to hold any ceremony frame`);
    }

    // A two-member group is the smallest one, and it must still converge.
    assert.equal(alice.session.phase, GROUP_PHASE.AWAITING_SAS);
    assert.equal(bob.session.phase, GROUP_PHASE.AWAITING_SAS);
    assert.equal(alice.session.sasCode, bob.session.sasCode);
    assert.match(alice.session.sasCode, /^\d{7}$/);
}

// ---------------------------------------------------------------------------
// leaving a group frees its members for the next one
// ---------------------------------------------------------------------------
{
    const { alice, bob, carol } = await formGroup();
    for (const node of [alice, bob, carol]) node.session.confirmSas();

    // A group of three losing one is still a group; losing two is not, and the
    // admin must be told it ended rather than throwing mid-teardown.
    await alice.session.removeMember(carol.session.selfFp);
    assert.equal(alice.session.members.size, 2);
    await assert.rejects(
        () => alice.session.removeMember(bob.session.selfFp),
        /cannot drop below two members/,
    );

    // When the admin leaves, the remaining member's group is over: nobody else
    // can sign a roster, so there is no next epoch and no code to compare again.
    await alice.session.leave();
    assert.ok(last(bob, 'ended'), 'the remaining member is told the group ended');
    assert.equal(last(bob, 'ended').reason, 'admin_left');
    assert.ok(!bob.session.members.has(alice.session.selfFp));
}

// ---------------------------------------------------------------------------
// a member who leaves disappears from everyone's list
// ---------------------------------------------------------------------------
{
    const { alice, bob, carol } = await formGroup();
    for (const node of [alice, bob, carol]) node.session.confirmSas();
    const carolFp = carol.session.selfFp;

    await carol.session.leave();

    // The admin's own view is what regressed: it deleted the member internally
    // but never told the UI, so a member who had visibly left stayed on screen.
    assert.ok(!alice.session.members.has(carolFp), 'the admin drops the departed member');
    const adminView = last(alice, 'members');
    assert.ok(adminView, 'the admin must emit a member list when someone leaves');
    assert.ok(!adminView.members.some((m) => m.fp === carolFp),
        'the departed member must be gone from the list the admin renders');
    assert.equal(adminView.members.length, 2);

    // And the remaining member learns it through the signed roster.
    assert.ok(!bob.session.members.has(carolFp), 'the other member drops her too');
    assert.ok(!last(bob, 'members').members.some((m) => m.fp === carolFp));

    // Membership changed, so the code must be compared again.
    assert.equal(alice.session.phase, GROUP_PHASE.AWAITING_SAS);
    assert.equal(alice.session.sasCode, bob.session.sasCode);
}

// ---------------------------------------------------------------------------
// the admin can invite into a group that is already running
// ---------------------------------------------------------------------------
{
    const mesh = makeMesh();
    const gid = GroupSession.newId();
    const alice = mesh.makeNode('alice', { isAdmin: true, groupId: gid, groupName: 'Field team' });
    const bob = mesh.makeNode('bob', {});
    const dana = mesh.makeNode('dana', {});
    mesh.connect('alice', 'bob', 'A-B');
    mesh.connect('alice', 'dana', 'A-D');

    await alice.session.init();
    await alice.session.invite([{ sessionId: 'A-B', name: 'Bob' }]);
    alice.session.confirmSas();
    bob.session.confirmSas();

    const firstCode = alice.session.sasCode;
    const firstEpoch = alice.session.epoch;
    assert.equal(alice.session.members.size, 2);

    // The group stays usable while the invitation is outstanding — nothing about
    // the membership has changed yet.
    await alice.session.sendText('before dana');
    assert.equal(last(bob, 'message').body, 'before dana');

    await alice.session.addMembers([{ sessionId: 'A-D', name: 'Dana' }]);

    for (const node of [alice, bob, dana]) {
        assert.equal(node.session.members.size, 3, `${node.name} sees three members`);
        assert.equal(node.session.epoch, firstEpoch + 1, `${node.name} moved to the next epoch`);
        assert.equal(node.session.phase, GROUP_PHASE.AWAITING_SAS, `${node.name} must compare a new code`);
    }

    // A changed member set means a changed code — the old one no longer says
    // anything about who is in the room.
    const codes = [alice, bob, dana].map((n) => n.session.sasCode);
    assert.equal(new Set(codes).size, 1, 'all three agree on the new code');
    assert.notEqual(codes[0], firstCode, 'adding a member must change the code');

    // And nothing flows until it is confirmed again, including for the member
    // who was already verified a moment ago.
    await assert.rejects(() => bob.session.sendText('too early'), /has not been confirmed/);

    for (const node of [alice, bob, dana]) node.session.confirmSas();
    await alice.session.sendText('welcome dana');
    assert.equal(last(dana, 'message').body, 'welcome dana');
    assert.equal(last(bob, 'message').body, 'welcome dana');

    // Dana can reach Bob even with no direct link, relayed by the admin.
    const result = await dana.session.sendText('hello bob');
    assert.equal(result.delivered, 2);
    assert.equal(last(bob, 'message').body, 'hello bob');
    assert.equal(last(bob, 'message').fp, dana.session.selfFp);
}

// ---------------------------------------------------------------------------
// invitation rounds that should not happen
// ---------------------------------------------------------------------------
{
    const { alice, bob, carol } = await formGroup();
    for (const node of [alice, bob, carol]) node.session.confirmSas();

    // Only the admin invites.
    await assert.rejects(
        () => bob.session.addMembers([{ sessionId: 'X', name: 'Nope' }]),
        /only the admin invites/,
    );

    // A session already carrying a member cannot be invited again — it would
    // answer with a second identity key and take two slots in the safety code.
    const bobsSession = [...alice.session.members.values()].find((m) => m.fp === bob.session.selfFp).sessionId;
    await assert.rejects(
        () => alice.session.addMembers([{ sessionId: bobsSession, name: 'Bob again' }]),
        /already a member/,
    );

    // The ceiling is enforced before anything is sent.
    await assert.rejects(
        () => alice.session.addMembers(Array.from({ length: 7 }, (_, i) => ({ sessionId: `s${i}`, name: 'x' }))),
        /limited to 8 members/,
    );

    // An add nobody answers leaves the group exactly as it was.
    const epochBefore = alice.session.epoch;
    const membersBefore = alice.session.members.size;
    mesh_unreachable: {
        // A link the mesh does not know about: the send fails, so the round is
        // abandoned at once rather than half-applied.
        await assert.rejects(
            () => alice.session.addMembers([{ sessionId: 'nowhere', name: 'Ghost' }]),
            /could not be sent/,
        );
    }
    assert.equal(alice.session.epoch, epochBefore, 'a failed invitation does not open an epoch');
    assert.equal(alice.session.members.size, membersBefore, 'and does not change the membership');
    assert.equal(alice.session._pendingAdd, null, 'the round is cleared');
}

// ---------------------------------------------------------------------------
// a member going offline is not a member leaving
// ---------------------------------------------------------------------------
{
    const { alice, bob, carol } = await formGroup();
    for (const node of [alice, bob, carol]) node.session.confirmSas();

    const carolFp = carol.session.selfFp;
    const carolsSession = [...alice.session.members.values()].find((m) => m.fp === carolFp).sessionId;
    const epochBefore = alice.session.epoch;
    const codeBefore = alice.session.sasCode;

    alice.session.setSessionState(carolsSession, false);

    // Still a member. Membership is a signed, epoch-ordered fact and a dropped
    // connection does not change it — re-keying the group every time someone's
    // network hiccups would make everyone re-compare a code for nothing.
    assert.ok(alice.session.members.has(carolFp), 'an offline member is still a member');
    assert.equal(alice.session.epoch, epochBefore, 'no new epoch for a dropped link');
    assert.equal(alice.session.sasCode, codeBefore, 'and no new code to compare');
    assert.equal(alice.session.phase, GROUP_PHASE.READY, 'the group stays usable');

    // But unmistakably unreachable, and the UI is told.
    assert.equal(alice.session.members.get(carolFp).state, MEMBER_STATE.LOST);
    const view = last(alice, 'members');
    assert.equal(view.members.find((m) => m.fp === carolFp).state, MEMBER_STATE.LOST,
        'the rendered list marks them lost rather than dropping or hiding them');

    // Sending reports the shortfall instead of pretending it reached everyone,
    // and it names WHO was missed. A count alone cannot tell one absent member
    // from another, which is what the app needs to know to stop repeating
    // itself under every message for as long as somebody stays away.
    const result = await alice.session.sendText('anyone there?');
    assert.equal(result.total, 2);
    assert.ok(result.delivered < result.total, 'delivery to an offline member is reported, not assumed');
    assert.deepEqual(result.unreachable.map((m) => m.fp), [carolFp],
        'the member who was missed is named, not just counted');

    // The same shortfall reported twice is the same shortfall: the app compares
    // these sets, so they have to be stable for an unchanged situation.
    const again = await alice.session.sendText('still anyone there?');
    assert.deepEqual(again.unreachable.map((m) => m.fp), [carolFp]);

    // Coming back restores the link with no ceremony at all.
    alice.session.setSessionState(carolsSession, true);
    assert.equal(alice.session.members.get(carolFp).state, MEMBER_STATE.LINKED);
    assert.equal(alice.session.epoch, epochBefore, 'reconnecting does not re-key either');

    // Removing them, by contrast, IS a membership change and does re-key.
    await alice.session.removeMember(carolFp);
    assert.equal(alice.session.epoch, epochBefore + 1);
    assert.ok(!alice.session.members.has(carolFp));
    assert.equal(alice.session.phase, GROUP_PHASE.AWAITING_SAS, 'a real removal makes everyone compare again');
}

console.log('group-session-e2e.test.mjs: all assertions passed');
