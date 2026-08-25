// The seam between GroupSession and the reducer.
//
// Every other group test drives GroupSession directly and reads its fields. That
// left the path the UI actually renders from — emitted event, dispatched action,
// reducer state — completely uncovered, and it is where two bugs hid: a group
// name that the create dialog accepted but the protocol rejected, and a failure
// that reached the store but was rendered as "still working".
//
// This file mirrors app.jsx's groupEmitter exactly, so a change there that stops
// the code reaching the store fails here rather than on a user's screen.

import assert from 'node:assert/strict';

const { GroupSession, GROUP_FRAMES, groupFrameType, decodeEnvelope } =
    await import('../src/group/GroupSession.js');
const {
    groupsReducer, createInitialGroupState, createGroupEntry,
    GROUP_ACTIONS: GA, GROUP_PHASE,
} = await import('../src/state/groupsStore.js');
const { GROUP_LIMITS, assertName } = await import('../src/group/groupCrypto.js');

const subtle = crypto.subtle;
const bytes = (s) => new TextEncoder().encode(s).length;

/**
 * A store plus the emitter app.jsx installs on every group. Kept structurally
 * identical to the real one: same actions, same order, same SET_ACTIVE_GROUP on
 * a code arriving.
 */
function makeStore() {
    let state = createInitialGroupState();
    const dispatch = (action) => { state = groupsReducer(state, action); };
    const emitterFor = (gid) => (event, payload = {}) => {
        switch (event) {
            case 'phase': dispatch({ type: GA.SET_PHASE, id: gid, phase: payload.phase }); break;
            case 'members': dispatch({ type: GA.SET_MEMBERS, id: gid, members: payload.members, epoch: payload.epoch }); break;
            case 'roster': dispatch({ type: GA.RENAME, id: gid, name: payload.name }); break;
            case 'sas':
                dispatch({ type: GA.SET_SAS, id: gid, code: payload.code });
                dispatch({ type: GA.SET_ACTIVE_GROUP, id: gid });
                break;
            case 'confirmed': dispatch({ type: GA.CONFIRM_SAS, id: gid }); break;
            case 'error': dispatch({ type: GA.SET_ERROR, id: gid, error: payload.error }); break;
            default: break;
        }
    };
    return { get: () => state, dispatch, emitterFor };
}

/** Two peers on one link, each with its own store, formed end to end. */
async function formPair(groupName) {
    const links = new Map();
    const nodes = new Map();
    const gid = GroupSession.newId();

    const make = (name, isAdmin) => {
        const store = makeStore();
        const node = { name, store, session: null, errors: [] };
        node.send = async (sid, frame) => {
            const pair = links.get(sid);
            if (!pair) return;
            const other = pair[0] === name ? pair[1] : pair[0];
            const target = nodes.get(other);
            if (!target) return;
            const wire = JSON.parse(JSON.stringify(frame));

            if (groupFrameType(wire) === GROUP_FRAMES.INVITE && !target.session) {
                const invite = decodeEnvelope(wire);
                target.session = new GroupSession({
                    groupId: invite.gid, name: invite.name, isAdmin: false, subtle,
                    send: target.send, emit: target.store.emitterFor(invite.gid),
                });
                await target.session.init();
                // Exactly what handleAcceptInvite does, in the same order.
                target.store.dispatch({
                    type: GA.CREATE_GROUP,
                    entry: createGroupEntry({ id: invite.gid, name: invite.name, selfFp: target.session.selfFp }),
                });
                await target.session.acceptInvite(sid, invite);
                return;
            }
            if (!target.session) return;
            // The app does not await this and swallows nothing — it routes the
            // rejection into SET_ERROR. Mirror that.
            try {
                await target.session.handleFrame(sid, wire);
            } catch (error) {
                target.errors.push(error?.code || 'unknown');
                target.store.dispatch({ type: GA.SET_ERROR, id: wire.gid, error: error?.code || 'frame_rejected' });
            }
        };
        if (isAdmin) {
            node.session = new GroupSession({
                groupId: gid, name: groupName, isAdmin: true, subtle,
                send: node.send, emit: store.emitterFor(gid),
            });
        }
        nodes.set(name, node);
        return node;
    };

    const admin = make('admin', true);
    const joiner = make('joiner', false);
    links.set('A-B', ['admin', 'joiner']);

    await admin.session.init();
    admin.store.dispatch({
        type: GA.CREATE_GROUP,
        entry: createGroupEntry({
            id: gid, name: groupName, selfFp: admin.session.selfFp,
            adminFp: admin.session.selfFp, isAdmin: true,
            members: admin.session._memberSnapshot(),
        }),
    });
    await admin.session.invite([{ sessionId: 'A-B', name: 'Peer' }]);

    return { gid, admin, joiner };
}

// ---------------------------------------------------------------------------
// the code reaches the store, on BOTH sides
// ---------------------------------------------------------------------------
{
    const { gid, admin, joiner } = await formPair('Field team');

    for (const node of [admin, joiner]) {
        const group = node.store.get().groups[gid];
        assert.ok(group, `${node.name} must have the group in its store`);
        assert.deepEqual(node.errors, [], `${node.name} saw no rejected frames`);
        assert.equal(group.phase, GROUP_PHASE.AWAITING_SAS,
            `${node.name}: the store must reach the safety-code step`);
        // The two things the modal reads to decide whether to show the digits and
        // enable the confirm button. Either one missing is the reported bug.
        assert.match(group.sasCode, /^\d{7}$/, `${node.name}: the code must be IN THE STORE, not just in the session`);
        assert.equal(group.sasConfirmed, false, `${node.name}: shown, not yet confirmed`);
        assert.equal(group.members.length, 2, `${node.name}: both members are in the store`);
    }

    // Both stores hold the same digits — the whole point of the ceremony.
    assert.equal(
        admin.store.get().groups[gid].sasCode,
        joiner.store.get().groups[gid].sasCode,
        'both sides must render the same code',
    );

    // The modal's own gate: with a code present, confirming is allowed and lands.
    for (const node of [admin, joiner]) {
        node.session.confirmSas();
        node.store.dispatch({ type: GA.CONFIRM_SAS, id: gid });
        const group = node.store.get().groups[gid];
        assert.equal(group.phase, GROUP_PHASE.READY, `${node.name}: confirmed group is ready`);
        assert.equal(group.sasConfirmed, true);
    }
}

// ---------------------------------------------------------------------------
// a group name in a non-Latin script
// ---------------------------------------------------------------------------
{
    // The bug: the create dialog capped input at MAX_NAME_BYTES *characters*, so
    // this 36-character name (68 bytes) passed the dialog and then threw inside
    // the admin's roster signing. Formation died with nothing on screen.
    const cyrillic = 'Наша секретная группа для обсуждений';
    assert.ok(bytes(cyrillic) > cyrillic.length, 'the test name really is multi-byte');
    assert.ok(bytes(cyrillic) > 64, 'and it really did exceed the old limit');
    assert.doesNotThrow(() => assertName(cyrillic), 'the protocol must accept a normal Cyrillic name');

    const { gid, admin, joiner } = await formPair(cyrillic);
    for (const node of [admin, joiner]) {
        const group = node.store.get().groups[gid];
        assert.deepEqual(node.errors, [], `${node.name}: a Cyrillic name must not break formation`);
        assert.equal(group.phase, GROUP_PHASE.AWAITING_SAS, `${node.name}: reached the code`);
        assert.match(group.sasCode, /^\d{7}$/);
    }

    // The limit still exists — it is just counted in the same unit everywhere.
    const tooLong = 'я'.repeat(GROUP_LIMITS.MAX_NAME_BYTES);
    assert.ok(bytes(tooLong) > GROUP_LIMITS.MAX_NAME_BYTES);
    assert.throws(() => assertName(tooLong), /too long/);
}

// ---------------------------------------------------------------------------
// a failure is visible in the store, not disguised as progress
// ---------------------------------------------------------------------------
{
    const { gid, admin } = await formPair('Broken');
    admin.store.dispatch({ type: GA.SET_ERROR, id: gid, error: 'ceremony_timed_out' });

    const group = admin.store.get().groups[gid];
    assert.equal(group.phase, GROUP_PHASE.FAILED);
    assert.equal(group.error, 'ceremony_timed_out');
    // FAILED is distinguishable from the working phases, which is what the modal
    // needs in order to stop claiming it is still exchanging nonces.
    assert.notEqual(group.phase, GROUP_PHASE.REVEALING);
    assert.notEqual(group.phase, GROUP_PHASE.COMMITTING);
    // And a failed group can never be confirmed into readiness.
    admin.store.dispatch({ type: GA.CONFIRM_SAS, id: gid });
    assert.notEqual(admin.store.get().groups[gid].phase, GROUP_PHASE.READY,
        'a failed group must not be confirmable');
}

console.log('group-app-integration.test.mjs: all assertions passed');
