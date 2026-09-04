// The groups reducer: isolation between groups, and the two transitions that
// carry security meaning — a group may not become "verified" without a code the
// user could have compared, and any membership change must drop that
// confirmation rather than carry it into a new epoch.

import assert from 'node:assert/strict';

const {
    groupsReducer,
    createInitialGroupState,
    createGroupEntry,
    GROUP_ACTIONS: A,
    GROUP_PHASE,
    MEMBER_STATE,
    decorateGroup,
    groupSub,
    groupDot,
    groupInitials,
    linkedCount,
} = await import('../src/state/groupsStore.js');
const { GROUP_LIMITS } = await import('../src/group/groupCrypto.js');

const fp = (n) => String(n).repeat(64).slice(0, 64);
const SELF = fp(1);
const BOB = fp(2);
const CAROL = fp(3);

function members(...states) {
    const fps = [SELF, BOB, CAROL];
    return fps.map((f, i) => ({
        fp: f,
        name: ['You', 'Bob', 'Carol'][i],
        sessionId: i === 0 ? null : `s${i}`,
        state: states[i] || (i === 0 ? MEMBER_STATE.SELF : MEMBER_STATE.LINKED),
    }));
}

function withTwoGroups() {
    let state = createInitialGroupState();
    state = groupsReducer(state, {
        type: A.CREATE_GROUP,
        entry: createGroupEntry({ id: 'g1', name: 'Field team', selfFp: SELF, adminFp: SELF, isAdmin: true, members: members() }),
    });
    state = groupsReducer(state, {
        type: A.CREATE_GROUP,
        entry: createGroupEntry({ id: 'g2', name: 'Review', selfFp: SELF, members: members() }),
    });
    return state;
}

// CREATE_GROUP activates the newest and preserves order.
{
    const state = withTwoGroups();
    assert.deepEqual(state.order, ['g1', 'g2']);
    assert.equal(state.activeGroupId, 'g2');
    assert.equal(state.groups.g1.phase, GROUP_PHASE.FORMING, 'a new group starts unformed');
    assert.equal(state.groups.g1.sasConfirmed, false);

    // A duplicate id is ignored rather than clobbering the live group.
    const again = groupsReducer(state, { type: A.CREATE_GROUP, entry: createGroupEntry({ id: 'g1', name: 'Impostor' }) });
    assert.equal(again, state, 'a repeated group id is a no-op');
}

// Isolation: touching g2 leaves g1 referentially untouched.
{
    const before = withTwoGroups();
    const g1Ref = before.groups.g1;
    const after = groupsReducer(before, { type: A.ADD_MESSAGE, id: 'g2', message: { id: 1, message: 'hi', type: 'sent' } });
    assert.equal(after.groups.g1, g1Ref, 'group 1 must be the same reference after editing group 2');
    assert.equal(after.groups.g2.messages.length, 1);
    assert.equal(before.groups.g2.messages.length, 0, 'the reducer is immutable');
}

// ---------------------------------------------------------------------------
// CONFIRM_SAS is the group's verification gate
// ---------------------------------------------------------------------------
{
    let state = withTwoGroups();

    // Without a computed code there is nothing the user could have compared, so
    // the transition is refused. This is the group analogue of the 1:1 rule that
    // verified state is never set by an inbound message.
    const refused = groupsReducer(state, { type: A.CONFIRM_SAS, id: 'g1' });
    assert.equal(refused, state, 'a group cannot be confirmed before a code exists');
    assert.equal(state.groups.g1.sasConfirmed, false);
    assert.equal(state.groups.g1.phase, GROUP_PHASE.FORMING);

    // A code alone is not enough either: the group must be waiting on THIS code.
    state = groupsReducer(state, { type: A.SET_SAS, id: 'g1', code: '4820193' });
    assert.equal(state.groups.g1.sasCode, '4820193');
    assert.equal(state.groups.g1.sasConfirmed, false, 'showing a code is not confirming it');
    assert.equal(
        groupsReducer(state, { type: A.CONFIRM_SAS, id: 'g1' }), state,
        'a group still forming cannot be confirmed, even holding a code',
    );

    // Waiting on the code is what makes confirmation meaningful.
    state = groupsReducer(state, { type: A.SET_PHASE, id: 'g1', phase: GROUP_PHASE.AWAITING_SAS });
    state = groupsReducer(state, { type: A.CONFIRM_SAS, id: 'g1' });
    assert.equal(state.groups.g1.sasConfirmed, true);
    assert.equal(state.groups.g1.phase, GROUP_PHASE.READY);

    // A new code (new epoch) always lands unconfirmed.
    state = groupsReducer(state, { type: A.SET_SAS, id: 'g1', code: '9911002' });
    assert.equal(state.groups.g1.sasConfirmed, false, 'a fresh code must be compared again');
}

// A ceremony that reached a code and THEN failed cannot be confirmed.
{
    let state = withTwoGroups();
    state = groupsReducer(state, { type: A.SET_PHASE, id: 'g1', phase: GROUP_PHASE.AWAITING_SAS });
    state = groupsReducer(state, { type: A.SET_SAS, id: 'g1', code: '5550001' });
    state = groupsReducer(state, { type: A.SET_ERROR, id: 'g1', error: 'commitment_mismatch' });
    assert.equal(state.groups.g1.phase, GROUP_PHASE.FAILED);
    assert.equal(state.groups.g1.sasCode, '5550001', 'the code survives so the UI can explain what failed');

    // The dangerous case: a failed verification must not be promotable to ready
    // just because a code is still lying around from before it failed.
    assert.equal(
        groupsReducer(state, { type: A.CONFIRM_SAS, id: 'g1' }), state,
        'a failed ceremony must never be confirmable',
    );
}

// Leaving READY drops the confirmation and the stale code.
{
    let state = withTwoGroups();
    state = groupsReducer(state, { type: A.SET_PHASE, id: 'g1', phase: GROUP_PHASE.AWAITING_SAS });
    state = groupsReducer(state, { type: A.SET_SAS, id: 'g1', code: '1234567' });
    state = groupsReducer(state, { type: A.CONFIRM_SAS, id: 'g1' });
    assert.equal(state.groups.g1.sasConfirmed, true);

    state = groupsReducer(state, { type: A.SET_PHASE, id: 'g1', phase: GROUP_PHASE.COMMITTING });
    assert.equal(state.groups.g1.sasConfirmed, false, 'a membership change un-verifies the group');
    assert.equal(state.groups.g1.sasCode, '', 'and clears the code it was confirmed against');
    assert.equal(state.groups.g2.sasConfirmed, false, 'sibling untouched');
}

// SET_ERROR fails the group; the phase follows.
{
    let state = withTwoGroups();
    state = groupsReducer(state, { type: A.SET_ERROR, id: 'g1', error: 'commitment_mismatch' });
    assert.equal(state.groups.g1.phase, GROUP_PHASE.FAILED);
    assert.equal(state.groups.g1.error, 'commitment_mismatch');

    // Moving to any non-failed phase clears the error.
    state = groupsReducer(state, { type: A.SET_PHASE, id: 'g1', phase: GROUP_PHASE.FORMING });
    assert.equal(state.groups.g1.error, null);
}

// ---------------------------------------------------------------------------
// members are kept in canonical order, whatever order they arrive in
// ---------------------------------------------------------------------------
{
    let state = createInitialGroupState();
    const shuffled = [
        { fp: CAROL, name: 'Carol', sessionId: 's2', state: MEMBER_STATE.LINKED },
        { fp: SELF, name: 'You', sessionId: null, state: MEMBER_STATE.SELF },
        { fp: BOB, name: 'Bob', sessionId: 's1', state: MEMBER_STATE.LINKED },
    ];
    state = groupsReducer(state, { type: A.CREATE_GROUP, entry: createGroupEntry({ id: 'g', name: 'X', members: shuffled }) });
    assert.deepEqual(state.groups.g.members.map((m) => m.fp), [SELF, BOB, CAROL], 'sorted on create');

    state = groupsReducer(state, { type: A.SET_MEMBERS, id: 'g', members: [...shuffled].reverse(), epoch: 4 });
    assert.deepEqual(state.groups.g.members.map((m) => m.fp), [SELF, BOB, CAROL], 'sorted on update');
    assert.equal(state.groups.g.epoch, 4);
}

// PATCH_MEMBER is a no-op when nothing actually moves (link state churns).
{
    let state = withTwoGroups();
    const before = state.groups.g1;
    state = groupsReducer(state, { type: A.PATCH_MEMBER, id: 'g1', fp: BOB, patch: { state: MEMBER_STATE.LINKED } });
    assert.equal(state.groups.g1, before, 'setting a member state to what it already is must not re-render');

    state = groupsReducer(state, { type: A.PATCH_MEMBER, id: 'g1', fp: BOB, patch: { state: MEMBER_STATE.LOST } });
    assert.notEqual(state.groups.g1, before);
    assert.equal(state.groups.g1.members.find((m) => m.fp === BOB).state, MEMBER_STATE.LOST);

    // An unknown fingerprint changes nothing.
    const after = groupsReducer(state, { type: A.PATCH_MEMBER, id: 'g1', fp: fp(9), patch: { state: MEMBER_STATE.LOST } });
    assert.equal(after, state);
}

// ---------------------------------------------------------------------------
// unread and active pointer
// ---------------------------------------------------------------------------
{
    let state = withTwoGroups();
    state = groupsReducer(state, { type: A.INCREMENT_UNREAD, id: 'g1' });
    state = groupsReducer(state, { type: A.INCREMENT_UNREAD, id: 'g1' });
    assert.equal(state.groups.g1.unreadCount, 2);
    assert.equal(state.groups.g2.unreadCount, 0, 'unread does not leak between groups');

    state = groupsReducer(state, { type: A.CLEAR_UNREAD, id: 'g1' });
    assert.equal(state.groups.g1.unreadCount, 0);
    assert.equal(groupsReducer(state, { type: A.CLEAR_UNREAD, id: 'g1' }), state, 'clearing twice is a no-op');

    // Removing the active group re-points to its neighbour.
    state = groupsReducer(state, { type: A.SET_ACTIVE_GROUP, id: 'g2' });
    state = groupsReducer(state, { type: A.REMOVE_GROUP, id: 'g2' });
    assert.equal(state.activeGroupId, 'g1');
    assert.deepEqual(state.order, ['g1']);

    // A 1:1 session taking the foreground clears the active group.
    state = groupsReducer(state, { type: A.SET_ACTIVE_GROUP, id: null });
    assert.equal(state.activeGroupId, null);
}

// ---------------------------------------------------------------------------
// derivation for rendering — partial connectivity is surfaced, not hidden
// ---------------------------------------------------------------------------
{
    const ready = createGroupEntry({ id: 'g', name: 'Field team', selfFp: SELF, members: members() });
    ready.phase = GROUP_PHASE.READY;
    ready.sasCode = '1234567';
    ready.sasConfirmed = true;

    assert.equal(linkedCount(ready), 3);
    assert.equal(groupSub(ready), '3 members · P2P mesh');
    // Custom properties rather than literals since the app gained a light theme: a dot is
    // a mark, so it takes the -solid accent, which is the brand colour in both themes.
    assert.equal(groupDot(ready), 'var(--sb-green-solid)');

    const degraded = { ...ready, members: members(MEMBER_STATE.SELF, MEMBER_STATE.LOST, MEMBER_STATE.LINKED) };
    assert.equal(linkedCount(degraded), 2);
    assert.equal(groupSub(degraded), '2 of 3 connected', 'an unreachable member is a member not getting your messages');
    assert.equal(groupDot(degraded), 'var(--sb-yellow-2-solid)', 'partial connectivity reads amber, not green');

    const forming = createGroupEntry({ id: 'h', name: 'New', members: members() });
    assert.equal(groupSub(forming), 'Forming…');
    assert.equal(groupDot(forming), 'var(--sb-yellow-2-solid)');

    const failed = { ...forming, phase: GROUP_PHASE.FAILED };
    assert.equal(groupDot(failed), 'var(--sb-red-solid)');

    const d = decorateGroup(ready, 'other');
    assert.equal(d.kind, 'group');
    assert.equal(d.mono, 'FT');
    assert.equal(d.verified, true);
    assert.equal(d.active, false);
    assert.equal(d.memberCount, 3);
    assert.equal(d.preview, '3 members · P2P mesh', 'with no messages the preview shows the group state');

    // A confirmed code alone is not "verified" if the phase regressed.
    assert.equal(decorateGroup({ ...ready, phase: GROUP_PHASE.COMMITTING }, 'g').verified, false);

    assert.equal(groupInitials('Field team'), 'FT');
    assert.equal(groupInitials('Ops'), 'OP');
    assert.equal(groupInitials(''), '##');
}

// RENAME trims and bounds.
{
    let state = withTwoGroups();
    state = groupsReducer(state, { type: A.RENAME, id: 'g1', name: '  Ops  ' });
    assert.equal(state.groups.g1.name, 'Ops');
    state = groupsReducer(state, { type: A.RENAME, id: 'g1', name: '   ' });
    assert.equal(state.groups.g1.name, 'Ops', 'a blank rename keeps the old name');
    state = groupsReducer(state, { type: A.RENAME, id: 'g1', name: 'x'.repeat(400) });
    assert.equal(state.groups.g1.name.length, GROUP_LIMITS.MAX_NAME_BYTES, 'the name is bounded');

    // Bounded in BYTES, not characters: a Cyrillic name is two bytes per letter,
    // so it must be cut at half the character count. Getting this wrong is what
    // let a name through the UI that the roster signing then rejected.
    state = groupsReducer(state, { type: A.RENAME, id: 'g1', name: 'я'.repeat(400) });
    const renamed = state.groups.g1.name;
    assert.ok(new TextEncoder().encode(renamed).length <= GROUP_LIMITS.MAX_NAME_BYTES,
        'a multi-byte name is clamped by bytes');
    assert.equal(renamed.length, GROUP_LIMITS.MAX_NAME_BYTES / 2);
}

console.log('groups-reducer.test.mjs: all assertions passed');
