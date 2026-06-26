// Verifies the multi-session reducer keeps sessions fully isolated: a change to one
// session never mutates another, unread only grows for non-active received traffic, and
// removing a session re-points the active pointer without disturbing siblings.
import assert from 'node:assert/strict';

const {
    sessionsReducer,
    createInitialState,
    createSessionEntry,
    SESSION_ACTIONS: A,
    decorateSession,
    monoInitials,
    statusDot
} = await import('../src/state/sessionsStore.js');

function withTwoSessions() {
    let state = createInitialState();
    state = sessionsReducer(state, { type: A.CREATE_SESSION, entry: createSessionEntry({ id: 'a', peerLabel: 'work laptop' }) });
    state = sessionsReducer(state, { type: A.CREATE_SESSION, entry: createSessionEntry({ id: 'b', peerLabel: 'atlas repo' }) });
    return state;
}

// CREATE_SESSION activates the new session and preserves order.
{
    const state = withTwoSessions();
    assert.deepEqual(state.order, ['a', 'b']);
    assert.equal(state.activeSessionId, 'b', 'newest session becomes active');
    assert.equal(Object.keys(state.sessions).length, 2);
}

// Isolation: mutating session B leaves session A's object referentially untouched.
{
    const before = withTwoSessions();
    const aRef = before.sessions.a;
    const after = sessionsReducer(before, { type: A.ADD_MESSAGE, id: 'b', message: { id: 1, message: 'hi', type: 'sent' } });
    assert.equal(after.sessions.a, aRef, 'session A object must be the same reference after editing B');
    assert.equal(after.sessions.b.messages.length, 1);
    assert.equal(after.sessions.a.messages.length, 0, 'A transcript untouched');
    // And the original state object was not mutated in place.
    assert.equal(before.sessions.b.messages.length, 0, 'reducer is immutable');
}

// SET_STATUS / SET_FINGERPRINT / SET_SAS are scoped to one session.
{
    let state = withTwoSessions();
    state = sessionsReducer(state, { type: A.SET_STATUS, id: 'a', status: 'verified' });
    state = sessionsReducer(state, { type: A.SET_SAS, id: 'a', sas: { isVerified: true, bothConfirmed: true } });
    state = sessionsReducer(state, { type: A.SET_FINGERPRINT, id: 'a', fingerprint: 'AB:CD' });
    assert.equal(state.sessions.a.status, 'verified');
    assert.equal(state.sessions.a.sas.isVerified, true);
    assert.equal(state.sessions.a.keyFingerprint, 'AB:CD');
    assert.equal(state.sessions.b.status, 'new', 'sibling status untouched');
    assert.equal(state.sessions.b.sas.isVerified, false, 'sibling SAS untouched');
    assert.equal(state.sessions.b.keyFingerprint, '', 'sibling fingerprint untouched');
}

// UPDATE_MESSAGE_STATUS and DELETE_MESSAGE only touch the named session/message.
{
    let state = withTwoSessions();
    state = sessionsReducer(state, { type: A.ADD_MESSAGE, id: 'a', message: { id: 1, mid: 'm1', message: 'x', type: 'sent', status: 'sending' } });
    state = sessionsReducer(state, { type: A.UPDATE_MESSAGE_STATUS, id: 'a', mid: 'm1', status: 'delivered' });
    assert.equal(state.sessions.a.messages[0].status, 'delivered');
    state = sessionsReducer(state, { type: A.DELETE_MESSAGE, id: 'a', mid: 'm1' });
    assert.equal(state.sessions.a.messages.length, 0);
    assert.equal(state.sessions.b.messages.length, 0);
}

// Unread bookkeeping.
{
    let state = withTwoSessions(); // active = b
    state = sessionsReducer(state, { type: A.INCREMENT_UNREAD, id: 'a' });
    state = sessionsReducer(state, { type: A.INCREMENT_UNREAD, id: 'a' });
    assert.equal(state.sessions.a.unreadCount, 2);
    assert.equal(state.sessions.b.unreadCount, 0);
    state = sessionsReducer(state, { type: A.SET_ACTIVE, id: 'a' });
    state = sessionsReducer(state, { type: A.CLEAR_UNREAD, id: 'a' });
    assert.equal(state.sessions.a.unreadCount, 0);
    assert.equal(state.activeSessionId, 'a');
}

// PATCH_SETUP merges, scoped per session.
{
    let state = withTwoSessions();
    state = sessionsReducer(state, { type: A.PATCH_SETUP, id: 'a', patch: { offerData: 'OFFER', showOfferStep: true } });
    assert.equal(state.sessions.a.setup.offerData, 'OFFER');
    assert.equal(state.sessions.a.setup.showOfferStep, true);
    assert.equal(state.sessions.a.setup.answerData, '', 'untouched setup field keeps default');
    assert.equal(state.sessions.b.setup.offerData, '', 'sibling setup untouched');
}

// RENAME marks the label custom.
{
    let state = withTwoSessions();
    state = sessionsReducer(state, { type: A.RENAME, id: 'a', label: 'Alice' });
    assert.equal(state.sessions.a.peerLabel, 'Alice');
    assert.equal(state.sessions.a.labelIsCustom, true);
    assert.equal(state.sessions.b.labelIsCustom, false);
}

// REMOVE_SESSION re-points active to the previous sibling and leaves the rest intact.
{
    let state = withTwoSessions(); // order [a,b], active b
    const bRef = state.sessions.b;
    state = sessionsReducer(state, { type: A.SET_ACTIVE, id: 'a' });
    state = sessionsReducer(state, { type: A.REMOVE_SESSION, id: 'a' });
    assert.equal(state.sessions.a, undefined, 'a removed');
    assert.equal(state.sessions.b, bRef, 'sibling b object untouched');
    assert.deepEqual(state.order, ['b']);
    assert.equal(state.activeSessionId, 'b', 'active re-pointed to remaining session');
}

// REMOVE_SESSION on the last session leaves no active.
{
    let state = createInitialState();
    state = sessionsReducer(state, { type: A.CREATE_SESSION, entry: createSessionEntry({ id: 'solo' }) });
    state = sessionsReducer(state, { type: A.REMOVE_SESSION, id: 'solo' });
    assert.equal(state.activeSessionId, null);
    assert.deepEqual(state.order, []);
}

// Decorators mirror the design helpers.
{
    assert.equal(monoInitials('work laptop'), 'WL');
    assert.equal(monoInitials('atlas'), 'AT');
    assert.equal(statusDot('verified'), '#3ecf8e');
    assert.equal(statusDot('connecting'), '#e3b341');
    assert.equal(statusDot('disconnected'), '#e5727a');

    const entry = createSessionEntry({ id: 'a', peerLabel: 'work laptop' });
    entry.unreadCount = 3;
    entry.status = 'connecting';
    const d = decorateSession(entry, 'b');
    assert.equal(d.mono, 'WL');
    assert.equal(d.unread, '3');
    assert.equal(d.active, false);
    assert.equal(d.inactive, true);
}

console.log('sessions-reducer.test.mjs: all assertions passed');
