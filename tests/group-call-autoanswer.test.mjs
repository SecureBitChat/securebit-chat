// One leg of a group call must never sit there ringing.
//
// A group call is N-1 ordinary 1:1 calls, and each of them is answered without
// prompting because the user already consented once, by joining. That answer is
// decided when the offer LANDS — so an offer that arrives before this session
// has been told it is a call leg falls through the check and rings instead.
//
// The window is real. A member who joins can place their offers immediately,
// and those offers can overtake the group frame announcing that they joined. The
// symptom was asymmetric and confusing: one member's tile read "connecting" for
// the whole call while the other member's browser was quietly ringing for a call
// they had already agreed to be in.
//
// The ordering that opens the window is fixed elsewhere (the app announces
// before it connects). This covers the safety net underneath it: being told,
// late, that a session is a call leg has to pick up whatever is already ringing.

import assert from 'node:assert/strict';

globalThis.window = { EnhancedSecureCryptoUtils: { secureLog: { log() {} } } };

const { EnhancedSecureWebRTCManager } = await import('../src/network/EnhancedSecureWebRTCManager.js');

/** A manager with only the call-state machinery a leg touches. */
function callLeg(phase, { pending = null } = {}) {
    const leg = Object.create(EnhancedSecureWebRTCManager.prototype);
    leg.callState = {
        active: phase !== 'idle', phase, withVideo: false, micEnabled: true,
        cameraEnabled: false, remoteHasVideo: false, callId: 'c1', quality: null,
        groupCallId: null, error: null,
    };
    leg._callGroupContext = null;
    leg._callStateListeners = new Set();
    leg._pendingCallOffer = pending;
    leg.onCallStateChanged = null;
    leg.accepted = 0;
    leg.acceptCall = async function () { this.accepted += 1; };
    leg._startAdaptation = () => {};
    leg._stopAdaptation = () => {};
    leg._secureLog = () => {};
    return leg;
}

const offer = { sdp: 'v=0', callId: 'c1', withVideo: false };

// ── an offer that was already ringing is answered when the leg is claimed ────
{
    const leg = callLeg('incoming', { pending: offer });
    leg.setCallGroupContext('group-call-1');
    await new Promise((r) => setTimeout(r, 0));

    assert.equal(leg.accepted, 1, 'a ringing group leg must be answered as soon as it is claimed');
    assert.equal(leg.getCallState().groupCallId, 'group-call-1',
        'and the state must say which group call it belongs to, so the 1:1 UI stays out of the way');
}

// ── an idle session is left alone: there is nothing to answer ────────────────
{
    const leg = callLeg('idle');
    leg.setCallGroupContext('group-call-1');
    await new Promise((r) => setTimeout(r, 0));
    assert.equal(leg.accepted, 0, 'claiming an idle session must not invent a call');
}

// ── a call already up is not answered a second time ─────────────────────────
{
    const leg = callLeg('active', { pending: offer });
    leg.setCallGroupContext('group-call-1');
    await new Promise((r) => setTimeout(r, 0));
    assert.equal(leg.accepted, 0, 'a live call must not be re-answered');
}

// ── THE guard: releasing a leg must never auto-answer anything ───────────────
//
// This is the part that would be a security bug rather than a display one. The
// flag is what allows a microphone to open without asking, so clearing it — which
// is what leaving a call does — must not be a path to opening one.
{
    const leg = callLeg('incoming', { pending: offer });
    leg._callGroupContext = 'group-call-1';
    leg.setCallGroupContext(null);
    await new Promise((r) => setTimeout(r, 0));

    assert.equal(leg.accepted, 0, 'clearing the group context must never answer a call');
    assert.equal(leg.getCallState().groupCallId, null);
}

// ── and a session that is no longer a leg rings normally again ──────────────
{
    const leg = callLeg('idle');
    leg.setCallGroupContext('group-call-1');
    leg.setCallGroupContext(null);
    assert.equal(leg._callGroupContext, null,
        'a cleared context must not linger — it is what lets a call open a microphone unasked');
}

console.log('group-call-autoanswer: ok');
