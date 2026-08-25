import assert from 'node:assert/strict';

globalThis.window = {
    EnhancedSecureCryptoUtils: { secureLog: { log() {} } }
};
globalThis.CustomEvent = class CustomEvent {
    constructor(type, init) { this.type = type; this.detail = init?.detail; }
};
const dispatched = [];
globalThis.document = { dispatchEvent(e) { dispatched.push(e.type); } };

const { EnhancedSecureWebRTCManager } = await import('../src/network/EnhancedSecureWebRTCManager.js');
const P = EnhancedSecureWebRTCManager.prototype;
const T = EnhancedSecureWebRTCManager.MESSAGE_TYPES;
const TIMEOUTS = EnhancedSecureWebRTCManager.TIMEOUTS;

// Fake timers: the retry cycle is self-rescheduling by design (bounded only by
// RECONNECT_MAX_DURATION), so real timers would keep the test process alive.
// Driving them by hand also lets the backoff schedule itself be asserted.
const realTimers = {
    setTimeout: globalThis.setTimeout,
    clearTimeout: globalThis.clearTimeout,
    setInterval: globalThis.setInterval,
    clearInterval: globalThis.clearInterval
};
let scheduled = [];
globalThis.setTimeout = (callback, delay) => {
    const timer = { kind: 'timeout', callback, delay, cleared: false };
    scheduled.push(timer);
    return timer;
};
globalThis.setInterval = (callback, delay) => {
    const timer = { kind: 'interval', callback, delay, cleared: false };
    scheduled.push(timer);
    return timer;
};
globalThis.clearTimeout = (timer) => { if (timer) timer.cleared = true; };
globalThis.clearInterval = (timer) => { if (timer) timer.cleared = true; };

const pending = () => scheduled.filter((t) => !t.cleared);
// A real timeout stops pending once it fires; mirror that so the next lookup
// finds the newly scheduled retry rather than the spent one.
const fire = (timer) => { timer.cleared = true; return timer.callback(); };
// Let queued microtasks settle: several recovery entry points fire an async
// restart without awaiting it.
const settle = async () => { for (let i = 0; i < 8; i += 1) await Promise.resolve(); };

const FP_A = 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99';
const FP_B = '99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC:BB:AA';
const sdpWith = (fp) => `v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\na=fingerprint:sha-256 ${fp}\r\na=setup:actpass\r\n`;

// Minimal manager stub carrying only the recovery surface under test.
function makeManager(overrides = {}) {
    const statuses = [];
    const sent = [];
    const ui = [];
    const mgr = {
        // Lifecycle announcements go through _dispatchAppEvent rather than
        // straight to `document`, so a connection with no window of its own — a
        // group's mesh link — can be muted. An ordinary session is not.
        _emitGlobalEvents: true,
        _dispatchAppEvent: EnhancedSecureWebRTCManager.prototype._dispatchAppEvent,
        isVerified: true,
        isInitiator: true,
        intentionalDisconnect: false,
        reconnectionFailedNotificationSent: false,
        // Raw frames written straight to the channel (heartbeats/probes), as
        // opposed to `sent`, which collects sendSystemMessage payloads.
        _sentFrames: [],
        _heartbeatConfig: { enabled: true, lastHeartbeat: 0 },
        _livenessProbeAt: 0,
        _livenessArmed: true,
        isConnected: () => true,
        dataChannel: { readyState: 'open', send: (raw) => { mgr._sentFrames.push(JSON.parse(raw)); } },
        peerConnection: {
            connectionState: 'disconnected',
            signalingState: 'stable',
            currentRemoteDescription: { sdp: sdpWith(FP_A) },
            localDescription: { sdp: sdpWith(FP_B) },
            createOffer: async () => ({ type: 'offer', sdp: sdpWith(FP_B) }),
            createAnswer: async () => ({ type: 'answer', sdp: sdpWith(FP_B) }),
            setLocalDescription: async () => {},
            setRemoteDescription: async (d) => { mgr._applied.push(d.type); }
        },
        _applied: [],
        _reconnect: {
            phase: 'idle', attempts: 0, startedAt: 0,
            graceTimer: null, retryTimer: null, restartTimer: null, pendingRole: null
        },
        _activeTimers: new Set(),
        _lastInboundAt: 0,
        _livenessTimer: null,
        _heartbeatTimer: null,
        _secureLog() {},
        _clearVerificationStates() { mgr._verificationCleared = true; },
        _verificationCleared: false,
        onStatusChange: (s) => statuses.push(s),
        deliverMessageToUI: (m) => ui.push(m),
        processMessageQueue() { mgr._queueFlushed = true; },
        _queueFlushed: false,
        waitForIceGathering: async () => true,
        sendSystemMessage: async (m) => { sent.push(m); return true; },
        // Real implementations under test
        _trackActiveTimer: P._trackActiveTimer,
        _noteInboundActivity: P._noteInboundActivity,
        handleHeartbeat: P.handleHeartbeat,
        _sendHeartbeat: P._sendHeartbeat,
        _checkLiveness: P._checkLiveness,
        isReconnecting: P.isReconnecting,
        _resetReconnectState: P._resetReconnectState,
        _onPathDegraded: P._onPathDegraded,
        _onPathLost: P._onPathLost,
        _onPathRecovered: P._onPathRecovered,
        _attemptIceRestart: P._attemptIceRestart,
        _scheduleReconnectRetry: P._scheduleReconnectRetry,
        _sendIceRestartOffer: P._sendIceRestartOffer,
        _currentRemoteDtlsFingerprint: P._currentRemoteDtlsFingerprint,
        _assertSameRemoteIdentity: P._assertSameRemoteIdentity,
        _handleIceRestartSignal: P._handleIceRestartSignal,
        _giveUpAutoReconnect: P._giveUpAutoReconnect,
        _extractDTLSFingerprintFromSDP: P._extractDTLSFingerprintFromSDP,
        _validateDTLSFingerprint: P._validateDTLSFingerprint,
        ...overrides
    };
    scheduled = [];
    return { mgr, statuses, sent, ui };
}

try {
    // ── the heartbeat handler exists and answers probes ──────────────────────
    // It used to be dispatched to but never defined, so every inbound heartbeat
    // threw a TypeError and liveness was never actually observed.
    {
        assert.equal(typeof P.handleHeartbeat, 'function', 'handleHeartbeat must exist');

        // A probe must be answered: that reply is the only thing that proves this
        // side is alive when its own timers are throttled by a backgrounded tab.
        const { mgr } = makeManager();
        mgr._lastInboundAt = 0;
        mgr.handleHeartbeat({ type: 'heartbeat', ack: false });
        assert.ok(mgr._lastInboundAt > 0, 'heartbeat must refresh the liveness clock');
        assert.equal(mgr._sentFrames.length, 1);
        assert.equal(mgr._sentFrames[0].ack, true, 'a probe must be acked');

        // An ack must NOT be acked, or the two sides ping-pong forever.
        const { mgr: acked } = makeManager();
        acked.handleHeartbeat({ type: 'heartbeat', ack: true });
        assert.deepEqual(acked._sentFrames, [], 'an ack must not be answered');
    }

    // ── the answerer starts its watchdog even on an already-open channel ─────
    // `ondatachannel` can hand over a channel that is ALREADY 'open', so the
    // 'open' event has been dispatched before onopen is assigned. That left the
    // answering side with no heartbeats and no liveness watchdog at all — the
    // peer whose network was fine kept showing "connected" indefinitely because
    // nothing on that side was running to notice the other one had vanished.
    {
        const started = [];
        const base = {
            isVerified: false,
            pendingSASCode: null,
            _secureLog() {},
            establishConnection: async () => {},
            initializeFileTransfer() {},
            _notifyVerificationReadyIfPossible() {},
            initiateVerification() {},
            processMessageQueue() {},
            onStatusChange() {},
            _resetReconnectState() {},
            _teardownRecoveryLifecycleListeners() {},
            _noteInboundActivity() {},
            startHeartbeat() { started.push(Date.now()); },
            setupDataChannel: P.setupDataChannel
        };

        // Channel already open when handed over: the handler must still run.
        const already = { ...base };
        already.setupDataChannel({ readyState: 'open', send() {} });
        await settle();
        assert.equal(started.length, 1, 'an already-open channel must still start the watchdog');

        // Normal case: the event fires, and the handler must not run twice.
        started.length = 0;
        const later = { ...base };
        const channel = { readyState: 'connecting', send() {} };
        later.setupDataChannel(channel);
        channel.readyState = 'open';
        await channel.onopen();
        await settle();
        assert.equal(started.length, 1, 'the open handler must run exactly once');
    }

    // ── a peer never heard from is not a dead peer ───────────────────────────
    // Right after connecting, the two sides finish SAS verification at different
    // moments, so one can be probing while the other still cannot answer.
    // Without a baseline, that silence used to read as death and tore down a
    // healthy, freshly established session.
    {
        const { mgr, statuses } = makeManager({ _livenessArmed: false });
        mgr._lastInboundAt = Date.now() - (TIMEOUTS.LIVENESS_PROBE_AFTER + 10_000);
        mgr._checkLiveness();
        await settle();
        assert.deepEqual(statuses, [], 'silence before the first frame must not start recovery');
        assert.deepEqual(mgr._sentFrames, [], 'and must not even probe yet');

        // One frame from the peer establishes the baseline; from then on it counts.
        mgr._noteInboundActivity();
        assert.equal(mgr._livenessArmed, true);
        mgr._lastInboundAt = Date.now() - (TIMEOUTS.LIVENESS_PROBE_AFTER + 10_000);
        mgr._checkLiveness();
        assert.equal(mgr._sentFrames.length, 1, 'a known peer that goes quiet is probed');
        mgr._resetReconnectState();
    }

    // ── a peer answers probes before it has finished verifying ───────────────
    // The heartbeat path is gated on the channel, not on isVerified: a human has
    // to compare the SAS code, and for that whole window the other side would
    // otherwise be unable to answer and would be declared dead.
    {
        const { mgr } = makeManager({ isVerified: false, isConnected: () => false });
        mgr.handleHeartbeat({ type: 'heartbeat', ack: false });
        assert.equal(mgr._sentFrames.length, 1, 'an unverified peer must still answer a probe');
        assert.equal(mgr._sentFrames[0].ack, true);
    }

    // ── liveness: silence prompts a probe, only an unanswered probe kills ────
    {
        // Busy conversation: recent inbound activity must NOT trip the watchdog.
        const { mgr, statuses } = makeManager();
        mgr._lastInboundAt = Date.now();
        mgr._checkLiveness();
        assert.deepEqual(statuses, [], 'recent traffic must not trigger recovery');
        assert.deepEqual(mgr._sentFrames, [], 'no probe while the peer is chatting');

        // Silence alone must NOT declare the path dead — a backgrounded tab has
        // its timers throttled and legitimately goes quiet. It only earns a probe.
        const { mgr: quiet, statuses: quietStatuses } = makeManager();
        quiet._lastInboundAt = Date.now() - (TIMEOUTS.LIVENESS_PROBE_AFTER + 1000);
        quiet._checkLiveness();
        assert.deepEqual(quietStatuses, [], 'silence alone must not start recovery');
        assert.equal(quiet._sentFrames.length, 1, 'silence must trigger a probe');
        assert.equal(quiet._sentFrames[0].ack, false);
        assert.ok(quiet._livenessProbeAt > 0);

        // The peer answers → still alive, no recovery, probe cleared.
        quiet.handleHeartbeat({ type: 'heartbeat', ack: true });
        quiet._checkLiveness();
        assert.deepEqual(quietStatuses, [], 'an answered probe proves the path is alive');
        assert.equal(quiet._livenessProbeAt, 0);

        // A peer whose tab the OS froze cannot answer anything — no JavaScript
        // runs in it at all. But ICE consent checks live in the browser's network
        // stack, not the page's thread, so a 'connected' ICE state proves the peer
        // is still reachable and the silence is a sleeping tab. Tearing the
        // session down here is what broke a healthy chat every time a phone
        // locked its screen.
        const { mgr: asleep, statuses: asleepStatuses } = makeManager();
        asleep.peerConnection.connectionState = 'connected';
        asleep._lastInboundAt = Date.now() - (TIMEOUTS.LIVENESS_PROBE_AFTER + 1000);
        asleep._checkLiveness();
        asleep._livenessProbeAt = Date.now() - (TIMEOUTS.LIVENESS_PROBE_TIMEOUT + 1000);
        asleep._checkLiveness();
        await settle();
        assert.deepEqual(asleepStatuses, [], 'a silent peer on a healthy ICE path must be left alone');
        assert.equal(asleep.isReconnecting(), false);
        // And since the answer would change nothing, it must not even be asked:
        // probing here was pure traffic for as long as the peer's phone slept.
        assert.deepEqual(asleep._sentFrames, [], 'a healthy ICE path must not be probed at all');
        assert.equal(asleep._livenessProbeAt, 0);
        asleep._resetReconnectState();

        // Probe goes unanswered past its deadline → the path really is dead.
        // This is the Wi-Fi → LTE case: nothing closes, nothing errors, packets
        // just stop and readyState still reads 'open'.
        const { mgr: dead, statuses: deadStatuses } = makeManager();
        dead._lastInboundAt = Date.now() - (TIMEOUTS.LIVENESS_PROBE_AFTER + 1000);
        dead._checkLiveness();                                   // sends the probe
        dead._livenessProbeAt = Date.now() - (TIMEOUTS.LIVENESS_PROBE_TIMEOUT + 1000);
        dead._checkLiveness();                                   // deadline passed
        await settle();
        assert.ok(deadStatuses.includes('reconnecting'), 'an unanswered probe must start recovery');
        dead._resetReconnectState();
    }

    // ── an unverified session is never dragged into recovery ────────────────
    {
        const { mgr, statuses } = makeManager({ isVerified: false });
        mgr._lastInboundAt = Date.now() - 10 * 60 * 1000;
        mgr._checkLiveness();
        mgr._onPathDegraded('ice_disconnected');
        mgr._onPathLost('ice_failed');
        await settle();
        assert.deepEqual(statuses, [], 'recovery must not run before verification');
    }

    // ── degraded path: UI says reconnecting, session is NOT torn down ────────
    {
        const { mgr, statuses } = makeManager();
        mgr._onPathDegraded('ice_disconnected');
        assert.deepEqual(statuses, ['reconnecting']);
        assert.equal(mgr._verificationCleared, false, 'a transient drop must not clear verification');
        assert.equal(mgr.isVerified, true, 'keys and SAS verification survive a path glitch');
        assert.equal(mgr.isReconnecting(), true);

        // The restart is held back for the grace window, because 'disconnected'
        // usually clears on its own.
        const grace = pending().find((t) => t.delay === TIMEOUTS.ICE_DISCONNECT_GRACE);
        assert.ok(grace, 'a grace window must be scheduled before spending a restart');

        // A second event while already recovering must not restart the cycle.
        mgr._onPathDegraded('ice_disconnected');
        assert.deepEqual(statuses, ['reconnecting'], 'recovery must not be re-entered');
        mgr._resetReconnectState();
        assert.equal(grace.cleared, true, 'reset must clear the grace timer');
    }

    // ── the grace window is sized to the browser's own ICE timings ───────────
    // 'disconnected' arrives after ~5 s of missed consent responses — ordinary
    // packet loss reaches that — and the browser then holds it ~25 s before
    // 'failed'. That window is where self-healing happens, and a phone with its
    // screen off produces these episodes constantly. Restarting at the start of
    // it answered every one with a renegotiation that broke a connection about
    // to recover. https://blog.mozilla.org/webrtc/ice-disconnected-not/
    {
        assert.ok(TIMEOUTS.ICE_DISCONNECT_GRACE >= 5000,
            'must outlast the ~5 s of loss that produces "disconnected" in the first place');
        assert.ok(TIMEOUTS.ICE_DISCONNECT_GRACE + TIMEOUTS.ICE_RESTART_TIMEOUT < 30000,
            'but a restart must still complete before the browser gives up at ~30 s');
    }

    // ── the path recovering during the grace window costs no restart ─────────
    {
        const { mgr, statuses, sent } = makeManager();
        mgr._onPathDegraded('ice_disconnected');
        const grace = pending().find((t) => t.delay === TIMEOUTS.ICE_DISCONNECT_GRACE);
        mgr.peerConnection.connectionState = 'connected';
        fire(grace);
        await settle();
        assert.deepEqual(sent, [], 'a self-healing glitch must not renegotiate');
        assert.deepEqual(statuses, ['reconnecting', 'connected']);
        mgr._resetReconnectState();
    }

    // ── role split: the offerer restarts, the answerer asks ─────────────────
    {
        const { mgr, sent } = makeManager({ isInitiator: true });
        mgr._reconnect.startedAt = Date.now();
        await mgr._attemptIceRestart();
        assert.equal(sent.length, 1);
        assert.equal(sent[0].type, T.ICE_RESTART_OFFER, 'offerer drives the restart');
        assert.ok(sent[0].sdp, 'restart offer carries SDP');
        mgr._resetReconnectState();

        // Both sides offering at once is glare, and with no signalling server
        // there is no referee — so the answerer asks instead of acting.
        const { mgr: answerer, sent: answererSent } = makeManager({ isInitiator: false });
        answerer._reconnect.startedAt = Date.now();
        await answerer._attemptIceRestart();
        assert.equal(answererSent[0].type, T.ICE_RESTART_REQUEST, 'answerer must not create a competing offer');
        answerer._resetReconnectState();
    }

    // ── retries back off, and stop the moment the path is back ──────────────
    {
        const { mgr, sent } = makeManager({ isInitiator: true });
        mgr._reconnect.startedAt = Date.now();
        const backoff = EnhancedSecureWebRTCManager.RECONNECT_BACKOFF;

        await mgr._attemptIceRestart();
        let retry = pending().find((t) => t.kind === 'timeout');
        assert.equal(retry.delay, backoff[0], 'first retry uses the head of the backoff');

        // The round-trip completes but the pair still fails to connect, so the
        // next retry is a genuine second attempt and backs off further.
        mgr.peerConnection.signalingState = 'have-local-offer';
        await mgr._handleIceRestartSignal(T.ICE_RESTART_ANSWER, { sdp: sdpWith(FP_A) });
        fire(retry);
        await settle();
        retry = pending().find((t) => t.kind === 'timeout');
        assert.equal(retry.delay, backoff[1], 'each failed attempt backs off further');
        assert.equal(sent.length, 2, 'each attempt re-sends the restart offer');
        mgr.peerConnection.signalingState = 'have-local-offer';
        await mgr._handleIceRestartSignal(T.ICE_RESTART_ANSWER, { sdp: sdpWith(FP_A) });
        const sentAfterTwoAttempts = sent.length;

        // Path comes back: the pending retry must not fire another restart.
        mgr.peerConnection.connectionState = 'connected';
        fire(retry);
        await settle();
        assert.equal(sent.length, sentAfterTwoAttempts, 'recovery stops as soon as the path is up');
        assert.equal(mgr.isReconnecting(), false);
        mgr._resetReconnectState();
    }

    // ── a healthy connection is never renegotiated ───────────────────────────
    // Recovery can be entered on a stale reading — a mobile tab thawing out of
    // the background is the common one, since its timers were frozen and
    // connectionState is still catching up. Restarting from there broke a
    // working session and stranded it in "reconnecting", where sending is
    // blocked while messages keep arriving.
    {
        const { mgr, sent, statuses } = makeManager();
        mgr._reconnect.phase = 'grace';
        mgr._reconnect.startedAt = Date.now();
        mgr.peerConnection.connectionState = 'connected';

        await mgr._attemptIceRestart();
        assert.deepEqual(sent, [], 'a connected path must not be renegotiated');
        assert.equal(mgr.isReconnecting(), false, 'recovery must stand down, not linger');
        assert.equal(statuses.at(-1), 'connected');
        assert.equal(mgr._queueFlushed, true, 'anything queued meanwhile must go out');
    }

    // ── returning to the foreground asks the peer, it does not accuse it ─────
    {
        const { mgr, statuses } = makeManager();
        mgr._setupRecoveryLifecycleListeners = P._setupRecoveryLifecycleListeners;

        const listeners = {};
        globalThis.window = {
            ...globalThis.window,
            addEventListener: (name, fn) => { listeners[name] = fn; },
            removeEventListener: () => {}
        };
        const realDocument = globalThis.document;
        globalThis.document = {
            visibilityState: 'visible',
            addEventListener: (name, fn) => { listeners[name] = fn; },
            removeEventListener: () => {},
            dispatchEvent: () => {}
        };
        try {
            mgr._setupRecoveryLifecycleListeners();
            // Long silence, but only because the tab's timers were frozen.
            mgr._lastInboundAt = Date.now() - 10 * 60 * 1000;
            listeners.visibilitychange();
            await settle();

            assert.deepEqual(statuses, [], 'coming back must not declare the session broken');
            assert.equal(mgr._sentFrames.length, 1, 'it must probe the peer instead');
            assert.equal(mgr._sentFrames[0].ack, false);
            assert.ok(mgr._livenessProbeAt > 0, 'the probe deadline must be armed');
        } finally {
            globalThis.document = realDocument;
        }
        mgr._resetReconnectState();
    }

    // ── one round-trip at a time ─────────────────────────────────────────────
    // A restart takes seconds end to end, far longer than the head of the
    // backoff. Without this guard each retry replaced the local description out
    // from under the attempt already in flight, so every try cancelled the last
    // and recovery never converged — observed as a long run of attempts that
    // ended in a plain timeout.
    {
        const { mgr, sent } = makeManager({ isInitiator: true });
        mgr._reconnect.startedAt = Date.now();

        await mgr._attemptIceRestart();
        assert.equal(sent.length, 1);
        assert.ok(mgr._reconnect.inFlightAt > 0, 'the round-trip must be marked in flight');

        // The retry fires while the round-trip is still running: it must wait,
        // not launch a competing restart.
        let retry = pending().find((t) => t.kind === 'timeout');
        fire(retry);
        await settle();
        assert.equal(sent.length, 1, 'no competing restart while one is in flight');
        assert.ok(pending().some((t) => t.kind === 'timeout'), 'it must keep waiting, not give up');

        // Round-trip completes (answer applied) → a further attempt is allowed.
        mgr.peerConnection.signalingState = 'have-local-offer';
        await mgr._handleIceRestartSignal(T.ICE_RESTART_ANSWER, { sdp: sdpWith(FP_A) });
        assert.equal(mgr._reconnect.inFlightAt, 0, 'a completed round-trip clears the in-flight mark');
        retry = pending().find((t) => t.kind === 'timeout');
        fire(retry);
        await settle();
        assert.equal(sent.length, 2, 'the next attempt runs once the round-trip is done');
        mgr._resetReconnectState();
    }

    // ── a restart gathers candidates on a budget that fits the round-trip ─────
    {
        const budget = TIMEOUTS.ICE_RESTART_GATHERING;
        assert.ok(budget < TIMEOUTS.ICE_GATHERING_TIMEOUT, 'recovery must gather faster than a fresh handshake');
        assert.ok(budget * 2 < TIMEOUTS.ICE_RESTART_TIMEOUT, 'both gathering legs must fit inside the round-trip budget');

        const { mgr } = makeManager({ isInitiator: true });
        const budgets = [];
        mgr.waitForIceGathering = async (ms) => { budgets.push(ms); return true; };
        mgr._reconnect.startedAt = Date.now();
        await mgr._attemptIceRestart();
        assert.deepEqual(budgets, [budget], 'the restart must pass the short budget');
        mgr._resetReconnectState();
    }

    // ── MITM guard: a restart must never re-point the session at a new identity
    {
        // Same fingerprint as the live session → accepted, answer goes back.
        const { mgr, sent } = makeManager({ isInitiator: false });
        await mgr._handleIceRestartSignal(T.ICE_RESTART_OFFER, { sdp: sdpWith(FP_A) });
        assert.deepEqual(mgr._applied, ['offer']);
        assert.equal(sent.at(-1).type, T.ICE_RESTART_ANSWER);
        mgr._resetReconnectState();

        // Different fingerprint → refused before the peer connection is touched.
        const { mgr: attacked, sent: attackedSent } = makeManager({ isInitiator: false });
        await assert.rejects(
            () => attacked._handleIceRestartSignal(T.ICE_RESTART_OFFER, { sdp: sdpWith(FP_B) }),
            /mismatch/i,
            'a restart offer with a different DTLS fingerprint must be refused'
        );
        assert.deepEqual(attacked._applied, [], 'nothing may be applied to the peer connection');
        assert.deepEqual(attackedSent, [], 'no answer may be sent to an unverified identity');
        attacked._resetReconnectState();

        // Same guard on the answer leg.
        const { mgr: offerer } = makeManager({ isInitiator: true });
        offerer.peerConnection.signalingState = 'have-local-offer';
        await assert.rejects(
            () => offerer._handleIceRestartSignal(T.ICE_RESTART_ANSWER, { sdp: sdpWith(FP_B) }),
            /mismatch/i,
            'a restart answer with a different DTLS fingerprint must be refused'
        );
        assert.deepEqual(offerer._applied, []);
        offerer._resetReconnectState();

        // With no live session to compare against, recovery refuses rather than
        // accepting an unverifiable identity.
        const { mgr: blind } = makeManager({ isInitiator: false });
        blind.peerConnection.currentRemoteDescription = null;
        blind.peerConnection.remoteDescription = null;
        await assert.rejects(
            () => blind._handleIceRestartSignal(T.ICE_RESTART_OFFER, { sdp: sdpWith(FP_A) }),
            /identity/i,
            'no baseline fingerprint must mean refusal, not blind trust'
        );
        blind._resetReconnectState();
    }

    // ── a restart request is only honoured by the offerer ───────────────────
    {
        const { mgr, sent } = makeManager({ isInitiator: false });
        await mgr._handleIceRestartSignal(T.ICE_RESTART_REQUEST, {});
        assert.deepEqual(sent, [], 'the answerer must ignore a restart request');
        mgr._resetReconnectState();

        const { mgr: offerer, sent: offererSent } = makeManager({ isInitiator: true });
        await offerer._handleIceRestartSignal(T.ICE_RESTART_REQUEST, {});
        assert.equal(offererSent[0].type, T.ICE_RESTART_OFFER);
        offerer._resetReconnectState();
    }

    // ── recovery completes: the same session resumes, the queue drains ───────
    {
        dispatched.length = 0;
        const { mgr, statuses } = makeManager();
        mgr._onPathDegraded('ice_disconnected');
        statuses.length = 0;
        mgr.peerConnection.connectionState = 'connected';
        mgr._onPathRecovered();
        assert.deepEqual(statuses, ['connected']);
        assert.equal(mgr._queueFlushed, true, 'messages sent into the dead path must go out');
        assert.equal(mgr.isReconnecting(), false);
        assert.equal(mgr._reconnect.attempts, 0, 'attempt counter resets for the next drop');
        assert.ok(dispatched.includes('connection-recovered'));

        // Recovering from an idle state is a no-op — no spurious 'connected'.
        const { mgr: idle, statuses: idleStatuses } = makeManager();
        idle._onPathRecovered();
        assert.deepEqual(idleStatuses, [], 'no status churn when nothing was broken');
    }

    // ── recovery stops when the channel cannot carry the renegotiation ───────
    // Every route out of a broken path runs over the data channel. If the peer
    // has been completely silent since recovery began, it carries nothing in
    // either direction and no further attempt can succeed. This matters most for
    // the answerer, which cannot renegotiate on its own and would otherwise sit
    // out the whole deadline sending requests nobody can receive — observed as a
    // long run of attempts ending in a plain timeout.
    {
        for (const role of [true, false]) {
            const { mgr, statuses, ui } = makeManager({ isInitiator: role });
            mgr._reconnect.startedAt = Date.now() - 60_000;
            mgr._lastInboundAt = Date.now() - 60_000;
            mgr._reconnect.attempts = 3;

            await mgr._attemptIceRestart();
            assert.equal(mgr._reconnect.phase, 'exhausted',
                `a silent channel must end recovery (${role ? 'offerer' : 'answerer'})`);
            assert.equal(statuses.at(-1), 'recovery_failed',
                'the UI must be told to tear the conversation down, not merely show a drop');
            assert.match(ui[0], /wiped/i, 'and the user must be told the chat is being closed');
        }

        // A peer that is still answering keeps recovery alive.
        const { mgr: alive, sent } = makeManager();
        alive._reconnect.startedAt = Date.now() - 60_000;
        alive._lastInboundAt = Date.now();          // heard from just now
        alive._reconnect.attempts = 3;
        await alive._attemptIceRestart();
        assert.notEqual(alive._reconnect.phase, 'exhausted', 'a responsive peer must not be abandoned');
        assert.equal(sent.length, 1, 'and the attempt goes out');
        alive._resetReconnectState();

        // Early attempts are never cut short on silence alone — a restart
        // round-trip has to be given a chance to produce its first reply.
        const { mgr: early } = makeManager();
        early._reconnect.startedAt = Date.now() - 60_000;
        early._lastInboundAt = Date.now() - 60_000;
        early._reconnect.attempts = 0;
        await early._attemptIceRestart();
        assert.notEqual(early._reconnect.phase, 'exhausted', 'the first attempt must still be tried');
        early._resetReconnectState();
    }

    // ── an ICE agent that cannot gather at all is not worth retrying ─────────
    // After a network change a PeerConnection is often left bound to interfaces
    // that no longer exist: every STUN and TURN request times out and each
    // restart fails with zero candidate pairs. restartIce() cannot rebind it, so
    // spending the whole two-minute deadline on it is two minutes of the user
    // watching nothing happen when the outcome was already decided.
    {
        const { mgr, statuses, ui } = makeManager();
        mgr._noteIceFailureDiagnostics = P._noteIceFailureDiagnostics;
        mgr._reconnect.phase = 'restarting';
        mgr._reconnect.startedAt = Date.now();

        // A failure that still produced pairs is an ordinary flaky path.
        mgr._noteIceFailureDiagnostics({ pairCount: 3 });
        assert.equal(mgr._reconnect.barrenFailures, 0);
        assert.notEqual(statuses.at(-1), 'disconnected');

        // Barren failures accumulate; one alone is not enough to conclude.
        mgr._noteIceFailureDiagnostics({ pairCount: 0 });
        assert.equal(mgr.isReconnecting(), true, 'one barren failure must not end recovery');

        // A pair appearing resets the count — the agent is evidently alive.
        mgr._noteIceFailureDiagnostics({ pairCount: 1 });
        assert.equal(mgr._reconnect.barrenFailures, 0, 'evidence of life resets the count');

        mgr._noteIceFailureDiagnostics({ pairCount: 0 });
        mgr._noteIceFailureDiagnostics({ pairCount: 0 });
        assert.equal(mgr._reconnect.phase, 'exhausted', 'a barren agent ends recovery promptly');
        assert.equal(statuses.at(-1), 'recovery_failed');
        assert.equal(ui.length, 1, 'and the user is told once, with the way out');
    }

    // ── a closed data channel cannot be repaired by an ICE restart ───────────
    // SCTP goes with it, so there is nothing left to carry the renegotiation.
    {
        const { mgr, statuses, ui } = makeManager();
        mgr.dataChannel = { readyState: 'closed' };
        mgr._reconnect.startedAt = Date.now();
        await mgr._attemptIceRestart();
        assert.equal(mgr._reconnect.phase, 'exhausted');
        assert.equal(statuses.at(-1), 'recovery_failed');
        assert.equal(mgr._verificationCleared, true, 'an unrecoverable session clears verification');
        assert.equal(ui.length, 1);
        assert.match(ui[0], /wiped/i, 'the user is told the chat is being closed and wiped');
        assert.deepEqual(pending().filter((t) => t.kind === 'timeout'), [], 'giving up leaves no timers behind');
    }

    // ── a device with no network holds the session instead of losing it ──────
    // A five-minute tunnel must not cost the user their session: no restart can
    // succeed with the radio off, so the give-up deadline is held open.
    {
        // Node exposes navigator as a getter-only global, so swap the descriptor.
        const realNavigator = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
        const fakeNavigator = { onLine: false };
        Object.defineProperty(globalThis, 'navigator', { value: fakeNavigator, configurable: true });
        try {
            const { mgr, sent, statuses } = makeManager();
            mgr._reconnect.startedAt = Date.now() - (TIMEOUTS.RECONNECT_MAX_DURATION + 60_000);
            await mgr._attemptIceRestart();
            assert.equal(mgr._reconnect.phase, 'waiting', 'recovery waits rather than giving up');
            assert.notEqual(statuses.at(-1), 'disconnected', 'an offline device must not end the session');
            assert.deepEqual(sent, [], 'nothing is transmitted with no network');

            // The hold must schedule a real retry, not a 0 ms spin.
            const retry = pending().find((t) => t.kind === 'timeout');
            assert.ok(retry && retry.delay > 0, 'the offline hold must schedule a sane retry delay');

            // Network comes back → retry immediately, deadline starts fresh.
            fakeNavigator.onLine = true;
            await mgr._attemptIceRestart();
            assert.equal(sent.at(-1).type, T.ICE_RESTART_OFFER, 'recovery resumes once the radio is back');
            mgr._resetReconnectState();
        } finally {
            if (realNavigator) Object.defineProperty(globalThis, 'navigator', realNavigator);
            else delete globalThis.navigator;
        }
    }

    // ── giving up is bounded by the overall deadline ─────────────────────────
    {
        const { mgr, statuses } = makeManager();
        mgr._reconnect.startedAt = Date.now() - (TIMEOUTS.RECONNECT_MAX_DURATION + 1000);
        await mgr._attemptIceRestart();
        assert.equal(mgr._reconnect.phase, 'exhausted');
        assert.equal(statuses.at(-1), 'recovery_failed');
    }

    // ── manual retry restarts the cycle with a fresh deadline ───────────────
    {
        const { mgr, sent } = makeManager();
        mgr.reconnectionFailedNotificationSent = true;
        mgr._reconnect.phase = 'exhausted';
        const ok = P.attemptReconnection.call(mgr);
        await settle();
        assert.equal(ok, true);
        assert.equal(mgr.reconnectionFailedNotificationSent, false, 'the user can be told again if it fails again');
        assert.equal(sent.at(-1).type, T.ICE_RESTART_OFFER);
        mgr._resetReconnectState();

        // Nothing to restart over: report failure instead of pretending.
        const { mgr: gone, ui } = makeManager();
        gone.dataChannel = { readyState: 'closed' };
        assert.equal(P.attemptReconnection.call(gone), false);
        assert.match(ui[0], /new connection is required/i);
    }

    // ── backoff is bounded and monotonic ─────────────────────────────────────
    {
        const backoff = EnhancedSecureWebRTCManager.RECONNECT_BACKOFF;
        assert.ok(backoff.length > 0);
        for (let i = 1; i < backoff.length; i += 1) {
            assert.ok(backoff[i] >= backoff[i - 1], 'backoff must not shrink');
        }
        assert.ok(Object.isFrozen(backoff));
    }

    // ── recovery frames never surface as chat messages ───────────────────────
    {
        const manager = {
            _debugMode: false,
            _secureLog() {},
            getSecurityStatus: () => ({ activeFeaturesCount: 0 }),
            _checkInboundRateLimit: () => true
        };
        for (const type of [T.ICE_RESTART_OFFER, T.ICE_RESTART_ANSWER, T.ICE_RESTART_REQUEST]) {
            const result = await P.removeSecurityLayers.call(manager, JSON.stringify({ type, sdp: 'v=0' }));
            assert.equal(result, 'SYSTEM_MESSAGE_FILTERED', `${type} must not reach the chat log`);
        }
    }

    console.log('session-recovery.test.mjs: all assertions passed');
} finally {
    Object.assign(globalThis, realTimers);
}
