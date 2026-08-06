// ICE gathering only reaches 'complete' once every configured STUN/TURN server
// has answered or timed out. On a network that blocks them — a VPN, a captive
// portal, an interface the browser cannot route from — that never happens, even
// though host candidates are available immediately and are enough to connect on
// a LAN.
//
// The old code waited a flat 10 s and then failed the whole handshake if the SDP
// happened to be empty at that instant. That made success a coin flip: the same
// device failed one attempt and connected on the next with gathering still in
// progress (observed in the field, 11 candidates at 10001 ms).

import assert from 'node:assert/strict';

globalThis.window = { EnhancedSecureCryptoUtils: { secureLog: { log() {} } } };
globalThis.CustomEvent = class { constructor(t, i) { this.type = t; this.detail = i?.detail; } };
globalThis.document = { dispatchEvent() {} };

const { EnhancedSecureWebRTCManager } = await import('../src/network/EnhancedSecureWebRTCManager.js');
const P = EnhancedSecureWebRTCManager.prototype;
const T = EnhancedSecureWebRTCManager.TIMEOUTS;

// Fake timers so the 10 s / 25 s deadlines can be driven by hand.
const realSetTimeout = globalThis.setTimeout;
const realClearTimeout = globalThis.clearTimeout;
let timers = [];
globalThis.setTimeout = (fn, delay) => {
    const t = { fn, delay, cleared: false };
    timers.push(t);
    return t;
};
globalThis.clearTimeout = (t) => { if (t) t.cleared = true; };
const fireDelay = (delay) => {
    for (const t of timers.filter((x) => !x.cleared && x.delay === delay)) {
        t.cleared = true;
        t.fn();
    }
};

const sdpWithCandidates = (n) =>
    'v=0\r\n' + Array.from({ length: n }, (_, i) =>
        `a=candidate:${i} 1 udp 2122260223 192.168.1.${i + 2} 5000${i} typ host\r\n`).join('');

function makeManager(candidateCount) {
    const listeners = [];
    const ui = [];
    return {
        ui,
        listeners,
        peerConnection: {
            iceGatheringState: 'gathering',
            localDescription: { sdp: sdpWithCandidates(candidateCount) },
            addEventListener: (name, fn) => listeners.push({ name, fn }),
            removeEventListener: () => {}
        },
        _activeTimers: new Set(),
        _secureLog() {},
        deliverMessageToUI: (m) => ui.push(m),
        _trackActiveTimer: P._trackActiveTimer,
        _untrackActiveTimer: P._untrackActiveTimer,
        _summarizeIceCandidatesInSDP: P._summarizeIceCandidatesInSDP,
        _countIceCandidatesInSDP: P._countIceCandidatesInSDP,
        waitForIceGathering: P.waitForIceGathering
    };
}

try {
    // ── the budget must actually be longer than the soft deadline ────────────
    assert.ok(T.ICE_GATHERING_HARD_TIMEOUT > T.ICE_GATHERING_TIMEOUT,
        'the hard ceiling must leave room past the soft deadline');

    // ── already complete: return immediately, no waiting ─────────────────────
    {
        timers = [];
        const mgr = makeManager(3);
        mgr.peerConnection.iceGatheringState = 'complete';
        assert.equal(await mgr.waitForIceGathering(), true);
        assert.deepEqual(timers.filter((t) => !t.cleared), [], 'no timers left behind');
    }

    // ── gathering finishes on its own: resolve true and drop the timers ──────
    {
        timers = [];
        const mgr = makeManager(3);
        const pending = mgr.waitForIceGathering();
        mgr.peerConnection.iceGatheringState = 'complete';
        mgr.listeners.forEach((l) => l.fn());
        assert.equal(await pending, true);
        assert.deepEqual(timers.filter((t) => !t.cleared), [],
            'a completed gather must not leave the hard timer armed');
    }

    // ── soft deadline WITH candidates: stop waiting, report "not complete" ───
    // This is the common case on a restricted network, and it must succeed: the
    // caller only refuses to export when there is nothing at all.
    {
        timers = [];
        const mgr = makeManager(11);
        const pending = mgr.waitForIceGathering();
        fireDelay(T.ICE_GATHERING_TIMEOUT);
        assert.equal(await pending, false, 'gathering did not complete...');
        // ...but the caller's guard is `!completed && count === 0`, so 11
        // candidates mean the handshake proceeds.
        assert.ok(mgr._summarizeIceCandidatesInSDP(mgr.peerConnection.localDescription.sdp).total > 0);
    }

    // ── soft deadline with NOTHING: keep waiting instead of failing ──────────
    // The regression under test. Previously this resolved at 10 s with an empty
    // SDP and the handshake threw.
    {
        timers = [];
        const mgr = makeManager(0);
        let settled = false;
        const pending = mgr.waitForIceGathering().then((v) => { settled = true; return v; });

        fireDelay(T.ICE_GATHERING_TIMEOUT);
        await Promise.resolve();
        assert.equal(settled, false, 'an empty SDP at the soft deadline must not end the wait');

        // A candidate arriving late is exactly what the extra patience buys.
        mgr.peerConnection.localDescription.sdp = sdpWithCandidates(4);
        mgr.peerConnection.iceGatheringState = 'complete';
        mgr.listeners.forEach((l) => l.fn());
        assert.equal(await pending, true, 'a late completion must still be picked up');
    }

    // ── a genuinely dead network still fails, at the hard ceiling ────────────
    {
        timers = [];
        const mgr = makeManager(0);
        const pending = mgr.waitForIceGathering();
        fireDelay(T.ICE_GATHERING_TIMEOUT);
        fireDelay(T.ICE_GATHERING_HARD_TIMEOUT);
        assert.equal(await pending, false, 'nothing gathered at all must eventually give up');
    }

    // ── a caller-supplied budget shorter than the hard default is honoured ───
    // Session recovery passes 4 s and must not silently wait 25 s instead.
    {
        timers = [];
        const mgr = makeManager(0);
        const pending = mgr.waitForIceGathering(T.ICE_RESTART_GATHERING, T.ICE_RESTART_GATHERING);
        fireDelay(T.ICE_RESTART_GATHERING);
        assert.equal(await pending, false, 'the recovery path keeps its short budget');
    }

    console.log('ice-gathering-patience.test.mjs: all assertions passed');
} finally {
    globalThis.setTimeout = realSetTimeout;
    globalThis.clearTimeout = realClearTimeout;
}
