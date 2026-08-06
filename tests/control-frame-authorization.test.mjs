// Regression tests for the SAS-bypass and the unauthenticated control plane.
//
// Both bugs shared a root cause: "the peer completed the handshake" was treated
// as "the peer is who the user thinks it is". It is not — a MITM who sits on the
// out-of-band invite channel completes the handshake too, and holds the session
// keys. Only the SAS comparison distinguishes them, so nothing that reshapes the
// session may happen before it.

import assert from 'node:assert/strict';

globalThis.window = {
    EnhancedSecureCryptoUtils: { secureLog: { log() {} } }
};
globalThis.CustomEvent = class CustomEvent {
    constructor(type, init) { this.type = type; this.detail = init?.detail; }
};
globalThis.document = { dispatchEvent() {} };

const { EnhancedSecureWebRTCManager } = await import('../src/network/EnhancedSecureWebRTCManager.js');
const P = EnhancedSecureWebRTCManager.prototype;
const T = EnhancedSecureWebRTCManager.MESSAGE_TYPES;

const FP = 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99';
const sdpWith = (fp) => `v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\na=fingerprint:sha-256 ${fp}\r\n`;

// ── the fingerprint comparison must not grant verification ───────────────────
// sessionMode is 'ratchet' for every session, so this branch ran on every
// restart round-trip. Because matching fingerprints are the NORMAL case, it
// effectively meant "any peer that echoes back the identity we already know is
// verified" — reachable with a single frame, and it bypassed _setVerifiedStatus
// and therefore the local-SAS-confirmation check it exists to enforce.
{
    const mgr = {
        sessionMode: 'ratchet',
        isVerified: false,
        _secureLog() {}
    };

    const same = await P._validateDTLSFingerprint.call(mgr, FP, FP, 'ice_restart_offer');
    assert.equal(same, true, 'identical fingerprints must still compare equal');
    assert.equal(mgr.isVerified, false,
        'comparing fingerprints must never mark the session verified');

    // And a genuine mismatch must still be refused, loudly.
    await assert.rejects(
        () => P._validateDTLSFingerprint.call(mgr, FP, '00:' + FP.slice(3), 'ice_restart_offer'),
        /mismatch/i,
        'a changed DTLS identity must be refused'
    );
    assert.equal(mgr.isVerified, false);
}

// ── _setVerifiedStatus remains the only way in ───────────────────────────────
{
    const mgr = {
        isVerified: false,
        encryptionKey: {}, macKey: {},
        localVerificationConfirmed: false,
        keyFingerprint: 'x',
        _secureLog() {},
        onStatusChange() {}
    };

    assert.throws(
        () => P._setVerifiedStatus.call(mgr, true, 'MUTUAL_SAS_CONFIRMED'),
        /local SAS confirmation/i,
        'a SAS-based transition without local confirmation must be refused'
    );
    assert.equal(mgr.isVerified, false);

    mgr.localVerificationConfirmed = true;
    P._setVerifiedStatus.call(mgr, true, 'MUTUAL_SAS_CONFIRMED');
    assert.equal(mgr.isVerified, true, 'the legitimate path must still work');
}

// ── control frames are refused before verification, honoured after ───────────
{
    const makeChannelManager = (isVerified) => {
        const seen = { deleted: [], delivered: [], call: [], ice: [] };
        const mgr = {
            isVerified,
            _secureLog() {},
            _noteInboundActivity() {},
            _enforceVerificationGate: P._enforceVerificationGate,
            establishConnection: async () => {},
            initializeFileTransfer() {},
            _notifyVerificationReadyIfPossible() {},
            initiateVerification() {},
            processMessageQueue() {},
            onStatusChange() {},
            _resetReconnectState() {},
            _teardownRecoveryLifecycleListeners() {},
            startHeartbeat() {},
            // The verified branch of the open handler schedules these on a timer.
            calculateAndReportSecurityLevel: async () => {},
            autoEnableSecurityFeatures() {},
            notifySecurityUpdate() {},
            pendingSASCode: null,
            onMessageDelete: (id) => seen.deleted.push(id),
            onMessageDelivered: (id) => seen.delivered.push(id),
            _handleCallSignal: async (type) => { seen.call.push(type); },
            _handleIceRestartSignal: async (type) => { seen.ice.push(type); },
            setupDataChannel: P.setupDataChannel
        };
        const channel = { readyState: 'open', send() {} };
        mgr.setupDataChannel(channel);
        return { mgr, channel, seen };
    };

    const frames = [
        [T.ICE_RESTART_OFFER, { sdp: sdpWith(FP) }],
        [T.ICE_RESTART_ANSWER, { sdp: sdpWith(FP) }],
        [T.ICE_RESTART_REQUEST, {}],
        [T.CALL_OFFER, { sdp: sdpWith(FP), callId: 'c1' }],
        [T.CALL_ANSWER, { sdp: sdpWith(FP) }],
        [T.CALL_ICE, { candidate: {} }],
        [T.CALL_DECLINE, {}],
        [T.CALL_END, {}],
        [T.MESSAGE_DELETE, { messageId: 'm1' }],
        [T.MESSAGE_RECEIPT, { messageId: 'm1' }]
    ];

    // Unverified: this is the MITM window. Nothing may take effect.
    {
        const { channel, seen } = makeChannelManager(false);
        for (const [type, data] of frames) {
            await channel.onmessage({ data: JSON.stringify({ type, data }) });
        }
        assert.deepEqual(seen.ice, [], 'no ICE restart may be driven before verification');
        assert.deepEqual(seen.call, [], 'no call may be signalled before verification');
        assert.deepEqual(seen.deleted, [], 'no message may be deleted before verification');
        assert.deepEqual(seen.delivered, [], 'no receipt may be forged before verification');
    }

    // Verified: the features must still work — a gate that breaks the product
    // gets removed by the next person who touches this file.
    {
        const { channel, seen } = makeChannelManager(true);
        for (const [type, data] of frames) {
            await channel.onmessage({ data: JSON.stringify({ type, data }) });
        }
        assert.deepEqual(seen.ice,
            [T.ICE_RESTART_OFFER, T.ICE_RESTART_ANSWER, T.ICE_RESTART_REQUEST]);
        assert.deepEqual(seen.call,
            [T.CALL_OFFER, T.CALL_ANSWER, T.CALL_ICE, T.CALL_DECLINE, T.CALL_END]);
        assert.deepEqual(seen.deleted, ['m1']);
        assert.deepEqual(seen.delivered, ['m1']);
    }

    // Every gated type must be in the allowlist, or it silently falls through to
    // the chat channel's default-deny branch and the feature breaks instead.
    for (const [type] of frames) {
        assert.ok(EnhancedSecureWebRTCManager.POST_VERIFICATION_CONTROL_TYPES.has(type),
            `${type} must be declared as a post-verification control frame`);
    }

    // The verification handshake itself must NOT be gated: it has to run before
    // verification exists, otherwise no session could ever be established.
    for (const type of [T.HEARTBEAT, T.VERIFICATION, T.VERIFICATION_RESPONSE,
                        T.VERIFICATION_CONFIRMED, T.VERIFICATION_BOTH_CONFIRMED]) {
        assert.equal(EnhancedSecureWebRTCManager.POST_VERIFICATION_CONTROL_TYPES.has(type), false,
            `${type} must stay reachable before verification`);
    }
}

// ── the legacy processMessage pipeline delivers nothing unauthenticated ──────
// It is unreachable from the live handler today, but it is a second inbound
// pipeline with weaker rules; if it ever gets called it must not undo the fix.
{
    const delivered = [];
    const mgr = {
        isVerified: false,
        _secureLog() {},
        _noteInboundActivity() {},
        _checkInboundRateLimit: () => true,
        _enforceVerificationGate: P._enforceVerificationGate,
        onMessage: () => {},
        deliverMessageToUI: (m) => delivered.push(m),
        onMessageDelete: (id) => delivered.push(`delete:${id}`),
        onMessageDelivered: (id) => delivered.push(`receipt:${id}`),
        _handleCallSignal: async () => { delivered.push('call'); },
        _handleIceRestartSignal: async () => { delivered.push('ice'); },
        processMessage: P.processMessage
    };

    await mgr.processMessage(JSON.stringify({ type: 'message', data: 'injected' }));
    await mgr.processMessage('not json at all');
    await mgr.processMessage(JSON.stringify({ type: T.ICE_RESTART_OFFER, data: { sdp: sdpWith(FP) } }));
    await mgr.processMessage(JSON.stringify({ type: T.MESSAGE_DELETE, data: { messageId: 'm1' } }));

    assert.deepEqual(delivered, [],
        'the legacy pipeline must not deliver or act on unauthenticated frames');
}

console.log('control-frame-authorization.test.mjs: all assertions passed');
