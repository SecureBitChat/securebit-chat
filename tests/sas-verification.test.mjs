import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

let compareCalls = 0;
globalThis.window = {
    EnhancedSecureCryptoUtils: {
        constantTimeCompare(a, b) {
            compareCalls += 1;
            return a === b;
        }
    }
};

const { EnhancedSecureWebRTCManager } = await import('../src/network/EnhancedSecureWebRTCManager.js');

function createFakeManager() {
    const sent = [];
    return {
        sent,
        verificationCode: 'A1-B2-C3',
        sasValidationAttempts: 0,
        localVerificationConfirmed: false,
        remoteVerificationConfirmed: false,
        bothVerificationsConfirmed: false,
        disconnected: false,
        _validateSASCode: EnhancedSecureWebRTCManager.prototype._validateSASCode,
        _secureLog() {},
        deliverMessageToUI() {},
        disconnect() {
            this.disconnected = true;
        },
        dataChannel: {
            send(payload) {
                sent.push(JSON.parse(payload));
            }
        },
        _checkBothVerificationsConfirmed() {},
        processMessageQueue() {}
    };
}

function createSASManager() {
    return {
        _secureLog() {}
    };
}

function createVerificationReadinessManager({
    localDescription = { type: 'answer' },
    remoteDescription = { type: 'offer' },
    dataChannelState = 'connecting',
    verificationCode = 'A1-B2-C3',
    localFingerprint = 'AA:BB',
    remoteFingerprint = 'CC:DD'
} = {}) {
    const notifications = [];
    return {
        peerConnection: { localDescription, remoteDescription },
        dataChannel: { readyState: dataChannelState },
        verificationCode,
        _sasLocalFingerprint: localFingerprint,
        _sasRemoteFingerprint: remoteFingerprint,
        notifications,
        _isVerificationReady: EnhancedSecureWebRTCManager.prototype._isVerificationReady,
        onStatusChange(status) {
            notifications.push({ kind: 'status', value: status });
        },
        onVerificationRequired(code) {
            notifications.push({ kind: 'verification', value: code });
        }
    };
}

// testSASNormalization
{
    const manager = createFakeManager();
    assert.equal(EnhancedSecureWebRTCManager.prototype._validateSASCode.call(manager, 'a1 b2 c3'), true);
    assert.equal(EnhancedSecureWebRTCManager.prototype._validateSASCode.call(manager, 'A1B2C3'), true);
}

// testConstantTimeCompare
{
    const manager = createFakeManager();
    compareCalls = 0;
    assert.equal(EnhancedSecureWebRTCManager.prototype._validateSASCode.call(manager, 'A1-B2-C3'), true);
    assert.equal(compareCalls, 1);
}

// testInvalidInputs
{
    const manager = createFakeManager();
    assert.equal(EnhancedSecureWebRTCManager.prototype._validateSASCode.call(manager, null), false);
    assert.equal(EnhancedSecureWebRTCManager.prototype._validateSASCode.call(manager, 'A1B2'), false);
    assert.equal(EnhancedSecureWebRTCManager.prototype._validateSASCode.call(manager, 'FFFFFF'), false);
}

// three failed attempts disconnect; a correct attempt signals only after validation
{
    const manager = createFakeManager();
    for (let i = 0; i < 2; i += 1) {
        assert.throws(
            () => EnhancedSecureWebRTCManager.prototype.confirmVerification.call(manager, 'FFFFFF'),
            /SAS_MISMATCH/
        );
    }
    assert.equal(manager.disconnected, false);
    assert.throws(
        () => EnhancedSecureWebRTCManager.prototype.confirmVerification.call(manager, 'FFFFFF'),
        /SAS_MAX_ATTEMPTS/
    );
    assert.equal(manager.disconnected, true);

    const validManager = createFakeManager();
    EnhancedSecureWebRTCManager.prototype.confirmVerification.call(validManager, 'a1 b2 c3');
    assert.equal(validManager.localVerificationConfirmed, true);
    assert.equal(validManager.sent[0].type, 'verification_confirmed');
    assert.equal(validManager.sent[0].data.verificationMethod, 'MANUAL_SAS_ENTRY');
}

// SAS is deterministic for the same key material and normalized fingerprints,
// and changes when either fingerprint changes.
{
    const manager = createSASManager();
    const keyMaterial = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const computeSAS = EnhancedSecureWebRTCManager.prototype._computeSAS;

    const baseline = await computeSAS.call(manager, keyMaterial, ' AA:BB ', 'CC:DD');
    const sameInputsNormalized = await computeSAS.call(manager, keyMaterial, 'aa:bb', ' cc:dd ');
    const changedLocal = await computeSAS.call(manager, keyMaterial, 'AA:BC', 'CC:DD');
    const changedRemote = await computeSAS.call(manager, keyMaterial, 'AA:BB', 'CC:DE');

    assert.equal(baseline, sameInputsNormalized);
    assert.notEqual(baseline, changedLocal);
    assert.notEqual(baseline, changedRemote);
}

// SAS rejects non-string or empty fingerprints instead of allowing JS coercion.
{
    const manager = createSASManager();
    const keyMaterial = new Uint8Array([1, 2, 3, 4]);
    const computeSAS = EnhancedSecureWebRTCManager.prototype._computeSAS;
    const invalidFingerprints = [{ fingerprint: 'aa' }, ['aa'], null, ''];

    for (const invalidFingerprint of invalidFingerprints) {
        await assert.rejects(
            () => computeSAS.call(manager, keyMaterial, invalidFingerprint, 'CC:DD'),
            /Security error: localFP must be a non-empty DTLS fingerprint string/
        );
        await assert.rejects(
            () => computeSAS.call(manager, keyMaterial, 'AA:BB', invalidFingerprint),
            /Security error: remoteFP must be a non-empty DTLS fingerprint string/
        );
    }
}

// The salt is built only from normalized fingerprint strings.
{
    const manager = createSASManager();
    const keyMaterial = new Uint8Array([9, 8, 7, 6]);
    let capturedSalt = '';
    const originalCryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');

    Object.defineProperty(globalThis, 'crypto', {
        configurable: true,
        value: {
            subtle: {
                importKey: (...args) => webcrypto.subtle.importKey(...args),
                deriveBits: async (params, ...args) => {
                    capturedSalt = new TextDecoder().decode(params.salt);
                    return webcrypto.subtle.deriveBits(params, ...args);
                }
            }
        }
    });

    try {
        await EnhancedSecureWebRTCManager.prototype._computeSAS.call(manager, keyMaterial, ' AA:BB ', 'CC:DD ');
        assert.equal(capturedSalt, 'webrtc-sas|aa:bb|cc:dd');
        assert.equal(capturedSalt.includes('[object Object]'), false);
    } finally {
        Object.defineProperty(globalThis, 'crypto', originalCryptoDescriptor);
    }
}

// Extraction returns a deterministic primary string for SAS binding.
{
    const manager = createSASManager();
    const sdp = [
        'v=0',
        'a=fingerprint:sha-512 FF:EE',
        'a=fingerprint:sha-256 BB:BB',
        'a=fingerprint:sha-256 AA:AA'
    ].join('\r\n');

    assert.equal(
        EnhancedSecureWebRTCManager.prototype._extractDTLSFingerprintFromSDP.call(manager, sdp),
        'AA:AA'
    );
}

// ICE diagnostics classify candidate types so connectivity failures are visible.
{
    const manager = createSASManager();
    const sdp = [
        'v=0',
        'a=candidate:1 1 UDP 2122252543 192.168.1.2 54400 typ host',
        'a=candidate:2 1 UDP 1686052607 203.0.113.10 40000 typ srflx raddr 192.168.1.2 rport 54400',
        'a=candidate:3 1 UDP 41819902 198.51.100.20 50000 typ relay raddr 0.0.0.0 rport 0',
        'a=candidate:4 1 UDP 1518280447 198.51.100.30 60000 typ prflx',
        'a=candidate:5 1 UDP 1518280447 198.51.100.40 61000 generation 0'
    ].join('\r\n');

    assert.deepEqual(
        EnhancedSecureWebRTCManager.prototype._summarizeIceCandidatesInSDP.call(manager, sdp),
        { total: 5, host: 1, srflx: 1, relay: 1, prflx: 1, unknown: 1 }
    );
}

// Manual exchange must not treat an ICE gathering timeout as completion.
{
    const listeners = new Map();
    const manager = {
        peerConnection: {
            iceGatheringState: 'gathering',
            addEventListener(eventName, handler) {
                listeners.set(eventName, handler);
            },
            removeEventListener(eventName) {
                listeners.delete(eventName);
            }
        }
    };

    const originalTimeout = EnhancedSecureWebRTCManager.TIMEOUTS.ICE_GATHERING_TIMEOUT;
    EnhancedSecureWebRTCManager.TIMEOUTS.ICE_GATHERING_TIMEOUT = 0;
    try {
        assert.equal(
            await EnhancedSecureWebRTCManager.prototype.waitForIceGathering.call(manager),
            false
        );
    } finally {
        EnhancedSecureWebRTCManager.TIMEOUTS.ICE_GATHERING_TIMEOUT = originalTimeout;
    }
}

// A timed-out ICE gathering can still yield usable candidates for manual export.
{
    const summary = EnhancedSecureWebRTCManager.prototype._summarizeIceCandidatesInSDP.call(
        createSASManager(),
        'a=candidate:1 1 UDP 2122252543 192.168.1.2 54400 typ host\r\n'
    );
    assert.equal(summary.total > 0, true);
}

// ICE gathering resolves positively only after the peer reports completion.
{
    let listener = null;
    const manager = {
        peerConnection: {
            iceGatheringState: 'gathering',
            addEventListener(_eventName, handler) {
                listener = handler;
            },
            removeEventListener() {}
        }
    };

    const gathering = EnhancedSecureWebRTCManager.prototype.waitForIceGathering.call(manager);
    manager.peerConnection.iceGatheringState = 'complete';
    listener();
    assert.equal(await gathering, true);
}

// ICE failure diagnostics summarize candidate-pair states without crashing.
{
    const reports = new Map([
        ['local-1', { id: 'local-1', type: 'local-candidate', candidateType: 'host', protocol: 'udp', address: '192.168.1.2', port: 5000 }],
        ['remote-1', { id: 'remote-1', type: 'remote-candidate', candidateType: 'srflx', protocol: 'udp', address: '203.0.113.10', port: 6000 }],
        ['pair-1', { id: 'pair-1', type: 'candidate-pair', state: 'failed', nominated: false, writable: false, bytesSent: 0, bytesReceived: 0, localCandidateId: 'local-1', remoteCandidateId: 'remote-1' }]
    ]);

    const manager = {
        peerConnection: {
            async getStats() {
                return reports;
            }
        }
    };

    assert.deepEqual(
        await EnhancedSecureWebRTCManager.prototype._collectIceFailureDiagnostics.call(manager),
        {
            pairCount: 1,
            states: { failed: 1 },
            pairs: [{
                state: 'failed',
                nominated: false,
                writable: false,
                bytesSent: 0,
                bytesReceived: 0,
                currentRoundTripTime: null,
                local: {
                    type: 'local-candidate',
                    candidateType: 'host',
                    protocol: 'udp',
                    address: '192.168.1.2',
                    port: 5000,
                    networkType: null
                },
                remote: {
                    type: 'remote-candidate',
                    candidateType: 'srflx',
                    protocol: 'udp',
                    address: '203.0.113.10',
                    port: 6000,
                    networkType: null
                }
            }]
        }
    );
}

// Remote SDP candidate summaries use the same parser as local diagnostics.
{
    const sdp = [
        'v=0',
        'a=candidate:1 1 UDP 2122252543 192.168.1.2 54400 typ host',
        'a=candidate:2 1 UDP 1686052607 203.0.113.10 40000 typ srflx'
    ].join('\r\n');
    assert.deepEqual(
        EnhancedSecureWebRTCManager.prototype._summarizeIceCandidatesInSDP.call(createSASManager(), sdp),
        { total: 2, host: 1, srflx: 1, relay: 0, prflx: 0, unknown: 0 }
    );
}

// Joining with an offer and generating an answer does not open verification
// before the answer has been applied by the creator and the channel opens.
{
    const joiner = createVerificationReadinessManager({
        dataChannelState: 'connecting'
    });
    assert.equal(EnhancedSecureWebRTCManager.prototype._isVerificationReady.call(joiner), false);
    assert.equal(
        EnhancedSecureWebRTCManager.prototype._notifyVerificationReadyIfPossible.call(joiner),
        false
    );
    assert.deepEqual(joiner.notifications, []);
}

// The creator has applied the answer only once both descriptions exist; even
// then verification waits for a real ready transport.
{
    const creatorBeforeAnswer = createVerificationReadinessManager({
        remoteDescription: null,
        dataChannelState: 'open'
    });
    assert.equal(EnhancedSecureWebRTCManager.prototype._isVerificationReady.call(creatorBeforeAnswer), false);

    const creatorAfterAnswerBeforeOpen = createVerificationReadinessManager({
        dataChannelState: 'connecting'
    });
    assert.equal(EnhancedSecureWebRTCManager.prototype._isVerificationReady.call(creatorAfterAnswerBeforeOpen), false);
}

// Verification opens only after negotiated descriptions, open data channel, and
// valid SAS fingerprint material are all present.
{
    const missingFingerprint = createVerificationReadinessManager({
        dataChannelState: 'open',
        remoteFingerprint: ''
    });
    assert.equal(EnhancedSecureWebRTCManager.prototype._isVerificationReady.call(missingFingerprint), false);

    const ready = createVerificationReadinessManager({
        dataChannelState: 'open'
    });
    assert.equal(EnhancedSecureWebRTCManager.prototype._isVerificationReady.call(ready), true);
    assert.equal(
        EnhancedSecureWebRTCManager.prototype._notifyVerificationReadyIfPossible.call(ready),
        true
    );
    assert.deepEqual(ready.notifications, [
        { kind: 'status', value: 'verifying' },
        { kind: 'verification', value: 'A1-B2-C3' }
    ]);

    // Existing happy path stays idempotent after the UI is opened once.
    EnhancedSecureWebRTCManager.prototype._notifyVerificationReadyIfPossible.call(ready);
    assert.equal(ready.notifications.length, 2);
}

// SDP diagnostics distinguish candidate-less exports from usable manual payloads.
{
    assert.equal(
        EnhancedSecureWebRTCManager.prototype._countIceCandidatesInSDP.call({}, 'v=0\r\na=mid:0'),
        0
    );
    assert.equal(
        EnhancedSecureWebRTCManager.prototype._countIceCandidatesInSDP.call(
            {},
            'v=0\r\na=candidate:1 1 udp 1 192.0.2.1 1234 typ host\r\na=candidate:2 1 udp 1 198.51.100.1 2345 typ srflx'
        ),
        2
    );
}

console.log('SAS verification tests passed');
