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

console.log('SAS verification tests passed');
