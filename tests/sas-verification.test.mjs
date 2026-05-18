import assert from 'node:assert/strict';

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

console.log('SAS verification tests passed');
