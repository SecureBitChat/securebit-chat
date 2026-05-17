import assert from 'node:assert/strict';

globalThis.window = {
    EnhancedSecureCryptoUtils: {
        secureLog: { log() {} }
    }
};
globalThis.CustomEvent = class CustomEvent {
    constructor(type, init) {
        this.type = type;
        this.detail = init?.detail;
    }
};
const dispatchedEvents = [];
globalThis.document = {
    dispatchEvent(event) {
        dispatchedEvents.push(event);
    }
};

const { EnhancedSecureWebRTCManager } = await import('../src/network/EnhancedSecureWebRTCManager.js');

function closableChannel() {
    return {
        readyState: 'open',
        closed: false,
        onopen() {},
        onclose() {},
        onmessage() {},
        onerror() {},
        close() { this.closed = true; }
    };
}

{
    let transferCleanups = 0;
    const dataChannel = closableChannel();
    const heartbeatChannel = closableChannel();
    const decoyChannel = closableChannel();
    const peerConnection = {
        closed: false,
        onconnectionstatechange() {},
        ondatachannel() {},
        close() { this.closed = true; }
    };
    const timer = setTimeout(() => {}, 10_000);
    const manager = {
        intentionalDisconnect: false,
        fileTransferSystem: { cleanup() { transferCleanups += 1; } },
        dataChannel,
        heartbeatChannel,
        peerConnection,
        decoyTimers: new Map([['decoy', timer]]),
        decoyChannels: new Map([['decoy', decoyChannel]]),
        packetBuffer: new Map([['p', 1]]),
        chunkQueue: [1],
        processedMessageIds: new Set(['m']),
        messageCounter: 4,
        keyVersions: new Map([['v', 1]]),
        oldKeys: new Map([['o', 1]]),
        currentKeyVersion: 3,
        lastKeyRotation: 1,
        sequenceNumber: 7,
        expectedSequenceNumber: 8,
        replayWindow: new Set([9]),
        messageQueue: [{ secret: true }],
        calls: [],
        _stopAllTimers() { this.calls.push('_stopAllTimers'); },
        stopHeartbeat() { this.calls.push('stopHeartbeat'); },
        stopFakeTrafficGeneration() { this.calls.push('stopFakeTrafficGeneration'); },
        _wipeEphemeralKeys() { this.calls.push('_wipeEphemeralKeys'); },
        _hardWipeOldKeys() { this.calls.push('_hardWipeOldKeys'); },
        _secureCleanupCryptographicMaterials() { this.calls.push('_secureCleanupCryptographicMaterials'); },
        _clearVerificationStates() {
            this.calls.push('_clearVerificationStates');
            this.localVerificationConfirmed = false;
            this.remoteVerificationConfirmed = false;
            this.bothVerificationsConfirmed = false;
            this.isVerified = false;
            this.verificationCode = null;
            this.pendingSASCode = null;
        },
        _secureWipeMemory() { this.calls.push('_secureWipeMemory'); },
        _forceGarbageCollection() { return Promise.resolve(); },
        sendDisconnectNotification() { this.calls.push('sendDisconnectNotification'); },
        onStatusChange(value) { this.status = value; },
        onKeyExchange(value) { this.keyExchange = value; },
        onVerificationRequired(value) { this.verificationRequired = value; },
        _secureLog() {}
    };

    EnhancedSecureWebRTCManager.prototype.disconnect.call(manager);

    assert.equal(transferCleanups, 1);
    assert.equal(manager.fileTransferSystem, null);
    assert.equal(dataChannel.closed, true);
    assert.equal(heartbeatChannel.closed, true);
    assert.equal(decoyChannel.closed, true);
    assert.equal(peerConnection.closed, true);
    assert.equal(manager.dataChannel, null);
    assert.equal(manager.heartbeatChannel, null);
    assert.equal(manager.peerConnection, null);
    assert.equal(manager.decoyTimers.size, 0);
    assert.equal(manager.decoyChannels.size, 0);
    assert.equal(manager.packetBuffer.size, 0);
    assert.deepEqual(manager.chunkQueue, []);
    assert.equal(manager.processedMessageIds.size, 0);
    assert.equal(manager.keyVersions.size, 0);
    assert.equal(manager.oldKeys.size, 0);
    assert.equal(manager.replayWindow.size, 0);
    assert.deepEqual(manager.messageQueue, []);
    assert.equal(manager.status, 'disconnected');
    assert.equal(manager.keyExchange, '');
    assert.equal(manager.verificationRequired, '');
    assert.ok(manager.calls.includes('_clearVerificationStates'));
    assert.ok(dispatchedEvents.some(event => event.type === 'peer-disconnect'));
    assert.ok(dispatchedEvents.some(event => event.type === 'connection-cleaned'));
}

console.log('Disconnect cleanup tests passed');
