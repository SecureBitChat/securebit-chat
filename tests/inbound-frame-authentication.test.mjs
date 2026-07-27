// Regression tests for inbound frame authentication.
//
// Chat content must reach the UI through exactly one door: an `enhanced_message`
// that has been AES-GCM decrypted, HMAC-verified and replay-checked. Anything
// else arriving on the data channel is unauthenticated peer input and must be
// dropped rather than rendered as if it were a real message.

import assert from 'node:assert/strict';

globalThis.window = globalThis.window || {};

const { EnhancedSecureWebRTCManager } = await import('../src/network/EnhancedSecureWebRTCManager.js');
const P = EnhancedSecureWebRTCManager.prototype;

function createReceiver({ isVerified = true } = {}) {
    const delivered = [];
    const receiver = {
        delivered,
        isVerified,
        encryptionKey: null,
        macKey: null,
        metadataKey: null,
        securityFeatures: {},
        onMessage: (m, t) => delivered.push({ message: m, type: t }),
        deliverMessageToUI(msg, type) { this.onMessage(msg, type); },
        _secureLog() {},
        _checkInboundRateLimit: () => true,
        establishConnection: async () => {},
        initializeFileTransfer() {},
        startHeartbeat() {},
        _notifyVerificationReadyIfPossible() {},
        initiateVerification() {},
        setupDataChannel: P.setupDataChannel,
        _processBinaryDataWithoutMutex: P._processBinaryDataWithoutMutex,
        _processEnhancedMessageWithoutMutex: P._processEnhancedMessageWithoutMutex
    };
    const channel = { readyState: 'open', send() {} };
    receiver.setupDataChannel(channel);
    return { receiver, channel };
}

// ── unencrypted {type:'message'} frames are rejected ─────────────────────────
{
    const { receiver, channel } = createReceiver();
    await channel.onmessage({
        data: JSON.stringify({ type: 'message', data: 'injected without any crypto' })
    });
    assert.deepEqual(receiver.delivered, [], 'plaintext message frames must not reach the UI');
}

// ── raw non-JSON text is rejected ────────────────────────────────────────────
{
    const { receiver, channel } = createReceiver();
    await channel.onmessage({ data: 'not even json' });
    assert.deepEqual(receiver.delivered, [], 'raw text frames must not reach the UI');
}

// ── binary frames never reach the UI ─────────────────────────────────────────
{
    const { receiver, channel } = createReceiver();
    const buf = new TextEncoder().encode('binary injection').buffer;
    await channel.onmessage({ data: buf });
    assert.deepEqual(receiver.delivered, [], 'binary frames must not reach the UI');
}

// ── cover traffic is still discarded silently ────────────────────────────────
{
    const { receiver, channel } = createReceiver();
    const fake = new TextEncoder().encode(JSON.stringify({ type: 'fake', isFakeTraffic: true })).buffer;
    await channel.onmessage({ data: fake });
    assert.deepEqual(receiver.delivered, []);
}

// ── the authenticated path still delivers, and enforces anti-replay ──────────
{
    let seq = 0;
    globalThis.window.EnhancedSecureCryptoUtils = {
        decryptMessage: async () => ({
            message: JSON.stringify({ type: 'message', data: `msg-${seq}` }),
            messageId: `id-${seq}`,
            sequenceNumber: seq
        })
    };

    const delivered = [];
    const receiver = {
        encryptionKey: {}, macKey: {}, metadataKey: {},
        _secureLog() {},
        _checkInboundRateLimit: () => true,
        _sanitizeIncomingChatMessage: (m) => m,
        _sanitizeMessageMeta: P._sanitizeMessageMeta,
        _validateIncomingSequenceNumber: P._validateIncomingSequenceNumber,
        replayProtectionEnabled: true,
        expectedSequenceNumber: 0,
        replayWindow: new Set(),
        replayWindowSize: 64,
        maxSequenceGap: 100,
        onMessage: (m) => delivered.push(m),
        deliverMessageToUI: P.deliverMessageToUI,
        _processEnhancedMessageWithoutMutex: P._processEnhancedMessageWithoutMutex
    };

    seq = 0;
    await receiver._processEnhancedMessageWithoutMutex({ type: 'enhanced_message', data: 'enc' });
    seq = 1;
    await receiver._processEnhancedMessageWithoutMutex({ type: 'enhanced_message', data: 'enc' });
    assert.deepEqual(delivered, ['msg-0', 'msg-1'], 'fresh messages must be delivered');

    // Replaying sequence number 0 must be refused.
    seq = 0;
    await receiver._processEnhancedMessageWithoutMutex({ type: 'enhanced_message', data: 'enc' });
    assert.deepEqual(delivered, ['msg-0', 'msg-1'], 'replayed message must be dropped');
}

// ── a missing sequence number fails closed ───────────────────────────────────
{
    const receiver = {
        replayProtectionEnabled: true,
        expectedSequenceNumber: 0,
        replayWindow: new Set(),
        replayWindowSize: 64,
        maxSequenceGap: 100,
        _secureLog() {},
        _validateIncomingSequenceNumber: P._validateIncomingSequenceNumber
    };

    assert.equal(receiver._validateIncomingSequenceNumber(undefined, 't'), false);
    assert.equal(receiver._validateIncomingSequenceNumber(null, 't'), false);
    assert.equal(receiver._validateIncomingSequenceNumber('3', 't'), false);
    assert.equal(receiver._validateIncomingSequenceNumber(NaN, 't'), false);
    assert.equal(receiver.replayWindow.size, 0, 'rejected values must not pollute the window');
    assert.equal(receiver._validateIncomingSequenceNumber(0, 't'), true);
}

// ── file control frames are gated on verification ────────────────────────────
{
    const handled = [];
    const makeReceiver = (isVerified) => {
        const receiver = {
            isVerified,
            securityFeatures: {},
            fileTransferSystem: { handleFileMessage: async (m) => handled.push(m.type) },
            _secureLog() {},
            _checkInboundRateLimit: () => true,
            _enforceVerificationGate: P._enforceVerificationGate,
            onMessage() {},
            deliverMessageToUI() {},
            establishConnection: async () => {},
            initializeFileTransfer() {},
            startHeartbeat() {},
            _notifyVerificationReadyIfPossible() {},
            initiateVerification() {},
            setupDataChannel: P.setupDataChannel
        };
        const channel = { readyState: 'open', send() {} };
        receiver.setupDataChannel(channel);
        return channel;
    };

    // Unverified peer: file frames must be dropped, not acted on.
    const unverified = makeReceiver(false);
    await unverified.onmessage({
        data: JSON.stringify({ type: 'file_transfer_start', fileId: 'f1', fileName: 'x.png' })
    });
    await unverified.onmessage({ data: JSON.stringify({ type: 'file_chunk', fileId: 'f1' }) });
    assert.deepEqual(handled, [], 'file frames must not be processed before verification');

    // Verified peer: transfers keep working exactly as before.
    const verified = makeReceiver(true);
    await verified.onmessage({
        data: JSON.stringify({ type: 'file_transfer_start', fileId: 'f1', fileName: 'x.png' })
    });
    await verified.onmessage({ data: JSON.stringify({ type: 'file_chunk', fileId: 'f1' }) });
    assert.deepEqual(handled, ['file_transfer_start', 'file_chunk'], 'verified transfers must still work');
}

// ── anti-replay helpers live on the connection, not on key storage ───────────
{
    for (const name of [
        '_validateIncomingSequenceNumber',
        '_validateMessageAAD',
        'getAntiReplayStatus',
        'configureAntiReplayProtection'
    ]) {
        assert.equal(
            typeof P[name],
            'function',
            `${name} must be reachable on the WebRTC manager (it reads this.replayWindow)`
        );
    }
}

console.log('Inbound frame authentication tests passed');
