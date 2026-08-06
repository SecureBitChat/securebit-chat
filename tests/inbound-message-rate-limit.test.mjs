import assert from 'node:assert/strict';

// Each call returns the next queued plaintext, so a flood can be distinguished
// message by message rather than all looking alike.
let nextPlaintext = 'hello';
globalThis.window = {
    EnhancedSecureCryptoUtils: {
        async decryptMessage() {
            return {
                message: JSON.stringify({ type: 'message', data: nextPlaintext }),
                messageId: 'msg_1',
                sequenceNumber: 0
            };
        }
    }
};

const { EnhancedSecureWebRTCManager } = await import('../src/network/EnhancedSecureWebRTCManager.js');

function fakeManager({ perMinute = 60, burst = 10 } = {}) {
    return {
        delivered: [],
        logs: [],
        _inputValidationLimits: {
            rateLimitMessagesPerMinute: perMinute,
            rateLimitBurstSize: burst
        },
        encryptionKey: {},
        macKey: {},
        metadataKey: {},
        // Anti-replay is a separate mechanism with its own test; keep this one
        // focused on rate limiting.
        _validateIncomingSequenceNumber: () => true,
        _checkInboundRateLimit: EnhancedSecureWebRTCManager.prototype._checkInboundRateLimit,
        _secureLog(level, message, context) {
            this.logs.push({ level, message, context });
        },
        onMessage() {},
        deliverMessageToUI(message, type) {
            this.delivered.push({ message, type });
        }
    };
}

// The rate limiter is exercised through `enhanced_message`, the only frame type
// that carries chat content. It used to be driven here through a bare
// `{type:'message'}` frame, but those are rejected now: they were
// unauthenticated peer input rendered as a real message.
const deliver = (manager, text) => {
    nextPlaintext = text;
    return EnhancedSecureWebRTCManager.prototype._processEnhancedMessageWithoutMutex.call(
        manager,
        { type: 'enhanced_message', data: 'ciphertext' }
    );
};

// Normal inbound messages are delivered.
{
    const manager = fakeManager();
    await deliver(manager, 'hello');
    assert.deepEqual(manager.delivered, [{ message: 'hello', type: 'received' }]);
}

// Burst floods are dropped safely and logged.
{
    const manager = fakeManager({ burst: 1 });
    await deliver(manager, 'first');
    await deliver(manager, 'second');
    assert.deepEqual(manager.delivered, [{ message: 'first', type: 'received' }]);
    assert.match(manager.logs.at(-1).message, /Inbound message burst limit exceeded/);
}

// Sustained-window floods are rejected independently of burst accounting.
{
    const manager = fakeManager({ perMinute: 1, burst: 10 });
    await deliver(manager, 'first');
    manager._inboundRateLimiter.lastBurstReset = Date.now() - 1001;
    await deliver(manager, 'second');
    assert.deepEqual(manager.delivered, [{ message: 'first', type: 'received' }]);
    assert.match(manager.logs.at(-1).message, /Inbound message rate limit exceeded/);
}

// And an unauthenticated frame is refused outright, limiter or no limiter —
// rate limiting is not what keeps injected chat text out.
{
    const manager = fakeManager();
    await EnhancedSecureWebRTCManager.prototype.processMessage.call(
        manager,
        JSON.stringify({ type: 'message', data: 'injected' })
    );
    assert.deepEqual(manager.delivered, [], 'a bare message frame must never be delivered');
}

// Binary and enhanced helpers are guarded before expensive processing.
{
    const binaryManager = {
        ...fakeManager({ burst: 0 }),
        securityFeatures: {
            hasNestedEncryption: false,
            hasPacketPadding: false,
            hasAntiFingerprinting: false
        }
    };
    await EnhancedSecureWebRTCManager.prototype._processBinaryDataWithoutMutex.call(
        binaryManager,
        new TextEncoder().encode('binary hello').buffer
    );
    assert.deepEqual(binaryManager.delivered, []);

    const enhancedManager = {
        ...fakeManager({ burst: 0 }),
        encryptionKey: {},
        macKey: {},
        metadataKey: {}
    };
    await EnhancedSecureWebRTCManager.prototype._processEnhancedMessageWithoutMutex.call(
        enhancedManager,
        { data: 'ciphertext' }
    );
    assert.deepEqual(enhancedManager.delivered, []);
}

// Outbound limiter remains a separate state machine.
{
    const manager = {
        _inputValidationLimits: {
            rateLimitMessagesPerMinute: 1,
            rateLimitBurstSize: 1
        },
        _secureLog() {},
        _checkRateLimit: EnhancedSecureWebRTCManager.prototype._checkRateLimit,
        _checkInboundRateLimit: EnhancedSecureWebRTCManager.prototype._checkInboundRateLimit
    };
    assert.equal(manager._checkRateLimit('send'), true);
    assert.equal(manager._checkInboundRateLimit('receive'), true);
    assert.notEqual(manager._rateLimiter, manager._inboundRateLimiter);
}

console.log('Inbound message rate limit tests passed');
