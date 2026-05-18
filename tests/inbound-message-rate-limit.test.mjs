import assert from 'node:assert/strict';

globalThis.window = {
    EnhancedSecureCryptoUtils: {
        async decryptMessage() {
            return { message: JSON.stringify({ type: 'message', data: 'enhanced hello' }) };
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

// Normal inbound messages are delivered.
{
    const manager = fakeManager();
    await EnhancedSecureWebRTCManager.prototype.processMessage.call(
        manager,
        JSON.stringify({ type: 'message', data: 'hello' })
    );
    assert.deepEqual(manager.delivered, [{ message: 'hello', type: 'received' }]);
}

// Burst floods are dropped safely and logged.
{
    const manager = fakeManager({ burst: 1 });
    await EnhancedSecureWebRTCManager.prototype.processMessage.call(manager, JSON.stringify({ type: 'message', data: 'first' }));
    await EnhancedSecureWebRTCManager.prototype.processMessage.call(manager, JSON.stringify({ type: 'message', data: 'second' }));
    assert.deepEqual(manager.delivered, [{ message: 'first', type: 'received' }]);
    assert.match(manager.logs.at(-1).message, /Inbound message burst limit exceeded/);
}

// Sustained-window floods are rejected independently of burst accounting.
{
    const manager = fakeManager({ perMinute: 1, burst: 10 });
    await EnhancedSecureWebRTCManager.prototype.processMessage.call(manager, JSON.stringify({ type: 'message', data: 'first' }));
    manager._inboundRateLimiter.lastBurstReset = Date.now() - 1001;
    await EnhancedSecureWebRTCManager.prototype.processMessage.call(manager, JSON.stringify({ type: 'message', data: 'second' }));
    assert.deepEqual(manager.delivered, [{ message: 'first', type: 'received' }]);
    assert.match(manager.logs.at(-1).message, /Inbound message rate limit exceeded/);
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
