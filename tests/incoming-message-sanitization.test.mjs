import assert from 'node:assert/strict';

globalThis.window = {
    DEBUG_MODE: true,
    DEVELOPMENT_MODE: true,
    webpackHotUpdate: {},
    location: {
        hostname: 'localhost',
        search: '?debug'
    }
};

const { EnhancedSecureCryptoUtils } = await import('../src/crypto/EnhancedSecureCryptoUtils.js');
window.EnhancedSecureCryptoUtils = EnhancedSecureCryptoUtils;
const { EnhancedSecureWebRTCManager } = await import('../src/network/EnhancedSecureWebRTCManager.js');

function createManager() {
    return {
        delivered: [],
        _debugMode: false,
        _secureLog() {},
        _sanitizeIncomingChatMessage: EnhancedSecureWebRTCManager.prototype._sanitizeIncomingChatMessage,
        onMessage(message, type) {
            this.delivered.push({ message, type });
        }
    };
}

// Normal text survives unchanged.
{
    const manager = createManager();
    EnhancedSecureWebRTCManager.prototype.deliverMessageToUI.call(manager, 'hello secure world', 'received');
    assert.deepEqual(manager.delivered[0], { message: 'hello secure world', type: 'received' });
}

// XSS-like and HTML payloads are sanitized before UI delivery.
{
    const manager = createManager();
    EnhancedSecureWebRTCManager.prototype.deliverMessageToUI.call(manager, '<script>alert(1)</script>Hello <b>peer</b>', 'received');
    assert.deepEqual(manager.delivered[0], { message: 'Hello peer', type: 'received' });
}

// Event-handler and protocol strings are removed before reaching React state.
{
    const manager = createManager();
    EnhancedSecureWebRTCManager.prototype.deliverMessageToUI.call(manager, '<img src=x onerror=alert(1)> javascript:alert(1)', 'received');
    assert.deepEqual(manager.delivered[0], { message: 'alert(1)', type: 'received' });
}

// Outgoing/system messages are not altered by the incoming-message gate.
{
    const manager = createManager();
    EnhancedSecureWebRTCManager.prototype.deliverMessageToUI.call(manager, '<b>system</b>', 'system');
    assert.deepEqual(manager.delivered[0], { message: '<b>system</b>', type: 'system' });
}

console.log('Incoming message sanitization tests passed');
