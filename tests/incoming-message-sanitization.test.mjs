import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const { window } = new JSDOM('<!doctype html><html><body></body></html>', {
    url: 'http://localhost/?debug'
});
window.DEBUG_MODE = true;
window.DEVELOPMENT_MODE = true;
window.webpackHotUpdate = {};
globalThis.window = window;

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

// Script payloads are removed while harmless visible text survives.
{
    const manager = createManager();
    EnhancedSecureWebRTCManager.prototype.deliverMessageToUI.call(manager, '<script>alert(1)</script>Hello <b>peer</b>', 'received');
    assert.deepEqual(manager.delivered[0], { message: 'Hello peer', type: 'received' });
}

// Dangerous protocols in markup and event handlers never reach React state.
{
    const manager = createManager();
    EnhancedSecureWebRTCManager.prototype.deliverMessageToUI.call(manager, '<a href="javascript:alert(1)">click</a><details ontoggle="alert(1)">open</details>', 'received');
    assert.deepEqual(manager.delivered[0], { message: 'clickopen', type: 'received' });
}

// SVG payloads and malformed HTML do not create executable remnants.
{
    const manager = createManager();
    EnhancedSecureWebRTCManager.prototype.deliverMessageToUI.call(manager, '<svg><script>alert(1)</script><a xlink:href="javascript:alert(2)">x</a></svg>', 'received');
    assert.deepEqual(manager.delivered[0], { message: '', type: 'received' });

    const malformedManager = createManager();
    EnhancedSecureWebRTCManager.prototype.deliverMessageToUI.call(malformedManager, '<div><b>Hello<script>alert(1)', 'received');
    assert.deepEqual(malformedManager.delivered[0], { message: 'Hello', type: 'received' });
}

// Plain text and Unicode text stay plain and intact.
{
    const manager = createManager();
    EnhancedSecureWebRTCManager.prototype.deliverMessageToUI.call(manager, 'javascript: is harmless as plain text', 'received');
    EnhancedSecureWebRTCManager.prototype.deliverMessageToUI.call(manager, 'Привет 👋 こんにちは', 'received');
    assert.deepEqual(manager.delivered[0], { message: 'javascript: is harmless as plain text', type: 'received' });
    assert.deepEqual(manager.delivered[1], { message: 'Привет 👋 こんにちは', type: 'received' });
}

// Outgoing/system messages are not altered by the incoming-message gate.
{
    const manager = createManager();
    EnhancedSecureWebRTCManager.prototype.deliverMessageToUI.call(manager, '<b>system</b>', 'system');
    assert.deepEqual(manager.delivered[0], { message: '<b>system</b>', type: 'system' });
}

console.log('Incoming message sanitization tests passed');
