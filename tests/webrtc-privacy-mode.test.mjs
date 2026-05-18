import assert from 'node:assert/strict';

globalThis.window = {
    EnhancedSecureCryptoUtils: {},
    DEBUG_MODE: true,
    DEVELOPMENT_MODE: true,
    location: { hostname: 'localhost', search: '?debug' },
    webpackHotUpdate: {}
};

const { EnhancedSecureWebRTCManager } = await import('../src/network/EnhancedSecureWebRTCManager.js');

function fake(config = {}) {
    return {
        _config: {
            webrtc: {
                relayOnly: config.relayOnly ?? false,
                iceServers: config.iceServers ?? [{ urls: 'stun:stun.example.test:3478' }]
            }
        },
        _ipLeakWarningShown: false,
        delivered: [],
        deliverMessageToUI(message, type) {
            this.delivered.push({ message, type });
        },
        _hasTurnServer: EnhancedSecureWebRTCManager.prototype._hasTurnServer
    };
}

// Default mode preserves current behavior.
{
    const manager = fake();
    const config = EnhancedSecureWebRTCManager.prototype._buildPeerConnectionConfig.call(manager);
    assert.equal(config.iceTransportPolicy, undefined);
    assert.equal(config.iceServers[0].urls, 'stun:stun.example.test:3478');
}

// Privacy mode uses relay-only transport.
{
    const manager = fake({ relayOnly: true, iceServers: [{ urls: 'turn:turn.example.test:3478' }] });
    const config = EnhancedSecureWebRTCManager.prototype._buildPeerConnectionConfig.call(manager);
    assert.equal(config.iceTransportPolicy, 'relay');
}

// Missing TURN warns clearly.
{
    const manager = fake();
    EnhancedSecureWebRTCManager.prototype._warnIfTurnMissing.call(manager);
    assert.match(manager.delivered[0].message, /may expose IP addresses/i);
}

// STUN-only config does not claim IP protection, even with privacy mode selected.
{
    const manager = fake({ relayOnly: true, iceServers: [{ urls: 'stun:stun.example.test:3478' }] });
    assert.equal(EnhancedSecureWebRTCManager.prototype._hasTurnServer.call(manager), false);
    EnhancedSecureWebRTCManager.prototype._warnIfTurnMissing.call(manager);
    assert.match(manager.delivered[0].message, /STUN alone does not hide IP addresses/i);
}

console.log('WebRTC privacy mode tests passed');
