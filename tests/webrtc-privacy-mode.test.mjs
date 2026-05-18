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
                privacyMode: config.privacyMode ?? (config.relayOnly ? 'relay-only' : 'standard'),
                relayOnly: config.relayOnly ?? false,
                iceServers: config.iceServers ?? [{ urls: 'stun:stun.example.test:3478' }]
            }
        },
        _ipLeakWarningShown: false,
        delivered: [],
        deliverMessageToUI(message, type) {
            this.delivered.push({ message, type });
        },
        _hasTurnServer: EnhancedSecureWebRTCManager.prototype._hasTurnServer,
        _isRelayOnlyMode: EnhancedSecureWebRTCManager.prototype._isRelayOnlyMode,
        _setRelayOnlyMode: EnhancedSecureWebRTCManager.prototype._setRelayOnlyMode
    };
}

// Standard mode remains usable, but it is not relay-only.
{
    const manager = fake();
    const config = EnhancedSecureWebRTCManager.prototype._buildPeerConnectionConfig.call(manager);
    assert.equal(config.iceTransportPolicy, undefined);
    assert.equal(config.iceServers[0].urls, 'stun:stun.example.test:3478');
}

// Explicit privacy mode uses relay-only transport, suppressing host/srflx usage.
{
    const manager = fake({ privacyMode: 'relay-only', iceServers: [{ urls: 'turn:turn.example.test:3478' }] });
    const config = EnhancedSecureWebRTCManager.prototype._buildPeerConnectionConfig.call(manager);
    assert.equal(config.iceTransportPolicy, 'relay');
}

// Backward-compatible relayOnly alias still enables relay transport.
{
    const manager = fake({ relayOnly: true, iceServers: [{ urls: 'turn:turn.example.test:3478' }] });
    const config = EnhancedSecureWebRTCManager.prototype._buildPeerConnectionConfig.call(manager);
    assert.equal(config.iceTransportPolicy, 'relay');
}

// Runtime toggles keep the canonical privacy state synchronized.
{
    const manager = fake({ privacyMode: 'standard', iceServers: [{ urls: 'turn:turn.example.test:3478' }] });
    manager._setRelayOnlyMode(true);
    assert.equal(manager._config.webrtc.privacyMode, 'relay-only');
    assert.equal(manager._config.webrtc.relayOnly, true);
    assert.equal(EnhancedSecureWebRTCManager.prototype._buildPeerConnectionConfig.call(manager).iceTransportPolicy, 'relay');

    manager._setRelayOnlyMode(false);
    assert.equal(manager._config.webrtc.privacyMode, 'standard');
    assert.equal(manager._config.webrtc.relayOnly, false);
    assert.equal(EnhancedSecureWebRTCManager.prototype._buildPeerConnectionConfig.call(manager).iceTransportPolicy, undefined);
}

// Canonical privacyMode wins over a stale legacy alias.
{
    const manager = fake({ privacyMode: 'standard', relayOnly: true, iceServers: [{ urls: 'turn:turn.example.test:3478' }] });
    assert.equal(manager._isRelayOnlyMode(), false);
    assert.equal(EnhancedSecureWebRTCManager.prototype._buildPeerConnectionConfig.call(manager).iceTransportPolicy, undefined);
}

// Missing TURN in standard mode warns clearly and visibly.
{
    const manager = fake();
    EnhancedSecureWebRTCManager.prototype._warnIfTurnMissing.call(manager);
    assert.equal(manager.delivered[0].type, 'system');
    assert.match(manager.delivered[0].message, /relay-only mode is disabled/i);
    assert.match(manager.delivered[0].message, /may expose host or server-reflexive IP addresses/i);
}

// STUN-only config does not claim IP protection, even with privacy mode selected.
{
    const manager = fake({ privacyMode: 'relay-only', iceServers: [{ urls: 'stun:stun.example.test:3478' }] });
    assert.equal(EnhancedSecureWebRTCManager.prototype._hasTurnServer.call(manager), false);
    EnhancedSecureWebRTCManager.prototype._warnIfTurnMissing.call(manager);
    assert.match(manager.delivered[0].message, /STUN alone does not hide IP addresses/i);
}

// Non-private mode warns even when TURN exists because direct candidates remain allowed.
{
    const manager = fake({ iceServers: [{ urls: 'turn:turn.example.test:3478' }] });
    EnhancedSecureWebRTCManager.prototype._warnIfTurnMissing.call(manager);
    assert.equal(manager.delivered[0].type, 'system');
    assert.match(manager.delivered[0].message, /relay-only mode is disabled/i);
    assert.match(manager.delivered[0].message, /may expose host or server-reflexive IP addresses/i);
}

// ICE defaults are centralized and operator overrides remain untouched.
{
    assert.equal(Array.isArray(EnhancedSecureWebRTCManager.DEFAULT_ICE_SERVERS), true);
    assert.equal(
        EnhancedSecureWebRTCManager.DEFAULT_ICE_SERVERS.some(server => server.urls === 'stun:stun.cloudflare.com:3478'),
        true
    );
    const overrideServers = [{ urls: ['stun:operator.example.test:3478', 'turn:operator.example.test:3478'] }];
    const manager = fake({ iceServers: overrideServers });
    const config = EnhancedSecureWebRTCManager.prototype._buildPeerConnectionConfig.call(manager);
    assert.equal(config.iceServers, overrideServers);
}

console.log('WebRTC privacy mode tests passed');
