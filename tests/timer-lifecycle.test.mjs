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
globalThis.document = { dispatchEvent() {} };

const { EnhancedSecureWebRTCManager } = await import('../src/network/EnhancedSecureWebRTCManager.js');

const realSetTimeout = globalThis.setTimeout;
const realClearTimeout = globalThis.clearTimeout;
const realSetInterval = globalThis.setInterval;
const realClearInterval = globalThis.clearInterval;

const timers = [];
globalThis.setTimeout = (callback, delay) => {
    const timer = { kind: 'timeout', callback, delay, cleared: false };
    timers.push(timer);
    return timer;
};
globalThis.clearTimeout = (timer) => {
    if (timer) timer.cleared = true;
};
globalThis.setInterval = (callback, delay) => {
    const timer = { kind: 'interval', callback, delay, cleared: false };
    timers.push(timer);
    return timer;
};
globalThis.clearInterval = (timer) => {
    if (timer) timer.cleared = true;
};

try {
    // Periodic log cleanup is tracked and cleared with the existing timer system.
    {
        const manager = {
            _activeTimers: new Set(),
            _startKeySecurityMonitoring() {},
            _verifyAPIIntegrity() { return true; },
            _startSecurityMonitoring() {},
            _cleanupLogs() {},
            _secureLog() {}
        };
        manager._trackActiveTimer = EnhancedSecureWebRTCManager.prototype._trackActiveTimer;
        EnhancedSecureWebRTCManager.prototype._finalizeSecureInitialization.call(manager);
        assert.equal(manager._activeTimers.size, 1);
        const logTimer = manager._logCleanupInterval;
        EnhancedSecureWebRTCManager.prototype._stopAllTimers.call(manager);
        assert.equal(logTimer.cleared, true);
    }

    // Deferred file-transfer retries are tracked, cleared, and cannot re-run after session shutdown.
    {
        let initCalls = 0;
        const manager = {
            _sessionAlive: true,
            _activeTimers: new Set(),
            _fileTransferInitRetryTimers: new Set(),
            fileTransferSystem: null,
            dataChannel: { readyState: 'open' },
            isVerified: false,
            _secureLog() {},
            _trackActiveTimer: EnhancedSecureWebRTCManager.prototype._trackActiveTimer,
            _untrackActiveTimer: EnhancedSecureWebRTCManager.prototype._untrackActiveTimer,
            _scheduleFileTransferInitRetry: EnhancedSecureWebRTCManager.prototype._scheduleFileTransferInitRetry,
            initializeFileTransfer() {
                initCalls += 1;
            }
        };
        EnhancedSecureWebRTCManager.prototype.initializeFileTransfer.call(manager);
        const retryTimer = [...manager._fileTransferInitRetryTimers][0];
        manager._sessionAlive = false;
        EnhancedSecureWebRTCManager.prototype._stopAllTimers.call(manager);
        if (!retryTimer.cleared) retryTimer.callback();
        assert.equal(retryTimer.cleared, true);
        assert.equal(manager._fileTransferInitRetryTimers.size, 0);
        assert.equal(initCalls, 0);
    }

    // Repeated peer-disconnect notifications schedule only one delayed cleanup, and cleanup is cancelled on disconnect.
    {
        let disconnectCalls = 0;
        const manager = {
            _sessionAlive: true,
            _activeTimers: new Set(),
            peerDisconnectNotificationSent: false,
            _peerDisconnectCleanupTimer: null,
            deliverMessageToUI() {},
            onStatusChange() {},
            stopHeartbeat() {},
            onKeyExchange() {},
            onVerificationRequired() {},
            disconnect() { disconnectCalls += 1; },
            _secureLog() {},
            _trackActiveTimer: EnhancedSecureWebRTCManager.prototype._trackActiveTimer,
            _untrackActiveTimer: EnhancedSecureWebRTCManager.prototype._untrackActiveTimer
        };
        EnhancedSecureWebRTCManager.prototype.handlePeerDisconnectNotification.call(manager, { reason: 'connection_lost' });
        EnhancedSecureWebRTCManager.prototype.handlePeerDisconnectNotification.call(manager, { reason: 'connection_lost' });
        const scheduled = timers.filter(timer => timer.kind === 'timeout' && timer.delay === 2000);
        assert.equal(scheduled.length, 1);

        manager._sessionAlive = false;
        EnhancedSecureWebRTCManager.prototype._stopAllTimers.call(manager);
        if (!scheduled[0].cleared) scheduled[0].callback();
        assert.equal(scheduled[0].cleared, true);
        assert.equal(disconnectCalls, 0);
    }
} finally {
    globalThis.setTimeout = realSetTimeout;
    globalThis.clearTimeout = realClearTimeout;
    globalThis.setInterval = realSetInterval;
    globalThis.clearInterval = realClearInterval;
}

console.log('Timer lifecycle tests passed');
