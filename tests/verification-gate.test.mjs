// Regression tests for the MITM-protection gate.
//
// The whole security model rests on one step: the two users compare a Short
// Authentication String out-of-band. Everything below asserts that this step
// cannot be skipped, faked or supplied by the peer — an attacker who completes
// the signalling exchange (and therefore holds valid ECDH-derived keys) must
// still be unable to reach a verified session.

import assert from 'node:assert/strict';

globalThis.window = globalThis.window || {};
globalThis.window.EnhancedSecureCryptoUtils = {
    constantTimeCompare: (a, b) => a === b
};

const { EnhancedSecureWebRTCManager } = await import('../src/network/EnhancedSecureWebRTCManager.js');
const P = EnhancedSecureWebRTCManager.prototype;

const settle = (ms = 2300) => new Promise((r) => setTimeout(r, ms));

function createPeerStub(overrides = {}) {
    const stub = {
        isVerified: false,
        localVerificationConfirmed: false,
        remoteVerificationConfirmed: false,
        bothVerificationsConfirmed: false,
        verificationCode: '1234567',
        // Present right after ECDH — a MITM has these too, which is exactly why
        // they must not be sufficient to become "verified".
        encryptionKey: {},
        macKey: {},
        keyFingerprint: 'aa:bb:cc',
        disconnected: false,
        statusChanges: [],
        uiMessages: [],

        onStatusChange(s) { this.statusChanges.push(s); },
        onVerificationStateChange() {},
        _secureLog() {},
        deliverMessageToUI(msg) { this.uiMessages.push(String(msg)); },
        disconnect() { this.disconnected = true; },
        dataChannel: { readyState: 'open', send() {} },

        handleSystemMessage: P.handleSystemMessage,
        handleVerificationBothConfirmed: P.handleVerificationBothConfirmed,
        handleVerificationConfirmed: P.handleVerificationConfirmed,
        handleSASCode: P.handleSASCode,
        _validateSASCode: P._validateSASCode,
        _checkBothVerificationsConfirmed: P._checkBothVerificationsConfirmed,
        _setVerifiedStatus: P._setVerifiedStatus,
        _enforceVerificationGate: P._enforceVerificationGate,
        _notifyVerificationReadyIfPossible() {},
        handleHeartbeat() {},
        handlePeerDisconnectNotification() {},
        handleVerificationRequest() {},
        handleVerificationResponse() {},
        processMessageQueue() {}
    };
    return Object.assign(stub, overrides);
}

// ── a peer cannot manufacture mutual confirmation ────────────────────────────
{
    const victim = createPeerStub();

    victim.handleSystemMessage({
        type: 'verification_both_confirmed',
        data: { timestamp: Date.now(), verificationMethod: 'SAS' }
    });
    await settle();

    assert.equal(victim.isVerified, false, 'peer must not be able to force verified state');
    assert.equal(victim.bothVerificationsConfirmed, false);
    assert.equal(victim.disconnected, true, 'protocol violation must tear down the session');
    assert.ok(
        !victim.statusChanges.includes('verified'),
        'no verified status may be emitted to the UI'
    );
}

// ── the same frame IS honoured once the user has confirmed locally ───────────
{
    const victim = createPeerStub({ localVerificationConfirmed: true });

    victim.handleSystemMessage({
        type: 'verification_both_confirmed',
        data: { timestamp: Date.now(), verificationMethod: 'SAS' }
    });
    await settle();

    assert.equal(victim.isVerified, true, 'legitimate mutual confirmation must still work');
    assert.equal(victim.remoteVerificationConfirmed, true);
    assert.equal(victim.disconnected, false);
    assert.ok(victim.statusChanges.includes('verified'));
}

// ── _setVerifiedStatus refuses SAS transitions without local confirmation ────
{
    const victim = createPeerStub();
    assert.throws(
        () => victim._setVerifiedStatus(true, 'MUTUAL_SAS_CONFIRMED', {}),
        /without local SAS confirmation/,
        'the low-level setter must fail closed too'
    );
    assert.equal(victim.isVerified, false);
}

// ── holding keys alone is never enough ───────────────────────────────────────
{
    const victim = createPeerStub({ encryptionKey: null, macKey: null });
    assert.throws(
        () => victim._setVerifiedStatus(true, 'MUTUAL_SAS_CONFIRMED', {}),
        /without encryption keys/
    );
}

// ── a peer-announced SAS may corroborate, never supply ───────────────────────
{
    // No locally derived code yet -> the announcement must be refused outright.
    const victim = createPeerStub({ verificationCode: null });
    victim.handleSystemMessage({ type: 'sas_code', data: { code: '7654321' } });

    assert.equal(victim.verificationCode, null, 'peer-supplied SAS must not be adopted');
    assert.equal(victim.disconnected, true);
}
{
    // Locally derived code present and matching -> accepted, ours retained.
    const victim = createPeerStub({ verificationCode: '1234567' });
    victim.handleSystemMessage({ type: 'sas_code', data: { code: '1234567' } });

    assert.equal(victim.verificationCode, '1234567');
    assert.equal(victim.disconnected, false);
}
{
    // Mismatch -> abort.
    const victim = createPeerStub({ verificationCode: '1234567' });
    victim.handleSystemMessage({ type: 'sas_code', data: { code: '7654321' } });

    assert.equal(victim.disconnected, true, 'SAS mismatch must abort the session');
}

console.log('Verification gate tests passed');
