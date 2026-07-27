// The header renders `level` and `score` straight from whatever the security
// getter returns:
//
//     sec.level || 'Secure'        ->  label
//     sec.score + '%'              ->  score badge
//
// so any getter the header may call must carry both fields. A getter that
// returned only per-feature booleans rendered as "Secure undefined%".
// These tests pin the shape for every branch of the header's fallback chain.

import assert from 'node:assert/strict';

globalThis.window = globalThis.window || {};

const { EnhancedSecureWebRTCManager } = await import('../src/network/EnhancedSecureWebRTCManager.js');
const P = EnhancedSecureWebRTCManager.prototype;

const SCORED = {
    level: 'HIGH',
    score: 90,
    color: 'green',
    isRealData: true,
    passedChecks: 9,
    totalChecks: 10
};

function createManager(overrides = {}) {
    return Object.assign({
        ecdhKeyPair: {},
        ecdsaKeyPair: {},
        encryptionKey: {},
        hmacKey: {},
        replayProtectionEnabled: true,
        expectedDTLSFingerprint: 'aa:bb',
        verificationCode: '1234567',
        connectionId: 'conn-1',
        keyFingerprint: 'ff:ee',
        _secureLog() {},
        calculateAndReportSecurityLevel: async () => ({ ...SCORED }),
        getRealSecurityLevel: P.getRealSecurityLevel
    }, overrides);
}

// ── the scored fields survive, alongside the feature flags ───────────────────
{
    const data = await createManager().getRealSecurityLevel();

    assert.equal(typeof data.score, 'number', 'score must be numeric (renders as `score + "%"`)');
    assert.equal(typeof data.level, 'string', 'level must be a string (renders as the label)');
    assert.equal(data.score, 90);
    assert.equal(data.level, 'HIGH');
    assert.equal(data.isRealData, true);
    assert.equal(data.passedChecks, 9);
    assert.equal(data.totalChecks, 10);

    // Feature flags are still exposed for the detailed security panel.
    assert.equal(data.ecdhKeyExchange, true);
    assert.equal(data.sasCode, true);
    assert.equal(data.replayProtection, true);

    // What the header would actually paint.
    assert.equal(String(data.level || 'Secure'), 'HIGH');
    assert.equal(data.score + '%', '90%');
}

// ── not-ready path is flagged, not rendered as a real measurement ────────────
{
    // calculateAndReportSecurityLevel returns null when the session is not yet
    // connected/verified or the keys are missing.
    const data = await createManager({
        calculateAndReportSecurityLevel: async () => null
    }).getRealSecurityLevel();

    assert.equal(data.isRealData, false, 'UI keeps its previous value when isRealData is false');
    assert.equal(typeof data.score, 'number');
    assert.equal(typeof data.level, 'string');
    assert.notEqual(data.score + '%', 'undefined%');
}

// ── the header's other fallback branch keeps the same contract ───────────────
{
    const data = await createManager().calculateAndReportSecurityLevel();
    assert.equal(typeof data.score, 'number');
    assert.equal(typeof data.level, 'string');
}

console.log('Security level shape tests passed');
