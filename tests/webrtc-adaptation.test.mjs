// Unit tests for the adaptive-bitrate metrics + decision logic.
// Run: node tests/webrtc-adaptation.test.mjs
import assert from 'node:assert';
import { summarizeStats, qualityFromMetrics } from '../src/network/webrtc/adaptation/metrics.js';
import { decideAdaptation } from '../src/network/webrtc/adaptation/controller.js';
import { ADAPTATION_CONFIG as CFG } from '../src/network/webrtc/config.js';

const stats = (packetsSent, packetsLost, rttSec, extra = {}) => ([
    { type: 'outbound-rtp', kind: 'video', packetsSent, qualityLimitationReason: extra.qlr || 'none' },
    { type: 'remote-inbound-rtp', kind: 'video', packetsLost, roundTripTime: rttSec, jitter: 0.01 },
    { type: 'candidate-pair', nominated: true, currentRoundTripTime: rttSec, availableOutgoingBitrate: 1000000 },
]);

function testMetrics() {
    // First sample: no deltas → 0% loss.
    const m1 = summarizeStats(stats(100, 0, 0.05));
    assert.strictEqual(m1.counters.packetsSent, 100);
    assert.strictEqual(m1.lossPct, 0, 'first sample has no loss');
    assert.strictEqual(m1.rttMs, 50, 'rtt in ms');
    assert.ok(m1.hasData);

    // Second sample: 100 sent, 20 lost → 20/120 ≈ 16.7%.
    const m2 = summarizeStats(stats(200, 20, 0.05), m1.counters);
    assert.ok(Math.abs(m2.lossPct - 20 / 120) < 1e-9, `loss ~16.7% (got ${m2.lossPct})`);

    // Quality thresholds.
    assert.strictEqual(qualityFromMetrics({ hasData: true, lossPct: 0.01, rttMs: 100 }), 'excellent');
    assert.strictEqual(qualityFromMetrics({ hasData: true, lossPct: 0.05, rttMs: 200 }), 'good');
    assert.strictEqual(qualityFromMetrics({ hasData: true, lossPct: 0.12, rttMs: 350 }), 'fair');
    assert.strictEqual(qualityFromMetrics({ hasData: true, lossPct: 0.30, rttMs: 500 }), 'poor');
    assert.strictEqual(qualityFromMetrics({ hasData: false }), null, 'no data → null');
}

function testDecide() {
    const base = { targetBitrate: 1500000, ceilingBitrate: 1500000, scaleResolutionDownBy: 1, goodTicks: 0 };

    // High loss → step down 20%.
    const d1 = decideAdaptation({ lossPct: 0.15, rttMs: 100, qualityLimitationReason: 'none' }, base, CFG);
    assert.strictEqual(d1.targetBitrate, 1200000, 'loss backoff -20%');
    assert.ok(d1.changed && d1.reason === 'backoff');

    // High RTT → step down.
    const d2 = decideAdaptation({ lossPct: 0, rttMs: 350, qualityLimitationReason: 'none' }, base, CFG);
    assert.strictEqual(d2.targetBitrate, 1200000, 'rtt backoff -20%');

    // Floor respected.
    const low = { ...base, targetBitrate: CFG.minVideoBitrate };
    const d3 = decideAdaptation({ lossPct: 0.5, rttMs: 500, qualityLimitationReason: 'none' }, low, CFG);
    assert.strictEqual(d3.targetBitrate, CFG.minVideoBitrate, 'never below floor');
    assert.strictEqual(d3.changed, false, 'no change at floor');

    // CPU limitation → scale down resolution, bitrate untouched.
    const d4 = decideAdaptation({ lossPct: 0, rttMs: 50, qualityLimitationReason: 'cpu' }, base, CFG);
    assert.strictEqual(d4.targetBitrate, 1500000, 'cpu keeps bitrate');
    assert.ok(d4.scaleResolutionDownBy > 1, 'cpu scales resolution down');

    // Recovery: needs recoverStableTicks good ticks, then ramps +10%.
    let st = { ...base, targetBitrate: 1000000 };
    const good = { lossPct: 0.01, rttMs: 100, qualityLimitationReason: 'none' };
    for (let i = 1; i < CFG.recoverStableTicks; i++) {
        st = { ...st, ...decideAdaptation(good, st, CFG) };
        assert.strictEqual(st.targetBitrate, 1000000, `no ramp before ${CFG.recoverStableTicks} ticks (tick ${i})`);
    }
    const dR = decideAdaptation(good, st, CFG);
    assert.strictEqual(dR.targetBitrate, 1100000, 'ramp +10% after stable ticks');
    assert.ok(dR.changed && dR.reason === 'rampup');

    // Ceiling respected.
    const atCeil = { ...base, targetBitrate: 1500000, goodTicks: CFG.recoverStableTicks - 1 };
    const dC = decideAdaptation(good, atCeil, CFG);
    assert.strictEqual(dC.targetBitrate, 1500000, 'never above ceiling');

    // Neutral zone → hold, reset goodTicks.
    const dN = decideAdaptation({ lossPct: 0.05, rttMs: 200, qualityLimitationReason: 'none' }, { ...base, goodTicks: 3 }, CFG);
    assert.strictEqual(dN.changed, false);
    assert.strictEqual(dN.goodTicks, 0, 'neutral resets goodTicks');
}

testMetrics();
testDecide();
console.log('webrtc-adaptation.test.mjs: all assertions passed');
