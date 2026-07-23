// Unit tests for the pure video codec helpers (src/network/webrtc/video.js).
// Run: node tests/webrtc-video.test.mjs
import assert from 'node:assert';
import {
    codecShortName, sortVideoCodecs, pickPreferredVideoCodec, encodingPlanFor,
    codecSupportsSvc, buildVideoSendEncodings,
} from '../src/network/webrtc/video.js';
import { VIDEO_CONFIG } from '../src/network/webrtc/config.js';

// names: array of codec short names, or {name, modes} objects for scalabilityModes.
function caps(names) {
    return { codecs: names.map(n => (typeof n === 'string'
        ? { mimeType: 'video/' + n }
        : { mimeType: 'video/' + n.name, scalabilityModes: n.modes })) };
}

function run() {
    // codecShortName
    assert.strictEqual(codecShortName('video/VP9'), 'VP9');
    assert.strictEqual(codecShortName('video/H264'), 'H264');
    assert.strictEqual(codecShortName('video/rtx'), 'RTX');

    // pickPreferredVideoCodec honours the VP9 > AV1 > H264 > VP8 order.
    assert.strictEqual(pickPreferredVideoCodec(caps(['VP8', 'H264', 'VP9', 'AV1'])), 'VP9');
    assert.strictEqual(pickPreferredVideoCodec(caps(['VP8', 'H264', 'AV1'])), 'AV1');
    assert.strictEqual(pickPreferredVideoCodec(caps(['VP8', 'H264'])), 'H264');
    assert.strictEqual(pickPreferredVideoCodec(caps(['VP8'])), 'VP8');
    assert.strictEqual(pickPreferredVideoCodec(caps(['red', 'rtx'])), null);
    assert.strictEqual(pickPreferredVideoCodec(null), null);

    // sortVideoCodecs: preferred codecs first (in our order), rtx/red/fec kept
    // afterwards in original relative order; no codec dropped.
    const input = caps(['rtx', 'VP8', 'red', 'H264', 'VP9', 'AV1', 'ulpfec']);
    const sorted = sortVideoCodecs(input.codecs).map(c => codecShortName(c.mimeType));
    assert.deepStrictEqual(sorted, ['VP9', 'AV1', 'H264', 'VP8', 'RTX', 'RED', 'ULPFEC']);
    assert.strictEqual(sorted.length, input.codecs.length, 'no codec dropped');

    // Stability: non-preferred codecs keep their input order.
    const s2 = sortVideoCodecs(caps(['red', 'rtx', 'VP9']).codecs).map(c => codecShortName(c.mimeType));
    assert.deepStrictEqual(s2, ['VP9', 'RED', 'RTX']);

    // encodingPlanFor: VP9 → L3T3_KEY balanced; AV1 → L1T3 maintain-framerate; else plain.
    const vp9 = encodingPlanFor('VP9');
    assert.strictEqual(vp9.scalabilityMode, VIDEO_CONFIG.vp9.preferredScalabilityMode);
    assert.strictEqual(vp9.degradationPreference, 'balanced');
    const av1 = encodingPlanFor('AV1');
    assert.strictEqual(av1.scalabilityMode, 'L1T3');
    assert.strictEqual(av1.maxBitrate, VIDEO_CONFIG.av1.maxBitrate);
    assert.strictEqual(av1.degradationPreference, 'maintain-framerate');
    const h264 = encodingPlanFor('H264');
    assert.strictEqual(h264.scalabilityMode, undefined, 'H264 no SVC');
    const vp8 = encodingPlanFor('VP8');
    assert.strictEqual(vp8.scalabilityMode, undefined, 'VP8 no SVC');

    // codecSupportsSvc: only true when scalabilityModes confirms our mode.
    assert.strictEqual(codecSupportsSvc(caps([{ name: 'VP9', modes: ['L1T3', 'L3T3_KEY'] }]), 'VP9'), true);
    assert.strictEqual(codecSupportsSvc(caps([{ name: 'VP9', modes: ['L1T3'] }]), 'VP9'), false, 'mode not present');
    assert.strictEqual(codecSupportsSvc(caps(['VP9']), 'VP9'), false, 'no scalabilityModes field → false');
    assert.strictEqual(codecSupportsSvc(caps([{ name: 'AV1', modes: ['L1T3'] }]), 'AV1'), true);

    // buildVideoSendEncodings:
    //  VP9 + confirmed SVC → single encoding with L3T3_KEY.
    const e1 = buildVideoSendEncodings(caps([{ name: 'VP9', modes: ['L3T3_KEY'] }, 'H264']));
    assert.strictEqual(e1.length, 1, 'VP9 SVC → single encoding');
    assert.strictEqual(e1[0].scalabilityMode, 'L3T3_KEY');
    //  VP9 without confirmed SVC → 3-rid L1T3 simulcast.
    const e2 = buildVideoSendEncodings(caps(['VP9', 'H264']));
    assert.strictEqual(e2.length, 3, 'VP9 no-SVC → simulcast ×3');
    assert.strictEqual(e2[0].scalabilityMode, 'L1T3', 'VP9 fallback uses L1T3 rids');
    assert.deepStrictEqual(e2.map(e => e.rid), ['low', 'mid', 'high']);
    //  H.264 only → plain 3-rid simulcast (no scalabilityMode).
    const e3 = buildVideoSendEncodings(caps(['H264']));
    assert.strictEqual(e3.length, 3, 'H264 → simulcast ×3');
    assert.strictEqual(e3[0].scalabilityMode, undefined, 'plain simulcast has no SVC mode');
    //  AV1 + confirmed SVC → single L1T3.
    const e4 = buildVideoSendEncodings(caps([{ name: 'AV1', modes: ['L1T3'] }]));
    assert.strictEqual(e4.length, 1);
    assert.strictEqual(e4[0].scalabilityMode, 'L1T3');

    console.log('webrtc-video.test.mjs: all assertions passed');
}

run();
