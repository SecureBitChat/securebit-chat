// Unit tests for the pure SDP munging utilities (src/network/webrtc/sdp.js).
// Run: node tests/webrtc-sdp.test.mjs
import assert from 'node:assert';
import {
    splitSdp, joinSdp, sectionKind, findPayloadTypes, upsertFmtp, applyOpusSettings,
    getCodecPayloadTypes, ensureRtcpFb, ensureExtmap, applyTransport,
} from '../src/network/webrtc/sdp.js';
import { AUDIO_CONFIG, TRANSPORT_CONFIG } from '../src/network/webrtc/config.js';

const CRLF = '\r\n';
// Synthetic SDP: one audio m-line (opus 111 + telephone-event 126, opus already
// has a partial fmtp) and one video m-line (VP9).
const SDP = [
    'v=0',
    'o=- 1 2 IN IP4 127.0.0.1',
    's=-',
    't=0 0',
    'a=group:BUNDLE 0 1',
    'm=audio 9 UDP/TLS/RTP/SAVPF 111 126',
    'c=IN IP4 0.0.0.0',
    'a=rtpmap:111 opus/48000/2',
    'a=fmtp:111 minptime=10;useinbandfec=1',
    'a=rtpmap:126 telephone-event/8000',
    'a=mid:0',
    'm=video 9 UDP/TLS/RTP/SAVPF 96',
    'c=IN IP4 0.0.0.0',
    'a=rtpmap:96 VP9/90000',
    'a=mid:1',
].join(CRLF) + CRLF;

function run() {
    // splitSdp / kinds
    const parsed = splitSdp(SDP);
    assert.strictEqual(parsed.eol, CRLF, 'detects CRLF');
    assert.strictEqual(parsed.media.length, 2, 'two m-sections');
    assert.strictEqual(sectionKind(parsed.media[0]), 'audio');
    assert.strictEqual(sectionKind(parsed.media[1]), 'video');

    // findPayloadTypes
    assert.deepStrictEqual(findPayloadTypes(parsed.media[0], 'opus'), ['111']);
    assert.deepStrictEqual(findPayloadTypes(parsed.media[1], 'VP9'), ['96']);

    // applyOpusSettings: all requested params present, existing ones merged (not dropped).
    const munged = applyOpusSettings(SDP, AUDIO_CONFIG.opusFmtp);
    const fmtp = munged.split(/\r\n/).find(l => l.startsWith('a=fmtp:111 '));
    assert.ok(fmtp, 'opus fmtp line exists');
    for (const [k, v] of Object.entries(AUDIO_CONFIG.opusFmtp)) {
        assert.ok(fmtp.includes(`${k}=${v}`), `fmtp has ${k}=${v} (got: ${fmtp})`);
    }
    assert.ok(fmtp.includes('minptime=10'), 'pre-existing param retained');

    // No duplicate fmtp keys.
    const params = fmtp.slice('a=fmtp:111 '.length).split(';').map(s => s.split('=')[0]);
    assert.strictEqual(new Set(params).size, params.length, 'no duplicate fmtp keys');

    // Idempotent: munging twice equals munging once.
    assert.strictEqual(applyOpusSettings(munged, AUDIO_CONFIG.opusFmtp), munged, 'idempotent');

    // Line endings preserved.
    assert.ok(munged.includes(CRLF), 'CRLF preserved');

    // Video section untouched (still exactly one line for VP9, no fmtp injected).
    assert.ok(!munged.includes('a=fmtp:96'), 'video section not modified');

    // No-Opus SDP returned unchanged (identity).
    const noOpus = 'v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=mid:0\r\n';
    assert.strictEqual(applyOpusSettings(noOpus, AUDIO_CONFIG.opusFmtp), noOpus, 'no-opus unchanged');

    // upsertFmtp creates a line when none exists.
    const p2 = splitSdp('m=audio 9 x 111\r\na=rtpmap:111 opus/48000/2\r\n');
    upsertFmtp(p2.media[0], '111', { usedtx: 1 });
    assert.ok(joinSdp(p2).includes('a=fmtp:111 usedtx=1'), 'fmtp created when missing');

    // joinSdp round-trips an unmodified SDP exactly (trailing CRLF preserved).
    assert.strictEqual(joinSdp(splitSdp(SDP)), SDP, 'round-trip preserves SDP exactly');

    // ── Transport feedback (Step 4) ──────────────────────────────────────────
    // Video section with a real codec (96) + rtx (97). Only 96 is a primary codec.
    const vsdp = [
        'v=0', 't=0 0',
        'm=video 9 UDP/TLS/RTP/SAVPF 96 97',
        'a=rtpmap:96 VP9/90000',
        'a=rtpmap:97 rtx/90000',
        'a=fmtp:97 apt=96',
        'a=mid:0',
        '',
    ].join(CRLF);
    const vparsed = splitSdp(vsdp);
    assert.deepStrictEqual(getCodecPayloadTypes(vparsed.media[0]), ['96'], 'rtx excluded from codec PTs');

    const t = applyTransport(vsdp, TRANSPORT_CONFIG);
    for (const fb of TRANSPORT_CONFIG.video.rtcpFb) {
        assert.ok(t.includes(`a=rtcp-fb:96 ${fb}`), `video has rtcp-fb 96 ${fb}`);
    }
    assert.ok(!t.includes('a=rtcp-fb:97'), 'no rtcp-fb on rtx');
    assert.ok(t.includes(`a=extmap:1 ${TRANSPORT_CONFIG.twccUri}`), 'TWCC extension added (id 1)');

    // Idempotent: applying twice adds nothing new.
    assert.strictEqual(applyTransport(t, TRANSPORT_CONFIG), t, 'applyTransport idempotent');
    const fbCount = (t.match(/a=rtcp-fb:96 transport-cc/g) || []).length;
    assert.strictEqual(fbCount, 1, 'no duplicate rtcp-fb line');

    // ensureExtmap allocates the next free id, not a colliding one.
    const ep = splitSdp('m=video 9 x 96\r\na=rtpmap:96 VP9/90000\r\na=extmap:3 urn:foo\r\na=mid:0\r\n');
    ensureExtmap(ep.media[0], 'urn:bar');
    assert.ok(joinSdp(ep).includes('a=extmap:4 urn:bar'), 'next free extmap id used');

    // Audio gets the subset (transport-cc + nack), no pli/fir/remb.
    const at = applyTransport(SDP, TRANSPORT_CONFIG);
    assert.ok(at.includes('a=rtcp-fb:111 transport-cc'), 'audio transport-cc');
    assert.ok(at.includes('a=rtcp-fb:111 nack'), 'audio nack');
    assert.ok(!at.includes('a=rtcp-fb:111 nack pli'), 'audio has no pli');

    console.log('webrtc-sdp.test.mjs: all assertions passed');
}

run();
