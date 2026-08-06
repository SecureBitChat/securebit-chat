// SBQ2 connection descriptor: round-trip on real browser SDP, and rejection of
// the whole class of malformed input a scanner can be handed.
//
// The Chrome fixtures in tests/fixtures/sdp-chrome.json were captured from a
// real Chrome over four network profiles (host-only, STUN, STUN+TURN, and
// relay-only) with an identical ICE configuration on both peers, each in its own
// renderer so neither side's gathering could truncate the other's. The Firefox
// fixtures in sdp-firefox.json came from a real Firefox 153 the same way.

import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const {
    parseSdp, pruneCandidates, candidateSize, encodeDescriptor, decodeDescriptor, serializeSdp,
    bindingTag, commitBlob, sasTranscript,
    toBase64Url, fromBase64Url, encodeText, decodeText,
    TYPE, LIMITS, EXT, SBQ2_VERSION, DescriptorError, KIND, KIND_FAMILY, KIND_TYPE,
} = await import('../src/network/descriptor/sbq2.js');

const load = (name) => {
    const url = new URL(`./fixtures/${name}`, import.meta.url);
    return existsSync(url) ? JSON.parse(readFileSync(url)) : null;
};
const chrome = load('sdp-chrome.json');
const firefox = load('sdp-firefox.json');

const digest = async (b) => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
const EXPIRY = () => Date.now() + 10 * 60 * 1000;

async function build(sdp, type, over = {}) {
    const raw = parseSdp(sdp);
    const isAnswer = type === TYPE.ANSWER;
    return encodeDescriptor({
        type,
        expiresAtMs: EXPIRY(),
        sdpFields: { ...raw, candidates: pruneCandidates(raw.candidates) },
        commitment: rnd(LIMITS.COMMITMENT_BYTES),
        ...(isAnswer ? { bindingTag: rnd(LIMITS.BINDING_BYTES) } : {}),
        ...over,
    });
}

const rejects = (fn, match, label) => {
    assert.throws(fn, (e) => {
        assert.ok(e instanceof DescriptorError, `${label}: wrong error type ${e.name}: ${e.message}`);
        assert.match(e.message, match, `${label}: unexpected message "${e.message}"`);
        return true;
    }, label);
};

// Offset of ufrag_len, which differs by type because only answers carry the tag.
const ufragLenOffset = (type) => 1 + 1 + 3 + (type === TYPE.ANSWER ? LIMITS.BINDING_BYTES : 0) + LIMITS.FINGERPRINT_BYTES;

// ---------------------------------------------------------------------------
// round-trip against real browser SDP
// ---------------------------------------------------------------------------
for (const [browser, fixtures] of [['chrome', chrome], ['firefox', firefox]]) {
    if (!fixtures) continue;
    for (const [profile, pair] of Object.entries(fixtures)) {
        for (const kind of ['offer', 'answer']) {
            if (!pair[kind]) continue;
            const tag = `${browser}/${profile}/${kind}`;
            const type = kind === 'offer' ? TYPE.OFFER : TYPE.ANSWER;
            const original = parseSdp(pair[kind]);
            const bytes = await build(pair[kind], type);
            const desc = decodeDescriptor(bytes);

            assert.equal(desc.version, SBQ2_VERSION, `${tag} version`);
            assert.equal(desc.type, type, `${tag} type`);
            assert.equal(desc.ufrag, original.ufrag, `${tag} ufrag`);
            assert.equal(desc.pwd, original.pwd, `${tag} pwd`);
            assert.deepEqual(desc.fingerprint, original.fingerprint, `${tag} fingerprint`);
            assert.equal(desc.setup, original.setup, `${tag} setup`);
            assert.equal(desc.maxMessageSize, original.maxMessageSize, `${tag} max-message-size`);
            assert.equal(desc.bindingTag === null, type === TYPE.OFFER, `${tag} binding tag presence`);

            // The rebuilt SDP must re-parse to exactly the fields we encoded —
            // this is what guarantees the template is lossless for everything
            // the descriptor claims to carry.
            const rebuilt = serializeSdp(desc);
            assert.ok(rebuilt.sdp.endsWith('\r\n'), `${tag} CRLF terminated`);
            const reparsed = parseSdp(rebuilt.sdp);
            assert.equal(reparsed.ufrag, original.ufrag);
            assert.equal(reparsed.pwd, original.pwd);
            assert.deepEqual(reparsed.fingerprint, original.fingerprint);
            assert.equal(reparsed.setup, original.setup);
            assert.equal(reparsed.maxMessageSize, original.maxMessageSize);
            assert.deepEqual(
                reparsed.candidates.map((c) => [c.kind, c.tcptype, [...c.addr], c.port]),
                desc.candidates.map((c) => [c.kind, c.tcptype, [...c.addr], c.port]),
                `${tag} candidates survive the template`,
            );

            // Acceptance criteria: offer <= QR v10, answer <= QR v8 at level M.
            const cap = kind === 'offer' ? 213 : 152;
            assert.ok(bytes.length <= cap, `${tag} is ${bytes.length} B, over the ${cap} B budget`);
        }
    }
}

// ---------------------------------------------------------------------------
// candidate pruning: coverage before count
// ---------------------------------------------------------------------------
{
    const cand = (kind, addr, port, priority, tcptype = 0) => ({ kind, tcptype, addr: Uint8Array.from(addr), port, priority });
    const v4 = (a, b, c, d) => [a, b, c, d];
    const v6 = (last) => [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last];

    // A pure count limit sorted v4-first would evict every v6 candidate here.
    const dual = [
        cand(KIND.HOST_V4, v4(192, 168, 1, 5), 1001, 2113937151),
        cand(KIND.SRFLX_V4, v4(203, 0, 113, 1), 1002, 1677729535),
        cand(KIND.RELAY_V4, v4(144, 172, 96, 126), 1003, 50340351),
        cand(KIND.RELAY_V4, v4(144, 172, 96, 126), 1004, 16785663),
        cand(KIND.RELAY_V4, v4(144, 172, 96, 126), 1005, 8191),
        cand(KIND.HOST_MDNS, new Array(16).fill(7), 1006, 2113937150),
        cand(KIND.HOST_V6, v6(1), 1007, 2113939199),
        cand(KIND.SRFLX_V6, v6(2), 1008, 1677731583),
        cand(KIND.RELAY_V6, v6(3), 1009, 50341375),
    ];
    const kept = pruneCandidates(dual);
    const groups = new Set(kept.map((c) => `${KIND_FAMILY[c.kind]}/${KIND_TYPE[c.kind]}`));
    for (const g of ['v4/host', 'v4/srflx', 'v4/relay', 'v6/host', 'v6/srflx', 'v6/relay', 'mdns/host']) {
        assert.ok(groups.has(g), `dual-stack pruning must keep a ${g} candidate`);
    }
    assert.ok(kept.length <= LIMITS.MAX_CANDIDATES, 'count limit still respected');

    // IPv6-only: nothing may be dropped for being v6.
    const v6only = [
        cand(KIND.HOST_V6, v6(1), 2001, 2113939199),
        cand(KIND.SRFLX_V6, v6(2), 2002, 1677731583),
        cand(KIND.RELAY_V6, v6(3), 2003, 50341375),
        cand(KIND.RELAY_V6, v6(4), 2004, 16786687),
    ];
    const keptV6 = pruneCandidates(v6only);
    assert.equal(new Set(keptV6.map((c) => KIND_TYPE[c.kind])).size, 3, 'host/srflx/relay all survive on v6-only');
    assert.ok(keptV6.every((c) => KIND_FAMILY[c.kind] === 'v6'));

    // NAT64: the synthesised v6 prefix carries a dotted-quad tail.
    const nat64 = parseSdp([
        'v=0', 'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
        'a=candidate:1 1 udp 1677729535 64:ff9b::203.0.113.7 40000 typ srflx',
        'a=ice-ufrag:abcd', 'a=ice-pwd:0123456789abcdef01234567',
        'a=fingerprint:sha-256 ' + new Array(32).fill('AA').join(':'), 'a=setup:actpass',
    ].join('\r\n'));
    assert.equal(nat64.candidates.length, 1, 'NAT64 address parses');
    assert.deepEqual([...nat64.candidates[0].addr].slice(12), [203, 0, 113, 7], 'dotted-quad tail preserved');
    assert.equal(KIND_FAMILY[nat64.candidates[0].kind], 'v6');

    // Coverage wins over the byte budget: a connection that can be made is
    // worth more than a smaller QR.
    const tight = pruneCandidates(dual, { maxBytes: 10 });
    assert.ok(new Set(tight.map((c) => `${KIND_FAMILY[c.kind]}/${KIND_TYPE[c.kind]}`)).size === 7,
        'coverage is not sacrificed to the byte budget');
    assert.equal(tight.length, 7, 'but nothing beyond coverage is admitted under a tight budget');

    // Relay cap applies only to the surplus, never to coverage.
    const manyRelays = pruneCandidates(dual, { maxRelays: 1 });
    assert.equal(manyRelays.filter((c) => KIND_TYPE[c.kind] === 'relay').length, 2,
        'one v4 relay + one v6 relay: both are coverage, so the cap does not evict either');

    // Exact duplicates collapse.
    const dupes = [cand(KIND.SRFLX_V4, v4(1, 2, 3, 4), 5, 100), cand(KIND.SRFLX_V4, v4(1, 2, 3, 4), 5, 100)];
    assert.equal(pruneCandidates(dupes).length, 1);

    assert.equal(candidateSize({ kind: KIND.SRFLX_V4 }), 7);
    assert.equal(candidateSize({ kind: KIND.HOST_MDNS }), 19);
    assert.equal(candidateSize({ kind: KIND.RELAY_V6 }), 19);
}

// ---------------------------------------------------------------------------
// IPv6 round-trip through the wire format
// ---------------------------------------------------------------------------
{
    const sdp = [
        'v=0', 'o=- 1 2 IN IP4 127.0.0.1', 's=-', 't=0 0',
        'm=application 9 UDP/DTLS/SCTP webrtc-datachannel', 'c=IN IP4 0.0.0.0',
        'a=candidate:1 1 udp 2113939199 2001:db8::1 40000 typ host',
        'a=candidate:2 1 udp 1677731583 2001:0db8:0000:0000:0000:ff00:0042:8329 40001 typ srflx',
        'a=candidate:3 1 udp 50341375 64:ff9b::198.51.100.9 40002 typ relay',
        'a=ice-ufrag:abcd', 'a=ice-pwd:0123456789abcdef01234567',
        'a=fingerprint:sha-256 ' + Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, '0').toUpperCase()).join(':'),
        'a=setup:active', 'a=mid:0', 'a=sctp-port:5000',
    ].join('\r\n') + '\r\n';
    const desc = decodeDescriptor(await build(sdp, TYPE.ANSWER));
    const re = parseSdp(serializeSdp(desc).sdp);
    assert.equal(re.candidates.length, 3);
    assert.deepEqual([...re.candidates[0].addr].slice(0, 4), [0x20, 0x01, 0x0d, 0xb8], 'IPv6 :: expansion round-trips');
    assert.deepEqual([...re.candidates[2].addr].slice(12), [198, 51, 100, 9], 'NAT64 tail round-trips');
}

// ---------------------------------------------------------------------------
// SDP grammar conformance of the rebuilt candidate lines
//
// Regression guard. rel-addr/rel-port are mandatory for srflx/prflx/relay
// (RFC 8839 §5.1). Leaving them out is silently fine in Chrome and fatal in
// Firefox, which drops the candidate: measured 0/8 relay-only connections to
// Firefox versus 8/8 for the browser's own SDP, and invisible in the STUN and
// TURN profiles because a host pair connected instead.
// ---------------------------------------------------------------------------
{
    const sdp = [
        'v=0', 'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
        'a=candidate:1 1 udp 2113937151 192.168.1.9 40000 typ host',
        'a=candidate:2 1 udp 1677729535 203.0.113.4 40001 typ srflx raddr 192.168.1.9 rport 40000',
        'a=candidate:3 1 udp 50340351 144.172.96.126 40002 typ relay raddr 203.0.113.4 rport 40001',
        'a=candidate:4 1 udp 50341375 2001:db8::5 40003 typ relay',
        'a=ice-ufrag:abcd', 'a=ice-pwd:0123456789abcdef01234567',
        'a=fingerprint:sha-256 ' + new Array(32).fill('EE').join(':'), 'a=setup:actpass',
    ].join('\r\n') + '\r\n';

    const out = serializeSdp(decodeDescriptor(await build(sdp, TYPE.OFFER))).sdp;
    for (const line of out.split('\r\n').filter((l) => l.startsWith('a=candidate:'))) {
        const type = line.split(' typ ')[1].split(' ')[0];
        if (type === 'host') {
            assert.ok(!line.includes('raddr'), `host candidates must not carry raddr: ${line}`);
        } else {
            assert.match(line, / raddr (0\.0\.0\.0|::) rport 0/, `${type} candidate needs rel-addr/rel-port: ${line}`);
        }
    }

    // The default candidate must be a real, routable address whenever one
    // exists — `m=... 9` with `c=IN IP4 0.0.0.0` is the trickle "none yet"
    // form, and a descriptor is never trickle.
    assert.ok(!out.includes('a=ice-options:trickle'), 'a complete candidate set must not advertise trickle');
    assert.match(out, /^a=end-of-candidates$/m, 'the candidate set is explicitly closed');

    // relay beats srflx beats host: the default candidate is the most publicly
    // reachable one, matching what Chrome emits. Asserted on a v4-only set so
    // the expected winner is unambiguous.
    const v4only = [
        'v=0', 'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
        'a=candidate:1 1 udp 2113937151 192.168.1.9 40000 typ host',
        'a=candidate:2 1 udp 1677729535 203.0.113.4 40001 typ srflx raddr 192.168.1.9 rport 40000',
        'a=candidate:3 1 udp 50340351 144.172.96.126 40002 typ relay raddr 203.0.113.4 rport 40001',
        'a=ice-ufrag:abcd', 'a=ice-pwd:0123456789abcdef01234567',
        'a=fingerprint:sha-256 ' + new Array(32).fill('EE').join(':'), 'a=setup:actpass',
    ].join('\r\n') + '\r\n';
    const vOut = serializeSdp(decodeDescriptor(await build(v4only, TYPE.OFFER))).sdp;
    assert.match(vOut, /^m=application 40002 /m, 'm-line carries the relay port as default');
    assert.match(vOut, /^c=IN IP4 144\.172\.96\.126$/m, 'c-line carries the relay address as default');

    // With only an mDNS candidate there is no literal address to advertise, so
    // the null form is correct — and it is what Chrome emits in that case too.
    const mdnsOnly = [
        'v=0', 'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
        'a=candidate:1 1 udp 2113937151 7d9c00c2-bcef-48b6-9166-428899e0582e.local 40000 typ host',
        'a=ice-ufrag:abcd', 'a=ice-pwd:0123456789abcdef01234567',
        'a=fingerprint:sha-256 ' + new Array(32).fill('EE').join(':'), 'a=setup:actpass',
    ].join('\r\n') + '\r\n';
    const mOut = serializeSdp(decodeDescriptor(await build(mdnsOnly, TYPE.OFFER))).sdp;
    assert.match(mOut, /^m=application 9 /m);
    assert.match(mOut, /^c=IN IP4 0\.0\.0\.0$/m);
}

// ---------------------------------------------------------------------------
// TCP candidates
// ---------------------------------------------------------------------------
{
    const sdp = [
        'v=0', 'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
        'a=candidate:1 1 tcp 1518280447 192.168.1.9 9 typ host tcptype active',
        'a=candidate:2 1 tcp 1518149375 192.168.1.9 50000 typ host tcptype passive',
        'a=candidate:3 1 tcp 1509957375 203.0.113.4 50001 typ srflx raddr 192.168.1.9 rport 50000',
        'a=ice-ufrag:abcd', 'a=ice-pwd:0123456789abcdef01234567',
        'a=fingerprint:sha-256 ' + new Array(32).fill('BB').join(':'), 'a=setup:actpass',
    ].join('\r\n') + '\r\n';
    const parsed = parseSdp(sdp);
    // The srflx line has no tcptype, which makes it unusable and it is dropped.
    assert.equal(parsed.candidates.length, 2, 'TCP candidates without tcptype are dropped');
    assert.deepEqual(parsed.candidates.map((c) => c.tcptype).sort(), [1, 2]);

    const desc = decodeDescriptor(await build(sdp, TYPE.OFFER));
    const out = serializeSdp(desc).sdp;
    assert.match(out, /tcptype passive/, 'passive tcptype re-emitted');
    assert.match(out, /tcptype active/, 'active tcptype re-emitted');
    const re = parseSdp(out);
    assert.deepEqual(re.candidates.map((c) => c.tcptype).sort(), [1, 2], 'tcptype survives the round trip');
}

// ---------------------------------------------------------------------------
// TLV extension area
// ---------------------------------------------------------------------------
{
    const base = [
        'v=0', 'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
        'a=candidate:1 1 udp 2113937151 192.168.1.9 40000 typ host',
        'a=ice-ufrag:abcd', 'a=ice-pwd:0123456789abcdef01234567',
        'a=fingerprint:sha-256 ' + new Array(32).fill('CC').join(':'), 'a=setup:actpass',
    ];
    const withMms = (v) => (base.concat(v === null ? [] : [`a=max-message-size:${v}`]).join('\r\n') + '\r\n');

    // The three well-known values stay in the flags: zero extension bytes.
    const flagged = await build(withMms(262144), TYPE.OFFER);
    assert.equal(decodeDescriptor(flagged).maxMessageSize, 262144);
    assert.equal(decodeDescriptor(flagged).extensions.size, 0);
    assert.equal((flagged[1] & 0x80), 0, 'no extension area when the enum suffices');
    assert.equal(decodeDescriptor(await build(withMms(1073741823), TYPE.OFFER)).maxMessageSize, 1073741823);
    assert.equal(decodeDescriptor(await build(withMms(null), TYPE.OFFER)).maxMessageSize, 65536,
        'an absent attribute means 64 KiB per RFC 8841');

    // A fifth value rides in a TLV record instead of being silently downgraded.
    const odd = await build(withMms(131072), TYPE.OFFER);
    const oddDesc = decodeDescriptor(odd);
    assert.equal(oddDesc.maxMessageSize, 131072, 'explicit max-message-size survives');
    assert.equal(oddDesc.extensions.get(EXT.MAX_MESSAGE_SIZE), 131072);
    assert.equal((odd[1] & 0x80) !== 0, true, 'extension flag set');
    assert.equal(odd.length - flagged.length, 7, 'the TLV costs exactly ext_len + type + len + 4');

    // Unknown types are refused, not skipped. This is the downgrade defence.
    const unknown = Uint8Array.from(odd);
    unknown[unknown.length - 6] = 0x7f;   // rewrite the record type
    rejects(() => decodeDescriptor(unknown), /unknown extension type 0x7f/, 'unknown extension type');

    // Length games inside the area.
    const badLen = Uint8Array.from(odd); badLen[badLen.length - 5] = 3;
    rejects(() => decodeDescriptor(badLen), /must be 4 bytes/, 'wrong TLV length');
    const overrun = Uint8Array.from(odd); overrun[overrun.length - 5] = 200;
    rejects(() => decodeDescriptor(overrun), /truncated/, 'TLV length overruns the area');
    const emptyArea = Uint8Array.from(flagged.subarray(0, flagged.length));
    const withEmpty = new Uint8Array(emptyArea.length + 1);
    withEmpty.set(emptyArea); withEmpty[1] |= 0x80; withEmpty[withEmpty.length - 1] = 0;
    rejects(() => decodeDescriptor(withEmpty), /flagged but empty/, 'empty extension area');

    // Ordering and duplicates: exactly one valid spelling per descriptor.
    const dup = new Uint8Array(odd.length + 6);
    dup.set(odd.subarray(0, odd.length - 7));
    dup[odd.length - 7] = 12;                       // ext_len = two records
    dup.set(odd.subarray(odd.length - 6), odd.length - 6);
    dup.set(odd.subarray(odd.length - 6), odd.length);
    rejects(() => decodeDescriptor(dup), /ascending type order/, 'duplicate extension record');

    // Flags and area must agree in both directions.
    const promised = Uint8Array.from(flagged); promised[1] |= 0x30;   // mmsIndex = 3, no area
    rejects(() => decodeDescriptor(promised), /no extension carries it/, 'explicit promised but absent');
    const unselected = Uint8Array.from(odd); unselected[1] &= ~0x30;  // area present, enum selected
    rejects(() => decodeDescriptor(unselected), /do not select it/, 'extension present but unselected');

    // A TLV that merely restates an enum value is non-canonical.
    const restate = Uint8Array.from(odd);
    restate[restate.length - 4] = 0x00; restate[restate.length - 3] = 0x04;
    restate[restate.length - 2] = 0x00; restate[restate.length - 1] = 0x00;   // 262144
    rejects(() => decodeDescriptor(restate), /duplicates a value the flags already encode/, 'non-canonical TLV');
}

// ---------------------------------------------------------------------------
// rejection: malformed / hostile descriptors
// ---------------------------------------------------------------------------
{
    const good = await build(chrome.turn_all.offer, TYPE.OFFER);
    const UF = ufragLenOffset(TYPE.OFFER);

    rejects(() => decodeDescriptor(new Uint8Array(0)), /empty/, 'empty');
    rejects(() => decodeDescriptor(good.subarray(0, good.length - 1)), /truncated/, 'truncated');
    rejects(() => decodeDescriptor(good.subarray(0, 20)), /truncated/, 'heavily truncated');

    // Version gate: a v1 byte is an error, never an attempt at the old parser.
    for (const v of [0x00, 0x01, 0x03, 0xff]) {
        const x = Uint8Array.from(good); x[0] = v;
        rejects(() => decodeDescriptor(x), /unsupported descriptor version/, `version 0x${v.toString(16)}`);
    }

    // Trailing bytes: never silently ignored.
    const trailing = new Uint8Array(good.length + 3);
    trailing.set(good); trailing.set([1, 2, 3], good.length);
    rejects(() => decodeDescriptor(trailing), /trailing byte/, 'trailing bytes');

    // Reserved VALUES are refused. (Every flag bit is now allocated; growth goes
    // through the TLV area, which is itself deny-by-default.)
    const reservedType = Uint8Array.from(good); reservedType[1] = (reservedType[1] & ~0x03) | 0x02;
    rejects(() => decodeDescriptor(reservedType), /reserved descriptor type/, 'reserved type');
    const reservedSetup = Uint8Array.from(good); reservedSetup[1] = (reservedSetup[1] & ~0x0c) | 0x0c;
    rejects(() => decodeDescriptor(reservedSetup), /reserved DTLS setup role/, 'reserved setup');

    rejects(() => decodeDescriptor(new Uint8Array(LIMITS.MAX_PAYLOAD_BYTES + 1)), /payload limit/, 'oversized');

    // Candidate count and kind.
    const pwdOff = UF + 1 + good[UF];
    const countOff = pwdOff + 1 + good[pwdOff];
    const tooMany = Uint8Array.from(good); tooMany[countOff] = LIMITS.MAX_CANDIDATES + 1;
    rejects(() => decodeDescriptor(tooMany), /too many candidates/, 'candidate count over limit');
    const badKind = Uint8Array.from(good); badKind[countOff + 1] = 0xf0;
    rejects(() => decodeDescriptor(badKind), /reserved candidate kind/, 'reserved candidate kind');
    const badTcp = Uint8Array.from(good); badTcp[countOff + 1] = (badTcp[countOff + 1] & 0xf0) | 0x0f;
    rejects(() => decodeDescriptor(badTcp), /reserved TCP candidate type/, 'reserved tcptype');
    const firstKind = good[countOff + 1] >> 4;
    const portOff = countOff + 2 + (firstKind === 1 || firstKind >= 4 ? 16 : 4);
    const zeroPort = Uint8Array.from(good); zeroPort[portOff] = 0; zeroPort[portOff + 1] = 0;
    rejects(() => decodeDescriptor(zeroPort), /port must be non-zero/, 'zero port');

    // ICE credential alphabet and length.
    const badUfragLen = Uint8Array.from(good); badUfragLen[UF] = 2;
    rejects(() => decodeDescriptor(badUfragLen), /ice-ufrag length out of range/, 'short ufrag');
    const badUfragChar = Uint8Array.from(good); badUfragChar[UF + 1] = '!'.charCodeAt(0);
    rejects(() => decodeDescriptor(badUfragChar), /ICE alphabet/, 'ufrag alphabet');

    // A CR or LF inside a credential is what an SDP-injection attempt looks
    // like; it must die in the decoder, long before the serializer.
    for (const evil of [0x0d, 0x0a, 0x00]) {
        const inj = Uint8Array.from(good); inj[UF + 1] = evil;
        rejects(() => decodeDescriptor(inj), /non-printable byte/, `injected byte 0x${evil.toString(16)}`);
    }
}

// ---------------------------------------------------------------------------
// expiry, clock skew, one-shot
// ---------------------------------------------------------------------------
{
    const bytes = await build(chrome.stun.offer, TYPE.OFFER, { expiresAtMs: Date.now() + 60_000 });
    assert.ok(decodeDescriptor(bytes, { nowMs: Date.now() }), 'valid inside the window');

    // Clock skew: a receiver running a minute fast still accepts.
    assert.ok(decodeDescriptor(bytes, { nowMs: Date.now() + 60_000 + 60_000 }),
        'one minute of receiver skew past expiry is tolerated');
    rejects(() => decodeDescriptor(bytes, { nowMs: Date.now() + 60_000 + LIMITS.CLOCK_SKEW_MS + 60_000 }),
        /expired/, 'beyond the skew allowance');

    // The error must point at the clock, because that is the likely cause.
    rejects(() => decodeDescriptor(bytes, { nowMs: Date.now() + 3600_000 }),
        /clock or time zone/, 'expiry error names the clock');
    try {
        decodeDescriptor(bytes, { nowMs: Date.now() + 3600_000 });
    } catch (e) {
        assert.equal(e.code, 'expired', 'expiry carries a machine-readable code');
    }

    // An attacker cannot mint a descriptor that never dies.
    const eternal = await build(chrome.stun.offer, TYPE.OFFER, {
        expiresAtMs: Date.now() + 365 * 24 * 3600 * 1000,
    });
    rejects(() => decodeDescriptor(eternal), /lifetime is implausibly long/, 'year-long lifetime');

    // The answer's replay defence: its tag must be the binding tag of the exact
    // offer being shown, so an answer to any other offer is refused and each
    // offer is consumed once.
    const offerA = await build(chrome.stun.offer, TYPE.OFFER);
    const offerB = await build(chrome.turn_all.offer, TYPE.OFFER);
    const tagA = await bindingTag(digest, offerA);
    const answer = await build(chrome.stun.answer, TYPE.ANSWER, { bindingTag: tagA });
    assert.deepEqual(decodeDescriptor(answer).bindingTag, tagA, 'answer binds to its offer');
    assert.notDeepEqual(decodeDescriptor(answer).bindingTag, await bindingTag(digest, offerB), 'not to a different offer');

    // The offer carries no nonce of its own; its uniqueness rides on ice-pwd,
    // which is inside the hashed bytes. Two offers differing only there must
    // still produce different tags.
    const raw = parseSdp(chrome.stun.offer);
    const mk = async (pwd) => encodeDescriptor({
        type: TYPE.OFFER, expiresAtMs: EXPIRY(),
        sdpFields: { ...raw, pwd, candidates: pruneCandidates(raw.candidates) },
        commitment: null,
    });
    const t1 = await bindingTag(digest, await mk('0123456789abcdef01234567'));
    const t2 = await bindingTag(digest, await mk('0123456789abcdef01234568'));
    assert.notDeepEqual(t1, t2, 'ice-pwd alone makes the offer unique');

    const tampered = Uint8Array.from(offerA); tampered[40] ^= 0x01;
    assert.notDeepEqual(await bindingTag(digest, tampered), tagA, 'binding tag is sensitive to the offer bytes');
}

// ---------------------------------------------------------------------------
// SAS transcript coverage
// ---------------------------------------------------------------------------
{
    const offer = await build(chrome.turn_all.offer, TYPE.OFFER);
    const answer = await build(chrome.turn_all.answer, TYPE.ANSWER);
    const extOffer = await build([
        'v=0', 'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
        'a=candidate:1 1 udp 2113937151 192.168.1.9 40000 typ host',
        'a=ice-ufrag:abcd', 'a=ice-pwd:0123456789abcdef01234567',
        'a=fingerprint:sha-256 ' + new Array(32).fill('DD').join(':'),
        'a=setup:actpass', 'a=max-message-size:131072',
    ].join('\r\n') + '\r\n', TYPE.OFFER);
    const blobO = rnd(400);
    const blobA = rnd(400);
    const base = await digest(sasTranscript(offer, answer, blobO, blobA));

    for (const [label, mutate] of [
        ['offer version byte', () => { const x = Uint8Array.from(offer); x[0] = 3; return [x, answer, blobO, blobA]; }],
        ['offer flags', () => { const x = Uint8Array.from(offer); x[1] ^= 0x10; return [x, answer, blobO, blobA]; }],
        ['offer expiry', () => { const x = Uint8Array.from(offer); x[4] ^= 0x01; return [x, answer, blobO, blobA]; }],
        ['offer fingerprint', () => { const x = Uint8Array.from(offer); x[6] ^= 0xff; return [x, answer, blobO, blobA]; }],
        ['offer ice-pwd', () => { const x = Uint8Array.from(offer); x[50] ^= 0x01; return [x, answer, blobO, blobA]; }],
        ['offer candidate port', () => { const x = Uint8Array.from(offer); x[x.length - 20] ^= 0x01; return [x, answer, blobO, blobA]; }],
        ['answer binding tag', () => { const x = Uint8Array.from(answer); x[6] ^= 0xff; return [offer, x, blobO, blobA]; }],
        ['answer bytes', () => { const x = Uint8Array.from(answer); x[20] ^= 0xff; return [offer, x, blobO, blobA]; }],
        ['extension area', () => { const x = Uint8Array.from(extOffer); x[x.length - 1] ^= 0x01; return [x, answer, blobO, blobA]; }],
        ['offer blob', () => { const x = Uint8Array.from(blobO); x[7] ^= 0x01; return [offer, answer, x, blobA]; }],
        ['answer blob', () => { const x = Uint8Array.from(blobA); x[7] ^= 0x01; return [offer, answer, blobO, x]; }],
    ]) {
        const args = mutate();
        const h = await digest(sasTranscript(...args));
        const ref = label === 'extension area'
            ? await digest(sasTranscript(extOffer, answer, blobO, blobA))
            : base;
        assert.notDeepEqual(h, ref, `SAS must change when the ${label} changes`);
    }

    // Length prefixes stop a boundary shift from producing a colliding
    // transcript.
    const shifted = await digest(sasTranscript(
        offer.subarray(0, offer.length - 1),
        new Uint8Array([offer[offer.length - 1], ...answer]),
        blobO, blobA,
    ));
    assert.notDeepEqual(shifted, base, 'field boundaries are unambiguous');
}

// ---------------------------------------------------------------------------
// commitment
// ---------------------------------------------------------------------------
{
    const blob = rnd(400);
    const c = await commitBlob(digest, blob);
    assert.equal(c.length, LIMITS.COMMITMENT_BYTES);
    const other = Uint8Array.from(blob); other[123] ^= 0x01;
    assert.notDeepEqual(await commitBlob(digest, other), c, 'commitment binds every blob byte');

    assert.deepEqual(decodeDescriptor(await build(chrome.stun.offer, TYPE.OFFER, { commitment: c })).commitment, c);
    assert.equal(decodeDescriptor(await build(chrome.stun.offer, TYPE.OFFER, { commitment: null })).commitment, null);
}

// ---------------------------------------------------------------------------
// text transport
// ---------------------------------------------------------------------------
{
    for (let n = 0; n < 200; n++) {
        const b = rnd(n);
        assert.deepEqual(fromBase64Url(toBase64Url(b)), b, `base64url round-trip at ${n} bytes`);
    }

    const bytes = await build(chrome.turn_all.offer, TYPE.OFFER);
    const text = encodeText(bytes);
    assert.ok(/^SB2:[A-Za-z0-9_-]+$/.test(text), 'text form uses only URL-safe characters');
    assert.deepEqual(decodeText(text), bytes);

    const wrapped = text.slice(0, 40) + '\n' + text.slice(40, 90) + ' \r\n' + text.slice(90);
    assert.deepEqual(decodeText(wrapped), bytes, 'wrapped paste still decodes');

    rejects(() => decodeText('SB1:bin:abcd'), /not an SB2 descriptor/, 'old prefix');
    rejects(() => decodeText('SB2:abc$def'), /outside base64url/, 'bad alphabet');
    rejects(() => decodeText('SB2:' + 'A'.repeat(5000)), /too long/, 'over-long text');
    rejects(() => fromBase64Url('AAAAA'), /impossible length/, 'impossible base64 length');
    rejects(() => fromBase64Url('AB'), /non-zero padding bits/, 'non-canonical tail');
}

// ---------------------------------------------------------------------------
// encoder-side input validation
// ---------------------------------------------------------------------------
{
    const raw = parseSdp(chrome.stun.offer);
    const fields = { ...raw, candidates: pruneCandidates(raw.candidates) };
    const base = { type: TYPE.OFFER, expiresAtMs: EXPIRY(), sdpFields: fields };

    rejects(() => encodeDescriptor({ ...base, type: 7 }), /invalid descriptor type/, 'bad type');
    rejects(() => encodeDescriptor({ ...base, bindingTag: rnd(8) }), /offers do not carry a binding tag/, 'tag on an offer');
    rejects(() => encodeDescriptor({ ...base, type: TYPE.ANSWER }), /answer needs an 8-byte binding tag/, 'answer without a tag');
    rejects(() => encodeDescriptor({ ...base, type: TYPE.ANSWER, bindingTag: rnd(7) }), /8-byte binding tag/, 'short tag');
    rejects(() => encodeDescriptor({ ...base, commitment: rnd(15) }), /commitment must be 16 bytes/, 'short commitment');
    rejects(() => encodeDescriptor({ ...base, sdpFields: { ...fields, ufrag: 'a b' } }), /invalid ice-ufrag/, 'ufrag with a space');
    rejects(() => encodeDescriptor({ ...base, sdpFields: { ...fields, pwd: 'short' } }), /invalid ice-pwd/, 'short pwd');
    for (const bad of [null, undefined, 0, -1, 1.5, 2 ** 31]) {
        rejects(
            () => encodeDescriptor({ ...base, sdpFields: { ...fields, maxMessageSize: bad } }),
            /max-message-size must be an integer/, `max-message-size ${bad}`,
        );
    }
    rejects(
        () => encodeDescriptor({ ...base, sdpFields: { ...fields, candidates: new Array(9).fill(fields.candidates[0]) } }),
        /too many candidates/, 'too many candidates',
    );

    rejects(() => parseSdp('v=0\r\n'), /missing ICE credentials/, 'no ICE creds');
    rejects(
        () => parseSdp('a=ice-ufrag:abcd\r\na=ice-pwd:0123456789abcdef01234567\r\n'),
        /missing a DTLS fingerprint/, 'no fingerprint',
    );
    rejects(
        () => parseSdp('a=ice-ufrag:abcd\r\na=ice-pwd:0123456789abcdef01234567\r\na=fingerprint:sha-1 AA:BB\r\n'),
        /unsupported DTLS fingerprint algorithm/, 'sha-1 fingerprint',
    );
}

console.log(`descriptor-sbq2: all assertions passed${firefox ? ' (chrome + firefox fixtures)' : ' (chrome fixtures only)'}`);
