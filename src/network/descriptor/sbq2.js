// SBQ2 — connection descriptor v2.
//
// The out-of-band descriptor (QR / link / paste) carries ONLY what is needed to
// bring up the DTLS association: ICE credentials, the DTLS certificate
// fingerprint, and the candidate list. Every byte of key material — identity
// key, ECDH key, signatures — travels in-band over the DataChannel that the
// fingerprint already authenticates, and is bound to the descriptor by a
// commitment carried here.
//
// Why that is safe, in one paragraph: the fingerprint is transferred over the
// out-of-band channel the user already trusts (they are looking at the QR), and
// DTLS will only complete with the holder of the matching private key. So the
// channel is authenticated to whoever showed the code before a single byte of
// key material moves. The commitment makes substitution of that material fail
// closed automatically instead of relying on the human SAS comparison, and the
// SAS itself is computed over a transcript that covers both descriptors
// verbatim and both in-band blobs — so nothing that travelled out of band can
// be altered without changing the digits the users read to each other.
//
// NOTE: the in-band half of that protocol is not implemented yet. This module
// is the wire format only; see doc/descriptor-sbq2.md for the migration gate.
//
// This module is pure: no DOM, no crypto beyond an injected digest, no network.
// It is the parser for fully attacker-controlled input, so every length, range
// and alphabet is checked before the value is used, and the SDP is rebuilt by a
// strict serializer from validated primitives — never by concatenating a string
// that came off the wire.

export const SBQ2_VERSION = 0x02;

// Hard limits applied BEFORE any structural parsing.
export const LIMITS = Object.freeze({
    MAX_PAYLOAD_BYTES: 512,   // ~3.5x the largest descriptor we have ever measured
    MAX_CANDIDATES: 8,
    MIN_UFRAG: 4,             // RFC 8839: ice-ufrag is 4..256 chars
    MAX_UFRAG: 64,
    MIN_PWD: 22,              // RFC 8839: ice-pwd is 22..256 chars, >=128 bits of randomness
    MAX_PWD: 64,
    FINGERPRINT_BYTES: 32,    // SHA-256
    COMMITMENT_BYTES: 16,     // 128-bit second-preimage resistance
    BINDING_BYTES: 8,
    MAX_LIFETIME_MINUTES: 60,
    MAX_EXT_BYTES: 255,

    // Byte budget for candidates admitted BEYOND the coverage set (coverage
    // itself is never cut — see pruneCandidates). Derived from the acceptance
    // target rather than picked: the largest answer head we have measured is
    // Firefox's, at 104 bytes (version+flags+expiry+tag+fingerprint+8-char
    // ufrag+32-char pwd+count+commitment), and QR version 8 at level M holds
    // 152 bytes in byte mode. 152 - 104 = 48.
    SURPLUS_CANDIDATE_BYTES: 48,

    // Clock-skew allowance, applied in both directions on the expiry check.
    //
    // Two minutes is chosen against the failure it exists for: a receiver whose
    // clock is off. An NTP-synced device is within milliseconds, and an
    // unsynced modern device drifts on the order of seconds per day, so two
    // minutes swallows every ordinary case. It does NOT swallow a grossly wrong
    // clock (manually set, or reset to the epoch by a dead battery) — that is
    // deliberate, because such a device cannot be given a meaningful freshness
    // guarantee and should be told so. The cost is that the replay window grows
    // from the nominal 10 minutes to 12; keeping the tolerance well under the
    // lifetime is what bounds that.
    CLOCK_SKEW_MS: 120_000,
});

// Expiry is stored as minutes since 2024-01-01T00:00:00Z in 24 bits, which runs
// out in 2055. Minute granularity is far finer than any descriptor lifetime, and
// uint16 was tried first and rejected: 65535 minutes is only 45 days of range.
const EPOCH_MS = Date.UTC(2024, 0, 1);
const MAX_EXPIRY_UNITS = 0xffffff;

export const TYPE = Object.freeze({ OFFER: 0, ANSWER: 1 });
const SETUP = Object.freeze(['actpass', 'active', 'passive']);

// max-message-size, packed into two flag bits. Index 3 means "an explicit value
// is carried in extension 0x01"; RFC 8841 makes 64 KiB the default when the
// attribute is absent, which is why absent and 65536 share an encoding.
const MMS_ENUM = Object.freeze([262144, 1073741823, 65536, null]);
const MMS_EXPLICIT = 3;

// Extension types. Unknown types are rejected, never skipped — see decodeExt.
export const EXT = Object.freeze({ MAX_MESSAGE_SIZE: 0x01 });

// Candidate kinds. Values are wire constants — never renumber, only append.
const KIND = Object.freeze({
    HOST_V4: 0, HOST_MDNS: 1, SRFLX_V4: 2, RELAY_V4: 3,
    HOST_V6: 4, SRFLX_V6: 5, RELAY_V6: 6,
});
const KIND_ADDR_LEN = Object.freeze({ 0: 4, 1: 16, 2: 4, 3: 4, 4: 16, 5: 16, 6: 16 });
const KIND_TYPE = Object.freeze({ 0: 'host', 1: 'host', 2: 'srflx', 3: 'relay', 4: 'host', 5: 'srflx', 6: 'relay' });
// Address family for the coverage rule. mDNS is its own family: it resolves
// only on the sender's link, so it covers a case neither v4 nor v6 does.
const KIND_FAMILY = Object.freeze({ 0: 'v4', 1: 'mdns', 2: 'v4', 3: 'v4', 4: 'v6', 5: 'v6', 6: 'v6' });
const TCPTYPE = Object.freeze([null, 'passive', 'active', 'so']);

// RFC 8445 §5.1.2.2 type preferences. We do not reproduce the sender's original
// priority values: ICE priority only orders connectivity checks, and both peers
// compute their own local priorities anyway. Re-deriving them from the type and
// the candidate's position in the list preserves the sender's ordering intent
// while costing zero bytes on the wire.
const TYPE_PREF = Object.freeze({ host: 126, srflx: 100, relay: 0 });

// RFC 8839 ice-char = ALPHA / DIGIT / "+" / "/"
const ICE_CHAR = /^[A-Za-z0-9+/]+$/;

class DescriptorError extends Error {
    constructor(message, code = 'malformed') { super(message); this.name = 'DescriptorError'; this.code = code; }
}
const fail = (msg, code) => { throw new DescriptorError(msg, code); };

// ---------------------------------------------------------------------------
// SDP -> structured fields
// ---------------------------------------------------------------------------

const UUID_RE = /^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})\.local$/i;
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function parseIpv4(s) {
    const m = IPV4_RE.exec(s);
    if (!m) return null;
    const out = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
        const v = Number(m[i + 1]);
        if (!Number.isInteger(v) || v < 0 || v > 255) return null;
        out[i] = v;
    }
    return out;
}

function parseIpv6(s) {
    // Accept the plain hextet forms (with "::" compression) and the dotted-quad
    // tail used by IPv4-mapped and NAT64 addresses (64:ff9b::203.0.113.7).
    if (!/^[0-9a-fA-F:.]+$/.test(s) || s.length > 45) return null;
    let text = s;
    let tail4 = null;
    const lastColon = text.lastIndexOf(':');
    if (text.includes('.')) {
        tail4 = parseIpv4(text.slice(lastColon + 1));
        if (!tail4) return null;
        text = text.slice(0, lastColon + 1) + '0:0';
    }
    const halves = text.split('::');
    if (halves.length > 2) return null;
    const toWords = (part) => (part === '' ? [] : part.split(':').map((h) => (
        h.length === 0 || h.length > 4 ? NaN : parseInt(h, 16)
    )));
    const head = toWords(halves[0]);
    const tail = halves.length === 2 ? toWords(halves[1]) : [];
    if ([...head, ...tail].some((w) => !Number.isInteger(w) || w < 0 || w > 0xffff)) return null;
    let words;
    if (halves.length === 2) {
        const gap = 8 - head.length - tail.length;
        if (gap < 1) return null;
        words = [...head, ...new Array(gap).fill(0), ...tail];
    } else {
        words = head;
    }
    if (words.length !== 8) return null;
    const out = new Uint8Array(16);
    words.forEach((w, i) => { out[i * 2] = w >> 8; out[i * 2 + 1] = w & 0xff; });
    if (tail4) out.set(tail4, 12);
    return out;
}

function parseMdns(s) {
    const m = UUID_RE.exec(s);
    if (!m) return null;
    const hex = (m[1] + m[2] + m[3] + m[4] + m[5]).toLowerCase();
    const out = new Uint8Array(16);
    for (let i = 0; i < 16; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
}

function sdpLines(sdp) {
    if (typeof sdp !== 'string') fail('SDP must be a string');
    if (sdp.length > 64 * 1024) fail('SDP is too large');
    return sdp.split(/\r\n|\n/).filter((l) => l.length > 0);
}

function attr(lines, name) {
    const prefix = `a=${name}:`;
    for (const l of lines) if (l.startsWith(prefix)) return l.slice(prefix.length).trim();
    return null;
}

/**
 * Extract the fields SBQ2 carries from a browser-generated SDP.
 * Anything not represented in the template is dropped here, deliberately.
 *
 * Candidates keep their original `priority` so pruneCandidates can rank by the
 * sender's own judgement; the value is never encoded.
 */
export function parseSdp(sdp) {
    const lines = sdpLines(sdp);

    const ufrag = attr(lines, 'ice-ufrag');
    const pwd = attr(lines, 'ice-pwd');
    if (!ufrag || !pwd) fail('SDP is missing ICE credentials');

    const fpLine = attr(lines, 'fingerprint');
    if (!fpLine) fail('SDP is missing a DTLS fingerprint');
    const [hashAlg, fpHex] = fpLine.split(/\s+/);
    if (!hashAlg || hashAlg.toLowerCase() !== 'sha-256') {
        fail(`unsupported DTLS fingerprint algorithm: ${String(hashAlg).slice(0, 16)}`);
    }
    const fpBytes = String(fpHex).split(':');
    if (fpBytes.length !== LIMITS.FINGERPRINT_BYTES) fail('DTLS fingerprint has the wrong length');
    const fingerprint = new Uint8Array(LIMITS.FINGERPRINT_BYTES);
    fpBytes.forEach((b, i) => {
        if (!/^[0-9a-fA-F]{2}$/.test(b)) fail('DTLS fingerprint is not hex');
        fingerprint[i] = parseInt(b, 16);
    });

    const setupStr = attr(lines, 'setup') || 'actpass';
    const setup = SETUP.indexOf(setupStr);
    if (setup < 0) fail(`unsupported DTLS setup role: ${setupStr.slice(0, 16)}`);

    // RFC 8841: an absent a=max-message-size means 64 KiB.
    const mmsStr = attr(lines, 'max-message-size');
    const maxMessageSize = mmsStr === null ? 65536 : Number(mmsStr);
    if (!Number.isInteger(maxMessageSize) || maxMessageSize < 0) fail('invalid a=max-message-size');

    const candidates = [];
    for (const line of lines) {
        if (!line.startsWith('a=candidate:')) continue;
        const p = line.slice('a=candidate:'.length).split(/\s+/);
        // foundation component transport priority addr port "typ" type ...
        if (p.length < 8 || p[6] !== 'typ') continue;
        if (p[1] !== '1') continue;                       // component 1 only (BUNDLE, no RTCP)
        const transport = p[2].toLowerCase();
        const priority = Number(p[3]);
        const addr = p[4];
        const port = Number(p[5]);
        const ctype = p[7];
        if (!Number.isInteger(port) || port < 1 || port > 65535) continue;

        let tcptype = 0;
        if (transport === 'tcp') {
            const idx = p.indexOf('tcptype');
            const t = idx >= 0 ? TCPTYPE.indexOf(p[idx + 1]) : -1;
            if (t <= 0) continue;                          // unusable TCP candidate
            tcptype = t;
        } else if (transport !== 'udp') {
            continue;
        }

        let kind = null; let bytes = null;
        const mdns = parseMdns(addr);
        if (mdns && ctype === 'host') { kind = KIND.HOST_MDNS; bytes = mdns; }
        else {
            const v4 = parseIpv4(addr);
            const v6 = v4 ? null : parseIpv6(addr);
            const raw = v4 || v6;
            if (!raw) continue;
            if (ctype === 'host') kind = v4 ? KIND.HOST_V4 : KIND.HOST_V6;
            else if (ctype === 'srflx' || ctype === 'prflx') kind = v4 ? KIND.SRFLX_V4 : KIND.SRFLX_V6;
            else if (ctype === 'relay') kind = v4 ? KIND.RELAY_V4 : KIND.RELAY_V6;
            else continue;
            bytes = raw;
        }
        candidates.push({
            kind, tcptype, addr: bytes, port,
            priority: Number.isFinite(priority) ? priority : 0,
        });
    }

    return { ufrag, pwd, fingerprint, setup, maxMessageSize, candidates };
}

/** Bytes a candidate occupies on the wire: kind byte + address + port. */
export function candidateSize(c) { return 1 + KIND_ADDR_LEN[c.kind] + 2; }

/**
 * True if a peer can actually connect TO this candidate.
 *
 * An ICE-TCP candidate with `tcptype active` is an outbound-only socket on the
 * discard port; it pairs solely with a remote `passive` candidate and offers the
 * peer no address to reach. Firefox advertises one on every connection. It is
 * therefore surplus, never coverage — otherwise it would claim a coverage slot
 * that buys no reachability, at 19 bytes for an mDNS address.
 */
const isConnectable = (c) => c.tcptype !== 2 && c.tcptype !== 3;

/**
 * Trim a candidate list to what actually buys connectivity, under a byte budget.
 *
 * The rule is coverage first, count second. Every (address family, candidate
 * type, transport) combination present in the input keeps at least one
 * representative before any second candidate is admitted. That ordering is the
 * whole point: a pure count limit sorted v4-first can evict the only working
 * candidate on an IPv6-only network, which is now a normal mode on several
 * mobile carriers, and a count limit that ignores transport can evict the TCP
 * candidate that exists precisely for networks where UDP is blocked.
 *
 * Only after coverage is satisfied is the remaining budget filled by the
 * sender's own priority, with relays capped — a TURN server offering udp/tcp/tls
 * hands out one allocation per transport, and they all resolve to the same
 * relayed address, so the third one adds nothing the first does not already
 * provide. Two are kept in case one allocation's binding dies.
 *
 * If coverage alone overruns the budget, coverage wins and the descriptor grows.
 * A QR one version larger is cheaper than a connection that cannot be made.
 */
export function pruneCandidates(candidates, {
    maxCandidates = LIMITS.MAX_CANDIDATES,
    maxBytes = LIMITS.SURPLUS_CANDIDATE_BYTES,
    keepMdns = true,
    maxRelays = 2,
} = {}) {
    const pool = candidates.filter((c) => keepMdns || c.kind !== KIND.HOST_MDNS);

    // Exact duplicates first — same kind, transport, address and port.
    const uniq = [];
    const seen = new Set();
    for (const c of pool) {
        const key = `${c.kind}:${c.tcptype}:${Array.from(c.addr).join('.')}:${c.port}`;
        if (seen.has(key)) continue;
        seen.add(key);
        uniq.push(c);
    }

    const byPriority = (a, b) => (b.priority || 0) - (a.priority || 0);
    const groupKey = (c) => `${KIND_FAMILY[c.kind]}/${KIND_TYPE[c.kind]}/${c.tcptype === 0 ? 'udp' : 'tcp'}`;

    // Pass 1 — one representative per (family, type, transport) group, best
    // priority first. Only candidates a peer can dial count for coverage.
    const groups = new Map();
    for (const c of [...uniq].sort(byPriority)) {
        if (!isConnectable(c)) continue;
        const g = groupKey(c);
        if (!groups.has(g)) groups.set(g, []);
        groups.get(g).push(c);
    }
    const chosen = [];
    const taken = new Set();
    let bytes = 0;
    let relays = 0;
    const admit = (c) => {
        chosen.push(c);
        taken.add(c);
        bytes += candidateSize(c);
        if (KIND_TYPE[c.kind] === 'relay') relays++;
    };
    for (const list of groups.values()) admit(list[0]);

    // Pass 2 — fill what is left by priority, honouring both budgets.
    for (const c of [...uniq].sort(byPriority)) {
        if (taken.has(c)) continue;
        if (chosen.length >= maxCandidates) break;
        if (bytes + candidateSize(c) > maxBytes) continue;
        if (KIND_TYPE[c.kind] === 'relay' && relays >= maxRelays) continue;
        admit(c);
    }

    // Emit in descending priority so the sender's ordering intent survives into
    // the localPref the serializer reconstructs.
    return chosen.sort(byPriority);
}

// ---------------------------------------------------------------------------
// encode
// ---------------------------------------------------------------------------

class Writer {
    constructor() { this.b = []; }
    u8(v) { this.b.push(v & 0xff); }
    u16(v) { this.b.push((v >> 8) & 0xff, v & 0xff); }
    u24(v) { this.b.push((v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff); }
    u32(v) { this.b.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff); }
    bytes(a) { for (const x of a) this.b.push(x & 0xff); }
    ascii(s) { for (let i = 0; i < s.length; i++) this.b.push(s.charCodeAt(i) & 0xff); }
    done() { return Uint8Array.from(this.b); }
}

function buildExtensions(maxMessageSize) {
    // Guard before the lookup: MMS_ENUM's slot 3 is the "explicit" marker and
    // holds null, so a null or undefined size would otherwise index straight
    // onto it and promise an extension record that never gets written.
    if (!Number.isInteger(maxMessageSize) || maxMessageSize < 1024 || maxMessageSize > 0x7fffffff) {
        fail('max-message-size must be an integer between 1024 and 2^31-1');
    }
    // Records are emitted in ascending type order so a descriptor has exactly
    // one valid spelling; the decoder enforces the same ordering.
    const records = [];
    let mmsIndex = MMS_ENUM.indexOf(maxMessageSize);
    if (mmsIndex < 0) {
        mmsIndex = MMS_EXPLICIT;
        const w = new Writer();
        w.u32(maxMessageSize);
        records.push({ type: EXT.MAX_MESSAGE_SIZE, value: w.done() });
    }
    return { mmsIndex, records };
}

/**
 * @param {object} d
 * @param {number} d.type              TYPE.OFFER | TYPE.ANSWER
 * @param {Uint8Array} [d.bindingTag]  answers only: 8-byte tag of the offer
 * @param {number} d.expiresAtMs       absolute expiry, ms since epoch
 * @param {object} d.sdpFields         output of parseSdp (already pruned)
 * @param {Uint8Array|null} d.commitment  16-byte commitment to the in-band blob
 */
export function encodeDescriptor(d) {
    const { type, bindingTag: tag = null, expiresAtMs, sdpFields, commitment = null } = d;
    if (type !== TYPE.OFFER && type !== TYPE.ANSWER) fail('invalid descriptor type');
    if (type === TYPE.ANSWER) {
        if (!(tag instanceof Uint8Array) || tag.length !== LIMITS.BINDING_BYTES) fail('answer needs an 8-byte binding tag');
    } else if (tag !== null) {
        fail('offers do not carry a binding tag');
    }
    if (commitment !== null && (!(commitment instanceof Uint8Array) || commitment.length !== LIMITS.COMMITMENT_BYTES)) {
        fail('commitment must be 16 bytes');
    }

    const { ufrag, pwd, fingerprint, setup, maxMessageSize, candidates } = sdpFields;
    if (ufrag.length < LIMITS.MIN_UFRAG || ufrag.length > LIMITS.MAX_UFRAG || !ICE_CHAR.test(ufrag)) fail('invalid ice-ufrag');
    if (pwd.length < LIMITS.MIN_PWD || pwd.length > LIMITS.MAX_PWD || !ICE_CHAR.test(pwd)) fail('invalid ice-pwd');
    if (candidates.length > LIMITS.MAX_CANDIDATES) fail('too many candidates');

    const minutes = Math.ceil((expiresAtMs - EPOCH_MS) / 60000);
    if (!Number.isInteger(minutes) || minutes < 0 || minutes > MAX_EXPIRY_UNITS) fail('expiry out of range');

    const { mmsIndex, records } = buildExtensions(maxMessageSize);

    const ext = new Writer();
    for (const r of records) {
        if (r.value.length > 255) fail('extension value is too long');
        ext.u8(r.type); ext.u8(r.value.length); ext.bytes(r.value);
    }
    const extBytes = ext.done();
    if (extBytes.length > LIMITS.MAX_EXT_BYTES) fail('extension area is too long');

    const flags = (type & 0x03)
        | ((setup & 0x03) << 2)
        | ((mmsIndex & 0x03) << 4)
        | (commitment ? 0x40 : 0)
        | (extBytes.length ? 0x80 : 0);

    const w = new Writer();
    w.u8(SBQ2_VERSION);
    w.u8(flags);
    w.u24(minutes);
    if (type === TYPE.ANSWER) w.bytes(tag);
    w.bytes(fingerprint);
    w.u8(ufrag.length); w.ascii(ufrag);
    w.u8(pwd.length); w.ascii(pwd);
    w.u8(candidates.length);
    for (const c of candidates) {
        w.u8(((c.kind & 0x0f) << 4) | (c.tcptype & 0x0f));
        w.bytes(c.addr);
        w.u16(c.port);
    }
    if (commitment) w.bytes(commitment);
    if (extBytes.length) { w.u8(extBytes.length); w.bytes(extBytes); }

    const out = w.done();
    if (out.length > LIMITS.MAX_PAYLOAD_BYTES) fail('descriptor exceeds the payload limit');
    return out;
}

// ---------------------------------------------------------------------------
// decode
// ---------------------------------------------------------------------------

class Reader {
    constructor(buf) { this.buf = buf; this.i = 0; }
    need(n) { if (this.i + n > this.buf.length) fail('descriptor is truncated'); }
    u8() { this.need(1); return this.buf[this.i++]; }
    u16() { this.need(2); const v = (this.buf[this.i] << 8) | this.buf[this.i + 1]; this.i += 2; return v; }
    u24() { this.need(3); const v = (this.buf[this.i] << 16) | (this.buf[this.i + 1] << 8) | this.buf[this.i + 2]; this.i += 3; return v; }
    u32() { this.need(4); const v = ((this.buf[this.i] << 24) >>> 0) + (this.buf[this.i + 1] << 16) + (this.buf[this.i + 2] << 8) + this.buf[this.i + 3]; this.i += 4; return v >>> 0; }
    bytes(n) { this.need(n); return this.buf.slice(this.i, this.i += n); }
    ascii(n) {
        this.need(n);
        let s = '';
        for (let k = 0; k < n; k++) {
            const c = this.buf[this.i + k];
            if (c < 0x20 || c > 0x7e) fail('non-printable byte in a text field');
            s += String.fromCharCode(c);
        }
        this.i += n;
        return s;
    }
    get rest() { return this.buf.length - this.i; }
}

/**
 * Parse the TLV extension area.
 *
 * An unrecognised type is a hard error, not a skip. That is deliberate: a
 * decoder that ignores what it does not understand turns the extension area
 * into a downgrade channel, because an attacker can append a record that one
 * side acts on and the other silently drops, and the two ends then disagree
 * about the session while both believe they validated it. Deny-by-default costs
 * forward compatibility, and that cost is paid on purpose — a new extension
 * type ships together with a version bump that both ends can gate on, never
 * silently to a population that will half-ignore it.
 */
function decodeExt(buf) {
    const r = new Reader(buf);
    const out = new Map();
    let lastType = -1;
    while (r.rest > 0) {
        const type = r.u8();
        const len = r.u8();
        const value = r.bytes(len);
        if (type <= lastType) fail('extension records must be in ascending type order without duplicates');
        lastType = type;
        switch (type) {
            case EXT.MAX_MESSAGE_SIZE: {
                if (len !== 4) fail('extension 0x01 must be 4 bytes');
                const v = new Reader(value).u32();
                if (v < 1024 || v > 0x7fffffff) fail('extension 0x01 value is out of range');
                if (MMS_ENUM.includes(v)) fail('extension 0x01 duplicates a value the flags already encode');
                out.set(type, v);
                break;
            }
            default:
                fail(`unknown extension type 0x${type.toString(16).padStart(2, '0')}`, 'unknown_extension');
        }
    }
    return out;
}

/**
 * Parse an SBQ2 descriptor. Throws DescriptorError on anything malformed —
 * there is no partial or best-effort result.
 *
 * @param {Uint8Array} buf
 * @param {object} [opts]
 * @param {number} [opts.nowMs]  clock to check the expiry against
 */
export function decodeDescriptor(buf, { nowMs = Date.now() } = {}) {
    if (!(buf instanceof Uint8Array)) fail('descriptor must be a Uint8Array');
    if (buf.length === 0) fail('descriptor is empty');
    if (buf.length > LIMITS.MAX_PAYLOAD_BYTES) fail('descriptor exceeds the payload limit');

    const r = new Reader(buf);

    // Version first, and a mismatch is an error — never an attempt to parse a
    // different shape. This is what makes downgrade to the old scheme impossible
    // rather than merely unlikely.
    const version = r.u8();
    if (version !== SBQ2_VERSION) fail(`unsupported descriptor version 0x${version.toString(16)}`, 'version');

    const flags = r.u8();
    const type = flags & 0x03;
    if (type !== TYPE.OFFER && type !== TYPE.ANSWER) fail('reserved descriptor type');
    const setup = (flags >> 2) & 0x03;
    if (setup > 2) fail('reserved DTLS setup role');
    const mmsIndex = (flags >> 4) & 0x03;
    const hasCommitment = (flags & 0x40) !== 0;
    const hasExt = (flags & 0x80) !== 0;

    const minutes = r.u24();
    const expiresAtMs = EPOCH_MS + minutes * 60000;
    if (nowMs - LIMITS.CLOCK_SKEW_MS > expiresAtMs) {
        const lateMin = Math.round((nowMs - expiresAtMs) / 60000);
        fail(
            `this code expired ${lateMin} minute(s) ago. If it was just created, ` +
            `this device's clock or time zone is probably wrong — check the date and time settings.`,
            'expired',
        );
    }
    if (expiresAtMs - nowMs > (LIMITS.MAX_LIFETIME_MINUTES * 60000) + LIMITS.CLOCK_SKEW_MS) {
        fail('descriptor lifetime is implausibly long', 'lifetime');
    }

    const bindingTag = type === TYPE.ANSWER ? r.bytes(LIMITS.BINDING_BYTES) : null;
    const fingerprint = r.bytes(LIMITS.FINGERPRINT_BYTES);

    const ufragLen = r.u8();
    if (ufragLen < LIMITS.MIN_UFRAG || ufragLen > LIMITS.MAX_UFRAG) fail('ice-ufrag length out of range');
    const ufrag = r.ascii(ufragLen);
    if (!ICE_CHAR.test(ufrag)) fail('ice-ufrag contains characters outside the ICE alphabet');

    const pwdLen = r.u8();
    if (pwdLen < LIMITS.MIN_PWD || pwdLen > LIMITS.MAX_PWD) fail('ice-pwd length out of range');
    const pwd = r.ascii(pwdLen);
    if (!ICE_CHAR.test(pwd)) fail('ice-pwd contains characters outside the ICE alphabet');

    const count = r.u8();
    if (count > LIMITS.MAX_CANDIDATES) fail('too many candidates');
    const candidates = [];
    for (let i = 0; i < count; i++) {
        const tagByte = r.u8();
        const kind = (tagByte >> 4) & 0x0f;
        const tcptype = tagByte & 0x0f;
        const addrLen = KIND_ADDR_LEN[kind];
        if (addrLen === undefined) fail(`reserved candidate kind ${kind}`);
        if (tcptype >= TCPTYPE.length) fail('reserved TCP candidate type');
        const addr = r.bytes(addrLen);
        const port = r.u16();
        if (port < 1) fail('candidate port must be non-zero');
        candidates.push({ kind, tcptype, addr, port });
    }

    let commitment = null;
    if (hasCommitment) commitment = r.bytes(LIMITS.COMMITMENT_BYTES);

    let extensions = new Map();
    if (hasExt) {
        const extLen = r.u8();
        if (extLen === 0) fail('extension area is flagged but empty');
        extensions = decodeExt(r.bytes(extLen));
    }

    // Trailing bytes are a malformed descriptor, not something to ignore: a
    // decoder that tolerates them lets an attacker smuggle a second reading of
    // the same QR past whatever hashed the canonical form.
    if (r.rest !== 0) fail(`${r.rest} trailing byte(s) after the descriptor`);

    let maxMessageSize;
    if (mmsIndex === MMS_EXPLICIT) {
        if (!extensions.has(EXT.MAX_MESSAGE_SIZE)) fail('flags promise an explicit max-message-size but no extension carries it');
        maxMessageSize = extensions.get(EXT.MAX_MESSAGE_SIZE);
    } else {
        if (extensions.has(EXT.MAX_MESSAGE_SIZE)) fail('extension 0x01 present but the flags do not select it');
        maxMessageSize = MMS_ENUM[mmsIndex];
    }

    return {
        version, type, setup, maxMessageSize, expiresAtMs,
        bindingTag, fingerprint, ufrag, pwd, candidates, commitment, extensions,
    };
}

// ---------------------------------------------------------------------------
// strict SDP serializer
// ---------------------------------------------------------------------------

const hex2 = (b) => b.toString(16).padStart(2, '0');

function renderAddr(kind, addr) {
    switch (kind) {
        case KIND.HOST_MDNS: {
            const h = Array.from(addr, hex2).join('');
            return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}.local`;
        }
        case KIND.HOST_V4: case KIND.SRFLX_V4: case KIND.RELAY_V4:
            return `${addr[0]}.${addr[1]}.${addr[2]}.${addr[3]}`;
        default: {
            const words = [];
            for (let i = 0; i < 16; i += 2) words.push(((addr[i] << 8) | addr[i + 1]).toString(16));
            return words.join(':');
        }
    }
}

/**
 * Rebuild an SDP from a decoded descriptor.
 *
 * Every value written here is either a template constant or a primitive that
 * decodeDescriptor already range-checked and that is re-rendered from bytes
 * (addresses from integers, the mDNS name from 16 raw bytes). The only strings
 * echoed through are ufrag and pwd, and both are constrained to the ICE
 * alphabet, so neither can carry a CRLF and inject an SDP line.
 */
export function serializeSdp(desc, { sessionId = '1' } = {}) {
    const isOffer = desc.type === TYPE.OFFER;
    const lines = [
        'v=0',
        `o=- ${sessionId} 2 IN IP4 127.0.0.1`,
        's=-',
        't=0 0',
        'a=group:BUNDLE 0',
        'a=msid-semantic: WMS',
        'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
        'c=IN IP4 0.0.0.0',
        'a=ice-ufrag:' + desc.ufrag,
        'a=ice-pwd:' + desc.pwd,
        // Deliberately NOT `a=ice-options:trickle`. A descriptor is a complete,
        // one-shot candidate set — there is no signalling channel to trickle
        // over, so advertising trickle promises candidates that can never
        // arrive and leaves the peer's ICE agent waiting for them.
        'a=fingerprint:sha-256 ' + Array.from(desc.fingerprint, (b) => hex2(b).toUpperCase()).join(':'),
        'a=setup:' + SETUP[desc.setup],
        'a=mid:0',
        'a=sctp-port:5000',
        'a=max-message-size:' + desc.maxMessageSize,
    ];

    // Candidate lines go after the ICE credentials; order within the m-section
    // is not significant to any implementation, but keeping them grouped
    // matches what every browser emits.
    const candLines = desc.candidates.map((c, i) => {
        const ctype = KIND_TYPE[c.kind];
        const transport = c.tcptype === 0 ? 'udp' : 'tcp';
        // RFC 8445 §5.1.2.1. localPref descends with list position so the
        // sender's ordering survives, and component is always 1.
        const localPref = Math.max(0, 65535 - i);
        const priority = TYPE_PREF[ctype] * 16777216 + localPref * 256 + 255;
        // Foundation must be equal for candidates sharing type+base+transport
        // and different otherwise (RFC 8445 §5.1.1.3); grouping by kind and
        // transport satisfies both halves of that.
        const foundation = String(c.kind * 4 + c.tcptype + 1);
        let line = `a=candidate:${foundation} 1 ${transport} ${priority} ${renderAddr(c.kind, c.addr)} ${c.port} typ ${ctype}`;
        if (transport === 'tcp') line += ` tcptype ${TCPTYPE[c.tcptype]}`;
        return line;
    });
    // `a=end-of-candidates` states explicitly that the set is complete
    // (RFC 8838 §14), so the peer stops waiting for more and can start failing
    // pairs promptly instead of sitting in checking until a timeout.
    candLines.push('a=end-of-candidates');
    const at = lines.indexOf('c=IN IP4 0.0.0.0') + 1;
    lines.splice(at, 0, ...candLines);

    return { type: isOffer ? 'offer' : 'answer', sdp: lines.join('\r\n') + '\r\n' };
}

// ---------------------------------------------------------------------------
// binding + transcript
// ---------------------------------------------------------------------------

const enc = new TextEncoder();

function concat(...parts) {
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
}

/**
 * 8-byte tag an answer carries so the offerer can confirm it answers THIS offer.
 * This is the answer's replay defence: the offerer keeps the tag of the offer it
 * is currently showing and rejects any answer that does not match it, which also
 * makes each offer exactly one-shot.
 *
 * The offer needs no nonce of its own. It already carries ice-pwd, which RFC
 * 8839 §5.4 requires to contain at least 128 bits of randomness and which every
 * browser regenerates per peer connection and per ICE restart; hashing the whole
 * descriptor therefore hashes that entropy. See doc/descriptor-sbq2.md.
 *
 * LIMITATION, on purpose: 64 bits is not a standalone integrity primitive. It is
 * a duplicate-detection tag whose security comes from the SAS transcript, which
 * covers both descriptors in full. Do not build anything on this tag alone.
 */
export async function bindingTag(digest, offerBytes) {
    const h = await digest(concat(enc.encode('sbq2/bind\0'), offerBytes));
    return h.slice(0, LIMITS.BINDING_BYTES);
}

/** 16-byte commitment to the in-band key blob. */
export async function commitBlob(digest, blobBytes) {
    const h = await digest(concat(enc.encode('sbq2/blob\0'), blobBytes));
    return h.slice(0, LIMITS.COMMITMENT_BYTES);
}

/**
 * The SAS transcript.
 *
 * It covers both descriptors *verbatim* — every byte that travelled out of
 * band, including the version byte, the flags and the whole extension area —
 * and both in-band blobs. So there is nothing an attacker can change anywhere in
 * the handshake, in either direction, that does not change the digits the two
 * users read to each other. Lengths are prefixed so no field boundary can be
 * shifted.
 */
export function sasTranscript(offerBytes, answerBytes, offerBlob, answerBlob) {
    const lp = (b) => {
        const n = new Uint8Array(4);
        new DataView(n.buffer).setUint32(0, b.length);
        return concat(n, b);
    };
    return concat(
        enc.encode('sbq2/sas/v1\0'),
        lp(offerBytes), lp(answerBytes), lp(offerBlob), lp(answerBlob),
    );
}

// ---------------------------------------------------------------------------
// transport encodings
// ---------------------------------------------------------------------------

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export function toBase64Url(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i += 3) {
        const a = bytes[i], b = bytes[i + 1], c = bytes[i + 2];
        out += B64URL[a >> 2];
        out += B64URL[((a & 3) << 4) | ((b ?? 0) >> 4)];
        if (b === undefined) break;
        out += B64URL[((b & 15) << 2) | ((c ?? 0) >> 6)];
        if (c === undefined) break;
        out += B64URL[c & 63];
    }
    return out;
}

export function fromBase64Url(text) {
    if (typeof text !== 'string') fail('payload must be a string');
    // Messengers wrap long lines; strip whitespace before validating, then
    // require the alphabet exactly.
    const s = text.replace(/\s+/g, '');
    if (s.length > Math.ceil(LIMITS.MAX_PAYLOAD_BYTES * 4 / 3) + 4) fail('payload is too long');
    if (!/^[A-Za-z0-9_-]*$/.test(s)) fail('payload contains characters outside base64url');
    if (s.length % 4 === 1) fail('payload has an impossible length');
    const out = new Uint8Array(Math.floor(s.length * 3 / 4));
    let o = 0, acc = 0, bits = 0;
    for (const ch of s) {
        acc = (acc << 6) | B64URL.indexOf(ch);
        bits += 6;
        if (bits >= 8) { bits -= 8; out[o++] = (acc >> bits) & 0xff; }
    }
    if (acc & ((1 << bits) - 1)) fail('payload has non-zero padding bits');
    return out.subarray(0, o);
}

export const TEXT_PREFIX = 'SB2:';

export function encodeText(bytes) { return TEXT_PREFIX + toBase64Url(bytes); }

export function decodeText(text) {
    if (typeof text !== 'string') fail('payload must be a string');
    const t = text.trim();
    if (!t.startsWith(TEXT_PREFIX)) fail('not an SB2 descriptor');
    return fromBase64Url(t.slice(TEXT_PREFIX.length));
}

export { DescriptorError, KIND, KIND_FAMILY, KIND_TYPE };
