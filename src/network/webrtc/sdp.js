// Pure SDP munging utilities.
//
// SDP munging is inherently fragile across browsers, so every function here is:
//   - idempotent (running twice yields the same SDP — no duplicate lines),
//   - line-ending preserving (SDP uses CRLF; we detect and keep it),
//   - defensive (unknown/missing sections are left untouched, never thrown on).
//
// No DOM/WebRTC APIs are used, so this module is unit-testable in plain Node.

/** Detect the line terminator used by an SDP blob (CRLF per RFC 4566, but be safe). */
function detectEol(sdp) {
    return sdp.indexOf('\r\n') !== -1 ? '\r\n' : '\n';
}

/**
 * Split an SDP into its session part and per-media sections.
 * @returns {{ eol:string, session:string[], media:Array<{lines:string[]}> }}
 */
export function splitSdp(sdp) {
    const eol = detectEol(sdp);
    const lines = sdp.split(/\r\n|\n/);
    const session = [];
    const media = [];
    let current = null;
    for (const line of lines) {
        if (line.startsWith('m=')) {
            current = { lines: [line] };
            media.push(current);
        } else if (current) {
            current.lines.push(line);
        } else {
            session.push(line);
        }
    }
    return { eol, session, media };
}

/** Reassemble a split SDP, preserving the original line ending. */
export function joinSdp(parsed) {
    const all = [...parsed.session];
    for (const m of parsed.media) all.push(...m.lines);
    return all.join(parsed.eol);
}

/** The media kind ('audio' | 'video' | 'application') of a section. */
export function sectionKind(section) {
    const m = section.lines[0].match(/^m=(\w+)/);
    return m ? m[1] : null;
}

/**
 * All payload types in a section whose rtpmap encoding name matches `codecName`
 * (case-insensitive), e.g. 'opus', 'VP9', 'red'.
 * @returns {string[]}
 */
export function findPayloadTypes(section, codecName) {
    const re = new RegExp('^a=rtpmap:(\\d+)\\s+' + codecName + '\\/', 'i');
    const pts = [];
    for (const line of section.lines) {
        const m = line.match(re);
        if (m) pts.push(m[1]);
    }
    return pts;
}

/** Parse an `a=fmtp:<pt> k=v;k2=v2;flag` value string into an ordered map. */
function parseFmtpParams(value) {
    const map = new Map();
    for (const part of value.split(';')) {
        const p = part.trim();
        if (!p) continue;
        const eq = p.indexOf('=');
        if (eq === -1) map.set(p, undefined);           // bare flag
        else map.set(p.slice(0, eq).trim(), p.slice(eq + 1).trim());
    }
    return map;
}

/** Serialise an fmtp param map back to `k=v;k2=v2` form. */
function serializeFmtpParams(map) {
    const parts = [];
    for (const [k, v] of map) parts.push(v === undefined ? k : `${k}=${v}`);
    return parts.join(';');
}

/**
 * Insert or update the `a=fmtp:<pt>` line for a payload type, merging `params`
 * over any existing values. Idempotent: existing keys are overwritten, not
 * duplicated; a missing fmtp line is created right after the rtpmap line.
 */
export function upsertFmtp(section, pt, params) {
    const fmtpIdx = section.lines.findIndex(l => l.startsWith(`a=fmtp:${pt} `) || l === `a=fmtp:${pt}`);
    if (fmtpIdx !== -1) {
        const existing = section.lines[fmtpIdx].slice(`a=fmtp:${pt} `.length);
        const map = parseFmtpParams(existing);
        for (const [k, v] of Object.entries(params)) map.set(k, String(v));
        section.lines[fmtpIdx] = `a=fmtp:${pt} ${serializeFmtpParams(map)}`;
        return;
    }
    // No fmtp yet — build one and place it after the matching rtpmap line.
    const map = new Map();
    for (const [k, v] of Object.entries(params)) map.set(k, String(v));
    const newLine = `a=fmtp:${pt} ${serializeFmtpParams(map)}`;
    const rtpmapIdx = section.lines.findIndex(l => l.startsWith(`a=rtpmap:${pt} `));
    if (rtpmapIdx !== -1) section.lines.splice(rtpmapIdx + 1, 0, newLine);
    else section.lines.push(newLine);
}

/**
 * Apply Opus fmtp parameters (FEC / DTX / bitrate / etc.) to every Opus payload
 * type in the audio m-line. Returns the munged SDP; input SDP with no Opus
 * audio section is returned unchanged.
 */
export function applyOpusSettings(sdp, opusFmtp) {
    if (!sdp || typeof sdp !== 'string') return sdp;
    const parsed = splitSdp(sdp);
    let changed = false;
    for (const section of parsed.media) {
        if (sectionKind(section) !== 'audio') continue;
        for (const pt of findPayloadTypes(section, 'opus')) {
            upsertFmtp(section, pt, opusFmtp);
            changed = true;
        }
    }
    return changed ? joinSdp(parsed) : sdp;
}

// ── Transport feedback ───────────────────────────────────────────────────────

// Auxiliary payloads that are not primary media codecs (no per-codec rtcp-fb).
const AUX_CODEC = /^(rtx|red|ulpfec|flexfec-03|telephone-event|CN)$/i;

/** Primary-codec payload types in a section (excludes rtx/red/fec/DTMF/CN). */
export function getCodecPayloadTypes(section) {
    const pts = [];
    for (const line of section.lines) {
        const m = line.match(/^a=rtpmap:(\d+)\s+([^/]+)\//);
        if (m && !AUX_CODEC.test(m[2])) pts.push(m[1]);
    }
    return pts;
}

/**
 * Ensure each `a=rtcp-fb:<pt> <fb>` line exists for every primary codec in the
 * section. Idempotent — never duplicates an existing line.
 */
export function ensureRtcpFb(section, feedbacks) {
    for (const pt of getCodecPayloadTypes(section)) {
        for (const fb of feedbacks) {
            const line = `a=rtcp-fb:${pt} ${fb}`;
            if (section.lines.includes(line)) continue;
            // Insert after the last existing attribute line for this pt.
            let insertAt = -1;
            for (let i = 0; i < section.lines.length; i++) {
                const l = section.lines[i];
                if (l.startsWith(`a=rtpmap:${pt} `) || l.startsWith(`a=fmtp:${pt} `) || l.startsWith(`a=rtcp-fb:${pt} `)) insertAt = i;
            }
            if (insertAt === -1) insertAt = section.lines.length - 1;
            section.lines.splice(insertAt + 1, 0, line);
        }
    }
}

/**
 * Ensure an RTP header extension (`a=extmap:<id> <uri>`) is present, allocating
 * the next free id. Idempotent — a section already carrying the uri is untouched.
 */
export function ensureExtmap(section, uri) {
    if (section.lines.some(l => l.startsWith('a=extmap:') && l.includes(uri))) return;
    let maxId = 0, insertAt = -1;
    for (let i = 0; i < section.lines.length; i++) {
        const m = section.lines[i].match(/^a=extmap:(\d+)/);
        if (m) { maxId = Math.max(maxId, Number(m[1])); insertAt = i; }
    }
    if (insertAt === -1) {
        // No extmap yet — place after mid/rtpmap area, else end.
        insertAt = section.lines.findIndex(l => l.startsWith('a=mid:'));
        if (insertAt === -1) insertAt = section.lines.length - 1;
    }
    section.lines.splice(insertAt + 1, 0, `a=extmap:${maxId + 1} ${uri}`);
}

/**
 * Ensure transport-wide-cc / nack / pli / fir / remb feedback and the TWCC header
 * extension are present on the audio/video m-lines per `cfg` (TRANSPORT_CONFIG).
 * Idempotent and non-destructive; SDP with no matching sections is returned as-is.
 */
export function applyTransport(sdp, cfg) {
    if (!sdp || typeof sdp !== 'string' || !cfg) return sdp;
    const parsed = splitSdp(sdp);
    let changed = false;
    for (const section of parsed.media) {
        const kind = sectionKind(section);
        const c = kind === 'video' ? cfg.video : kind === 'audio' ? cfg.audio : null;
        if (!c) continue;
        if (Array.isArray(c.rtcpFb)) { ensureRtcpFb(section, c.rtcpFb); changed = true; }
        if (c.twcc && cfg.twccUri) { ensureExtmap(section, cfg.twccUri); changed = true; }
    }
    return changed ? joinSdp(parsed) : sdp;
}
