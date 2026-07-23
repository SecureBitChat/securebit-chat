// Video sender / transceiver configuration for calls.
//
// Strategy for 1:1 P2P (single remote peer): use a SINGLE encoding with SVC
// (VP9 L3T3_KEY / AV1 L1T3) applied through sender.setParameters — this needs no
// addTransceiver/rids and therefore doesn't disturb the working addTrack flow.
// Layered SVC already gives graceful per-layer degradation for one receiver;
// multi-rid simulcast (mainly useful for SFUs) is a documented fallback, not
// wired here. All calls feature-detect and fall back gracefully:
//   VP9 → AV1 → H.264 → VP8, and SVC → plain encoding if a mode is rejected.

import { VIDEO_CONFIG, IS_WEBKIT } from './config.js';

const CODEC_RANK = { VP9: 0, AV1: 1, H264: 2, VP8: 3 };

/** 'video/VP9' → 'VP9', 'video/H264' → 'H264', 'video/rtx' → 'RTX', … */
export function codecShortName(mimeType) {
    const sub = String(mimeType || '').split('/')[1] || '';
    return sub.toUpperCase();
}

/**
 * Reorder a getCapabilities().codecs array so our preferred video codecs come
 * first (VP9, AV1, H264, VP8), with everything else (rtx / red / *fec) kept in
 * its original relative order afterwards — dropping rtx/fec would break
 * retransmission, so they must stay in the list.
 */
export function sortVideoCodecs(codecs) {
    const rank = c => {
        const n = codecShortName(c.mimeType);
        return Object.prototype.hasOwnProperty.call(CODEC_RANK, n) ? CODEC_RANK[n] : 99;
    };
    return codecs
        .map((c, i) => ({ c, i }))
        .sort((a, b) => (rank(a.c) - rank(b.c)) || (a.i - b.i))   // stable
        .map(x => x.c);
}

/** The top available video codec by our preference order, or null. */
export function pickPreferredVideoCodec(caps) {
    if (!caps || !Array.isArray(caps.codecs)) return null;
    const present = new Set(caps.codecs.map(c => codecShortName(c.mimeType)));
    for (const name of VIDEO_CONFIG.codecPreferenceOrder) if (present.has(name)) return name;
    return null;
}

function videoCaps() {
    return (typeof RTCRtpSender !== 'undefined' && RTCRtpSender.getCapabilities)
        ? RTCRtpSender.getCapabilities('video') : null;
}

/**
 * Order codec preferences on the video transceiver (VP9 first …). Must be called
 * before createOffer/createAnswer. Returns the chosen top codec name (or false).
 * @param {RTCRtpTransceiver} transceiver
 */
export function applyVideoCodecPreferences(transceiver) {
    try {
        if (IS_WEBKIT) return false; // codec preferences skipped on WebKit (capture-safe)
        if (!transceiver || typeof transceiver.setCodecPreferences !== 'function') return false;
        const caps = videoCaps();
        if (!caps || !Array.isArray(caps.codecs)) return false;
        transceiver.setCodecPreferences(sortVideoCodecs(caps.codecs));
        return pickPreferredVideoCodec(caps);
    } catch (e) {
        return false;
    }
}

/**
 * Whether the browser confirms the SVC scalabilityMode we want for a codec.
 * Uses the `scalabilityModes` capability field (Chromium M113+, recent Firefox).
 * When it's absent we return false so we fall back to simulcast — safer than
 * assuming SVC on a browser that can't do it (e.g. older Firefox/Safari).
 */
export function codecSupportsSvc(caps, name) {
    const codec = caps?.codecs?.find(c => codecShortName(c.mimeType) === name);
    const modes = codec && codec.scalabilityModes;
    if (!Array.isArray(modes)) return false;
    const want = name === 'AV1' ? VIDEO_CONFIG.av1.scalabilityMode : VIDEO_CONFIG.vp9.preferredScalabilityMode;
    return modes.includes(want);
}

/**
 * Build the `sendEncodings` for addTransceiver('video', …) per the brief:
 *   - VP9/AV1 with confirmed SVC → a SINGLE encoding with scalabilityMode
 *     (one stream that degrades by layer — ideal for 1:1),
 *   - VP9 without confirmed SVC → the 3-rid L1T3 simulcast ladder,
 *   - H.264/VP8 (or AV1 w/o SVC) → plain 3-rid simulcast.
 * @param {RTCRtpCapabilities} [caps] pass to override detection (tests)
 */
export function buildVideoSendEncodings(caps = videoCaps()) {
    const preferred = pickPreferredVideoCodec(caps) || 'VP8';
    if ((preferred === 'VP9' || preferred === 'AV1') && codecSupportsSvc(caps, preferred)) {
        const plan = encodingPlanFor(preferred);
        return [{ scalabilityMode: plan.scalabilityMode, maxBitrate: plan.maxBitrate }];
    }
    if (preferred === 'VP9') {
        return VIDEO_CONFIG.vp9.simulcast.map(e => ({ ...e }));
    }
    return VIDEO_CONFIG.simulcast.map(e => ({ ...e }));
}

/** SVC mode + bitrate + degradation for a given codec (single-encoding P2P). */
export function encodingPlanFor(codecName) {
    if (codecName === 'VP9') {
        return { scalabilityMode: VIDEO_CONFIG.vp9.preferredScalabilityMode, maxBitrate: 1500000, degradationPreference: VIDEO_CONFIG.vp9.degradationPreference };
    }
    if (codecName === 'AV1') {
        return { scalabilityMode: VIDEO_CONFIG.av1.scalabilityMode, maxBitrate: VIDEO_CONFIG.av1.maxBitrate, degradationPreference: VIDEO_CONFIG.av1.degradationPreference };
    }
    // H.264 / VP8 / unknown: plain single encoding, no SVC.
    return { scalabilityMode: undefined, maxBitrate: 1500000, degradationPreference: 'balanced' };
}

/**
 * Apply the single-encoding SVC plan + networkPriority + degradationPreference to
 * a video sender via setParameters. Falls back to a plain encoding if the browser
 * rejects the requested scalabilityMode (Firefox/Safari SVC gaps).
 * @param {RTCRtpSender} sender
 */
export async function configureVideoSender(sender, options = {}) {
    try {
        if (IS_WEBKIT) return false; // sender setParameters skipped on WebKit (capture-safe)
        if (!sender || typeof sender.getParameters !== 'function') return false;
        const preferred = pickPreferredVideoCodec(videoCaps()) || 'VP8';
        const plan = { ...encodingPlanFor(preferred), ...options };
        const params = sender.getParameters();
        if (!params.encodings || params.encodings.length === 0) params.encodings = [{}];
        const simulcast = params.encodings.length > 1;

        if (simulcast) {
            // Simulcast: keep the per-rid bitrate ladder set at addTransceiver time;
            // only stamp networkPriority so video stays below audio on the wire.
            for (const enc of params.encodings) enc.networkPriority = VIDEO_CONFIG.networkPriority;
        } else {
            const enc = params.encodings[0];
            enc.maxBitrate = plan.maxBitrate;
            enc.networkPriority = VIDEO_CONFIG.networkPriority;
            if (plan.scalabilityMode) enc.scalabilityMode = plan.scalabilityMode;
        }
        if (plan.degradationPreference) params.degradationPreference = plan.degradationPreference;

        try {
            await sender.setParameters(params);
            return true;
        } catch (e) {
            // Most likely an unsupported scalabilityMode → retry without it.
            if (!simulcast && plan.scalabilityMode) {
                delete params.encodings[0].scalabilityMode;
                try {
                    await sender.setParameters(params);
                    return true;
                } catch (e2) {
                    return false;
                }
            }
            return false;
        }
    } catch (e) {
        return false;
    }
}
