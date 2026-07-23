// Audio sender / transceiver configuration for calls.
//
// Splits the brief's "configureAudioSender" into the three WebRTC surfaces it
// actually touches, because a single RTCRtpSender cannot do all of them:
//   - setCodecPreferences  → on the TRANSCEIVER, before createOffer (RED ordering)
//   - fmtp munging          → on the SDP string (see sdp.js applyOpusSettings)
//   - setParameters         → on the SENDER, any time after it exists
//
// All functions feature-detect and swallow unsupported-API errors so Safari /
// Firefox (which vary on RED and setCodecPreferences) degrade gracefully.

import { AUDIO_CONFIG, IS_WEBKIT } from './config.js';

/**
 * Order codecs so RED (RFC 2198) is preferred first and Opus second, keeping any
 * other codecs (e.g. telephone-event) after them. No-op when RED isn't offered
 * or setCodecPreferences is unsupported.
 * @param {RTCRtpTransceiver} transceiver
 */
export function applyAudioCodecPreferences(transceiver) {
    try {
        if (IS_WEBKIT) return false; // codec preferences skipped on WebKit (capture-safe)
        if (!transceiver || typeof transceiver.setCodecPreferences !== 'function') return false;
        if (!AUDIO_CONFIG.preferRed) return false;
        const caps = (typeof RTCRtpSender !== 'undefined' && RTCRtpSender.getCapabilities)
            ? RTCRtpSender.getCapabilities('audio')
            : null;
        if (!caps || !Array.isArray(caps.codecs)) return false;

        const isRed = c => /red$/i.test(c.mimeType);
        const isOpus = c => /opus$/i.test(c.mimeType);
        if (!caps.codecs.some(isRed)) return false; // RED not available

        const red = caps.codecs.filter(isRed);
        const opus = caps.codecs.filter(isOpus);
        const rest = caps.codecs.filter(c => !isRed(c) && !isOpus(c));
        transceiver.setCodecPreferences([...red, ...opus, ...rest]);
        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Apply sender-level parameters: high bandwidth priority, high network priority
 * (audio ahead of video on the wire) and a maxBitrate cap. Uses read-modify-write
 * on getParameters()/setParameters() so we never clobber existing encodings.
 * @param {RTCRtpSender} sender
 * @param {object} [options] overrides for AUDIO_CONFIG.sender
 */
export async function configureAudioSender(sender, options = {}) {
    try {
        if (IS_WEBKIT) return false; // sender setParameters skipped on WebKit (capture-safe)
        if (!sender || typeof sender.getParameters !== 'function') return false;
        const cfg = { ...AUDIO_CONFIG.sender, ...options };
        const params = sender.getParameters();
        if (!params.encodings || params.encodings.length === 0) params.encodings = [{}];
        for (const enc of params.encodings) {
            enc.maxBitrate = cfg.maxBitrate;
            enc.priority = cfg.priority;
            enc.networkPriority = cfg.networkPriority;
        }
        await sender.setParameters(params);
        return true;
    } catch (e) {
        return false;
    }
}
