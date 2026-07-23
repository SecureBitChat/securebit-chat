// Adaptive WebRTC call parameters — single source of truth.
//
// Every value here is a tuning constant for the voice/video call stack, with a
// note on where it comes from. Kept as plain data (no behaviour) so it can be
// imported by both the browser bundle and the Node unit tests.
//
// Targets (from the task brief): usable voice at up to 15–20% loss, RTT up to
// 400 ms, fluctuating bandwidth; voice must not break as bitrate drops; video
// degrades gracefully by layer.

// WebKit (desktop Safari + ALL iOS browsers) kills a live capture MediaStreamTrack
// with "capture failure" when we manipulate the sender via setParameters /
// setCodecPreferences (RED, priorities, SVC bitrate). So the adaptive codec/bitrate
// tuning is applied on Chromium only; WebKit runs plain WebRTC (Opus + the
// browser's own congestion control), which is reliable. The read-only quality
// indicator still works everywhere. Matches Chrome/Chromium/Edge; excludes Safari
// and iOS browsers (all WebKit — iOS Chrome is "CriOS", not "Chrome").
export const IS_WEBKIT = (typeof navigator !== 'undefined')
    && /AppleWebKit/.test(navigator.userAgent)
    && !/Chrome|Chromium|Edg\//.test(navigator.userAgent);

// ── AUDIO ──────────────────────────────────────────────────────────────────
// Opus is mandatory-to-implement in WebRTC (RFC 7874). FEC + DTX + a low target
// bitrate keep speech intelligible under loss.
export const AUDIO_CONFIG = {
    // Opus fmtp params applied via SDP munging.
    //  - minptime=10          smaller packets → lower latency (Opus RFC 7587 §7).
    //  - useinbandfec=1       in-band Forward Error Correction — reconstructs lost
    //                         packets from the next one (RFC 6716 §2.1.7). Key for loss.
    //  - usedtx=1             Discontinuous Transmission — stop sending in silence,
    //                         frees the pipe for video/FEC (RFC 7587 §3.1.3).
    //  - stereo=0             mono: voice doesn't need stereo, halves the bitrate.
    //  - maxaveragebitrate    32 kbps — brief says 32000; comfortable wideband speech.
    //  - cbr=0                variable bitrate: lets the encoder spend bits only when
    //                         needed, better quality per bit than CBR for speech.
    opusFmtp: {
        minptime: 10,
        useinbandfec: 1,
        usedtx: 1,
        stereo: 0,
        maxaveragebitrate: 32000,
        cbr: 0,
    },
    // RED (RFC 2198) wraps Opus payloads with a redundant copy of the previous
    // frame — recovers isolated losses without waiting for retransmission. Only
    // enabled when the browser advertises audio/red (Chromium yes; Safari/FF vary).
    preferRed: true,
    // RTCRtpSender.setParameters — encoding-level knobs. Audio is prioritised over
    // video on the shared transport so speech survives congestion.
    sender: {
        maxBitrate: 40000,        // bps — brief: 40000. Head-room over 32 kbps for RED.
        priority: 'high',         // RTCPriorityType — bandwidth arbitration within the PC.
        networkPriority: 'high',  // DSCP marking hint — audio ahead of video on the wire.
    },
};

// ── VIDEO ──────────────────────────────────────────────────────────────────
// Preference order VP9 → AV1 → H.264 → VP8. VP9/AV1 give temporal/spatial
// scalability (SVC) so a single stream degrades by layer; H.264/VP8 fall back to
// plain simulcast. Values from the brief.
export const VIDEO_CONFIG = {
    codecPreferenceOrder: ['VP9', 'AV1', 'H264', 'VP8'],
    // Preferred single-encoding SVC mode for VP9 (3 spatial × 3 temporal, key-frame
    // aligned). If the browser rejects it we fall back to the simulcast ladder below.
    vp9: {
        preferredScalabilityMode: 'L3T3_KEY',
        simulcast: [
            { rid: 'low',  scaleResolutionDownBy: 4, maxBitrate: 150000,  scalabilityMode: 'L1T3' },
            { rid: 'mid',  scaleResolutionDownBy: 2, maxBitrate: 500000,  scalabilityMode: 'L1T3' },
            { rid: 'high', scaleResolutionDownBy: 1, maxBitrate: 1500000, scalabilityMode: 'L1T3' },
        ],
        degradationPreference: 'balanced',
    },
    av1: {
        scalabilityMode: 'L1T3',
        maxBitrate: 1200000,
        degradationPreference: 'maintain-framerate',
    },
    // H.264 / VP8: ordinary simulcast, no SVC.
    simulcast: [
        { rid: 'low',  scaleResolutionDownBy: 4, maxBitrate: 150000 },
        { rid: 'mid',  scaleResolutionDownBy: 2, maxBitrate: 500000 },
        { rid: 'high', scaleResolutionDownBy: 1, maxBitrate: 1500000 },
    ],
    networkPriority: 'medium',    // below audio's 'high'.
};

// ── TRANSPORT (RTCP feedback / header extensions to guarantee in SDP) ────────
// transport-wide-cc drives the bandwidth estimator; nack/pli/fir/remb handle
// loss recovery and keyframe requests. Video gets the full set, audio a subset.
export const TRANSPORT_CONFIG = {
    twccUri: 'http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01',
    video: {
        rtcpFb: ['transport-cc', 'nack', 'nack pli', 'ccm fir', 'goog-remb'],
        twcc: true,
    },
    audio: {
        rtcpFb: ['transport-cc', 'nack'],
        twcc: true,
    },
};

// ── ADAPTATION (getStats loop) ──────────────────────────────────────────────
// Reactive bitrate control. Thresholds from the brief. Applied via setParameters
// only — never renegotiation, never track restarts.
export const ADAPTATION_CONFIG = {
    intervalMs: 1000,
    loss: {
        highPct: 0.10,          // >10% loss → back off video.
        recoverPct: 0.03,       // <3% loss (sustained) → ramp up.
        audioProtectPct: 0.25,  // don't touch audio until loss exceeds 25%.
    },
    rtt: {
        highMs: 300,            // >300 ms → back off.
        recoverMs: 150,         // <150 ms (sustained) → ramp up.
    },
    stepDownPct: 0.20,          // shrink video maxBitrate by 20% per bad tick.
    stepUpPct: 0.10,            // grow by 10% per good window.
    minVideoBitrate: 100000,    // floor for the low layer (bps).
    recoverStableTicks: 5,      // consecutive good ticks before ramping up.
    cpuScaleStep: 1.5,          // qualityLimitationReason 'cpu' → bump scaleResolutionDownBy ×1.5.
};
