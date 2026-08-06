# Voice and video calls

Calls run over the same peer connection as the chat. Media is added to the
existing connection and renegotiated onto it, and the call SDP is exchanged over
the encrypted data channel rather than through any signalling service. Media
therefore inherits the session's verification: the DTLS-SRTP fingerprints
negotiated for the media were themselves carried over an authenticated channel.

All tunable values live in `src/network/webrtc/config.js`. This document explains
where they come from, because the numbers are otherwise indistinguishable from
arbitrary choices.

## Where the settings attach

A single `RTCRtpSender` cannot express codec ordering or fmtp parameters, so
configuring a sender is spread across three WebRTC surfaces, each at the point in
the lifecycle where it works:

| Concern | Surface | When | Implementation |
| --- | --- | --- | --- |
| Codec ordering (RED before Opus) | `transceiver.setCodecPreferences` | before creating the offer or answer | `applyAudioCodecPreferences` in `audio.js` |
| Opus FEC, DTX, bitrate | SDP `a=fmtp` rewriting | after create, before `setLocalDescription` | `applyOpusSettings` in `sdp.js` |
| Priority and maximum bitrate | `sender.setParameters` | after `setLocalDescription` | `configureAudioSender` in `audio.js` |

Both peers apply the same rewriting, so the negotiated session carries the
parameters regardless of who called.

## Audio

Speech has to stay intelligible on a bad link, and that goal drives every value
below.

### Opus parameters

| Parameter | Value | Reason |
| --- | --- | --- |
| `minptime` | 10 | Smaller packetisation interval, lower latency (RFC 7587, section 7) |
| `useinbandfec` | 1 | In-band forward error correction reconstructs a lost packet from the next one. This is the main lever for staying intelligible at 15 to 20 percent loss (RFC 6716, section 2.1.7) |
| `usedtx` | 1 | Discontinuous transmission stops sending during silence, leaving the transport free for video and FEC (RFC 7587, section 3.1.3) |
| `stereo` | 0 | Mono halves the bitrate with no loss for speech |
| `maxaveragebitrate` | 32000 | Comfortable wideband speech |
| `cbr` | 0 | Variable bitrate spends bits only when needed |

### Redundancy

RED (RFC 2198) carries the previous frame's payload alongside each packet, so
isolated losses recover without retransmission. It is enabled only when the
browser advertises `audio/red` in `RTCRtpSender.getCapabilities('audio')`, which
Chromium does and others vary on; when absent it is skipped silently. RED is
ordered before Opus in codec preferences.

### Sender parameters

| Parameter | Value | Reason |
| --- | --- | --- |
| `maxBitrate` | 40000 bps | Headroom above the 32 kbps Opus target for RED redundancy |
| `priority` | `high` | Audio wins bandwidth arbitration against video within the connection |
| `networkPriority` | `high` | DSCP hint so audio is prioritised on the wire |

Audio is never throttled by the adaptation controller. Under sustained loss the
video degrades and speech continues.

## Video

Codec preference order is VP9, AV1, H.264, VP8, applied through
`setCodecPreferences`. Retransmission and FEC codecs are kept after the media
codecs so they still function. VP9 and AV1 provide scalable coding; H.264 and VP8
do not.

### Scalable coding rather than simulcast

This is a one-to-one connection with a single receiver, so one encoding with SVC
is the right tool: a single stream that degrades by spatial or temporal layer. It
is applied through `sender.setParameters` and needs no `addTransceiver` or rid
configuration, which keeps it away from the media path that actually works.

| Codec | scalabilityMode | maxBitrate | degradationPreference |
| --- | --- | --- | --- |
| VP9 | `L3T3_KEY` (3 spatial, 3 temporal, key-aligned) | 1.5 Mbps | `balanced` |
| AV1 | `L1T3` | 1.2 Mbps | `maintain-framerate` |
| H.264, VP8 | none | 1.5 Mbps | `balanced` |

`networkPriority` is `medium`, below audio. If a browser rejects the scalability
mode, which Firefox and Safari do in places, `configureVideoSender` retries with
a plain encoding.

### Why media is attached with addTrack

An explicit `addTransceiver({ sendEncodings })` path was built and then removed,
because it broke media on real devices in two ways. On the answering side,
reusing the transceiver created by `setRemoteDescription` rejected the SVC
parameters outright. On repeat and role-reversed calls, the reused transceiver
directions desynchronised: the call connected and `ontrack` fired, but no media
flowed.

What ships instead attaches media with `addTrack`, reused across calls through
`replaceTrack`, and lets the browser manage transceiver direction. This is what
keeps audio and video flowing across reversed and repeated calls.

Multi-rid simulcast primitives (`buildVideoSendEncodings`) are kept and tested for
a future group-call path, but are not wired into the one-to-one flow. They need
`addTransceiver({ sendEncodings })`, which requires the problems above to be
solved first, ideally with a two-connection browser test rig that is not set up.
The adaptation controller is already simulcast-aware for when that lands.

## Transport feedback

The call m-lines need RTCP feedback and header extensions present. Most browsers
emit them already, so this is an idempotent safety net:

| Media | RTCP feedback | Header extension |
| --- | --- | --- |
| Video | `transport-cc`, `nack`, `nack pli`, `ccm fir`, `goog-remb` | transport-wide congestion control |
| Audio | `transport-cc`, `nack` | transport-wide congestion control |

These are added only when missing, never duplicated, and applied only to primary
codecs. Transport-wide congestion control is what feeds the bandwidth estimator
that adaptation reads.

Rewritten local SDP is applied with progressive fallback: full rewrite, then Opus
only, then raw. A browser that rejects an injected line cannot break the call.

## Adaptation

`NetworkAdaptationController` samples `pc.getStats()` every second and reacts:

| Condition | Action |
| --- | --- |
| Loss above 10 percent, or round trip above 300 ms | Reduce video `maxBitrate` by 20 percent, floor 100 kbps |
| Loss below 3 percent and round trip below 150 ms, sustained 5 samples | Raise video `maxBitrate` by 10 percent, up to the ceiling |
| `qualityLimitationReason` is `cpu` | Scale resolution down by 1.5, bitrate unchanged |

Every change goes through `sender.setParameters`. There is no renegotiation and
no track restart, so adaptation is invisible to the call. Audio is never touched.

The decision function and the stats parsing are pure and unit-tested against
recorded `getStats` output.

### Quality indicator

The same sample produces a coarse label shown in the call interface:

| Label | Condition |
| --- | --- |
| Excellent | Loss below 3 percent and round trip below 150 ms |
| Good | Loss below 7 percent and round trip below 250 ms |
| Fair | Loss below 15 percent and round trip below 400 ms |
| Weak | Anything else |

It appears in the voice overlay, the video top bar, and as compact bars in the
minimized widget, and stays hidden until the first sample has data.

## Verifying a change

Unit tests cover SDP rewriting, video codec selection and the adaptation
decision:

```bash
npm test
```

For anything touching media in practice, open `chrome://webrtc-internals` during
a call and check that:

- outbound audio shows Opus with the fmtp parameters above, appearing as `red`
  and `opus` on Chromium
- throttling the link steps outbound video `targetBitrate` down within a second
  or two and recovers when the link clears
- audio bitrate holds steady while video adapts
- the in-call indicator moves through Fair and Weak as the link degrades
