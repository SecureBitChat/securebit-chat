# WebRTC call configuration & rationale

All tunables live in `src/network/webrtc/config.js`. This doc explains the values
and where they come from. Built incrementally per step; **all steps shipped** —
adaptive audio, SVC video, transport feedback, and runtime bitrate adaptation are
live in the 1:1 call flow.

## How the pieces attach (why not one `configureAudioSender`)

A single `RTCRtpSender` cannot carry codec ordering or fmtp, so the brief's
`configureAudioSender` is split across the three WebRTC surfaces at their correct
lifecycle points (see `EnhancedSecureWebRTCManager` call methods):

| Concern | API surface | When | Code |
|---|---|---|---|
| RED-first / Opus-second ordering | `transceiver.setCodecPreferences` | before `createOffer`/`createAnswer` | `applyAudioCodecPreferences` (audio.js) via `_applyAudioCodecPrefs` |
| Opus FEC/DTX/bitrate | SDP `a=fmtp` munging | after create, before `setLocalDescription` | `applyOpusSettings` (sdp.js) via `_mungeCallSdp` |
| priority / networkPriority / maxBitrate | `sender.setParameters` | after `setLocalDescription` | `configureAudioSender` (audio.js) via `_applyCallSenderParams` |

Both peers run the same munging, so the negotiated session carries the params.

## Step 2 — Audio (`AUDIO_CONFIG`)

### Opus fmtp (`opusFmtp`)
| Param | Value | Why |
|---|---|---|
| `minptime` | 10 | Smaller packetisation time → lower latency. Opus RFC 7587 §7. |
| `useinbandfec` | 1 | In-band FEC reconstructs a lost packet from the next one — the main lever for the 15–20% loss target. RFC 6716 §2.1.7. |
| `usedtx` | 1 | Discontinuous transmission: stop sending in silence, freeing the shared transport for video/FEC. RFC 7587 §3.1.3. |
| `stereo` | 0 | Mono voice — halves bitrate, no quality loss for speech. |
| `maxaveragebitrate` | 32000 | Comfortable wideband speech; brief-specified. |
| `cbr` | 0 | Variable bitrate spends bits only when needed — better quality/bit than CBR for speech. |

### RED (`preferRed: true`)
RFC 2198 redundant audio: each packet also carries the previous frame's payload,
so isolated losses recover without retransmission. Enabled only when the browser
advertises `audio/red` in `RTCRtpSender.getCapabilities('audio')` (Chromium yes;
Safari/Firefox vary → silently skipped). Ordered **RED first, Opus second** via
`setCodecPreferences`.

### Sender (`sender`)
| Param | Value | Why |
|---|---|---|
| `maxBitrate` | 40000 bps | Brief value; head-room above 32 kbps Opus for RED redundancy. |
| `priority` | `high` | Bandwidth arbitration within the PC — audio wins over video. |
| `networkPriority` | `high` | DSCP hint so audio packets are prioritised on the wire. |

## Step 3 — Video (`VIDEO_CONFIG`)

### Codec preference (`codecPreferenceOrder`)
`VP9 → AV1 → H.264 → VP8`, applied with `setCodecPreferences` (via
`applyVideoCodecPreferences`). rtx/red/fec codecs are kept after the media codecs
so retransmission/FEC still work. VP9/AV1 give SVC; H.264/VP8 are plain.

### Single-encoding SVC (why not multi-rid simulcast)
This is **1:1 P2P** (one receiver), so a single encoding with **SVC** is the right
tool: one stream that degrades by spatial/temporal layer. It's applied through
`sender.setParameters` (`configureVideoSender`) and needs **no** `addTransceiver`/
rids, so it doesn't disturb the working `addTrack` media path.

| Codec | scalabilityMode | maxBitrate | degradationPreference |
|---|---|---|---|
| VP9 | `L3T3_KEY` (3 spatial × 3 temporal, key-aligned) | 1.5 Mbps | `balanced` |
| AV1 | `L1T3` | 1.2 Mbps | `maintain-framerate` |
| H.264 / VP8 | none (plain) | 1.5 Mbps | `balanced` |

`networkPriority: 'medium'` — below audio's `high`. If a browser rejects the SVC
mode (Firefox/Safari gaps), `configureVideoSender` retries with a plain encoding.

### Initialization (Step 6) + simulcast (Step 3) — what shipped, and why

**Attempted then reverted:** an explicit `addTransceiver({sendEncodings})` path
(single-encoding SVC / multi-rid simulcast) was implemented but **broke media on
real devices** during testing:
- on the **answerer**, reusing the transceiver created by `setRemoteDescription`
  rejected the SVC `setParameters` (`"parameters are not valid"`), and
- on **role-reversed / repeat calls**, the reused transceiver **directions
  desynced** — the call connected (timer ran, `ontrack` fired) but no audio/video
  actually flowed.

**What ships instead:** media is attached with **`addTrack`** (reused across calls
via `replaceTrack`), letting the browser manage transceiver direction implicitly —
this is what keeps audio/video flowing across reversed and repeat calls. Video uses
**single-encoding SVC** (VP9 `L3T3_KEY` / AV1 `L1T3`) applied via
`configureVideoSender`→`setParameters`, plus `setCodecPreferences` (VP9→AV1→H264→VP8).
For 1:1 P2P a single SVC stream is the right tool anyway — it degrades by
spatial/temporal layer, which is what the "video degrades gracefully" requirement
needs. `configureVideoSender` falls back to a plain encoding if a scalabilityMode
is rejected.

**Multi-rid simulcast** (`buildVideoSendEncodings`, `VIDEO_CONFIG.*.simulcast`) is
kept as **tested, exported primitives** for a future SFU/group-call path, but is
**not wired into the 1:1 call flow** — it needs `addTransceiver({sendEncodings})`,
which requires the answerer-direction / setParameters issues above to be solved
first (ideally with a Playwright two-PC test rig, which isn't set up). The
adaptation controller is already simulcast-aware (`_applyToVideoSender` throttles
only the top layer) for when that lands.

## Step 4 — Transport (`TRANSPORT_CONFIG`)

Ensures the RTCP feedback / header extensions are present on the call m-lines
(most browsers already emit them, so this is an idempotent safety net):

| m-line | rtcp-fb | header ext |
|---|---|---|
| video | `transport-cc`, `nack`, `nack pli`, `ccm fir`, `goog-remb` | TWCC (`…transport-wide-cc…`) |
| audio | `transport-cc`, `nack` | TWCC |

Implemented as pure, idempotent SDP utils (`ensureRtcpFb`, `ensureExtmap`,
`applyTransport`) — added only when missing, never duplicated, applied only to
primary codecs (rtx/red/fec skipped). `transport-cc` (TWCC) is what feeds the
bandwidth estimator the Step-5 controller reads.

**Safety:** munged local SDP is set via `_setLocalMunged` with progressive
fallback — full munge → Opus-only → raw — so a browser rejecting an injected
line can never break the call.

## Step 5 — Adaptation + quality indicator (`ADAPTATION_CONFIG`)

`NetworkAdaptationController` reads `pc.getStats()` every 1 s and reacts:

| Condition | Action | Note |
|---|---|---|
| loss > 10% **or** RTT > 300 ms | video `maxBitrate` −20% (floor 100 kbps) | audio never touched |
| loss < 3% **and** RTT < 150 ms, 5 ticks | video `maxBitrate` +10% (up to ceiling) | gradual recovery |
| `qualityLimitationReason === 'cpu'` | `scaleResolutionDownBy` ×1.5 | bitrate unchanged |

All changes go through `sender.setParameters` — **no renegotiation, no track
restart**. **Audio is never throttled** by the controller, so speech stays intact
regardless of loss (stronger than the brief's "≥25%" guard). The pure decision
(`decideAdaptation`) and stats parsing (`summarizeStats`) are unit-tested with
mock getStats.

### Connection-quality indicator (user-facing)
The same `getStats` sample yields a coarse label (`qualityFromMetrics`) surfaced in
`callState.quality` and rendered in the call UI as signal bars + text:

| Label | Loss / RTT | Colour |
|---|---|---|
| Excellent | <3% and <150 ms | green |
| Good | <7% and <250 ms | green |
| Fair | <15% and <400 ms | yellow |
| Weak | otherwise | red |

Shown in the voice overlay, the video top bar, and (compact bars) the minimized
widget. Hidden until the first sample has data.

## Verification (all steps)
- Unit: `npm test` (SDP, video codecs, adaptation) — all green.
- Manual (`chrome://webrtc-internals`, per criteria): throttle the link (DevTools
  Network / OS) → outbound video `targetBitrate` steps down within ~1–2 s and
  recovers when the link clears; audio bitrate holds; the in-call indicator moves
  Excellent → Fair → Weak.
- Audio: in a call, open `chrome://webrtc-internals` → audio outbound-rtp should
  show Opus with the fmtp above; on Chromium the codec is `red`/`opus`. Under
  packet loss, `useinbandfec` keeps audio intelligible.

> The temporary `[Call]` / `window.__sbCallLog` diagnostic logger used during
> bring-up has been removed for production; the manager's `_secureLog` handles
> runtime logging and stays silent in production builds (`DEBUG_MODE = false`).
