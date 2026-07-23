# WebRTC Audit — SecureBit.chat call stack

**Step 1 deliverable. No code changed.** This maps the existing WebRTC/call code so we can plan the adaptive voice/video stack (Opus FEC/DTX/RED, VP9-SVC + fallbacks, TWCC/NACK/PLI, getStats adaptation) *without* creating a parallel branch.

---

## 0. Reality vs. the task spec (read this first)

The task is written against a modular TypeScript layout (`src/webrtc/codecs/*.ts`, `call.ts`, `config.ts`, …). **That layout does not exist and does not match the repo.** Concretely:

| Task assumption | Actual repo |
|---|---|
| TypeScript (`.ts`) | Plain JS / JSX. No `tsconfig`, no `.ts` files, esbuild bundles JS as-is. |
| `src/webrtc/` modular stack | One monolith: `src/network/EnhancedSecureWebRTCManager.js` (~14.8k lines). |
| Fresh `RTCPeerConnection` per call, `addTransceiver` at init | **One long-lived PC** shared with the encrypted **data channel**; calls are **renegotiated onto it**. Media is added with `addTrack`, **never** `addTransceiver`. |
| Standard signalling server / offer at init | **Two separate SDP paths** (see §5). Call SDP is exchanged **in-band over the E2E data channel**. |
| Playwright available | Not installed. Tests are plain `node tests/*.test.mjs`. No `RTCPeerConnection` in Node. |
| `debug('webrtc:adapt')` | No `debug` dependency. Logging is `_secureLog(...)` + the new `window.sbCallLog(...)`. |

**Consequence:** we integrate into the existing manager + a small set of **new plain-JS helper modules** it imports. We do **not** add TypeScript or a `src/webrtc/` TS tree. Proposed JS layout in §7.

---

## 1. Module map

| File | Kind | Exports / globals | Role |
|---|---|---|---|
| `src/network/EnhancedSecureWebRTCManager.js` | ES module | `export { EnhancedSecureWebRTCManager, SecureMasterKeyManager, SecureIndexedDBWrapper, SecurePersistentKeyStorage }` (line 14812). Also `window.EnhancedSecureWebRTCManager`. | **All** transport + crypto + call logic. The class to extend. |
| `src/components/ui/CallUI.jsx` | ES module (side-effect) | `window.CallUIComponent`, `export { CallUIComponent }` | Presentational call overlay (voice/video/minimized/incoming). Pure UI; no media/crypto. |
| `src/scripts/app-boot.js` | bundled entry | imports the manager + UI components; sets `window.*` | Real loader (→ `dist/app-boot.js`). CallUI is imported here. |
| `src/app.jsx` | bundled entry | React app (`h`/createElement) | Header call buttons + mounts `CallUI`. getUserMedia for **voice messages** (unrelated to calls) at 816–817. |
| `config/ice-servers*.js` | script | `window.SECUREBIT_ICE_SERVERS` | Operator STUN/TURN override. |
| `src/network/iceServers.js`, `iceSettingsStore.js` | ES modules | ICE validation/persistence | User-supplied ICE servers. |

> `src/scripts/bootstrap-modules.js` exists but is **dead** (not referenced anywhere). Ignore it.

---

## 2. RTCPeerConnection: creation & config

- **`createPeerConnection()`** — `EnhancedSecureWebRTCManager.js:7731`. Single `new RTCPeerConnection(config)` at **7737**. Wires `onconnectionstatechange`, `oniceconnectionstatechange`, `onicecandidateerror`, **`ontrack`** (7802, call media), `ondatachannel`.
  - Called from **9983** (initiator/offer path) and **10646** (responder/answer path).
- **`_buildPeerConnectionConfig()`** — `7661`. Returns:
  ```js
  { iceServers, iceCandidatePoolSize: 10, bundlePolicy: 'balanced' }   // + iceTransportPolicy:'relay' in privacy mode
  ```
  No `rtcpMuxPolicy`, no codec/degradation config (nothing to do there; those live on senders/transceivers).
- One PC per session; multi-session keeps a `Map<id, manager>` (each with its own PC).

## 3. SDP formation

No codec munging exists today — only **DTLS fingerprint extraction** (`_extractDTLSFingerprintFromSDP`) and **ICE candidate diagnostics** (`_summarizeIceCandidatesInSDP` 1057, `_logIceCandidateDiagnostics` 1119, `_warnIfRemoteCandidatesNeedRelay` 1145).

| Op | Line(s) | Path |
|---|---|---|
| `createOffer` | 10004 | **Data-channel handshake** (initial connection) |
| `setLocalDescription(offer)` | 10009 | handshake |
| `setRemoteDescription(offer)` | 10682 | handshake |
| `createAnswer` | 10717 | handshake |
| `setLocalDescription(answer)` | 10727 | handshake |
| `setRemoteDescription(answer)` | 11462 | handshake |
| `createOffer` | 13047, 13262 | **Call** (startCall / renegotiate) |
| `setLocalDescription` | 13048, 13263 | call |
| `setRemoteDescription(offer)` | 13081 | call |
| `createAnswer` + `setLocalDescription` | 13087–13088 | call |
| `setRemoteDescription(answer)` | 13285 | call |
| `setLocalDescription({type:'rollback'})` | 13176 | call teardown |

**Where codec/RTP munging must hook:** only the **call** offers/answers (13047/13087/13262). The handshake SDP (m=application/data channel only) must stay untouched.

## 4. Media: getUserMedia / addTrack / transceivers

- **getUserMedia (calls):** `_acquireLocalMedia` 13012, `upgradeToVideo` 13221, `switchCamera` 13245.
  - Unrelated: voice-message recorder `app.jsx:817`; QR scanner `QRScanner.js:72`.
- **addTrack:** `_acquireLocalMedia` 13017, `upgradeToVideo` 13230. **← the only way media is attached today.**
- **replaceTrack:** upgrade 13228, switchCamera 13252, teardown 13151.
- **removeTrack / getReceivers / getTransceivers / .stop():** teardown 13146–13158.
- **`addTransceiver`: NONE.** `sendEncodings`: NONE. `setParameters`/`getParameters`: NONE. `setCodecPreferences`/`getCapabilities`: NONE.
- **`ontrack`** handler: 7802 (accumulates into `this.remoteMediaStream`).

## 5. Signalling model (two SDP paths — important)

1. **Connection handshake** (data channel): offer/answer compressed and exchanged **out-of-band** (QR / copy-paste), authenticated by **SAS**. Establishes the DTLS transport + `securechat` data channel (`createDataChannel` 9986).
2. **Call setup** (media): after the channel is verified, call SDP rides **in-band over that data channel** via `MESSAGE_TYPES.CALL_OFFER/CALL_ANSWER/CALL_ICE/CALL_DECLINE/CALL_END`. Routed in the live `dataChannel.onmessage` (~7996) → `_handleCallSignal` (13274). Media BUNDLEs onto the existing transport, so **no new ICE**.

→ Adaptive stack changes affect **path 2 only**.

## 6. Call subsystem inventory (all in the manager, added recently)

State/getters: `callState` object; `getCallState` 12957, `getRemoteMediaStream` 12961, `getLocalMediaStream` 12965, `_updateCallState` 12969 (fires `onCallStateChanged` + `securebit-call-state` DOM event).
Lifecycle: `_callCanStart` 12983 (gated on connected+verified), `_acquireLocalMedia` 12999, `startCall` 13025, `_onIncomingCallOffer` 13065, `_answerCallOffer` 13080, `acceptCall`/`declineCall`, `endCall` 13120, `_teardownCallMedia` 13132.
Controls: `setMicEnabled` 13186, `toggleMic` 13193, `setCameraEnabled` 13197, `toggleCamera` 13215, `upgradeToVideo` 13218, `switchCamera` 13241, `_renegotiateCall` 13258.
Signalling: `_handleCallSignal` 13274, `_sendCallSignal`, `MESSAGE_TYPES.CALL_*`.
Debug: `window.sbCallLog` / `window.__sbCallLog` (module top of the manager).
UI: `CallUI.jsx` + header buttons (`app.jsx`) + overlay mount in `EnhancedChatInterface`.

## 7. Gaps vs. the target spec

| Requirement | Status | Note |
|---|---|---|
| Opus fmtp (FEC/DTX/RED, maxavgbitrate, cbr=0) | ❌ | No SDP munging. |
| RED via setCodecPreferences | ❌ | No codec prefs. |
| Audio sender priority/networkPriority/maxBitrate | ❌ | No setParameters. |
| VP9 SVC (`L3T3_KEY`) + simulcast fallback | ❌ | No `sendEncodings`; uses `addTrack`. |
| AV1 / H.264 / VP8 fallback order | ❌ | No `getCapabilities` sort. |
| TWCC/NACK/PLI/FIR/REMB on m-lines | ⚠️ | Whatever the browser emits by default; not enforced/verified. |
| `NetworkAdaptationController` (getStats loop) | ❌ | None. |
| Config with sourced constants | ❌ | Only `_config.webrtc` (ICE/privacy). |

## 8. Proposed integration (for confirmation — not yet built)

New **plain-JS** modules under `src/network/webrtc/` (imported by the manager), mapping to the task's requested files:

| Task file | Proposed actual file |
|---|---|
| `src/webrtc/config.ts` | `src/network/webrtc/config.js` — all constants + source comments |
| `src/webrtc/codecs/audio.ts` | `src/network/webrtc/audio.js` — `configureAudioSender` |
| `src/webrtc/codecs/video.ts` | `src/network/webrtc/video.js` — `configureVideoSender` |
| `src/webrtc/codecs/sdp.ts` | `src/network/webrtc/sdp.js` — pure SDP munging utils (testable in Node) |
| `src/webrtc/adaptation/metrics.ts` | `src/network/webrtc/adaptation/metrics.js` — getStats parsing |
| `src/webrtc/adaptation/controller.ts` | `src/network/webrtc/adaptation/controller.js` — `NetworkAdaptationController` |
| `src/webrtc/call.ts` | **integrate into `EnhancedSecureWebRTCManager.js`** call methods |

Hook points in the manager:
- `_acquireLocalMedia` (12999): switch `addTrack` → `addTransceiver('audio'/'video', {direction, sendEncodings})`, then `setCodecPreferences` on the transceivers.
- `startCall`/`_answerCallOffer`/`_renegotiateCall`: after `createOffer/createAnswer`, run `sdp.js` munging before `setLocalDescription`; after `setRemoteDescription`, call `configureAudioSender`/`configureVideoSender` and start the controller.
- `_teardownCallMedia`: stop the controller.

**Key compromise to confirm:** the PC is long-lived and shared with the data channel, so we **cannot** follow Step-6's "addTransceiver at PC init" literally. Transceivers are added/negotiated in-band at call start on the existing PC (the audio/video transceivers can be created once on first call and reused via `replaceTrack` thereafter — this also fixes the transceiver-accumulation issue seen earlier).

## 9. Constraints / risks

- **Browser matrix:** `scalabilityMode`/`setCodecPreferences` support varies. Firefox: SVC limited → simulcast fallback mandatory. Safari: VP9 often absent → H.264 fallback; RED support varies. All feature-detected via `getCapabilities`/try-catch.
- **SDP munging is fragile** across browsers (m-line/payload ordering). Utilities must be defensive and idempotent (spec says "no duplicate lines").
- **Testing:** SDP utils + controller (mock `getStats`) → plain `node .mjs` unit tests (fits current infra). **Integration test needs a real browser** (two `RTCPeerConnection`s + throttling) — **Playwright is not installed**; that item needs either adding Playwright (a dependency — task says avoid unless necessary) or manual `chrome://webrtc-internals` verification.
- **In-band renegotiation** must keep the perfect-negotiation guards already in place to avoid glare.

## 10. Open questions before Step 2

1. Confirm JS (not TS) + `src/network/webrtc/` layout in §8.
2. Confirm the long-lived-PC compromise in §8 (reuse transceivers via `replaceTrack`, negotiate in-band).
3. Playwright: add it for the integration test, or rely on `chrome://webrtc-internals` manual verification for the "adaptation visible under throttling" criterion?
4. Commit-per-step + deploy to Fly after each step (as before), GitHub untouched — same as current workflow?
