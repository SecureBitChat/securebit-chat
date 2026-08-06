# Changelog

## v5.9.0 — The invitation is now one small QR code

The connection descriptor moves to SBQ2 and the key material moves onto the
DataChannel. Measured on the live site: the invitation payload went from **2274
characters across 4 animated QR frames to 151 characters in a single frame**.

### Changed

- **Invitations use the SBQ2 format.** The out-of-band code now carries only what
  brings up DTLS — ICE credentials, the certificate fingerprint, candidates, an
  expiry — plus a 16-byte commitment to the key material.

- **Key material is exchanged in band.** The ECDH and ECDSA public keys travel as
  the first frame on the DataChannel, and are checked against the commitment from
  the invitation *before* they are parsed or imported. A mismatch closes the
  connection; it is not a warning.

- **The SAS is computed over a transcript** covering both descriptors verbatim and
  both key blobs, with length prefixes. Anything an attacker can alter anywhere in
  the handshake, in either direction, changes the digits the two people compare.

- **The HKDF salt is derived from that transcript instead of transmitted**, so
  every session key is bound to both DTLS fingerprints and every candidate, and
  neither side can steer it.

- **`authProof` is replaced by one signature over the transcript.** The old
  challenge/response echoed a nonce back across seven fields; the signature proves
  the same possession and binds the whole handshake at once.

- The Double Ratchet starts from the transcript-derived material. SBQ2 postdates
  the ratchet entirely, so support is implied by the format rather than advertised
  in it — which also removes the silent "peer is old, use static keys" fallback
  from this path.

### Rollback

`EnhancedSecureWebRTCManager.SBQ2_SEND_ENABLED = false` and redeploy puts every
new invitation back on SB1. Reception of both formats is unconditional and is not
governed by the flag, so a client built with it off still reads SBQ2 invitations.

### Compatibility

SB1 invitations are still read, and the animated multi-frame QR path stays for
them. A client older than 5.9.0 cannot read an SBQ2 invitation: from 5.9.0 on, an
unrecognised `SB<n>:` family reports "This invitation was created by a newer
version of SecureBit. Please update the app to connect." Versions 5.8.1 and
earlier predate that check and show a JSON parse error instead — the two ends must
both be on 5.9.0+.


## v5.8.1 — SBQ2 rebuilds SDP that Firefox accepts

Still nothing in the application calls the SBQ2 descriptor; this fixes defects in
it found by running live connections between real browsers.

### Fixed

- The rebuilt SDP omitted `raddr`/`rport` on srflx and relay candidates. RFC 8839
  §5.1 makes them mandatory for non-host candidates, and while Chrome tolerates
  the omission, **Firefox drops the candidate entirely**. Relay-only connections
  to Firefox failed 0/8 where the browser's own SDP succeeded 8/8. The STUN and
  TURN profiles hid it, because a host candidate pair connected instead.

- The template advertised `a=ice-options:trickle` and never closed the candidate
  set. A descriptor is a complete one-shot set with no channel to trickle over,
  so this promised candidates that could never arrive. Trickle is gone and
  `a=end-of-candidates` is emitted.

- The `m=` port and `c=` line were hard-coded to the `9` / `0.0.0.0` null default
  candidate, which is the trickle-ICE "nothing gathered yet" convention and false
  here. The most publicly reachable candidate is advertised instead — relay, then
  srflx, then host — falling back to the null form only when every candidate is
  mDNS, as Chrome does.

None of these change the descriptor: all three are serializer-side and cost zero
bytes. Sizes are unchanged at 98–149 bytes, QR version 6–8.

Verified across all 16 combinations of {Chrome, Firefox} x {Chrome, Firefox} and
four network profiles: **48/48 connections**, with every relay-only pair now
connecting over the relay.


## v5.8.0 — A connection descriptor that fits in a small QR code

No change to how messages are protected, and no change to how a connection is
established. This release adds the wire format for a much smaller invitation and
the code that reads and writes it; nothing in the application calls it yet.

### Added

- `src/network/descriptor/sbq2.js` — version 2 of the connection descriptor. The
  current `SB1:` payload runs 2000–2400 characters and needs QR version 38–40, at
  which point the app has to fall back to an animated multi-frame code. Measured
  on real Chrome and Firefox SDP across four network profiles, SBQ2 is **98–149
  bytes**, which is **QR version 6–8** — a single, instantly scannable image.

  The saving comes from sending only what is needed to bring up DTLS (ICE
  credentials, certificate fingerprint, candidates) and templating the SDP rather
  than shipping it verbatim. Key material is intended to move to the DataChannel,
  bound to the descriptor by a commitment; **that half is not implemented**, which
  is why the format is not yet in the connection path. See
  `doc/DESCRIPTOR-SBQ2.md` for the layout, the security argument and the migration
  gate.

  The decoder is written as a parser of hostile input: fixed offsets, explicit
  lengths, deny-by-default on every reserved value and on unknown extension types,
  trailing bytes rejected, and ICE credentials alphabet-checked so a CRLF cannot
  reach the SDP serializer. Compression is deliberately absent — on this payload
  DEFLATE adds bytes, and removing it removes the decompression-bomb surface too.

- `doc/DESCRIPTOR-SBQ2.md`, and `tests/descriptor-sbq2.test.mjs` covering
  round-trip against real Chrome and Firefox SDP, IPv6 and NAT64 addresses,
  ICE-TCP candidates, candidate-coverage pruning, the TLV extension area, clock
  skew, one-shot binding and the SAS transcript.

- `tests/fixtures/sdp-chrome.json` and `tests/fixtures/sdp-firefox.json` —
  SDP captured from real browsers rather than written by hand.


## v5.7.2 — Documentation, and a version that keeps itself honest

No changes to the protocol or to how messages are protected.

### Fixed

- The version shown in the application header was written as a literal and had
  fallen behind, displaying v5.6.0 while running 5.7.1. It now comes from
  `package.json`, so it cannot drift again, and a test fails the build if anyone
  reintroduces a hard-coded one. The same test checks that `meta.json`, the README
  badge and the changelog agree with each other before a release goes out.

### Changed

- Documentation reorganised. Everything technical now lives in `doc/`, with an
  index at `doc/README.md`. The root keeps only what belongs there by convention:
  `README.md`, `SECURITY.md`, `CHANGELOG.md` and `LICENSE`.
- `SECURITY.md` rewritten. It described a release line three major versions old
  and made claims the software does not make. It now states what is guaranteed,
  what is not, and how to report a problem.
- `SECURITY_DISCLAIMER.md` and `RESPONSIBLE_USE.md` merged into
  `doc/USE-POLICY.md`, which says plainly what the software cannot protect
  against instead of listing generic advice.
- `doc/CRYPTOGRAPHY.md` and `doc/ARCHITECTURE.md` rewritten to describe the
  current design, including the Double Ratchet, and to quote real values taken
  from the source rather than restated approximations.
- WebRTC call tuning notes moved to `doc/CALLS.md` and rewritten. The obsolete
  `docs/` directory, which held a working document full of stale line numbers,
  has been removed.
- `doc/CONTRIBUTING.md` now records what recent bugs taught us about writing
  tests that can actually fail.

## v5.7.1 — Forward secrecy now engages for both sides of a chat

The Double Ratchet introduced in 5.7.0 was only taking effect for the peer who
joined a conversation; the peer who created the invitation stayed on the
previous per-session key scheme. Both sides now negotiate and run it, so a
conversation is protected symmetrically end to end.

If you installed 5.7.0, updating is worthwhile — it is what makes per-message
forward secrecy apply to your whole conversation rather than one direction of it.

### Internal

- The ratchet's test suites now construct the peer's public key exactly as the
  handshake delivers it (exported and re-imported, non-extractable) rather than
  reusing a locally generated one. Locally generated public keys are always
  extractable in WebCrypto, so the earlier tests exercised a key shape the app
  never actually produces.

## v5.7.0 — Double Ratchet: forward secrecy for every message

Sessions previously derived one set of keys during the handshake and used them
for the whole conversation. This release adds the Double Ratchet (Signal's
design) on top of that, so protection no longer rests on a single set of keys
lasting the entire chat.

### Added

- **A separate key for every message.** Each message key is derived from a chain
  key through a one-way function and discarded immediately after use, so keys
  that exist now cannot be used to reconstruct earlier ones.
- **A Diffie–Hellman step on every change of direction.** Each reply introduces a
  fresh ECDH key pair and mixes a new shared secret into the root key. A session
  therefore re-keys itself continuously as the conversation goes back and forth.
- **Bounded handling of out-of-order messages.** Keys for messages that have not
  arrived yet are held so they can still be read, with firm limits on how many
  are kept (512 per chain, 1024 in total, expiring after five minutes) and a
  fixed ceiling on how far ahead a message number may jump.

The ratchet required no change to the handshake. Both peers already hold each
other's authenticated ECDH public key, and the safety code compared during
verification covers exactly those keys. The ratchet's root is derived from the
existing shared secret through its own branch of the key schedule, keeping it
separate from the session's other keys.

### Compatibility

Support is advertised in the invitation and the response and used only when both
sides have it. A peer on an earlier release negotiates it away and the session
runs on the previous scheme — with no server in the design there is no way to
update both ends at once, and connecting with the earlier protection is better
than not connecting. The security panel shows which of the two is actually in
use, rather than what the client is capable of.

One behaviour worth knowing: the peer who joins has no sending chain until the
inviting peer's first message arrives — that is inherent to the ratchet, since
both sides derive it from the same exchange. The app sends a presence update from
both sides as soon as verification completes, so those first frames use the
session keys and everything afterwards is ratcheted.

### Improved

- **Connection setup on restrictive networks.** Gathering network candidates only
  finishes once every configured STUN/TURN server has replied or timed out, which
  behind a VPN or a strict firewall may not happen at all. Setup now proceeds as
  soon as there are usable candidates and only keeps waiting while there are
  none, up to a longer ceiling. A network that genuinely yields nothing now
  explains what to try instead of failing without explanation.

## v5.6.2 — Restore connectivity after the 5.6.1 key-handling change

5.6.1 changed how the shared secret is handled in memory and missed a matching
adjustment to key generation, which prevented sessions from being established.
Anyone on 5.6.1 should update.

Key agreement is unchanged on the wire, so 5.6.0 sessions remain compatible.

### Internal

- Added an end-to-end test that drives the real key generator and derivation
  rather than constructing its own keys, which is what allowed the mismatch
  through.

## v5.6.1 — Hardening pass

A review of the client produced a set of improvements to how the session is
verified, how peer input is handled and what the app stores. Updating is
recommended.

### Improved — verification and peer input

- **The safety-code comparison is now the only route to a verified session.**
  Verification state is set in exactly one place, and the checks that guard it
  cannot be reached around.
- **Control messages are honoured only after verification.** Reconnection
  signalling, call setup, message deletion and delivery receipts all wait until
  both people have compared the safety code. The verification exchange itself
  continues to work beforehand, as it must.
- **A single path for incoming chat content.** An older, weaker inbound code path
  was retired so that everything shown in a conversation has been authenticated.

### Improved — accuracy of what the app reports

- **The security panel now measures what it displays.** Several checks previously
  reported a fixed result; they now exercise the subsystem they describe and can
  report a failure. As a result the score reflects the session more precisely,
  and may read lower than before on the same connection.
- **Forward-secrecy reporting matches reality.** In 5.6.1 the panel reported the
  session-level guarantee accurately rather than implying per-message protection;
  5.7.0 adds the per-message protection itself.
- **Clearer memory-handling semantics.** Operations that cannot clear a value in
  JavaScript — immutable strings, non-extractable keys — now say so instead of
  reporting success.

### Improved — what stays on the device

- **Invitation data is no longer kept in local storage.** An unused
  reference-based QR path wrote session invitation details to local storage
  without removing them; the path has been removed and existing entries are
  cleared on first launch after updating.
- **Ephemeral messages stay ephemeral.** View-once and disappearing messages no
  longer place their text in system notifications, where the operating system
  would retain it beyond the app's control. Ordinary messages are unchanged.

### Improved — hardening

- **Shared-secret handling in memory.** The value is derived into a buffer that is
  overwritten once it is no longer needed.
- **Scanned QR codes are decompressed with a size limit,** so a malformed or
  hostile code cannot exhaust memory.
- **Voice notes are validated before being accepted automatically.** Only genuine
  audio types within a size limit skip the consent prompt; anything else goes
  through the normal confirmation, which also bounds how much a peer can send
  unattended.
- **The master-password prompt now comes from the app's own interface** rather
  than a browser dialog.
- **Clearer handling of DTLS fingerprints,** with the local and remote values kept
  separate and reported accurately.

## v5.6.0 — Survive a dropped connection

A chat no longer dies when the network moves under it. Switching Wi-Fi → LTE,
a NAT rebind, a lift, a tunnel: the session now repairs its own network path and
the messages you typed meanwhile go out when it comes back.

This is done without adding any server. An ICE restart renegotiates *only* the
transport path; the DTLS handshake, the session keys and the SCTP association
carrying the data channel all sit above ICE and survive it. So the renegotiation
SDP travels over the existing end-to-end encrypted, SAS-verified channel — there
is still no signalling service anywhere in the design, and an attacker who cannot
already decrypt the session cannot inject a reconnection.

### Added

- **Automatic session recovery.** A broken path is repaired in place with an
  in-band ICE restart, retried with a 1/2/4/8/15/30 s backoff for up to two
  minutes. Keys, SAS verification and message history are all preserved — no
  re-handshake, no comparing codes again.
- **Liveness detection that understands sleeping devices.** A data channel keeps
  reporting `readyState: 'open'` long after the path underneath it has died — the
  classic Wi-Fi → LTE switch, where nothing closes and nothing errors, packets
  just stop. Silence alone is deliberately not treated as death, because a
  browser freezes a backgrounded tab outright and a healthy peer then answers
  nothing at all. What survives that freeze is ICE consent, which the browser
  runs in its network stack rather than on the page's thread — so a connected ICE
  state means a silent peer is asleep, not gone, and the session is left alone.
  Only when ICE itself is degraded does an unanswered probe end the session.
- **Recovery is given up promptly when it cannot possibly work.** Every route out
  of a broken path runs over the data channel, so if nothing at all has reached
  us since the drop, no further attempt can succeed. Likewise an ICE agent left
  bound to a network that is gone — every candidate times out, every restart ends
  with zero candidate pairs — cannot be repaired by restarting it. Both are now
  recognised in seconds instead of being retried for two minutes.
- **A session that cannot be recovered is closed, not left half-alive.** When the
  path is gone for good, the chat is ended and its data wiped — keys, queued
  messages and transcript together. There is deliberately no manual fallback: a
  conversation whose transport is gone should not leave its plaintext sitting in
  a tab, and starting a fresh one is a single, honest step.
- **Store-and-forward while reconnecting.** Messages typed during a repair are
  queued and delivered when the path returns, in order. A send that races a
  still-settling path is re-queued rather than marked failed.
- **The conversation stays on screen** during a repair, with a "Restoring
  connection…" state, instead of dropping you back to the connect screen.
- **A device with no network holds the session open.** Five minutes underground
  no longer costs a session: the give-up deadline does not run while this device
  has no connectivity, and recovery retries the moment the radio returns or the
  tab comes back to the foreground.
- `tests/session-recovery.test.mjs` covers the state machine, the backoff, the
  offline hold and the identity check below.

### Security

- **A reconnection cannot re-point a session at a different peer.** The DTLS
  fingerprint in an incoming restart offer or answer is checked against the
  fingerprint of the live, already-verified session *before* anything is applied
  to the peer connection. A mismatch aborts recovery. If there is no live
  fingerprint to compare against, the restart is refused rather than trusted.
- Only the side that created the original offer may drive a restart; the other
  side asks. With no signalling server there is no referee to resolve glare.
- Calls cannot be placed onto a path that is mid-repair, where the media
  renegotiation would race the ICE restart on the same connection.

### Fixed

- **Every inbound heartbeat threw a `TypeError`.** `handleHeartbeat()` was
  dispatched to but never defined, so peer liveness was never actually observed.
- **Heartbeats were sent every 5 minutes, not the intended interval** — the send
  was folded into the general maintenance cycle, far too coarse to notice a dead
  path. It now runs on its own timer, and answering one no longer requires the
  peer to have finished verifying: the two sides confirm a SAS code at different
  moments, and for that whole window one of them could not reply and was being
  declared dead on a healthy connection.
- **The answering side never started its watchdog.** `ondatachannel` can hand over
  a channel that is already open, so the `open` event had been dispatched before
  the handler was assigned and never fired — leaving that side with no heartbeat,
  no liveness watchdog and no file-transfer init. The peer whose network was fine
  kept showing "connected" indefinitely because nothing was running to notice.
- **A failed send no longer fails silently.** Sending on a channel that was not
  ready simply returned: the text stayed in the box, nothing was transmitted and
  nothing said why.
- **A transient `disconnected` no longer tears down the session.** ICE reports it
  routinely and the browser usually recovers unaided; it is now given a grace
  window before a restart is spent, and it never clears verification on its own.
- A reconnected session no longer re-announces "secure connection established" —
  it is the same session resuming, and no handshake took place.
- Liveness bookkeeping can no longer throw ahead of message routing, where the
  surrounding catch would have swallowed it and silently dropped every inbound
  message.

## v5.5.4 — Fix the desktop download buttons

### Fixed

- **The download buttons still led to a dead GitHub page.** 5.5.3 updated one of the two places these links live; the platforms menu on the connection screen has its own `DOWNLOADS` table, and it was missed. It still pointed at 0.1.0.
- The stale links used `/releases/latest/download/<file>`. GitHub resolves `latest` by redirecting to the newest tag, so once 0.3.0 shipped, a link written for 0.1.0 became `/releases/download/v0.3.0/SecureBit.Chat_0.1.0_x64-setup.exe` — a file that never existed under that tag. The button navigated to GitHub and downloaded nothing, which is why it looked like a working link that simply did nothing.

### Added

- `tests/desktop-download-links.test.mjs`, which fails the build if any source drifts: it requires every file to derive its URLs from one `DESKTOP_VERSION` constant, forbids `/releases/latest/download/` and hardcoded versions in filenames, and fetches each generated URL to prove the release asset is really there. Set `SKIP_NETWORK=1` to skip the fetches offline.

## v5.5.3 — Desktop downloads point at 0.3.0

### Fixed

- **The desktop download buttons still offered 0.1.0.** Windows, macOS and Linux now link to the current 0.3.0 release, which is the first with in-app updates, voice-note parity and the verification fixes.
- The release version was repeated across three URLs in two different forms (two resolving through `/releases/latest/`, one pinned to a tag), which is how they drifted out of date. It is now a single constant, and the tag is pinned deliberately: filenames carry the version, so a `latest` link breaks as soon as a newer release exists, whereas a pinned tag keeps serving a working installer.

## v5.5.2 — Fix security level in the header

### Fixed

- **Header showed "Secure undefined%".** Moving `getRealSecurityLevel()` onto the connection manager in v5.5.1 made it reachable for the first time, so the header started calling it instead of falling through to `calculateAndReportSecurityLevel()`. It returned only per-feature booleans — no `level`, no `score` — and the header renders those two fields directly. It now runs the same verified scoring as every other consumer and merges the feature flags on top, so all callers see one consistent number. A regression test pins the shape for every branch of the header's fallback chain.

## v5.5.1 — Security audit fixes

A security review of the transport and verification layers. Every item below is a
fix to how untrusted peer input is handled; no features changed.

### Security

- **SAS verification can no longer be bypassed.** `verification_both_confirmed` is an unauthenticated frame that arrives on a channel that is not yet trusted, but it was accepted as proof that both sides had compared their codes — so a peer who completed the signalling exchange could send it right after the data channel opened and drive the other side to a "verified" session while the user never looked at the code. It is now only an *acknowledgement*: it is refused unless this side has already confirmed locally, and `_setVerifiedStatus()` independently rejects any SAS-based transition without a local confirmation. Holding ECDH-derived keys was never sufficient proof of identity — a MITM has those too.
- **Unauthenticated frames can no longer be injected into the chat.** A bare `{type:"message"}` JSON frame, a raw non-JSON text frame, and a binary frame were each decoded and rendered in the chat, bypassing decryption, the HMAC check and the verification gate — the injected text was visually indistinguishable from a genuine message. Chat content now reaches the UI only through the authenticated `enhanced_message` path; everything else is dropped and logged.
- **A peer can no longer supply the verification code.** `sas_code` announcements were adopted verbatim when no local SAS had been derived yet, which would have shown the user a number chosen by the other end. The announcement may now only corroborate the locally derived code; a missing or mismatching code aborts the session.
- **File transfers are gated on verification in both directions.** File control frames (`file_transfer_start`, `file_chunk`, …) are written straight to the data channel by the transfer system, so they never passed through the send path's verification gate on receipt. Sending was already gated; receiving now is too, so an unverified peer cannot open transfers, push chunks or drive transfer state before the SAS has been compared. User consent remains required on top of this.
- **Anti-replay is actually enforced.** The sequence-number and AAD validators were defined on the wrong class (`SecureKeyStorage` instead of the connection manager), so every call site silently failed and the sliding replay window never ran. They now live on the manager, the live chat path validates the authenticated sequence number of each message, and a missing or non-numeric sequence number fails closed instead of sailing through the range checks.
- **Stale sequence numbers are rejected** rather than logged and decrypted anyway.
- **Tighter CSP.** `connect-src` and `img-src` no longer allow arbitrary `https:` hosts (nothing in the app talks to a third party), and `base-uri 'none'` is set. This removes the exfiltration channel an injection would otherwise have.
- The SAS is no longer written to logs, and the peer-announced code is compared in constant time on every path.
- Fixed `SecureMasterKeyManager.isUnlocked()` testing a field renamed long ago, so it never actually gated anything.

### Added

- Regression tests covering the verification gate and inbound frame authentication (`tests/verification-gate.test.mjs`, `tests/inbound-frame-authentication.test.mjs`).

## v5.5.0 — Encrypted voice & video calls

SecureBit now supports **end-to-end encrypted voice and video calls** — the "5.5 Secure Voice & Calls" roadmap milestone.

### Added

- **Voice & video calls.** Start a call from the chat header (phone / camera buttons). Audio and video tracks ride the **same RTCPeerConnection as the chat**, bundled onto one **DTLS-SRTP** transport — so media is end-to-end encrypted with the very connection that in-person **SAS verification** authenticated. Call setup (SDP offer/answer) is renegotiated **in-band over the verified data channel**, never through a signalling server, so the media's DTLS fingerprints are authenticated end-to-end too. There is no server that can see or MITM a call.
- **Verification-gated.** Calls are only permitted once a session is **connected and SAS-verified**; the manager rejects call signalling otherwise. The header call buttons stay disabled until then.
- **In-call controls.** Mute / unmute, camera on/off (turning the camera on during a voice call upgrades it to video in-band), front/back camera flip, minimize-to-widget (chat stays usable) and hang up. Incoming calls show an accept / decline prompt.
- **Adaptive audio codec.** Opus tuned for real-world links — in-band FEC, DTX and RED redundancy (RED preferred first where the browser advertises it) keep speech intelligible under 15–20% packet loss. Audio is bandwidth-prioritised and is **never** throttled by the network controller.
- **Adaptive video codec.** VP9 / AV1 single-encoding **SVC** (with H.264 / VP8 fallback), so video degrades gracefully by spatial/temporal layer on a weak link. A runtime `NetworkAdaptationController` reads `getStats()` every second and trims video bitrate on loss/RTT, recovering as the link clears — no renegotiation, no track restart.
- **Live connection-quality indicator.** Excellent → Good → Fair → Weak, surfaced in the voice overlay, video top bar and minimized widget. Codec tunables and their rationale are documented in [`doc/CALLS.md`](doc/CALLS.md).

### Security

- Media inherits the session's DTLS-SRTP encryption; SDP is exchanged only over the ECDH + SAS-authenticated data channel. No new ICE or signalling server is introduced — calls reuse the existing verified transport.

## v5.4.5 — Encrypted voice messages

SecureBit now supports **end-to-end encrypted voice messages**, sent over the same secure transfer channel as files.

### Added

- **Voice messages.** Record a note in the browser and send it over the existing chunked, AES-GCM-encrypted file-transfer pipeline, so it inherits the same per-file session key and SHA-256 integrity check. Audio is captured as raw PCM and encoded to **WAV**, so it plays back on every platform — including iOS/Safari. Duration and a downsampled waveform travel as unsigned presentation metadata; the audio bytes stay integrity-protected by the signed file hash.
- Voice notes are **auto-accepted** on the receiver (no consent prompt) and played **inline** from an in-memory blob — nothing is written to disk. The bubble shows an upload/download progress ring, a seekable waveform, play/pause and duration, and the usual Encrypted/Decrypted status.
- **Composer.** A mic button records a note with a live waveform and timer plus discard / send controls. On desktop the mic and send buttons sit side by side; on mobile the mic swaps to a send button as soon as you type text.

### Changed

- Content Security Policy `media-src` now allows `blob:` so recorded and received audio can be played back.
- Version scheme moved to the 5.x line (Desktop Edition = **5.0**). The roadmap gains a **5.5 "Secure Voice & Calls"** milestone (encrypted voice messages, audio calls, video calls); later milestones shift accordingly.

## v4.9.0 — Full redesign + reworked offline mode

A ground-up visual redesign of the whole application surface — landing page, "Why unique" / partners / roadmap / community sections, connection setup, in-chat header, real-time security verification report, file transfer, and the PWA install / update / offline / install-guide dialogs.

Offline experience reworked with store-and-forward over the live P2P channel:

- Messages sent while offline are queued (single ✓) and transmitted on reconnect, preserving their original send time.
- Messages to an offline peer stay at one check until that peer returns; the offline client holds them back and surfaces them on reconnect with a notice.
- WhatsApp-style per-message delivery status (sending → sent → delivered, plus a "not sent" state) via an authenticated delivery-receipt control message.
- Browser offline state no longer leaks into the P2P connection indicator.

Resilient file transfer: per-chunk segmented progress, receiver-driven retransmission of missing chunks with auto-resume after a connection blip, corrected receive rate limits, and automatic save on completion.

## v4.8.21 — Redesigned chat surface

A full visual refresh of the connected chat experience, ported from the SecureBit Chat design. No protocol, crypto or message-handling changes — only the presentation layer of the chat screen.

### Changed

- **Message bubbles** redesigned: tighter dark surface (`#0f0f11` canvas, `#26262b` sent / `#161618` received), asymmetric corner radii, monospace timestamps, and a compact per-message status row showing **Encrypted** / **Decrypted** with a lock glyph.
- **View-once** now uses a Telegram-style blurred cover with an SVG grain overlay and a centered "View once · tap to reveal" prompt; after reveal it shows a "Viewed once" tag and still burns after the sender-chosen window.
- **Disappearing timers** render a live `mm:ss` countdown in the message meta in brand orange.
- **Composer** rebuilt: inline `Send files` / `Code` / `View once` / `Timer` chips with active states, inline time-picker rows (view-once: Off/5s/10s/30s/1m, timer: Off/5s/30s/1m/1h/24h), an auto-growing message field, an "Encrypted on your device" affordance, a live character counter, and an orange send button.
- **Handshake summary** card at the top of a verified chat (collapsible): transport / cipher / key-exchange / integrity facts plus the safety number (key fingerprint).
- Fonts are mapped to the self-hosted **Inter** + system monospace stack rather than loading Google Fonts, preserving the look without an external request from a privacy-focused client.

## v4.8.20 — Secure chat tools: completed, fixed and polished

Completes the messaging controls introduced in v4.8.14 and fixes the bug that made them appear broken for recipients. All per-message options travel inside the encrypted message envelope (never in the sanitized text), so message content cannot spoof or corrupt them.

### Fixed

- **Per-message metadata was silently dropped for recipients.** `NotificationIntegration` wrapped both `webrtcManager.onMessage` and `webrtcManager.deliverMessageToUI` with two-argument shims that called the originals without the third argument (`meta`). With notifications enabled, every received message lost its `meta`, so view-once, disappearing timers and unsend all failed on the recipient side. Both wrappers now forward all arguments (`...rest`). Added `tests/notification-meta-forwarding.test.mjs`.
- **Chat would not open after SAS** (regression from the initial wiring): the composer props were threaded into the wrong component (`EnhancedConnectionSetup` instead of `EnhancedChatInterface`), throwing `ReferenceError: nowTick` on the verified-state re-render. Props are now on the chat component.

### Changed

- **Code blocks** now include lightweight, dependency-free syntax highlighting (comments, strings, numbers, keywords) rendered via React nodes — no `innerHTML`, no remote scripts. Enabling code mode expands the input (monospace, 8 rows) for comfortable entry. Copying a block auto-clears the clipboard after ~30s.
- **View-once** is now configurable: the sender picks how long the message stays visible after the peer opens it (5s / 15s / 30s / 1m) via `meta.onceTtl` (clamped 1s–1h).
- **Disappearing timer** uses a duration picker (Off / 30s / 5m / 1h) instead of click-cycling.
- **Composer toolbar** moved next to the "Send files" control; borderless buttons with the brand-orange (`accent-orange`) active state; time pickers open upward and are sized for mobile readability.
- Sender bubble background lightened to `rgba(249, 115, 22, 0.05)`.

### Removed

- **Panic wipe** button. Disconnecting already wipes keys and clears session state, so a separate panic control was redundant.

## v4.8.15 — Fix: chat would not open after SAS in v4.8.14

### Fixed

- The secure chat failed to open after both peers confirmed the SAS code: the message list and composer (in `EnhancedChatInterface`) referenced `nowTick`, `onUnsendMessage` and the new composer props, but those were threaded into the sibling `EnhancedConnectionSetup` component by mistake. At runtime this threw `ReferenceError: Can't find variable: nowTick` during the verified-state re-render, so the chat never rendered. The new props are now destructured and passed on `EnhancedChatInterface`, where the chat UI actually lives. No behavioural change to the v4.8.14 features otherwise.

## v4.8.14 — Secure chat tools: code blocks, view-once, disappearing, unsend, panic

Adds privacy-focused messaging controls. Per-message metadata (id, view-once, timer) travels **inside the encrypted message envelope**, never in the sanitized text, so message content cannot spoof or corrupt these controls. The unsend/delete signal travels over the authenticated DTLS control channel like other system messages.

### Added

- **Code blocks.** A composer button wraps the message in a fenced block; both peers render it as a monospace code window with a copy button. The marker travels as ordinary text, and the window is built from already-sanitized text via React nodes only (no `dangerouslySetInnerHTML`), so there is no new XSS surface.
- **Clipboard auto-clear.** Copying a code block clears the clipboard after ~30s — only when it can confirm the clipboard still holds the copied value, or cannot read it back, so a later copy is never clobbered.
- **View-once messages.** The recipient sees a blurred bubble that reveals on tap and is then wiped. Honestly cooperative (a malicious client or a screenshot can still capture it) — this is hygiene, not a guarantee.
- **Disappearing messages.** An optional sticky timer (30s / 5m / 1h) auto-deletes a message on both sides, with a live countdown. The incoming timer value is clamped to [5s, 24h].
- **Unsend (delete for everyone).** Removes your message locally and asks the peer to drop it via a `message_delete` control message (`MESSAGE_TYPES.MESSAGE_DELETE`).
- **Panic wipe.** One button clears the conversation, wipes keys (`_secureWipeKeys`) and tears down the session, behind a confirm prompt.

### Security

- New per-message metadata is whitelisted and bounded by `_sanitizeMessageMeta` on both send and receive; unknown fields, wrong types and out-of-range timers are dropped.
- AAD/replay protection, the SAS verification gate and receive-side DOMPurify sanitization are unchanged.

### Tests

- Added `tests/secure-chat-features.test.mjs` covering metadata sanitization, meta delivery to the UI, and the unsend control path. Full suite: 17 files, all passing.

## v4.8.13 — Message integrity & transport hardening

Security review follow-up. The end-to-end cryptography (ECDH, AES-GCM, PBKDF2, SAS bound to DTLS fingerprints, anti-replay) was verified sound; these changes fix availability/integrity defects on the send path and tighten transport headers and logging.

### Fixed

- Outgoing messages were silently rejected by an over-broad keyword blocklist in `_validateInputData`. Plain words such as "constructor", "global", "document.", "prototype", or the literal text "javascript:" caused `sendSecureMessage` to throw, so legitimate messages never reached the peer. The blocklist provided no real protection: XSS is enforced at the rendering boundary by the receive-side DOMPurify pass and by `sanitizeMessage()` before encryption. The send-path blocklist was removed.
- `_sanitizeInputString` collapsed all whitespace (`/\s+/g` to a single space), destroying multi-line messages and code snippets (`"a\nb\nc"` became `"a b c"`). Newlines, tabs and indentation are now preserved; only control characters are stripped and runs of 3+ blank lines are collapsed to two.
- AAD validation failures logged the raw AAD string, which carried `sessionId` and `keyFingerprint`. Both the message and file-message validators now log only the AAD length.

### Security

- Added `Strict-Transport-Security` (`max-age=63072000; includeSubDomains; preload`) to `deploy/nginx.conf` and `.htaccess`, closing the first-visit SSL-strip window that `upgrade-insecure-requests` alone does not cover.
- Added a restrictive `Permissions-Policy` (`camera=(self)` for in-page QR scanning; microphone, geolocation, payment, usb and sensors denied).

### Tests

- Added `tests/outgoing-message-integrity.test.mjs` covering keyword acceptance, multi-line/indentation preservation, control-character stripping, blank-line collapsing, and the size limit.

## v4.8.12 — Chat notification & file-transfer UI fixes

Fixes duplicated chat output and a layout overflow in the message list.

### Fixed

- A received file was announced many times in the chat instead of once. The per-transfer lock used a single `if` check, so when 3+ chunk operations queued on the same file they ran concurrently and broke assembly atomicity. The lock now serializes correctly, and file assembly is idempotent, so `File received` is shown exactly once per file.
- System messages were duplicated during connection setup (e.g. "Both parties confirmed!" and "Secure connection successfully established"). `handleVerificationBothConfirmed` now bails out if both confirmations were already recorded, so the message and the verified transition fire only once.
- The DTLS fingerprint (a long unbroken string) overflowed the chat bubble. The message text container now uses `min-w-0` so the fingerprint wraps within the bubble.
- Site header, init banner, and manifest now report the current version.

## v4.8.11 — File transfer reliability fix

Fixes file transfers that silently failed to reach the peer, and relaxes the overly strict file-type check that rejected legitimate files.

### Fixed

- File chunks are now sized so the on-the-wire message stays under the 64 KB SCTP message-size limit enforced by WebRTC. Previously each 64 KB chunk became a ~87 KB encrypted+Base64 message that exceeded this limit, so the consent handshake succeeded but no data was ever delivered — most visibly on Safari and cross-browser connections whose SDP omits `a=max-message-size`. The send chunk size is now 16 KB (~22 KB on the wire); inbound chunks up to 64 KB are still accepted for backward compatibility.

### Changed

- File-type validation is now driven by the extension allow-list, with the (client-supplied, easily spoofed) MIME type treated as an advisory signal. Files with a missing MIME type or a cross-OS MIME variant (e.g. `application/x-zip-compressed` for `.zip`, `image/jpg` for `.jpg`) are no longer rejected. Blocked executable/script extensions, a blatantly foreign MIME on a safe extension, and per-type size limits are still enforced.

## v4.8.10 — User-configurable STUN/TURN servers

Adds optional, advanced control over WebRTC connectivity for power and privacy-focused users. Public servers remain the zero-config default.

### Added

- "Advanced network settings" panel (header gear icon and the connection-creation screen) where users can supply their own STUN/TURN servers instead of the bundled public defaults.
- Allowlist-based validation of user input: only `stun:`/`stuns:`/`turn:`/`turns:` URLs with valid hosts are accepted; `javascript:`, `data:`, `http(s):`, `ws(s):`, control characters, and oversized input are rejected before anything reaches `RTCPeerConnection`.
- Optional on-device persistence, encrypted at rest with a non-extractable AES-GCM device key in IndexedDB, with an explicit save prompt and a "Forget saved" action.
- "Test servers" button that gathers ICE candidates against the entered configuration and reports STUN/TURN reachability.
- Privacy guidance in the panel: a TURN relay sees peer IPs and traffic timing (never message contents), so only a trusted/self-hosted relay improves privacy.

### Changed

- Relay-only privacy mode now lives in the advanced settings panel. The standalone relay-only toggle on the start screen was removed to declutter the initial view.
- Server selection priority: user custom servers > operator override (`config/ice-servers.js`) > built-in public defaults.

## v4.8.9 — Security hardening patch

This release closes a vulnerable dependency, removes committed TURN credentials, and tightens production logging.

### Security

- Upgraded DOMPurify from 3.4.4 to a patched release, resolving a high-severity XSS advisory (GHSA-87xg-pxx2-7hvx) in the incoming-message sanitizer.
- Upgraded the `esbuild` build dependency to clear a high-severity advisory in the toolchain. `npm audit` now reports zero vulnerabilities.
- Stopped tracking `config/ice-servers.js` (operator TURN credentials) in Git and added `config/ice-servers.example.js` as a template. Operators must rotate any previously committed credentials.
- Removed temporary debug branches from the production logger so it no longer prints error context or info/debug payloads — only an opaque error code.

### Documentation

- Updated the supported-release table in `SECURITY.md` to the v4.8.x line.
- Synchronized the version string across the header, manifest, README, and in-app initialization message.

## v4.8.8 — File transfer consent fix

This patch completes the mandatory receiver-consent gate for incoming file transfers and resolves a callback ownership conflict that caused every incoming file request to be silently auto-rejected.

### Fixed

- Wired up the missing fourth `onIncomingFileRequest` callback in the main `setFileTransferCallbacks` call. Without it, `handleFileTransferStart` always saw `null` for the consent handler and auto-rejected every incoming file silently.
- Removed independent callback registration from `FileTransferComponent`. The component was overwriting the application-level callbacks on mount and nulling all four on unmount, which destroyed the progress, received, and error handlers whenever the panel was hidden.
- Centralized incoming-consent state (`pendingIncomingFiles`) in the root application component so consent prompts appear regardless of whether the file-transfer panel is currently visible.
- Auto-opens the file-transfer panel when an incoming request arrives so the user sees the Accept / Reject prompt immediately.
- Added `getReceivedFileObjectURL` / `revokeReceivedFileObjectURL` helpers to `EnhancedSecureWebRTCManager` so the panel can offer a download button for completed transfers without relying on captured callback closures.
- Updated `file-transfer-ui-cleanup` regression test to match the new single-owner callback architecture.

### Security

No change to the cryptographic or transport-level security model. Sender chunks are still gated behind an explicit `file_transfer_response` from the receiver before any data is transmitted.

### Verification

- `npm test` — all 14 tests pass.
- `npm run build` — clean production build.

## v4.8.7 — WebRTC manual join reliability patch

This patch improves manual WebRTC setup across separate devices and restrictive local networks.

### Fixed

- Stabilized the manual offer/answer join flow so verification waits for real transport readiness.
- Preserved generated response data during manual exchange instead of resetting the joiner screen prematurely.
- Preserved pending creator-side offer context so responses can be applied after transient ICE failures without false session-salt hijacking errors.
- Added operator ICE override support through `config/ice-servers.js`.
- Added ExpressTURN TURN/STUN configuration for relay fallback in environments where mDNS host candidates cannot connect.
- Added user-visible warning when a remote peer provides only mDNS host candidates and no `srflx` or `relay` route.
- Added safer ICE diagnostics that report candidate classes without exposing full IP addresses or TURN credentials.

### Verification

- `npm test`
- `npm run build`

## v4.8.7 — Security hardening patch release

This patch release strengthens SecureBit.chat across verification, sanitization, privacy, transport abuse resistance, cache safety, and repository hygiene.

### Security hardening

- Bound SAS verification to the actual DTLS fingerprint strings of both peers.
- Replaced regex-based chat sanitization with DOMPurify-backed sanitization.
- Made WebRTC privacy mode explicit and kept relay-only state synchronized at runtime.
- Removed production exposure of internal debug/control hooks.
- Added receiver-side rate limiting for inbound chat messages.
- Added receiver-side throttling for inbound file chunks.

### Runtime and privacy safety

- Hardened service-worker caching so only explicitly allowlisted safe assets are cached.
- Removed an untracked disconnect timer so teardown no longer leaves delayed callbacks behind.
- Preserved relay-only TURN behavior while making privacy implications clearer when relay-only mode is disabled or TURN is unavailable.

### Repository hygiene

- Stopped tracking `node_modules` in Git so platform-specific dependency binaries no longer pollute the repository or break cross-platform builds.

### Validation

- Full regression suite passes.
- Clean install succeeds with `npm ci`.
- Production build succeeds with `npm run build`.

## v4.8.7 — Security hardening release

This release consolidates several months of security, privacy, and lifecycle hardening work by the SecureBit.chat team.

### Security

- Added mandatory interactive SAS verification; passive click-through confirmation is no longer sufficient.
- Made SAS computation deterministic across peers using shared session material.
- Enforced protocol version `4.1` mismatch handling for incompatible clients.
- Added TURN relay-only privacy mode and explicit warnings when TURN is unavailable.
- Encrypted sensitive IndexedDB metadata and added safe lazy migration for legacy plaintext records.
- Added mandatory consent gating for every incoming file transfer.
- Replaced broad file acceptance with an explicit file-type allowlist and spoofing checks.
- Sanitized every incoming decrypted chat message before UI delivery.

### Reliability and resource lifecycle

- Consolidated disconnect behavior into one canonical cleanup path.
- Added cleanup for tracked timers, deferred retries, peer-disconnect scheduling, and fake/decoy traffic.
- Rejected pending sender consent promises immediately during cleanup.
- Bounded retained received-file buffers and added graceful handling for expired download handles.
- Cleared React file-transfer UI state and detached live callbacks on unmount.
- Improved reconnect hygiene and stale-session cleanup behavior.

### Maintenance

- Pinned dependency versions.
- Applied safe transitive patch/minor updates.
- Verified a clean `npm audit` result.
- Expanded regression coverage for SAS, file consent, sanitization, privacy mode, metadata encryption, cleanup, and callback lifecycle behavior.
