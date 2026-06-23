# Changelog

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
