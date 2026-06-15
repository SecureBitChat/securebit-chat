# Changelog

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
