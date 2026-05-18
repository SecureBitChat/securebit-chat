# Changelog

## v4.8.6 — Security hardening patch release

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

## v4.8.5 — Security hardening release

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
