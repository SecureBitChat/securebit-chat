# SecureBit.chat v4.8.20

SecureBit.chat is a browser-based peer-to-peer chat application built on WebRTC and Web Crypto APIs. It is designed for direct encrypted communication, explicit peer verification, and a small operational footprint without account registration or server-side message storage.

## Security model

SecureBit.chat uses:

- ECDH key agreement with derived session keys
- DTLS-protected WebRTC transport
- deterministic Short Authentication String (SAS) verification
- end-to-end encrypted chat payloads
- replay protection and session-state cleanup
- encrypted local key metadata in IndexedDB

A session is not treated as verified until both peers complete the interactive SAS flow. Each user must compare the displayed code with the peer through an out-of-band channel and enter the matching code manually. Three failed SAS attempts terminate the session.

## Highlights in v4.8.20

Secure messaging controls, available from a single composer toolbar next to **Send files**. Active controls use the brand-orange accent. Every per-message option travels **inside the encrypted message envelope** (never in the sanitized text), so message content can neither spoof nor corrupt these controls.

- **Code blocks.** A `Code` button sends the message as a monospace code window with lightweight syntax highlighting and a one-click **Copy** button; the clipboard auto-clears ~30s after copying so keys/commands don't linger. Enabling it also expands the input box (monospace, 8 rows) for comfortable code entry. Highlighting is built from already-sanitized text via React nodes only — no `innerHTML`, no remote scripts, no new XSS surface.
- **View-once messages.** Pick how long the message stays visible after the peer opens it (5s / 15s / 30s / 1m). The recipient sees a blurred bubble; tapping reveals it, then it is wiped after the chosen window. Cooperative, like WhatsApp view-once — it reduces accidental lingering but is **not** screenshot-proof.
- **Disappearing messages.** A timer picker (30s / 5m / 1h) auto-deletes the message on **both** sides, with a live countdown. The incoming timer is clamped to a safe range.
- **Unsend (delete for everyone).** Removes your message locally and asks the peer to drop it too, over the authenticated control channel.

Earlier in v4.8.13:

- Security/integrity: outgoing chat messages are no longer silently rejected by an over-broad keyword blocklist (plain words like "constructor", "global", "document." or the literal text "javascript:" were being blocked). XSS is still prevented at the rendering boundary by the receive-side DOMPurify pass and by message sanitization before encryption.
- Integrity: multi-line messages and code snippets keep their newlines and indentation instead of being collapsed onto a single line.
- Privacy: AAD validation failures no longer log the raw AAD (which carried `sessionId` and `keyFingerprint`); only its length is logged.
- Hardening: production now sends `Strict-Transport-Security` (2-year, preload) and a restrictive `Permissions-Policy` (camera kept for in-page QR scanning; microphone, geolocation and sensors denied).

Earlier in v4.8.11:

- Fixed: file transfers that completed the consent handshake but never delivered any data. Chunks are now sized to stay under WebRTC's 64 KB SCTP message limit (most visible on Safari and cross-browser connections).
- File-type validation is now extension-driven; the easily-spoofed MIME type is advisory, so files with a missing or cross-OS MIME variant are no longer wrongly rejected. Blocked executable/script extensions and size limits are still enforced.

Earlier in v4.8.10:

- New: users can configure their own STUN/TURN servers under "Advanced network settings" (header gear or the connection-creation screen). Input is allowlist-validated, optionally saved encrypted on-device, and a built-in "Test servers" check reports STUN/TURN reachability.
- Relay-only privacy mode moved into the advanced settings panel; the standalone start-screen toggle was removed.

Earlier in the v4.8 hardening line:

- Patched a high-severity XSS advisory in the DOMPurify dependency (the message sanitizer) by upgrading to a fixed release.
- Operator TURN credentials are no longer committed to the repository; use `config/ice-servers.example.js` as a template.
- The production logger no longer prints error context or info/debug output, only opaque error codes.

- Manual WebRTC setup preserves pending offer/answer state during slow out-of-band exchange.
- TURN relay fallback can be configured through `config/ice-servers.js` for restrictive networks.
- ICE diagnostics identify mDNS-only candidate failures without exposing full peer IPs.

- SAS verification is bound to the actual DTLS fingerprint strings of both peers
- chat sanitization uses DOMPurify-backed text-only output
- WebRTC privacy mode is explicit and relay-only state stays synchronized at runtime
- production debug window hooks are gated behind an explicit debug flag
- receiver-side throttling covers inbound messages and file chunks
- service-worker caching is restricted to an explicit safe-asset allowlist
- disconnect cleanup leaves no orphaned delayed timer behind
- `node_modules` is no longer tracked in Git

## Quick start

### Run locally

```bash
npm install
npm run build
npm run serve
```

Then open the local server URL in two browser windows or profiles.

### Establish a session

1. Create an offer in the first browser.
2. Transfer the offer to the peer and create an answer.
3. Return the answer to the first browser.
4. Compare the SAS code out of band.
5. Enter the matching SAS code on both sides.
6. Begin chatting only after both peers are verified.

## Configuration

### TURN / privacy mode

Direct WebRTC connections may expose IP addresses to peers. SecureBit.chat supports a relay-only privacy mode:

- default mode keeps normal WebRTC behavior and existing STUN support
- relay-only mode sets `iceTransportPolicy: "relay"`
- relay-only mode requires a configured TURN server
- STUN alone does not hide IP addresses
- public TURN credentials are not bundled or hardcoded

Configure ICE servers at deployment time and enable relay-only mode only when a TURN service is available. See [`doc/CONFIGURATION.md`](doc/CONFIGURATION.md).

### File transfer policy

Incoming file transfers require explicit user consent. Before the consent prompt appears, metadata is validated and dangerous names are rejected. Safe accepted categories are:

- common raster images
- PDF
- plain text
- ZIP archives

Executable, scriptable, and high-risk formats are rejected, including `.exe`, `.bat`, `.cmd`, `.sh`, `.js`, `.msi`, `.dmg`, `.app`, `.jar`, `.scr`, `.ps1`, `.vbs`, `.html`, and `.svg`. MIME type and filename extension must agree.

## Development

### Requirements

- Node.js 18+
- npm

### Commands

```bash
npm install
npm test
npm audit
npm run build
npm run dev
```

### Project layout

```text
src/network/   WebRTC connection and session lifecycle
src/transfer/  secure file-transfer implementation
src/crypto/    cryptographic utilities
src/components React UI components
doc/           technical documentation
```

## Documentation

- [`SECURITY.md`](SECURITY.md)
- [`doc/CONFIGURATION.md`](doc/CONFIGURATION.md)
- [`doc/CRYPTOGRAPHY.md`](doc/CRYPTOGRAPHY.md)
- [`doc/SECURITY-ARCHITECTURE.md`](doc/SECURITY-ARCHITECTURE.md)
- [`doc/API.md`](doc/API.md)
- [`CHANGELOG.md`](CHANGELOG.md)

## Responsible use

SecureBit.chat is intended for lawful, ethical use. See [`RESPONSIBLE_USE.md`](RESPONSIBLE_USE.md) and [`SECURITY_DISCLAIMER.md`](SECURITY_DISCLAIMER.md).

## License

MIT License. See [`LICENSE`](LICENSE).
