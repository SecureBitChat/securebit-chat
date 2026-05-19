# SecureBit.chat v4.8.7

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

## Highlights in v4.8.7

- Manual WebRTC setup now preserves pending offer/answer state during slow out-of-band exchange.
- TURN relay fallback can be configured through `config/ice-servers.js` for restrictive networks.
- ICE diagnostics now identify mDNS-only candidate failures without exposing full peer IPs.

This patch release strengthens the existing security model with a focused hardening pass:

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
