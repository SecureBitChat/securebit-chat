# Configuration Guide

## Requirements

- modern browser with WebRTC and Web Crypto support
- Node.js 18+ for local development
- TURN service only when relay-only privacy mode is required

## Local setup

```bash
npm install
npm run build
npm run serve
```

## ICE server configuration

SecureBit.chat keeps existing STUN support for ordinary WebRTC connectivity. Deployments that require relay-only privacy must provide their own TURN service credentials through deployment configuration; public TURN credentials are intentionally not bundled.

### Privacy modes

| Mode | Behavior | IP privacy |
| --- | --- | --- |
| default | standard WebRTC candidate gathering | direct candidates may expose IP addresses |
| relay-only | `iceTransportPolicy: "relay"` | requires TURN and avoids direct peer candidates when configured correctly |

### Operational rules

- STUN is not a privacy substitute for TURN.
- Relay-only mode without TURN cannot establish a working relay connection.
- The UI warns users when TURN is missing.
- Validate TURN deployment with browser WebRTC diagnostics before production rollout.

## Verification flow

Protocol `4.1` requires interactive SAS verification:

1. both peers derive the same SAS from shared session material
2. users compare the code out of band
3. each user enters the matching code manually
4. the chat unlocks only after both confirmations succeed

Three failed local attempts disconnect the session.

## File-transfer policy

Incoming file requests are validated before the consent prompt and require explicit user approval.

Allowed categories:

- common raster images
- PDF
- plain text
- ZIP archives

Blocked examples:

- `.exe`, `.bat`, `.cmd`, `.sh`, `.js`
- `.msi`, `.dmg`, `.app`, `.jar`, `.scr`
- `.ps1`, `.vbs`, `.html`, `.svg`

Both MIME type and extension must be acceptable. Missing or unknown MIME types are treated as unsafe unless explicitly covered by policy.
