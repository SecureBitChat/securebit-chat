# Security Policy

## Supported release line

| Release | Status | Protocol |
| --- | --- | --- |
| v4.8.x | Supported | 4.1 |
| v4.1.x – v4.7.x | Unsupported | 4.1 |
| earlier releases | Unsupported | legacy |

Users should run the current supported release line to receive the latest verification, storage, and file-transfer protections.

## Reporting a vulnerability

Please report security issues privately before public disclosure.

- Email: `SecureBitChat@proton.me`
- Include: affected version, reproduction steps, impact, and any proof-of-concept material
- Avoid publishing exploit details before a coordinated fix is available

## Current security behavior

### Peer verification

- SAS verification is mandatory and interactive.
- SAS values are derived deterministically from shared session material.
- Users must compare the code out of band and enter the matching code manually.
- A session becomes verified only after both local and remote confirmations succeed.
- Three failed local SAS entries terminate the session.
- Protocol version `4.1` rejects incompatible peers instead of silently falling back to older verification behavior.

### Message handling

- Chat payloads remain encrypted in transit.
- Decrypted incoming chat text is sanitized before it reaches React state or the UI.
- Encrypted payload validation remains separate from display sanitization.

### File transfer

- Incoming transfer metadata is validated before presentation to the user.
- Every incoming file requires explicit Accept or Reject consent.
- Receive buffers are not allocated before consent.
- File names are normalized for display and dangerous names are rejected.
- Allowed file types are explicit and validated using both MIME type and extension.
- High-risk executable or scriptable types are blocked.
- Repeated incoming transfer offers are rate-limited and bounded.

### Local storage

- Sensitive IndexedDB metadata is encrypted, including timestamps and session-related fields where feasible.
- Only minimum lookup keys remain in plaintext when required.
- Legacy plaintext metadata is migrated lazily on read.
- Corrupted encrypted metadata fails closed.

### Network privacy

- Default mode preserves standard WebRTC connectivity.
- Relay-only privacy mode uses TURN by setting `iceTransportPolicy: "relay"`.
- STUN-only configurations do not provide IP protection.
- If TURN is absent, the UI warns that direct WebRTC may expose IP addresses.

### Lifecycle cleanup

- Disconnect cleanup closes data channels and peer connections, clears verification state, and wipes session crypto state.
- Timers, deferred retries, decoy traffic, pending transfers, and React file-transfer callbacks are cleaned up on shutdown.
- Received file buffers are retained only within a bounded window and expired handles fail gracefully.

## Security verification commands

```bash
npm audit
npm test
npm run build
```

## Limitations

- A compromised endpoint can still expose plaintext.
- WebRTC privacy depends on deployment configuration; TURN must be supplied by the operator.
- Users must perform the out-of-band SAS comparison correctly.
- Browser security and operating-system security remain part of the threat model.
