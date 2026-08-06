# API Notes

## EnhancedSecureWebRTCManager

### Verification

- `confirmVerification(userCode)` validates a manually entered SAS code.
- Verification succeeds only after both local and remote confirmations are present.
- `isVerified` is assigned in one place (`_setVerifiedStatus`), which refuses any
  SAS-based transition without a recorded local confirmation.
- Control frames listed in `POST_VERIFICATION_CONTROL_TYPES` (reconnection
  signalling, call setup, message deletion, delivery receipts) are only acted on
  after verification. The set is an allowlist; unrecognised frame types are
  rejected by the chat channel's default-deny branch.
- Protocol version `4.1` is enforced during offer/answer processing.

### Forward secrecy

- `isRatchetActive()` reports whether the Double Ratchet is running on this
  connection. It is negotiated: both peers advertise `RATCHET_VERSION` in the
  offer and answer, and a peer that does not falls back to per-session keys.
- `_ratchet.canEncrypt` is false on the joining peer until the inviting peer's
  first message arrives — the sending chain does not exist until then. Callers
  must check it rather than assume; the send path falls back to session keys for
  those first frames.
- `_ratchet.getState()` returns counters and the number of retained keys for
  diagnostics. It exposes no key material.
- Ratcheted chat arrives as `MESSAGE_TYPES.RATCHET_MESSAGE` with `h` (the header
  string, used verbatim as AES-GCM additional data) and `c` (base64 body). The
  header must be passed back to `decrypt()` exactly as received; re-serialising
  it can change a byte and fail authentication.

### Privacy mode

- relay-only configuration sets WebRTC `iceTransportPolicy` to `"relay"`.
- TURN availability is checked before claiming IP protection.

### File transfer callbacks

- `setFileTransferCallbacks(onProgress, onReceived, onError, onIncomingRequest)` updates manager fields and any live `EnhancedSecureFileTransfer` instance.
- Passing `null` values detaches callbacks from the active transfer system.

### Voice messages

- `sendFile(file, options)` accepts an optional `options` object. `options.voice`
  (`{ dur, bars }`) marks the transfer as a voice note and rides along as unsigned
  metadata; `options.uiId` correlates progress events to a UI bubble before the
  `fileId` resolves.
- `onProgress` receives `{ fileId, uiId, direction, progress, isVoice, voice }`.
  `onIncomingFileRequest` and `onReceived` include `isVoice` and `voice` so the UI
  can auto-accept and render a voice bubble instead of a file card.
- The `isVoice` a callback receives is the **receiver's** verdict, not the
  sender's claim: `validateIncomingMetadata` clears it unless the transfer
  declares a recognised audio MIME type and fits the per-note and per-session
  size budgets. A transfer that fails those checks is not rejected — it simply
  loses the consent-free shortcut and is offered as a normal file.

## EnhancedSecureFileTransfer

### Incoming transfers

- metadata is validated before prompting
- acceptance is explicit
- receive buffers are allocated only after consent
- file type acceptance is allowlist-based

### Cleanup

- pending sender consent promises are rejected on cleanup
- consent timeouts are cleared immediately
- retained received buffers are bounded
- evicted download handles fail with a user-facing availability message

## SecurePersistentKeyStorage

- metadata is encrypted before storage
- legacy plaintext records migrate lazily
- corrupted encrypted metadata is ignored safely
