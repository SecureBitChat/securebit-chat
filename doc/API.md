# API Notes

## EnhancedSecureWebRTCManager

### Verification

- `confirmVerification(userCode)` validates a manually entered SAS code.
- Verification succeeds only after both local and remote confirmations are present.
- Protocol version `4.1` is enforced during offer/answer processing.

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
