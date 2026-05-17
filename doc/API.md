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
