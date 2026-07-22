# Security Architecture

## Current baseline

| Area | Current behavior |
| --- | --- |
| Protocol | `4.1` with mismatch rejection |
| Peer verification | mandatory manual SAS entry |
| Transport | WebRTC over DTLS |
| Privacy mode | optional TURN relay-only mode |
| Message UI safety | incoming decrypted text sanitized before display |
| File transfer | validated metadata, explicit consent, allowlist policy |
| Voice messages | same chunked AES-GCM transfer as files; auto-accepted and played inline |
| Local metadata | encrypted IndexedDB envelopes with migration |
| Lifecycle | unified disconnect cleanup and bounded resource retention |

## Verification state machine

```text
connection established
        ↓
shared keys derived
        ↓
deterministic SAS displayed
        ↓
manual out-of-band comparison
        ↓
local input validated
        ↓
peer confirmation received
        ↓
verified session
```

The verified state is reached only when both local and remote confirmation flags are true.

## File-transfer architecture

1. sender emits metadata
2. receiver validates name, size, type, and abuse limits
3. receiver sees Accept / Reject prompt
4. no receive buffers are allocated before acceptance
5. sender transmits chunks only after acceptance
6. completed received buffers are retained within a bounded window

## Voice messages

Voice notes reuse the file-transfer pipeline, so they inherit its per-file
AES-GCM session key, chunking, and SHA-256 integrity check. Differences from a
regular file:

1. audio is recorded in-browser and encoded as PCM/WAV before sending
2. duration and a downsampled waveform travel as **unsigned** presentation
   metadata; the audio bytes remain integrity-protected by the signed file hash
3. the receiver **auto-accepts** voice transfers (no consent prompt) and plays
   them inline from an in-memory blob — nothing is written to disk

## Disconnect cleanup

The canonical disconnect path clears:

- WebRTC channels and peer connection handles
- timers, deferred retries, fake traffic, and decoy traffic
- pending transfer state and consent waits
- verification state and crypto/PFS state
- React file-transfer callbacks and stale UI transfer state
