# Security Architecture

## Current baseline

| Area | Current behavior |
| --- | --- |
| Protocol | `4.1` with mismatch rejection |
| Peer verification | mandatory manual SAS entry; control messages gated on it |
| Forward secrecy | Double Ratchet (wire version `1`), negotiated per session |
| Transport | WebRTC over DTLS |
| Privacy mode | optional TURN relay-only mode |
| Message UI safety | one authenticated inbound path; decrypted text sanitized before display |
| File transfer | validated metadata, explicit consent, allowlist policy |
| Voice messages | same chunked AES-GCM transfer as files; auto-accepted within audio-type and size limits |
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

The verified state is reached only when both local and remote confirmation flags are true, and it is set in a single place so the transition cannot be reached by another route.

Verification is enforced, not merely displayed. Before it completes, the session declines to act on control messages from the peer — reconnection signalling, call setup, message deletion and delivery receipts. Only the verification exchange itself and liveness probes run earlier, because they have to.

## Message protection layers

```text
                 ECDH (P-384)
                      ↓
              HKDF key schedule
        ┌─────────┬───────┬──────────┬─────────────┐
        ↓         ↓       ↓          ↓             ↓
    message     MAC   metadata  fingerprint   ratchet root
      key       key      key      (→ SAS)          ↓
                                            Double Ratchet
                                          per-message keys
```

Chat content is encrypted under a ratchet-derived key when both peers support it, and under the session message key otherwise. Either way it reaches the interface through one authenticated path; frames that fail authentication are dropped rather than displayed.

## Forward secrecy

Per-message keys are derived from a chain key by a one-way function and destroyed after use, and each change of direction introduces a fresh ECDH key pair that re-keys the session root. Out-of-order delivery is supported within fixed bounds (512 skipped keys per chain, 1024 retained in total, five-minute expiry), which limits how much state a peer can cause to be held. Incoming frames are authenticated before any ratchet state is committed, so a bad frame cannot desynchronise a live session.

See [`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md) for the key schedule and framing details.

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

The auto-accept decision belongs to the receiver, not the sender. A transfer
qualifies only if it declares a recognised audio MIME type and stays within a
4 MB per-note limit and a per-session budget; anything else is handled as an
ordinary file and goes through the normal consent prompt. This keeps the
convenience of voice notes from becoming an unattended transfer channel.

## Disconnect cleanup

The canonical disconnect path clears:

- WebRTC channels and peer connection handles
- timers, deferred retries, fake traffic, and decoy traffic
- pending transfer state and consent waits
- verification state and crypto/PFS state
- ratchet state: root key, both chain keys and every retained message key are
  overwritten, not merely dereferenced
- React file-transfer callbacks and stale UI transfer state
