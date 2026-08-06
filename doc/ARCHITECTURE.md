# Architecture

SecureBit.chat is a browser application with no backend. Two browsers negotiate a
direct WebRTC connection, derive keys from an ECDH exchange, and confirm each
other's identity by comparing a short code out of band. Everything after that
runs between the two endpoints.

There is no server in the message path, and there is no signalling service. The
offer and the answer are moved between the two people by whatever channel they
already have (a QR code, a pasted block of text, a link). That choice shapes the
rest of the design: the out-of-band channel is untrusted, so the protocol assumes
an attacker can read and rewrite anything travelling over it, and the safety code
comparison is what closes that gap.

## Session lifecycle

```text
1. Invitation      Peer A generates its key pairs and an SDP offer, and exports a
                   compact descriptor: ICE candidates, the DTLS certificate
                   fingerprint, an expiry, and a 16-byte commitment to its key
                   material. 110-150 bytes; one QR code. No keys travel in it.

2. Response        Peer B validates the descriptor strictly, answers the SDP, and
                   returns a descriptor of the same shape, tagged so that it can
                   only be an answer to this particular invitation.

3. Transport up    DTLS completes and the data channel opens. Only the peer
                   holding the private key behind the fingerprint in the
                   invitation can reach this point.

4. Key exchange    Each side sends its public keys over the open channel as the
                   first frame. Each verifies the other's blob against the
                   commitment from the invitation BEFORE parsing it, then derives
                   the session from a transcript of both descriptors and both
                   blobs, and signs that transcript to prove it owns its identity
                   key. Any failure closes the connection.

5. Verification    Both sides display the same safety code, derived from that
                   transcript. The users compare it over a channel an attacker
                   cannot impersonate and enter it.

6. Verified        Only now does the session accept traffic that changes state,
                   and only now does the chat open.
```

Steps 3 and 4 are the ones worth dwelling on. The fingerprint in the invitation
authenticates the transport to whoever showed you the code, and the commitment
means substituted key material is refused automatically rather than noticed by a
human. But neither proves *who* showed you the code. Anyone positioned on the
out-of-band channel can rewrite the whole invitation, commitment included, and
complete steps 3 and 4 with both people at once. Step 5 is the only step that
distinguishes the intended peer, so everything that could be useful to an
impostor waits for it — and because the safety code is computed over the full
transcript, a rewritten handshake cannot produce matching digits.

The invitation format and its decoder rules are in
[DESCRIPTOR-SBQ2.md](DESCRIPTOR-SBQ2.md).

## What verification gates

Verification is enforced, not merely displayed. Until both sides confirm:

- reconnection signalling is refused
- call setup is refused
- message deletion and delivery receipts are refused
- incoming file transfers are refused

The verification exchange itself and liveness probes run earlier, because they
have to. That set is an allowlist in the code
(`POST_VERIFICATION_CONTROL_TYPES`), and anything not on it is rejected by
default rather than passed through.

The verified state is set in one place, which refuses the transition unless the
local user has actually confirmed the code. Three incorrect entries end the
session.

## Message protection layers

```text
        ECDH P-384 exchange
                 |
        HKDF key schedule
                 |
   .........................................................
   |        |         |            |               |
message    MAC     metadata   fingerprint     ratchet root
  key      key       key       (safety code)       |
                                            Double Ratchet
                                          per-message keys
```

Chat content is encrypted with a ratchet-derived key when both peers support the
ratchet, and with the session message key otherwise. Either way it reaches the
interface through a single authenticated path. Frames that fail authentication
are dropped rather than displayed, so nothing appears in a conversation that has
not been verified as coming from the peer holding the session keys.

## Forward secrecy

Per-message keys come from a chain key through a one-way function and are
destroyed after a single use, so a key held now cannot reconstruct an earlier
one. Each change of direction in the conversation introduces a fresh ECDH key
pair, which re-keys the session root and moves it away from any state an attacker
may have captured.

Out-of-order delivery is supported within fixed bounds: 512 skipped keys per
chain, 1024 retained in total, expiring after five minutes. These are a resource
control rather than a tuning parameter, because the message number is supplied by
the peer.

Incoming frames are authenticated before any ratchet state is committed. A frame
that fails leaves the ratchet untouched, so a malformed or forged frame cannot
desynchronise an established session.

[CRYPTOGRAPHY.md](CRYPTOGRAPHY.md) has the key schedule and the frame format.

## Session recovery

A network path can break without anything closing: switching from Wi-Fi to a
mobile network, a NAT rebind, a tunnel. The data channel keeps reporting itself
as open while packets stop arriving.

Recovery renegotiates only the transport path, using an ICE restart carried over
the existing encrypted channel. The DTLS session, the session keys, the ratchet
state and the message history all sit above ICE and survive it, so a repaired
connection is the same session and needs no new verification.

Silence alone is not treated as a dead peer. A backgrounded tab is frozen by the
browser and answers nothing, while ICE consent checks continue in the browser's
network stack. A connected ICE state therefore means a silent peer is asleep, not
gone. Only an unanswered probe on a degraded path starts recovery.

Recovery gives up when it cannot succeed: when nothing has arrived from the peer
since the break (no route exists for the renegotiation), or when the ICE agent
produces no candidate pairs at all (restarting cannot rebind it). A session that
cannot be recovered is closed and its data wiped rather than left half alive.

## File transfer

1. The sender emits metadata.
2. The receiver validates name, size, type and abuse limits.
3. The receiver is shown an Accept or Reject prompt.
4. No receive buffers are allocated before acceptance.
5. Chunks are transmitted only after acceptance.
6. Completed buffers are retained within a bounded window.

Voice notes reuse this pipeline and inherit its per-file AES-GCM session key,
chunking and SHA-256 integrity check. They differ in three ways: the audio is
recorded in the browser, the duration and waveform travel as unsigned
presentation metadata (the audio bytes stay covered by the signed hash), and the
receiver accepts them without a prompt so they can play inline.

That last point is why the receiver decides what counts as a voice note. The
sender's claim is not enough: a transfer qualifies only if it declares a
recognised audio MIME type, stays under 4 MB, and fits a per-session budget of
64 MB. Anything else is handled as an ordinary file and goes through the normal
prompt. This keeps the convenience of voice notes from becoming a channel for
unattended transfers.

## Disconnect

The disconnect path clears:

- WebRTC channels and peer connection handles
- timers, deferred retries, cover traffic and decoy traffic
- pending transfer state and consent waits
- verification state and session key material
- ratchet state: the root key, both chain keys and every retained message key are
  overwritten rather than only dereferenced
- React file transfer callbacks and stale interface state

Values that cannot be overwritten in JavaScript are documented as such rather
than reported as cleared. See the memory handling section of
[CRYPTOGRAPHY.md](CRYPTOGRAPHY.md).

## Multiple conversations

Each conversation gets its own manager instance, peer connection, key material
and verification state, held in a map keyed by session. Nothing is shared between
them, so two conversations cannot mix, and closing one leaves the others
connected.

## Code layout

| Path | Responsibility |
| --- | --- |
| `src/network/EnhancedSecureWebRTCManager.js` | Connection lifecycle, verification, session state, message routing |
| `src/network/webrtc/` | Call stack: SDP handling, audio and video senders, network adaptation |
| `src/crypto/DoubleRatchet.js` | Forward secrecy: root and chain keys, DH ratchet, skipped keys |
| `src/crypto/EnhancedSecureCryptoUtils.js` | Key generation, key schedule, message encryption, sanitization |
| `src/crypto/cose-qr.js` | Invitation packing for QR transport |
| `src/transfer/EnhancedSecureFileTransfer.js` | Chunked encrypted transfers, consent, type policy |
| `src/state/sessionsStore.js` | Reducer for the set of open conversations |
| `src/app.jsx` | Interface and message rendering |
