# Cryptography and Verification

## Release context

- Product release: `v5.7.1`
- Protocol version: `4.1`
- Ratchet wire version: `1`

## Session establishment

SecureBit.chat uses ECDH-derived session material, DTLS-protected WebRTC transport, and a mandatory Short Authentication String (SAS) verification step.

The SAS is deterministic for both peers in the same authenticated session: it is derived with HKDF from the ECDH-derived key fingerprint together with both peers' DTLS fingerprints, canonicalised so each side computes the same value. Users compare the displayed code through an out-of-band channel and enter the matching code manually. Local success alone is insufficient: the session becomes verified only after both peers confirm.

Verification is the gate for the session, not a label on it. Until both peers have confirmed, the connection does not act on control messages from the other side — reconnection signalling, call setup, message deletion and delivery receipts all wait. The verification exchange itself is the deliberate exception, since it necessarily runs first.

## Key schedule

A single ECDH exchange produces the session's root material. From it, HKDF-SHA256 derives four independent keys plus the ratchet root, each under its own `info` label so that compromise of one reveals nothing about the others:

| Derived key | Purpose |
| --- | --- |
| `message-encryption-v4` | AES-256-GCM payload key (static path) |
| `message-authentication-v4` | HMAC-SHA256 message authentication |
| `metadata-protection-v4` | AES-256-GCM for message metadata |
| `fingerprint-generation-v4` | Key fingerprint shown to the user and fed to the SAS |
| `double-ratchet-root-v1` | Root key for the Double Ratchet |

The raw ECDH output is derived with `deriveBits`, used as HKDF input material, and the buffer holding it is overwritten as soon as the derivation completes. Session keys themselves are non-extractable `CryptoKey` handles.

## Forward secrecy — the Double Ratchet

Message protection does not rest on the keys agreed during the handshake. On top of them the client runs the Double Ratchet (Signal's design), implemented in `src/crypto/DoubleRatchet.js`.

**Symmetric ratchet.** Each message key is derived from a chain key with `KDF_CK` (HMAC-SHA256 over the chain key with distinct constants for the message key and the next chain key), then discarded after a single use. The construction is one-way, so possession of the current chain key does not yield any earlier message key.

**DH ratchet.** Each time the conversation changes direction, the replying peer introduces a fresh ECDH key pair and both sides mix a new shared secret into the root key with `KDF_RK` (HKDF-SHA256, root key as salt). A session therefore re-keys continuously as messages go back and forth.

**Initialisation.** No additional handshake data is exchanged. Both peers already hold each other's authenticated ECDH public key — the same keys the SAS covers — so the inviting peer begins with a fresh ratchet key against the peer's handshake key, and the joining peer begins with its own handshake key pair. The first DH step converges on the same secret from both directions.

The joining peer has no sending chain until the inviting peer's first message arrives; this is inherent to the ratchet, since both sides derive it from the same exchange. Frames sent before that point use the session keys.

**Message framing.** Each ratcheted frame carries a header — the sender's current ratchet public key, the length of the previous sending chain and the message number in the current one. The header is transmitted in the clear, because the receiver needs it before it can derive a key, and is passed to AES-GCM as additional authenticated data. Any modification to it causes decryption to fail rather than redirecting the ratchet.

**Out-of-order messages.** Keys for messages that have not yet arrived are retained so they can still be read, within fixed bounds:

| Bound | Value |
| --- | --- |
| Maximum skip within one chain | 512 |
| Total retained keys | 1024 (oldest evicted first) |
| Retention period | 5 minutes |

These are a resource control, not a tuning parameter: the message number is supplied by the peer, so the jump a single frame may claim has to be limited.

**State changes are applied only after authentication.** Receiving stages the chain advance and any DH step, attempts decryption, and commits only on success. A frame that fails authentication leaves the ratchet untouched, so a malformed or forged frame cannot desynchronise an established session.

**Negotiation.** Support is advertised in the invitation and in the response, and the ratchet is used only when both sides advertise it. A peer on an earlier release negotiates it away and the session runs on the per-session keys described above. The security panel reports which of the two is in force for the current connection.

## Message protection

- encrypted payloads are validated before decryption
- chat content reaches the interface through one authenticated path only; unauthenticated frames are rejected rather than rendered
- decrypted chat text is sanitized before entering React state or the UI
- replay and ordering controls remain part of the session layer; on the ratcheted path replay protection is intrinsic, since a message key is destroyed on use
- voice messages are transported over the file-transfer channel: each is
  encrypted with a per-file AES-GCM session key and integrity-checked with a
  signed SHA-256 hash before playback

## Local key metadata

Sensitive IndexedDB metadata is stored in encrypted envelopes. Legacy plaintext metadata remains readable through a migration path and is re-written in encrypted form when accessed. Corrupted encrypted metadata fails closed.

## Memory handling

Values that can be overwritten are overwritten: the ECDH output, HKDF intermediates, ratchet root and chain keys, and retained message keys are all zeroed when no longer needed. Values that cannot be overwritten in JavaScript — immutable strings, and non-extractable `CryptoKey` handles whose material lives outside the JS heap — are documented as such rather than reported as cleared; for those, non-extractability is the protection.

## Scope note

This document describes the current browser implementation behavior relevant to the v5.7.1 release. It does not replace independent cryptographic review.
