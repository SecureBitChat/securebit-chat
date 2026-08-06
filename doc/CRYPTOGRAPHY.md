# Cryptography

Everything here runs in the browser on the Web Crypto API. There are no
hand-rolled primitives. What is written by hand is the composition: the key
schedule, the ratchet, the verification flow and the framing, and that is what
this document describes.

| | |
| --- | --- |
| Release | v5.9.0 |
| Protocol version | 4.1 |
| Ratchet wire version | 1 |

## Primitives

| Purpose | Algorithm |
| --- | --- |
| Key agreement | ECDH P-384, falling back to P-256 if the browser refuses P-384 |
| Signatures | ECDSA P-384 with SHA-384, falling back to P-256 with SHA-256 |
| Key derivation | HKDF-SHA256 |
| Message encryption | AES-256-GCM |
| Message authentication | HMAC-SHA256, and AES-GCM's own tag on the ratcheted path |
| Password derivation | PBKDF2-SHA256, 310,000 iterations, 32-byte salt |

Session keys are non-extractable `CryptoKey` handles. The exceptions are the
values a ratchet has to chain itself, which Web Crypto cannot do behind an opaque
handle; those are raw bytes and are overwritten when finished with.

## Session establishment

A session begins with one ECDH exchange. The public keys do **not** travel in the
invitation — they are sent over the data channel once it opens, and are checked
against a 16-byte commitment carried in the invitation before they are parsed or
imported. The receiving side then validates the SPKI structure (algorithm OID,
curve, point format and length) before importing anything. See
[DESCRIPTOR-SBQ2.md](DESCRIPTOR-SBQ2.md) for the wire format and the reasoning.

From the shared secret, HKDF-SHA256 derives five independent values, each under
its own `info` label so that recovering one reveals nothing about the others:

| Label | Use |
| --- | --- |
| `message-encryption-v4` | AES-256-GCM payload key on the static path |
| `message-authentication-v4` | HMAC-SHA256 message authentication |
| `metadata-protection-v4` | AES-256-GCM for message metadata |
| `fingerprint-generation-v4` | Key fingerprint shown to the user and fed into the safety code |
| `double-ratchet-root-v1` | Root key for the Double Ratchet |

The raw ECDH output is produced with `deriveBits`, used as HKDF input material,
and the buffer holding it is overwritten as soon as derivation completes. It is
never exported through an extractable key.

The 64-byte session salt is **not transmitted**. Both sides derive it as
SHA-512 of the handshake transcript — both invitations byte for byte, and both
key blobs, each length-prefixed. That has two consequences: the salt cannot be
steered by either side alone, and every key in the schedule is bound to both DTLS
fingerprints and every ICE candidate that was exchanged.

## Verification

Both peers compute the same safety code with HKDF-SHA256, using the raw ECDH
shared secret as input material and the SHA-256 of the handshake transcript as
salt. The transcript covers **both invitations verbatim** — version byte, flags,
expiry, fingerprints, ICE credentials, every candidate, the commitments — and
**both key blobs**, each with a length prefix so no field boundary can be shifted.
Components are ordered by role rather than by who is computing, so both sides
reach the same seven digits.

Because the shared secret is the input material, an attacker who observes the
entire transcript still cannot predict the digits. Because the transcript is the
salt, nothing exchanged anywhere in the handshake, in either direction, can be
altered without changing them.

Possession of the identity key is proved separately: each side signs the
transcript with its ECDSA key and sends the signature over the channel. This
replaced an earlier challenge/response that echoed a nonce back across seven
fields; one signature binds the whole handshake at once.

Users compare the code through a channel an attacker cannot impersonate and enter
it manually. Local success is not sufficient: the session becomes verified only
after both peers confirm. Three incorrect entries end the session.

This is the step that makes the rest meaningful. Completing the key exchange
proves only that someone completed it; anyone able to rewrite the invitation can
do that with both people at once. The safety code covers the keys actually in use
and the invitations they arrived with, so a substitution anywhere changes the code
the users read to each other.

Key substitution alone — an attacker who can rewrite the in-band blob but not the
invitation — does not get that far: the commitment check fails first and the
connection is closed without anyone comparing anything.

Verification is also a gate rather than a label. Before it completes, the session
declines to act on control messages from the peer: reconnection signalling, call
setup, message deletion and delivery receipts. The verification exchange itself is
the deliberate exception, since it necessarily runs first.

## Forward secrecy

The session keys above would last the whole conversation on their own. The Double
Ratchet, implemented in `src/crypto/DoubleRatchet.js`, replaces them for message
traffic so that protection does not rest on a single set of keys.

### Symmetric ratchet

Each message key comes from the current chain key through `KDF_CK`, which is
HMAC-SHA256 over the chain key with one constant for the message key and another
for the next chain key. The message key is used once and destroyed. Because the
construction is one-way, holding the current chain key yields no earlier message
key.

### DH ratchet

Each time the conversation changes direction, the replying peer generates a fresh
ECDH key pair, and both sides mix the new shared secret into the root key with
`KDF_RK` (HKDF-SHA256, root key as salt, producing the next root and a new chain
key). A session therefore re-keys continuously as messages go back and forth, and
an attacker who captured the full state is excluded again after one message in
each direction.

### Initialisation

No extra handshake data is exchanged. Both peers already hold each other's
authenticated ECDH public key, which is exactly what the safety code covers.

The inviting peer starts with a fresh ratchet key pair against the peer's
handshake key and steps the root once, so even its first message has left the
handshake key behind. The joining peer keeps its handshake key pair as its
current ratchet pair, which is what the inviting peer derived against, and takes
no chain until the first message arrives.

That asymmetry is inherent to the ratchet, not an implementation shortcut: both
sides must derive the first chain from the same exchange. The consequence is that
the joining peer has no sending chain until it receives something. The
application sends a presence update from both sides as soon as verification
completes, so those first frames use the session keys, and everything after them
is ratcheted.

### Frame format

A ratcheted message is `{ type: "ratchet_message", h, c }`, where `h` is a header
string and `c` is the base64 body.

The header carries the sender's current ratchet public key, the length of the
previous sending chain, and the message number in the current one. It travels in
the clear because the receiver needs it before it can derive a key, and it is
passed to AES-GCM as additional authenticated data. Modifying any field causes
decryption to fail rather than redirecting the ratchet.

The header must be handed back to the decrypt call exactly as received. It is the
authenticated data itself, so re-serialising it can change a byte and fail
authentication for no reason.

### Out-of-order messages

Keys for messages that have not yet arrived are retained so they can still be
read, within fixed bounds:

| Bound | Value |
| --- | --- |
| Maximum skip within one chain | 512 |
| Total retained keys | 1024, oldest evicted first |
| Retention period | 5 minutes |

The message number comes off the wire, so the distance a single frame may claim
has to be limited. Without a cap, one frame claiming a number in the millions
would force the receiver to derive and hold that many keys.

Replay protection is intrinsic here. A message key is destroyed on use, so a
number behind the current chain has no key left to open it.

### State is committed only after authentication

Receiving stages the chain advance and any DH step, attempts decryption, and
commits only on success. A frame that fails authentication leaves the ratchet
exactly as it was.

This matters because the header is reachable by anyone on the channel. Advancing
the chains before verifying would let a single bad frame push the receiver past
the sender and break the session permanently, which would be a remote denial of
service against an established conversation.

### Negotiation

Support is advertised in the invitation and in the response, and the ratchet runs
only when both sides advertise it. A peer on an earlier release negotiates it
away and the session uses the per-session keys described above.

The fallback is deliberate. With no server there is no way to update both ends at
once, and a one-sided ratchet decrypts nothing. The security panel reports which
of the two is in force for the current connection rather than what the client is
capable of.

## Message protection on the static path

Messages encrypted with the session keys carry their metadata (identifier,
timestamp, sequence number, original length) encrypted separately under the
metadata key, and the whole payload is covered by an HMAC. Sequence numbers are
checked against a sliding window: a number behind the expected one is rejected as
a replay, and a gap beyond the window is rejected as well.

Payloads are padded to a 16-byte boundary with random bytes, with the true length
carried in the encrypted metadata.

## Rendering

Decrypted text is sanitized with DOMPurify configured to allow no tags and no
attributes at all, then rendered through React text nodes. Fenced code blocks are
tokenised by Prism, which escapes its input before highlighting and never
evaluates it. The content security policy permits no inline or remote scripts.

Chat content reaches the interface through one authenticated path. Frames that
are not authenticated are rejected rather than displayed, so nothing can appear
in a conversation that did not come from the peer holding the session keys.

## Local storage

Sensitive IndexedDB metadata is stored in encrypted envelopes. Legacy plaintext
records remain readable through a migration path and are rewritten encrypted when
next accessed. Corrupted encrypted metadata fails closed.

The master key for persistent storage is derived from a password with PBKDF2 and
is non-extractable. The application supplies the password interface; there is no
browser dialog fallback.

## Memory handling

Values that can be overwritten are overwritten: the ECDH output, HKDF
intermediates, the ratchet root and chain keys, and retained message keys.

Values that cannot be overwritten are documented rather than reported as cleared.
JavaScript strings are immutable, so a secret held as a string can only be
dereferenced. A non-extractable `CryptoKey` has no bytes visible to JavaScript at
all, so dropping the handle is the only available action and non-extractability is
what protects it. Functions that cannot wipe say so in their logs instead of
reporting success, because a cleanup path that reports work it did not do is
worse than one that reports nothing.

## Scope

This describes the browser implementation as it stands in v5.9.0. It is not a
substitute for independent cryptographic review.
