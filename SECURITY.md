# Security Policy

## Reporting a vulnerability

Report privately, before public disclosure.

- Email: `SecureBitChat@proton.me`
- Include the affected version, steps to reproduce, the impact you see, and any
  proof-of-concept material
- Please allow time for a fix to reach users before publishing details

There is no server to patch centrally. Every user has to load a new build, so
early publication exposes exactly the people who have not updated yet. That is
the only reason for the delay, and it is not indefinite: if you do not get a
response within a reasonable time, say so and set your own timeline.

Reports about a specific deployment (someone else's hosted instance, a TURN
server) should go to whoever operates it.

## Supported versions

| Release | Status |
| --- | --- |
| 5.7.x | Supported |
| 5.6.x | Superseded, update recommended |
| 5.5.x and earlier | Unsupported |

Because the application is served fresh from the network on each load, most users
are on the current release automatically. Installed progressive web app instances
update on the next launch after a new build is deployed.

Forward secrecy applies only when both peers are on 5.7.0 or later. The feature
is negotiated, and a session with an older peer falls back to the previous scheme.
The security panel in the application shows which is in force for the current
connection.

## What the software guarantees

Message content between two peers who have compared their safety code, against an
attacker on the network between them.

That guarantee has a precondition, and it is not optional. Completing the key
exchange proves that someone completed it, not who. The safety code comparison is
what identifies the peer, and it has to happen over a channel an attacker cannot
impersonate.

## What it does not guarantee

- A compromised endpoint. Malware, a hostile extension or physical access to an
  unlocked device sees the plaintext.
- Behaviour of the person you are talking to. View-once and disappearing messages
  are cooperative, not enforced against a determined recipient.
- Network privacy by default. A direct connection reveals your IP address to the
  peer. Relay-only mode with your own TURN server prevents that, at the cost of
  the relay operator seeing both addresses and traffic timing.
- The fact that you are using the software. That is visible to anyone watching
  your network.

[doc/USE-POLICY.md](doc/USE-POLICY.md) goes into more detail.

## Current behaviour

**Verification.** The safety code is derived deterministically from shared
session material and both DTLS fingerprints, and is compared manually out of
band. A session becomes verified only after both peers confirm. Three incorrect
entries end it. Until verification completes, the session refuses control
messages from the peer: reconnection signalling, call setup, message deletion and
delivery receipts.

**Message protection.** Chat content is encrypted with a per-message key from the
Double Ratchet when both peers support it, and with per-session keys otherwise.
Ratchet message keys are destroyed after a single use, and each change of
direction re-keys the session root. Content reaches the interface through one
authenticated path; unauthenticated frames are dropped rather than displayed.
Decrypted text is sanitized before rendering.

**File transfer.** Metadata is validated before the user is prompted, every
transfer requires explicit consent, and no receive buffer is allocated before
consent. Accepted types are an explicit allowlist checked by extension, with MIME
type as a secondary signal. Executable and scriptable formats are blocked. Voice
notes are the one exception to the prompt, and qualify only if the receiver
confirms they are genuine audio within size and per-session budgets.

**Local storage.** Sensitive IndexedDB metadata is stored encrypted. Legacy
plaintext records migrate on read. Corrupted encrypted metadata fails closed. No
message history is written to disk.

**Cleanup.** Disconnecting closes the channels, clears verification state, and
overwrites the key material that can be overwritten. Timers, retries, cover
traffic, pending transfers and interface callbacks are all torn down.

## Verifying a build

```bash
npm audit
npm test
npm run build
```

The bundles in `dist/` are committed and served directly. They are not currently
verified against the sources by automation, so if you are reviewing this project
seriously, build from source and compare rather than reading `src/` alone.

## Limitations of this policy

This is a small project. There has been no independent cryptographic audit. The
documentation in [`doc/`](doc/) describes the design in enough detail to review
it, and that is the intended substitute until an audit happens.
