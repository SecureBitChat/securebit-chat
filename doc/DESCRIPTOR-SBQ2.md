# SBQ2 — connection descriptor v2

The descriptor is the blob a user carries from one device to the other by hand:
a QR code, a deep link, or a paste into another messenger. There is no signalling
server, so this is the only channel that exists before the peers can talk.

SBQ2 replaces the `SB1:bin:` format (CBOR + zlib + base64url of the whole offer
package). Measured on real Chrome and Firefox SDP, a descriptor went from
2000–2400 characters to **98–149 bytes**, and the QR from version 38–40 down to
**version 6–8** at error-correction level M.

**Status: specified and implemented, not wired into the connection path.** See
[Migration](#migration) for the gate on phase 3.

---

## 1. What travels where

Out of band (this descriptor): ICE credentials, the DTLS certificate
fingerprint, the candidate list, an expiry, and a 16-byte commitment.

In band (over the DataChannel, once DTLS is up): identity key, ECDH key,
signatures — everything that used to make the descriptor large.

The fingerprint is what makes that split safe. It arrives over the channel the
user already trusts, and DTLS completes only with the holder of the matching
private key, so the transport is authenticated to whoever showed the code before
any key material moves. The commitment makes substitution of that material fail
closed automatically rather than relying on the human comparison, and the SAS
covers a transcript containing both descriptors verbatim and both in-band blobs.

---

## 2. Wire layout

All integers big-endian. Offsets are for the offer; an answer inserts its
8-byte binding tag at offset 5 and everything after shifts by 8.

```
off  len  field
  0    1  version = 0x02        mismatch is an error, never a reparse
  1    1  flags
  2    3  expiry                u24, minutes since 2024-01-01T00:00:00Z
  5   [8] binding_tag           ANSWERS ONLY
 ..   32  dtls_fingerprint      SHA-256 of the certificate, raw
 ..    1  ufrag_len             4..64
 ..   L1  ufrag                 ASCII, RFC 8839 ice-char alphabet
 ..    1  pwd_len               22..64
 ..   L2  pwd                   ASCII, RFC 8839 ice-char alphabet
 ..    1  candidate_count       0..8
 ..   ..  candidates
 ..  [16] commitment            if flags bit 6
 ..   [1] ext_len               if flags bit 7
 ..   ..  TLV records           if flags bit 7
```

### flags

| bits | meaning |
|---|---|
| 0–1 | type: 0 offer, 1 answer. 2 and 3 are reserved → **reject** |
| 2–3 | DTLS setup role: 0 actpass, 1 active, 2 passive. 3 reserved → **reject** |
| 4–5 | max-message-size: 0 = 262144, 1 = 1073741823, 2 = 65536, 3 = explicit, in extension `0x01` |
| 6 | a commitment follows the candidates |
| 7 | a TLV extension area follows |

Every bit is allocated. Future fields go in the TLV area, which is itself
deny-by-default; there is deliberately no spare "ignore me" bit.

### candidate

```
1 byte   kind << 4 | tcptype
n bytes  address   (v4 = 4, v6 = 16, mDNS UUID = 16)
2 bytes  port
```

`kind`: 0 host-v4, 1 host-mDNS, 2 srflx-v4, 3 relay-v4, 4 host-v6, 5 srflx-v6,
6 relay-v6. 7–15 reserved → **reject**.
`tcptype`: 0 udp, 1 tcp/passive, 2 tcp/active, 3 tcp/so. 4–15 → **reject**.

Foundation and priority are **not** transmitted. Priority only orders
connectivity checks, and each peer computes its own local priorities anyway; the
serializer re-derives RFC 8445 §5.1.2.1 values with `localPref = 65535 - index`,
so the sender's ordering intent survives at zero cost. Foundations are grouped by
kind and transport, satisfying both halves of §5.1.1.3. `raddr`/`rport` are
diagnostics that ICE does not consume, and `generation`/`network-cost` are Chrome
extensions.

### TLV extension area

```
ext_len  u8, 1..255, must be consumed exactly
record:  type u8, len u8, value[len]
```

Records must appear in **ascending type order with no duplicates**, so every
descriptor has exactly one valid spelling. An unknown type is a hard error.

| type | len | value |
|---|---|---|
| `0x01` | 4 | max-message-size, u32, 1024..2^31-1, and not equal to a value the flags already encode |

---

## 3. Sizes measured

Real SDP, identical ICE configuration on both peers, each peer gathering in its
own browser process. QR versions are byte mode at level M.

| browser | profile | offer | QR | answer | QR |
|---|---|---|---|---|---|
| Chrome | host_only | 103 B | v6 | 111 B | v7 |
| Chrome | stun | 110 B | v7 | 118 B | v7 |
| Chrome | turn_all | 124 B | v8 | 132 B | v8 |
| Chrome | turn_relay_only | 98 B | v6 | 106 B | v6 |
| Firefox | host_only | 134 B | v8 | 142 B | v8 |
| Firefox | stun | 141 B | v8 | 149 B | v8 |
| Firefox | turn_all | 136 B | v8 | 144 B | v8 |
| Firefox | turn_relay_only | 110 B | v7 | 118 B | v7 |

Firefox descriptors run ~12 bytes larger because its ICE credentials are longer
(8-char ufrag and 32-char pwd against Chrome's 4 and 24).

Transport: **raw bytes in QR byte mode**. base45 buys nothing (198 alphanumeric
characters = 1089 bits against 1056 bits raw for the same 132-byte payload), and
base64url costs a QR version. For text channels the form is `SB2:` + base64url,
whose alphabet survives messenger auto-formatting; the decoder strips whitespace
so a wrapped paste still works. **DEFLATE is not used** — on this payload it adds
2 to 11 bytes, and dropping it removes the decompression-bomb surface with it.

---

## 4. Candidate pruning: coverage before count

A count limit is the wrong policy. Sorted v4-first it can evict the only usable
candidate on an IPv6-only network, which is a normal mode on several mobile
carriers, and one that ignores transport can evict the TCP candidate that exists
precisely for networks where UDP is blocked.

The rule, in order:

1. **Coverage.** Every `(address family, candidate type, transport)` combination
   present in the input keeps its highest-priority representative. Families are
   `v4`, `v6` and `mdns` — mDNS is its own family because it resolves only on
   the sender's link, covering a case neither of the others does. Coverage is
   never cut, not even to stay inside the byte budget: a QR one version larger
   costs less than a connection that cannot be made.
2. **Surplus,** by the sender's own priority, until either `MAX_CANDIDATES` (8)
   or `SURPLUS_CANDIDATE_BYTES` (48) runs out, with relays capped at 2.

Candidates a peer cannot dial — ICE-TCP `active` and `so`, which are
outbound-only sockets on the discard port — are excluded from coverage and
compete only for surplus. Firefox advertises an `active` host candidate on every
connection; at 19 bytes for an mDNS address it must not hold a coverage slot it
cannot use.

The 48-byte surplus budget is derived, not chosen: the largest answer head
measured is Firefox's at 104 bytes, and QR version 8 at level M holds 152, so
152 − 104 = 48.

The relay cap of 2 applies only to surplus. A TURN server offering udp/tcp/tls
hands out one allocation per transport and they all resolve to the same relayed
address, so the third adds no reachability; two survive in case one allocation's
binding dies.

---

## 5. Freshness, uniqueness, one-shot

**Expiry** is absolute, at minute granularity, with a ±2-minute skew allowance.
Two minutes is sized against the failure it exists for: an NTP-synced device is
within milliseconds and an unsynced modern device drifts seconds per day, so two
minutes swallows every ordinary case while still refusing a grossly wrong clock
(manually set, or reset by a dead battery) — a device that cannot be given a
meaningful freshness guarantee should be told so, and the error message names the
clock as the likely cause. The cost is a replay window of 12 minutes instead of
10.

**The offer carries no nonce.** It does not need one: `ice-pwd` is in the hashed
bytes, RFC 8839 §5.4 requires it to contain at least 128 bits of randomness, and
every browser regenerates it per peer connection and per ICE restart. A separate
8-byte random field would have been 8 bytes restating entropy already present.

**The answer carries an 8-byte binding tag**, `SHA-256("sbq2/bind\0" ||
offer_bytes)[0..8]`. The offerer keeps the tag of the offer it is currently
showing and refuses anything else, which is both the answer's replay defence and
what makes each offer exactly one-shot — without any stored state between
sessions.

> **Limitation, on the record:** 64 bits is not a standalone integrity primitive.
> The tag is a duplicate-detection device whose security comes from the SAS
> transcript, which covers both descriptors in full. Nothing may be built on this
> tag alone. If a future change needs one, widen the field rather than lean on it.

---

## 6. SAS

```
transcript = "sbq2/sas/v1\0"
           || len32(offer_bytes)  || offer_bytes
           || len32(answer_bytes) || answer_bytes
           || len32(offer_blob)   || offer_blob
           || len32(answer_blob)  || answer_blob

SAS = HKDF-SHA256(IKM = ECDH shared secret,
                  salt = SHA-256(transcript),
                  info = "sbq2-sas-v1") -> 64 bits -> 7 digits
```

The transcript covers both descriptors byte for byte — version, flags, expiry,
binding tag, fingerprints, ICE credentials, every candidate, the commitment and
the whole extension area — plus both in-band blobs. Lengths are prefixed so no
field boundary can be shifted to produce a colliding transcript.

---

## 7. Migration

The two formats separate without heuristics: an SBQ2 QR starts with byte `0x02`,
an SB1 payload starts with ASCII `S` (`0x53`); in text, the prefixes are `SB2:`
and `SB1:bin:` / `SB1:gz:`.

| phase | change |
|---|---|
| 1 (done) | Codec and tests in the tree. Nothing in the connection path changes. |
| 2 | Receiver accepts both. Try SBQ2 first, fall back to the SB1 parser. Sender still emits `SB1:`. |
| 3 | Sender switches to SBQ2 behind a flag. **Gated — see below.** |
| 4 | `SB1:` emission removed; SB1 parsing kept one more release, then deleted along with `cose-qr.js`, `inflateBounded`, and the animated multi-frame QR path in `app.jsx`. |

### Phase 3 is blocked on the in-band key exchange

**The security argument in §1 describes a protocol that does not exist in the
code yet.** Today `EnhancedSecureWebRTCManager` still ships the key material
inside the descriptor, still computes the SAS in `_computeSAS` from the DTLS
fingerprints alone, and still sends `authProof`. Shrinking the descriptor without
that delivery would remove the key material from the QR with nothing carrying it
instead.

Phase 3 must not be enabled until a separate delivery lands:

- a key-exchange phase after the DataChannel opens,
- verification of the commitment **before** any use of the blob,
- `_computeSAS` replaced by the transcript SAS above,
- the session salt derived from the transcript instead of transmitted,
- `authProof` replaced by a signature over the transcript,
- interlock with the Double Ratchet start,

each with its own tests. Phases 1 and 2 are safe to ship without it, because
neither changes what is sent.

---

## 8. Decoder rules

The decoder parses fully attacker-controlled input.

- Payload ceiling (512 B) checked before any structure is walked.
- Version compared first; a mismatch throws.
- Reserved values (descriptor type 2–3, setup role 3, candidate kind 7–15,
  tcptype 4–15) are refused, never coerced.
- Unknown TLV types are refused. Records must be ascending and unique, and a TLV
  restating a value the flags already encode is refused as non-canonical.
- Flags and extension area must agree in both directions: `mms = 3` without
  extension `0x01` is an error, and extension `0x01` without `mms = 3` is too.
- ufrag and pwd are range-checked and alphabet-checked; any byte outside
  printable ASCII fails before the value is used, so a CR or LF cannot reach the
  serializer and inject an SDP line.
- Trailing bytes after the structure are an error. A decoder that tolerated them
  would let a second reading of the same QR slip past whatever hashed the
  canonical form.
- Base64url input must be canonical: non-zero padding bits are refused, so a
  descriptor has exactly one textual spelling.

---

## 9. Provenance of the numbers

Everything above was measured, not estimated.

- Chrome fixtures: `tests/fixtures/sdp-chrome.json`, captured over CDP from a
  real Chrome across four network profiles, both peers configured identically,
  each gathering in isolation.
- Firefox fixtures: `tests/fixtures/sdp-firefox.json`, Firefox 153 over
  Marionette, same method.
- Round-trip, rejection, coverage, TLV, skew and transcript tests:
  `tests/descriptor-sbq2.test.mjs`.

The original brief's payload (CBOR 2391 B, 991 B of SDP) was an **offer** — it
carries `sl`, `si`, `vc` and `ac`, and has no `ap` block. An earlier draft of the
analysis matched it against a STUN-profile answer on the strength of the post-
zlib and post-base64 sizes; those agreed by coincidence while the CBOR sizes
differ by 135 bytes. Conclusions were unaffected, but the attribution was wrong.
