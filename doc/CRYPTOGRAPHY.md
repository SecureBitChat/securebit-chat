# Cryptography and Verification

## Release context

- Product release: `v4.8.5`
- Protocol version: `4.1`

## Session establishment

SecureBit.chat uses ECDH-derived session material, DTLS-protected WebRTC transport, and a mandatory Short Authentication String (SAS) verification step.

The SAS is deterministic for both peers in the same authenticated session. Users compare the displayed code through an out-of-band channel and enter the matching code manually. Local success alone is insufficient: the session becomes verified only after both peers confirm.

## Message protection

- encrypted payloads are validated before decryption
- decrypted chat text is sanitized before entering React state or the UI
- replay and ordering controls remain part of the session layer

## Local key metadata

Sensitive IndexedDB metadata is stored in encrypted envelopes. Legacy plaintext metadata remains readable through a migration path and is re-written in encrypted form when accessed. Corrupted encrypted metadata fails closed.

## Scope note

This document describes the current browser implementation behavior relevant to the v4.8.5 hardening release. It does not replace independent cryptographic review.
