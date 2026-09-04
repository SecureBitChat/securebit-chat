# Frequently asked questions

Short answers to what people ask before they trust the software with anything.
Every one of them is drawn from the documents linked alongside it, so if an answer
here and a document disagree, the document is right and this page is stale.

## Do I need an account?

No. There is nothing to register, no email address, no phone number and no
password. You open the page, your browser generates a key pair, and you send the
resulting invitation to the person you want to talk to. Nothing about you is
stored anywhere, because there is nowhere to store it.

## Where are my messages stored?

Nowhere. Messages travel directly between the two browsers over WebRTC and are
held only in the memory of the two devices taking part. There is no message
server, no database and no backup — which also means a conversation you close is
gone, and nobody can hand it over later because nobody has it.

## Is there a server in the middle?

No, and there is not even a signalling service. The offer and the answer that set
up a connection are moved between the two people by whatever channel they already
have: a QR code, a pasted block of text, a link. That is the unusual part of the
design and it shapes everything else — the out-of-band channel is assumed to be
readable and rewritable by an attacker, which is exactly why the safety code
comparison exists. See [ARCHITECTURE.md](ARCHITECTURE.md).

A TURN server, if you use one, relays encrypted packets. It never sees message
content, and it is optional.

## What encryption does SecureBit.chat use?

Key exchange is ECDH on P-384, message payloads are AES-256-GCM, and messages
carry ECDSA signatures with full ASN.1 validation of every key that arrives.
Session keys rotate continuously through a Double Ratchet and are discarded after
use, so a key recovered later cannot open earlier conversations. The transport
underneath is DTLS, as WebRTC requires. Everything runs on the browser's Web
Crypto API rather than hand-rolled primitives — [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md)
sets out the key schedule in full.

## What is the safety code, and why do I have to compare it?

It is a short code derived from both sides of the completed key exchange. If the
two of you see the same code, nobody sat in the middle of the exchange; if someone
did, the codes differ and the session is not what it claims to be.

The comparison has to happen over a channel an attacker cannot impersonate — in
person, or a voice you recognise. Comparing it inside the chat itself proves
nothing. It is enforced rather than merely displayed: until both sides confirm,
reconnection signalling, call setup, delivery receipts and incoming file
transfers are all refused, and three incorrect entries end the session.

## Is it free, and can I read the source?

Yes to both. The software is free, has no paid tier and no upsell, and is
published under the MIT licence at
[github.com/SecureBitChat/securebit-chat](https://github.com/SecureBitChat/securebit-chat).
Nothing is minified beyond recognition or hidden behind a build you cannot
reproduce; [CONFIGURATION.md](CONFIGURATION.md) describes building and running it
yourself.

## Do I have to install anything?

No. It runs in any current browser with WebRTC and the Web Crypto API. It can be
installed as a Progressive Web App if you would rather have an icon, and there are
native desktop builds for Windows, macOS and Linux. Calls are not yet available on
the Linux desktop build; they work everywhere else, including in the browser.

## Can the person I am talking to see my IP address?

On a default connection, yes — a direct WebRTC path means each side learns the
other's address. That is how a direct connection works, not a flaw in this
implementation.

Relay-only mode prevents it: it sets `iceTransportPolicy: "relay"`, so all traffic
goes through a TURN server and the peers see only the relay. The trade is that the
relay operator can then see both addresses and the timing of the traffic, though
never the content. Choose according to who you are protecting against.

## Do I need my own TURN server?

Only for relay-only mode, or when a direct path cannot be established at all.
Public STUN defaults are built in and are enough for most connections. You can
paste your own STUN and TURN servers under Advanced network settings; they are
validated against an allowlist of schemes, hosts and transports before they reach
the connection.

One thing worth knowing: any TURN credential sent to a browser is public by
definition, because the browser has to read it. Apply quotas on the TURN server
rather than relying on the credential staying secret. [CONFIGURATION.md](CONFIGURATION.md)
covers the setup and how to verify it works.

## Can I send files, and how large?

Yes, over the same encrypted channel, with a per-file AES-GCM key and a SHA-256
integrity check. The receiver sees name, size and type and has to accept before
any buffer is allocated or a single chunk is sent.

The ceiling is 100 MB per file, with lower limits by category: images 25 MB, PDFs
50 MB, text 10 MB, archives 100 MB, audio 20 MB. Executable and scriptable formats
are blocked outright — `.exe`, `.js`, `.html`, `.svg` and others — and the file
extension, not the browser-supplied MIME type, is the boundary that decides.

## Are group chats and calls supported?

Yes. Encrypted voice and video calls shipped in early 2026, and group
communications are current work. Group sessions keep the same properties as
one-to-one ones: no server holds the conversation, and members verify each other.
[CALLS.md](CALLS.md) covers codec choices and how the connection adapts to a poor
network.

## Is there a mobile app?

Not yet. The web application works in mobile browsers today and can be installed
to the home screen as a PWA. Native iOS and Android builds are planned; the
roadmap on the front page lists where they sit relative to the rest of the work.

## What does it not protect against?

Read [USE-POLICY.md](USE-POLICY.md) before relying on this for anything that
matters. In short: a compromised device sees your messages exactly as you do, and
no transport encryption helps. The person you are talking to can screenshot or
repeat what you said. A safety code you skipped protects nothing. And someone
watching your network can see that you are using a WebRTC application, even though
they cannot see what you send — the software does not hide its own use.
