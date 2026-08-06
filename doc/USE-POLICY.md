# Use policy and limitations

SecureBit.chat is open-source software for private communication, research and
education. It is provided as is, without warranty of any kind. This document sets
out what the software can and cannot do for you, and what is expected of you when
you use it.

## What it protects

Message content between two verified peers, against anyone observing or
manipulating the network between them. That is a real guarantee and it is what
the design is built around.

## What it does not protect

Be clear about these before relying on the software for anything that matters.

**A compromised device.** Malware, a hostile browser extension, a keylogger or
someone with access to an unlocked machine sees your messages as you do. No
transport encryption helps. This is the most common way private communication is
actually broken.

**The person you are talking to.** They can screenshot, photograph the screen,
copy the text, or simply repeat what you said. View-once and disappearing
messages are cooperative features that a normal client honours; they are not a
technical restriction on a determined recipient.

**Verification you skipped.** If you do not compare the safety code, or you
compare it over a channel the attacker controls, the software cannot tell that
someone is in the middle. The comparison must happen over something an attacker
cannot impersonate: in person, or a voice you recognise.

**Metadata, depending on your setup.** A direct connection reveals your IP
address to the peer. Relay-only mode with your own TURN server prevents that, but
the relay operator can then see both addresses and the timing of traffic, though
never the content. Choose according to who you are protecting against.

**The fact that you are using it.** Someone watching your network can see a
WebRTC connection and can see you loading this application. The software does not
hide its own use.

## Your responsibilities

- Comply with the law where you are and with any policies that apply to you
- Keep your device and browser current and under your control
- Compare the safety code out of band, every time, on every new session
- Configure TURN correctly if you need relay-only mode, and verify it works
- Understand that endpoint compromise defeats everything above the endpoint

## Intended use

The software is meant for legitimate private communication: journalism and source
protection, human rights work, business confidentiality, medical and legal
matters, research and education, and ordinary personal conversation that is
nobody else's business.

It is not meant to facilitate unlawful activity, abuse, harassment, exploitation
or harm, and being able to communicate privately does not make any of those
acceptable.

If you become aware of the software being used to harm someone, report it to the
appropriate authorities. Vulnerabilities in the software itself go to the
maintainers first: see [SECURITY.md](../SECURITY.md).

## Operational notes

If your threat model is serious, the software is only one part of it.

Use a device you control and keep it patched. Consider a separate device for
sensitive conversations. Be aware of who can see your screen and who can hear
you. Understand that a camera and microphone are attached to the machine you are
typing on. Consider what your network operator can observe, and whether a VPN or
Tor changes that in your favour or simply moves the observation point.

Know the law where you are. Encryption is regulated differently in different
places, and in some jurisdictions there are disclosure requirements attached to
it.

## Contributing

Contributions are welcome under the same expectations. Report vulnerabilities
through the process in [SECURITY.md](../SECURITY.md) rather than publishing them,
and give a fix reasonable time to reach users before disclosure. Users who have
not updated yet are the ones exposed by early publication.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow.
