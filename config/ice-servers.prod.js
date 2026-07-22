// Production ICE override baked into the Fly.io image (no secrets — public STUN
// only). The Dockerfile copies this to config/ice-servers.js, which is otherwise
// git-ignored. Users who want a TURN relay can add one via "Advanced network
// settings"; to ship an operator TURN here, add it below (TURN credentials are
// visible to every browser, so rotate them if exposed).
window.SECUREBIT_ICE_SERVERS = [
  { urls: 'stun:stun.cloudflare.com:3478' },
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
  // Raw-IP STUN (same coturn box as turn.securebit.chat). Required fallback: some
  // clients — notably Safari on certain networks — fail to resolve STUN/TURN
  // hostnames inside their WebRTC layer even though normal page DNS works, so they
  // gather zero srflx/relay candidates and can't connect. Reaching the server by IP
  // bypasses that. Harmless to other browsers.
  { urls: 'stun:144.172.96.126:3478' },
  {
    // SecureBit self-hosted coturn relay (turn.securebit.chat) — used only when
    // direct P2P fails (strict NAT / STUN limits). Media stays E2E-encrypted over
    // DTLS; the relay forwards only ciphertext. Multiple transports are offered so
    // every browser finds one that works:
    //   - turn:3478?transport=udp  — plain UDP, the most universally compatible
    //     transport (notably the one Safari reliably gathers relay candidates on).
    //   - turn:3478?transport=tcp  — TCP fallback when UDP is blocked.
    //   - turns:443?transport=tcp  — TURN over TLS on 443, bypasses restrictive
    //     firewalls that only allow HTTPS.
    //
    // The credential below is a long-lived token derived from the server's TURN
    // REST API secret (static-auth-secret) — username is "<expiry-unix-ts>:label".
    // Expiry 2147483647 = 2038-01-19 (max value coturn accepts; it parses the
    // timestamp as int32). The master secret itself never leaves the server; only
    // this derived username/credential pair is public (by design, like any
    // browser-side TURN credential). To revoke/renew, rotate the server's
    // static-auth-secret and re-issue with generate_turn_credentials.py.
    urls: [
      'turn:turn.securebit.chat:3478?transport=udp',
      'turn:turn.securebit.chat:3478?transport=tcp',
      // Raw-IP TURN relay — the DNS-bypass fallback that lets Safari (and any client
      // whose WebRTC layer can't resolve the hostname) obtain a relay candidate.
      // Plain turn: (no TLS) so no cert/hostname check is needed; the REST-API
      // credential is host-independent, and relayed traffic is already E2E ciphertext.
      'turn:144.172.96.126:3478?transport=udp',
      'turn:144.172.96.126:3478?transport=tcp',
      'turns:turn.securebit.chat:443?transport=tcp'
    ],
    username: '2147483647:securebit',
    credential: 'tNrw3h2p/+OE0uLMLVc+ech7T6o='
  }
];
