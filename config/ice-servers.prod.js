// Production ICE override baked into the Fly.io image (no secrets — public STUN
// only; the relay is added at runtime with a short-lived password). The Dockerfile copies this to config/ice-servers.js, which is otherwise
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
  { urls: 'stun:144.172.96.126:3478' }
  // SecureBit's own TURN relay (turn.securebit.chat) is deliberately not listed
  // here. It no longer has a built-in password: the app asks the site for one
  // that expires after a day (POST /api/turn-credentials) and adds the relay to
  // this list itself — see src/network/turnCredentials.js.
];
