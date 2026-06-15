// Production ICE override baked into the Fly.io image (no secrets — public STUN
// only). The Dockerfile copies this to config/ice-servers.js, which is otherwise
// git-ignored. Users who want a TURN relay can add one via "Advanced network
// settings"; to ship an operator TURN here, add it below (TURN credentials are
// visible to every browser, so rotate them if exposed).
window.SECUREBIT_ICE_SERVERS = [
  { urls: 'stun:stun.cloudflare.com:3478' },
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' }
];
