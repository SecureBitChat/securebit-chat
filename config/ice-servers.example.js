// SecureBit.chat operator ICE server override — TEMPLATE.
//
// Copy this file to `config/ice-servers.js` and fill in your own TURN/STUN
// servers. The real `config/ice-servers.js` is git-ignored on purpose:
// TURN credentials are visible to every browser that loads the page, so they
// must never be committed to a public repository. Rotate them from your TURN
// provider dashboard if they are ever exposed.
//
// If this override is absent, the WebRTC manager falls back to the built-in
// public STUN defaults (standard mode only — no relay/IP protection).
window.SECUREBIT_ICE_SERVERS = [
  { urls: 'stun:stun.cloudflare.com:3478' },
  {
    urls: [
      'turn:YOUR_TURN_HOST:3478?transport=udp',
      'turn:YOUR_TURN_HOST:3478?transport=tcp'
    ],
    username: 'YOUR_TURN_USERNAME',
    credential: 'YOUR_TURN_CREDENTIAL'
  }
];
