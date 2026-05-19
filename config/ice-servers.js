// SecureBit.chat operator ICE server override.
// Loaded before the WebRTC manager is created. Credentials are visible to browsers;
// rotate them from the ExpressTURN dashboard if this file is published publicly.
window.SECUREBIT_ICE_SERVERS = [
  { urls: 'stun:stun.cloudflare.com:3478' },
  { urls: 'stun:stun.expressturn.com:3478' },
  {
    urls: [
      'turn:free.expressturn.com:3478?transport=udp',
      'turn:free.expressturn.com:3478?transport=tcp'
    ],
    username: '000000002094555952',
    credential: 't1oK9Zftes9j7E7hJmsLad9jq1M='
  }
];
