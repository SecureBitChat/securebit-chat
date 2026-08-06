# Configuration

## Requirements

- A browser with WebRTC and Web Crypto support
- Node.js 18 or later, for building
- A TURN service, if you need relay-only privacy mode or you expect users behind
  strict NAT

## Building and running

```bash
npm install
npm run build
npm run serve
```

`npm run build` compiles the CSS, bundles the JavaScript into `dist/`, and
regenerates `meta.json` with a build stamp. That stamp is what the update
mechanism compares, and it is also written into `sw.js` so the browser reinstalls
the service worker on each release. A deployment that skips `post-build` will not
notify anyone that an update exists.

The application is static. Any web server can host it, and there is no backend to
run.

## ICE and TURN

WebRTC needs to discover network paths between the two browsers. STUN is enough
to learn a public address; TURN is needed when a direct path cannot be
established, and is the only way to keep peers from seeing each other's IP
addresses.

Configuration comes from three places, in order of precedence:

1. User settings under Advanced network settings, stored in IndexedDB per device
2. `config/ice-servers.js`, an operator override loaded before the application
3. Built-in public STUN defaults

`config/ice-servers.js` is not committed, because it is where operator TURN
credentials would go. Use `config/ice-servers.example.js` as the template. The
Docker image copies `config/ice-servers.prod.js` into place at build time.

```js
window.SECUREBIT_ICE_SERVERS = [
  { urls: 'stun:stun.example.org:3478' },
  {
    urls: [
      'turn:turn.example.org:3478?transport=udp',
      'turn:turn.example.org:3478?transport=tcp',
      'turns:turn.example.org:443?transport=tcp'
    ],
    username: '...',
    credential: '...'
  }
];
```

Offering several transports is worth the extra lines. UDP is the most widely
usable, TCP covers networks that block UDP, and TURNS on 443 gets through
firewalls that only allow HTTPS. Some browsers also fail to resolve STUN and TURN
hostnames inside their WebRTC layer even when ordinary page DNS works, so listing
a raw IP alongside the hostname is a reasonable fallback.

Any TURN credential shipped to a browser is public by definition, because the
browser has to be able to read it. Treat it as a shared resource and apply quotas
on the TURN server rather than relying on the credential staying secret.

### User-supplied servers

Users can paste their own STUN and TURN servers. Input is validated against an
allowlist before it reaches `RTCPeerConnection`: only the `stun`, `stuns`, `turn`
and `turns` schemes, a hostname or bracketed IPv6 address with an optional port,
and an optional `transport=udp` or `transport=tcp` query. At most 10 servers with
8 URLs each. Anything else is rejected with a specific reason.

### Privacy modes

| Mode | Behaviour | IP exposure |
| --- | --- | --- |
| Default | Standard candidate gathering | Direct candidates can reveal addresses to the peer |
| Relay-only | Sets `iceTransportPolicy: "relay"` | Requires TURN; peers see only the relay |

STUN is not a substitute for TURN here. It reveals your public address to the
peer by design. Relay-only mode without a configured TURN server cannot connect
at all, and the interface warns when TURN is missing.

Validate a TURN deployment with `chrome://webrtc-internals` before relying on it.
A relay candidate should appear in the gathered set; if none does, the credentials
or the ports are wrong.

### When connections fail

Candidate gathering finishes only when every configured server has replied or
timed out. Behind a VPN or a restrictive firewall that may never happen, and the
console will show `701` errors for each unreachable server.

The application handles this: it proceeds as soon as there are usable candidates
and only keeps waiting while there are none, up to 25 seconds. Host candidates
alone are often enough on a local network. If nothing at all is gathered, the
message names the likely causes, which in practice are a VPN binding the browser
to an interface that cannot reach the servers, or a firewall dropping UDP.

## File transfer policy

Incoming transfers are validated before the consent prompt and require explicit
approval.

| Category | Extensions | Size limit |
| --- | --- | --- |
| Images | `.jpg` `.jpeg` `.png` `.gif` `.webp` `.bmp` `.ico` | 25 MB |
| Documents | `.pdf` | 50 MB |
| Text | `.txt` | 10 MB |
| Archives | `.zip` | 100 MB |
| Voice | `.webm` `.ogg` `.oga` `.opus` `.m4a` `.mp4` `.mp3` `.wav` | 20 MB |

Overall ceiling is 100 MB per file.

Blocked outright: `.exe` `.bat` `.cmd` `.sh` `.js` `.msi` `.dmg` `.app` `.jar`
`.scr` `.ps1` `.vbs` `.html` `.svg`

The extension list is the security boundary. MIME type is treated as advisory,
because it is client-supplied, varies between browsers and operating systems, and
is frequently absent. An allowed extension is accepted when the MIME type is
absent, generic, or one of the recognised types, but a clearly contradictory MIME
type is rejected as a spoofing signal.

Voice notes are the one transfer accepted without a prompt, so they are checked
more strictly. The receiver decides, not the sender: a genuine audio MIME type,
at most 4 MB, and a 64 MB budget for the whole session. A transfer that fails
those checks is not rejected, it simply loses the shortcut and appears as a normal
file with the usual prompt.

## Deployment notes

The repository includes an nginx configuration (`deploy/nginx.conf`) and an
Apache one (`.htaccess`). Both set the same policy, and the important parts are:

- `index.html`, `sw.js`, `manifest.json`, `meta.json` and `config/ice-servers.js`
  must not be cached. A stale `meta.json` breaks update notification, and a stale
  `sw.js` freezes the service worker.
- `dist/` bundles are query-versioned, so `no-cache` with revalidation is enough
  and avoids re-downloading unchanged bundles.
- `CDN-Cache-Control` is set separately, because a CDN reads it independently of
  the browser directive and will otherwise happily serve a stale app shell.
- `frame-ancestors` and HSTS have to be sent as headers. The rest of the content
  security policy is a meta tag in `index.html`.
- `.jsx` and `.mjs` must be served as JavaScript, or module loading fails.

Asset requests should return 404 when a file is missing rather than falling back
to the HTML shell. A missing script served as HTML fails in a confusing way.
