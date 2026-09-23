// Short-lived TURN credentials for SecureBit clients, served by nginx (njs) at
// POST /api/turn-credentials.
//
// WHY THIS EXISTS
// ---------------
// The relay used to be reached with one credential that was valid until 2038 and
// shipped inside every client. Anything shipped inside a client is public, so
// anyone could lift it and relay their own traffic through our server for years.
// Here the coturn REST-API secret stays on the server and each client asks for a
// credential that expires in a day. A lifted credential stops working on its own,
// and getting a new one means coming back here, where requests are rate-limited.
//
// WHAT IT DOES NOT DO
// -------------------
// It cannot prove the caller is our app. A browser cannot lie about Origin, so
// other WEBSITES cannot use our relay for their visitors; a script outside a
// browser can send any Origin it likes, or none (native apps send none). Those
// callers are bounded by the rate limit in nginx.conf and by coturn's own quotas.
//
// It is not a signalling service: it never sees a message, an SDP or who talks to
// whom. It hands out a relay credential and forgets the request.
//
// Plain ES module on purpose: njs runs it in nginx, and the test suite imports the
// same file under Node (both provide crypto.createHmac).

import crypto from 'crypto';

// Long enough to outlast a call: coturn re-checks the expiry on every refresh of
// an allocation, so a credential that expires mid-call drops the relayed leg.
// Clients fetch a fresh one well before this runs out.
const TTL_SECONDS = 24 * 60 * 60;

const ALLOWED_ORIGINS = [
    'https://securebit.chat',
    'https://securebit-chat.fly.dev',
    // Desktop (Tauri) webviews: macOS/Linux, then Windows.
    'tauri://localhost',
    'http://tauri.localhost',
    'https://tauri.localhost',
];

const TURN_URLS = [
    'turn:turn.securebit.chat:3478?transport=udp',
    'turn:turn.securebit.chat:3478?transport=tcp',
    // Raw-IP fallback for clients whose WebRTC stack cannot resolve the name.
    'turn:144.172.96.126:3478?transport=udp',
    'turn:144.172.96.126:3478?transport=tcp',
    'turns:turn.securebit.chat:443?transport=tcp',
];

/** coturn REST-API credential: username "<expiry>:<label>", password HMAC-SHA1. */
function makeCredential(secret, nowSeconds) {
    const username = (Math.floor(nowSeconds) + TTL_SECONDS) + ':securebit';
    const credential = crypto.createHmac('sha1', secret).update(username).digest('base64');
    return { username: username, credential: credential };
}

/**
 * Decide a request. Pure, so it can be tested without nginx.
 * @returns {{status:number, body?:object, allowOrigin?:string}}
 */
// Written without destructuring or default parameters: njs does not parse them.
function decide(req) {
    const method = req.method;
    const origin = req.origin;
    const secret = req.secret;
    // A browser always sends Origin on a POST. A missing one is a native app or a
    // script — let it through; the rate limit is what bounds it.
    const hasOrigin = typeof origin === 'string' && origin.length > 0;
    if (hasOrigin && ALLOWED_ORIGINS.indexOf(origin) === -1) return { status: 403 };

    const allowOrigin = hasOrigin ? origin : undefined;
    if (method === 'OPTIONS') return { status: 204, allowOrigin: allowOrigin };
    if (method !== 'POST') return { status: 405 };
    if (!secret) return { status: 503 };

    const cred = makeCredential(secret, req.nowSeconds);
    return {
        status: 200,
        allowOrigin: allowOrigin,
        body: {
            ttl: TTL_SECONDS,
            iceServers: [{ urls: TURN_URLS, username: cred.username, credential: cred.credential }],
        },
    };
}

function handle(r) {
    const result = decide({
        method: r.method,
        origin: r.headersIn['Origin'],
        secret: process.env.TURN_SECRET,
        nowSeconds: Date.now() / 1000,
    });

    if (result.allowOrigin) {
        r.headersOut['Access-Control-Allow-Origin'] = result.allowOrigin;
        r.headersOut['Access-Control-Allow-Methods'] = 'POST, OPTIONS';
        r.headersOut['Access-Control-Max-Age'] = '600';
        r.headersOut['Vary'] = 'Origin';
    }
    if (!result.body) {
        r.return(result.status);
        return;
    }
    r.headersOut['Content-Type'] = 'application/json';
    r.return(result.status, JSON.stringify(result.body));
}

// njs accepts only a default export; the helpers ride along for the tests.
export default {
    handle: handle, decide: decide, makeCredential: makeCredential,
    TTL_SECONDS: TTL_SECONDS, ALLOWED_ORIGINS: ALLOWED_ORIGINS, TURN_URLS: TURN_URLS
};
