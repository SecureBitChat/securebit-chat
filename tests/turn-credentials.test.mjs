// The TURN credential endpoint (deploy/turn-credentials.js) and the web client
// that consumes it (src/network/turnCredentials.js).
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import endpoint from '../deploy/turn-credentials.js';
import { applyTurnCredentials, isOwnRelayEntry, parseCredentialResponse } from '../src/network/turnCredentials.js';

const SECRET = 'test-secret';
const NOW = 1_800_000_000;

// ---- endpoint ----

{
    const res = endpoint.decide({ method: 'POST', origin: 'https://securebit.chat', secret: SECRET, nowSeconds: NOW });
    assert.equal(res.status, 200);
    assert.equal(res.allowOrigin, 'https://securebit.chat');
    const server = res.body.iceServers[0];
    assert.equal(server.username, `${NOW + endpoint.TTL_SECONDS}:securebit`);
    // Exactly what coturn's use-auth-secret expects: base64(HMAC-SHA1(secret, username)).
    const expected = crypto.createHmac('sha1', SECRET).update(server.username).digest('base64');
    assert.equal(server.credential, expected);
    assert.ok(server.urls.every((u) => /^turns?:/.test(u)));
}

// Other websites are refused: a browser cannot fake Origin.
assert.equal(endpoint.decide({ method: 'POST', origin: 'https://evil.example', secret: SECRET, nowSeconds: NOW }).status, 403);
assert.equal(endpoint.decide({ method: 'POST', origin: 'null', secret: SECRET, nowSeconds: NOW }).status, 403);

// Desktop webviews are allowed and get CORS back.
for (const origin of ['tauri://localhost', 'http://tauri.localhost', 'https://tauri.localhost']) {
    const res = endpoint.decide({ method: 'POST', origin, secret: SECRET, nowSeconds: NOW });
    assert.equal(res.status, 200, origin);
    assert.equal(res.allowOrigin, origin);
}

// No Origin (native app / script) is served but gets no CORS header.
{
    const res = endpoint.decide({ method: 'POST', origin: undefined, secret: SECRET, nowSeconds: NOW });
    assert.equal(res.status, 200);
    assert.equal(res.allowOrigin, undefined);
}

// Only POST mints; preflight is answered; a missing secret fails closed.
assert.equal(endpoint.decide({ method: 'GET', origin: 'https://securebit.chat', secret: SECRET, nowSeconds: NOW }).status, 405);
assert.equal(endpoint.decide({ method: 'OPTIONS', origin: 'https://securebit.chat', secret: SECRET, nowSeconds: NOW }).status, 204);
assert.equal(endpoint.decide({ method: 'POST', origin: 'https://securebit.chat', secret: '', nowSeconds: NOW }).status, 503);

// ---- web client: updating the shared ICE list in place ----

const ownEntry = () => ({
    urls: ['turn:turn.securebit.chat:3478?transport=udp', 'turns:turn.securebit.chat:443?transport=tcp'],
    username: '2147483647:securebit',
    credential: 'old',
});

{
    const stun = { urls: 'stun:stun.l.google.com:19302' };
    const own = ownEntry();
    const list = [stun, own];
    const fresh = { username: `${NOW + 86400}:securebit`, credential: 'new' };

    assert.equal(applyTurnCredentials(list, fresh), true);
    // Same array, same objects: managers hold a reference to this list, so an
    // in-place update is what makes the next connection use the new credential.
    assert.equal(list[1], own);
    assert.equal(own.username, fresh.username);
    assert.equal(own.credential, 'new');
    assert.equal(stun.username, undefined);
}

{
    // A user's own TURN server is never touched.
    const custom = { urls: 'turn:relay.example.org:3478', username: 'me', credential: 'mine' };
    assert.equal(isOwnRelayEntry(custom), false);
    assert.equal(applyTurnCredentials([custom], { username: 'x:securebit', credential: 'y' }), false);
    assert.equal(custom.credential, 'mine');

    // Raw-IP entries of our relay count as ours.
    assert.equal(isOwnRelayEntry({ urls: ['turn:144.172.96.126:3478?transport=udp'] }), true);
    assert.equal(isOwnRelayEntry({ urls: 'turn:evil.example.com?securebit.chat' }), false);
}

{
    // Malformed responses are rejected rather than written into the ICE list.
    const own = ownEntry();
    for (const bad of [null, {}, { username: 'a', credential: 'b\n' }, { username: 'x'.repeat(600), credential: 'b' }, { username: 5, credential: 'b' }]) {
        assert.equal(applyTurnCredentials([own], bad), false);
    }
    assert.equal(own.credential, 'old');
}

{
    // The web build ships no relay entry: the first fetch adds it.
    const stun = { urls: 'stun:stun.l.google.com:19302' };
    const list = [stun];
    const body = endpoint.decide({ method: 'POST', origin: 'https://securebit.chat', secret: SECRET, nowSeconds: NOW }).body;
    const cred = parseCredentialResponse(body, NOW);
    assert.ok(cred, 'a real endpoint response parses');
    assert.equal(applyTurnCredentials(list, cred), true);
    assert.equal(list.length, 2, 'the relay is added to the same array');
    assert.equal(list[0], stun);
    assert.deepEqual(list[1].urls, endpoint.TURN_URLS);
    assert.equal(list[1].credential, cred.credential);

    // A second fetch renews that entry instead of adding another.
    const next = parseCredentialResponse(endpoint.decide({ method: 'POST', origin: undefined, secret: SECRET, nowSeconds: NOW + 60 }).body, NOW + 60);
    applyTurnCredentials(list, next);
    assert.equal(list.length, 2);
    assert.equal(list[1].username, next.username);

    // The response may renew a password; it may not point us at another server.
    const hijack = [stun];
    assert.equal(applyTurnCredentials(hijack, { username: 'u:securebit', credential: 'c', urls: ['turn:relay.evil.example:3478'] }), false);
    assert.equal(hijack.length, 1);
    const mixed = [];
    applyTurnCredentials(mixed, { username: 'u:securebit', credential: 'c', urls: ['turn:relay.evil.example:3478', 'turn:turn.securebit.chat:3478'] });
    assert.deepEqual(mixed[0].urls, ['turn:turn.securebit.chat:3478']);

    // Expired credentials are refused outright.
    assert.equal(parseCredentialResponse(body, NOW + endpoint.TTL_SECONDS + 1), null);
}

// The shipped production config carries no relay password any more.
{
    const fs = await import('node:fs');
    const prod = fs.readFileSync(new URL('../config/ice-servers.prod.js', import.meta.url), 'utf8');
    assert.doesNotMatch(prod, /credential\s*:/, 'config/ice-servers.prod.js must not ship a TURN password');
    assert.doesNotMatch(prod, /urls:\s*\[?\s*'turns?:/, 'the relay is added at runtime, not listed statically');
}

console.log('turn-credentials.test.mjs: all assertions passed');
