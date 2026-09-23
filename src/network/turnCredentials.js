// Keeps the credential for SecureBit's own TURN relay fresh.
//
// The relay's credential is no longer something the client carries: it is minted
// by the site (POST /api/turn-credentials, see deploy/turn-credentials.js) and
// expires after a day. This module fetches one at startup and again before it
// runs out, and writes it into the ICE list the connection managers already hold.
//
// The update is made IN PLACE on the existing entry objects. Every manager keeps a
// reference to window.SECUREBIT_ICE_SERVERS rather than a copy, so the next peer
// connection — and the next in-band ICE restart, which re-reads the list — picks
// up the new credential without anything else having to know it changed.
//
// If the endpoint cannot be reached, nothing is changed and the entry keeps the
// credential it shipped with. Only our relay's entries are touched; a TURN server
// the user configured themselves is never modified.

const ENDPOINT = '/api/turn-credentials';
const OWN_RELAY_HOSTS = ['turn.securebit.chat', '144.172.96.126'];
const MAX_FIELD = 512;
// How long to wait before trying again after a failed fetch.
const RETRY_DELAYS_MS = [60_000, 5 * 60_000, 15 * 60_000];

function relayHost(url) {
    const m = /^turns?:([^:?\s]+)/i.exec(String(url || '').trim());
    return m ? m[1].toLowerCase() : null;
}

/** True when an ICE entry points at SecureBit's own relay. */
export function isOwnRelayEntry(entry) {
    if (!entry || typeof entry !== 'object') return false;
    const urls = Array.isArray(entry.urls) ? entry.urls : [entry.urls];
    return urls.some((u) => OWN_RELAY_HOSTS.includes(relayHost(u)));
}

function isCleanField(value) {
    if (typeof value !== 'string' || value.length === 0 || value.length > MAX_FIELD) return false;
    for (let i = 0; i < value.length; i++) {
        const c = value.charCodeAt(i);
        if (c < 0x20 || c === 0x7f) return false;
    }
    return true;
}

/**
 * Write a fresh credential into every own-relay entry of `list`, in place.
 * @returns {boolean} whether anything was updated
 */
export function applyTurnCredentials(list, cred) {
    if (!Array.isArray(list) || !cred || !isCleanField(cred.username) || !isCleanField(cred.credential)) {
        return false;
    }
    let updated = false;
    for (const entry of list) {
        if (!isOwnRelayEntry(entry)) continue;
        entry.username = cred.username;
        entry.credential = cred.credential;
        updated = true;
    }
    return updated;
}

/** Pull the credential out of an endpoint response, or null if it is not usable. */
export function parseCredentialResponse(body, nowSeconds) {
    const server = body && Array.isArray(body.iceServers) ? body.iceServers[0] : null;
    if (!server || !isCleanField(server.username) || !isCleanField(server.credential)) return null;
    // coturn REST-API usernames are "<expiry>:<label>"; refuse one already expired.
    const expiry = Number(String(server.username).split(':')[0]);
    if (!Number.isFinite(expiry) || expiry <= nowSeconds) return null;
    const ttl = Number(body.ttl);
    return {
        username: server.username,
        credential: server.credential,
        expiry,
        ttl: Number.isFinite(ttl) && ttl > 0 ? ttl : expiry - nowSeconds,
    };
}

let started = false;

/**
 * Start keeping the relay credential fresh. Safe to call more than once.
 * @param {object} [opts]
 * @param {() => Array} [opts.getList]  the ICE list to update
 */
export function startTurnCredentialRefresh(opts = {}) {
    if (started || typeof window === 'undefined' || typeof fetch !== 'function') return;
    started = true;

    const getList = opts.getList || (() => window.SECUREBIT_ICE_SERVERS);
    let expiry = 0;
    let ttl = 0;
    let timer = null;
    let failures = 0;

    const schedule = (ms) => {
        if (timer) clearTimeout(timer);
        timer = setTimeout(refresh, ms);
    };

    async function refresh() {
        timer = null;
        try {
            const res = await fetch(ENDPOINT, { method: 'POST', cache: 'no-store', credentials: 'omit' });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const cred = parseCredentialResponse(await res.json(), Date.now() / 1000);
            if (!cred) throw new Error('unusable response');
            applyTurnCredentials(getList(), cred);
            expiry = cred.expiry;
            ttl = cred.ttl;
            failures = 0;
            // Renew at half-life, so a call started just before renewal still has
            // hours of validity left for the relay to refresh its allocation.
            schedule(Math.max(60, ttl / 2) * 1000);
        } catch (_) {
            const delay = RETRY_DELAYS_MS[Math.min(failures, RETRY_DELAYS_MS.length - 1)];
            failures++;
            schedule(delay);
        }
    }

    // Timers are throttled in background tabs and stop while a laptop sleeps; on
    // coming back, renew straight away if the credential is past its half-life.
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState !== 'visible') return;
        const now = Date.now() / 1000;
        if (!expiry || expiry - now < ttl / 2) refresh();
    });

    refresh();
}
