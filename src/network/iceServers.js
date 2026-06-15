// Pure, dependency-free validation and normalization of user-supplied ICE
// (STUN/TURN) servers. No DOM, no browser APIs — safe to unit-test in Node.
//
// Security intent: a user can paste arbitrary text here. We must never hand an
// un-vetted value to RTCPeerConnection, and we must reject anything that is not
// a real STUN/TURN URL (e.g. javascript:, data:, http(s):, ws(s):) so the field
// cannot be abused as an injection surface or silently break the connection.
// Validation is allowlist-based: only known-good schemes, host shapes, and the
// standard transport query are accepted; everything else is rejected.

export const ICE_LIMITS = Object.freeze({
    MAX_SERVERS: 10,
    MAX_URLS_PER_SERVER: 8,
    MAX_STRING_LENGTH: 512
});

// RTCIceServer only accepts these schemes. Everything else is rejected.
export const ALLOWED_ICE_SCHEMES = Object.freeze(['stun', 'stuns', 'turn', 'turns']);

const SCHEME_RE = /^(stuns?|turns?):/i;
// Positive allowlist for the host portion: hostname/IPv4, or bracketed IPv6,
// with an optional numeric port. Anything outside this shape is rejected.
const HOST_RE = /^(\[[0-9a-f:]+\]|[a-z0-9.-]+)(:\d{1,5})?$/i;
const TRANSPORT_RE = /^transport=(udp|tcp)$/i;

// True if the string contains any ASCII control character (0x00–0x1F or 0x7F).
// Implemented via char codes to keep the source free of literal control bytes.
function hasControlChars(value) {
    for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i);
        if (code < 0x20 || code === 0x7f) return true;
    }
    return false;
}

/**
 * Validate a single ICE URL string.
 * @returns {string|null} error message, or null if valid.
 */
export function validateIceUrl(url) {
    if (typeof url !== 'string') return 'URL must be a string';
    const trimmed = url.trim();
    if (!trimmed) return 'URL is empty';
    if (trimmed.length > ICE_LIMITS.MAX_STRING_LENGTH) return 'URL is too long';
    if (hasControlChars(trimmed)) return 'URL contains invalid characters';

    const scheme = trimmed.match(SCHEME_RE);
    if (!scheme) {
        return 'URL must start with stun:, stuns:, turn: or turns:';
    }

    // Validate the part after "<scheme>:" — host[:port][?transport=udp|tcp].
    const rest = trimmed.slice(scheme[0].length);
    const [hostPort, query, ...extra] = rest.split('?');
    if (extra.length > 0) return 'URL has an invalid query';
    if (!hostPort) return 'URL is missing a host';
    if (!HOST_RE.test(hostPort)) return 'URL has an invalid host or port';

    if (query !== undefined && !TRANSPORT_RE.test(query)) {
        return 'URL query must be transport=udp or transport=tcp';
    }

    return null;
}

export function isTurnUrl(url) {
    return typeof url === 'string' && /^turns?:/i.test(url.trim());
}

function validateSecret(value, label) {
    if (value === undefined || value === null || value === '') return null;
    if (typeof value !== 'string') return `${label} must be a string`;
    if (value.length > ICE_LIMITS.MAX_STRING_LENGTH) return `${label} is too long`;
    if (hasControlChars(value)) return `${label} contains invalid characters`;
    return null;
}

/**
 * Validate and normalize a list of ICE server entries.
 * Each entry: { urls: string | string[], username?: string, credential?: string }
 * @returns {{ servers: Array, errors: string[], warnings: string[] }}
 */
export function normalizeIceServers(entries) {
    const errors = [];
    const warnings = [];
    const servers = [];

    if (!Array.isArray(entries)) {
        return { servers: [], errors: ['Server list must be an array'], warnings: [] };
    }
    if (entries.length === 0) {
        return { servers: [], errors: [], warnings: [] };
    }
    if (entries.length > ICE_LIMITS.MAX_SERVERS) {
        errors.push(`Too many servers (max ${ICE_LIMITS.MAX_SERVERS})`);
        return { servers: [], errors, warnings };
    }

    entries.forEach((entry, index) => {
        const label = `Server #${index + 1}`;
        if (!entry || typeof entry !== 'object') {
            errors.push(`${label}: invalid entry`);
            return;
        }

        const rawUrls = Array.isArray(entry.urls) ? entry.urls : [entry.urls];
        if (rawUrls.length === 0 || rawUrls.length > ICE_LIMITS.MAX_URLS_PER_SERVER) {
            errors.push(`${label}: between 1 and ${ICE_LIMITS.MAX_URLS_PER_SERVER} URLs required`);
            return;
        }

        const cleanUrls = [];
        let entryHasTurn = false;
        for (const rawUrl of rawUrls) {
            const err = validateIceUrl(rawUrl);
            if (err) {
                errors.push(`${label}: ${err}`);
                continue;
            }
            const trimmed = rawUrl.trim();
            cleanUrls.push(trimmed);
            if (isTurnUrl(trimmed)) entryHasTurn = true;
        }
        if (cleanUrls.length === 0) return;

        const userErr = validateSecret(entry.username, `${label} username`);
        if (userErr) errors.push(userErr);
        const credErr = validateSecret(entry.credential, `${label} credential`);
        if (credErr) errors.push(credErr);

        const server = { urls: cleanUrls.length === 1 ? cleanUrls[0] : cleanUrls };
        if (entry.username) server.username = String(entry.username);
        if (entry.credential) server.credential = String(entry.credential);

        if (entryHasTurn && (!server.username || !server.credential)) {
            warnings.push(`${label}: TURN servers usually require a username and credential`);
        }

        servers.push(server);
    });

    return { servers, errors, warnings };
}

/**
 * Parse free-form user input into ICE server entries.
 * Accepts either a JSON array of RTCIceServer-like objects, or one URL per line
 * (URL-only servers, e.g. public STUN). Returns normalized + validated output.
 */
export function parseIceServersInput(text) {
    if (typeof text !== 'string' || !text.trim()) {
        return { servers: [], errors: [], warnings: [] };
    }

    const trimmed = text.trim();
    if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
        let parsed;
        try {
            parsed = JSON.parse(trimmed);
        } catch {
            return { servers: [], errors: ['Invalid JSON'], warnings: [] };
        }
        const arr = Array.isArray(parsed) ? parsed : [parsed];
        return normalizeIceServers(arr);
    }

    // Line-based: each non-empty line is a single URL-only server.
    const entries = trimmed
        .split('\n')
        .map(line => line.trim())
        .filter(Boolean)
        .map(url => ({ urls: url }));
    return normalizeIceServers(entries);
}

/** Does a normalized server list contain at least one TURN/TURNS server? */
export function listHasTurn(servers) {
    if (!Array.isArray(servers)) return false;
    return servers.some(server => {
        const urls = Array.isArray(server?.urls) ? server.urls : [server?.urls];
        return urls.some(isTurnUrl);
    });
}
