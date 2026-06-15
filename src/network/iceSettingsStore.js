// Persistent, at-rest-encrypted storage for the user's custom ICE (STUN/TURN)
// configuration. Persistence is OPTIONAL: the UI only calls saveIceSettings when
// the user explicitly opts in ("Save on this device"). Session-only use never
// touches this store — the settings live in React state and vanish on reload.
//
// At-rest protection model:
//   - A non-extractable AES-GCM device key is generated once and kept in
//     IndexedDB. It can never be exported back into JS, so a copy of the
//     on-disk database is useless without executing code in this exact origin.
//   - The settings blob (which may contain TURN credentials) is encrypted with
//     that key before being written.
//   This protects against disk/profile inspection. It does NOT protect against a
//   live code-execution compromise of the page (consistent with the project's
//   stated threat model — see SECURITY.md). Credentials are never persisted in
//   plaintext, and the user can delete them at any time via clearIceSettings().

const DB_NAME = 'securebit-net';
const DB_VERSION = 1;
const STORE = 'kv';
const KEY_RECORD = 'ice-device-key';
const SETTINGS_RECORD = 'ice-settings';
const SETTINGS_VERSION = 1;

function isSupported() {
    return typeof indexedDB !== 'undefined' &&
        typeof crypto !== 'undefined' &&
        !!crypto.subtle;
}

function openDb() {
    return new Promise((resolve, reject) => {
        let request;
        try {
            request = indexedDB.open(DB_NAME, DB_VERSION);
        } catch (error) {
            reject(error);
            return;
        }
        request.onupgradeneeded = () => {
            const db = request.result;
            if (!db.objectStoreNames.contains(STORE)) {
                db.createObjectStore(STORE);
            }
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

function idbGet(db, key) {
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, 'readonly');
        const req = tx.objectStore(STORE).get(key);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

function idbPut(db, key, value) {
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, 'readwrite');
        tx.objectStore(STORE).put(value, key);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
}

function idbDelete(db, key) {
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, 'readwrite');
        tx.objectStore(STORE).delete(key);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
}

async function getOrCreateDeviceKey(db) {
    const existing = await idbGet(db, KEY_RECORD);
    if (existing instanceof CryptoKey) {
        return existing;
    }
    const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false, // non-extractable
        ['encrypt', 'decrypt']
    );
    await idbPut(db, KEY_RECORD, key);
    return key;
}

/**
 * Persist custom ICE settings, encrypted at rest.
 * @param {{ servers: Array, privacyMode: string }} settings
 */
export async function saveIceSettings(settings) {
    if (!isSupported()) throw new Error('Persistent storage is not available in this browser');

    const db = await openDb();
    const key = await getOrCreateDeviceKey(db);

    const payload = JSON.stringify({
        version: SETTINGS_VERSION,
        servers: Array.isArray(settings?.servers) ? settings.servers : [],
        privacyMode: settings?.privacyMode === 'relay-only' ? 'relay-only' : 'standard'
    });

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        new TextEncoder().encode(payload)
    );

    await idbPut(db, SETTINGS_RECORD, {
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(ciphertext))
    });
}

/**
 * Load and decrypt previously saved ICE settings.
 * Fails closed: returns null if absent, unsupported, or undecryptable.
 * @returns {Promise<{ servers: Array, privacyMode: string }|null>}
 */
export async function loadIceSettings() {
    if (!isSupported()) return null;

    try {
        const db = await openDb();
        const record = await idbGet(db, SETTINGS_RECORD);
        if (!record || !Array.isArray(record.iv) || !Array.isArray(record.data)) {
            return null;
        }
        const key = await idbGet(db, KEY_RECORD);
        if (!(key instanceof CryptoKey)) return null;

        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: new Uint8Array(record.iv) },
            key,
            new Uint8Array(record.data)
        );
        const parsed = JSON.parse(new TextDecoder().decode(plaintext));
        return {
            servers: Array.isArray(parsed.servers) ? parsed.servers : [],
            privacyMode: parsed.privacyMode === 'relay-only' ? 'relay-only' : 'standard'
        };
    } catch {
        // Corrupted or tampered record: fail closed.
        return null;
    }
}

/** Delete any persisted ICE settings (the device key is left in place). */
export async function clearIceSettings() {
    if (!isSupported()) return;
    try {
        const db = await openDb();
        await idbDelete(db, SETTINGS_RECORD);
    } catch {
        // Best-effort deletion; nothing to surface to the user.
    }
}

export async function hasSavedIceSettings() {
    if (!isSupported()) return false;
    try {
        const db = await openDb();
        const record = await idbGet(db, SETTINGS_RECORD);
        return !!record;
    } catch {
        return false;
    }
}
