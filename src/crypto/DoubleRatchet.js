/**
 * Double Ratchet (Signal specification) for SecureBit.chat.
 *
 * WHY THIS EXISTS
 * ---------------
 * Until now the session derived one set of keys from a single ECDH at handshake
 * time and used them for the whole conversation. `rotateKeys()` was written but
 * never called and `keyRotationInterval` was null, so a key recovered at any
 * point — from a heap snapshot, a compromised extension, a seized device with
 * the tab still open — decrypted every message ever sent in that session,
 * including messages sent hours earlier. Forward secrecy existed only BETWEEN
 * sessions.
 *
 * The Double Ratchet fixes both halves of that:
 *
 *   - Symmetric ratchet: each message gets its own key, derived from a chain key
 *     by a one-way KDF. The message key is destroyed after use and the chain key
 *     is replaced by its successor, so a key captured now cannot reproduce any
 *     earlier one. That is forward secrecy per message.
 *
 *   - DH ratchet: each time the conversation changes direction, the replying
 *     side introduces a fresh ECDH key pair and both sides mix a new shared
 *     secret into the root key. An attacker who learns the entire state is
 *     locked out again as soon as one message is exchanged in each direction.
 *     That is post-compromise security, which no amount of symmetric ratcheting
 *     provides.
 *
 * INITIALISATION WITHOUT A HANDSHAKE CHANGE
 * -----------------------------------------
 * Signal bootstraps from a pre-key bundle. We do not need one: both peers
 * already hold each other's authenticated ECDH public key from the existing
 * handshake, and the SAS the user compared covers exactly those keys. So the
 * initiator starts with a fresh ratchet key against the peer's handshake key,
 * and the responder starts with its own handshake key pair as its ratchet pair.
 * The first DH ratchet then agrees on the same secret from both directions.
 * Nothing new has to be sent during setup, which keeps the change confined to
 * the message path.
 *
 * WHAT IS AUTHENTICATED
 * ---------------------
 * The header (ratchet public key, previous chain length, message number) travels
 * in the clear — the receiver needs it before it can derive a key — but it is
 * passed to AES-GCM as additional authenticated data. Tampering with any header
 * field makes decryption fail rather than silently redirecting the ratchet.
 */

const ROOT_INFO = 'SecureBit-DR-Root-v1';
const MESSAGE_INFO = 'SecureBit-DR-Message-v1';
const INIT_INFO = 'SecureBit-DR-Init-v1';

// Chain-key advance constants, per the Signal spec's KDF_CK.
const MK_SEED = Uint8Array.of(0x01);
const CK_SEED = Uint8Array.of(0x02);

const enc = new TextEncoder();
const dec = new TextDecoder();

/**
 * Bounds on out-of-order tolerance. These are a DoS control, not a tuning knob:
 * every skipped message forces us to derive and RETAIN a key, so an attacker who
 * can pick message numbers would otherwise make us allocate without limit by
 * sending n = 2^31 once.
 */
export const RATCHET_LIMITS = Object.freeze({
    // How far ahead of the expected number a single message may jump.
    MAX_SKIP_PER_CHAIN: 512,
    // Total retained keys for messages that never arrived, across all chains.
    MAX_SKIPPED_KEYS: 1024,
    // Retained keys older than this are dropped: the data channel is reliable
    // and ordered, so a gap that has not resolved in minutes never will.
    SKIPPED_KEY_TTL_MS: 5 * 60 * 1000
});

function b64(bytes) {
    let binary = '';
    const view = new Uint8Array(bytes);
    for (let i = 0; i < view.length; i++) binary += String.fromCharCode(view[i]);
    return btoa(binary);
}

function unb64(text) {
    const binary = atob(text);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
}

function zeroize(bytes) {
    try {
        if (bytes && bytes.length) {
            crypto.getRandomValues(bytes);
            bytes.fill(0);
        }
    } catch (_) { /* detached buffer — already unreadable */ }
}

async function hkdf(ikm, salt, info, lengthBytes) {
    const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) },
        key,
        lengthBytes * 8
    );
    return new Uint8Array(bits);
}

async function hmac(keyBytes, data) {
    const key = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}

/** KDF_CK — advance a chain and emit this message's key. One-way by construction. */
async function advanceChain(chainKey) {
    const messageKey = await hmac(chainKey, MK_SEED);
    const nextChainKey = await hmac(chainKey, CK_SEED);
    return { messageKey, nextChainKey };
}

/** KDF_RK — mix a fresh DH secret into the root key, yielding the next chain. */
async function advanceRoot(rootKey, dhOutput) {
    const derived = await hkdf(dhOutput, rootKey, ROOT_INFO, 64);
    const nextRoot = derived.slice(0, 32);
    const chainKey = derived.slice(32, 64);
    zeroize(derived);
    return { nextRoot, chainKey };
}

export class DoubleRatchet {
    constructor() {
        this._rootKey = null;
        this._sendingChainKey = null;
        this._receivingChainKey = null;
        this._selfKeyPair = null;      // DHs
        this._remotePublicKey = null;  // DHr
        this._remotePublicKeyB64 = null;
        this._sendCount = 0;           // Ns
        this._receiveCount = 0;        // Nr
        this._previousSendCount = 0;   // PN
        this._skipped = new Map();     // "<dhB64>|<n>" -> { key, storedAt }
        this._namedCurve = 'P-384';
        this._initialised = false;
    }

    /**
     * @param {object} options
     * @param {Uint8Array} options.sharedSecret  ECDH output from the handshake.
     * @param {Uint8Array} options.sessionSalt   The session's 64-byte salt.
     * @param {CryptoKey}  options.selfPrivateKey    Our handshake ECDH private key.
     * @param {CryptoKey}  options.remotePublicKey   Peer's handshake ECDH public key.
     * @param {boolean}    options.isInitiator   True for the side that created the offer.
     */
    async init({ sharedSecret, sessionSalt, selfPrivateKey, remotePublicKey, isInitiator }) {
        if (!(sharedSecret instanceof Uint8Array) || sharedSecret.length === 0) {
            throw new Error('DoubleRatchet: a shared secret is required');
        }
        if (!(selfPrivateKey instanceof CryptoKey) || !(remotePublicKey instanceof CryptoKey)) {
            throw new Error('DoubleRatchet: handshake ECDH keys are required');
        }

        this._namedCurve = selfPrivateKey.algorithm?.namedCurve || 'P-384';

        // The root key is bound to the session salt, so two sessions between the
        // same pair of long-term keys never share ratchet state.
        this._rootKey = await hkdf(sharedSecret, sessionSalt ?? new Uint8Array(0), INIT_INFO, 32);

        if (isInitiator) {
            // Send first: adopt a fresh ratchet key immediately and step the root
            // once, so the very first message already leaves the handshake key
            // behind.
            this._selfKeyPair = await this._generateKeyPair();

            // Deliberately NOT exported to base64 here. The peer's handshake
            // public key arrives via importSignedPublicKey, which imports it as
            // NON-EXTRACTABLE — exporting it throws InvalidAccessError and would
            // abort ratchet setup on the initiator only, silently downgrading it
            // to static keys while the responder ran fine. The b64 form exists
            // solely to recognise a changed ratchet key on inbound messages, and
            // there are none yet: leaving it null makes the peer's first message
            // (which carries their own fresh ratchet key) correctly read as a new
            // chain and trigger the DH ratchet.
            this._remotePublicKey = remotePublicKey;
            this._remotePublicKeyB64 = null;

            const dh = await this._dh(this._selfKeyPair.privateKey, this._remotePublicKey);
            const { nextRoot, chainKey } = await advanceRoot(this._rootKey, dh);
            zeroize(dh);
            zeroize(this._rootKey);
            this._rootKey = nextRoot;
            this._sendingChainKey = chainKey;
        } else {
            // Receive first: keep the handshake key pair as the current ratchet
            // pair so the initiator's first DH lands on a key we hold, and take
            // no chain until that message arrives.
            this._selfKeyPair = { privateKey: selfPrivateKey, publicKey: null };
            this._remotePublicKey = null;
            this._remotePublicKeyB64 = null;
        }

        this._initialised = true;
    }

    get isInitialised() { return this._initialised; }

    /**
     * False on the responder until the initiator's first message arrives.
     *
     * This is inherent to the Double Ratchet, not an implementation gap: the
     * responder's sending chain is only defined once it has seen the initiator's
     * ratchet key, because both sides must derive it from the same DH. Callers
     * have to check this rather than assume, or the responder's first message —
     * which the app sends automatically as a presence update the moment
     * verification completes — throws instead of going out.
     */
    get canEncrypt() {
        return this._initialised && this._sendingChainKey !== null;
    }

    /** Diagnostics only — deliberately exposes no key material. */
    getState() {
        return {
            initialised: this._initialised,
            sending: this._sendingChainKey !== null,
            receiving: this._receivingChainKey !== null,
            sendCount: this._sendCount,
            receiveCount: this._receiveCount,
            previousSendCount: this._previousSendCount,
            skippedKeys: this._skipped.size
        };
    }

    async _generateKeyPair() {
        return crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: this._namedCurve },
            false,
            ['deriveKey', 'deriveBits']
        );
    }

    async _dh(privateKey, publicKey) {
        const bits = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: publicKey }, privateKey, 256
        );
        return new Uint8Array(bits);
    }

    async _selfPublicKeyB64() {
        if (!this._selfKeyPair?.publicKey) return null;
        return b64(await crypto.subtle.exportKey('spki', this._selfKeyPair.publicKey));
    }

    async _importPublic(spkiB64) {
        return crypto.subtle.importKey(
            'spki', unb64(spkiB64), { name: 'ECDH', namedCurve: this._namedCurve }, true, []
        );
    }

    /** Derive the AES-GCM key and IV for one message, then forget the message key. */
    async _messageCipher(messageKey) {
        const material = await hkdf(messageKey, new Uint8Array(32), MESSAGE_INFO, 44);
        const key = await crypto.subtle.importKey(
            'raw', material.slice(0, 32), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
        );
        const iv = material.slice(32, 44);
        zeroize(material);
        return { key, iv };
    }

    /**
     * @param {string} plaintext
     * @returns {Promise<{header: string, ciphertext: string}>} header is the exact
     *   string that must be transmitted and fed back to decrypt(): it doubles as
     *   the AAD, so re-serialising it on the far side could change a byte and
     *   fail authentication for no reason.
     */
    async encrypt(plaintext) {
        if (!this._initialised) throw new Error('DoubleRatchet: not initialised');
        if (!this._sendingChainKey) {
            throw new Error('DoubleRatchet: no sending chain — awaiting the peer\'s first message');
        }

        const { messageKey, nextChainKey } = await advanceChain(this._sendingChainKey);
        zeroize(this._sendingChainKey);
        this._sendingChainKey = nextChainKey;

        const header = JSON.stringify({
            dh: await this._selfPublicKeyB64(),
            pn: this._previousSendCount,
            n: this._sendCount
        });
        this._sendCount += 1;

        const { key, iv } = await this._messageCipher(messageKey);
        zeroize(messageKey);

        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, additionalData: enc.encode(header) },
            key,
            enc.encode(plaintext)
        );

        return { header, ciphertext: b64(ciphertext) };
    }

    /**
     * @param {string} header      Exactly the string produced by encrypt().
     * @param {string} ciphertext  Base64 body.
     * @returns {Promise<string>} plaintext
     */
    async decrypt(header, ciphertext) {
        if (!this._initialised) throw new Error('DoubleRatchet: not initialised');

        let parsed;
        try {
            parsed = JSON.parse(header);
        } catch (_) {
            throw new Error('DoubleRatchet: malformed header');
        }
        const { dh, pn, n } = parsed;
        if (typeof dh !== 'string' || !Number.isSafeInteger(n) || n < 0 ||
            !Number.isSafeInteger(pn) || pn < 0) {
            throw new Error('DoubleRatchet: invalid header fields');
        }

        this._pruneSkipped();

        // A key retained for a message that arrived late. Only drop it once the
        // message actually opens: a forged frame quoting a real header must not
        // consume the key that the genuine message still needs.
        const skippedId = `${dh}|${n}`;
        const retained = this._skipped.get(skippedId);
        if (retained) {
            const plaintext = await this._open(retained.key, header, ciphertext);
            this._skipped.delete(skippedId);
            zeroize(retained.key);
            return plaintext;
        }

        // SECURITY / ROBUSTNESS: everything below is staged and only committed
        // once the message authenticates. The header is attacker-reachable — it
        // travels in the clear so the receiver can route on it — and mutating the
        // ratchet before verifying would let one forged or corrupted frame
        // advance our chains past the peer's, desynchronising the session
        // permanently. AES-GCM covers the header as AAD, so a bad frame is
        // detected; it must simply leave no trace when it is.
        const staged = await this._stageReceive(dh, pn, n);

        let plaintext;
        try {
            plaintext = await this._open(staged.messageKey, header, ciphertext);
        } catch (error) {
            staged.discard();
            throw error;
        }

        staged.commit();
        return plaintext;
    }

    /**
     * Work out which key opens this message and what the resulting state would
     * be, without touching `this`. Returns the candidate key plus commit/discard.
     */
    async _stageReceive(dh, pn, n) {
        const isNewChain = dh !== this._remotePublicKeyB64;
        const pending = [];       // skipped keys to retain on commit
        const toZeroOnCommit = []; // superseded chain keys
        let ratchet = null;

        let chainKey;
        let receiveCount;
        let remoteB64;

        if (isNewChain) {
            // Messages still missing from the OLD chain, before it is replaced.
            if (this._receivingChainKey) {
                const carried = await this._collectSkipped(
                    this._receivingChainKey, this._receiveCount, pn, this._remotePublicKeyB64
                );
                pending.push(...carried.keys);
                toZeroOnCommit.push(carried.finalChainKey);
            }
            ratchet = await this._stageDhRatchet(dh);
            chainKey = ratchet.receivingChainKey;
            receiveCount = 0;
            remoteB64 = dh;
        } else {
            chainKey = this._receivingChainKey;
            receiveCount = this._receiveCount;
            remoteB64 = this._remotePublicKeyB64;
        }

        if (!chainKey) {
            throw new Error('DoubleRatchet: no receiving chain for this message');
        }

        const gap = await this._collectSkipped(chainKey, receiveCount, n, remoteB64);
        pending.push(...gap.keys);

        const { messageKey, nextChainKey } = await advanceChain(gap.finalChainKey);
        if (gap.finalChainKey !== chainKey) toZeroOnCommit.push(gap.finalChainKey);

        return {
            messageKey,
            commit: () => {
                if (ratchet) ratchet.apply();
                if (this._receivingChainKey && this._receivingChainKey !== nextChainKey) {
                    zeroize(this._receivingChainKey);
                }
                for (const key of toZeroOnCommit) zeroize(key);
                this._receivingChainKey = nextChainKey;
                this._receiveCount = n + 1;
                this._remotePublicKeyB64 = remoteB64;
                for (const { id, key } of pending) this._rememberSkipped(id, key);
                zeroize(messageKey);
            },
            discard: () => {
                if (ratchet) ratchet.discard();
                for (const { key } of pending) zeroize(key);
                for (const key of toZeroOnCommit) zeroize(key);
                zeroize(nextChainKey);
                zeroize(messageKey);
            }
        };
    }

    /**
     * Derive the keys for messages `from`..`until-1` without mutating state.
     * `until` comes off the wire, so the jump is bounded here rather than trusted.
     */
    async _collectSkipped(chainKey, from, until, remoteB64) {
        if (until < from) {
            // An older number on a chain we have already advanced past: either a
            // replay or a duplicate. Its key is gone, so it cannot be opened.
            throw new Error('DoubleRatchet: message number is behind the current chain');
        }
        if (until - from > RATCHET_LIMITS.MAX_SKIP_PER_CHAIN) {
            throw new Error(
                `DoubleRatchet: refusing to skip ${until - from} messages ` +
                `(limit ${RATCHET_LIMITS.MAX_SKIP_PER_CHAIN})`
            );
        }

        const keys = [];
        let current = chainKey;
        for (let i = from; i < until; i++) {
            const { messageKey, nextChainKey } = await advanceChain(current);
            if (current !== chainKey) zeroize(current);
            current = nextChainKey;
            keys.push({ id: `${remoteB64}|${i}`, key: messageKey });
        }
        return { keys, finalChainKey: current };
    }

    async _open(messageKey, header, ciphertext) {
        const { key, iv } = await this._messageCipher(messageKey);
        let opened;
        try {
            opened = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv, additionalData: enc.encode(header) },
                key,
                unb64(ciphertext)
            );
        } catch (_) {
            // Wrong key, tampered body, or a tampered header — AES-GCM cannot
            // tell us which, and neither should we: the answer is the same.
            throw new Error('DoubleRatchet: authentication failed');
        }
        return dec.decode(opened);
    }

    _rememberSkipped(id, key) {
        // Oldest-first eviction keeps the cache bounded even if every gap is
        // legitimate; losing the oldest gap is preferable to unbounded growth.
        while (this._skipped.size >= RATCHET_LIMITS.MAX_SKIPPED_KEYS) {
            const oldest = this._skipped.keys().next().value;
            const evicted = this._skipped.get(oldest);
            this._skipped.delete(oldest);
            if (evicted) zeroize(evicted.key);
        }
        this._skipped.set(id, { key, storedAt: Date.now() });
    }

    _pruneSkipped() {
        const cutoff = Date.now() - RATCHET_LIMITS.SKIPPED_KEY_TTL_MS;
        for (const [id, entry] of this._skipped) {
            if (entry.storedAt < cutoff) {
                zeroize(entry.key);
                this._skipped.delete(id);
            }
        }
    }

    /**
     * Compute the DH-ratchet step without applying it. The caller applies it only
     * after the triggering message has authenticated — see _stageReceive.
     */
    async _stageDhRatchet(remotePublicKeyB64) {
        const remotePublicKey = await this._importPublic(remotePublicKeyB64);

        // Receiving chain: our CURRENT key pair against their new key. For the
        // responder's first ratchet this is still the handshake key pair, which
        // is exactly what the initiator derived against at init.
        const receiveDh = await this._dh(this._selfKeyPair.privateKey, remotePublicKey);
        const received = await advanceRoot(this._rootKey, receiveDh);
        zeroize(receiveDh);

        // Sending chain: a fresh key pair, so our next message moves the ratchet
        // on again. This is the step that locks out an attacker who captured the
        // previous state — without it there is no post-compromise security.
        const nextSelfKeyPair = await this._generateKeyPair();
        const sendDh = await this._dh(nextSelfKeyPair.privateKey, remotePublicKey);
        const sending = await advanceRoot(received.nextRoot, sendDh);
        zeroize(sendDh);

        return {
            receivingChainKey: received.chainKey,
            apply: () => {
                zeroize(this._rootKey);
                zeroize(received.nextRoot);
                if (this._sendingChainKey) zeroize(this._sendingChainKey);
                this._rootKey = sending.nextRoot;
                this._sendingChainKey = sending.chainKey;
                this._selfKeyPair = nextSelfKeyPair;
                this._remotePublicKey = remotePublicKey;
                this._remotePublicKeyB64 = remotePublicKeyB64;
                this._previousSendCount = this._sendCount;
                this._sendCount = 0;
            },
            discard: () => {
                zeroize(received.nextRoot);
                zeroize(received.chainKey);
                zeroize(sending.nextRoot);
                zeroize(sending.chainKey);
            }
        };
    }

    /** Destroy every piece of key material this object holds. */
    destroy() {
        zeroize(this._rootKey);
        zeroize(this._sendingChainKey);
        zeroize(this._receivingChainKey);
        for (const entry of this._skipped.values()) zeroize(entry.key);
        this._skipped.clear();
        this._rootKey = null;
        this._sendingChainKey = null;
        this._receivingChainKey = null;
        this._selfKeyPair = null;
        this._remotePublicKey = null;
        this._remotePublicKeyB64 = null;
        this._initialised = false;
    }
}
