import assert from 'node:assert/strict';

globalThis.window = { EnhancedSecureCryptoUtils: {} };
const { SecureIndexedDBWrapper, SecurePersistentKeyStorage } = await import('../src/network/EnhancedSecureWebRTCManager.js');

class FakeMasterKeyManager {
    isUnlocked() { return true; }
    async unlock() {}
    async encryptBytes(bytes) {
        return { encryptedData: Uint8Array.from(bytes, byte => byte ^ 0xaa), iv: new Uint8Array(12).fill(7) };
    }
    async decryptBytes(bytes, iv) {
        if (!iv || iv[0] !== 7) throw new Error('bad iv');
        return Uint8Array.from(bytes, byte => byte ^ 0xaa);
    }
}

class FakeDB {
    constructor(records = []) {
        this.records = new Map(records.map(record => [record.keyId, record]));
    }
    async initialize() {}
    async listKeys() { return [...this.records.values()]; }
    async getKeyMetadataRecord(keyId) { return this.records.get(keyId) || null; }
    async putKeyMetadataRecord(record) { this.records.set(record.keyId, record); }
}

class FakeIndexedDBConnection {
    constructor() {
        this.records = new Map();
    }
    transaction(storeNames) {
        const transaction = {
            objectStore: (name) => ({
                put: (record) => {
                    this.records.set(name, record);
                    queueMicrotask(() => transaction.oncomplete?.());
                    return {};
                }
            }),
            oncomplete: null,
            onerror: null
        };
        return transaction;
    }
}

// New metadata is encrypted and sensitive fields are not plaintext.
{
    const db = new FakeDB();
    const storage = new SecurePersistentKeyStorage(new FakeMasterKeyManager(), db);
    const encrypted = await storage._encryptMetadata({
        created: 111,
        lastAccessed: 222,
        sessionId: 'session-secret',
        peerId: 'peer-secret'
    });
    await db.putKeyMetadataRecord({ keyId: 'k1', ...encrypted });
    const raw = db.records.get('k1');
    assert.equal(raw.created, undefined);
    assert.equal(raw.lastAccessed, undefined);
    assert.equal(raw.sessionId, undefined);
    assert.ok(Array.isArray(raw.encryptedMetadata));
}

// Old plaintext metadata can be read and is migrated.
{
    const db = new FakeDB([{ keyId: 'legacy', created: 1, lastAccessed: 2, sessionId: 'old-session' }]);
    const storage = new SecurePersistentKeyStorage(new FakeMasterKeyManager(), db);
    const listed = await storage.listStoredKeys();
    assert.equal(listed[0].sessionId, 'old-session');
    const migrated = db.records.get('legacy');
    assert.equal(migrated.sessionId, undefined);
    assert.ok(migrated.encryptedMetadata);
}

// Corrupted encrypted metadata fails safely and is not exposed.
{
    const db = new FakeDB([{ keyId: 'bad', encryptedMetadata: [1, 2, 3], metadataIv: [0] }]);
    const storage = new SecurePersistentKeyStorage(new FakeMasterKeyManager(), db);
    const listed = await storage.listStoredKeys();
    assert.deepEqual(listed, []);
}

// Plaintext timestamp fields are avoidable in the encrypted envelope.
{
    const storage = new SecurePersistentKeyStorage(new FakeMasterKeyManager(), new FakeDB());
    const encrypted = await storage._encryptMetadata({ created: 10, lastAccessed: 20, usageCount: 3 });
    assert.equal('created' in encrypted, false);
    assert.equal('lastAccessed' in encrypted, false);
    assert.equal('usageCount' in encrypted, false);
}

// Avoidable timestamps are not left plaintext in new IndexedDB records.
{
    const wrapper = new SecureIndexedDBWrapper();
    wrapper.db = new FakeIndexedDBConnection();
    await wrapper.storeEncryptedKey(
        'k2',
        new Uint8Array([1]),
        new Uint8Array([2]),
        { name: 'AES-GCM' },
        ['encrypt'],
        'secret',
        { metadataVersion: 1, encryptedMetadata: [3], metadataIv: [4] }
    );
    assert.equal('timestamp' in wrapper.db.records.get(wrapper.KEYS_STORE), false);
    assert.equal('created' in wrapper.db.records.get(wrapper.METADATA_STORE), false);
    assert.equal('lastAccessed' in wrapper.db.records.get(wrapper.METADATA_STORE), false);
}

console.log('IndexedDB metadata encryption tests passed');
