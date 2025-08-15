import init, * as wasm from './pkg/enhanced_secure_crypto.js';

export class SecureCryptoBridge {
    constructor() {
        this.wasmModule = null;
        this.cryptoUtils = null;
        this.isInitialized = false;
    }

    async initialize() {
        try {
            await init();
            this.cryptoUtils = new wasm.EnhancedSecureCryptoUtils();
            this.isInitialized = true;
            console.log('✅ Secure Crypto WASM module initialized successfully');
            return true;
        } catch (error) {
            console.error('❌ Failed to initialize WASM module:', error);
            return false;
        }
    }

    ensureInitialized() {
        if (!this.isInitialized) {
            throw new Error('Crypto module not initialized. Call initialize() first.');
        }
    }

    async encryptData(data, password) {
        this.ensureInitialized();
        try {
            return this.cryptoUtils.encrypt_data(data, password);
        } catch (error) {
            throw new Error(`Encryption failed: ${error.message}`);
        }
    }

    async decryptData(encryptedData, password) {
        this.ensureInitialized();
        try {
            return this.cryptoUtils.decrypt_data(encryptedData, password);
        } catch (error) {
            throw new Error(`Decryption failed: ${error.message}`);
        }
    }

    generateSecurePassword() {
        this.ensureInitialized();
        return this.cryptoUtils.generate_secure_password();
    }

    generateSalt() {
        this.ensureInitialized();
        return Array.from(this.cryptoUtils.generate_salt());
    }

    async generateECDSAKeyPair() {
        this.ensureInitialized();
        try {
            return this.cryptoUtils.generate_ecdsa_keypair();
        } catch (error) {
            throw new Error(`Key generation failed: ${error.message}`);
        }
    }

    sanitizeMessage(message) {
        this.ensureInitialized();
        return this.cryptoUtils.sanitize_message(message);
    }

    arrayBufferToBase64(buffer) {
        this.ensureInitialized();
        return wasm.array_buffer_to_base64(buffer);
    }

    base64ToArrayBuffer(base64Str) {
        this.ensureInitialized();
        return Array.from(wasm.base64_to_array_buffer(base64Str));
    }
}

let cryptoBridgeInstance = null;

export function getCryptoBridge() {
    if (!cryptoBridgeInstance) {
        cryptoBridgeInstance = new SecureCryptoBridge();
    }
    return cryptoBridgeInstance;
}