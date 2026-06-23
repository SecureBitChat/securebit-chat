// ============================================
// SECURE FILE TRANSFER CONTEXT
// ============================================
class SecureFileTransferContext {
    static #instance = null;
    static #contextKey = Symbol('SecureFileTransferContext');
    
    static getInstance() {
        if (!this.#instance) {
            this.#instance = new SecureFileTransferContext();
        }
        return this.#instance;
    }
    
    #fileTransferSystem = null;
    #active = false;
    #securityLevel = 'high';
    
    setFileTransferSystem(system) {
        if (!(system instanceof EnhancedSecureFileTransfer)) {
            throw new Error('Invalid file transfer system instance');
        }
        this.#fileTransferSystem = system;
        this.#active = true;
    }
    
    getFileTransferSystem() {
        return this.#fileTransferSystem;
    }
    
    isActive() {
        return this.#active && this.#fileTransferSystem !== null;
    }
    
    deactivate() {
        this.#active = false;
        this.#fileTransferSystem = null;
    }
    
    getSecurityLevel() {
        return this.#securityLevel;
    }
    
    setSecurityLevel(level) {
        if (['low', 'medium', 'high'].includes(level)) {
            this.#securityLevel = level;
        }
    }
}

// ============================================
// SECURITY ERROR HANDLER
// ============================================

class SecurityErrorHandler {
    static #allowedErrors = new Set([
        'File size exceeds maximum limit',
        'Unsupported file type',
        'Transfer timeout',
        'Connection lost',
        'Invalid file data',
        'File transfer failed',
        'Transfer cancelled',
        'Network error',
        'File not found',
        'Permission denied'
    ]);
    
    static sanitizeError(error) {
        const message = error.message || error;

        for (const allowed of this.#allowedErrors) {
            if (message.includes(allowed)) {
                return allowed;
            }
        }

        console.error('🔒 Internal file transfer error:', {
            message: error.message,
            stack: error.stack,
            timestamp: new Date().toISOString()
        });

        return 'File transfer failed';
    }
    
    static logSecurityEvent(event, details = {}) {
        console.warn('🔒 Security event:', {
            event,
            timestamp: new Date().toISOString(),
            ...details
        });
    }
}

// ============================================
// FILE METADATA SIGNATURE SYSTEM
// ============================================

class FileMetadataSigner {
    static async signFileMetadata(metadata, privateKey) {
        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(JSON.stringify({
                fileId: metadata.fileId,
                fileName: metadata.fileName,
                fileSize: metadata.fileSize,
                fileHash: metadata.fileHash,
                timestamp: metadata.timestamp,
                version: metadata.version || '2.0'
            }));
            
            const signature = await crypto.subtle.sign(
                'RSASSA-PKCS1-v1_5',
                privateKey,
                data
            );
            
            return Array.from(new Uint8Array(signature));
        } catch (error) {
            SecurityErrorHandler.logSecurityEvent('signature_failed', { error: error.message });
            throw new Error('Failed to sign file metadata');
        }
    }
    
    static async verifyFileMetadata(metadata, signature, publicKey) {
        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(JSON.stringify({
                fileId: metadata.fileId,
                fileName: metadata.fileName,
                fileSize: metadata.fileSize,
                fileHash: metadata.fileHash,
                timestamp: metadata.timestamp,
                version: metadata.version || '2.0'
            }));
            
            const signatureBuffer = new Uint8Array(signature);
            
            const isValid = await crypto.subtle.verify(
                'RSASSA-PKCS1-v1_5',
                publicKey,
                signatureBuffer,
                data
            );
            
            if (!isValid) {
                SecurityErrorHandler.logSecurityEvent('invalid_signature', { fileId: metadata.fileId });
            }
            
            return isValid;
        } catch (error) {
            SecurityErrorHandler.logSecurityEvent('verification_failed', { error: error.message });
            return false;
        }
    }
}

// ============================================
// ТОЧНЫЕ ИСПРАВЛЕНИЯ БЕЗОПАСНОСТИ
// ============================================

class MessageSizeValidator {
    static MAX_MESSAGE_SIZE = 1024 * 1024; // 1MB
    
    static isMessageSizeValid(message) {
        const messageString = JSON.stringify(message);
        const sizeInBytes = new Blob([messageString]).size;
        
        if (sizeInBytes > this.MAX_MESSAGE_SIZE) {
            SecurityErrorHandler.logSecurityEvent('message_too_large', {
                size: sizeInBytes,
                limit: this.MAX_MESSAGE_SIZE
            });
            throw new Error('Message too large');
        }
        
        return true;
    }
}

class AtomicOperations {
    constructor() {
        this.locks = new Map();
    }
    
    async withLock(key, operation) {
        // Serialize all operations sharing the same key. Must loop (not a single
        // `if`): when 3+ callers queue on one key they all await the same in-flight
        // lock, so after it resolves we have to re-check before claiming the slot —
        // otherwise multiple operations run concurrently and break atomicity.
        while (this.locks.has(key)) {
            await this.locks.get(key);
        }

        let releaseLock;
        const lockPromise = new Promise(resolve => { releaseLock = resolve; });
        this.locks.set(key, lockPromise);

        try {
            return await operation();
        } finally {
            this.locks.delete(key);
            releaseLock();
        }
    }
}

// Rate limiting для защиты от спама
class RateLimiter {
    constructor(maxRequests, windowMs) {
        this.maxRequests = maxRequests;
        this.windowMs = windowMs;
        this.requests = new Map();
    }
    
    isAllowed(identifier) {
        const now = Date.now();
        const windowStart = now - this.windowMs;
        
        if (!this.requests.has(identifier)) {
            this.requests.set(identifier, []);
        }
        
        const userRequests = this.requests.get(identifier);
        
        const validRequests = userRequests.filter(time => time > windowStart);
        this.requests.set(identifier, validRequests);
        
        if (validRequests.length >= this.maxRequests) {
            SecurityErrorHandler.logSecurityEvent('rate_limit_exceeded', {
                identifier,
                requestCount: validRequests.length,
                limit: this.maxRequests
            });
            return false;
        }
        
        validRequests.push(now);
        return true;
    }
}

class SecureMemoryManager {
    static secureWipe(buffer) {
        if (buffer instanceof ArrayBuffer) {
            const view = new Uint8Array(buffer);
            crypto.getRandomValues(view);
        } else if (buffer instanceof Uint8Array) {
            crypto.getRandomValues(buffer);
        }
    }
    
    static secureDelete(obj, prop) {
        if (obj[prop]) {
            this.secureWipe(obj[prop]);
            delete obj[prop];
        }
    }
}

class EnhancedSecureFileTransfer {
    constructor(webrtcManager, onProgress, onComplete, onError, onFileReceived, onIncomingFileRequest) {
        this.webrtcManager = webrtcManager;
        this.onProgress = onProgress;
        this.onComplete = onComplete;
        this.onError = onError;
        this.onFileReceived = onFileReceived;
        this.onIncomingFileRequest = onIncomingFileRequest;
        
        // Validate webrtcManager
        if (!webrtcManager) {
            throw new Error('webrtcManager is required for EnhancedSecureFileTransfer');
        }
        
        SecureFileTransferContext.getInstance().setFileTransferSystem(this);
        
        this.atomicOps = new AtomicOperations();
        this.rateLimiter = new RateLimiter(10, 60000);

        this.signingKey = null;
        this.verificationKey = null;
        
        // Transfer settings
        // NOTE: chunks are AES-GCM encrypted (+16-byte tag) and Base64-encoded
        // before being wrapped in a JSON `file_chunk` message. Base64 inflates the
        // payload by ~4/3, so the actual bytes handed to RTCDataChannel.send() are
        // much larger than CHUNK_SIZE. The SCTP interop floor for a single WebRTC
        // message is 64 KB (65536 bytes) — Safari and any peer whose SDP omits
        // `a=max-message-size` enforce exactly this limit and will throw on larger
        // sends. A 16 KB chunk yields a ~22 KB on-wire message, safely under that
        // floor on every browser. (64 KB chunks produced ~87 KB messages, which
        // silently failed to send and broke transfers cross-browser.)
        this.CHUNK_SIZE = 16 * 1024; // 16 KB raw -> ~22 KB on the wire (SCTP-safe)
        // Inbound chunks may legitimately be larger (e.g. an older peer that still
        // sends 64 KB chunks), so validate received metadata against this ceiling
        // rather than our own outbound CHUNK_SIZE.
        this.MAX_RECEIVE_CHUNK_SIZE = 64 * 1024;
        this.MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB limit
        this.MAX_CONCURRENT_TRANSFERS = 3;
        this.CHUNK_TIMEOUT = 30000; // 30 seconds per chunk
        this.RETRY_ATTEMPTS = 3;

        this.FILE_TYPE_RESTRICTIONS = {
            pdf: {
                extensions: ['.pdf'],
                mimeTypes: ['application/pdf', 'application/x-pdf', 'application/acrobat'],
                maxSize: 50 * 1024 * 1024,
                category: 'PDF',
                description: 'PDF'
            },

            text: {
                extensions: ['.txt'],
                mimeTypes: ['text/plain', 'application/txt'],
                maxSize: 10 * 1024 * 1024,
                category: 'Plain text',
                description: 'TXT'
            },

            images: {
                extensions: ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.ico'],
                mimeTypes: [
                    'image/jpeg',
                    'image/jpg',
                    'image/pjpeg',
                    'image/png',
                    'image/gif',
                    'image/webp',
                    'image/bmp',
                    'image/x-windows-bmp',
                    'image/x-icon',
                    'image/vnd.microsoft.icon'
                ],
                maxSize: 25 * 1024 * 1024, // 25 MB
                category: 'Images',
                description: 'JPG, JPEG, PNG, GIF, WEBP, BMP, ICO'
            },

            archives: {
                extensions: ['.zip'],
                mimeTypes: [
                    'application/zip',
                    'application/x-zip',
                    'application/x-zip-compressed',
                    'multipart/x-zip'
                ],
                maxSize: 100 * 1024 * 1024, // 100 MB
                category: 'Archives',
                description: 'ZIP'
            }
        };
        this.BLOCKED_EXTENSIONS = new Set([
            '.exe', '.bat', '.cmd', '.sh', '.js', '.msi', '.dmg', '.app',
            '.jar', '.scr', '.ps1', '.vbs', '.html', '.svg'
        ]);
        // Generic MIME types browsers emit when they cannot determine a real one.
        // Treated as acceptable for any allowed extension.
        this._genericMimeTypes = new Set(['application/octet-stream', 'application/binary']);
        // Union of every recognised allowed MIME type (incl. cross-OS aliases),
        // used to keep MIME advisory rather than a strict per-type gate.
        this._allowedMimeTypes = new Set();
        for (const typeConfig of Object.values(this.FILE_TYPE_RESTRICTIONS)) {
            for (const mime of typeConfig.mimeTypes) this._allowedMimeTypes.add(mime);
        }
        
        // Active transfers tracking
        this.activeTransfers = new Map(); // fileId -> transfer state
        this.receivingTransfers = new Map(); // fileId -> receiving state
        this.pendingIncomingTransfers = new Map(); // fileId -> validated metadata awaiting consent
        this.transferQueue = []; // Queue for pending transfers
        this.pendingChunks = new Map();
        this.incomingOfferLimiter = new RateLimiter(5, 60000);
        // Chunks are 16 KB, so a 100 MB file is ~6400 chunks. The previous caps
        // (240 aggregate / 120 per-transfer per minute) throttled to ~64 KB/s and
        // KILLED any file larger than ~3.8 MB mid-transfer. Size the limits to the
        // worst-case file plus retransmission headroom so legitimate transfers are
        // never starved, while still bounding a flooding peer.
        this.incomingChunkLimiter = new RateLimiter(60000, 60000); // aggregate ceiling (~16 MB/s)
        this.incomingTransferChunkLimiters = new Map();
        this.MAX_INCOMING_CHUNKS_PER_TRANSFER_PER_MINUTE = 30000; // per transfer (~8 MB/s)
        this.MAX_PENDING_INCOMING_TRANSFERS = 3;
        
        // Session key derivation
        this.sessionKeys = new Map(); // fileId -> derived session key
        
        // Security
        this.processedChunks = new Set(); // Prevent replay attacks
        this.transferNonces = new Map(); // fileId -> current nonce counter
        this.receivedFileBuffers = new Map(); // fileId -> { buffer:ArrayBuffer, type:string, name:string, size:number }
        this.MAX_RETAINED_RECEIVED_FILE_BUFFERS = 3;

        this.setupFileMessageHandlers();

        if (this.webrtcManager) {
            this.webrtcManager.fileTransferSystem = this;
        }
    }

    // ============================================
    // FILE TYPE VALIDATION SYSTEM
    // ============================================

    getFileType(file) {
        const fileName = String(file?.name || '').toLowerCase();
        const extensionIndex = fileName.lastIndexOf('.');
        const fileExtension = extensionIndex >= 0 ? fileName.substring(extensionIndex) : '';
        const mimeType = String(file?.type || '').toLowerCase();

        // The extension allow-list (plus BLOCKED_EXTENSIONS) is the security
        // boundary. MIME is only an advisory signal: it is client-supplied,
        // varies across browsers/OSes, and is frequently empty. We accept an
        // allowed extension when the MIME is absent, generic, or belongs to any
        // recognised allowed type, but still reject a blatantly foreign MIME
        // (e.g. an executable MIME on a ".png") as a spoofing signal.
        for (const [typeKey, typeConfig] of Object.entries(this.FILE_TYPE_RESTRICTIONS)) {
            const extensionAllowed = typeConfig.extensions.includes(fileExtension);
            if (!extensionAllowed) continue;
            const mimeAcceptable = !mimeType
                || this._genericMimeTypes.has(mimeType)
                || this._allowedMimeTypes.has(mimeType);
            if (mimeAcceptable) {
                return {
                    type: typeKey,
                    category: typeConfig.category,
                    description: typeConfig.description,
                    maxSize: typeConfig.maxSize,
                    allowed: true,
                    extension: fileExtension,
                    mimeType
                };
            }
        }

        return {
            type: 'blocked',
            category: 'Unsupported',
            description: 'Allowed: JPG, JPEG, PNG, GIF, WEBP, BMP, ICO, PDF, TXT, ZIP',
            maxSize: this.MAX_FILE_SIZE,
            allowed: false,
            extension: fileExtension,
            mimeType
        };
    }

    validateFile(file) {
        const fileType = this.getFileType(file);
        const errors = [];
        const fileName = String(file?.name || '');
        const lowerName = fileName.toLowerCase();
        const extensionIndex = lowerName.lastIndexOf('.');
        const fileExtension = extensionIndex >= 0 ? lowerName.substring(extensionIndex) : '';

        if (this.BLOCKED_EXTENSIONS.has(fileExtension)) {
            errors.push(`File rejected: ${fileExtension} files are not allowed for security reasons.`);
        }

        if (file.size > fileType.maxSize) {
            errors.push(`File size (${this.formatFileSize(file.size)}) exceeds maximum allowed for ${fileType.category} (${this.formatFileSize(fileType.maxSize)})`);
        }

        if (!fileType.allowed && !this.BLOCKED_EXTENSIONS.has(fileExtension)) {
            errors.push(`File rejected: unsupported file type. Supported types: ${fileType.description}`);
        }

        if (file.size > this.MAX_FILE_SIZE) {
            errors.push(`File size (${this.formatFileSize(file.size)}) exceeds general limit (${this.formatFileSize(this.MAX_FILE_SIZE)})`);
        }
        
        return {
            isValid: errors.length === 0,
            errors: errors,
            fileType: fileType,
            fileSize: file.size,
            formattedSize: this.formatFileSize(file.size)
        };
    }

    normalizeDisplayFileName(fileName) {
        return String(fileName || '')
            .normalize('NFKC')
            .replace(/[\u0000-\u001F\u007F]/g, '')
            .replace(/[\\/]+/g, '_')
            .trim()
            .slice(0, 255);
    }

    validateIncomingMetadata(metadata) {
        const errors = [];
        if (!metadata || typeof metadata !== 'object') errors.push('Invalid file transfer metadata');
        if (!metadata?.fileId || typeof metadata.fileId !== 'string') errors.push('Invalid file id');
        if (!Number.isSafeInteger(metadata?.fileSize) || metadata.fileSize <= 0) errors.push('Invalid file size');
        if (!Number.isSafeInteger(metadata?.totalChunks) || metadata.totalChunks <= 0) errors.push('Invalid chunk count');
        if (!Number.isSafeInteger(metadata?.chunkSize) || metadata.chunkSize <= 0 || metadata.chunkSize > this.MAX_RECEIVE_CHUNK_SIZE) errors.push('Invalid chunk size');
        if (!Array.isArray(metadata?.salt) || metadata.salt.length !== 32) errors.push('Invalid salt');

        const rawName = typeof metadata?.fileName === 'string' ? metadata.fileName : '';
        const displayName = this.normalizeDisplayFileName(rawName);
        const hasDangerousName =
            !rawName ||
            rawName !== rawName.trim() ||
            /[\u0000-\u001F\u007F]/.test(rawName) ||
            /[\\/]/.test(rawName) ||
            rawName === '.' ||
            rawName === '..' ||
            displayName.length === 0;
        if (hasDangerousName) errors.push('Dangerous file name');

        if (errors.length === 0) {
            const validation = this.validateFile({
                name: displayName,
                size: metadata.fileSize,
                type: metadata.fileType || 'application/octet-stream'
            });
            if (!validation.isValid) errors.push(...validation.errors);
        }

        return { isValid: errors.length === 0, errors, displayName };
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    getSupportedFileTypes() {
        const supportedTypes = {};
        
        for (const [typeKey, typeConfig] of Object.entries(this.FILE_TYPE_RESTRICTIONS)) {
            supportedTypes[typeKey] = {
                category: typeConfig.category,
                description: typeConfig.description,
                extensions: typeConfig.extensions,
                maxSize: this.formatFileSize(typeConfig.maxSize),
                maxSizeBytes: typeConfig.maxSize
            };
        }
        
        return supportedTypes;
    }

    getFileTypeInfo() {
        return {
            supportedTypes: this.getSupportedFileTypes(),
            generalMaxSize: this.formatFileSize(this.MAX_FILE_SIZE),
            generalMaxSizeBytes: this.MAX_FILE_SIZE,
            restrictions: this.FILE_TYPE_RESTRICTIONS
        };
    }

    // ============================================
    // ENCODING HELPERS (Base64 for efficient transport)
    // ============================================
    arrayBufferToBase64(buffer) {
        const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        let binary = '';
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    base64ToUint8Array(base64) {
        const binaryString = atob(base64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes;
    }

    // ============================================
    // PUBLIC ACCESSORS FOR RECEIVED FILES
    // ============================================
    getReceivedFileMeta(fileId) {
        const entry = this.receivedFileBuffers.get(fileId);
        if (!entry) return null;
        return { fileId, fileName: entry.name, fileSize: entry.size, mimeType: entry.type };
    }

    async getBlob(fileId) {
        const entry = this.receivedFileBuffers.get(fileId);
        if (!entry) return null;
        return new Blob([entry.buffer], { type: entry.type });
    }

    async getObjectURL(fileId) {
        const blob = await this.getBlob(fileId);
        if (!blob) return null;
        return URL.createObjectURL(blob);
    }

    revokeObjectURL(url) {
        try { URL.revokeObjectURL(url); } catch (_) {}
    }

    setupFileMessageHandlers() {
        if (!this.webrtcManager.dataChannel) {
            const setupRetry = setInterval(() => {
                if (this.webrtcManager.dataChannel) {
                    clearInterval(setupRetry);
                    this.setupMessageInterception();
                }
            }, 100);

            setTimeout(() => {
                clearInterval(setupRetry);
            }, 5000);
            
            return;
        }
        
        // Если dataChannel уже готов, сразу настраиваем
        this.setupMessageInterception();
    }

    setupMessageInterception() {
        try {
            if (!this.webrtcManager.dataChannel) {
                return;
            }

            if (this.webrtcManager) {
                this.webrtcManager.fileTransferSystem = this;
            }

            if (this.webrtcManager.dataChannel.onmessage) {
                this.originalOnMessage = this.webrtcManager.dataChannel.onmessage;
            }

            this.webrtcManager.dataChannel.onmessage = async (event) => {
                try {
                    if (event.data.length > MessageSizeValidator.MAX_MESSAGE_SIZE) {
                        console.warn('🔒 Message too large, ignoring');
                        SecurityErrorHandler.logSecurityEvent('oversized_message_blocked');
                        return;
                    }
                    
                    if (typeof event.data === 'string') {
                        try {
                            const parsed = JSON.parse(event.data);
                            
                            MessageSizeValidator.isMessageSizeValid(parsed);
                            
                            if (this.isFileTransferMessage(parsed)) {
                                await this.handleFileMessage(parsed);
                                return; 
                            }
                        } catch (parseError) {
                            if (parseError.message === 'Message too large') {
                                return; 
                            }
                        }
                    }

                    if (this.originalOnMessage) {
                        return this.originalOnMessage.call(this.webrtcManager.dataChannel, event);
                    }
                } catch (error) {
                    console.error('❌ Error in file system message interception:', error);
                    if (this.originalOnMessage) {
                        return this.originalOnMessage.call(this.webrtcManager.dataChannel, event);
                    }
                }
            };
        } catch (error) {
            console.error('❌ Failed to set up message interception:', error);
        }
    }

    isFileTransferMessage(message) {
        if (!message || typeof message !== 'object' || !message.type) {
            return false;
        }
        
        const fileMessageTypes = [
            'file_transfer_start',
            'file_transfer_response',
            'file_chunk',
            'chunk_confirmation',
            'file_chunk_request',
            'file_transfer_complete',
            'file_transfer_error'
        ];
        
        return fileMessageTypes.includes(message.type);
    }

    async handleFileMessage(message) {
        try {
            if (!this.webrtcManager.fileTransferSystem) {
                try {
                    if (typeof this.webrtcManager.initializeFileTransfer === 'function') {
                        this.webrtcManager.initializeFileTransfer();
                        
                        let attempts = 0;
                        const maxAttempts = 50; 
                        while (!this.webrtcManager.fileTransferSystem && attempts < maxAttempts) {
                            await new Promise(resolve => setTimeout(resolve, 100));
                            attempts++;
                        }
                        
                        if (!this.webrtcManager.fileTransferSystem) {
                            throw new Error('File transfer system initialization timeout');
                        }
                    } else {
                        throw new Error('initializeFileTransfer method not available');
                    }
                } catch (initError) {
                    console.error('❌ Failed to initialize file transfer system:', initError);
                    if (message.fileId) {
                        const errorMessage = {
                            type: 'file_transfer_error',
                            fileId: message.fileId,
                            error: 'File transfer system not available',
                            timestamp: Date.now()
                        };
                        await this.sendSecureMessage(errorMessage);
                    }
                    return;
                }
            }
            
            switch (message.type) {
                case 'file_transfer_start':
                    await this.handleFileTransferStart(message);
                    break;
                    
                case 'file_transfer_response':
                    this.handleTransferResponse(message);
                    break;
                    
                case 'file_chunk':
                    await this.handleFileChunk(message);
                    break;
                    
                case 'chunk_confirmation':
                    this.handleChunkConfirmation(message);
                    break;

                case 'file_chunk_request':
                    await this.handleChunkRequest(message);
                    break;

                case 'file_transfer_complete':
                    this.handleTransferComplete(message);
                    break;
                    
                case 'file_transfer_error':
                    this.handleTransferError(message);
                    break;
                    
                default:
                    console.warn('⚠️ Unknown file message type:', message.type);
            }
            
        } catch (error) {
            console.error('❌ Error handling file message:', error);

            if (message.fileId) {
                const errorMessage = {
                    type: 'file_transfer_error',
                    fileId: message.fileId,
                    error: error.message,
                    timestamp: Date.now()
                };
                await this.sendSecureMessage(errorMessage);
            }
        }
    }

    // ============================================
    // SIMPLIFIED KEY DERIVATION - USE SHARED DATA
    // ============================================

    async deriveFileSessionKey(fileId) {
        try {
            
            if (!this.webrtcManager.keyFingerprint || !this.webrtcManager.sessionSalt) {
                throw new Error('WebRTC session data not available');
            }

            const fileSalt = crypto.getRandomValues(new Uint8Array(32));

            const encoder = new TextEncoder();
            const fingerprintData = encoder.encode(this.webrtcManager.keyFingerprint);
            const fileIdData = encoder.encode(fileId);

            const sessionSaltArray = new Uint8Array(this.webrtcManager.sessionSalt);
            const combinedSeed = new Uint8Array(
                fingerprintData.length + 
                sessionSaltArray.length + 
                fileSalt.length + 
                fileIdData.length
            );
            
            let offset = 0;
            combinedSeed.set(fingerprintData, offset);
            offset += fingerprintData.length;
            combinedSeed.set(sessionSaltArray, offset);
            offset += sessionSaltArray.length;
            combinedSeed.set(fileSalt, offset);
            offset += fileSalt.length;
            combinedSeed.set(fileIdData, offset);

            const keyMaterial = await crypto.subtle.digest('SHA-256', combinedSeed);

            const fileSessionKey = await crypto.subtle.importKey(
                'raw',
                keyMaterial,
                { name: 'AES-GCM' },
                false,
                ['encrypt', 'decrypt']
            );

            this.sessionKeys.set(fileId, {
                key: fileSessionKey,
                salt: Array.from(fileSalt),
                created: Date.now()
            });

            return { key: fileSessionKey, salt: Array.from(fileSalt) };

        } catch (error) {
            console.error('❌ Failed to derive file session key:', error);
            throw error;
        }
    }

    async deriveFileSessionKeyFromSalt(fileId, saltArray) {
        try {
            if (!saltArray || !Array.isArray(saltArray) || saltArray.length !== 32) {
                throw new Error(`Invalid salt: ${saltArray?.length || 0} bytes`);
            }
            
            if (!this.webrtcManager.keyFingerprint || !this.webrtcManager.sessionSalt) {
                throw new Error('WebRTC session data not available');
            }

            const encoder = new TextEncoder();
            const fingerprintData = encoder.encode(this.webrtcManager.keyFingerprint);
            const fileIdData = encoder.encode(fileId);

            const fileSalt = new Uint8Array(saltArray);
            const sessionSaltArray = new Uint8Array(this.webrtcManager.sessionSalt);

            const combinedSeed = new Uint8Array(
                fingerprintData.length + 
                sessionSaltArray.length + 
                fileSalt.length + 
                fileIdData.length
            );
            
            let offset = 0;
            combinedSeed.set(fingerprintData, offset);
            offset += fingerprintData.length;
            combinedSeed.set(sessionSaltArray, offset);
            offset += sessionSaltArray.length;
            combinedSeed.set(fileSalt, offset);
            offset += fileSalt.length;
            combinedSeed.set(fileIdData, offset);

            const keyMaterial = await crypto.subtle.digest('SHA-256', combinedSeed);

            const fileSessionKey = await crypto.subtle.importKey(
                'raw',
                keyMaterial,
                { name: 'AES-GCM' },
                false,
                ['encrypt', 'decrypt']
            );

            this.sessionKeys.set(fileId, {
                key: fileSessionKey,
                salt: saltArray,
                created: Date.now()
            });

            return fileSessionKey;

        } catch (error) {
            console.error('❌ Failed to derive session key from salt:', error);
            throw error;
        }
    }

    // ============================================
    // FILE TRANSFER IMPLEMENTATION
    // ============================================

    async sendFile(file) {
        try {
            // Validate webrtcManager
            if (!this.webrtcManager) {
                throw new Error('WebRTC Manager not initialized');
            }

            const clientId = this.getClientIdentifier();
            if (!this.rateLimiter.isAllowed(clientId)) {
                SecurityErrorHandler.logSecurityEvent('rate_limit_exceeded', { clientId });
                throw new Error('Rate limit exceeded. Please wait before sending another file.');
            }

            if (!file || !file.size) {
                throw new Error('Invalid file object');
            }

            const validation = this.validateFile(file);
            if (!validation.isValid) {
                const errorMessage = validation.errors.join('. ');
                throw new Error(errorMessage);
            }

            if (this.activeTransfers.size >= this.MAX_CONCURRENT_TRANSFERS) {
                throw new Error('Maximum concurrent transfers reached');
            }

            // Generate unique file ID
            const fileId = `file_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            
            // Calculate file hash for integrity verification
            const fileHash = await this.calculateFileHash(file);
            
            // Derive session key for this file
            const keyResult = await this.deriveFileSessionKey(fileId);
            const sessionKey = keyResult.key;
            const salt = keyResult.salt;
            
            // Create transfer state
            const transferState = {
                fileId: fileId,
                file: file,
                fileHash: fileHash,
                sessionKey: sessionKey,
                salt: salt, 
                totalChunks: Math.ceil(file.size / this.CHUNK_SIZE),
                sentChunks: 0,
                confirmedChunks: 0,
                startTime: Date.now(),
                status: 'preparing',
                retryCount: 0,
                lastChunkTime: Date.now()
            };

            this.activeTransfers.set(fileId, transferState);
            this.transferNonces.set(fileId, 0);

            const consentPromise = new Promise((resolve, reject) => {
                transferState.resolveConsent = resolve;
                transferState.rejectConsent = reject;
                transferState.consentTimeout = setTimeout(() => {
                    transferState.consentTimeout = null;
                    reject(new Error('Transfer timeout'));
                }, 30000);
            });

            // Send file metadata first
            await this.sendFileMetadata(transferState);
            
            // Wait for explicit receiver consent before any chunks are sent.
            await consentPromise;
            
            await this.startChunkTransmission(transferState);
            
            return fileId;

        } catch (error) {
            const safeError = SecurityErrorHandler.sanitizeError(error);
            console.error('❌ File sending failed:', safeError);
            if (this.onError) this.onError(safeError);
            throw new Error(safeError);
        }
    }

    async sendFileMetadata(transferState) {
        try {
            const metadata = {
                type: 'file_transfer_start',
                fileId: transferState.fileId,
                fileName: transferState.file.name,
                fileSize: transferState.file.size,
                fileType: transferState.file.type || 'application/octet-stream',
                fileHash: transferState.fileHash,
                totalChunks: transferState.totalChunks,
                chunkSize: this.CHUNK_SIZE,
                salt: transferState.salt, 
                timestamp: Date.now(),
                version: '2.0'
            };

            if (this.signingKey) {
                try {
                    metadata.signature = await FileMetadataSigner.signFileMetadata(metadata, this.signingKey);
                    console.log('🔒 File metadata signed successfully');
                } catch (signError) {
                    SecurityErrorHandler.logSecurityEvent('signature_failed', { 
                        fileId: transferState.fileId, 
                        error: signError.message 
                    });
                }
            }

            // Send metadata through secure channel
            await this.sendSecureMessage(metadata);
            
            transferState.status = 'metadata_sent';

        } catch (error) {
            const safeError = SecurityErrorHandler.sanitizeError(error);
            console.error('❌ Failed to send file metadata:', safeError);
            transferState.status = 'failed';
            throw new Error(safeError);
        }
    }

    async startChunkTransmission(transferState) {
        try {
            transferState.status = 'transmitting';
            
            const file = transferState.file;
            const totalChunks = transferState.totalChunks;
            
            for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
                const start = chunkIndex * this.CHUNK_SIZE;
                const end = Math.min(start + this.CHUNK_SIZE, file.size);
                
                // Read chunk from file
                const chunkData = await this.readFileChunk(file, start, end);
                
                // Send chunk (с учётом backpressure)
                await this.sendFileChunk(transferState, chunkIndex, chunkData);
                
                // Update progress
                transferState.sentChunks++;
                const progress = Math.round((transferState.sentChunks / totalChunks) * 95) + 5; // 5-100%

                await this.waitForBackpressure();
            }
            
            transferState.status = 'waiting_confirmation';

            // Keep the file + session key alive while the receiver may still be
            // re-requesting missing chunks (e.g. after a connection blip). The
            // sender is only torn down once the receiver confirms completion or
            // after a long idle with no chunk requests/confirmations.
            this._armSenderIdleTimeout(transferState);

        } catch (error) {
            const safeError = SecurityErrorHandler.sanitizeError(error);
            console.error('❌ Chunk transmission failed:', safeError);
            transferState.status = 'failed';
            throw new Error(safeError);
        }
    }

    // Resets a long idle timer; the sender stays available to retransmit missing
    // chunks until the receiver finishes or this fires after sustained silence.
    _armSenderIdleTimeout(transferState) {
        const IDLE_MS = 180000; // 3 minutes with no activity from the receiver
        if (transferState._idleTimeout) clearTimeout(transferState._idleTimeout);
        transferState._idleTimeout = setTimeout(() => {
            const state = this.activeTransfers.get(transferState.fileId);
            if (state && state.status !== 'completed') {
                this.cleanupTransfer(transferState.fileId);
            }
        }, IDLE_MS);
    }

    // Receiver asked us to re-send specific chunk indices (loss recovery / resume).
    async handleChunkRequest(message) {
        const transferState = this.activeTransfers.get(message?.fileId);
        if (!transferState || !transferState.file) return;
        const missing = Array.isArray(message.missing) ? message.missing : [];
        if (missing.length === 0) return;

        this._armSenderIdleTimeout(transferState);
        transferState.status = 'transmitting';

        const MAX_PER_REQUEST = 512;
        const indices = missing.slice(0, MAX_PER_REQUEST);
        for (const idx of indices) {
            if (!Number.isInteger(idx) || idx < 0 || idx >= transferState.totalChunks) continue;
            try {
                const start = idx * this.CHUNK_SIZE;
                const end = Math.min(start + this.CHUNK_SIZE, transferState.file.size);
                const chunkData = await this.readFileChunk(transferState.file, start, end);
                await this.sendFileChunk(transferState, idx, chunkData);
                await this.waitForBackpressure();
            } catch (error) {
                console.warn('⚠️ Failed to retransmit chunk', idx, SecurityErrorHandler.sanitizeError(error));
            }
        }

        if (transferState.status === 'transmitting') {
            transferState.status = 'waiting_confirmation';
        }
        this._armSenderIdleTimeout(transferState);
    }

    async readFileChunk(file, start, end) {
        try {
            const blob = file.slice(start, end);
            return await blob.arrayBuffer();
        } catch (error) {
            const safeError = SecurityErrorHandler.sanitizeError(error);
            console.error('❌ Failed to read file chunk:', safeError);
            throw new Error(safeError);
        }
    }

    async sendFileChunk(transferState, chunkIndex, chunkData) {
        try {
            const sessionKey = transferState.sessionKey;
            const nonce = crypto.getRandomValues(new Uint8Array(12));
            
            // Encrypt chunk data
            const encryptedChunk = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: nonce
                },
                sessionKey,
                chunkData
            );
            
            // Use Base64 to drastically reduce JSON overhead
            const encryptedB64 = this.arrayBufferToBase64(new Uint8Array(encryptedChunk));
            const chunkMessage = {
                type: 'file_chunk',
                fileId: transferState.fileId,
                chunkIndex: chunkIndex,
                totalChunks: transferState.totalChunks,
                nonce: Array.from(nonce),
                encryptedDataB64: encryptedB64,
                chunkSize: chunkData.byteLength,
                timestamp: Date.now()
            };

            await this.waitForBackpressure();
            // Send chunk through secure channel
            await this.sendSecureMessage(chunkMessage);
            
        } catch (error) {
            const safeError = SecurityErrorHandler.sanitizeError(error);
            console.error('❌ Failed to send file chunk:', safeError);
            throw new Error(safeError);
        }
    }

    async sendSecureMessage(message) {

        const messageString = JSON.stringify(message);
        const dc = this.webrtcManager?.dataChannel;
        const maxRetries = 10;
        let attempt = 0;
        const wait = (ms) => new Promise(r => setTimeout(r, ms));

        while (true) {
            try {
                if (!dc || dc.readyState !== 'open') {
                    throw new Error('Data channel not ready');
                }
                await this.waitForBackpressure();
                dc.send(messageString);
                return; // success
            } catch (error) {
                const msg = String(error?.message || '');
                const queueFull = msg.includes('send queue is full') || msg.includes('bufferedAmount');
                const opErr = error?.name === 'OperationError';
                if ((queueFull || opErr) && attempt < maxRetries) {
                    attempt++;
                    await this.waitForBackpressure();
                    await wait(Math.min(50 * attempt, 500));
                    continue;
                }
                console.error('❌ Failed to send secure message:', error);
                throw error;
            }
        }
    }

    async waitForBackpressure() {
        try {
            const dc = this.webrtcManager?.dataChannel;
            if (!dc) return;

            if (typeof dc.bufferedAmountLowThreshold === 'number') {
                if (dc.bufferedAmount > dc.bufferedAmountLowThreshold) {
                    await new Promise(resolve => {
                        const handler = () => {
                            dc.removeEventListener('bufferedamountlow', handler);
                            resolve();
                        };
                        dc.addEventListener('bufferedamountlow', handler, { once: true });
                    });
                }
                return;
            }

            const softLimit = 4 * 1024 * 1024;
            while (dc.bufferedAmount > softLimit) {
                await new Promise(r => setTimeout(r, 20));
            }
        } catch (_) {
            // ignore
        }
    }

    async calculateFileHash(file) {
        try {
            const arrayBuffer = await file.arrayBuffer();
            const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (error) {
            console.error('❌ File hash calculation failed:', error);
            throw error;
        }
    }

    // ============================================
    // MESSAGE HANDLERS
    // ============================================

    async handleFileTransferStart(metadata) {
        try {
            const clientId = this.getClientIdentifier();
            if (!this.incomingOfferLimiter.isAllowed(clientId)) {
                throw new Error('Incoming file request rate limit exceeded');
            }

            const validation = this.validateIncomingMetadata(metadata);
            if (!validation.isValid) throw new Error(validation.errors.join('. '));

            if (metadata.signature && this.verificationKey) {
                try {
                    const isValid = await FileMetadataSigner.verifyFileMetadata(
                        metadata, 
                        metadata.signature, 
                        this.verificationKey
                    );
                    
                    if (!isValid) {
                        SecurityErrorHandler.logSecurityEvent('invalid_metadata_signature', { 
                            fileId: metadata.fileId 
                        });
                        throw new Error('Invalid file metadata signature');
                    }
                    
                    console.log('🔒 File metadata signature verified successfully');
                } catch (verifyError) {
                    SecurityErrorHandler.logSecurityEvent('verification_failed', { 
                        fileId: metadata.fileId, 
                        error: verifyError.message 
                    });
                    throw new Error('File metadata verification failed');
                }
            }
            
            // Check if we already have this transfer
            if (this.receivingTransfers.has(metadata.fileId) || this.pendingIncomingTransfers.has(metadata.fileId)) {
                return;
            }

            if (this.pendingIncomingTransfers.size >= this.MAX_PENDING_INCOMING_TRANSFERS) {
                throw new Error('Too many pending incoming file requests');
            }

            const pendingMetadata = {
                ...metadata,
                fileName: validation.displayName,
                receivedAt: Date.now()
            };
            this.pendingIncomingTransfers.set(metadata.fileId, pendingMetadata);

            if (typeof this.onIncomingFileRequest === 'function') {
                this.onIncomingFileRequest({
                    fileId: pendingMetadata.fileId,
                    fileName: pendingMetadata.fileName,
                    fileSize: pendingMetadata.fileSize,
                    mimeType: pendingMetadata.fileType || 'application/octet-stream'
                });
            } else {
                await this.rejectIncomingFile(metadata.fileId, 'User consent unavailable');
            }
            
        } catch (error) {
            const safeError = SecurityErrorHandler.sanitizeError(error);
            console.error('❌ Failed to handle file transfer start:', safeError);
            
            // Send error response
            const errorResponse = {
                type: 'file_transfer_response',
                fileId: metadata.fileId,
                accepted: false,
                error: safeError, 
                timestamp: Date.now()
            };
            await this.sendSecureMessage(errorResponse);
        }
    }

    async handleFileChunk(chunkMessage) {
        return this.atomicOps.withLock(
            `chunk-${chunkMessage.fileId}`, 
            async () => {
                try {
                    let receivingState = this.receivingTransfers.get(chunkMessage.fileId);

                    // Never buffer chunks before explicit consent.
                    if (!receivingState) {
                        return;
                    }

                    // Already assembled — ignore late/duplicate (retransmitted) chunks.
                    if (receivingState._assembled || receivingState.status === 'completed') {
                        return;
                    }

                    if (!this._isIncomingChunkAllowed(chunkMessage.fileId)) {
                        console.warn('⚠️ Incoming file chunk rate limit exceeded; cleaning up transfer:', chunkMessage.fileId);
                        this.cleanupReceivingTransfer(chunkMessage.fileId);
                        return;
                    }
                    
                    // Update last chunk time
                    receivingState.lastChunkTime = Date.now();
                    
                    // Check if chunk already received
                    if (receivingState.receivedChunks.has(chunkMessage.chunkIndex)) {
                        return;
                    }
                    
                    // Validate chunk
                    if (chunkMessage.chunkIndex < 0 || chunkMessage.chunkIndex >= receivingState.totalChunks) {
                        throw new Error(`Invalid chunk index: ${chunkMessage.chunkIndex}`);
                    }
                    
                    // Decrypt chunk
                    const nonce = new Uint8Array(chunkMessage.nonce);
                    // Backward compatible: prefer Base64, fallback to numeric array
                    let encryptedData;
                    if (chunkMessage.encryptedDataB64) {
                        encryptedData = this.base64ToUint8Array(chunkMessage.encryptedDataB64);
                    } else if (chunkMessage.encryptedData) {
                        encryptedData = new Uint8Array(chunkMessage.encryptedData);
                    } else {
                        throw new Error('Missing encrypted data');
                    }
                    
                    const decryptedChunk = await crypto.subtle.decrypt(
                        {
                            name: 'AES-GCM',
                            iv: nonce
                        },
                        receivingState.sessionKey,
                        encryptedData
                    );
                    
                    // Verify chunk size
                    if (decryptedChunk.byteLength !== chunkMessage.chunkSize) {
                        throw new Error(`Chunk size mismatch: expected ${chunkMessage.chunkSize}, got ${decryptedChunk.byteLength}`);
                    }
                    
                    // Store chunk
                    receivingState.receivedChunks.set(chunkMessage.chunkIndex, decryptedChunk);
                    receivingState.receivedCount++;
                    
                    // Send chunk confirmation
                    const confirmation = {
                        type: 'chunk_confirmation',
                        fileId: chunkMessage.fileId,
                        chunkIndex: chunkMessage.chunkIndex,
                        timestamp: Date.now()
                    };
                    await this.sendSecureMessage(confirmation);
                    
                    // Check if all chunks received
                    if (receivingState.receivedCount === receivingState.totalChunks) {
                        await this.assembleFile(receivingState);
                    }
                    
                } catch (error) {
                    // A single bad/lost chunk must NOT kill the whole transfer:
                    // drop it and let the receiver's stall detector re-request it.
                    // (The data channel is reliable+ordered, so this path is rare —
                    // typically a transient decrypt hiccup or post-cleanup straggler.)
                    const safeError = SecurityErrorHandler.sanitizeError(error);
                    console.warn('⚠️ Dropping unprocessable file chunk (will be re-requested):', chunkMessage.chunkIndex, safeError);
                }
            }
        );
    }

    _isIncomingChunkAllowed(fileId) {
        const clientId = this.getClientIdentifier();
        if (!this.incomingChunkLimiter.isAllowed(clientId)) {
            SecurityErrorHandler.logSecurityEvent('incoming_chunk_aggregate_rate_limit_exceeded', {
                clientId,
                fileId
            });
            return false;
        }

        if (!this.incomingTransferChunkLimiters.has(fileId)) {
            this.incomingTransferChunkLimiters.set(
                fileId,
                new RateLimiter(this.MAX_INCOMING_CHUNKS_PER_TRANSFER_PER_MINUTE, 60000)
            );
        }

        const transferLimiter = this.incomingTransferChunkLimiters.get(fileId);
        if (!transferLimiter.isAllowed(fileId)) {
            SecurityErrorHandler.logSecurityEvent('incoming_chunk_transfer_rate_limit_exceeded', {
                clientId,
                fileId
            });
            return false;
        }

        return true;
    }

    async assembleFile(receivingState) {
        // Idempotency guard: assembly must run (and onFileReceived must fire)
        // exactly once per transfer. Guards against any duplicate/concurrent
        // completion trigger so the receiver never sees the same file repeated.
        if (receivingState._assembled) {
            return;
        }
        receivingState._assembled = true;

        try {
            receivingState.status = 'assembling';
            
            // Verify we have all chunks
            for (let i = 0; i < receivingState.totalChunks; i++) {
                if (!receivingState.receivedChunks.has(i)) {
                    throw new Error(`Missing chunk ${i}`);
                }
            }
            
            // Combine all chunks in order
            const chunks = [];
            for (let i = 0; i < receivingState.totalChunks; i++) {
                const chunk = receivingState.receivedChunks.get(i);
                chunks.push(new Uint8Array(chunk));
            }
            
            // Calculate total size
            const totalSize = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
            
            // Verify total size matches expected
            if (totalSize !== receivingState.fileSize) {
                throw new Error(`File size mismatch: expected ${receivingState.fileSize}, got ${totalSize}`);
            }
            
            // Combine into single array
            const fileData = new Uint8Array(totalSize);
            let offset = 0;
            for (const chunk of chunks) {
                fileData.set(chunk, offset);
                offset += chunk.length;
            }
            
            // Verify file integrity
            const receivedHash = await this.calculateFileHashFromData(fileData);
            if (receivedHash !== receivingState.fileHash) {
                throw new Error('File integrity check failed - hash mismatch');
            }

            const fileBuffer = fileData.buffer;
            const fileBlob = new Blob([fileBuffer], { type: receivingState.fileType });
            
            receivingState.endTime = Date.now();
            receivingState.status = 'completed';

            this._storeReceivedFileBuffer(receivingState.fileId, {
                buffer: fileBuffer,
                type: receivingState.fileType,
                name: receivingState.fileName,
                size: receivingState.fileSize
            });

            if (this.onFileReceived) {
                const getBlob = async () => {
                    const blob = await this.getBlob(receivingState.fileId);
                    if (!blob) {
                        throw new Error('This file is no longer available for download.');
                    }
                    return blob;
                };
                const getObjectURL = async () => {
                    const blob = await getBlob();
                    return URL.createObjectURL(blob);
                };
                const revokeObjectURL = (url) => {
                    try { URL.revokeObjectURL(url); } catch (_) {}
                };

                this.onFileReceived({
                    fileId: receivingState.fileId,
                    fileName: receivingState.fileName,
                    fileSize: receivingState.fileSize,
                    mimeType: receivingState.fileType,
                    transferTime: receivingState.endTime - receivingState.startTime,
                    // backward-compatibility for existing UIs
                    fileBlob,
                    getBlob,
                    getObjectURL,
                    revokeObjectURL
                });
            }
            
            // Send completion confirmation
            const completionMessage = {
                type: 'file_transfer_complete',
                fileId: receivingState.fileId,
                success: true,
                timestamp: Date.now()
            };
            await this.sendSecureMessage(completionMessage);

            // Stop the stall detector and free the heavy chunk data, but KEEP the
            // transfer entry in receivingTransfers with status 'completed' so the UI
            // can render the Download action. The assembled file lives in
            // receivedFileBuffers; this entry is removed on cancel/disconnect or when
            // its buffer is evicted (see _discardReceivedFileBuffer).
            if (receivingState._stallTimer) {
                clearInterval(receivingState._stallTimer);
                receivingState._stallTimer = null;
            }
            if (receivingState.receivedChunks) receivingState.receivedChunks.clear();
            receivingState.sessionKey = null;

        } catch (error) {
            console.error('❌ File assembly failed:', error);
            receivingState.status = 'failed';
            
            if (this.onError) {
                this.onError(`File assembly failed: ${error.message}`);
            }
            
            // Send error notification
            const errorMessage = {
                type: 'file_transfer_complete',
                fileId: receivingState.fileId,
                success: false,
                error: error.message,
                timestamp: Date.now()
            };
            await this.sendSecureMessage(errorMessage);
            
            // Cleanup failed transfer
            this.cleanupReceivingTransfer(receivingState.fileId);
        }
    }

    async calculateFileHashFromData(data) {
        try {
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (error) {
            console.error('❌ Hash calculation failed:', error);
            throw error;
        }
    }

    handleTransferResponse(response) {
        try {
            const transferState = this.activeTransfers.get(response.fileId);
            
            if (!transferState) {
                return;
            }
            
            if (response.accepted) {
                transferState.status = 'accepted';
                if (transferState.consentTimeout) clearTimeout(transferState.consentTimeout);
                transferState.consentTimeout = null;
                transferState.resolveConsent?.();
                transferState.resolveConsent = null;
                transferState.rejectConsent = null;
            } else {
                transferState.status = 'rejected';
                if (transferState.consentTimeout) clearTimeout(transferState.consentTimeout);
                transferState.consentTimeout = null;
                transferState.rejectConsent?.(new Error(response.error || 'Transfer rejected'));
                transferState.rejectConsent = null;
                transferState.resolveConsent = null;
                
                if (this.onError) {
                    this.onError(`Transfer rejected: ${response.error || 'Unknown reason'}`);
                }
                
                this.cleanupTransfer(response.fileId);
            }
        } catch (error) {
            console.error('❌ Failed to handle transfer response:', error);
        }
    }

    handleChunkConfirmation(confirmation) {
        try {
            const transferState = this.activeTransfers.get(confirmation.fileId);
            if (!transferState) {
                return;
            }
            
            transferState.confirmedChunks++;
            transferState.lastChunkTime = Date.now();
            if (transferState.status === 'waiting_confirmation') {
                this._armSenderIdleTimeout(transferState);
            }
        } catch (error) {
            console.error('❌ Failed to handle chunk confirmation:', error);
        }
    }

    handleTransferComplete(completion) {
        try {
            const transferState = this.activeTransfers.get(completion.fileId);
            if (!transferState) {
                return;
            }
            
            if (completion.success) {
                transferState.status = 'completed';
                transferState.endTime = Date.now();
                
                if (this.onComplete) {
                    this.onComplete({
                        fileId: transferState.fileId,
                        fileName: transferState.file.name,
                        fileSize: transferState.file.size,
                        transferTime: transferState.endTime - transferState.startTime,
                        status: 'completed'
                    });
                }
            } else {
                transferState.status = 'failed';
                
                if (this.onError) {
                    this.onError(`Transfer failed: ${completion.error || 'Unknown error'}`);
                }
            }
            
            this.cleanupTransfer(completion.fileId);
            
        } catch (error) {
            console.error('❌ Failed to handle transfer completion:', error);
        }
    }

    handleTransferError(errorMessage) {
        try {
            const transferState = this.activeTransfers.get(errorMessage.fileId);
            if (transferState) {
                transferState.status = 'failed';
                this.cleanupTransfer(errorMessage.fileId);
            }
            
            const receivingState = this.receivingTransfers.get(errorMessage.fileId);
            if (receivingState) {
                receivingState.status = 'failed';
                this.cleanupReceivingTransfer(errorMessage.fileId);
            }
            
            if (this.onError) {
                this.onError(`Transfer error: ${errorMessage.error || 'Unknown error'}`);
            }
            
        } catch (error) {
            console.error('❌ Failed to handle transfer error:', error);
        }
    }

    // ============================================
    // UTILITY METHODS
    // ============================================

    getActiveTransfers() {
        return Array.from(this.activeTransfers.values()).map(transfer => ({
            fileId: transfer.fileId,
            fileName: transfer.file?.name || 'Unknown',
            fileSize: transfer.file?.size || 0,
            progress: Math.round((transfer.sentChunks / transfer.totalChunks) * 100),
            // Per-chunk detail for the segmented progress UI.
            totalChunks: transfer.totalChunks || 0,
            transferredChunks: transfer.sentChunks || 0,
            status: transfer.status,
            startTime: transfer.startTime
        }));
    }

    getReceivingTransfers() {
        return Array.from(this.receivingTransfers.values()).map(transfer => ({
            fileId: transfer.fileId,
            fileName: transfer.fileName || 'Unknown',
            fileSize: transfer.fileSize || 0,
            progress: Math.round((transfer.receivedCount / transfer.totalChunks) * 100),
            // Per-chunk detail for the segmented progress UI.
            totalChunks: transfer.totalChunks || 0,
            transferredChunks: transfer.receivedCount || 0,
            status: transfer.status,
            startTime: transfer.startTime
        }));
    }

    getPendingIncomingTransfers() {
        return Array.from(this.pendingIncomingTransfers.values()).map(transfer => ({
            fileId: transfer.fileId,
            fileName: transfer.fileName,
            fileSize: transfer.fileSize,
            mimeType: transfer.fileType || 'application/octet-stream',
            receivedAt: transfer.receivedAt
        }));
    }

    async acceptIncomingFile(fileId) {
        const metadata = this.pendingIncomingTransfers.get(fileId);
        if (!metadata) return false;
        const sessionKey = await this.deriveFileSessionKeyFromSalt(fileId, metadata.salt);
        this.receivingTransfers.set(fileId, {
            fileId,
            fileName: metadata.fileName,
            fileSize: metadata.fileSize,
            fileType: metadata.fileType || 'application/octet-stream',
            fileHash: metadata.fileHash,
            totalChunks: metadata.totalChunks,
            chunkSize: metadata.chunkSize || this.CHUNK_SIZE,
            sessionKey,
            salt: metadata.salt,
            receivedChunks: new Map(),
            receivedCount: 0,
            startTime: Date.now(),
            lastChunkTime: Date.now(),
            status: 'receiving'
        });
        this.pendingIncomingTransfers.delete(fileId);
        await this.sendSecureMessage({ type: 'file_transfer_response', fileId, accepted: true, timestamp: Date.now() });
        // Loss-recovery / resume: watch for missing chunks and re-request them.
        this._startReceiverStallDetector(fileId);
        return true;
    }

    // Periodically detects a stalled receive (lost chunks, connection blip,
    // reconnect) and asks the sender to retransmit only the chunks we are still
    // missing — so a dropped connection never loses the file.
    _startReceiverStallDetector(fileId) {
        const TICK_MS = 2500;        // how often we evaluate
        const STALL_MS = 5000;       // quiet period before we re-request
        const MAX_IDLE_MS = 180000;  // give up after 3 min of zero progress

        const rs = this.receivingTransfers.get(fileId);
        if (!rs) return;
        if (rs._stallTimer) clearInterval(rs._stallTimer);
        rs._lastProgressCount = rs.receivedCount || 0;
        rs._lastProgressTime = Date.now();

        rs._stallTimer = setInterval(async () => {
            const state = this.receivingTransfers.get(fileId);
            if (!state || state._stallTimer !== rs._stallTimer) {
                clearInterval(rs._stallTimer);
                return;
            }
            if (state.status === 'completed' || state._assembled) {
                clearInterval(state._stallTimer);
                state._stallTimer = null;
                return;
            }

            // Track forward progress for the idle/give-up clock.
            if (state.receivedCount !== state._lastProgressCount) {
                state._lastProgressCount = state.receivedCount;
                state._lastProgressTime = Date.now();
            }
            if (state.receivedCount >= state.totalChunks) return; // assembly handled elsewhere

            // Still actively receiving — don't interrupt.
            if (Date.now() - (state.lastChunkTime || 0) < STALL_MS) return;

            // No progress for too long → fail cleanly rather than hang forever.
            if (Date.now() - state._lastProgressTime > MAX_IDLE_MS) {
                clearInterval(state._stallTimer);
                state._stallTimer = null;
                state.status = 'failed';
                if (this.onError) this.onError('File transfer stalled — no data received. Please try again.');
                this.cleanupReceivingTransfer(fileId);
                return;
            }

            await this._requestMissingChunks(fileId);
        }, TICK_MS);
    }

    async _requestMissingChunks(fileId) {
        const state = this.receivingTransfers.get(fileId);
        if (!state || !state.receivedChunks) return;
        const MAX_PER_REQUEST = 256;
        const missing = [];
        for (let i = 0; i < state.totalChunks && missing.length < MAX_PER_REQUEST; i++) {
            if (!state.receivedChunks.has(i)) missing.push(i);
        }
        if (missing.length === 0) return;
        state.status = 'receiving';
        try {
            await this.sendSecureMessage({
                type: 'file_chunk_request',
                fileId,
                missing,
                timestamp: Date.now()
            });
        } catch (_) {
            // Will retry on the next tick.
        }
    }

    async rejectIncomingFile(fileId, error = 'Rejected by user') {
        if (!this.pendingIncomingTransfers.has(fileId)) return false;
        this.pendingIncomingTransfers.delete(fileId);
        await this.sendSecureMessage({ type: 'file_transfer_response', fileId, accepted: false, error, timestamp: Date.now() });
        return true;
    }

    cancelTransfer(fileId) {
        try {
            if (this.activeTransfers.has(fileId)) {
                this.cleanupTransfer(fileId);
                return true;
            }
            if (this.receivingTransfers.has(fileId)) {
                this.cleanupReceivingTransfer(fileId);
                return true;
            }
            return false;
        } catch (error) {
            console.error('❌ Failed to cancel transfer:', error);
            return false;
        }
    }

    cleanupTransfer(fileId) {
        const transferState = this.activeTransfers.get(fileId);
        if (transferState) {
            if (transferState._idleTimeout) {
                clearTimeout(transferState._idleTimeout);
                transferState._idleTimeout = null;
            }
            if (transferState.consentTimeout) {
                clearTimeout(transferState.consentTimeout);
                transferState.consentTimeout = null;
            }
            if (transferState.rejectConsent) {
                transferState.rejectConsent(new Error('Transfer cancelled during cleanup or disconnect'));
                transferState.rejectConsent = null;
                transferState.resolveConsent = null;
            }
        }

        this.activeTransfers.delete(fileId);
        this.sessionKeys.delete(fileId);
        this.transferNonces.delete(fileId);
        this.incomingTransferChunkLimiters.delete(fileId);
        
        // Remove processed chunk IDs for this transfer
        for (const chunkId of this.processedChunks) {
            if (chunkId.startsWith(fileId)) {
                this.processedChunks.delete(chunkId);
            }
        }
    }

    _storeReceivedFileBuffer(fileId, entry) {
        this.receivedFileBuffers.set(fileId, entry);
        while (this.receivedFileBuffers.size > this.MAX_RETAINED_RECEIVED_FILE_BUFFERS) {
            const oldestFileId = this.receivedFileBuffers.keys().next().value;
            this._discardReceivedFileBuffer(oldestFileId);
        }
    }

    _discardReceivedFileBuffer(fileId) {
        const fileBuffer = this.receivedFileBuffers.get(fileId);
        if (!fileBuffer) return;
        try {
            if (fileBuffer.buffer) {
                SecureMemoryManager.secureWipe(fileBuffer.buffer);
                new Uint8Array(fileBuffer.buffer).fill(0);
            }
        } catch (_) {
            // Best-effort wipe; deletion must still proceed.
        }
        this.receivedFileBuffers.delete(fileId);
        // The matching 'completed' entry is kept only to drive the Download UI;
        // once the file bytes are gone the entry is meaningless, so drop it too
        // (keeps the receiving list bounded over a long session).
        const rs = this.receivingTransfers.get(fileId);
        if (rs && (rs.status === 'completed' || rs._assembled)) {
            if (rs._stallTimer) { clearInterval(rs._stallTimer); rs._stallTimer = null; }
            this.receivingTransfers.delete(fileId);
        }
    }

    // ✅ УЛУЧШЕННАЯ безопасная очистка памяти для предотвращения use-after-free
    cleanupReceivingTransfer(fileId) {
        try {
            // Безопасно очищаем pending chunks
            this.pendingChunks.delete(fileId);
            
            const receivingState = this.receivingTransfers.get(fileId);
            if (receivingState) {
                // Stop the loss-recovery stall detector for this transfer.
                if (receivingState._stallTimer) {
                    clearInterval(receivingState._stallTimer);
                    receivingState._stallTimer = null;
                }
                // ✅ БЕЗОПАСНАЯ очистка receivedChunks с дополнительной защитой
                if (receivingState.receivedChunks && receivingState.receivedChunks.size > 0) {
                    for (const [index, chunk] of receivingState.receivedChunks) {
                        try {
                            // Дополнительная проверка на валидность chunk
                            if (chunk && (chunk instanceof ArrayBuffer || chunk instanceof Uint8Array)) {
                                SecureMemoryManager.secureWipe(chunk);
                                
                                // Дополнительная очистка - заполняем нулями перед удалением
                                if (chunk instanceof ArrayBuffer) {
                                    const view = new Uint8Array(chunk);
                                    view.fill(0);
                                } else if (chunk instanceof Uint8Array) {
                                    chunk.fill(0);
                                }
                            }
                        } catch (chunkError) {
                            console.warn('⚠️ Failed to securely wipe chunk:', chunkError);
                        }
                    }
                    receivingState.receivedChunks.clear();
                }
                
                // ✅ БЕЗОПАСНАЯ очистка session key
                if (receivingState.sessionKey) {
                    try {
                        // Для CryptoKey нельзя безопасно очистить, но можем удалить ссылку
                        receivingState.sessionKey = null;
                    } catch (keyError) {
                        console.warn('⚠️ Failed to clear session key:', keyError);
                    }
                }
                
                // ✅ БЕЗОПАСНАЯ очистка других чувствительных данных
                if (receivingState.salt) {
                    try {
                        if (Array.isArray(receivingState.salt)) {
                            receivingState.salt.fill(0);
                        }
                        receivingState.salt = null;
                    } catch (saltError) {
                        console.warn('⚠️ Failed to clear salt:', saltError);
                    }
                }
                
                // Очищаем все свойства receivingState
                for (const [key, value] of Object.entries(receivingState)) {
                    if (value && typeof value === 'object') {
                        if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
                            SecureMemoryManager.secureWipe(value);
                        } else if (Array.isArray(value)) {
                            value.fill(0);
                        }
                        receivingState[key] = null;
                    }
                }
            }
            
            // Удаляем из основных коллекций
            this.receivingTransfers.delete(fileId);
            this.sessionKeys.delete(fileId);
            this.incomingTransferChunkLimiters.delete(fileId);
            
            // ✅ БЕЗОПАСНАЯ очистка финального буфера файла
            const fileBuffer = this.receivedFileBuffers.get(fileId);
            if (fileBuffer) {
                try {
                    if (fileBuffer.buffer) {
                        SecureMemoryManager.secureWipe(fileBuffer.buffer);
                        
                        // Дополнительная очистка - заполняем нулями
                        const view = new Uint8Array(fileBuffer.buffer);
                        view.fill(0);
                    }
                    
                    // Очищаем все свойства fileBuffer
                    for (const [key, value] of Object.entries(fileBuffer)) {
                        if (value && typeof value === 'object') {
                            if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
                                SecureMemoryManager.secureWipe(value);
                            }
                            fileBuffer[key] = null;
                        }
                    }
                    
                    this.receivedFileBuffers.delete(fileId);
                } catch (bufferError) {
                    console.warn('⚠️ Failed to securely clear file buffer:', bufferError);
                    // Принудительно удаляем даже при ошибке
                    this.receivedFileBuffers.delete(fileId);
                }
            }
            
            // ✅ БЕЗОПАСНАЯ очистка processed chunks
            const chunksToRemove = [];
            for (const chunkId of this.processedChunks) {
                if (chunkId.startsWith(fileId)) {
                    chunksToRemove.push(chunkId);
                }
            }
            
            // Удаляем в отдельном цикле для избежания изменения коллекции во время итерации
            for (const chunkId of chunksToRemove) {
                this.processedChunks.delete(chunkId);
            }
            
            // Принудительная очистка памяти
            if (typeof global !== 'undefined' && global.gc) {
                try {
                    global.gc();
                } catch (gcError) {
                    // Игнорируем ошибки GC
                }
            }
            
            console.log(`🔒 Memory safely cleaned for file transfer: ${fileId}`);
            
        } catch (error) {
            console.error('❌ Error during secure memory cleanup:', error);
            
            // Принудительная очистка даже при ошибке
            this.receivingTransfers.delete(fileId);
            this.sessionKeys.delete(fileId);
            this.receivedFileBuffers.delete(fileId);
            this.pendingChunks.delete(fileId);
            
            throw new Error(`Memory cleanup failed: ${error.message}`);
        }
    }

    getTransferStatus(fileId) {
        if (this.activeTransfers.has(fileId)) {
            const transfer = this.activeTransfers.get(fileId);
            return {
                type: 'sending',
                fileId: transfer.fileId,
                fileName: transfer.file.name,
                progress: Math.round((transfer.sentChunks / transfer.totalChunks) * 100),
                status: transfer.status,
                startTime: transfer.startTime
            };
        }
        
        if (this.receivingTransfers.has(fileId)) {
            const transfer = this.receivingTransfers.get(fileId);
            return {
                type: 'receiving',
                fileId: transfer.fileId,
                fileName: transfer.fileName,
                progress: Math.round((transfer.receivedCount / transfer.totalChunks) * 100),
                status: transfer.status,
                startTime: transfer.startTime
            };
        }
        
        return null;
    }

    getSystemStatus() {
        return {
            initialized: true,
            activeTransfers: this.activeTransfers.size,
            receivingTransfers: this.receivingTransfers.size,
            totalTransfers: this.activeTransfers.size + this.receivingTransfers.size,
            maxConcurrentTransfers: this.MAX_CONCURRENT_TRANSFERS,
            maxFileSize: this.MAX_FILE_SIZE,
            chunkSize: this.CHUNK_SIZE,
            hasWebrtcManager: !!this.webrtcManager,
            isConnected: this.webrtcManager?.isConnected?.() || false,
            hasDataChannel: !!this.webrtcManager?.dataChannel,
            dataChannelState: this.webrtcManager?.dataChannel?.readyState,
            isVerified: this.webrtcManager?.isVerified,
            hasEncryptionKey: !!this.webrtcManager?.encryptionKey,
            hasMacKey: !!this.webrtcManager?.macKey,
            linkedToWebRTCManager: this.webrtcManager?.fileTransferSystem === this,
            supportedFileTypes: this.getSupportedFileTypes(),
            fileTypeInfo: this.getFileTypeInfo()
        };
    }

    cleanup() {
        SecureFileTransferContext.getInstance().deactivate();

        if (this.webrtcManager && this.webrtcManager.dataChannel && this.originalOnMessage) {
            this.webrtcManager.dataChannel.onmessage = this.originalOnMessage;
            this.originalOnMessage = null;
        }
        
        if (this.webrtcManager && this.originalProcessMessage) {
            this.webrtcManager.processMessage = this.originalProcessMessage;
            this.originalProcessMessage = null;
        }
        
        if (this.webrtcManager && this.originalRemoveSecurityLayers) {
            this.webrtcManager.removeSecurityLayers = this.originalRemoveSecurityLayers;
            this.originalRemoveSecurityLayers = null;
        }
        
        // Cleanup all active transfers with secure memory wiping
        for (const fileId of this.activeTransfers.keys()) {
            this.cleanupTransfer(fileId);
        }
        
        for (const fileId of this.receivingTransfers.keys()) {
            this.cleanupReceivingTransfer(fileId);
        }

        if (this.atomicOps) {
            this.atomicOps.locks.clear();
        }
        
        if (this.rateLimiter) {
            this.rateLimiter.requests.clear();
        }
        if (this.incomingChunkLimiter) {
            this.incomingChunkLimiter.requests.clear();
        }
        this.incomingTransferChunkLimiters.clear();
        
        // Clear all state
        this.pendingChunks.clear();
        this.pendingIncomingTransfers.clear();
        this.activeTransfers.clear();
        this.receivingTransfers.clear();
        this.transferQueue.length = 0;
        this.sessionKeys.clear();
        this.transferNonces.clear();
        this.processedChunks.clear();

        for (const fileId of Array.from(this.receivedFileBuffers.keys())) {
            this._discardReceivedFileBuffer(fileId);
        }

        this.clearKeys();
    }

    // ============================================
    // SESSION UPDATE HANDLER - FIXED
    // ============================================
    
    onSessionUpdate(sessionData) {
        // Clear session keys cache for resync
        this.sessionKeys.clear();
    }

    // ============================================
    // DEBUGGING AND DIAGNOSTICS
    // ============================================

    diagnoseFileTransferIssue() {
        const diagnosis = {
            timestamp: new Date().toISOString(),
            fileTransferSystem: {
                initialized: !!this,
                hasWebrtcManager: !!this.webrtcManager,
                webrtcManagerType: this.webrtcManager?.constructor?.name,
                linkedToWebRTCManager: this.webrtcManager?.fileTransferSystem === this
            },
            webrtcManager: {
                hasDataChannel: !!this.webrtcManager?.dataChannel,
                dataChannelState: this.webrtcManager?.dataChannel?.readyState,
                isConnected: this.webrtcManager?.isConnected?.() || false,
                isVerified: this.webrtcManager?.isVerified,
                hasEncryptionKey: !!this.webrtcManager?.encryptionKey,
                hasMacKey: !!this.webrtcManager?.macKey,
                hasKeyFingerprint: !!this.webrtcManager?.keyFingerprint,
                hasSessionSalt: !!this.webrtcManager?.sessionSalt
            },
            securityContext: {
                contextActive: SecureFileTransferContext.getInstance().isActive(),
                securityLevel: SecureFileTransferContext.getInstance().getSecurityLevel(),
                hasAtomicOps: !!this.atomicOps,
                hasRateLimiter: !!this.rateLimiter
            },
            transfers: {
                activeTransfers: this.activeTransfers.size,
                receivingTransfers: this.receivingTransfers.size,
                pendingChunks: this.pendingChunks.size,
                sessionKeys: this.sessionKeys.size
            },
            fileTypeSupport: {
                supportedTypes: this.getSupportedFileTypes(),
                generalMaxSize: this.formatFileSize(this.MAX_FILE_SIZE),
                restrictions: Object.keys(this.FILE_TYPE_RESTRICTIONS)
            }
        };
        
        return diagnosis;
    }

    async debugKeyDerivation(fileId) {
        try {
            if (!this.webrtcManager.keyFingerprint || !this.webrtcManager.sessionSalt) {
                throw new Error('Session data not available');
            }
            
            // Test sender derivation
            const senderResult = await this.deriveFileSessionKey(fileId);
            
            // Test receiver derivation with same salt
            const receiverKey = await this.deriveFileSessionKeyFromSalt(fileId, senderResult.salt);
            
            // Test encryption/decryption
            const testData = new TextEncoder().encode('test data');
            const nonce = crypto.getRandomValues(new Uint8Array(12));
            
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: nonce },
                senderResult.key,
                testData
            );
            
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: nonce },
                receiverKey,
                encrypted
            );
            
            const decryptedText = new TextDecoder().decode(decrypted);
            
            if (decryptedText === 'test data') {
                return { success: true, message: 'All tests passed' };
            } else {
                throw new Error('Decryption verification failed');
            }
            
        } catch (error) {
            console.error('❌ Key derivation test failed:', error);
            return { success: false, error: error.message };
        }
    }

    // ============================================
    // ALTERNATIVE METHOD OF INITIALIZING HANDLERS
    // ============================================

    registerWithWebRTCManager() {
        if (!this.webrtcManager) {
            throw new Error('WebRTC manager not available');
        }

        this.webrtcManager.fileTransferSystem = this;

        this.webrtcManager.setFileMessageHandler = (handler) => {
            this.webrtcManager._fileMessageHandler = handler;
        };

        this.webrtcManager.setFileMessageHandler((message) => {
            return this.handleFileMessage(message);
        });
    }

    static createFileMessageFilter(fileTransferSystem) {
        return async (event) => {
            try {
                if (typeof event.data === 'string') {
                    const parsed = JSON.parse(event.data);
                    
                    if (fileTransferSystem.isFileTransferMessage(parsed)) {
                        await fileTransferSystem.handleFileMessage(parsed);
                        return true; 
                    }
                }
            } catch (error) {
            }
            
            return false; 
        };
    }

    // ============================================
    // SECURITY KEY MANAGEMENT
    // ============================================

    setSigningKey(privateKey) {
        if (!privateKey || !(privateKey instanceof CryptoKey)) {
            throw new Error('Invalid private key for signing');
        }
        this.signingKey = privateKey;
        console.log('🔒 Signing key set successfully');
    }

    setVerificationKey(publicKey) {
        if (!publicKey || !(publicKey instanceof CryptoKey)) {
            throw new Error('Invalid public key for verification');
        }
        this.verificationKey = publicKey;
        console.log('🔒 Verification key set successfully');
    }

    async generateSigningKeyPair() {
        try {
            const keyPair = await crypto.subtle.generateKey(
                {
                    name: 'RSASSA-PKCS1-v1_5',
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: 'SHA-256'
                },
                true, // extractable
                ['sign', 'verify']
            );
            
            this.signingKey = keyPair.privateKey;
            this.verificationKey = keyPair.publicKey;
            
            console.log('🔒 RSA key pair generated successfully');
            return keyPair;
        } catch (error) {
            const safeError = SecurityErrorHandler.sanitizeError(error);
            console.error('❌ Failed to generate signing key pair:', safeError);
            throw new Error(safeError);
        }
    }

    clearKeys() {
        this.signingKey = null;
        this.verificationKey = null;
        console.log('🔒 Security keys cleared');
    }

    getSecurityStatus() {
        return {
            signingEnabled: this.signingKey !== null,
            verificationEnabled: this.verificationKey !== null,
            contextActive: SecureFileTransferContext.getInstance().isActive(),
            securityLevel: SecureFileTransferContext.getInstance().getSecurityLevel()
        };
    }

    getClientIdentifier() {
        return this.webrtcManager?.connectionId || 
               this.webrtcManager?.keyFingerprint?.substring(0, 16) || 
               'default-client';
    }
    
    destroy() {
        SecureFileTransferContext.getInstance().deactivate();
        this.clearKeys();
        console.log('🔒 File transfer system destroyed safely');
    }
}

export { EnhancedSecureFileTransfer };
