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
        if (this.locks.has(key)) {
            await this.locks.get(key);
        }
        
        const lockPromise = (async () => {
            try {
                return await operation();
            } finally {
                this.locks.delete(key);
            }
        })();
        
        this.locks.set(key, lockPromise);
        return lockPromise;
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
    constructor(webrtcManager, onProgress, onComplete, onError, onFileReceived) {
        this.webrtcManager = webrtcManager;
        this.onProgress = onProgress;
        this.onComplete = onComplete;
        this.onError = onError;
        this.onFileReceived = onFileReceived;
        
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
        this.CHUNK_SIZE = 64 * 1024; // 64 KB
        this.MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB limit
        this.MAX_CONCURRENT_TRANSFERS = 3;
        this.CHUNK_TIMEOUT = 30000; // 30 seconds per chunk
        this.RETRY_ATTEMPTS = 3;

        this.FILE_TYPE_RESTRICTIONS = {
            documents: {
                extensions: ['.pdf', '.doc', '.docx', '.txt', '.md', '.rtf', '.odt'],
                mimeTypes: [
                    'application/pdf',
                    'application/msword',
                    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                    'text/plain',
                    'text/markdown',
                    'application/rtf',
                    'application/vnd.oasis.opendocument.text'
                ],
                maxSize: 50 * 1024 * 1024, // 50 MB
                category: 'Documents',
                description: 'PDF, DOC, TXT, MD, RTF, ODT'
            },
            
            images: {
                extensions: ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg', '.ico'],
                mimeTypes: [
                    'image/jpeg',
                    'image/png',
                    'image/gif',
                    'image/webp',
                    'image/bmp',
                    'image/svg+xml',
                    'image/x-icon'
                ],
                maxSize: 25 * 1024 * 1024, // 25 MB
                category: 'Images',
                description: 'JPG, PNG, GIF, WEBP, BMP, SVG, ICO'
            },
            
            archives: {
                extensions: ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'],
                mimeTypes: [
                    'application/zip',
                    'application/x-rar-compressed',
                    'application/x-7z-compressed',
                    'application/x-tar',
                    'application/gzip',
                    'application/x-bzip2',
                    'application/x-xz'
                ],
                maxSize: 100 * 1024 * 1024, // 100 MB
                category: 'Archives',
                description: 'ZIP, RAR, 7Z, TAR, GZ, BZ2, XZ'
            },
            
            media: {
                extensions: ['.mp3', '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.ogg', '.wav'],
                mimeTypes: [
                    'audio/mpeg',
                    'video/mp4',
                    'video/x-msvideo',
                    'video/x-matroska',
                    'video/quicktime',
                    'video/x-ms-wmv',
                    'video/x-flv',
                    'video/webm',
                    'audio/ogg',
                    'audio/wav'
                ],
                maxSize: 100 * 1024 * 1024, // 100 MB
                category: 'Media',
                description: 'MP3, MP4, AVI, MKV, MOV, WMV, FLV, WEBM, OGG, WAV'
            },
            
            general: {
                extensions: [], 
                mimeTypes: [], 
                maxSize: 50 * 1024 * 1024, // 50 MB
                category: 'General',
                description: 'Any file type up to size limits'
            }
        };
        
        // Active transfers tracking
        this.activeTransfers = new Map(); // fileId -> transfer state
        this.receivingTransfers = new Map(); // fileId -> receiving state
        this.transferQueue = []; // Queue for pending transfers
        this.pendingChunks = new Map();
        
        // Session key derivation
        this.sessionKeys = new Map(); // fileId -> derived session key
        
        // Security
        this.processedChunks = new Set(); // Prevent replay attacks
        this.transferNonces = new Map(); // fileId -> current nonce counter
        this.receivedFileBuffers = new Map(); // fileId -> { buffer:ArrayBuffer, type:string, name:string, size:number }

        this.setupFileMessageHandlers();

        if (this.webrtcManager) {
            this.webrtcManager.fileTransferSystem = this;
        }
    }

    // ============================================
    // FILE TYPE VALIDATION SYSTEM
    // ============================================

    getFileType(file) {
        const fileName = file.name.toLowerCase();
        const fileExtension = fileName.substring(fileName.lastIndexOf('.'));
        const mimeType = file.type.toLowerCase();

        for (const [typeKey, typeConfig] of Object.entries(this.FILE_TYPE_RESTRICTIONS)) {
            if (typeKey === 'general') continue; // Пропускаем общий тип

            if (typeConfig.extensions.includes(fileExtension)) {
                return {
                    type: typeKey,
                    category: typeConfig.category,
                    description: typeConfig.description,
                    maxSize: typeConfig.maxSize,
                    allowed: true
                };
            }

            if (typeConfig.mimeTypes.includes(mimeType)) {
                return {
                    type: typeKey,
                    category: typeConfig.category,
                    description: typeConfig.description,
                    maxSize: typeConfig.maxSize,
                    allowed: true
                };
            }
        }

        const generalConfig = this.FILE_TYPE_RESTRICTIONS.general;
        return {
            type: 'general',
            category: generalConfig.category,
            description: generalConfig.description,
            maxSize: generalConfig.maxSize,
            allowed: true
        };
    }

    validateFile(file) {
        const fileType = this.getFileType(file);
        const errors = [];

        if (file.size > fileType.maxSize) {
            errors.push(`File size (${this.formatFileSize(file.size)}) exceeds maximum allowed for ${fileType.category} (${this.formatFileSize(fileType.maxSize)})`);
        }

        if (!fileType.allowed) {
            errors.push(`File type not allowed. Supported types: ${fileType.description}`);
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
            if (typeKey === 'general') continue;
            
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

            // Send file metadata first
            await this.sendFileMetadata(transferState);
            
            // Start chunk transmission
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
            
            // Timeout for completion confirmation
            setTimeout(() => {
                if (this.activeTransfers.has(transferState.fileId)) {
                    const state = this.activeTransfers.get(transferState.fileId);
                    if (state.status === 'waiting_confirmation') {
                        this.cleanupTransfer(transferState.fileId);
                    }
                }
            }, 30000);
            
        } catch (error) {
            const safeError = SecurityErrorHandler.sanitizeError(error);
            console.error('❌ Chunk transmission failed:', safeError);
            transferState.status = 'failed';
            throw new Error(safeError);
        }
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
            // Validate metadata
            if (!metadata.fileId || !metadata.fileName || !metadata.fileSize) {
                throw new Error('Invalid file transfer metadata');
            }

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
            if (this.receivingTransfers.has(metadata.fileId)) {
                return;
            }
            
            // Derive session key from salt
            const sessionKey = await this.deriveFileSessionKeyFromSalt(
                metadata.fileId,
                metadata.salt
            );
            
            // Create receiving transfer state
            const receivingState = {
                fileId: metadata.fileId,
                fileName: metadata.fileName,
                fileSize: metadata.fileSize,
                fileType: metadata.fileType || 'application/octet-stream',
                fileHash: metadata.fileHash,
                totalChunks: metadata.totalChunks,
                chunkSize: metadata.chunkSize || this.CHUNK_SIZE,
                sessionKey: sessionKey,
                salt: metadata.salt,
                receivedChunks: new Map(),
                receivedCount: 0,
                startTime: Date.now(),
                lastChunkTime: Date.now(),
                status: 'receiving'
            };
            
            this.receivingTransfers.set(metadata.fileId, receivingState);
            
            // Send acceptance response
            const response = {
                type: 'file_transfer_response',
                fileId: metadata.fileId,
                accepted: true,
                timestamp: Date.now()
            };
            
            await this.sendSecureMessage(response);

            // Process buffered chunks if any
            if (this.pendingChunks.has(metadata.fileId)) {
                const bufferedChunks = this.pendingChunks.get(metadata.fileId);
                
                for (const [chunkIndex, chunkMessage] of bufferedChunks.entries()) {
                    await this.handleFileChunk(chunkMessage);
                }
                
                this.pendingChunks.delete(metadata.fileId);
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
                
                    // Buffer early chunks if transfer not yet initialized
                    if (!receivingState) {
                        if (!this.pendingChunks.has(chunkMessage.fileId)) {
                            this.pendingChunks.set(chunkMessage.fileId, new Map());
                        }
                        
                        this.pendingChunks.get(chunkMessage.fileId).set(chunkMessage.chunkIndex, chunkMessage);
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
                    const safeError = SecurityErrorHandler.sanitizeError(error);
                    console.error('❌ Failed to handle file chunk:', safeError);
                    
                    // Send error notification
                    const errorMessage = {
                        type: 'file_transfer_error',
                        fileId: chunkMessage.fileId,
                        error: safeError, 
                        chunkIndex: chunkMessage.chunkIndex,
                        timestamp: Date.now()
                    };
                    await this.sendSecureMessage(errorMessage);
                    
                    // Mark transfer as failed
                    const receivingState = this.receivingTransfers.get(chunkMessage.fileId);
                    if (receivingState) {
                        receivingState.status = 'failed';
                    }
                    
                    if (this.onError) {
                        this.onError(`Chunk processing failed: ${safeError}`);
                    }
                }
            }
        );
    }

    async assembleFile(receivingState) {
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

            this.receivedFileBuffers.set(receivingState.fileId, {
                buffer: fileBuffer,
                type: receivingState.fileType,
                name: receivingState.fileName,
                size: receivingState.fileSize
            });

            if (this.onFileReceived) {
                const getBlob = async () => new Blob([this.receivedFileBuffers.get(receivingState.fileId).buffer], { type: receivingState.fileType });
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
            
            // Cleanup
            if (this.receivingTransfers.has(receivingState.fileId)) {
                const rs = this.receivingTransfers.get(receivingState.fileId);
                if (rs && rs.receivedChunks) rs.receivedChunks.clear();
            }
            this.receivingTransfers.delete(receivingState.fileId);
            
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
            } else {
                transferState.status = 'rejected';
                
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
            status: transfer.status,
            startTime: transfer.startTime
        }));
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
        this.activeTransfers.delete(fileId);
        this.sessionKeys.delete(fileId);
        this.transferNonces.delete(fileId);
        
        // Remove processed chunk IDs for this transfer
        for (const chunkId of this.processedChunks) {
            if (chunkId.startsWith(fileId)) {
                this.processedChunks.delete(chunkId);
            }
        }
    }

    // ✅ УЛУЧШЕННАЯ безопасная очистка памяти для предотвращения use-after-free
    cleanupReceivingTransfer(fileId) {
        try {
            // Безопасно очищаем pending chunks
            this.pendingChunks.delete(fileId);
            
            const receivingState = this.receivingTransfers.get(fileId);
            if (receivingState) {
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
        
        // Clear all state
        this.pendingChunks.clear();
        this.activeTransfers.clear();
        this.receivingTransfers.clear();
        this.transferQueue.length = 0;
        this.sessionKeys.clear();
        this.transferNonces.clear();
        this.processedChunks.clear();

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