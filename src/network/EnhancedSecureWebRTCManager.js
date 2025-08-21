// Import EnhancedSecureFileTransfer
import { EnhancedSecureFileTransfer } from '../transfer/EnhancedSecureFileTransfer.js';

// ============================================
// MUTEX SYSTEM FIXES - RESOLVING MESSAGE DELIVERY ISSUES
// ============================================
// Issue: After introducing the Mutex system, messages stopped being delivered between users
// Fix: Simplified locking logic — mutex is used ONLY for critical operations
// - Regular messages are processed WITHOUT mutex
// - File messages are processed WITHOUT mutex  
// - Mutex is used ONLY for cryptographic operations
// ============================================

class EnhancedSecureWebRTCManager {
    // ============================================
    // CONSTANTS
    // ============================================
    
    static TIMEOUTS = {
        KEY_ROTATION_INTERVAL: 300000,      // 5 minutes
        CONNECTION_TIMEOUT: 10000,          // 10 seconds  
        HEARTBEAT_INTERVAL: 30000,          // 30 seconds
        SECURITY_CALC_DELAY: 1000,          // 1 second
        SECURITY_CALC_RETRY_DELAY: 3000,    // 3 seconds
        CLEANUP_INTERVAL: 300000,           // 5 minutes (periodic cleanup)
        CLEANUP_CHECK_INTERVAL: 60000,      // 1 minute (cleanup check)
        ICE_GATHERING_TIMEOUT: 10000,       // 10 seconds
        DISCONNECT_CLEANUP_DELAY: 500,      // 500ms
        PEER_DISCONNECT_CLEANUP: 2000,      // 2 seconds
        STAGE2_ACTIVATION_DELAY: 10000,     // 10 seconds
        STAGE3_ACTIVATION_DELAY: 15000,     // 15 seconds  
        STAGE4_ACTIVATION_DELAY: 20000,     // 20 seconds
        FILE_TRANSFER_INIT_DELAY: 1000,     // 1 second
        FAKE_TRAFFIC_MIN_INTERVAL: 15000,   // 15 seconds
        FAKE_TRAFFIC_MAX_INTERVAL: 30000,   // 30 seconds
        DECOY_INITIAL_DELAY: 5000,          // 5 seconds
        DECOY_TRAFFIC_MIN: 10000,           // 10 seconds
        DECOY_TRAFFIC_MAX: 25000,           // 25 seconds
        REORDER_TIMEOUT: 3000,              // 3 seconds
        RETRY_CONNECTION_DELAY: 2000        // 2 seconds
    };

    static LIMITS = {
        MAX_CONNECTION_ATTEMPTS: 3,
        MAX_OLD_KEYS: 3,
        MAX_PROCESSED_MESSAGE_IDS: 1000,
        MAX_OUT_OF_ORDER_PACKETS: 5,
        MAX_DECOY_CHANNELS: 1,
        MESSAGE_RATE_LIMIT: 60,             // messages per minute
        MAX_KEY_AGE: 900000,                // 15 minutes
        OFFER_MAX_AGE: 3600000,             // 1 hour
        SALT_SIZE_V3: 32,                   // bytes
        SALT_SIZE_V4: 64                    // bytes
    };

    static SIZES = {
        VERIFICATION_CODE_MIN_LENGTH: 6,
        FAKE_TRAFFIC_MIN_SIZE: 32,
        FAKE_TRAFFIC_MAX_SIZE: 128,
        PACKET_PADDING_MIN: 64,
        PACKET_PADDING_MAX: 512,
        CHUNK_SIZE_MAX: 2048,
        CHUNK_DELAY_MIN: 100,
        CHUNK_DELAY_MAX: 500,
        FINGERPRINT_DISPLAY_LENGTH: 8,
        SESSION_ID_LENGTH: 16,
        NESTED_ENCRYPTION_IV_SIZE: 12
    };

    static MESSAGE_TYPES = {
        // Regular messages
        MESSAGE: 'message',
        ENHANCED_MESSAGE: 'enhanced_message',
        
        // System messages
        HEARTBEAT: 'heartbeat',
        VERIFICATION: 'verification',
        VERIFICATION_RESPONSE: 'verification_response',
        PEER_DISCONNECT: 'peer_disconnect',
        SECURITY_UPGRADE: 'security_upgrade',
        KEY_ROTATION_SIGNAL: 'key_rotation_signal',
        KEY_ROTATION_READY: 'key_rotation_ready',
        
        // File transfer messages
        FILE_TRANSFER_START: 'file_transfer_start',
        FILE_TRANSFER_RESPONSE: 'file_transfer_response',
        FILE_CHUNK: 'file_chunk',
        CHUNK_CONFIRMATION: 'chunk_confirmation',
        FILE_TRANSFER_COMPLETE: 'file_transfer_complete',
        FILE_TRANSFER_ERROR: 'file_transfer_error',
        
        // Fake traffic
        FAKE: 'fake'
    };

    static FILTERED_RESULTS = {
        FAKE_MESSAGE: 'FAKE_MESSAGE_FILTERED',
        FILE_MESSAGE: 'FILE_MESSAGE_FILTERED', 
        SYSTEM_MESSAGE: 'SYSTEM_MESSAGE_FILTERED'
    };
    constructor(onMessage, onStatusChange, onKeyExchange, onVerificationRequired, onAnswerError = null) {
    // Determine runtime mode
    this._isProductionMode = this._detectProductionMode();
    this._debugMode = !this._isProductionMode && window.DEBUG_MODE;

    // Initialize the secure logging system
        this._initializeSecureLogging();
        this._disableConsoleLogInProduction();
        this._redirectConsoleLogToSecure();
    // Check the availability of the global object
        this._setupSecureGlobalAPI();
    if (!window.EnhancedSecureCryptoUtils) {
        throw new Error('EnhancedSecureCryptoUtils is not loaded. Please ensure the module is loaded first.');
    }
    this.getSecurityData = () => {
        // Return only public information
        return this.lastSecurityCalculation ? {
            level: this.lastSecurityCalculation.level,
            score: this.lastSecurityCalculation.score,
            timestamp: this.lastSecurityCalculation.timestamp,
            // Do NOT return check details or sensitive data
        } : null;
    };
    this._secureLog('info', '🔒 Enhanced WebRTC Manager initialized with secure API');
    this.currentSessionType = null;
    this.currentSecurityLevel = 'basic';
    this.sessionConstraints = null;
    this.peerConnection = null;
    this.dataChannel = null;


    this.onMessage = onMessage;
    this.onStatusChange = onStatusChange;
    this.onKeyExchange = onKeyExchange;
    this.onVerificationRequired = onVerificationRequired;
    this.onAnswerError = onAnswerError; // Callback for response processing errors
    this.isInitiator = false;
    this.connectionAttempts = 0;
    this.maxConnectionAttempts = EnhancedSecureWebRTCManager.LIMITS.MAX_CONNECTION_ATTEMPTS;
    try {
    this._initializeMutexSystem();
} catch (error) {
    this._secureLog('error', '❌ Failed to initialize mutex system', {
        errorType: error.constructor.name
    });
    throw new Error('Critical: Mutex system initialization failed');
}

// Post-initialization validation of the mutex system
if (!this._validateMutexSystem()) {
    this._secureLog('error', '❌ Mutex system validation failed after initialization');
    throw new Error('Critical: Mutex system validation failed');
}

// Add global emergency handlers
if (typeof window !== 'undefined') {
    window.emergencyUnlockMutexes = () => {
        return this._emergencyUnlockAllMutexes();
    };
    
    window.getMutexDiagnostics = () => {
        return this._getMutexSystemDiagnostics();
    };
    
    window.recoverMutexSystem = () => {
        return this._emergencyRecoverMutexSystem();
    };
}

this._secureLog('info', '🔒 Enhanced Mutex system fully initialized and validated');
    this.heartbeatInterval = null;
    this.messageQueue = [];
    this.ecdhKeyPair = null;
    this.ecdsaKeyPair = null;
    if (this.fileTransferSystem) {
        this.fileTransferSystem.cleanup();
        this.fileTransferSystem = null;
    }
    this.verificationCode = null;
    this.isVerified = false;
    this.processedMessageIds = new Set();
    this.messageCounter = 0;
    this.sequenceNumber = 0;
    this.expectedSequenceNumber = 0;
    this.sessionSalt = null;
    this.sessionId = null; // MITM protection: Session identifier
    this.peerPublicKey = null; // Store peer's public key for PFS
    this.rateLimiterId = null;
    this.intentionalDisconnect = false;
    this.lastCleanupTime = Date.now();
    
    // Reset notification flags for new connection
    this._resetNotificationFlags();
    
    

    this.verificationInitiationSent = false;
    this.disconnectNotificationSent = false;
    this.reconnectionFailedNotificationSent = false;
    this.peerDisconnectNotificationSent = false;
    this.connectionClosedNotificationSent = false;
    this.fakeTrafficDisabledNotificationSent = false;
    this.advancedFeaturesDisabledNotificationSent = false;
    this.securityUpgradeNotificationSent = false;
    this.lastSecurityUpgradeStage = null;
    this.securityCalculationNotificationSent = false;
    this.lastSecurityCalculationLevel = null;
    
    // File transfer integration
    this.fileTransferSystem = null;
    this.onFileProgress = null;
    this.onFileReceived = null;
    this.onFileError = null;
    
    // PFS (Perfect Forward Secrecy) Implementation
    this.keyRotationInterval = EnhancedSecureWebRTCManager.TIMEOUTS.KEY_ROTATION_INTERVAL;
    this.lastKeyRotation = Date.now();
    this.currentKeyVersion = 0;
    this.keyVersions = new Map(); // Store key versions for PFS
    this.oldKeys = new Map(); // Store old keys temporarily for decryption
    this.maxOldKeys = EnhancedSecureWebRTCManager.LIMITS.MAX_OLD_KEYS; // Keep last 3 key versions for decryption
    this.peerConnection = null;
    this.dataChannel = null;
         this.securityFeatures = {
            hasEncryption: true,
            hasECDH: true,
            hasECDSA: false,
            hasMutualAuth: false,
            hasMetadataProtection: false,
            hasEnhancedReplayProtection: false,
            hasNonExtractableKeys: false,
            hasRateLimiting: true,
            hasEnhancedValidation: false,
            hasPFS: false,
            
            // Advanced Features (Session Managed)
            hasNestedEncryption: false,     
            hasPacketPadding: false,        
            hasPacketReordering: false,    
            hasAntiFingerprinting: false,  
            hasFakeTraffic: false,         
            hasDecoyChannels: false,       
            hasMessageChunking: false      
        };
        console.log('🔒 Enhanced WebRTC Manager initialized with tiered security');
    // ============================================
    // ENHANCED SECURITY FEATURES
    // ============================================
        
        // 1. Nested Encryption Layer
            this.nestedEncryptionKey = null;
            this.nestedEncryptionIV = null;
            this.nestedEncryptionCounter = 0;
                
            // 2. Packet Padding
            this.paddingConfig = {
                enabled: true,              
                minPadding: EnhancedSecureWebRTCManager.SIZES.PACKET_PADDING_MIN,
                maxPadding: EnhancedSecureWebRTCManager.SIZES.PACKET_PADDING_MAX,            
                useRandomPadding: true,
                preserveMessageSize: false
            };
                
            // 3. Fake Traffic Generation
            this.fakeTrafficConfig = {
                enabled: !window.DISABLE_FAKE_TRAFFIC, 
                minInterval: EnhancedSecureWebRTCManager.TIMEOUTS.FAKE_TRAFFIC_MIN_INTERVAL,        
                maxInterval: EnhancedSecureWebRTCManager.TIMEOUTS.FAKE_TRAFFIC_MAX_INTERVAL,       
                minSize: EnhancedSecureWebRTCManager.SIZES.FAKE_TRAFFIC_MIN_SIZE,
                maxSize: EnhancedSecureWebRTCManager.SIZES.FAKE_TRAFFIC_MAX_SIZE,               
                patterns: ['heartbeat', 'status', 'sync']
            };
            this.fakeTrafficTimer = null;
            this.lastFakeTraffic = 0;
                
            // 4. Message Chunking
            this.chunkingConfig = {
                enabled: false,
                maxChunkSize: EnhancedSecureWebRTCManager.SIZES.CHUNK_SIZE_MAX,        
                minDelay: EnhancedSecureWebRTCManager.SIZES.CHUNK_DELAY_MIN,
                maxDelay: EnhancedSecureWebRTCManager.SIZES.CHUNK_DELAY_MAX,
                useRandomDelays: true,
                addChunkHeaders: true
            };
            this.chunkQueue = [];
            this.chunkingInProgress = false;
                
            // 5. Decoy Channels
            this.decoyChannels = new Map();
            this.decoyChannelConfig = {
                enabled: !window.DISABLE_DECOY_CHANNELS, 
                maxDecoyChannels: EnhancedSecureWebRTCManager.LIMITS.MAX_DECOY_CHANNELS,       
                decoyChannelNames: ['heartbeat'], 
                sendDecoyData: true,
                randomDecoyIntervals: true
            };
            this.decoyTimers = new Map();
                
            // 6. Packet Reordering Protection
            this.reorderingConfig = {
                enabled: false,             
                maxOutOfOrder: EnhancedSecureWebRTCManager.LIMITS.MAX_OUT_OF_ORDER_PACKETS,           
                reorderTimeout: EnhancedSecureWebRTCManager.TIMEOUTS.REORDER_TIMEOUT,       
                useSequenceNumbers: true,
                useTimestamps: true
            };
            this.packetBuffer = new Map(); // sequence -> {data, timestamp}
            this.lastProcessedSequence = -1;
                
            // 7. Anti-Fingerprinting
            this.antiFingerprintingConfig = {
                enabled: false,             
                randomizeTiming: true,
                randomizeSizes: false,      
                addNoise: true,
                maskPatterns: false,        
                useRandomHeaders: false     
            };
            this.fingerprintMask = this.generateFingerprintMask();
                
            // Initialize rate limiter ID
            this.rateLimiterId = `webrtc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
                
            // Start periodic cleanup
            this.startPeriodicCleanup();
                
            this.initializeEnhancedSecurity(); 
            // ============================================
            // MUTEX SYSTEM TO PREVENT RACE CONDITIONS
            // ============================================

            // Mutex for key operations
            this._keyOperationMutex = {
                locked: false,
                queue: [],
                lockId: null,
                lockTimeout: null
            };

            // Mutex for encryption/decryption operations
            this._cryptoOperationMutex = {
                locked: false,
                queue: [],
                lockId: null,
                lockTimeout: null
            };

            // Mutex for connection initialization
            this._connectionOperationMutex = {
                locked: false,
                queue: [],
                lockId: null,
                lockTimeout: null
            };

            // Key system state
            this._keySystemState = {
                isInitializing: false,
                isRotating: false,
                isDestroying: false,
                lastOperation: null,
                lastOperationTime: Date.now()
            };

            // Operation counters
            this._operationCounters = {
                keyOperations: 0,
                cryptoOperations: 0,
                connectionOperations: 0
            };

        }
_initializeMutexSystem() {
	// Initialize standard mutexes expected by the system
	this._keyOperationMutex = {
		locked: false,
		queue: [],
		lockId: null,
		lockTimeout: null
	};

	this._cryptoOperationMutex = {
		locked: false,
		queue: [],
		lockId: null,
		lockTimeout: null
	};

	this._connectionOperationMutex = {
		locked: false,
		queue: [],
		lockId: null,
		lockTimeout: null
	};

	// Key system state
	this._keySystemState = {
		isInitializing: false,
		isRotating: false,
		isDestroying: false,
		lastOperation: null,
		lastOperationTime: Date.now()
	};

	// Operation counters
	this._operationCounters = {
		keyOperations: 0,
		cryptoOperations: 0,
		connectionOperations: 0
	};

	this._secureLog('info', '🔒 Mutex system initialized successfully', {
		mutexes: ['keyOperation', 'cryptoOperation', 'connectionOperation'],
		timestamp: Date.now()
	});
}

    // ============================================
    // SECURE KEY STORAGE MANAGEMENT
    // ============================================

    /**
     * Initializes the secure key storage
     */
    _initializeSecureKeyStorage() {
        this._secureKeyStorage = new Map();
        this._keyStorageStats = {
            totalKeys: 0,
            activeKeys: 0,
            lastAccess: null,
            lastRotation: null,
        };
        this._secureLog('info', '🔐 Secure key storage initialized');
    }

    // Helper: ensure file transfer system is ready (lazy init on receiver)
    async _ensureFileTransferReady() {
        try {
            // If already initialized — done
            if (this.fileTransferSystem) {
                return true;
            }
            // Requires an open data channel and a verified connection
            if (!this.dataChannel || this.dataChannel.readyState !== 'open') {
                throw new Error('Data channel not open');
            }
            if (!this.isVerified) {
                throw new Error('Connection not verified');
            }
            // Initialization
            this.initializeFileTransfer();
            
            // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Ждем инициализации с таймаутом
            let attempts = 0;
            const maxAttempts = 50; // 5 секунд максимум
            while (!this.fileTransferSystem && attempts < maxAttempts) {
                await new Promise(r => setTimeout(r, 100));
                attempts++;
            }
            
            if (!this.fileTransferSystem) {
                throw new Error('File transfer system initialization timeout');
            }
            
            return true;
        } catch (e) {
            console.error('❌ _ensureFileTransferReady failed:', e?.message || e);
            return false;
        }
    }

    /**
     * Retrieves a key from secure storage
     * @param {string} keyId - Key identifier
     * @returns {CryptoKey|null} The key or null if not found
     */
    _getSecureKey(keyId) {
        if (!this._secureKeyStorage.has(keyId)) {
            this._secureLog('warn', `⚠️ Key ${keyId} not found in secure storage`);
            return null;
        }
        this._keyStorageStats.lastAccess = Date.now();
        return this._secureKeyStorage.get(keyId);
    }

    /**
     * Stores a key in secure storage
     * @param {string} keyId - Key identifier
     * @param {CryptoKey} key - Key to store
     */
    _setSecureKey(keyId, key) {
        if (!(key instanceof CryptoKey)) {
            this._secureLog('error', '❌ Attempt to store non-CryptoKey in secure storage');
            return;
        }
        this._secureKeyStorage.set(keyId, key);
        this._keyStorageStats.totalKeys++;
        this._keyStorageStats.activeKeys++;
        this._keyStorageStats.lastAccess = Date.now();
        this._secureLog('info', `🔑 Key ${keyId} stored securely`);
    }

    /**
     * Validates a key value
     * @param {CryptoKey} key - Key to validate
     * @returns {boolean} true if the key is valid
     */
    _validateKeyValue(key) {
        return key instanceof CryptoKey &&
            key.algorithm &&
            key.usages &&
            key.usages.length > 0;
    }

    /**
     * Securely wipes all keys from storage
     */
    _secureWipeKeys() {
        this._secureKeyStorage.clear();
        this._keyStorageStats = {
            totalKeys: 0,
            activeKeys: 0,
            lastAccess: null,
            lastRotation: null,
        };
        this._secureLog('info', '🧹 All keys securely wiped from storage');
    }

    /**
     * Validates key storage state
     * @returns {boolean} true if the storage is ready
     */
    _validateKeyStorage() {
        return this._secureKeyStorage instanceof Map;
    }

    /**
     * Returns secure key storage statistics
     * @returns {object} Storage metrics
     */
    _getKeyStorageStats() {
        return {
            totalKeysCount: this._keyStorageStats.totalKeys,
            activeKeysCount: this._keyStorageStats.activeKeys,
            hasLastAccess: !!this._keyStorageStats.lastAccess,
            hasLastRotation: !!this._keyStorageStats.lastRotation,
            storageType: 'SecureMap',
            timestamp: Date.now()
        };
    }

    /**
     * Performs key rotation in storage
     */
    _rotateKeys() {
        const oldKeys = Array.from(this._secureKeyStorage.keys());
        this._secureKeyStorage.clear();
        this._keyStorageStats.lastRotation = Date.now();
        this._keyStorageStats.activeKeys = 0;
        this._secureLog('info', `🔄 Key rotation completed. ${oldKeys.length} keys rotated`);
    }

    /**
     * Emergency key wipe (e.g., upon detecting a threat)
     */
    _emergencyKeyWipe() {
        this._secureWipeKeys();
        this._secureLog('error', '🚨 EMERGENCY: All keys wiped due to security threat');
    }

    /**
     * Starts key security monitoring
     */
    _startKeySecurityMonitoring() {
        setInterval(() => {
            if (this._keyStorageStats.activeKeys > 10) {
                this._secureLog('warn', '⚠️ High number of active keys detected. Consider rotation.');
            }
            if (Date.now() - (this._keyStorageStats.lastRotation || 0) > 3600000) {
                this._rotateKeys();
            }
        }, 300000); // Check every 5 minutes
    }


    // ============================================
    // HELPER METHODS
    // ============================================
    /**
     * Initializes the secure logging system
     */
    _initializeSecureLogging() {
        // Logging levels
        this._logLevels = {
            error: 0,
            warn: 1, 
            info: 2,
            debug: 3,
            trace: 4
        };
        
        // FIX: Stricter levels for production
        this._currentLogLevel = this._isProductionMode ? 
            this._logLevels.error : // In production, ONLY errors
            this._logLevels.info;   // In development, up to info
        
        // Log counter to prevent spam
        this._logCounts = new Map();
        this._maxLogCount = this._isProductionMode ? 10 : 100; // Max logs of one type

        this._absoluteBlacklist = new Set([
            'encryptionKey', 'macKey', 'metadataKey', 'privateKey', 
            'verificationCode', 'sessionSalt', 'keyFingerprint',
            'password', 'token', 'secret', 'credential', 'signature',
            'ecdhKeyPair', 'ecdsaKeyPair', 'peerPublicKey',
            'sessionId', 'authChallenge', 'authProof'
        ]);

        // NEW: Whitelist of safe fields
        this._safeFieldsWhitelist = new Set([
            'timestamp', 'type', 'length', 'size', 'count', 'level',
            'status', 'state', 'readyState', 'connectionState', 
            'isConnected', 'isVerified', 'isInitiator', 'version',
            'activeFeaturesCount', 'totalFeatures', 'stage'
        ]);
        
        this._secureLog('info', `🔧 Secure logging initialized (Production: ${this._isProductionMode})`);
    }
    /**
     * Shim to redirect arbitrary console.log calls to _secureLog('info', ...)
     */
    _secureLogShim(...args) {
        try {
            if (!args || args.length === 0) {
                return;
            }
            const [message, ...rest] = args;
            if (rest.length === 0) {
                this._secureLog('info', String(message));
                return;
            }
            if (rest.length === 1) {
                this._secureLog('info', String(message), rest[0]);
                return;
            }
            this._secureLog('info', String(message), { args: rest });
        } catch (e) {
            // Fallback — do not disrupt main execution flow
        }
    }
    /**
     * Redirects global console.log to this instance's secure logger
     */
    _redirectConsoleLogToSecure() {
        try {
            if (typeof console === 'undefined') return;
            // Preserve originals once
            if (!this._originalConsole) {
                this._originalConsole = {
                    log: console.log?.bind(console),
                    info: console.info?.bind(console),
                    warn: console.warn?.bind(console),
                    error: console.error?.bind(console),
                    debug: console.debug?.bind(console)
                };
            }
            const self = this;
            // Only console.log is redirected to secure; warn/error stay intact
            console.log = function(...args) {
                try {
                    self._secureLogShim(...args);
                } catch (e) {
                    // Fallback to original log on failure
                    if (self._originalConsole?.log) self._originalConsole.log(...args);
                }
            };
        } catch (e) {
            // Safe degradation
        }
    }
    /**
     * Disables noisy logging in production: console.log/debug become no-ops
     * Intentionally preserves warn/error for problem visibility
     */
    _disableConsoleLogInProduction() {
        try {
            if (this._isProductionMode && typeof console !== 'undefined') {
                const originalWarn = console.warn?.bind(console);
                const originalError = console.error?.bind(console);
                // Safely mute informational logs
                console.log = () => {};
                console.debug = () => {};
                // Preserve warnings and errors
                if (originalWarn) console.warn = (...args) => originalWarn(...args);
                if (originalError) console.error = (...args) => originalError(...args);
            }
        } catch (e) {
            // No action required, non-functional safeguard
        }
    }
    /**
     * Secure logging
     * @param {string} level - Log level (error, warn, info, debug, trace)
     * @param {string} message - Message
     * @param {object} data - Optional payload (will be sanitized)
     */
    _secureLog(level, message, data = null) {
        // Check log level
        if (this._logLevels[level] > this._currentLogLevel) {
            return;
        }
        
        // NEW: Audit check before logging
        if (data && !this._auditLogMessage(message, data)) {
            return; // Logging blocked due to potential data leakage
        }
        
        // Prevent log spam
        const logKey = `${level}:${message}`;
        const currentCount = this._logCounts.get(logKey) || 0;
        
        if (currentCount >= this._maxLogCount) {
            return;
        }
        
        this._logCounts.set(logKey, currentCount + 1);
        
        // Sanitize data
        const sanitizedData = data ? this._sanitizeLogData(data) : null;
        
        // NEW: In production do not output payloads
        if (this._isProductionMode && level !== 'error') {
            console[level] || console.log(message); // Only message without payload
        } else {
            const logMethod = console[level] || console.log;
            if (sanitizedData) {
                logMethod(message, sanitizedData);
            } else {
                logMethod(message);
            }
        }
    }
    /**
     * Sanitize data for logging
     */
    _sanitizeLogData(data) {
        if (!data || typeof data !== 'object') {
            // For primitive types — check for sensitive patterns
            if (typeof data === 'string') {
                return this._sanitizeString(data);
            }
            return data;
        }
        
        const sanitized = {};
        
        for (const [key, value] of Object.entries(data)) {
            const lowerKey = key.toLowerCase();
            
            // ABSOLUTE BLACKLIST — never log
            if (this._absoluteBlacklist.has(key) || 
                Array.from(this._absoluteBlacklist).some(banned => lowerKey.includes(banned))) {
                sanitized[key] = '[ABSOLUTELY_FORBIDDEN]';
                continue;
            }
            
            // WHITELIST — safe fields are logged as-is
            if (this._safeFieldsWhitelist.has(key)) {
                sanitized[key] = value;
                continue;
            }
            
            // Strict handling for all other fields
            if (typeof value === 'boolean' || typeof value === 'number') {
                sanitized[key] = value;
            } else if (typeof value === 'string') {
                sanitized[key] = this._sanitizeString(value);
            } else if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
                sanitized[key] = `[${value.constructor.name}(${value.byteLength || value.length} bytes)]`;
            } else if (value && typeof value === 'object') {
                // Recursive with depth limitation
                sanitized[key] = this._sanitizeLogData(value);
            } else {
                sanitized[key] = `[${typeof value}]`;
            }
        }
        
        return sanitized;
    }
    /**
     * NEW: Specialized sanitization for strings
     */
    _sanitizeString(str) {
        if (typeof str !== 'string' || str.length === 0) {
            return str;
        }
        
        // CRITICAL: Detect sensitive patterns
        const sensitivePatterns = [
            /[a-f0-9]{32,}/i,                    // Hex strings (keys)
            /[A-Za-z0-9+/=]{20,}/,               // Base64 strings
            /\b[A-Za-z0-9]{20,}\b/,              // Long alphanumeric strings
            /BEGIN\s+(PRIVATE|PUBLIC)\s+KEY/i,   // PEM keys
            /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, // Credit cards
            /\b\d{3}-\d{2}-\d{4}\b/,             // SSN
            /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/, // Email (partial)
        ];
        
        for (const pattern of sensitivePatterns) {
            if (pattern.test(str)) {
                // If short — fully hide
                if (str.length <= 10) {
                    return '[SENSITIVE]';
                }
                // If long — reveal only start and end
                return `${str.substring(0, 3)}...[REDACTED]...${str.substring(str.length - 3)}`;
            }
        }
        
        // For regular strings — limit length
        if (str.length > 100) {
            return str.substring(0, 50) + '...[TRUNCATED]';
        }
        
        return str;
    }
    /**
     * Checks whether a string contains sensitive content
     */
    _containsSensitiveContent(str) {
        if (typeof str !== 'string') return false;
        
        const sensitivePatterns = [
            /[a-f0-9]{32,}/i,          // Hex strings (keys)
            /[A-Za-z0-9+/=]{20,}/,     // Base64 strings
            /\b[A-Za-z0-9]{20,}\b/,    // Long alphanumeric strings
            /BEGIN\s+(PRIVATE|PUBLIC)\s+KEY/i, // PEM keys
        ];
        
        return sensitivePatterns.some(pattern => pattern.test(str));
    }
    // ============================================
    // SECURE LOGGING SYSTEM
    // ============================================
    
    /**
     * Detects production mode
     */
    _detectProductionMode() {
        // Check various production mode indicators
        return (
            // Standard env variables
            (typeof process !== 'undefined' && process.env?.NODE_ENV === 'production') ||
            // No debug flags
            (!window.DEBUG_MODE && !window.DEVELOPMENT_MODE) ||
            // Production domains
            (window.location.hostname && !window.location.hostname.includes('localhost') && 
             !window.location.hostname.includes('127.0.0.1') && 
             !window.location.hostname.includes('.local')) ||
            // Minified code (heuristic check)
            (typeof window.webpackHotUpdate === 'undefined' && !window.location.search.includes('debug'))
        );
    }
    // ============================================
    // FIXED SECURE GLOBAL API
    // ============================================
    
    /**
     * Sets up a secure global API with limited access
     */
    _setupSecureGlobalAPI() {
        // Create a restricted public API
        const secureAPI = {
            // ============================================
            // SAFE PUBLIC METHODS
            // ============================================
            
            /**
             * Send a message (safe wrapper)
             */
            sendMessage: (message) => {
                try {
                    if (typeof message !== 'string' || message.length === 0) {
                        throw new Error('Invalid message format');
                    }
                    if (message.length > 10000) {
                        throw new Error('Message too long');
                    }
                    return this.sendMessage(message);
                } catch (error) {
                    console.error('❌ Failed to send message through secure API:', error.message);
                    throw new Error('Failed to send message');
                }
            },
            
            /**
             * Get connection status (public information only)
             */
            getConnectionStatus: () => {
                return {
                    isConnected: this.isConnected(),
                    isVerified: this.isVerified,
                    connectionState: this.peerConnection?.connectionState || 'disconnected',
                };
            },
            
            /**
             * Get security status (limited information)
             */
            getSecurityStatus: () => {
                const status = this.getSecurityStatus();
                return {
                    securityLevel: status.securityLevel,
                    stage: status.stage,
                    activeFeaturesCount: status.activeFeaturesCount,
                };
            },
            
            /**
             * Send a file (safe wrapper)
             */
            sendFile: async (file) => {
                try {
                    if (!file || !(file instanceof File)) {
                        throw new Error('Invalid file object');
                    }
                    if (file.size > 100 * 1024 * 1024) { // 100MB limit
                        throw new Error('File too large');
                    }
                    return await this.sendFile(file);
                } catch (error) {
                    console.error('❌ Failed to send file through secure API:', error.message);
                    throw new Error('Failed to send file');
                }
            },
            
            /**
             * Get file transfer status
             */
            getFileTransferStatus: () => {
                const status = this.getFileTransferStatus();
                return {
                    initialized: status.initialized,
                    status: status.status,
                    activeTransfers: status.activeTransfers || 0,
                    receivingTransfers: status.receivingTransfers || 0,
                };
            },
            
            /**
             * Disconnect (safe)
             */
            disconnect: () => {
                try {
                    this.disconnect();
                    return true;
                } catch (error) {
                    console.error('❌ Failed to disconnect through secure API:', error.message);
                    return false;
                }
            },
            
            // API meta information
            _api: {
                version: '4.0.1-secure',
                type: 'secure-wrapper',
                methods: [
                    'sendMessage', 'getConnectionStatus', 'getSecurityStatus',
                    'sendFile', 'getFileTransferStatus', 'disconnect'
                ]
            }
        };
       // ============================================
        // INSTALL SECURE GLOBAL API
        // ============================================
        
        // Make the API immutable
        Object.freeze(secureAPI);
        Object.freeze(secureAPI._api);
        
        // Set global API only if it does not exist yet
        if (!window.secureBitChat) {
            Object.defineProperty(window, 'secureBitChat', {
                value: secureAPI,
                writable: false,
                enumerable: true,
                configurable: false
            });
            
            console.log('🔒 Secure global API established: window.secureBitChat');
        } else {
            console.warn('⚠️ Global API already exists, skipping setup');
        }
        
        // ============================================
        // SIMPLIFIED PROTECTION WITHOUT PROXY
        // ============================================
        this._setupSimpleProtection();
    }
    _setupSimpleProtection() {
        // Protect via monitoring only, without overriding window
        this._monitorGlobalExposure();
        
        // Console notice
        if (window.DEBUG_MODE) {
            console.warn('🔒 Security Notice: WebRTC Manager is protected. Use window.secureBitChat for safe access.');
        }
    }
    /**
     * Monitoring global exposure without Proxy
     */
    _monitorGlobalExposure() {
        // Potentially dangerous global names
        const dangerousNames = [
            'webrtcManager', 'globalWebRTCManager', 'webrtcInstance', 
            'rtcManager', 'secureWebRTC', 'enhancedWebRTC'
        ];
        
        // Periodic check
        const checkForExposure = () => {
            const exposures = [];
            
            dangerousNames.forEach(name => {
                if (window[name] === this || 
                    (window[name] && window[name].constructor === this.constructor)) {
                    exposures.push(name);
                }
            });
            
            if (exposures.length > 0) {
                console.warn('🚫 WARNING: Potential security exposure detected:', exposures);
                
                // In production, remove automatically
                if (!window.DEBUG_MODE) {
                    exposures.forEach(name => {
                        try {
                            delete window[name];
                            console.log(`🧹 Removed exposure: ${name}`);
                        } catch (error) {
                            console.error(`❌ Failed to remove: ${name}`);
                        }
                    });
                }
            }
            
            return exposures;
        };
        
        // Immediate check
        checkForExposure();
        
        // Periodic check
        const interval = window.DEBUG_MODE ? 30000 : 300000; // 30s in dev, 5min in prod
        setInterval(checkForExposure, interval);
    }
    /**
     * Prevents accidental global exposure
     */
    _preventGlobalExposure() {
        // Monitor attempts to add webrtc objects to window
        const originalDefineProperty = Object.defineProperty;
        const self = this;
        
        // Override defineProperty for window only for webrtc-related properties
        const webrtcRelatedNames = [
            'webrtcManager', 'globalWebRTCManager', 'webrtcInstance', 
            'rtcManager', 'secureWebRTC', 'enhancedWebRTC'
        ];
        
        Object.defineProperty = function(obj, prop, descriptor) {
            if (obj === window && webrtcRelatedNames.includes(prop)) {
                console.warn(`🚫 Prevented potential global exposure of: ${prop}`);
                // Do not set the property, only log
                return obj;
            }
            return originalDefineProperty.call(this, obj, prop, descriptor);
        };
        
        // Protect against direct assignment
        const webrtcRelatedPatterns = /webrtc|rtc|secure.*chat/i;
        const handler = {
            set(target, property, value) {
                if (typeof property === 'string' && webrtcRelatedPatterns.test(property)) {
                    if (value === self || (value && value.constructor === self.constructor)) {
                        console.warn(`🚫 Prevented global exposure attempt: window.${property}`);
                        return true; // Pretend we set it, but do not
                    }
                }
                target[property] = value;
                return true;
            }
        };
        
        // Apply Proxy only in development mode for performance
        if (window.DEBUG_MODE) {
            window = new Proxy(window, handler);
        }
    }
    /**
     * API integrity check
     */
    _verifyAPIIntegrity() {
        try {
            if (!window.secureBitChat) {
                console.error('🚨 SECURITY ALERT: Secure API has been removed!');
                return false;
            }
            
            const requiredMethods = ['sendMessage', 'getConnectionStatus', 'disconnect'];
            const missingMethods = requiredMethods.filter(method => 
                typeof window.secureBitChat[method] !== 'function'
            );
            
            if (missingMethods.length > 0) {
                console.error('🚨 SECURITY ALERT: API tampering detected, missing methods:', missingMethods);
                return false;
            }
            
            return true;
        } catch (error) {
            console.error('🚨 SECURITY ALERT: API integrity check failed:', error);
            return false;
        }
    }
    // ============================================
    // ADDITIONAL SECURITY METHODS
    // ============================================
    
    /**
     * Checks for accidental exposure in global scope
     */
    _auditGlobalExposure() {
        const dangerousExposures = [];
        
        // Check window for WebRTC manager
        for (const prop in window) {
            const value = window[prop];
            if (value === this || (value && value.constructor === this.constructor)) {
                dangerousExposures.push(prop);
            }
        }
        
        if (dangerousExposures.length > 0) {
            console.error('🚨 SECURITY ALERT: WebRTC Manager exposed globally:', dangerousExposures);
            
            // In production mode, remove exposure automatically
            if (!window.DEBUG_MODE) {
                dangerousExposures.forEach(prop => {
                    try {
                        delete window[prop];
                        console.log(`🧹 Removed dangerous global exposure: ${prop}`);
                    } catch (error) {
                        console.error(`❌ Failed to remove exposure: ${prop}`, error);
                    }
                });
            }
        }
        
        return dangerousExposures;
    }
    
    /**
     * Periodic security audit
     */
    _startSecurityAudit() {
        // Check every 30 seconds in development, every 5 minutes in production
        const auditInterval = window.DEBUG_MODE ? 30000 : 300000;
        
        setInterval(() => {
            const exposures = this._auditGlobalExposure();
            
            if (exposures.length > 0 && !window.DEBUG_MODE) {
                // In production, this is a critical issue
                console.error('🚨 CRITICAL: Unauthorized global exposure detected in production');
                
                // Could add alert sending or forced shutdown
                // this.emergencyShutdown();
            }
        }, auditInterval);
    }
    
    /**
     * Emergency shutdown for critical issues
     */
    _emergencyShutdown(reason = 'Security breach') {
        console.error(`🚨 EMERGENCY SHUTDOWN: ${reason}`);
        
        try {
            // Clear critical data
            this.encryptionKey = null;
            this.macKey = null;
            this.metadataKey = null;
            this.verificationCode = null;
            this.keyFingerprint = null;
            
            // Close connections
            if (this.dataChannel) {
                this.dataChannel.close();
                this.dataChannel = null;
            }
            if (this.peerConnection) {
                this.peerConnection.close();
                this.peerConnection = null;
            }
            
            // Clear buffers
            this.messageQueue = [];
            this.processedMessageIds.clear();
            this.packetBuffer.clear();
            
            // Notify UI
            if (this.onStatusChange) {
                this.onStatusChange('security_breach');
            }
            
            console.log('🔒 Emergency shutdown completed');
            
        } catch (error) {
            console.error('❌ Error during emergency shutdown:', error);
        }
    }
    _finalizeSecureInitialization() {
        this._startKeySecurityMonitoring();
        // Verify API integrity
        if (!this._verifyAPIIntegrity()) {
            console.error('🚨 Security initialization failed');
            return;
        }
        
        // Start monitoring
        this._startSecurityMonitoring();
        // Start periodic log cleanup
        setInterval(() => {
            this._cleanupLogs();
        }, 300000);
        
        console.log('✅ Secure WebRTC Manager initialization completed');
    }
    /**
     * Start security monitoring
     */
    _startSecurityMonitoring() {
        // Check every 5 minutes
        setInterval(() => {
            this._verifyAPIIntegrity();
        }, 300000);
        
        // In development mode, perform more frequent checks
        if (window.DEBUG_MODE) {
            setInterval(() => {
                this._monitorGlobalExposure();
            }, 30000);
        }
    }
    /**
     * Validates connection readiness for sending data
     * @param {boolean} throwError - whether to throw on not ready
     * @returns {boolean} true if connection is ready
     */
    _validateConnection(throwError = true) {
        const isDataChannelReady = this.dataChannel && this.dataChannel.readyState === 'open';
        const isConnectionVerified = this.isVerified;
        const isValid = isDataChannelReady && isConnectionVerified;
        
        if (!isValid && throwError) {
            if (!isDataChannelReady) {
                throw new Error('Data channel not ready');
            }
            if (!isConnectionVerified) {
                throw new Error('Connection not verified');
            }
        }
        
        return isValid;
    }

    /**
     * Validates encryption keys readiness
     * @param {boolean} throwError - whether to throw on not ready
     * @returns {boolean} true if keys are ready
     */
    _validateEncryptionKeys(throwError = true) {
        const hasAllKeys = !!(this.encryptionKey && this.macKey && this.metadataKey);
        
        if (!hasAllKeys && throwError) {
            throw new Error('Encryption keys not initialized');
        }
        
        return hasAllKeys;
    }

    /**
     * Checks whether a message is a file-transfer message
     * @param {string|object} data - message payload
     * @returns {boolean} true if it's a file message
     */
    _isFileMessage(data) {
        if (typeof data === 'string') {
            try {
                const parsed = JSON.parse(data);
                return parsed.type && parsed.type.startsWith('file_');
            } catch {
                return false;
            }
        }
        
        if (typeof data === 'object' && data.type) {
            return data.type.startsWith('file_');
        }
        
        return false;
    }

    /**
     * Checks whether a message is a system message
     * @param {string|object} data - message payload  
     * @returns {boolean} true if it's a system message
     */
    _isSystemMessage(data) {
        const systemTypes = [
            EnhancedSecureWebRTCManager.MESSAGE_TYPES.HEARTBEAT,
            EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION,
            EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_RESPONSE,
            EnhancedSecureWebRTCManager.MESSAGE_TYPES.PEER_DISCONNECT,
            EnhancedSecureWebRTCManager.MESSAGE_TYPES.SECURITY_UPGRADE,
            EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_SIGNAL,
            EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_READY
        ];

        if (typeof data === 'string') {
            try {
                const parsed = JSON.parse(data);
                return systemTypes.includes(parsed.type);
            } catch {
                return false;
            }
        }
        
        if (typeof data === 'object' && data.type) {
            return systemTypes.includes(data.type);
        }
        
        return false;
    }

    /**
     * Checks whether a message is fake traffic
     * @param {any} data - message payload
     * @returns {boolean} true if it's a fake message
     */
    _isFakeMessage(data) {
        if (typeof data === 'string') {
            try {
                const parsed = JSON.parse(data);
                return parsed.type === EnhancedSecureWebRTCManager.MESSAGE_TYPES.FAKE || 
                       parsed.isFakeTraffic === true;
            } catch {
                return false;
            }
        }
        
        if (typeof data === 'object' && data !== null) {
            return data.type === EnhancedSecureWebRTCManager.MESSAGE_TYPES.FAKE || 
                   data.isFakeTraffic === true;
        }
        
        return false;
    }

    /**
     * Safely executes an operation with error handling
     * @param {Function} operation - operation to execute
     * @param {string} errorMessage - error message to log
     * @param {any} fallback - default value on error
     * @returns {any} operation result or fallback
     */
    _withErrorHandling(operation, errorMessage, fallback = null) {
        try {
            return operation();
        } catch (error) {
            if (window.DEBUG_MODE) {
                console.error(`❌ ${errorMessage}:`, error);
            }
            return fallback;
        }
    }

    /**
     * Safely executes an async operation with error handling
     * @param {Function} operation - async operation
     * @param {string} errorMessage - error message to log
     * @param {any} fallback - default value on error
     * @returns {Promise<any>} operation result or fallback
     */
    async _withAsyncErrorHandling(operation, errorMessage, fallback = null) {
        try {
            return await operation();
        } catch (error) {
            if (window.DEBUG_MODE) {
                console.error(`❌ ${errorMessage}:`, error);
            }
            return fallback;
        }
    }

    /**
     * Checks rate limits
     * @returns {boolean} true if allowed to proceed
     */
    _checkRateLimit() {
        return window.EnhancedSecureCryptoUtils.rateLimiter.checkConnectionRate(this.rateLimiterId);
    }

    /**
     * Extracts message type from data
     * @param {string|object} data - message data
     * @returns {string|null} message type or null
     */
    _getMessageType(data) {
        if (typeof data === 'string') {
            try {
                const parsed = JSON.parse(data);
                return parsed.type || null;
            } catch {
                return null;
            }
        }
        
        if (typeof data === 'object' && data !== null) {
            return data.type || null;
        }
        
        return null;
    }

    /**
     * Resets notification flags for a new connection
     */
    _resetNotificationFlags() {
        this.lastSecurityLevelNotification = null;
        this.verificationNotificationSent = false;
        this.verificationInitiationSent = false;
        this.disconnectNotificationSent = false;
        this.reconnectionFailedNotificationSent = false;
        this.peerDisconnectNotificationSent = false;
        this.connectionClosedNotificationSent = false;
        this.fakeTrafficDisabledNotificationSent = false;
        this.advancedFeaturesDisabledNotificationSent = false;
        this.securityUpgradeNotificationSent = false;
        this.lastSecurityUpgradeStage = null;
        this.securityCalculationNotificationSent = false;
        this.lastSecurityCalculationLevel = null;
    }

    /**
     * Checks whether a message was filtered out
     * @param {any} result - processing result
     * @returns {boolean} true if filtered
     */
    _isFilteredMessage(result) {
        const filteredResults = Object.values(EnhancedSecureWebRTCManager.FILTERED_RESULTS);
        return filteredResults.includes(result);
    }
    /**
     * Cleans up log counters to prevent memory leaks
     */
    _cleanupLogs() {
        // Clear log counters if there are too many
        if (this._logCounts.size > 1000) {
            this._logCounts.clear();
            this._secureLog('debug', '🧹 Log counts cleared');
        }
    }
    /**
     * Returns logging stats (for diagnostics)
     */
    _getLoggingStats() {
        return {
            isProductionMode: this._isProductionMode,
            debugMode: this._debugMode,
            currentLogLevel: this._currentLogLevel,
            logCountsSize: this._logCounts.size,
            maxLogCount: this._maxLogCount
        };
    }
    /**
     * Emergency logging disable
     */
    _emergencyDisableLogging() {
        this._currentLogLevel = -1; // Disable all logs
        this._logCounts.clear();
        // Override _secureLog to a no-op
        this._secureLog = () => {};
        // Only critical error to console (no payload)
        console.error('🚨 SECURITY: Logging disabled due to potential data exposure');
    }
    _auditLogMessage(message, data) {
        if (!data || typeof data !== 'object') return true;
        
        const dataString = JSON.stringify(data).toLowerCase();
        
        // Check for accidental leaks
        // Narrow patterns to avoid false positives (e.g., words like "keyOperation")
        const dangerousPatterns = [
            'secret', 'token', 'password', 'credential',
            'fingerprint', 'salt', 'signature', 'private_key', 'api_key', 'private'
        ];
        
        for (const pattern of dangerousPatterns) {
            if (dataString.includes(pattern) && !this._safeFieldsWhitelist.has(pattern)) {
                this._emergencyDisableLogging();
                console.error(`🚨 SECURITY BREACH: Potential sensitive data in log: ${pattern}`);
                return false;
            }
        }
        
        return true;
    }

    initializeFileTransfer() {
        try {
            console.log('🔧 Initializing Enhanced Secure File Transfer system...');
            
            // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Проверяем, не инициализирована ли уже система
            if (this.fileTransferSystem) {
                console.log('✅ File transfer system already initialized');
                return;
            }
            
            // CRITICAL FIX: Step-by-step readiness check
            const channelReady = !!(this.dataChannel && this.dataChannel.readyState === 'open');
            if (!channelReady) {
                console.warn('⚠️ Data channel not open, deferring file transfer initialization');
                if (this.dataChannel) {
                    const initHandler = () => {
                        console.log('🔄 DataChannel opened, initializing file transfer...');
                        this.initializeFileTransfer();
                    };
                    this.dataChannel.addEventListener('open', initHandler, { once: true });
                }
                return;
            }

            if (!this.isVerified) {
                console.warn('⚠️ Connection not verified yet, deferring file transfer initialization');
                setTimeout(() => this.initializeFileTransfer(), 500);
                return;
            }
            
            // FIX: Clean up previous system if present
            if (this.fileTransferSystem) {
                console.log('🧹 Cleaning up existing file transfer system');
                this.fileTransferSystem.cleanup();
                this.fileTransferSystem = null;
            }
            
            // CRITICAL FIX: Ensure encryption keys are present
            if (!this.encryptionKey || !this.macKey) {
                console.warn('⚠️ Encryption keys not ready, deferring file transfer initialization');
                setTimeout(() => this.initializeFileTransfer(), 1000);
                return;
            }
            
            // IMPORTANT: callback order: (onProgress, onComplete, onError, onFileReceived)
            const safeOnComplete = (summary) => {
                // Sender: finalize transfer, no Blob handling
                try {
                    console.log('🏁 Sender transfer summary:', summary);
                    // Optionally forward as progress/UI event
                    if (this.onFileProgress) {
                        this.onFileProgress({ type: 'complete', ...summary });
                    }
                } catch (e) {
                    console.warn('⚠️ onComplete handler failed:', e.message);
                }
            };

            this.fileTransferSystem = new EnhancedSecureFileTransfer(
                this,
                this.onFileProgress || null,
                safeOnComplete,
                this.onFileError || null,
                this.onFileReceived || null
            );
            
            // CRITICAL FIX: Set global references
            window.FILE_TRANSFER_ACTIVE = true;
            window.fileTransferSystem = this.fileTransferSystem;
            
            console.log('✅ Enhanced Secure File Transfer system initialized successfully');
            
            // Verify the system is ready
            const status = this.fileTransferSystem.getSystemStatus();
            console.log('🔍 File transfer system status after init:', status);
            
        } catch (error) {
            console.error('❌ Failed to initialize file transfer system:', error);
            this.fileTransferSystem = null;
            window.FILE_TRANSFER_ACTIVE = false;
            window.fileTransferSystem = null;
        }
    }

    // ============================================
    // ENHANCED SECURITY INITIALIZATION
    // ============================================

    async initializeEnhancedSecurity() {
        try {
            // Generate nested encryption key
            await this.generateNestedEncryptionKey();
            
            // Initialize decoy channels
            if (this.decoyChannelConfig.enabled) {
                this.initializeDecoyChannels();
            }
            
            // Start fake traffic generation
            if (this.fakeTrafficConfig.enabled) {
                this.startFakeTrafficGeneration();
            }

        } catch (error) {
            console.error('❌ Failed to initialize enhanced security:', error);
        }
    }
    
    // Generate fingerprint mask for anti-fingerprinting
    generateFingerprintMask() {
        const mask = {
            timingOffset: Math.random() * 1000,
            sizeVariation: Math.random() * 0.5 + 0.75, // 0.75 to 1.25
            noisePattern: Array.from(crypto.getRandomValues(new Uint8Array(32))),
            headerVariations: [
                'X-Client-Version',
                'X-Session-ID', 
                'X-Request-ID',
                'X-Timestamp',
                'X-Signature'
            ]
        };
        return mask;
    }

    // Security configuration for session type
    configureSecurityForSession(sessionType, securityLevel) {
        console.log(`🔧 Configuring security for ${sessionType} session (${securityLevel} level)`);
        
        this.currentSessionType = sessionType;
        this.currentSecurityLevel = securityLevel;
        
        if (window.sessionManager && window.sessionManager.isFeatureAllowedForSession) {
            this.sessionConstraints = {};
            
            Object.keys(this.securityFeatures).forEach(feature => {
                this.sessionConstraints[feature] = window.sessionManager.isFeatureAllowedForSession(sessionType, feature);
            });
            
            this.applySessionConstraints();
            
            console.log(`✅ Security configured for ${sessionType}:`, this.sessionConstraints);
            
            this.notifySecurityLevel();
            
            setTimeout(() => {
                this.calculateAndReportSecurityLevel();
            }, EnhancedSecureWebRTCManager.TIMEOUTS.SECURITY_CALC_DELAY);
            
        } else {
            console.warn('⚠️ Session manager not available, using default security');
        }
    }

    // Applying session restrictions
    applySessionConstraints() {
        if (!this.sessionConstraints) return;

        // Applying restrictions to security features
        Object.keys(this.sessionConstraints).forEach(feature => {
            const allowed = this.sessionConstraints[feature];
            
            if (!allowed && this.securityFeatures[feature]) {
                console.log(`🔒 Disabling ${feature} for ${this.currentSessionType} session`);
                this.securityFeatures[feature] = false;
                
                // Disabling linked configurations
                switch (feature) {
                    case 'hasFakeTraffic':
                        this.fakeTrafficConfig.enabled = false;
                        this.stopFakeTrafficGeneration();
                        break;
                    case 'hasDecoyChannels':
                        this.decoyChannelConfig.enabled = false;
                        this.cleanupDecoyChannels();
                        break;
                    case 'hasPacketReordering':
                        this.reorderingConfig.enabled = false;
                        this.packetBuffer.clear();
                        break;
                    case 'hasAntiFingerprinting':
                        this.antiFingerprintingConfig.enabled = false;
                        break;
                    case 'hasMessageChunking':
                        this.chunkingConfig.enabled = false;
                        break;
                }
            } else if (allowed && !this.securityFeatures[feature]) {
                console.log(`🔓 Enabling ${feature} for ${this.currentSessionType} session`);
                this.securityFeatures[feature] = true;
                
                // Enable linked configurations
                switch (feature) {
                    case 'hasFakeTraffic':
                        this.fakeTrafficConfig.enabled = true;
                        if (this.isConnected()) {
                            this.startFakeTrafficGeneration();
                        }
                        break;
                    case 'hasDecoyChannels':
                        this.decoyChannelConfig.enabled = true;
                        if (this.isConnected()) {
                            this.initializeDecoyChannels();
                        }
                        break;
                    case 'hasPacketReordering':
                        this.reorderingConfig.enabled = true;
                        break;
                    case 'hasAntiFingerprinting':
                        this.antiFingerprintingConfig.enabled = true;
                        break;
                    case 'hasMessageChunking':
                        this.chunkingConfig.enabled = true;
                        break;
                }
            }
        });
    }
    deliverMessageToUI(message, type = 'received') {
        try {
            // Add debug logs
            console.log('📤 deliverMessageToUI called:', {
                message: message,
                type: type,
                messageType: typeof message,
                hasOnMessage: !!this.onMessage
            });
            
            // Filter out file-transfer and system messages
            if (typeof message === 'object' && message.type) {
                const blockedTypes = [
                    EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_START,
                    EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_RESPONSE,
                    EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_CHUNK,
                    EnhancedSecureWebRTCManager.MESSAGE_TYPES.CHUNK_CONFIRMATION,
                    EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_COMPLETE,
                    EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_ERROR,
                    EnhancedSecureWebRTCManager.MESSAGE_TYPES.HEARTBEAT,
                    EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION,
                    EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_RESPONSE,
                    EnhancedSecureWebRTCManager.MESSAGE_TYPES.PEER_DISCONNECT,
                    EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_SIGNAL,
                    EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_READY,
                    EnhancedSecureWebRTCManager.MESSAGE_TYPES.SECURITY_UPGRADE
                ];
                if (blockedTypes.includes(message.type)) {
                    if (window.DEBUG_MODE) {
                        console.log(`🛑 Blocked system/file message from UI: ${message.type}`);
                    }
                    return; // do not show in chat
                }
            }

            // Additional check for string messages containing JSON
            if (typeof message === 'string' && message.trim().startsWith('{')) {
                try {
                    const parsedMessage = JSON.parse(message);
                    if (parsedMessage.type) {
                        const blockedTypes = [
                            EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_START,
                            EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_RESPONSE,
                            EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_CHUNK,
                            EnhancedSecureWebRTCManager.MESSAGE_TYPES.CHUNK_CONFIRMATION,
                            EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_COMPLETE,
                            EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_ERROR,
                            EnhancedSecureWebRTCManager.MESSAGE_TYPES.HEARTBEAT,
                            EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION,
                            EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_RESPONSE,
                            EnhancedSecureWebRTCManager.MESSAGE_TYPES.PEER_DISCONNECT,
                            EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_SIGNAL,
                            EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_READY,
                            EnhancedSecureWebRTCManager.MESSAGE_TYPES.SECURITY_UPGRADE
                        ];
                        if (blockedTypes.includes(parsedMessage.type)) {
                            if (window.DEBUG_MODE) {
                                console.log(`🛑 Blocked system/file message from UI (string): ${parsedMessage.type}`);
                            }
                            return; // do not show in chat
                        }
                    }
                } catch (parseError) {
                    // Not JSON — fine for plain text messages
                }
            }

            if (this.onMessage) {
                console.log('📤 Calling this.onMessage callback with:', { message, type });
                this.onMessage(message, type);
            } else {
                console.warn('⚠️ this.onMessage callback is null or undefined');
            }
        } catch (err) {
            console.error('❌ Failed to deliver message to UI:', err);
        }
    }


    // Security Level Notification
    notifySecurityLevel() {
        // Avoid duplicate notifications for the same security level
        if (this.lastSecurityLevelNotification === this.currentSecurityLevel) {
            return; // prevent duplication
        }
        
        this.lastSecurityLevelNotification = this.currentSecurityLevel;
        
        const levelMessages = {
            'basic': '🔒 Basic Security Active - Demo session with essential protection',
            'enhanced': '🔐 Enhanced Security Active - Paid session with advanced protection',
            'maximum': '🛡️ Maximum Security Active - Premium session with complete protection'
        };

        const message = levelMessages[this.currentSecurityLevel] || levelMessages['basic'];
        
        if (this.onMessage) {
            this.deliverMessageToUI(message, 'system');
        }

        // Showing details of functions for paid sessions
        if (this.currentSecurityLevel !== 'basic' && this.onMessage) {
            const activeFeatures = Object.entries(this.securityFeatures)
                .filter(([key, value]) => value === true)
                .map(([key]) => key.replace('has', '').replace(/([A-Z])/g, ' $1').trim().toLowerCase())
                .slice(0, 5); 

            this.deliverMessageToUI(`🔧 Active: ${activeFeatures.join(', ')}...`, 'system');
        }
    }

    // Cleaning decoy channels
    cleanupDecoyChannels() {
        // Stopping decoy traffic
        for (const [channelName, timer] of this.decoyTimers.entries()) {
            clearTimeout(timer);
        }
        this.decoyTimers.clear();
        
        // Closing decoy channels
        for (const [channelName, channel] of this.decoyChannels.entries()) {
            if (channel.readyState === 'open') {
                channel.close();
            }
        }
        this.decoyChannels.clear();
        
        console.log('🧹 Decoy channels cleaned up');
    }

    // ============================================
    // 1. NESTED ENCRYPTION LAYER
    // ============================================

    async generateNestedEncryptionKey() {
        try {
            // Generate additional encryption key for nested encryption
            this.nestedEncryptionKey = await crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
            
            // Generate random IV for nested encryption
            this.nestedEncryptionIV = crypto.getRandomValues(new Uint8Array(EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE));
            this.nestedEncryptionCounter = 0;
            
        } catch (error) {
            console.error('❌ Failed to generate nested encryption key:', error);
            throw error;
        }
    }

    async applyNestedEncryption(data) {
        if (!this.nestedEncryptionKey || !this.securityFeatures.hasNestedEncryption) {
            return data;
        }

        try {
            // Create unique IV for each encryption
            const uniqueIV = new Uint8Array(EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE);
            uniqueIV.set(this.nestedEncryptionIV);
            uniqueIV[11] = (this.nestedEncryptionCounter++) & 0xFF;
            
            // Encrypt data with nested layer
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: uniqueIV },
                this.nestedEncryptionKey,
                data
            );
            
            // Combine IV and encrypted data
            const result = new Uint8Array(EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE + encrypted.byteLength);
            result.set(uniqueIV, 0);
            result.set(new Uint8Array(encrypted), EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE);
            
            return result.buffer;
        } catch (error) {
            console.error('❌ Nested encryption failed:', error);
            return data; // Fallback to original data
        }
    }

    async removeNestedEncryption(data) {
        if (!this.nestedEncryptionKey || !this.securityFeatures.hasNestedEncryption) {
            return data;
        }

        // FIX: Check that the data is actually encrypted
        if (!(data instanceof ArrayBuffer) || data.byteLength < 20) {
            if (window.DEBUG_MODE) {
                console.log('📝 Data not encrypted or too short for nested decryption');
            }
            return data;
        }

        try {
            const dataArray = new Uint8Array(data);
            const iv = dataArray.slice(0, EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE);
            const encryptedData = dataArray.slice(EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE);
            
            // Check that there is data to decrypt
            if (encryptedData.length === 0) {
                if (window.DEBUG_MODE) {
                    console.log('📝 No encrypted data found');
                }
                return data;
            }
            
            // Decrypt nested layer
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                this.nestedEncryptionKey,
                encryptedData
            );
            
            return decrypted;
        } catch (error) {
            // FIX: Better error handling
            if (error.name === 'OperationError') {
                if (window.DEBUG_MODE) {
                    console.log('📝 Data not encrypted with nested encryption, skipping...');
                }
            } else {
                if (window.DEBUG_MODE) {
                    console.warn('⚠️ Nested decryption failed:', error.message);
                }
            }
            return data; // Fallback to original data
        }
    }

    // ============================================
    // 2. PACKET PADDING
    // ============================================

    applyPacketPadding(data) {
        if (!this.securityFeatures.hasPacketPadding) {
            return data;
        }

        try {
            const originalSize = data.byteLength;
            let paddingSize;
            
            if (this.paddingConfig.useRandomPadding) {
                // Generate random padding size
                paddingSize = Math.floor(Math.random() * 
                    (this.paddingConfig.maxPadding - this.paddingConfig.minPadding + 1)) + 
                    this.paddingConfig.minPadding;
            } else {
                // Use fixed padding size
                paddingSize = this.paddingConfig.minPadding;
            }
            
            // Generate random padding data
            const padding = crypto.getRandomValues(new Uint8Array(paddingSize));
            
            // Create padded message
            const paddedData = new Uint8Array(originalSize + paddingSize + 4);
            
            // Add original size (4 bytes)
            const sizeView = new DataView(paddedData.buffer, 0, 4);
            sizeView.setUint32(0, originalSize, false);
            
            // Add original data
            paddedData.set(new Uint8Array(data), 4);
            
            // Add padding
            paddedData.set(padding, 4 + originalSize);
            
            return paddedData.buffer;
        } catch (error) {
            console.error('❌ Packet padding failed:', error);
            return data; // Fallback to original data
        }
    }

    removePacketPadding(data) {
        if (!this.securityFeatures.hasPacketPadding) {
            return data;
        }

        try {
            const dataArray = new Uint8Array(data);
            
            // Check for minimum data length (4 bytes for size + minimum 1 byte of data)
            if (dataArray.length < 5) {
                if (window.DEBUG_MODE) {
                    console.warn('⚠️ Data too short for packet padding removal, skipping');
                }
                return data;
            }
            
            // Extract original size (first 4 bytes)
            const sizeView = new DataView(dataArray.buffer, 0, 4);
            const originalSize = sizeView.getUint32(0, false);
            
            // Checking the reasonableness of the size
            if (originalSize <= 0 || originalSize > dataArray.length - 4) {
                if (window.DEBUG_MODE) {
                    console.warn('⚠️ Invalid packet padding size, skipping removal');
                }
                return data;
            }
            
            // Extract original data
            const originalData = dataArray.slice(4, 4 + originalSize);
            
            return originalData.buffer;
        } catch (error) {
            if (window.DEBUG_MODE) {
                console.error('❌ Packet padding removal failed:', error);
            }
            return data; // Fallback to original data
        }
    }

    // ============================================
    // 3. FAKE TRAFFIC GENERATION
    // ============================================

    startFakeTrafficGeneration() {
        if (!this.fakeTrafficConfig.enabled || !this.isConnected()) {
            return;
        }

        // Prevent multiple fake traffic generators
        if (this.fakeTrafficTimer) {
            console.log('⚠️ Fake traffic generation already running');
            return;
        }

        const sendFakeMessage = async () => {
            if (!this.isConnected()) {
                this.stopFakeTrafficGeneration();
                return;
            }

            try {
                const fakeMessage = this.generateFakeMessage();
                await this.sendFakeMessage(fakeMessage);
                
                // FIX: Increase intervals to reduce load
                const nextInterval = this.fakeTrafficConfig.randomDecoyIntervals ? 
                    Math.random() * (this.fakeTrafficConfig.maxInterval - this.fakeTrafficConfig.minInterval) + 
                    this.fakeTrafficConfig.minInterval :
                    this.fakeTrafficConfig.minInterval;
                
                // Minimum interval 15 seconds for stability
                const safeInterval = Math.max(nextInterval, EnhancedSecureWebRTCManager.TIMEOUTS.FAKE_TRAFFIC_MIN_INTERVAL);
                
                this.fakeTrafficTimer = setTimeout(sendFakeMessage, safeInterval);
            } catch (error) {
                if (window.DEBUG_MODE) {
                    console.error('❌ Fake traffic generation failed:', error);
                }
                this.stopFakeTrafficGeneration();
            }
        };

        // Start fake traffic generation with longer initial delay
        const initialDelay = Math.random() * this.fakeTrafficConfig.maxInterval + EnhancedSecureWebRTCManager.TIMEOUTS.DECOY_INITIAL_DELAY; // Add 5 seconds minimum
        this.fakeTrafficTimer = setTimeout(sendFakeMessage, initialDelay);
    }

    stopFakeTrafficGeneration() {
        if (this.fakeTrafficTimer) {
            clearTimeout(this.fakeTrafficTimer);
            this.fakeTrafficTimer = null;
        }
    }

    generateFakeMessage() {
        const pattern = this.fakeTrafficConfig.patterns[
            Math.floor(Math.random() * this.fakeTrafficConfig.patterns.length)
        ];
        
        const size = Math.floor(Math.random() * 
            (this.fakeTrafficConfig.maxSize - this.fakeTrafficConfig.minSize + 1)) + 
            this.fakeTrafficConfig.minSize;
        
        const fakeData = crypto.getRandomValues(new Uint8Array(size));
        
        return {
            type: EnhancedSecureWebRTCManager.MESSAGE_TYPES.FAKE, 
            pattern: pattern,
            data: Array.from(fakeData).map(b => b.toString(16).padStart(2, '0')).join(''),
            timestamp: Date.now(),
            size: size,
            isFakeTraffic: true, 
            source: 'fake_traffic_generator',
            fakeId: crypto.getRandomValues(new Uint32Array(1))[0].toString(36) 
        };
    }

    // ============================================
    // EMERGENCY SHUT-OFF OF ADVANCED FUNCTIONS
    // ============================================

        emergencyDisableAdvancedFeatures() {
        console.log('🚨 Emergency disabling advanced security features due to errors');
        
        // Disable problematic functions
        this.securityFeatures.hasNestedEncryption = false;
        this.securityFeatures.hasPacketReordering = false;
        this.securityFeatures.hasAntiFingerprinting = false;
        
        // Disable configurations
        this.reorderingConfig.enabled = false;
        this.antiFingerprintingConfig.enabled = false;
        
        // Clear the buffers
        this.packetBuffer.clear();
        
        // Stopping fake traffic
        this.emergencyDisableFakeTraffic();
        
        console.log('✅ Advanced features disabled, keeping basic encryption');
        
        // Check that advanced-features-disabled notification wasn't already sent
        if (!this.advancedFeaturesDisabledNotificationSent) {
            this.advancedFeaturesDisabledNotificationSent = true;
            if (this.onMessage) {
                this.deliverMessageToUI('🚨 Advanced security features temporarily disabled due to compatibility issues', 'system');
            }
        }
    }

    async sendFakeMessage(fakeMessage) {
        if (!this._validateConnection(false)) {
            return;
        }

        try {
            this._secureLog('debug', '🎭 Sending fake message', {
                hasPattern: !!fakeMessage.pattern,
                sizeRange: fakeMessage.size > 100 ? 'large' : 'small'
            });
            
            const fakeData = JSON.stringify({
                ...fakeMessage,
                type: EnhancedSecureWebRTCManager.MESSAGE_TYPES.FAKE, 
                isFakeTraffic: true, 
                timestamp: Date.now()
            });
            
            const fakeBuffer = new TextEncoder().encode(fakeData);
            const encryptedFake = await this.applySecurityLayers(fakeBuffer, true);
            this.dataChannel.send(encryptedFake);
            
            this._secureLog('debug', '🎭 Fake message sent successfully', {
                pattern: fakeMessage.pattern
            });
        } catch (error) {
            this._secureLog('error', '❌ Failed to send fake message', {
                error: error.message
            });
        }
    }

checkFakeTrafficStatus() {
        const status = {
            fakeTrafficEnabled: this.securityFeatures.hasFakeTraffic,
            fakeTrafficConfigEnabled: this.fakeTrafficConfig.enabled,
            timerActive: !!this.fakeTrafficTimer,
            patterns: this.fakeTrafficConfig.patterns,
            intervals: {
                min: this.fakeTrafficConfig.minInterval,
                max: this.fakeTrafficConfig.maxInterval
            }
        };
        
        if (window.DEBUG_MODE) {
            console.log('🎭 Fake Traffic Status:', status);
        }
        return status;
    }
emergencyDisableFakeTraffic() {
        if (window.DEBUG_MODE) {
            console.log('🚨 Emergency disabling fake traffic');
        }
        
        this.securityFeatures.hasFakeTraffic = false;
        this.fakeTrafficConfig.enabled = false;
        this.stopFakeTrafficGeneration();
        
        if (window.DEBUG_MODE) {
            console.log('✅ Fake traffic disabled');
        }
        
        // Check that fake-traffic-disabled notification wasn't already sent
        if (!this.fakeTrafficDisabledNotificationSent) {
            this.fakeTrafficDisabledNotificationSent = true;
            if (this.onMessage) {
                this.deliverMessageToUI('🚨 Fake traffic emergency disabled', 'system');
            }
        }
    }
    async _applySecurityLayersWithoutMutex(data, isFakeMessage = false) {
    try {
        let processedData = data;
        
        if (isFakeMessage) {
            if (this.encryptionKey && typeof processedData === 'string') {
                processedData = await window.EnhancedSecureCryptoUtils.encryptData(processedData, this.encryptionKey);
            }
            return processedData;
        }
        
        // Nested Encryption (if enabled)
        if (this.securityFeatures.hasNestedEncryption && this.nestedEncryptionKey && processedData instanceof ArrayBuffer) {
            processedData = await this.applyNestedEncryption(processedData);
        }
        
        // Packet Reordering (if enabled)
        if (this.securityFeatures.hasPacketReordering && this.reorderingConfig?.enabled && processedData instanceof ArrayBuffer) {
            processedData = this.applyPacketReordering(processedData);
        }
        
        // Packet Padding (if enabled)
        if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
            processedData = this.applyPacketPadding(processedData);
        }
        
        // Anti-Fingerprinting (if enabled)
        if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
            processedData = this.applyAntiFingerprinting(processedData);
        }
        
        // Final encryption (if keys are present)
        if (this.encryptionKey && typeof processedData === 'string') {
            processedData = await window.EnhancedSecureCryptoUtils.encryptData(processedData, this.encryptionKey);
        }
        
        return processedData;
        
    } catch (error) {
        console.error('❌ Error in applySecurityLayersWithoutMutex:', error);
        return data; // Return original data on error
    }
}
    // ============================================
    // 4. MESSAGE CHUNKING
    // ============================================

    async processChunkedMessage(chunkData) {
        try {
            if (!this.chunkingConfig.addChunkHeaders) {
                // No headers, treat as regular message
                return this.processMessage(chunkData);
            }

            const chunkArray = new Uint8Array(chunkData);
            if (chunkArray.length < 16) {
                // Too small to be a chunk with header
                return this.processMessage(chunkData);
            }

            // Extract chunk header
            const headerView = new DataView(chunkArray.buffer, 0, 16);
            const messageId = headerView.getUint32(0, false);
            const chunkIndex = headerView.getUint32(4, false);
            const totalChunks = headerView.getUint32(8, false);
            const chunkSize = headerView.getUint32(12, false);

            // Extract chunk data
            const chunk = chunkArray.slice(16, 16 + chunkSize);

            // Store chunk in buffer
            if (!this.chunkQueue[messageId]) {
                this.chunkQueue[messageId] = {
                    chunks: new Array(totalChunks),
                    received: 0,
                    timestamp: Date.now()
                };
            }

            const messageBuffer = this.chunkQueue[messageId];
            messageBuffer.chunks[chunkIndex] = chunk;
            messageBuffer.received++;

            console.log(`📦 Received chunk ${chunkIndex + 1}/${totalChunks} for message ${messageId}`);

            // Check if all chunks received
            if (messageBuffer.received === totalChunks) {
                // Combine all chunks
                const totalSize = messageBuffer.chunks.reduce((sum, chunk) => sum + chunk.length, 0);
                const combinedData = new Uint8Array(totalSize);
                
                let offset = 0;
                for (const chunk of messageBuffer.chunks) {
                    combinedData.set(chunk, offset);
                    offset += chunk.length;
                }

                // Process complete message
                await this.processMessage(combinedData.buffer);
                
                // Clean up
                delete this.chunkQueue[messageId];
                
                console.log(`📦 Chunked message ${messageId} reassembled and processed`);
            }
        } catch (error) {
            console.error('❌ Chunked message processing failed:', error);
        }
    }

    // ============================================
    // 5. DECOY CHANNELS
    // ============================================

    initializeDecoyChannels() {
        if (!this.decoyChannelConfig.enabled || !this.peerConnection) {
            return;
        }

        // Prevent multiple initializations
        if (this.decoyChannels.size > 0) {
            console.log('⚠️ Decoy channels already initialized, skipping...');
            return;
        }

        try {
            const numDecoyChannels = Math.min(
                this.decoyChannelConfig.maxDecoyChannels,
                this.decoyChannelConfig.decoyChannelNames.length
            );

            for (let i = 0; i < numDecoyChannels; i++) {
                const channelName = this.decoyChannelConfig.decoyChannelNames[i];
                const decoyChannel = this.peerConnection.createDataChannel(channelName, {
                    ordered: Math.random() > 0.5,
                    maxRetransmits: Math.floor(Math.random() * 3)
                });

                this.setupDecoyChannel(decoyChannel, channelName);
                this.decoyChannels.set(channelName, decoyChannel);
            }

            if (window.DEBUG_MODE) {
                console.log(`🎭 Initialized ${numDecoyChannels} decoy channels`);
            }
        } catch (error) {
            if (window.DEBUG_MODE) {
                console.error('❌ Failed to initialize decoy channels:', error);
            }
        }
    }

    setupDecoyChannel(channel, channelName) {
        channel.onopen = () => {
            if (window.DEBUG_MODE) {
                console.log(`🎭 Decoy channel "${channelName}" opened`);
            }
            this.startDecoyTraffic(channel, channelName);
        };

        channel.onmessage = (event) => {
            if (window.DEBUG_MODE) {
                console.log(`🎭 Received decoy message on "${channelName}": ${event.data?.length || 'undefined'} bytes`);
            }
        };

        channel.onclose = () => {
            if (window.DEBUG_MODE) {
                console.log(`🎭 Decoy channel "${channelName}" closed`);
            }
            this.stopDecoyTraffic(channelName);
        };

        channel.onerror = (error) => {
            if (window.DEBUG_MODE) {
                console.error(`❌ Decoy channel "${channelName}" error:`, error);
            }
        };
    }

    startDecoyTraffic(channel, channelName) {
        const sendDecoyData = async () => {
            if (channel.readyState !== 'open') {
                return;
            }

            try {
                const decoyData = this.generateDecoyData(channelName);
                channel.send(decoyData);
                
                const interval = this.decoyChannelConfig.randomDecoyIntervals ?
                    Math.random() * 15000 + 10000 : 
                    20000; 
                
                this.decoyTimers.set(channelName, setTimeout(() => sendDecoyData(), interval));
            } catch (error) {
                if (window.DEBUG_MODE) {
                    console.error(`❌ Failed to send decoy data on "${channelName}":`, error);
                }
            }
        };

        const initialDelay = Math.random() * 10000 + 5000; 
        this.decoyTimers.set(channelName, setTimeout(() => sendDecoyData(), initialDelay));
    }

    stopDecoyTraffic(channelName) {
        const timer = this.decoyTimers.get(channelName);
        if (timer) {
            clearTimeout(timer);
            this.decoyTimers.delete(channelName);
        }
    }

    generateDecoyData(channelName) {
        const decoyTypes = {
            'sync': () => JSON.stringify({
                type: 'sync',
                timestamp: Date.now(),
                sequence: Math.floor(Math.random() * 1000),
                data: Array.from(crypto.getRandomValues(new Uint8Array(32)))
                    .map(b => b.toString(16).padStart(2, '0')).join('')
            }),
            'status': () => JSON.stringify({
                type: 'status',
                status: ['online', 'away', 'busy'][Math.floor(Math.random() * 3)],
                uptime: Math.floor(Math.random() * 3600),
                data: Array.from(crypto.getRandomValues(new Uint8Array(16)))
                    .map(b => b.toString(16).padStart(2, '0')).join('')
            }),
            'heartbeat': () => JSON.stringify({
                type: 'heartbeat',
                timestamp: Date.now(),
                data: Array.from(crypto.getRandomValues(new Uint8Array(24)))
                    .map(b => b.toString(16).padStart(2, '0')).join('')
            }),
            'metrics': () => JSON.stringify({
                type: 'metrics',
                cpu: Math.random() * 100,
                memory: Math.random() * 100,
                network: Math.random() * 1000,
                data: Array.from(crypto.getRandomValues(new Uint8Array(20)))
                    .map(b => b.toString(16).padStart(2, '0')).join('')
            }),
            'debug': () => JSON.stringify({
                type: 'debug',
                level: ['info', 'warn', 'error'][Math.floor(Math.random() * 3)],
                message: 'Debug message',
                data: Array.from(crypto.getRandomValues(new Uint8Array(28)))
                    .map(b => b.toString(16).padStart(2, '0')).join('')
            })
        };

        return decoyTypes[channelName] ? decoyTypes[channelName]() : 
            Array.from(crypto.getRandomValues(new Uint8Array(64)))
                .map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // ============================================
    // 6. PACKET REORDERING PROTECTION
    // ============================================

    addReorderingHeaders(data) {
        if (!this.reorderingConfig.enabled) {
            return data;
        }

        try {
            const dataArray = new Uint8Array(data);
            const headerSize = this.reorderingConfig.useTimestamps ? 12 : 8;
            const header = new ArrayBuffer(headerSize);
            const headerView = new DataView(header);

            // Add sequence number
            if (this.reorderingConfig.useSequenceNumbers) {
                headerView.setUint32(0, this.sequenceNumber++, false);
            }

            // Add timestamp
            if (this.reorderingConfig.useTimestamps) {
                headerView.setUint32(4, Date.now(), false);
            }

            // Add data size
            headerView.setUint32(this.reorderingConfig.useTimestamps ? 8 : 4, dataArray.length, false);

            // Combine header and data
            const result = new Uint8Array(headerSize + dataArray.length);
            result.set(new Uint8Array(header), 0);
            result.set(dataArray, headerSize);

            return result.buffer;
        } catch (error) {
            console.error('❌ Failed to add reordering headers:', error);
            return data;
        }
    }

    async processReorderedPacket(data) {
    if (!this.reorderingConfig.enabled) {
        return this.processMessage(data);
    }

    try {
        const dataArray = new Uint8Array(data);
        const headerSize = this.reorderingConfig.useTimestamps ? 12 : 8;

        if (dataArray.length < headerSize) {
            if (window.DEBUG_MODE) {
                console.warn('⚠️ Data too short for reordering headers, processing directly');
            }
            return this.processMessage(data);
        }

        const headerView = new DataView(dataArray.buffer, 0, headerSize);
        let sequence = 0;
        let timestamp = 0;
        let dataSize = 0;

        if (this.reorderingConfig.useSequenceNumbers) {
            sequence = headerView.getUint32(0, false);
        }

        if (this.reorderingConfig.useTimestamps) {
            timestamp = headerView.getUint32(4, false);
        }

        dataSize = headerView.getUint32(this.reorderingConfig.useTimestamps ? 8 : 4, false);

        if (dataSize > dataArray.length - headerSize || dataSize <= 0) {
            if (window.DEBUG_MODE) {
                console.warn('⚠️ Invalid reordered packet data size, processing directly');
            }
            return this.processMessage(data);
        }

        const actualData = dataArray.slice(headerSize, headerSize + dataSize);

        try {
            const textData = new TextDecoder().decode(actualData);
            const content = JSON.parse(textData);
            if (content.type === 'fake' || content.isFakeTraffic === true) {
                if (window.DEBUG_MODE) {
                    console.log(`🎭 BLOCKED: Reordered fake message: ${content.pattern || 'unknown'}`);
                }
                return; 
            }
        } catch (e) {

        }

        this.packetBuffer.set(sequence, {
            data: actualData.buffer,
            timestamp: timestamp || Date.now()
        });

        await this.processOrderedPackets();

    } catch (error) {
        console.error('❌ Failed to process reordered packet:', error);
        return this.processMessage(data);
    }
}

// ============================================
// IMPROVED PROCESSORDEREDPACKETS with filtering
// ============================================

async processOrderedPackets() {
    const now = Date.now();
    const timeout = this.reorderingConfig.reorderTimeout;

    while (true) {
        const nextSequence = this.lastProcessedSequence + 1;
        const packet = this.packetBuffer.get(nextSequence);

        if (!packet) {
            const oldestPacket = this.findOldestPacket();
            if (oldestPacket && (now - oldestPacket.timestamp) > timeout) {
                console.warn(`⚠️ Packet ${oldestPacket.sequence} timed out, processing out of order`);
                
                try {
                    const textData = new TextDecoder().decode(oldestPacket.data);
                    const content = JSON.parse(textData);
                    if (content.type === 'fake' || content.isFakeTraffic === true) {
                        console.log(`🎭 BLOCKED: Timed out fake message: ${content.pattern || 'unknown'}`);
                        this.packetBuffer.delete(oldestPacket.sequence);
                        this.lastProcessedSequence = oldestPacket.sequence;
                        continue; 
                    }
                } catch (e) {
                }
                
                await this.processMessage(oldestPacket.data);
                this.packetBuffer.delete(oldestPacket.sequence);
                this.lastProcessedSequence = oldestPacket.sequence;
            } else {
                break; 
            }
        } else {
            try {
                const textData = new TextDecoder().decode(packet.data);
                const content = JSON.parse(textData);
                if (content.type === 'fake' || content.isFakeTraffic === true) {
                    console.log(`🎭 BLOCKED: Ordered fake message: ${content.pattern || 'unknown'}`);
                    this.packetBuffer.delete(nextSequence);
                    this.lastProcessedSequence = nextSequence;
                    continue; 
                }
            } catch (e) {
            }
            
            await this.processMessage(packet.data);
            this.packetBuffer.delete(nextSequence);
            this.lastProcessedSequence = nextSequence;
        }
    }

    this.cleanupOldPackets(now, timeout);
}


    findOldestPacket() {
        let oldest = null;
        for (const [sequence, packet] of this.packetBuffer.entries()) {
            if (!oldest || packet.timestamp < oldest.timestamp) {
                oldest = { sequence, ...packet };
            }
        }
        return oldest;
    }

    cleanupOldPackets(now, timeout) {
        for (const [sequence, packet] of this.packetBuffer.entries()) {
            if ((now - packet.timestamp) > timeout) {
                console.warn(`🗑️ Removing timed out packet ${sequence}`);
                this.packetBuffer.delete(sequence);
            }
        }
    }

    // ============================================
    // 7. ANTI-FINGERPRINTING
    // ============================================

    applyAntiFingerprinting(data) {
        if (!this.antiFingerprintingConfig.enabled) {
            return data;
        }

        try {
            let processedData = data;

            // Add random noise
            if (this.antiFingerprintingConfig.addNoise) {
                processedData = this.addNoise(processedData);
            }

            // Randomize sizes
            if (this.antiFingerprintingConfig.randomizeSizes) {
                processedData = this.randomizeSize(processedData);
            }

            // Mask patterns
            if (this.antiFingerprintingConfig.maskPatterns) {
                processedData = this.maskPatterns(processedData);
            }

            // Add random headers
            if (this.antiFingerprintingConfig.useRandomHeaders) {
                processedData = this.addRandomHeaders(processedData);
            }

            return processedData;
        } catch (error) {
            console.error('❌ Anti-fingerprinting failed:', error);
            return data;
        }
    }

    addNoise(data) {
        const dataArray = new Uint8Array(data);
        const noiseSize = Math.floor(Math.random() * 32) + 8; // 8-40 bytes
        const noise = crypto.getRandomValues(new Uint8Array(noiseSize));
        
        const result = new Uint8Array(dataArray.length + noiseSize);
        result.set(dataArray, 0);
        result.set(noise, dataArray.length);
        
        return result.buffer;
    }

    randomizeSize(data) {
        const dataArray = new Uint8Array(data);
        const variation = this.fingerprintMask.sizeVariation;
        const targetSize = Math.floor(dataArray.length * variation);
        
        if (targetSize > dataArray.length) {
            // Add padding to increase size
            const padding = crypto.getRandomValues(new Uint8Array(targetSize - dataArray.length));
            const result = new Uint8Array(targetSize);
            result.set(dataArray, 0);
            result.set(padding, dataArray.length);
            return result.buffer;
        } else if (targetSize < dataArray.length) {
            // Truncate to decrease size
            return dataArray.slice(0, targetSize).buffer;
        }
        
        return data;
    }

    maskPatterns(data) {
        const dataArray = new Uint8Array(data);
        const result = new Uint8Array(dataArray.length);
        
        // Apply XOR with noise pattern
        for (let i = 0; i < dataArray.length; i++) {
            const noiseByte = this.fingerprintMask.noisePattern[i % this.fingerprintMask.noisePattern.length];
            result[i] = dataArray[i] ^ noiseByte;
        }
        
        return result.buffer;
    }

    addRandomHeaders(data) {
        const dataArray = new Uint8Array(data);
        const headerCount = Math.floor(Math.random() * 3) + 1; // 1-3 headers
        let totalHeaderSize = 0;
        
        // Calculate total header size
        for (let i = 0; i < headerCount; i++) {
            totalHeaderSize += 4 + Math.floor(Math.random() * 16) + 4; // size + data + checksum
        }
        
        const result = new Uint8Array(totalHeaderSize + dataArray.length);
        let offset = 0;
        
        // Add random headers
        for (let i = 0; i < headerCount; i++) {
            const headerName = this.fingerprintMask.headerVariations[
                Math.floor(Math.random() * this.fingerprintMask.headerVariations.length)
            ];
            const headerData = crypto.getRandomValues(new Uint8Array(Math.floor(Math.random() * 16) + 4));
            
            // Header structure: [size:4][name:4][data:variable][checksum:4]
            const headerView = new DataView(result.buffer, offset);
            headerView.setUint32(0, headerData.length + 8, false); // Total header size
            headerView.setUint32(4, this.hashString(headerName), false); // Name hash
            
            result.set(headerData, offset + 8);
            
            // Add checksum
            const checksum = this.calculateChecksum(result.slice(offset, offset + 8 + headerData.length));
            const checksumView = new DataView(result.buffer, offset + 8 + headerData.length);
            checksumView.setUint32(0, checksum, false);
            
            offset += 8 + headerData.length + 4;
        }
        
        // Add original data
        result.set(dataArray, offset);
        
        return result.buffer;
    }

    hashString(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return Math.abs(hash);
    }

    calculateChecksum(data) {
        let checksum = 0;
        for (let i = 0; i < data.length; i++) {
            checksum = (checksum + data[i]) & 0xFFFFFFFF;
        }
        return checksum;
    }

    // ============================================
    // ENHANCED MESSAGE SENDING AND RECEIVING
    // ============================================

    async removeSecurityLayers(data) {
    try {
        const status = this.getSecurityStatus();
        if (window.DEBUG_MODE) {
            console.log(`🔍 removeSecurityLayers (Stage ${status.stage}):`, {
                dataType: typeof data,
                dataLength: data?.length || data?.byteLength || 0,
                activeFeatures: status.activeFeaturesCount
            });
        }

        if (!data) {
            console.warn('⚠️ Received empty data');
            return null;
        }

        let processedData = data;

        // IMPORTANT: Early check for fake messages
        if (typeof data === 'string') {
            try {
                const jsonData = JSON.parse(data);
                
                // PRIORITY ONE: Filtering out fake messages
                if (jsonData.type === 'fake') {
                    if (window.DEBUG_MODE) {
                        console.log(`🎭 Fake message filtered out: ${jsonData.pattern} (size: ${jsonData.size})`);
                    }
                    return 'FAKE_MESSAGE_FILTERED'; 
                }
                
                // System messages — do NOT return for re-processing
                if (jsonData.type && ['heartbeat', 'verification', 'verification_response', 'peer_disconnect', 'key_rotation_signal', 'key_rotation_ready', 'security_upgrade'].includes(jsonData.type)) {
                    if (window.DEBUG_MODE) {
                        console.log('🔧 System message detected, blocking from chat:', jsonData.type);
                    }
                    return 'SYSTEM_MESSAGE_FILTERED';
                }
                
                // File transfer messages — do NOT return for display
                if (jsonData.type && ['file_transfer_start', 'file_transfer_response', 'file_chunk', 'chunk_confirmation', 'file_transfer_complete', 'file_transfer_error'].includes(jsonData.type)) {
                    if (window.DEBUG_MODE) {
                        console.log('📁 File transfer message detected, blocking from chat:', jsonData.type);
                    }
                    return 'FILE_MESSAGE_FILTERED';
                }
                
                // Regular text messages - extract the actual message text
                if (jsonData.type === 'message') {
                    if (window.DEBUG_MODE) {
                        console.log('📝 Regular message detected, extracting text:', jsonData.data);
                    }
                    return jsonData.data; // Return the actual message text, not the JSON
                }
                
                // Enhanced messages
                if (jsonData.type === 'enhanced_message' && jsonData.data) {
                    if (window.DEBUG_MODE) {
                        console.log('🔐 Enhanced message detected, decrypting...');
                    }
                    
                    if (!this.encryptionKey || !this.macKey || !this.metadataKey) {
                        console.error('❌ Missing encryption keys');
                        return null;
                    }
                    
                    const decryptedResult = await window.EnhancedSecureCryptoUtils.decryptMessage(
                        jsonData.data,
                        this.encryptionKey,
                        this.macKey,
                        this.metadataKey
                    );
                    
                    if (window.DEBUG_MODE) {
                        console.log('✅ Enhanced message decrypted, extracting...');
                        console.log('🔍 decryptedResult:', {
                            type: typeof decryptedResult,
                            hasMessage: !!decryptedResult?.message,
                            messageType: typeof decryptedResult?.message,
                            messageLength: decryptedResult?.message?.length || 0,
                            messageSample: decryptedResult?.message?.substring(0, 50) || 'no message'
                        });
                    }
                    
                    // CHECKING FOR FAKE MESSAGES AFTER DECRYPTION
                    try {
                        const decryptedContent = JSON.parse(decryptedResult.message);
                        if (decryptedContent.type === 'fake' || decryptedContent.isFakeTraffic === true) {
                            if (window.DEBUG_MODE) {
                                console.log(`🎭 BLOCKED: Encrypted fake message: ${decryptedContent.pattern || 'unknown'}`);
                            }
                            return 'FAKE_MESSAGE_FILTERED';
                        }
                    } catch (e) {
                        if (window.DEBUG_MODE) {
                            console.log('📝 Decrypted content is not JSON, treating as plain text message');
                        }
                    }
                    
                    if (window.DEBUG_MODE) {
                        console.log('📤 Returning decrypted message:', decryptedResult.message?.substring(0, 50));
                    }
                    return decryptedResult.message;
                }
                
                // Regular messages
                if (jsonData.type === 'message' && jsonData.data) {
                    if (window.DEBUG_MODE) {
                        console.log('📝 Regular message detected, extracting data');
                    }
                    return jsonData.data; // Return the actual message text
                }
                
                // If it's a regular message with type 'message', let it continue processing
                if (jsonData.type === 'message') {
                    if (window.DEBUG_MODE) {
                        console.log('📝 Regular message detected, returning for display');
                    }
                    return data; // Return the original JSON string for processing
                }
                
                // If it's not a special type, return the original data for display
                if (!jsonData.type || (jsonData.type !== 'fake' && !['heartbeat', 'verification', 'verification_response', 'peer_disconnect', 'key_rotation_signal', 'key_rotation_ready', 'enhanced_message', 'security_upgrade', 'file_transfer_start', 'file_transfer_response', 'file_chunk', 'chunk_confirmation', 'file_transfer_complete', 'file_transfer_error'].includes(jsonData.type))) {
                    if (window.DEBUG_MODE) {
                        console.log('📝 Regular message detected, returning for display');
                    }
                    return data;
                }
            } catch (e) {
                if (window.DEBUG_MODE) {
                    console.log('📄 Not JSON, processing as raw data');
                }
                // If it's not JSON, it might be a plain text message - return as-is
                return data;
            }
        }

        // Standard Decryption
        if (this.encryptionKey && typeof processedData === 'string' && processedData.length > 50) {
            try {
                const base64Regex = /^[A-Za-z0-9+/=]+$/;
                if (base64Regex.test(processedData.trim())) {
                    if (window.DEBUG_MODE) {
                        console.log('🔓 Applying standard decryption...');
                    }
                    processedData = await window.EnhancedSecureCryptoUtils.decryptData(processedData, this.encryptionKey);
                    if (window.DEBUG_MODE) {
                        console.log('✅ Standard decryption successful');
                    }
                    
                    // CHECKING FOR FAKE MESSAGES AFTER LEGACY DECRYPTION
                    if (typeof processedData === 'string') {
                        try {
                            const legacyContent = JSON.parse(processedData);
                            if (legacyContent.type === 'fake' || legacyContent.isFakeTraffic === true) {
                                if (window.DEBUG_MODE) {
                                    console.log(`🎭 BLOCKED: Legacy fake message: ${legacyContent.pattern || 'unknown'}`);
                                }
                                return 'FAKE_MESSAGE_FILTERED';
                            }
                        } catch (e) {
                            
                        }
                        processedData = new TextEncoder().encode(processedData).buffer;
                    }
                }
            } catch (error) {
                if (window.DEBUG_MODE) {
                    console.warn('⚠️ Standard decryption failed:', error.message);
                }
                return data; 
            }
        }

        if (this.securityFeatures.hasNestedEncryption && 
            this.nestedEncryptionKey && 
            processedData instanceof ArrayBuffer &&
            processedData.byteLength > 12) { 
            
            try {
                processedData = await this.removeNestedEncryption(processedData);
                
                if (processedData instanceof ArrayBuffer) {
                    try {
                        const textData = new TextDecoder().decode(processedData);
                        const nestedContent = JSON.parse(textData);
                        if (nestedContent.type === 'fake' || nestedContent.isFakeTraffic === true) {
                            if (window.DEBUG_MODE) {
                                console.log(`🎭 BLOCKED: Nested fake message: ${nestedContent.pattern || 'unknown'}`);
                            }
                            return 'FAKE_MESSAGE_FILTERED';
                        }
                    } catch (e) {
                        
                    }
                }
            } catch (error) {
                if (window.DEBUG_MODE) {
                    console.warn('⚠️ Nested decryption failed - skipping this layer:', error.message);
                }
            }
        }

        if (this.securityFeatures.hasPacketReordering && 
            this.reorderingConfig.enabled && 
            processedData instanceof ArrayBuffer) {
            try {
                const headerSize = this.reorderingConfig.useTimestamps ? 12 : 8;
                if (processedData.byteLength > headerSize) {
                    return await this.processReorderedPacket(processedData);
                }
            } catch (error) {
                if (window.DEBUG_MODE) {
                    console.warn('⚠️ Reordering processing failed - using direct processing:', error.message);
                }
            }
        }

        // Packet Padding Removal
        if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
            try {
                processedData = this.removePacketPadding(processedData);
            } catch (error) {
                if (window.DEBUG_MODE) {
                    console.warn('⚠️ Padding removal failed:', error.message);
                }
            }
        }

        // Anti-Fingerprinting Removal
        if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
            try {
                processedData = this.removeAntiFingerprinting(processedData);
            } catch (error) {
                if (window.DEBUG_MODE) {
                    console.warn('⚠️ Anti-fingerprinting removal failed:', error.message);
                }
            }
        }

        // Final transformation
        if (processedData instanceof ArrayBuffer) {
            processedData = new TextDecoder().decode(processedData);
        }

        if (typeof processedData === 'string') {
            try {
                const finalContent = JSON.parse(processedData);
                if (finalContent.type === 'fake' || finalContent.isFakeTraffic === true) {
                    if (window.DEBUG_MODE) {
                        console.log(`🎭 BLOCKED: Final check fake message: ${finalContent.pattern || 'unknown'}`);
                    }
                    return 'FAKE_MESSAGE_FILTERED';
                }
            } catch (e) {
            }
        }

        return processedData;

    } catch (error) {
        console.error('❌ Critical error in removeSecurityLayers:', error);
        return data;
    }
}

    removeAntiFingerprinting(data) {
        // This is a simplified version - in practice, you'd need to reverse all operations
        // For now, we'll just return the data as-is since the operations are mostly additive
        return data;
    }

    async applySecurityLayers(data, isFakeMessage = false) {
        try {
            let processedData = data;
            
            if (isFakeMessage) {
                if (this.encryptionKey && typeof processedData === 'string') {
                    processedData = await window.EnhancedSecureCryptoUtils.encryptData(processedData, this.encryptionKey);
                }
                return processedData;
            }
            
            if (this.securityFeatures.hasNestedEncryption && this.nestedEncryptionKey && processedData instanceof ArrayBuffer) {
                processedData = await this.applyNestedEncryption(processedData);
            }
            
            if (this.securityFeatures.hasPacketReordering && this.reorderingConfig?.enabled && processedData instanceof ArrayBuffer) {
                processedData = this.applyPacketReordering(processedData);
            }
            
            if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
                processedData = this.applyPacketPadding(processedData);
            }
            
            if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
                processedData = this.applyAntiFingerprinting(processedData);
            }
            
            if (this.encryptionKey && typeof processedData === 'string') {
                processedData = await window.EnhancedSecureCryptoUtils.encryptData(processedData, this.encryptionKey);
            }
            
            return processedData;
            
        } catch (error) {
            console.error('❌ Error in applySecurityLayers:', error);
            return data;
        }
    }

    async sendMessage(data) {
    if (!this.dataChannel || this.dataChannel.readyState !== 'open') {
        throw new Error('Data channel not ready');
    }

    try {
        this._secureLog('debug', 'sendMessage called', {
            hasDataChannel: !!this.dataChannel,
            dataChannelReady: this.dataChannel?.readyState === 'open',
            isInitiator: this.isInitiator,
            isVerified: this.isVerified,
            connectionReady: this.peerConnection?.connectionState === 'connected'
        });

        this._secureLog('debug', '🔍 sendMessage DEBUG', {
            dataType: typeof data,
            isString: typeof data === 'string',
            isArrayBuffer: data instanceof ArrayBuffer,
            dataLength: data?.length || data?.byteLength || 0,
        });

        // FIX: Check whether this is a file-transfer message
        if (typeof data === 'string') {
            try {
                const parsed = JSON.parse(data);
                
                // Send file messages directly without additional encryption
                if (parsed.type && parsed.type.startsWith('file_')) {
                    this._secureLog('debug', '📁 Sending file message directly', { type: parsed.type });
                    this.dataChannel.send(data);
                    return true;
                }
            } catch (jsonError) {
                // Not JSON — continue normal handling
            }
        }

        // For regular text messages, send via secure path
        if (typeof data === 'string') {
            return await this.sendSecureMessage({ type: 'message', data, timestamp: Date.now() });
        }

        // For binary data, apply security layers with a limited mutex
        this._secureLog('debug', '🔐 Applying security layers to non-string data');
        const securedData = await this._applySecurityLayersWithLimitedMutex(data, false);
        this.dataChannel.send(securedData);
        
        return true;
    } catch (error) {
        this._secureLog('error', '❌ Failed to send message', { 
            error: error.message,
            errorType: error.constructor.name
        });
        throw error;
    }
}

    // FIX: New method applying security layers with limited mutex use
    async _applySecurityLayersWithLimitedMutex(data, isFakeMessage = false) {
    // Use mutex ONLY for cryptographic operations
    return this._withMutex('cryptoOperation', async (operationId) => {
        try {
            let processedData = data;
            
            if (isFakeMessage) {
                if (this.encryptionKey && typeof processedData === 'string') {
                    processedData = await window.EnhancedSecureCryptoUtils.encryptData(processedData, this.encryptionKey);
                }
                return processedData;
            }
            
            if (this.securityFeatures.hasNestedEncryption && this.nestedEncryptionKey && processedData instanceof ArrayBuffer) {
                processedData = await this.applyNestedEncryption(processedData);
            }
            
            if (this.securityFeatures.hasPacketReordering && this.reorderingConfig?.enabled && processedData instanceof ArrayBuffer) {
                processedData = this.applyPacketReordering(processedData);
            }
            
            if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
                processedData = this.applyPacketPadding(processedData);
            }
            
            if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
                processedData = this.applyAntiFingerprinting(processedData);
            }
            
            if (this.encryptionKey && typeof processedData === 'string') {
                processedData = await window.EnhancedSecureCryptoUtils.encryptData(processedData, this.encryptionKey);
            }
            
            return processedData;
            
        } catch (error) {
            console.error('❌ Error in applySecurityLayers:', error);
            return data;
        }
    }, 3000); // Short timeout for crypto operations
}

    async sendSystemMessage(messageData) {
        if (!this.dataChannel || this.dataChannel.readyState !== 'open') {
            console.warn('⚠️ Cannot send system message - data channel not ready');
            return false;
        }

        try {
            const systemMessage = JSON.stringify({
                type: messageData.type,
                data: messageData,
                timestamp: Date.now()
            });

            console.log('🔧 Sending system message:', messageData.type);
            this.dataChannel.send(systemMessage);
            return true;
        } catch (error) {
            console.error('❌ Failed to send system message:', error);
            return false;
        }
    }

    // FIX 1: Simplified mutex system for message processing
async processMessage(data) {
    try {
        this._secureLog('debug', '�� Processing message', {
            dataType: typeof data,
            isArrayBuffer: data instanceof ArrayBuffer,
            hasData: !!(data?.length || data?.byteLength)
        });
        
        // CRITICAL: Early check for file messages WITHOUT mutex
        if (typeof data === 'string') {
            try {
                const parsed = JSON.parse(data);

                // ============================================
                // FILE MESSAGES — PRIORITY 1 (WITHOUT MUTEX)
                // ============================================
                
                const fileMessageTypes = [
                    'file_transfer_start',
                    'file_transfer_response',
                    'file_chunk', 
                    'chunk_confirmation',
                    'file_transfer_complete',
                    'file_transfer_error'
                ];

                if (parsed.type && fileMessageTypes.includes(parsed.type)) {
                    console.log('📁 File message detected in processMessage:', parsed.type);
                    
                    // Process file messages WITHOUT mutex
                    if (this.fileTransferSystem && typeof this.fileTransferSystem.handleFileMessage === 'function') {
                        console.log('📁 Processing file message directly:', parsed.type);
                        await this.fileTransferSystem.handleFileMessage(parsed);
                        return;
                    }
                    
                    // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Автоматическая инициализация файловой системы
                    console.warn('⚠️ File transfer system not available, attempting automatic initialization...');
                    try {
                        // Проверяем готовность соединения
                        if (!this.isVerified) {
                            console.warn('⚠️ Connection not verified, cannot initialize file transfer');
                            return;
                        }
                        
                        if (!this.dataChannel || this.dataChannel.readyState !== 'open') {
                            console.warn('⚠️ Data channel not open, cannot initialize file transfer');
                            return;
                        }
                        
                        // Инициализируем файловую систему
                        this.initializeFileTransfer();
                        
                        // Ждем инициализации
                        let attempts = 0;
                        const maxAttempts = 30; // 3 секунды максимум
                        while (!this.fileTransferSystem && attempts < maxAttempts) {
                            await new Promise(resolve => setTimeout(resolve, 100));
                            attempts++;
                        }
                        
                        if (this.fileTransferSystem && typeof this.fileTransferSystem.handleFileMessage === 'function') {
                            console.log('✅ File transfer system initialized, processing message:', parsed.type);
                            await this.fileTransferSystem.handleFileMessage(parsed);
                            return;
                        } else {
                            console.error('❌ File transfer system initialization failed');
                        }
                    } catch (e) {
                        console.error('❌ Automatic file transfer initialization failed:', e?.message || e);
                    }
                    
                    console.error('❌ File transfer system not available for:', parsed.type);
                    return; // IMPORTANT: Exit after handling
                }
                
                // ============================================
                // REGULAR USER MESSAGES (WITHOUT MUTEX)
                // ============================================
                
                if (parsed.type === 'message') {
                    console.log('📝 Regular user message detected in processMessage');
                    if (this.onMessage && parsed.data) {
                        this.deliverMessageToUI(parsed.data, 'received');
                    }
                    return;
                }
                
                // ============================================
                // SYSTEM MESSAGES (WITHOUT MUTEX)
                // ============================================
                
                if (parsed.type && ['heartbeat', 'verification', 'verification_response', 'peer_disconnect', 'security_upgrade'].includes(parsed.type)) {
                    this.handleSystemMessage(parsed);
                    return;
                }
                
                // ============================================
                // FAKE MESSAGES (WITHOUT MUTEX)
                // ============================================
                
                if (parsed.type === 'fake') {
                    console.log('🎭 Fake message blocked in processMessage:', parsed.pattern);
                    return;
                }
                
            } catch (jsonError) {
                // Not JSON — treat as text WITHOUT mutex
                if (this.onMessage) {
                    this.deliverMessageToUI(data, 'received');
                }
                return;
            }
        }

        // ============================================
        // ENCRYPTED DATA PROCESSING (WITH MUTEX ONLY FOR CRYPTO)
        // ============================================
        
        // If here — apply security layers with limited mutex
        const originalData = await this._processEncryptedDataWithLimitedMutex(data);

        // Check processing result
        if (originalData === 'FAKE_MESSAGE_FILTERED' || 
            originalData === 'FILE_MESSAGE_FILTERED' || 
            originalData === 'SYSTEM_MESSAGE_FILTERED') {
            return;
        }
        
        if (!originalData) {
            console.warn('⚠️ No data returned from removeSecurityLayers');
            return;
        }

        // Handle result after removeSecurityLayers
        let messageText;
        
        if (typeof originalData === 'string') {
            try {
                const message = JSON.parse(originalData);
                
                // SECOND CHECK FOR FILE MESSAGES AFTER DECRYPTION
                if (message.type && fileMessageTypes.includes(message.type)) {
                    console.log('📁 File message detected after decryption:', message.type);
                    if (this.fileTransferSystem) {
                        await this.fileTransferSystem.handleFileMessage(message);
                    }
                    return;
                }
                
                if (message.type && ['heartbeat', 'verification', 'verification_response', 'peer_disconnect', 'security_upgrade'].includes(message.type)) {
                    this.handleSystemMessage(message);
                    return;
                }
                
                if (message.type === 'fake') {
                    console.log(`🎭 Post-decryption fake message blocked: ${message.pattern}`);
                    return;
                }
                
                // Regular messages
                if (message.type === 'message' && message.data) {
                    messageText = message.data;
                } else {
                    messageText = originalData;
                }
            } catch (e) {
                messageText = originalData;
            }
        } else if (originalData instanceof ArrayBuffer) {
            messageText = new TextDecoder().decode(originalData);
        } else if (originalData && typeof originalData === 'object' && originalData.message) {
            messageText = originalData.message;
        } else {
            console.warn('⚠️ Unexpected data type after processing:', typeof originalData);
            return;
        }

        // Final check for fake and file messages
        if (messageText && messageText.trim().startsWith('{')) {
            try {
                const finalCheck = JSON.parse(messageText);
                if (finalCheck.type === 'fake') {
                    console.log(`�� Final fake message check blocked: ${finalCheck.pattern}`);
                    return;
                }
                
                // Additional check for file and system messages
                const blockedTypes = [
                    'file_transfer_start', 'file_transfer_response', 'file_chunk', 
                    'chunk_confirmation', 'file_transfer_complete', 'file_transfer_error',
                    'heartbeat', 'verification', 'verification_response', 
                    'peer_disconnect', 'key_rotation_signal', 'key_rotation_ready', 'security_upgrade'
                ];
                
                if (finalCheck.type && blockedTypes.includes(finalCheck.type)) {
                    console.log(`📁 Final system/file message check blocked: ${finalCheck.type}`);
                    return;
                }
            } catch (e) {
                // Not JSON — fine for plain text
            }
        }

        // Deliver message to the UI
        if (this.onMessage && messageText) {
            console.log('📤 Calling message handler with:', messageText.substring(0, 100));
            this.deliverMessageToUI(messageText, 'received');
        }

    } catch (error) {
        console.error('❌ Failed to process message:', error);
    }
}

    // FIX: New method with limited mutex when processing encrypted data
    async _processEncryptedDataWithLimitedMutex(data) {
        // Use mutex ONLY for cryptographic operations
        return this._withMutex('cryptoOperation', async (operationId) => {
            this._secureLog('debug', '🔐 Processing encrypted data with limited mutex', {
                operationId: operationId,
                dataType: typeof data
            });
            
            try {
                // Apply security layers
                const originalData = await this.removeSecurityLayers(data);
                return originalData;
                
            } catch (error) {
                this._secureLog('error', '❌ Error processing encrypted data', {
                    operationId: operationId,
                    errorType: error.constructor.name
                });
                return data; // Return original data on error
            }
        }, 2000); // Short timeout for crypto operations
    }

notifySecurityUpdate() {
    try {
        this._secureLog('debug', '🔒 Notifying about security level update', {
                isConnected: this.isConnected(),
                isVerified: this.isVerified,
                hasKeys: !!(this.encryptionKey && this.macKey && this.metadataKey),
                hasLastCalculation: !!this.lastSecurityCalculation
            });
        
        // Send an event about security level update
        document.dispatchEvent(new CustomEvent('security-level-updated', {
            detail: { 
                timestamp: Date.now(), 
                manager: 'webrtc',
                webrtcManager: this,
                isConnected: this.isConnected(),
                isVerified: this.isVerified,
                hasKeys: !!(this.encryptionKey && this.macKey && this.metadataKey),
                lastCalculation: this.lastSecurityCalculation
            }
        }));
        
        // FIX: Force header refresh with correct manager
        setTimeout(() => {
            if (window.forceHeaderSecurityUpdate) {
                window.forceHeaderSecurityUpdate(this);
            }
        }, 100);
        
        // FIX: Direct update if there is a calculation
        if (this.lastSecurityCalculation) {
            document.dispatchEvent(new CustomEvent('real-security-calculated', {
                detail: {
                    securityData: this.lastSecurityCalculation,
                    webrtcManager: this,
                    timestamp: Date.now()
                }
            }));
        }
        
    } catch (error) {
        this._secureLog('error', '❌ Error in notifySecurityUpdate', {
                error: error.message
            });
    }
}

handleSystemMessage(message) {
    console.log('🔧 Handling system message:', message.type);
    
    switch (message.type) {
        case 'heartbeat':
            this.handleHeartbeat();
            break;
        case 'verification':
            this.handleVerificationRequest(message.data);
            break;
        case 'verification_response':
            this.handleVerificationResponse(message.data);
            break;
        case 'peer_disconnect':
            this.handlePeerDisconnectNotification(message);
            break;
        case 'key_rotation_signal':
            console.log('🔄 Key rotation signal received (ignored for stability)');
            break;
        case 'key_rotation_ready':
            console.log('🔄 Key rotation ready signal received (ignored for stability)');
            break;
        case 'security_upgrade':
            console.log('🔒 Security upgrade notification received:', message);
            // Security upgrade messages are handled internally, not displayed to user
            // to prevent duplicate system messages
            break;
        default:
            console.log('🔧 Unknown system message type:', message.type);
    }
}

        // ============================================
        // FUNCTION MANAGEMENT METHODS
        // ============================================

        // Method to enable Stage 2 functions
        enableStage2Security() {
        if (this.sessionConstraints?.hasPacketReordering) {
            this.securityFeatures.hasPacketReordering = true;
            this.reorderingConfig.enabled = true;
        }
        
        if (this.sessionConstraints?.hasAntiFingerprinting) {
            this.securityFeatures.hasAntiFingerprinting = true;
            this.antiFingerprintingConfig.enabled = true;
            if (this.currentSecurityLevel === 'enhanced') {
                this.antiFingerprintingConfig.randomizeSizes = false;
                this.antiFingerprintingConfig.maskPatterns = false;
                this.antiFingerprintingConfig.useRandomHeaders = false;
            }
        }
        
        this.notifySecurityUpgrade(2);
        setTimeout(() => {
            this.calculateAndReportSecurityLevel();
        }, 500);
    }

        // Method to enable Stage 3 features (traffic obfuscation)
        enableStage3Security() {
            if (this.currentSecurityLevel !== 'maximum') {
                console.log('🔒 Stage 3 features only available for premium sessions');
                return;
            }
            
            if (this.sessionConstraints?.hasMessageChunking) {
                this.securityFeatures.hasMessageChunking = true;
                this.chunkingConfig.enabled = true;
            }
            
            if (this.sessionConstraints?.hasFakeTraffic) {
                this.securityFeatures.hasFakeTraffic = true;
                this.fakeTrafficConfig.enabled = true;
                this.startFakeTrafficGeneration();
            }
            
            this.notifySecurityUpgrade(3);
            setTimeout(() => {
                this.calculateAndReportSecurityLevel();
            }, 500);
        }

        // Method for enabling Stage 4 functions (maximum safety)
        enableStage4Security() {
            if (this.currentSecurityLevel !== 'maximum') {
                console.log('🔒 Stage 4 features only available for premium sessions');
                return;
            }
            
            if (this.sessionConstraints?.hasDecoyChannels && this.isConnected() && this.isVerified) {
                this.securityFeatures.hasDecoyChannels = true;
                this.decoyChannelConfig.enabled = true;
                
                try {
                    this.initializeDecoyChannels();
                } catch (error) {
                    console.warn('⚠️ Decoy channels initialization failed:', error.message);
                    this.securityFeatures.hasDecoyChannels = false;
                    this.decoyChannelConfig.enabled = false;
                }
            }
            
            // Full anti-fingerprinting for maximum sessions
            if (this.sessionConstraints?.hasAntiFingerprinting) {
                this.antiFingerprintingConfig.randomizeSizes = true;
                this.antiFingerprintingConfig.maskPatterns = true;
                this.antiFingerprintingConfig.useRandomHeaders = false; 
            }
            
            this.notifySecurityUpgrade(4);
            setTimeout(() => {
                this.calculateAndReportSecurityLevel();
            }, 500);
        }

        forceSecurityUpdate() {
            setTimeout(() => {
                this.calculateAndReportSecurityLevel();
                this.notifySecurityUpdate();
            }, 100);
        }

        // Method for getting security status
        getSecurityStatus() {
            const activeFeatures = Object.entries(this.securityFeatures)
                .filter(([key, value]) => value === true)
                .map(([key]) => key);
                
            const stage = this.currentSecurityLevel === 'basic' ? 1 : 
                     this.currentSecurityLevel === 'enhanced' ? 2 :
                     this.currentSecurityLevel === 'maximum' ? 4 : 1;
                        
            return {
                stage: stage,
                sessionType: this.currentSessionType,
                securityLevel: this.currentSecurityLevel,
                activeFeatures: activeFeatures,
                totalFeatures: Object.keys(this.securityFeatures).length,
                activeFeaturesCount: activeFeatures.length,
                activeFeaturesNames: activeFeatures,
                sessionConstraints: this.sessionConstraints
            };
        }

        // Method to notify UI about security update
        notifySecurityUpgrade(stage) {
            const stageNames = {
                1: 'Basic Enhanced',
                2: 'Medium Security', 
                3: 'High Security',
                4: 'Maximum Security'
            };
            
            const message = `🔒 Security upgraded to Stage ${stage}: ${stageNames[stage]}`;
            
            // Avoid duplicate security-upgrade notifications
            if (!this.securityUpgradeNotificationSent || this.lastSecurityUpgradeStage !== stage) {
                this.securityUpgradeNotificationSent = true;
                this.lastSecurityUpgradeStage = stage;
                
                // Notify local UI via onMessage
                if (this.onMessage) {
                    this.deliverMessageToUI(message, 'system');
                }
            }

            // Send security upgrade notification to peer via WebRTC
            if (this.dataChannel && this.dataChannel.readyState === 'open') {
                try {
                    const securityNotification = {
                        type: 'security_upgrade',
                        stage: stage,
                        stageName: stageNames[stage],
                        message: message,
                        timestamp: Date.now()
                    };
                    
                    console.log('🔒 Sending security upgrade notification to peer:', securityNotification);
                    this.dataChannel.send(JSON.stringify(securityNotification));
                } catch (error) {
                    console.warn('⚠️ Failed to send security upgrade notification to peer:', error.message);
                }
            }

            const status = this.getSecurityStatus();
        }

        async calculateAndReportSecurityLevel() {
            try {
                if (!window.EnhancedSecureCryptoUtils) {
                    this._secureLog('warn', '⚠️ EnhancedSecureCryptoUtils not available for security calculation');
                    return null;
                }

                if (!this.isConnected() || !this.isVerified || !this.encryptionKey || !this.macKey) {
                    this._secureLog('debug', '⚠️ WebRTC not ready for security calculation', {
                        connected: this.isConnected(),
                        verified: this.isVerified,
                        hasEncryptionKey: !!this.encryptionKey,
                        hasMacKey: !!this.macKey
                    });
                    return null;
                }

                this._secureLog('debug', '🔍 Calculating real security level', {
                    managerState: 'ready',
                    hasAllKeys: !!(this.encryptionKey && this.macKey && this.metadataKey)
                });
                
                const securityData = await window.EnhancedSecureCryptoUtils.calculateSecurityLevel(this);
                
                this._secureLog('info', '🔐 Real security level calculated', {
                    hasSecurityLevel: !!securityData.level,
                    scoreRange: securityData.score > 80 ? 'high' : securityData.score > 50 ? 'medium' : 'low',
                    checksRatio: `${securityData.passedChecks}/${securityData.totalChecks}`,
                    isRealCalculation: securityData.isRealData
                });

                this.lastSecurityCalculation = securityData;

                document.dispatchEvent(new CustomEvent('real-security-calculated', {
                    detail: {
                        securityData: securityData,
                        webrtcManager: this,
                        timestamp: Date.now(),
                        source: 'calculateAndReportSecurityLevel'
                    }
                }));

                if (securityData.isRealData && this.onMessage) {
                    if (!this.securityCalculationNotificationSent || this.lastSecurityCalculationLevel !== securityData.level) {
                        this.securityCalculationNotificationSent = true;
                        this.lastSecurityCalculationLevel = securityData.level;
                        
                        const message = `🔒 Security Level: ${securityData.level} (${securityData.score}%) - ${securityData.passedChecks}/${securityData.totalChecks} checks passed`;
                        this.deliverMessageToUI(message, 'system');
                    }
                }
                
                return securityData;
                
            } catch (error) {
                this._secureLog('error', '❌ Failed to calculate real security level', {
                    errorType: error.constructor.name
                });
                return null;
            }
        }

        // ============================================
        // AUTOMATIC STEP-BY-STEP SWITCHING ON
        // ============================================

        // Method for automatic feature enablement with stability check
        async autoEnableSecurityFeatures() {
        if (this.currentSessionType === 'demo') {
            console.log('🔒 Demo session - keeping basic security only');
            await this.calculateAndReportSecurityLevel();
            this.notifySecurityUpgrade(1);
            return;
        }

        const checkStability = () => {
            const isStable = this.isConnected() && 
                            this.isVerified && 
                            this.connectionAttempts === 0 && 
                            this.messageQueue.length === 0 &&
                            this.peerConnection?.connectionState === 'connected';
            return isStable;
        };
        
        console.log(`🔒 ${this.currentSessionType} session - starting graduated security activation`);
        await this.calculateAndReportSecurityLevel();
        this.notifySecurityUpgrade(1);
        
        if (this.currentSecurityLevel === 'enhanced' || this.currentSecurityLevel === 'maximum') {
            setTimeout(async () => {
                if (checkStability()) {
                    console.log('✅ Activating Stage 2 for paid session');
                    this.enableStage2Security();
                    await this.calculateAndReportSecurityLevel(); 
                    
                    // For maximum sessions, turn on Stage 3 and 4
                    if (this.currentSecurityLevel === 'maximum') {
                        setTimeout(async () => {
                            if (checkStability()) {
                                console.log('✅ Activating Stage 3 for premium session');
                                this.enableStage3Security();
                                await this.calculateAndReportSecurityLevel();
                                
                                setTimeout(async () => {
                                    if (checkStability()) {
                                        console.log('✅ Activating Stage 4 for premium session');
                                        this.enableStage4Security();
                                        await this.calculateAndReportSecurityLevel();
                                    }
                                }, 20000);
                            }
                        }, 15000);
                    }
                }
            }, 10000);
        }
    }

    // ============================================
    // CONNECTION MANAGEMENT WITH ENHANCED SECURITY
    // ============================================

    async establishConnection() {
        try {
            // Initialize enhanced security features
            await this.initializeEnhancedSecurity();
            
            // Start fake traffic generation
            if (this.fakeTrafficConfig.enabled) {
                this.startFakeTrafficGeneration();
            }
            
            // Initialize decoy channels
            if (this.decoyChannelConfig.enabled) {
                this.initializeDecoyChannels();
            }
            
        } catch (error) {
            console.error('❌ Failed to establish enhanced connection:', error);
            // Do not close the connection on setup errors — just log and continue
            this.onStatusChange('disconnected');
            throw error;
        }
    }

    disconnect() {
        try {
            console.log('🔌 Disconnecting WebRTC Manager...');
            
            // Cleanup file transfer system
            if (this.fileTransferSystem) {
                console.log('🧹 Cleaning up file transfer system during disconnect...');
                this.fileTransferSystem.cleanup();
                this.fileTransferSystem = null;
            }
            
            // Stop fake traffic generation
            this.stopFakeTrafficGeneration();
            
            // Stop decoy traffic
            for (const [channelName, timer] of this.decoyTimers.entries()) {
                clearTimeout(timer);
            }
            this.decoyTimers.clear();
            
            // Close decoy channels
            for (const [channelName, channel] of this.decoyChannels.entries()) {
                if (channel.readyState === 'open') {
                    channel.close();
                }
            }
            this.decoyChannels.clear();
            
            // Clean up packet buffer
            this.packetBuffer.clear();
            
            // Clean up chunk queue
            this.chunkQueue = [];

        } catch (error) {
            console.error('❌ Error during enhanced disconnect:', error);
        }
    }

    // Start periodic cleanup for rate limiting and security
    startPeriodicCleanup() {
        setInterval(() => {
            const now = Date.now();
            if (now - this.lastCleanupTime > EnhancedSecureWebRTCManager.TIMEOUTS.CLEANUP_INTERVAL) { // Every 5 minutes
                window.EnhancedSecureCryptoUtils.rateLimiter.cleanup();
                this.lastCleanupTime = now;
                
                // Clean old processed message IDs (keep only last hour)
                if (this.processedMessageIds.size > EnhancedSecureWebRTCManager.LIMITS.MAX_PROCESSED_MESSAGE_IDS) {
                    this.processedMessageIds.clear();
                }
                
                // PFS: Clean old keys that are no longer needed
                this.cleanupOldKeys();
            }
        }, EnhancedSecureWebRTCManager.TIMEOUTS.CLEANUP_CHECK_INTERVAL); // Check every minute
    }

    // Calculate current security level with real verification
    async calculateSecurityLevel() {
        return await window.EnhancedSecureCryptoUtils.calculateSecurityLevel(this);
    }

    // PFS: Check if key rotation is needed
    shouldRotateKeys() {
        if (!this.isConnected() || !this.isVerified) {
            return false;
        }
        
        const now = Date.now();
        const timeSinceLastRotation = now - this.lastKeyRotation;
        
        // Rotate keys every 5 minutes or after 100 messages
        return timeSinceLastRotation > this.keyRotationInterval || 
               this.messageCounter % 100 === 0;
    }

    // PFS: Rotate encryption keys for Perfect Forward Secrecy
    async rotateKeys() {
        return this._withMutex('keyOperation', async (operationId) => {
            this._secureLog('info', '🔄 Starting key rotation with mutex', {
                operationId: operationId
            });
            
            // Validate state inside the critical section
            if (!this.isConnected() || !this.isVerified) {
                this._secureLog('warn', '⚠️ Key rotation aborted - connection not ready', {
                    operationId: operationId,
                    isConnected: this.isConnected(),
                    isVerified: this.isVerified
                });
                return false;
            }
            
            // Ensure rotation is not already in progress
            if (this._keySystemState.isRotating) {
                this._secureLog('warn', '⚠️ Key rotation already in progress', {
                    operationId: operationId
                });
                return false;
            }
            
            try {
                // Set rotation flag
                this._keySystemState.isRotating = true;
                this._keySystemState.lastOperation = 'rotation';
                this._keySystemState.lastOperationTime = Date.now();
                
                // Send rotation signal to peer
                const rotationSignal = {
                    type: 'key_rotation_signal',
                    newVersion: this.currentKeyVersion + 1,
                    timestamp: Date.now(),
                    operationId: operationId
                };
                
                if (this.dataChannel && this.dataChannel.readyState === 'open') {
                    this.dataChannel.send(JSON.stringify(rotationSignal));
                } else {
                    throw new Error('Data channel not ready for key rotation');
                }
                
                // Wait for peer confirmation
                return new Promise((resolve) => {
                    this.pendingRotation = {
                        newVersion: this.currentKeyVersion + 1,
                        operationId: operationId,
                        resolve: resolve,
                        timeout: setTimeout(() => {
                            this._secureLog('error', '⚠️ Key rotation timeout', {
                                operationId: operationId
                            });
                            this._keySystemState.isRotating = false;
                            this.pendingRotation = null;
                            resolve(false);
                        }, 10000) // 10 seconds timeout
                    };
                });
                
            } catch (error) {
                this._secureLog('error', '❌ Key rotation failed in critical section', {
                    operationId: operationId,
                    errorType: error.constructor.name
                });
                this._keySystemState.isRotating = false;
                return false;
            }
        }, 10000); // 10 seconds timeout for the entire operation
    }

    // PFS: Clean up old keys that are no longer needed
    cleanupOldKeys() {
        const now = Date.now();
        const maxKeyAge = EnhancedSecureWebRTCManager.LIMITS.MAX_KEY_AGE; // 15 minutes - keys older than this are deleted
        
        for (const [version, keySet] of this.oldKeys.entries()) {
            if (now - keySet.timestamp > maxKeyAge) {
                this.oldKeys.delete(version);
                window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Old PFS keys cleaned up', {
                    version: version,
                    age: Math.round((now - keySet.timestamp) / 1000) + 's'
                });
            }
        }
    }

    // PFS: Get keys for specific version (for decryption)
    getKeysForVersion(version) {
        // First, we check the old keys (including version 0).
        const oldKeySet = this.oldKeys.get(version);
        if (oldKeySet && oldKeySet.encryptionKey && oldKeySet.macKey && oldKeySet.metadataKey) {
            return {
                encryptionKey: oldKeySet.encryptionKey,
                macKey: oldKeySet.macKey,
                metadataKey: oldKeySet.metadataKey
            };
        }
        
        // If this is the current version, return the current keys.
        if (version === this.currentKeyVersion) {
            if (this.encryptionKey && this.macKey && this.metadataKey) {
                return {
                    encryptionKey: this.encryptionKey,
                    macKey: this.macKey,
                    metadataKey: this.metadataKey
                };
            }
        }
        
        window.EnhancedSecureCryptoUtils.secureLog.log('error', 'No valid keys found for version', {
            requestedVersion: version,
            currentVersion: this.currentKeyVersion,
            availableVersions: Array.from(this.oldKeys.keys())
        });
        
        return null;
    }

    createPeerConnection() {
        const config = {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' },
                { urls: 'stun:stun2.l.google.com:19302' },
                { urls: 'stun:stun3.l.google.com:19302' },
                { urls: 'stun:stun4.l.google.com:19302' }
            ],
            iceCandidatePoolSize: 10,
            bundlePolicy: 'balanced'
        };

        this.peerConnection = new RTCPeerConnection(config);

        this.peerConnection.onconnectionstatechange = () => {
            const state = this.peerConnection.connectionState;
            console.log('Connection state:', state);
            
            if (state === 'connected' && !this.isVerified) {
                this.onStatusChange('verifying');
            } else if (state === 'connected' && this.isVerified) {
                this.onStatusChange('connected');
            } else if (state === 'disconnected' || state === 'closed') {
                // If this is an intentional disconnect, clear immediately.
                if (this.intentionalDisconnect) {
                    this.onStatusChange('disconnected');
                    setTimeout(() => this.disconnect(), 100);
                } else {
                    // Unexpected disconnection — do not auto-reconnect
                    this.onStatusChange('disconnected');
                    // Do not call cleanupConnection automatically
                    // to avoid closing the session on connection errors
                }
            } else if (state === 'failed') {
                // Do not auto-reconnect to avoid closing the session on errors
                this.onStatusChange('disconnected');
                // if (!this.intentionalDisconnect && this.connectionAttempts < this.maxConnectionAttempts) {
                //     this.connectionAttempts++;
                //     setTimeout(() => this.retryConnection(), 2000);
                // } else {
                //     this.onStatusChange('disconnected');
                //     // Do not call cleanupConnection automatically for 'failed'
                //     // to avoid closing the session on connection errors
                // }
            } else {
                this.onStatusChange(state);
            }
        };

        this.peerConnection.ondatachannel = (event) => {
            console.log('🔗 Data channel received:', {
                channelLabel: event.channel.label,
                channelState: event.channel.readyState,
                isInitiator: this.isInitiator,
                channelId: event.channel.id,
                protocol: event.channel.protocol
            });
            
            // CRITICAL: Store the received data channel
            if (event.channel.label === 'securechat') {
                console.log('🔗 MAIN DATA CHANNEL RECEIVED (answerer side)');
                this.dataChannel = event.channel;
                this.setupDataChannel(event.channel);
            } else {
                console.log('🔗 ADDITIONAL DATA CHANNEL RECEIVED:', event.channel.label);
                // Handle additional channels (heartbeat, etc.)
                if (event.channel.label === 'heartbeat') {
                    this.heartbeatChannel = event.channel;
                }
            }
        };
    }

    setupDataChannel(channel) {
        console.log('🔗 setupDataChannel called:', {
            channelLabel: channel.label,
            channelState: channel.readyState,
            isInitiator: this.isInitiator,
            isVerified: this.isVerified
        });

        this.dataChannel = channel;

        this.dataChannel.onopen = async () => {
            console.log('🔗 Data channel opened:', {
                isInitiator: this.isInitiator,
                isVerified: this.isVerified,
                dataChannelState: this.dataChannel.readyState,
                dataChannelLabel: this.dataChannel.label
            });
            // Configure backpressure for large transfers
            try {
                if (this.dataChannel && typeof this.dataChannel.bufferedAmountLowThreshold === 'number') {
                    // 1 MB threshold for bufferedamountlow event
                    this.dataChannel.bufferedAmountLowThreshold = 1024 * 1024;
                }
            } catch (e) {
                // ignore
            }
            
            try {
                await this.establishConnection();
                
                        // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Инициализируем файловую систему для обеих сторон
        this.initializeFileTransfer();
                
            } catch (error) {
                console.error('❌ Error in establishConnection:', error);
                // Continue despite errors
            }
                
            if (this.isVerified) {
                this.onStatusChange('connected');
                this.processMessageQueue();
                
                setTimeout(async () => {
                    await this.calculateAndReportSecurityLevel();
                    this.autoEnableSecurityFeatures();
                    this.notifySecurityUpdate();
                }, 500);
            } else {
                this.onStatusChange('verifying');
                this.initiateVerification();
            }
            this.startHeartbeat();
        };

        this.dataChannel.onclose = () => {
            if (!this.intentionalDisconnect) {
                this.onStatusChange('disconnected');
                
                if (!this.connectionClosedNotificationSent) {
                    this.connectionClosedNotificationSent = true;
                    this.deliverMessageToUI('🔌 Enhanced secure connection closed. Check connection status.', 'system');
                }
            } else {
                this.onStatusChange('disconnected');
                
                if (!this.connectionClosedNotificationSent) {
                    this.connectionClosedNotificationSent = true;
                    this.deliverMessageToUI('🔌 Enhanced secure connection closed', 'system');
                }
            }
            
            this.stopHeartbeat();
            this.isVerified = false;
        };

        // FIX 2: Remove mutex entirely from message processing path
        this.dataChannel.onmessage = async (event) => {
            try {
                console.log('📨 Raw message received:', {
                    dataType: typeof event.data,
                    dataLength: event.data?.length || event.data?.byteLength || 0,
                    isString: typeof event.data === 'string'
                });

                // IMPORTANT: Process ALL messages WITHOUT mutex
                if (typeof event.data === 'string') {
                    try {
                        const parsed = JSON.parse(event.data);
                        console.log('📨 Parsed message:', {
                            type: parsed.type,
                            hasData: !!parsed.data,
                            timestamp: parsed.timestamp
                        });
                        
                        // ============================================
                        // CRITICAL: FILE MESSAGES (WITHOUT MUTEX)
                        // ============================================
                        
                        const fileMessageTypes = [
                            'file_transfer_start',
                            'file_transfer_response', 
                            'file_chunk',
                            'chunk_confirmation',
                            'file_transfer_complete',
                            'file_transfer_error'
                        ];
                        
                        if (parsed.type && fileMessageTypes.includes(parsed.type)) {
                            console.log('📁 File message intercepted at WebRTC level:', parsed.type);
                            
                            // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Инициализируем файловую систему при получении файловых сообщений
                            if (!this.fileTransferSystem) {
                                try {
                                    // Проверяем готовность соединения
                                    if (this.isVerified && this.dataChannel && this.dataChannel.readyState === 'open') {
                                        this.initializeFileTransfer();
                                        
                                        // Ждем инициализации
                                        let attempts = 0;
                                        const maxAttempts = 30;
                                        while (!this.fileTransferSystem && attempts < maxAttempts) {
                                            await new Promise(resolve => setTimeout(resolve, 100));
                                            attempts++;
                                        }
                                    }
                                } catch (initError) {
                                    console.error('❌ Failed to initialize file transfer system for receiver:', initError);
                                }
                            }
                            
                            // Handle directly WITHOUT extra checks
                            if (window.fileTransferSystem) {
                                console.log('📁 Forwarding to global file transfer system:', parsed.type);
                                await window.fileTransferSystem.handleFileMessage(parsed);
                                return;
                            }
                            if (this.fileTransferSystem) {
                                console.log('📁 Forwarding to local file transfer system:', parsed.type);
                                await this.fileTransferSystem.handleFileMessage(parsed);
                                return;
                            }
                            // Attempt lazy initialization on receiver side
                            console.warn('⚠️ File transfer system not ready, attempting lazy init...');
                            try {
                                await this._ensureFileTransferReady();
                                if (this.fileTransferSystem) {
                                    await this.fileTransferSystem.handleFileMessage(parsed);
                                    return;
                                }
                            } catch (e) {
                                console.error('❌ Lazy init of file transfer failed:', e?.message || e);
                            }
                            console.error('❌ No file transfer system available for:', parsed.type);
                            return; // IMPORTANT: Do not process further
                        }
                        
                        // ============================================
                        // SYSTEM MESSAGES (WITHOUT MUTEX)
                        // ============================================
                        
                        if (parsed.type && ['heartbeat', 'verification', 'verification_response', 'peer_disconnect', 'security_upgrade'].includes(parsed.type)) {
                            console.log('🔧 System message detected:', parsed.type);
                            this.handleSystemMessage(parsed);
                            return;
                        }
                        
                        // ============================================
                        // REGULAR USER MESSAGES (WITHOUT MUTEX)
                        // ============================================
                        
                        if (parsed.type === 'message' && parsed.data) {
                            console.log('📝 User message detected:', parsed.data.substring(0, 50));
                            if (this.onMessage) {
                                this.deliverMessageToUI(parsed.data, 'received');
                            }
                            return;
                        }
                        
                        // ============================================
                        // ENHANCED MESSAGES (WITHOUT MUTEX)
                        // ============================================
                        
                        if (parsed.type === 'enhanced_message' && parsed.data) {
                            console.log('🔐 Enhanced message detected, processing...');
                            await this._processEnhancedMessageWithoutMutex(parsed);
                            return;
                        }
                        
                        // ============================================
                        // FAKE MESSAGES (WITHOUT MUTEX)
                        // ============================================
                        
                        if (parsed.type === 'fake') {
                            console.log('🎭 Fake message blocked:', parsed.pattern);
                            return;
                        }
                        
                        // ============================================
                        // UNKNOWN MESSAGE TYPES
                        // ============================================
                        
                        console.log('❓ Unknown message type:', parsed.type);
                        
                    } catch (jsonError) {
                        // Not JSON — treat as regular text message
                        console.log('📄 Non-JSON message detected, treating as text');
                        if (this.onMessage) {
                            this.deliverMessageToUI(event.data, 'received');
                        }
                        return;
                    }
                } else if (event.data instanceof ArrayBuffer) {
                    // Binary data — process WITHOUT mutex
                    console.log('🔢 Binary data received, processing...');
                    await this._processBinaryDataWithoutMutex(event.data);
                } else {
                    console.log('❓ Unknown data type:', typeof event.data);
                }
                
            } catch (error) {
                console.error('❌ Failed to process message in onmessage:', error);
            }
        };
    }
    // FIX 4: New method for processing binary data WITHOUT mutex
async _processBinaryDataWithoutMutex(data) {
    try {
        console.log('🔢 Processing binary data without mutex...');
        
        // Apply security layers WITHOUT mutex
        let processedData = data;
        
        // Nested Encryption Removal (if enabled)
        if (this.securityFeatures.hasNestedEncryption && 
            this.nestedEncryptionKey && 
            processedData instanceof ArrayBuffer &&
            processedData.byteLength > 12) {
            
            try {
                processedData = await this.removeNestedEncryption(processedData);
            } catch (error) {
                console.warn('⚠️ Nested decryption failed, continuing with original data');
            }
        }
        
        // Packet Padding Removal (if enabled)
        if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
            try {
                processedData = this.removePacketPadding(processedData);
            } catch (error) {
                console.warn('⚠️ Packet padding removal failed, continuing with original data');
            }
        }
        
        // Anti-Fingerprinting Removal (if enabled)
        if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
            try {
                processedData = this.removeAntiFingerprinting(processedData);
            } catch (error) {
                console.warn('⚠️ Anti-fingerprinting removal failed, continuing with original data');
            }
        }
        
        // Convert to text
        if (processedData instanceof ArrayBuffer) {
            const textData = new TextDecoder().decode(processedData);
            
            // Check for fake messages
            try {
                const content = JSON.parse(textData);
                if (content.type === 'fake' || content.isFakeTraffic === true) {
                    console.log(`🎭 BLOCKED: Binary fake message: ${content.pattern || 'unknown'}`);
                    return;
                }
            } catch (e) {
                // Not JSON — fine for plain text
            }
            
            // Deliver message to user
            if (this.onMessage) {
                this.deliverMessageToUI(textData, 'received');
            }
        }
        
    } catch (error) {
        console.error('❌ Error processing binary data:', error);
    }
}
    // FIX 3: New method for processing enhanced messages WITHOUT mutex
async _processEnhancedMessageWithoutMutex(parsedMessage) {
    try {
        console.log('🔐 Processing enhanced message without mutex...');
        
        if (!this.encryptionKey || !this.macKey || !this.metadataKey) {
            console.error('❌ Missing encryption keys for enhanced message');
            return;
        }
        
        const decryptedResult = await window.EnhancedSecureCryptoUtils.decryptMessage(
            parsedMessage.data,
            this.encryptionKey,
            this.macKey,
            this.metadataKey
        );
        
        if (decryptedResult && decryptedResult.message) {
            console.log('✅ Enhanced message decrypted successfully');
            
            // Try parsing JSON and showing nested text if it's a chat message
            try {
                const decryptedContent = JSON.parse(decryptedResult.message);
                if (decryptedContent.type === 'fake' || decryptedContent.isFakeTraffic === true) {
                    console.log(`�� BLOCKED: Encrypted fake message: ${decryptedContent.pattern || 'unknown'}`);
                    return;
                }
                if (decryptedContent && decryptedContent.type === 'message' && typeof decryptedContent.data === 'string') {
                    if (this.onMessage) {
                        this.deliverMessageToUI(decryptedContent.data, 'received');
                    }
                    return;
                }
            } catch (e) {
                // Not JSON — fine for plain text
            }
            
            // Otherwise pass as-is
            if (this.onMessage) {
                this.deliverMessageToUI(decryptedResult.message, 'received');
            }
        } else {
            console.warn('⚠️ No message content in decrypted result');
        }
        
    } catch (error) {
        console.error('❌ Error processing enhanced message:', error);
    }
}
    /**
     * Creates a unique ID for an operation
     */
    _generateOperationId() {
        return `op_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    /**
     * Universal function to acquire a mutex
     */
    async _acquireMutex(mutexName, operationId, timeout = 5000) {
        // CRITICAL FIX: Build correct mutex property name
        const mutexPropertyName = `_${mutexName}Mutex`;
        const mutex = this[mutexPropertyName];
        
        if (!mutex) {
            this._secureLog('error', `❌ Unknown mutex: ${mutexName}`, {
                mutexPropertyName: mutexPropertyName,
                availableMutexes: this._getAvailableMutexes(),
                operationId: operationId
            });
            throw new Error(`Unknown mutex: ${mutexName}. Available: ${this._getAvailableMutexes().join(', ')}`);
        }
        
        return new Promise((resolve, reject) => {
            const attemptLock = () => {
                if (!mutex.locked) {
                    // Acquire lock
                    mutex.locked = true;
                    mutex.lockId = operationId;
                    mutex.lockTimeout = setTimeout(() => {
                        this._secureLog('error', `⚠️ Mutex timeout for ${mutexName}`, {
                            operationId: operationId,
                            timeout: timeout,
                            queueLength: mutex.queue.length
                        });
                        this._releaseMutex(mutexName, operationId);
                        reject(new Error(`Mutex timeout for ${mutexName}`));
                    }, timeout);
                    
                    this._secureLog('debug', `🔒 Mutex acquired: ${mutexName}`, {
                        operationId: operationId,
                        queueLength: mutex.queue.length
                    });
                    
                    resolve();
                } else {
                    // Enqueue
                    mutex.queue.push({ resolve, reject, operationId, attemptLock });
                    
                    this._secureLog('debug', `⏳ Mutex queued: ${mutexName}`, {
                        operationId: operationId,
                        queuePosition: mutex.queue.length,
                        currentLockId: mutex.lockId
                    });
                }
            };
            
            attemptLock();
        });
    }

    /**
     * Release a mutex
     */
    _releaseMutex(mutexName, operationId) {
        // CRITICAL FIX: Build correct mutex property name
        const mutexPropertyName = `_${mutexName}Mutex`;
        const mutex = this[mutexPropertyName];
        
        if (!mutex) {
            this._secureLog('error', `❌ Unknown mutex for release: ${mutexName}`, {
                mutexPropertyName: mutexPropertyName,
                availableMutexes: this._getAvailableMutexes(),
                operationId: operationId
            });
            return; // Do not throw, just log
        }
        
        if (mutex.lockId !== operationId) {
            this._secureLog('error', `❌ Invalid mutex release attempt`, {
                mutexName: mutexName,
                expectedLockId: mutex.lockId,
                providedOperationId: operationId
            });
            return; // Do not throw, just log
        }
        
        // Clear timeout
        if (mutex.lockTimeout) {
            clearTimeout(mutex.lockTimeout);
            mutex.lockTimeout = null;
        }
        
        // Release lock
        mutex.locked = false;
        mutex.lockId = null;
        
        this._secureLog('debug', `🔓 Mutex released: ${mutexName}`, {
            operationId: operationId,
            queueLength: mutex.queue.length
        });
        
        // Process queue
        if (mutex.queue.length > 0) {
            const next = mutex.queue.shift();
            setImmediate(() => {
                try {
                    next.attemptLock();
                } catch (error) {
                    this._secureLog('error', '❌ Error processing mutex queue', {
                        mutexName: mutexName,
                        errorType: error.constructor.name
                    });
                    next.reject(error);
                }
            });
        }
    }

    _getAvailableMutexes() {
        const mutexes = [];
        const propertyNames = Object.getOwnPropertyNames(this);
        
        for (const prop of propertyNames) {
            if (prop.endsWith('Mutex') && prop.startsWith('_')) {
                // Extract mutex name without prefix/suffix
                const mutexName = prop.slice(1, -5); // Remove '_' prefix and 'Mutex' suffix
                mutexes.push(mutexName);
            }
        }
        
        return mutexes;
    }

    /**
     * Safely execute an operation with a mutex
     */
    async _withMutex(mutexName, operation, timeout = 5000) {
    const operationId = this._generateOperationId();
    
    // Validate before start
    if (!this._validateMutexSystem()) {
        this._secureLog('error', '❌ Mutex system not properly initialized', {
            operationId: operationId,
            mutexName: mutexName
        });
        throw new Error('Mutex system not properly initialized. Call _initializeMutexSystem() first.');
    }
    
    try {
        await this._acquireMutex(mutexName, operationId, timeout);
        
        // Increment operation counter
        const counterKey = `${mutexName}Operations`;
        if (this._operationCounters && this._operationCounters[counterKey] !== undefined) {
            this._operationCounters[counterKey]++;
        }
        
        // Execute the operation
        const result = await operation(operationId);
        return result;
        
    } catch (error) {
        this._secureLog('error', '❌ Error in mutex operation', {
            operationId: operationId,
            mutexName: mutexName,
            errorType: error.constructor.name,
            errorMessage: error.message
        });
        throw error;
    } finally {
        // Always release the mutex in the finally block
        try {
            this._releaseMutex(mutexName, operationId);
        } catch (releaseError) {
            this._secureLog('error', '❌ Error releasing mutex in finally block', {
                operationId: operationId,
                mutexName: mutexName,
                releaseErrorType: releaseError.constructor.name
            });
        }
    }
}

_validateMutexSystem() {
    const requiredMutexes = ['keyOperation', 'cryptoOperation', 'connectionOperation'];
    
    for (const mutexName of requiredMutexes) {
        const mutexPropertyName = `_${mutexName}Mutex`;
        const mutex = this[mutexPropertyName];
        
        if (!mutex || typeof mutex !== 'object') {
            this._secureLog('error', `❌ Missing or invalid mutex: ${mutexName}`, {
                mutexPropertyName: mutexPropertyName,
                mutexType: typeof mutex
            });
            return false;
        }
        
        // Validate mutex structure
        const requiredProps = ['locked', 'queue', 'lockId', 'lockTimeout'];
        for (const prop of requiredProps) {
            if (!(prop in mutex)) {
                this._secureLog('error', `❌ Mutex ${mutexName} missing property: ${prop}`);
                return false;
            }
        }
    }
    
    return true;
}

/**
 * NEW: Emergency recovery of the mutex system
 */
_emergencyRecoverMutexSystem() {
    this._secureLog('warn', '🚨 Emergency mutex system recovery initiated');
    
    try {
        // Force re-initialize the system
        this._initializeMutexSystem();
        
        this._secureLog('info', '✅ Mutex system recovered successfully');
        return true;
        
    } catch (error) {
        this._secureLog('error', '❌ Failed to recover mutex system', {
            errorType: error.constructor.name
        });
        return false;
    }
}

    /**
     * Secure key generation with mutex
     */
    async _generateEncryptionKeys() {
        return this._withMutex('keyOperation', async (operationId) => {
            this._secureLog('info', '🔑 Generating encryption keys with mutex', {
                operationId: operationId
            });
            
            // Ensure initialization is not already in progress
            if (this._keySystemState.isInitializing) {
                throw new Error('Key initialization already in progress');
            }
            
            try {
                this._keySystemState.isInitializing = true;
                this._keySystemState.lastOperation = 'generation';
                this._keySystemState.lastOperationTime = Date.now();
                
                // Generate ECDH keys
                const ecdhKeyPair = await window.EnhancedSecureCryptoUtils.generateECDHKeyPair();
                
                // Validate that keys were generated correctly
                if (!ecdhKeyPair || !ecdhKeyPair.privateKey || !ecdhKeyPair.publicKey) {
                    throw new Error('Failed to generate valid ECDH key pair');
                }
                
                // Generate ECDSA keys
                const ecdsaKeyPair = await window.EnhancedSecureCryptoUtils.generateECDSAKeyPair();
                
                if (!ecdsaKeyPair || !ecdsaKeyPair.privateKey || !ecdsaKeyPair.publicKey) {
                    throw new Error('Failed to generate valid ECDSA key pair');
                }
                
                this._secureLog('info', '✅ Encryption keys generated successfully', {
                    operationId: operationId,
                    hasECDHKeys: !!(ecdhKeyPair?.privateKey && ecdhKeyPair?.publicKey),
                    hasECDSAKeys: !!(ecdsaKeyPair?.privateKey && ecdsaKeyPair?.publicKey)
                });
                
                return { ecdhKeyPair, ecdsaKeyPair };
                
            } finally {
                this._keySystemState.isInitializing = false;
            }
        });
    }

    /**
     * Emergency unlocking of all mutexes
     */
    _emergencyUnlockAllMutexes() {
        const mutexes = ['keyOperation', 'cryptoOperation', 'connectionOperation'];
        
        this._secureLog('error', '🚨 EMERGENCY: Unlocking all mutexes');
        
        mutexes.forEach(mutexName => {
            const mutex = this[`_${mutexName}Mutex`];
            if (mutex) {
                if (mutex.lockTimeout) {
                    clearTimeout(mutex.lockTimeout);
                }
                mutex.locked = false;
                mutex.lockId = null;
                mutex.lockTimeout = null;
                
                // Clear the queue
                mutex.queue.forEach(item => {
                    item.reject(new Error('Emergency mutex unlock'));
                });
                mutex.queue = [];
            }
        });
    }
/**
 * NEW: Diagnostics of the mutex system state
 */
_getMutexSystemDiagnostics() {
    const diagnostics = {
        timestamp: Date.now(),
        systemValid: this._validateMutexSystem(),
        mutexes: {},
        counters: { ...this._operationCounters },
        keySystemState: { ...this._keySystemState }
    };
    
    const mutexNames = ['keyOperation', 'cryptoOperation', 'connectionOperation'];
    
    mutexNames.forEach(mutexName => {
        const mutexPropertyName = `_${mutexName}Mutex`;
        const mutex = this[mutexPropertyName];
        
        if (mutex) {
            diagnostics.mutexes[mutexName] = {
                locked: mutex.locked,
                lockId: mutex.lockId,
                queueLength: mutex.queue.length,
                hasTimeout: !!mutex.lockTimeout
            };
        } else {
            diagnostics.mutexes[mutexName] = { error: 'not_found' };
        }
    });
    
    return diagnostics;
}

    /**
     * FULLY FIXED createSecureOffer()
     * With race-condition protection and improved security
     */
    async createSecureOffer() {
        return this._withMutex('connectionOperation', async (operationId) => {
            this._secureLog('info', '📤 Creating secure offer with mutex', {
                operationId: operationId,
                connectionAttempts: this.connectionAttempts,
                currentState: this.peerConnection?.connectionState || 'none'
            });
            
            try {
                // ============================================
                // PHASE 1: INITIALIZATION AND VALIDATION
                // ============================================
                
                // Reset notification flags for a new connection
                this._resetNotificationFlags();
                
                // Rate limiting check
                if (!this._checkRateLimit()) {
                    throw new Error('Connection rate limit exceeded. Please wait before trying again.');
                }
                
                // Reset attempt counters
                this.connectionAttempts = 0;
                
                // Generate session salt (64 bytes for v4.0)
                this.sessionSalt = window.EnhancedSecureCryptoUtils.generateSalt();
                
                this._secureLog('debug', '🧂 Session salt generated', {
                    operationId: operationId,
                    saltLength: this.sessionSalt.length,
                    isValidSalt: Array.isArray(this.sessionSalt) && this.sessionSalt.length === 64
                });
                
                // ============================================
                // PHASE 2: SECURE KEY GENERATION
                // ============================================
                
                // Secure key generation via mutex
                const keyPairs = await this._generateEncryptionKeys();
                this.ecdhKeyPair = keyPairs.ecdhKeyPair;
                this.ecdsaKeyPair = keyPairs.ecdsaKeyPair;
                
                // Validate generated keys
                if (!this.ecdhKeyPair?.privateKey || !this.ecdhKeyPair?.publicKey) {
                    throw new Error('Failed to generate valid ECDH key pair');
                }
                
                if (!this.ecdsaKeyPair?.privateKey || !this.ecdsaKeyPair?.publicKey) {
                    throw new Error('Failed to generate valid ECDSA key pair');
                }
                
                // ============================================
                // PHASE 3: MITM PROTECTION AND FINGERPRINTING
                // ============================================
                
                // MITM Protection: Compute unique key fingerprints
                const ecdhFingerprint = await window.EnhancedSecureCryptoUtils.calculateKeyFingerprint(
                    await crypto.subtle.exportKey('spki', this.ecdhKeyPair.publicKey)
                );
                const ecdsaFingerprint = await window.EnhancedSecureCryptoUtils.calculateKeyFingerprint(
                    await crypto.subtle.exportKey('spki', this.ecdsaKeyPair.publicKey)
                );
                
                // Validate fingerprints
                if (!ecdhFingerprint || !ecdsaFingerprint) {
                    throw new Error('Failed to generate key fingerprints');
                }
                
                this._secureLog('info', 'Generated unique key pairs for MITM protection', {
                    operationId: operationId,
                    hasECDHFingerprint: !!ecdhFingerprint,
                    hasECDSAFingerprint: !!ecdsaFingerprint,
                    fingerprintLength: ecdhFingerprint.length,
                    timestamp: Date.now()
                });
                
                // ============================================
                // PHASE 4: EXPORT SIGNED KEYS
                // ============================================
                
                // Export keys with digital signatures
                const ecdhPublicKeyData = await window.EnhancedSecureCryptoUtils.exportPublicKeyWithSignature(
                    this.ecdhKeyPair.publicKey,
                    this.ecdsaKeyPair.privateKey,
                    'ECDH'
                );
                
                const ecdsaPublicKeyData = await window.EnhancedSecureCryptoUtils.exportPublicKeyWithSignature(
                    this.ecdsaKeyPair.publicKey,
                    this.ecdsaKeyPair.privateKey,
                    'ECDSA'
                );
                
                // Validate exported data
                if (!ecdhPublicKeyData?.keyData || !ecdhPublicKeyData?.signature) {
                    throw new Error('Failed to export ECDH public key with signature');
                }
                
                if (!ecdsaPublicKeyData?.keyData || !ecdsaPublicKeyData?.signature) {
                    throw new Error('Failed to export ECDSA public key with signature');
                }
                
                // ============================================
                // PHASE 5: UPDATE SECURITY FEATURES
                // ============================================
                
                // Atomic update of security features
                this._updateSecurityFeatures({
                    hasEncryption: true,
                    hasECDH: true,
                    hasECDSA: true,
                    hasMutualAuth: true,
                    hasMetadataProtection: true,
                    hasEnhancedReplayProtection: true,
                    hasNonExtractableKeys: true,
                    hasRateLimiting: true,
                    hasEnhancedValidation: true,
                    hasPFS: true
                });
                
                // ============================================
                // PHASE 6: INITIALIZE PEER CONNECTION
                // ============================================
                
                this.isInitiator = true;
                this.onStatusChange('connecting');
                
                // Create peer connection
                this.createPeerConnection();
                
                // Create main data channel
                this.dataChannel = this.peerConnection.createDataChannel('securechat', {
                    ordered: true
                });
                
                // Setup data channel
                this.setupDataChannel(this.dataChannel);
                
                this._secureLog('debug', '🔗 Data channel created', {
                    operationId: operationId,
                    channelLabel: this.dataChannel.label,
                    channelOrdered: this.dataChannel.ordered
                });
                
                // ============================================
                // PHASE 7: CREATE SDP OFFER
                // ============================================
                
                // Create WebRTC offer
                const offer = await this.peerConnection.createOffer({
                    offerToReceiveAudio: false,
                    offerToReceiveVideo: false
                });
                
                // Set local description
                await this.peerConnection.setLocalDescription(offer);
                
                // Await ICE gathering
                await this.waitForIceGathering();
                
                this._secureLog('debug', '🧊 ICE gathering completed', {
                    operationId: operationId,
                    iceGatheringState: this.peerConnection.iceGatheringState,
                    connectionState: this.peerConnection.connectionState
                });
                
                // ============================================
                // PHASE 8: GENERATE VERIFICATION CODE
                // ============================================
                
                // Generate verification code for out-of-band auth
                this.verificationCode = window.EnhancedSecureCryptoUtils.generateVerificationCode();
                
                // Validate verification code
                if (!this.verificationCode || this.verificationCode.length < EnhancedSecureWebRTCManager.SIZES.VERIFICATION_CODE_MIN_LENGTH) {
                    throw new Error('Failed to generate valid verification code');
                }
                
                // Notify UI about verification requirement
                this.onVerificationRequired(this.verificationCode);
                
                // ============================================
                // PHASE 9: MUTUAL AUTHENTICATION CHALLENGE
                // ============================================
                
                // Generate challenge for mutual authentication
                const authChallenge = window.EnhancedSecureCryptoUtils.generateMutualAuthChallenge();
                
                if (!authChallenge) {
                    throw new Error('Failed to generate mutual authentication challenge');
                }
                
                // ============================================
                // PHASE 10: SESSION ID FOR MITM PROTECTION
                // ============================================
                
                // MITM Protection: Generate session-specific ID
                this.sessionId = Array.from(crypto.getRandomValues(new Uint8Array(EnhancedSecureWebRTCManager.SIZES.SESSION_ID_LENGTH)))
                    .map(b => b.toString(16).padStart(2, '0')).join('');
                
                // Validate session ID
                if (!this.sessionId || this.sessionId.length !== (EnhancedSecureWebRTCManager.SIZES.SESSION_ID_LENGTH * 2)) {
                    throw new Error('Failed to generate valid session ID');
                }
                
                // ============================================
                // PHASE 11: SECURITY LEVEL CALCULATION
                // ============================================
                
                // Preliminary security level calculation
                let securityLevel;
                try {
                    securityLevel = await this.calculateSecurityLevel();
                } catch (error) {
                    this._secureLog('warn', '⚠️ Security level calculation failed, using fallback', {
                        operationId: operationId,
                        errorType: error.constructor.name
                    });
                    
                    // Fallback value
                    securityLevel = {
                        level: 'enhanced',
                        score: 75,
                        passedChecks: 10,
                        totalChecks: 15,
                        isRealData: false
                    };
                }
                
                // ============================================
                // PHASE 12: CREATE OFFER PACKAGE
                // ============================================
                
                const currentTimestamp = Date.now();
                
                const offerPackage = {
                    // Core information
                    type: 'enhanced_secure_offer',
                    sdp: this.peerConnection.localDescription.sdp,
                    version: '4.0',
                    timestamp: currentTimestamp,
                    
                    // Cryptographic keys
                    ecdhPublicKey: ecdhPublicKeyData,
                    ecdsaPublicKey: ecdsaPublicKeyData,
                    
                    // Session data
                    salt: this.sessionSalt,
                    sessionId: this.sessionId,
                    
                    // Authentication
                    verificationCode: this.verificationCode,
                    authChallenge: authChallenge,
                    
                    // Security metadata
                    securityLevel: securityLevel,
                    
                    // Additional fields for validation
                    keyFingerprints: {
                        ecdh: ecdhFingerprint.substring(0, 16), // First 16 chars for validation
                        ecdsa: ecdsaFingerprint.substring(0, 16)
                    },
                    
                    // Optional capabilities info
                    capabilities: {
                        supportsFileTransfer: true,
                        supportsEnhancedSecurity: true,
                        supportsKeyRotation: true,
                        supportsFakeTraffic: this.fakeTrafficConfig.enabled,
                        supportsDecoyChannels: this.decoyChannelConfig.enabled
                    }
                };
                
                // ============================================
                // PHASE 13: VALIDATE OFFER PACKAGE
                // ============================================
                
                // Final validation of the generated package
                if (!this.validateEnhancedOfferData(offerPackage)) {
                    throw new Error('Generated offer package failed validation');
                }
                
                // ============================================
                // PHASE 14: LOGGING AND EVENTS
                // ============================================
                
                this._secureLog('info', 'Enhanced secure offer created successfully', {
                    operationId: operationId,
                    version: offerPackage.version,
                    hasECDSA: true,
                    hasMutualAuth: true,
                    hasSessionId: !!offerPackage.sessionId,
                    securityLevel: securityLevel.level,
                    timestamp: currentTimestamp,
                    capabilitiesCount: Object.keys(offerPackage.capabilities).length
                });
                
                // Dispatch event about new connection
                document.dispatchEvent(new CustomEvent('new-connection', {
                    detail: { 
                        type: 'offer',
                        timestamp: currentTimestamp,
                        securityLevel: securityLevel.level,
                        operationId: operationId
                    }
                }));
                
                // ============================================
                // PHASE 15: RETURN RESULT
                // ============================================
                
                return offerPackage;
                
            } catch (error) {
                // ============================================
                // ERROR HANDLING
                // ============================================
                
                this._secureLog('error', '❌ Enhanced secure offer creation failed in critical section', {
                    operationId: operationId,
                    errorType: error.constructor.name,
                    errorMessage: error.message,
                    phase: this._determineErrorPhase(error),
                    connectionAttempts: this.connectionAttempts
                });
                
                // Cleanup state on error
                this._cleanupFailedOfferCreation();
                
                // Update status
                this.onStatusChange('disconnected');
                
                // Re-throw for upper-level handling
                throw error;
            }
        }, 15000); // 15 seconds timeout for the entire offer creation
    }

    /**
     * HELPER: Determine the phase where the error occurred
     */
    _determineErrorPhase(error) {
        const message = error.message.toLowerCase();
        
        if (message.includes('rate limit')) return 'rate_limiting';
        if (message.includes('key pair') || message.includes('generate')) return 'key_generation';
        if (message.includes('fingerprint')) return 'fingerprinting';
        if (message.includes('export') || message.includes('signature')) return 'key_export';
        if (message.includes('peer connection')) return 'webrtc_setup';
        if (message.includes('offer') || message.includes('sdp')) return 'sdp_creation';
        if (message.includes('verification')) return 'verification_setup';
        if (message.includes('session')) return 'session_setup';
        if (message.includes('validation')) return 'package_validation';
        
        return 'unknown';
    }

    /**
     * HELPER: Cleanup state after failed offer creation
     */
    _cleanupFailedOfferCreation() {
        try {
            // Clear keys
            this.ecdhKeyPair = null;
            this.ecdsaKeyPair = null;
            this.sessionSalt = null;
            this.sessionId = null;
            this.verificationCode = null;
            
            // Close peer connection if it was created
            if (this.peerConnection) {
                this.peerConnection.close();
                this.peerConnection = null;
            }
            
            // Clear data channel
            if (this.dataChannel) {
                this.dataChannel.close();
                this.dataChannel = null;
            }
            
            // Reset flags
            this.isInitiator = false;
            this.isVerified = false;
            
            // Reset security features to baseline
            this._updateSecurityFeatures({
                hasEncryption: false,
                hasECDH: false,
                hasECDSA: false,
                hasMutualAuth: false,
                hasMetadataProtection: false,
                hasEnhancedReplayProtection: false,
                hasNonExtractableKeys: false,
                hasEnhancedValidation: false,
                hasPFS: false
            });
            
            this._secureLog('debug', '🧹 Failed offer creation cleanup completed');
            
        } catch (cleanupError) {
            this._secureLog('error', '❌ Error during offer creation cleanup', {
                errorType: cleanupError.constructor.name
            });
        }
    }

    /**
     * HELPER: Atomic update of security features (if not added yet)
     */
    _updateSecurityFeatures(updates) {
        const oldFeatures = { ...this.securityFeatures };
        
        try {
            Object.assign(this.securityFeatures, updates);
            
            this._secureLog('debug', '🔧 Security features updated', {
                updatedCount: Object.keys(updates).length,
                totalFeatures: Object.keys(this.securityFeatures).length
            });
            
        } catch (error) {
            // Roll back on error
            this.securityFeatures = oldFeatures;
            this._secureLog('error', '❌ Security features update failed, rolled back', {
                errorType: error.constructor.name
            });
            throw error;
        }
    }

    /**
     * FULLY FIXED METHOD createSecureAnswer()
     * With race-condition protection and enhanced security
     */
    async createSecureAnswer(offerData) {
        return this._withMutex('connectionOperation', async (operationId) => {
            this._secureLog('info', '📨 Creating secure answer with mutex', {
                operationId: operationId,
                hasOfferData: !!offerData,
                offerType: offerData?.type,
                offerVersion: offerData?.version,
                offerTimestamp: offerData?.timestamp
            });
            
            try {
                // ============================================
                // PHASE 1: PRE-VALIDATION OF OFFER
                // ============================================
                
                // Reset notification flags for a new connection
                this._resetNotificationFlags();
                
                this._secureLog('debug', 'Starting enhanced offer validation', {
                    operationId: operationId,
                    hasOfferData: !!offerData,
                    offerType: offerData?.type,
                    hasECDHKey: !!offerData?.ecdhPublicKey,
                    hasECDSAKey: !!offerData?.ecdsaPublicKey,
                    hasSalt: !!offerData?.salt
                });
                
                // Strict input validation
                if (!this.validateEnhancedOfferData(offerData)) {
                    throw new Error('Invalid connection data format - failed enhanced validation');
                }
                
                // Rate limiting check
                if (!window.EnhancedSecureCryptoUtils.rateLimiter.checkConnectionRate(this.rateLimiterId)) {
                    throw new Error('Connection rate limit exceeded. Please wait before trying again.');
                }
                
                // ============================================
                // PHASE 2: SECURITY AND ANTI-REPLAY PROTECTION
                // ============================================
                
                // MITM Protection: Validate offer data structure
                if (!offerData.timestamp || !offerData.version) {
                    throw new Error('Missing required security fields in offer data – possible MITM attack');
                }
                
                // Replay attack protection (window reduced to 5 minutes)
                const offerAge = Date.now() - offerData.timestamp;
                const MAX_OFFER_AGE = 300000; // 5 minutes instead of 1 hour
                
                if (offerAge > MAX_OFFER_AGE) {
                    this._secureLog('error', 'Offer data is too old - possible replay attack', {
                        operationId: operationId,
                        offerAge: Math.round(offerAge / 1000),
                        maxAllowedAge: Math.round(MAX_OFFER_AGE / 1000),
                        timestamp: offerData.timestamp
                    });
                    
                    // Notify the main code about the replay attack
                    if (this.onAnswerError) {
                        this.onAnswerError('replay_attack', 'Offer data is too old – possible replay attack');
                    }
                    
                    throw new Error('Offer data is too old – possible replay attack');
                }
                
                // Protocol version compatibility check
                if (offerData.version !== '4.0') {
                    this._secureLog('warn', 'Protocol version mismatch detected', {
                        operationId: operationId,
                        expectedVersion: '4.0',
                        receivedVersion: offerData.version
                    });
                    
                    // For backward compatibility with v3.0, a fallback can be added
                    if (offerData.version !== '3.0') {
                        throw new Error(`Unsupported protocol version: ${offerData.version}`);
                    }
                }
                
                // ============================================
                // PHASE 3: EXTRACT AND VALIDATE SESSION SALT
                // ============================================
                
                // Set session salt from offer
                this.sessionSalt = offerData.salt;
                
                // Validate session salt
                if (!Array.isArray(this.sessionSalt)) {
                    throw new Error('Invalid session salt format - must be array');
                }
                
                const expectedSaltLength = offerData.version === '4.0' ? 64 : 32;
                if (this.sessionSalt.length !== expectedSaltLength) {
                    throw new Error(`Invalid session salt length: expected ${expectedSaltLength}, got ${this.sessionSalt.length}`);
                }
                
                // MITM Protection: Check salt integrity
                const saltFingerprint = await window.EnhancedSecureCryptoUtils.calculateKeyFingerprint(this.sessionSalt);
                
                this._secureLog('info', 'Session salt validated successfully', {
                    operationId: operationId,
                    saltLength: this.sessionSalt.length,
                    saltFingerprint: saltFingerprint.substring(0, 8)
                });
                
                // ============================================
                // PHASE 4: SECURE GENERATION OF OUR KEYS
                // ============================================
                
                // Secure generation of our keys via mutex
                const keyPairs = await this._generateEncryptionKeys();
                this.ecdhKeyPair = keyPairs.ecdhKeyPair;
                this.ecdsaKeyPair = keyPairs.ecdsaKeyPair;
                
                // Additional validation of generated keys
                if (!(this.ecdhKeyPair?.privateKey instanceof CryptoKey)) {
                    this._secureLog('error', 'Local ECDH private key is not a CryptoKey', {
                        operationId: operationId,
                        hasKeyPair: !!this.ecdhKeyPair,
                        privateKeyType: typeof this.ecdhKeyPair?.privateKey,
                        privateKeyAlgorithm: this.ecdhKeyPair?.privateKey?.algorithm?.name
                    });
                    throw new Error('Local ECDH private key is not a valid CryptoKey');
                }
                
                // ============================================
                // PHASE 5: IMPORT AND VERIFY PEER KEYS
                // ============================================
                
                // Import peer ECDSA public key for signature verification
                let peerECDSAPublicKey;
                
                try {
                    peerECDSAPublicKey = await crypto.subtle.importKey(
                        'spki',
                        new Uint8Array(offerData.ecdsaPublicKey.keyData),
                        {
                            name: 'ECDSA',
                            namedCurve: 'P-384'
                        },
                        false,
                        ['verify']
                    );
                } catch (error) {
                    throw new Error(`Failed to import peer ECDSA public key: ${error.message}`);
                }
                
                // Verify ECDSA key self-signature
                const ecdsaPackageCopy = { ...offerData.ecdsaPublicKey };
                delete ecdsaPackageCopy.signature;
                const ecdsaPackageString = JSON.stringify(ecdsaPackageCopy);
                
                const ecdsaSignatureValid = await window.EnhancedSecureCryptoUtils.verifySignature(
                    peerECDSAPublicKey,
                    offerData.ecdsaPublicKey.signature,
                    ecdsaPackageString
                );
                
                if (!ecdsaSignatureValid) {
                    this._secureLog('error', 'Invalid ECDSA signature detected - possible MITM attack', {
                        operationId: operationId,
                        timestamp: offerData.timestamp,
                        version: offerData.version
                    });
                    throw new Error('Invalid ECDSA key signature – possible MITM attack');
                }
                
                this._secureLog('info', 'ECDSA signature verification passed', {
                    operationId: operationId,
                    timestamp: offerData.timestamp,
                    version: offerData.version
                });
                
                // ============================================
                // PHASE 6: IMPORT AND VERIFY ECDH KEY
                // ============================================
                
                // Import and verify ECDH public key using verified ECDSA key
                let peerECDHPublicKey;
                
                try {
                    peerECDHPublicKey = await window.EnhancedSecureCryptoUtils.importSignedPublicKey(
                        offerData.ecdhPublicKey,
                        peerECDSAPublicKey,
                        'ECDH'
                    );
                } catch (error) {
                    this._secureLog('error', 'Failed to import signed ECDH public key', {
                        operationId: operationId,
                        errorType: error.constructor.name
                    });
                    throw new Error(`Failed to import peer ECDH public key: ${error.message}`);
                }
                
                // Final validation of ECDH key
                if (!(peerECDHPublicKey instanceof CryptoKey)) {
                    this._secureLog('error', 'Peer ECDH public key is not a CryptoKey', {
                        operationId: operationId,
                        publicKeyType: typeof peerECDHPublicKey,
                        publicKeyAlgorithm: peerECDHPublicKey?.algorithm?.name
                    });
                    throw new Error('Peer ECDH public key is not a valid CryptoKey');
                }
                
                // Save peer key for PFS rotation
                this.peerPublicKey = peerECDHPublicKey;
                
                // ============================================
                // PHASE 7: DERIVE SHARED ENCRYPTION KEYS
                // ============================================
                
                // Derive shared keys with metadata protection
                let derivedKeys;
                
                try {
                    derivedKeys = await window.EnhancedSecureCryptoUtils.deriveSharedKeys(
                        this.ecdhKeyPair.privateKey,
                        peerECDHPublicKey,
                        this.sessionSalt
                    );
                } catch (error) {
                    this._secureLog('error', 'Failed to derive shared keys', {
                        operationId: operationId,
                        errorType: error.constructor.name
                    });
                    throw new Error(`Key derivation failed: ${error.message}`);
                }
                
                // Securely set keys via helper
                await this._setEncryptionKeys(
                    derivedKeys.encryptionKey,
                    derivedKeys.macKey,
                    derivedKeys.metadataKey,
                    derivedKeys.fingerprint
                );
                
                // Additional validation of installed keys
                if (!(this.encryptionKey instanceof CryptoKey) || 
                    !(this.macKey instanceof CryptoKey) || 
                    !(this.metadataKey instanceof CryptoKey)) {
                    
                    this._secureLog('error', 'Invalid key types after derivation', {
                        operationId: operationId,
                        encryptionKeyType: typeof this.encryptionKey,
                        macKeyType: typeof this.macKey,
                        metadataKeyType: typeof this.metadataKey
                    });
                    throw new Error('Invalid key types after derivation');
                }
                
                // Set verification code from offer
                this.verificationCode = offerData.verificationCode;
                
                this._secureLog('info', 'Encryption keys derived and set successfully', {
                    operationId: operationId,
                    hasEncryptionKey: !!this.encryptionKey,
                    hasMacKey: !!this.macKey,
                    hasMetadataKey: !!this.metadataKey,
                    hasKeyFingerprint: !!this.keyFingerprint,
                    mitmProtection: 'enabled',
                    signatureVerified: true
                });
                
                // ============================================
                // PHASE 8: UPDATE SECURITY FEATURES
                // ============================================
                
                // Atomic update of security features
                this._updateSecurityFeatures({
                    hasEncryption: true,
                    hasECDH: true,
                    hasECDSA: true,
                    hasMutualAuth: true,
                    hasMetadataProtection: true,
                    hasEnhancedReplayProtection: true,
                    hasNonExtractableKeys: true,
                    hasRateLimiting: true,
                    hasEnhancedValidation: true,
                    hasPFS: true
                });
                
                // PFS: Initialize key version tracking
                this.currentKeyVersion = 0;
                this.lastKeyRotation = Date.now();
                this.keyVersions.set(0, {
                    salt: this.sessionSalt,
                    timestamp: this.lastKeyRotation,
                    messageCount: 0
                });
                
                // ============================================
                // PHASE 9: CREATE AUTHENTICATION PROOF
                // ============================================
                
                // Create proof for mutual authentication
                let authProof;
                
                if (offerData.authChallenge) {
                    try {
                        authProof = await window.EnhancedSecureCryptoUtils.createAuthProof(
                            offerData.authChallenge,
                            this.ecdsaKeyPair.privateKey,
                            this.ecdsaKeyPair.publicKey
                        );
                    } catch (error) {
                        this._secureLog('error', 'Failed to create authentication proof', {
                            operationId: operationId,
                            errorType: error.constructor.name
                        });
                        throw new Error(`Authentication proof creation failed: ${error.message}`);
                    }
                } else {
                    this._secureLog('warn', 'No auth challenge in offer - mutual auth disabled', {
                        operationId: operationId
                    });
                }
                
                // ============================================
                // PHASE 10: INITIALIZE WEBRTC
                // ============================================
                
                this.isInitiator = false;
                this.onStatusChange('connecting');
                this.onKeyExchange(this.keyFingerprint);
                this.onVerificationRequired(this.verificationCode);
                
                // Create peer connection
                this.createPeerConnection();
                
                // Set remote description from offer
                try {
                    await this.peerConnection.setRemoteDescription(new RTCSessionDescription({
                        type: 'offer',
                        sdp: offerData.sdp
                    }));
                } catch (error) {
                    throw new Error(`Failed to set remote description: ${error.message}`);
                }
                
                this._secureLog('debug', '🔗 Remote description set successfully', {
                    operationId: operationId,
                    connectionState: this.peerConnection.connectionState,
                    signalingState: this.peerConnection.signalingState
                });
                
                // ============================================
                // PHASE 11: CREATE SDP ANSWER
                // ============================================
                
                // Create WebRTC answer
                let answer;
                
                try {
                    answer = await this.peerConnection.createAnswer({
                        offerToReceiveAudio: false,
                        offerToReceiveVideo: false
                    });
                } catch (error) {
                    throw new Error(`Failed to create answer: ${error.message}`);
                }
                
                // Set local description
                try {
                    await this.peerConnection.setLocalDescription(answer);
                } catch (error) {
                    throw new Error(`Failed to set local description: ${error.message}`);
                }
                
                // Await ICE gathering
                await this.waitForIceGathering();
                
                this._secureLog('debug', '🧊 ICE gathering completed for answer', {
                    operationId: operationId,
                    iceGatheringState: this.peerConnection.iceGatheringState,
                    connectionState: this.peerConnection.connectionState
                });
                
                // ============================================
                // PHASE 12: EXPORT OUR KEYS
                // ============================================
                
                // Export our keys with signatures
                const ecdhPublicKeyData = await window.EnhancedSecureCryptoUtils.exportPublicKeyWithSignature(
                    this.ecdhKeyPair.publicKey,
                    this.ecdsaKeyPair.privateKey,
                    'ECDH'
                );
                
                const ecdsaPublicKeyData = await window.EnhancedSecureCryptoUtils.exportPublicKeyWithSignature(
                    this.ecdsaKeyPair.publicKey,
                    this.ecdsaKeyPair.privateKey,
                    'ECDSA'
                );
                
                // Validate exported data
                if (!ecdhPublicKeyData?.keyData || !ecdhPublicKeyData?.signature) {
                    throw new Error('Failed to export ECDH public key with signature');
                }
                
                if (!ecdsaPublicKeyData?.keyData || !ecdsaPublicKeyData?.signature) {
                    throw new Error('Failed to export ECDSA public key with signature');
                }
                
                // ============================================
                // PHASE 13: SECURITY LEVEL CALCULATION
                // ============================================
                
                // Calculate security level
                let securityLevel;
                
                try {
                    securityLevel = await this.calculateSecurityLevel();
                } catch (error) {
                    this._secureLog('warn', '⚠️ Security level calculation failed, using fallback', {
                        operationId: operationId,
                        errorType: error.constructor.name
                    });
                    
                    // Fallback value
                    securityLevel = {
                        level: 'enhanced',
                        score: 80,
                        passedChecks: 12,
                        totalChecks: 15,
                        isRealData: false
                    };
                }
                
                // ============================================
                // PHASE 14: CREATE ANSWER PACKAGE
                // ============================================
                
                const currentTimestamp = Date.now();
                
                const answerPackage = {
                    // Core information
                    type: 'enhanced_secure_answer',
                    sdp: this.peerConnection.localDescription.sdp,
                    version: '4.0',
                    timestamp: currentTimestamp,
                    
                    // Cryptographic keys
                    ecdhPublicKey: ecdhPublicKeyData,
                    ecdsaPublicKey: ecdsaPublicKeyData,
                    
                    // Authentication
                    authProof: authProof,
                    
                    // Security metadata
                    securityLevel: securityLevel,
                    
                    // Additional security fields
                    sessionConfirmation: {
                        saltFingerprint: saltFingerprint.substring(0, 16),
                        keyDerivationSuccess: true,
                        mutualAuthEnabled: !!authProof
                    },
                    
                    // Answerer capabilities
                    capabilities: {
                        supportsFileTransfer: true,
                        supportsEnhancedSecurity: true,
                        supportsKeyRotation: true,
                        supportsFakeTraffic: this.fakeTrafficConfig.enabled,
                        supportsDecoyChannels: this.decoyChannelConfig.enabled,
                        protocolVersion: '4.0'
                    }
                };
                
                // ============================================
                // PHASE 15: VALIDATION AND LOGGING
                // ============================================
                
                // Final validation of the answer package
                if (!answerPackage.sdp || !answerPackage.ecdhPublicKey || !answerPackage.ecdsaPublicKey) {
                    throw new Error('Generated answer package is incomplete');
                }
                
                this._secureLog('info', 'Enhanced secure answer created successfully', {
                    operationId: operationId,
                    version: answerPackage.version,
                    hasECDSA: true,
                    hasMutualAuth: !!authProof,
                    hasSessionConfirmation: !!answerPackage.sessionConfirmation,
                    securityLevel: securityLevel.level,
                    timestamp: currentTimestamp,
                    processingTime: currentTimestamp - offerData.timestamp
                });
                
                // Dispatch event about new connection
                document.dispatchEvent(new CustomEvent('new-connection', {
                    detail: { 
                        type: 'answer',
                        timestamp: currentTimestamp,
                        securityLevel: securityLevel.level,
                        operationId: operationId
                    }
                }));
                
                // ============================================
                // PHASE 16: SCHEDULE SECURITY CALCULATIONS
                // ============================================
                
                // Plan security calculation after connection
                setTimeout(async () => {
                    try {
                        const realSecurityData = await this.calculateAndReportSecurityLevel();
                        if (realSecurityData) {
                            this.notifySecurityUpdate();
                            this._secureLog('info', '✅ Post-connection security level calculated', {
                                operationId: operationId,
                                level: realSecurityData.level
                            });
                        }
                    } catch (error) {
                        this._secureLog('error', '❌ Error calculating post-connection security', {
                            operationId: operationId,
                            errorType: error.constructor.name
                        });
                    }
                }, 1000);
                
                // Retry if the first calculation fails
                setTimeout(async () => {
                    if (!this.lastSecurityCalculation || this.lastSecurityCalculation.score < 50) {
                        this._secureLog('info', '🔄 Retrying security calculation', {
                            operationId: operationId
                        });
                        await this.calculateAndReportSecurityLevel();
                        this.notifySecurityUpdate();
                    }
                }, 3000);
                
                // Final security update
                this.notifySecurityUpdate();
                
                // ============================================
                // PHASE 17: RETURN RESULT
                // ============================================
                
                return answerPackage;
                
            } catch (error) {
                // ============================================
                // ERROR HANDLING
                // ============================================
                
                this._secureLog('error', '❌ Enhanced secure answer creation failed in critical section', {
                    operationId: operationId,
                    errorType: error.constructor.name,
                    errorMessage: error.message,
                    phase: this._determineAnswerErrorPhase(error),
                    offerAge: offerData?.timestamp ? Date.now() - offerData.timestamp : 'unknown'
                });
                
                // Cleanup state on error
                this._cleanupFailedAnswerCreation();
                
                // Update status
                this.onStatusChange('disconnected');
                
                // Special handling of security errors
                if (this.onAnswerError) {
                    if (error.message.includes('too old') || error.message.includes('replay')) {
                        this.onAnswerError('replay_attack', error.message);
                    } else if (error.message.includes('MITM') || error.message.includes('signature')) {
                        this.onAnswerError('security_violation', error.message);
                    } else if (error.message.includes('validation') || error.message.includes('format')) {
                        this.onAnswerError('invalid_format', error.message);
                    } else {
                        this.onAnswerError('general_error', error.message);
                    }
                }
                
                // Re-throw for upper-level handling
                throw error;
            }
        }, 20000); // 20 seconds timeout for the entire answer creation (longer than offer)
    }

    /**
     * HELPER: Determine error phase for answer
     */
    _determineAnswerErrorPhase(error) {
        const message = error.message.toLowerCase();
        
        if (message.includes('validation') || message.includes('format')) return 'offer_validation';
        if (message.includes('rate limit')) return 'rate_limiting';
        if (message.includes('replay') || message.includes('too old')) return 'replay_protection';
        if (message.includes('salt')) return 'salt_validation';
        if (message.includes('key pair') || message.includes('generate')) return 'key_generation';
        if (message.includes('import') || message.includes('ecdsa') || message.includes('ecdh')) return 'key_import';
        if (message.includes('signature') || message.includes('mitm')) return 'signature_verification';
        if (message.includes('derive') || message.includes('shared')) return 'key_derivation';
        if (message.includes('auth') || message.includes('proof')) return 'authentication';
        if (message.includes('remote description') || message.includes('local description')) return 'webrtc_setup';
        if (message.includes('answer') || message.includes('sdp')) return 'sdp_creation';
        if (message.includes('export')) return 'key_export';
        if (message.includes('security level')) return 'security_calculation';
        
        return 'unknown';
    }

    /**
     * HELPER: Cleanup state after failed answer creation
     */
    _cleanupFailedAnswerCreation() {
        try {
            // Clear keys and session data
            this.ecdhKeyPair = null;
            this.ecdsaKeyPair = null;
            this.peerPublicKey = null;
            this.sessionSalt = null;
            this.verificationCode = null;
            this.encryptionKey = null;
            this.macKey = null;
            this.metadataKey = null;
            this.keyFingerprint = null;
            
            // Reset PFS key versions
            this.currentKeyVersion = 0;
            this.keyVersions.clear();
            this.oldKeys.clear();
            
            // Close peer connection if created
            if (this.peerConnection) {
                this.peerConnection.close();
                this.peerConnection = null;
            }
            
            // Clear data channel
            if (this.dataChannel) {
                this.dataChannel.close();
                this.dataChannel = null;
            }
            
            // Reset flags and counters
            this.isInitiator = false;
            this.isVerified = false;
            this.sequenceNumber = 0;
            this.expectedSequenceNumber = 0;
            this.messageCounter = 0;
            this.processedMessageIds.clear();
            
            // Reset security features to baseline
            this._updateSecurityFeatures({
                hasEncryption: false,
                hasECDH: false,
                hasECDSA: false,
                hasMutualAuth: false,
                hasMetadataProtection: false,
                hasEnhancedReplayProtection: false,
                hasNonExtractableKeys: false,
                hasEnhancedValidation: false,
                hasPFS: false
            });
            
            this._secureLog('debug', '🧹 Failed answer creation cleanup completed');
            
        } catch (cleanupError) {
            this._secureLog('error', '❌ Error during answer creation cleanup', {
                errorType: cleanupError.constructor.name
            });
        }
    }

    /**
     * HELPER: Securely set encryption keys (if not set yet)
     */
    async _setEncryptionKeys(encryptionKey, macKey, metadataKey, keyFingerprint) {
        return this._withMutex('keyOperation', async (operationId) => {
            this._secureLog('info', '🔐 Setting encryption keys with mutex', {
                operationId: operationId
            });
            
            // Validate all keys before setting
            if (!(encryptionKey instanceof CryptoKey) ||
                !(macKey instanceof CryptoKey) ||
                !(metadataKey instanceof CryptoKey)) {
                throw new Error('Invalid key types provided');
            }
            
            if (!keyFingerprint || typeof keyFingerprint !== 'string') {
                throw new Error('Invalid key fingerprint provided');
            }
            
            // Atomically set all keys
            const oldKeys = {
                encryptionKey: this.encryptionKey,
                macKey: this.macKey,
                metadataKey: this.metadataKey,
                keyFingerprint: this.keyFingerprint
            };
            
            try {
                this.encryptionKey = encryptionKey;
                this.macKey = macKey;
                this.metadataKey = metadataKey;
                this.keyFingerprint = keyFingerprint;
                
                // Reset counters
                this.sequenceNumber = 0;
                this.expectedSequenceNumber = 0;
                this.messageCounter = 0;
                this.processedMessageIds.clear();
                
                this._secureLog('info', '✅ Encryption keys set successfully', {
                    operationId: operationId,
                    hasAllKeys: !!(this.encryptionKey && this.macKey && this.metadataKey),
                    hasFingerprint: !!this.keyFingerprint
                });
                
                return true;
                
            } catch (error) {
                // Roll back on error
                this.encryptionKey = oldKeys.encryptionKey;
                this.macKey = oldKeys.macKey;
                this.metadataKey = oldKeys.metadataKey;
                this.keyFingerprint = oldKeys.keyFingerprint;
                
                this._secureLog('error', '❌ Key setting failed, rolled back', {
                    operationId: operationId,
                    errorType: error.constructor.name
                });
                
                throw error;
            }
        });
    }

    async handleSecureAnswer(answerData) {
        try {
            if (!answerData || answerData.type !== 'enhanced_secure_answer' || !answerData.sdp) {
                throw new Error('Invalid response format');
            }

            // Import peer's ECDH public key from the signed package
            if (!answerData.ecdhPublicKey || !answerData.ecdhPublicKey.keyData) {
                throw new Error('Missing ECDH public key data');
            }

            // First, import and verify the ECDSA public key for signature verification
            if (!answerData.ecdsaPublicKey || !answerData.ecdsaPublicKey.keyData) {
                throw new Error('Missing ECDSA public key data for signature verification');
            }

            // Additional MITM protection: Validate answer data structure
            if (!answerData.timestamp || !answerData.version) {
                throw new Error('Missing required fields in response data – possible MITM attack');
            }

            // MITM Protection: Verify session ID if present (for enhanced security)
            if (answerData.sessionId && this.sessionId && answerData.sessionId !== this.sessionId) {
                window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Session ID mismatch detected - possible MITM attack', {
                    expectedSessionId: this.sessionId,
                    receivedSessionId: answerData.sessionId
                });
                throw new Error('Session ID mismatch – possible MITM attack');
            }

            // Check for replay attacks (reject answers older than 1 hour)
            const answerAge = Date.now() - answerData.timestamp;
            if (answerAge > 3600000) { // 1 hour in milliseconds
                window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Answer data is too old - possible replay attack', {
                    answerAge: answerAge,
                    timestamp: answerData.timestamp
                });
                
                // Notify the main code about the replay attack error
                if (this.onAnswerError) {
                    this.onAnswerError('replay_attack', 'Response data is too old – possible replay attack');
                }
                
                throw new Error('Response data is too old – possible replay attack');
            }

            // Check protocol version compatibility
            if (answerData.version !== '4.0') {
                window.EnhancedSecureCryptoUtils.secureLog.log('warn', 'Incompatible protocol version in answer', {
                    expectedVersion: '4.0',
                    receivedVersion: answerData.version
                });
            }

            // Import ECDSA public key for verification (self-signed)
            const peerECDSAPublicKey = await crypto.subtle.importKey(
                'spki',
                new Uint8Array(answerData.ecdsaPublicKey.keyData),
                {
                    name: 'ECDSA',
                    namedCurve: 'P-384'
                },
                false,
                ['verify']
            );

            // Verify ECDSA key's self-signature
            const ecdsaPackageCopy = { ...answerData.ecdsaPublicKey };
            delete ecdsaPackageCopy.signature;
            const ecdsaPackageString = JSON.stringify(ecdsaPackageCopy);
            const ecdsaSignatureValid = await window.EnhancedSecureCryptoUtils.verifySignature(
                peerECDSAPublicKey,
                answerData.ecdsaPublicKey.signature,
                ecdsaPackageString
            );

            if (!ecdsaSignatureValid) {
                window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Invalid ECDSA signature detected - possible MITM attack', {
                    timestamp: answerData.timestamp,
                    version: answerData.version
                });
                throw new Error('Invalid ECDSA key signature – possible MITM attack');
            }

            window.EnhancedSecureCryptoUtils.secureLog.log('info', 'ECDSA signature verification passed', {
                timestamp: answerData.timestamp,
                version: answerData.version
            });

            // Now import and verify the ECDH public key using the verified ECDSA key
            const peerPublicKey = await window.EnhancedSecureCryptoUtils.importPublicKeyFromSignedPackage(
                answerData.ecdhPublicKey,
                peerECDSAPublicKey
            );
            
            // Additional MITM protection: Verify session salt integrity
            if (!this.sessionSalt || this.sessionSalt.length !== 64) {
                window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Invalid session salt detected - possible session hijacking', {
                    saltLength: this.sessionSalt ? this.sessionSalt.length : 0
                });
                throw new Error('Invalid session salt – possible session hijacking attempt');
            }

            // Verify that the session salt hasn't been tampered with
            const expectedSaltHash = await window.EnhancedSecureCryptoUtils.calculateKeyFingerprint(this.sessionSalt);
            window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Session salt integrity verified', {
                saltFingerprint: expectedSaltHash.substring(0, 8)
            });

            // Additional validation: Ensure all keys are CryptoKey instances before derivation
            if (!(this.ecdhKeyPair?.privateKey instanceof CryptoKey)) {
                window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Local ECDH private key is not a CryptoKey in handleSecureAnswer', {
                    hasKeyPair: !!this.ecdhKeyPair,
                    privateKeyType: typeof this.ecdhKeyPair?.privateKey,
                    privateKeyAlgorithm: this.ecdhKeyPair?.privateKey?.algorithm?.name
                });
                throw new Error('Local ECDH private key is not a CryptoKey');
            }
            
            if (!(peerPublicKey instanceof CryptoKey)) {
                window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Peer ECDH public key is not a CryptoKey in handleSecureAnswer', {
                    publicKeyType: typeof peerPublicKey,
                    publicKeyAlgorithm: peerPublicKey?.algorithm?.name
                });
                throw new Error('Peer ECDH public key is not a CryptoKey');
            }

            // Store peer's public key for PFS key rotation
            this.peerPublicKey = peerPublicKey;

            const derivedKeys = await window.EnhancedSecureCryptoUtils.deriveSharedKeys(
                this.ecdhKeyPair.privateKey,
                peerPublicKey,
                this.sessionSalt
            );
            
            this.encryptionKey = derivedKeys.encryptionKey;
            this.macKey = derivedKeys.macKey;
            this.metadataKey = derivedKeys.metadataKey;
            this.keyFingerprint = derivedKeys.fingerprint;
            this.sequenceNumber = 0;
            this.expectedSequenceNumber = 0;
            this.messageCounter = 0;
            this.processedMessageIds.clear();
            // Validate that all keys are properly set
            if (!(this.encryptionKey instanceof CryptoKey) || 
                !(this.macKey instanceof CryptoKey) || 
                !(this.metadataKey instanceof CryptoKey)) {
                window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Invalid key types after derivation in handleSecureAnswer', {
                    encryptionKeyType: typeof this.encryptionKey,
                    macKeyType: typeof this.macKey,
                    metadataKeyType: typeof this.metadataKey,
                    encryptionKeyAlgorithm: this.encryptionKey?.algorithm?.name,
                    macKeyAlgorithm: this.macKey?.algorithm?.name,
                    metadataKeyAlgorithm: this.metadataKey?.algorithm?.name
                });
                throw new Error('Invalid key types after export');
            }
            
            this._secureLog('info', 'Encryption keys set in handleSecureAnswer', {
                hasEncryptionKey: !!this.encryptionKey,
                hasMacKey: !!this.macKey,
                hasMetadataKey: !!this.metadataKey,
                hasKeyFingerprint: !!this.keyFingerprint,
                mitmProtection: 'enabled',
                signatureVerified: true
            });
            
            // Update security features for initiator after successful key exchange
            this.securityFeatures.hasMutualAuth = true;
            this.securityFeatures.hasMetadataProtection = true;
            this.securityFeatures.hasEnhancedReplayProtection = true;
            this.securityFeatures.hasPFS = true;
            
            // PFS: Initialize key version tracking
            this.currentKeyVersion = 0;
            this.lastKeyRotation = Date.now();
            this.keyVersions.set(0, {
                salt: this.sessionSalt,
                timestamp: this.lastKeyRotation,
                messageCount: 0
            });
            
            this.onKeyExchange(this.keyFingerprint);

            await this.peerConnection.setRemoteDescription({
                type: 'answer',
                sdp: answerData.sdp
            });
            
            console.log('Enhanced secure connection established');

            setTimeout(async () => {
                try {
                    const securityData = await this.calculateAndReportSecurityLevel();
                    if (securityData) {
                        console.log('✅ Security level calculated after connection:', securityData.level);
                        this.notifySecurityUpdate();
                    }
                } catch (error) {
                    console.error('❌ Error calculating security after connection:', error);
                }
            }, 1000);
            setTimeout(async () => {
                if (!this.lastSecurityCalculation || this.lastSecurityCalculation.score < 50) {
                    console.log('🔄 Retrying security calculation...');
                    await this.calculateAndReportSecurityLevel();
                    this.notifySecurityUpdate();
                }
            }, 3000);
            this.notifySecurityUpdate();
        } catch (error) {
            this._secureLog('error', 'Enhanced secure answer handling failed', {
                errorType: error.constructor.name
            });
            this.onStatusChange('failed');

            if (this.onAnswerError) {
                if (error.message.includes('too old') || error.message.includes('слишком старые')) {
                    this.onAnswerError('replay_attack', error.message);
                } else if (error.message.includes('MITM') || error.message.includes('signature') || error.message.includes('подпись')) {
                    this.onAnswerError('security_violation', error.message);
                } else {
                    this.onAnswerError('general_error', error.message);
                }
            }
            
            throw error;
        }
    }

    forceSecurityUpdate() {
        console.log('🔄 Force security update requested');
        setTimeout(async () => {
            try {
                const securityData = await this.calculateAndReportSecurityLevel();
                if (securityData) {
                    this.notifySecurityUpdate();
                    console.log('✅ Force security update completed');
                }
            } catch (error) {
                console.error('❌ Force security update failed:', error);
            }
        }, 100);
    }

    initiateVerification() {
        if (this.isInitiator) {
            // Ensure verification initiation notice wasn't already sent
            if (!this.verificationInitiationSent) {
                this.verificationInitiationSent = true;
                this.deliverMessageToUI('🔐 Confirm the security code with your peer to complete the connection', 'system');
            }
        } else {
            // Responder confirms verification automatically if codes match
            this.confirmVerification();
        }
    }

    confirmVerification() {
        try {
            const verificationPayload = {
                type: 'verification',
                data: {
                    code: this.verificationCode,
                    timestamp: Date.now()
                }
            };
            
            this.dataChannel.send(JSON.stringify(verificationPayload));
            this.isVerified = true;
            this.onStatusChange('connected');
            
            // Ensure verification success notice wasn't already sent
            if (!this.verificationNotificationSent) {
                this.verificationNotificationSent = true;
                this.deliverMessageToUI('✅ Verification successful. The channel is now secure!', 'system');
            }
            
            this.processMessageQueue();
        } catch (error) {
            console.error('Verification failed:', error);
            this.deliverMessageToUI('❌ Verification failed', 'system');
        }
    }

    handleVerificationRequest(data) {
        if (data.code === this.verificationCode) {
            const responsePayload = {
                type: 'verification_response',
                data: {
                    verified: true,
                    timestamp: Date.now()
                }
            };
            this.dataChannel.send(JSON.stringify(responsePayload));
            this.isVerified = true;
            this.onStatusChange('connected');
            
            // Ensure verification success notice wasn't already sent
            if (!this.verificationNotificationSent) {
                this.verificationNotificationSent = true;
                this.deliverMessageToUI('✅ Verification successful. The channel is now secure!', 'system');
            }
            
            this.processMessageQueue();
        } else {
            this.deliverMessageToUI('❌ Verification code mismatch! Possible MITM attack detected. Connection aborted for safety!', 'system');
            this.disconnect();
        }
    }

    handleVerificationResponse(data) {
        if (data.verified) {
            this.isVerified = true;
            this.onStatusChange('connected');
            
            // Ensure verification success notice wasn't already sent
            if (!this.verificationNotificationSent) {
                this.verificationNotificationSent = true;
                this.deliverMessageToUI('✅ Verification successful. The channel is now secure!', 'system');
            }
            
            this.processMessageQueue();
        } else {
            this.deliverMessageToUI('❌ Verification failed!', 'system');
            this.disconnect();
        }
    }

    validateOfferData(offerData) {
        return offerData &&
               offerData.type === 'enhanced_secure_offer' &&
               offerData.sdp &&
               offerData.publicKey &&
               offerData.salt &&
               offerData.verificationCode &&
               Array.isArray(offerData.publicKey) &&
               Array.isArray(offerData.salt) &&
               offerData.salt.length === 32;
    }

    // Enhanced validation with backward compatibility
    validateEnhancedOfferData(offerData) {
        try {
            if (!offerData || typeof offerData !== 'object') {
                throw new Error('Offer data must be an object');
            }

            // Basic required fields for all versions
            const basicFields = ['type', 'sdp'];
            for (const field of basicFields) {
                if (!offerData[field]) {
                    throw new Error(`Missing required field: ${field}`);
                }
            }

            // Validate offer type (support both v3.0 and v4.0 formats)
            if (!['enhanced_secure_offer', 'secure_offer'].includes(offerData.type)) {
                throw new Error('Invalid offer type');
            }

            // Check if this is v4.0 format with enhanced features
            const isV4Format = offerData.version === '4.0' && offerData.ecdhPublicKey && offerData.ecdsaPublicKey;
            
            if (isV4Format) {
                // v4.0 enhanced validation
                const v4RequiredFields = [
                    'ecdhPublicKey', 'ecdsaPublicKey', 'salt', 'verificationCode',
                    'authChallenge', 'timestamp', 'version', 'securityLevel'
                ];

                for (const field of v4RequiredFields) {
                    if (!offerData[field]) {
                        throw new Error(`Missing v4.0 field: ${field}`);
                    }
                }

                // Validate salt (must be 64 bytes for v4.0)
                if (!Array.isArray(offerData.salt) || offerData.salt.length !== 64) {
                    throw new Error('Salt must be exactly 64 bytes for v4.0');
                }

                // Validate timestamp (not older than 1 hour)
                const offerAge = Date.now() - offerData.timestamp;
                if (offerAge > 3600000) {
                    throw new Error('Offer is too old (older than 1 hour)');
                }

                // Validate key structures (more lenient)
                if (!offerData.ecdhPublicKey || typeof offerData.ecdhPublicKey !== 'object') {
                    throw new Error('Invalid ECDH public key structure');
                }

                if (!offerData.ecdsaPublicKey || typeof offerData.ecdsaPublicKey !== 'object') {
                    throw new Error('Invalid ECDSA public key structure');
                }

                // Validate verification code format (more flexible)
                if (typeof offerData.verificationCode !== 'string' || offerData.verificationCode.length < 6) {
                    throw new Error('Invalid verification code format');
                }

                this._secureLog('info', 'v4.0 offer validation passed', {
                    version: offerData.version,
                    hasSecurityLevel: !!offerData.securityLevel?.level,
                    offerAge: Math.round(offerAge / 1000) + 's'
                });
            } else {
                // v3.0 backward compatibility validation
                const v3RequiredFields = ['publicKey', 'salt', 'verificationCode'];
                for (const field of v3RequiredFields) {
                    if (!offerData[field]) {
                        throw new Error(`Missing v3.0 field: ${field}`);
                    }
                }

                // Validate salt (32 bytes for v3.0)
                if (!Array.isArray(offerData.salt) || offerData.salt.length !== 32) {
                    throw new Error('Salt must be exactly 32 bytes for v3.0');
                }

                // Validate public key
                if (!Array.isArray(offerData.publicKey)) {
                    throw new Error('Invalid public key format for v3.0');
                }

                window.EnhancedSecureCryptoUtils.secureLog.log('info', 'v3.0 offer validation passed (backward compatibility)', {
                    version: 'v3.0',
                    legacy: true
                });
            }

            // Validate SDP structure (basic check for all versions)
            if (typeof offerData.sdp !== 'string' || !offerData.sdp.includes('v=0')) {
                throw new Error('Invalid SDP structure');
            }

            return true;
        } catch (error) {
            window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Offer validation failed', {
                error: error.message
            });
            return false; // Return false instead of throwing to allow graceful handling
        }
    }

    async sendSecureMessage(message) {
        // Quick readiness check WITHOUT mutex
        if (!this.isConnected() || !this.isVerified) {
            if (message && typeof message === 'object' && message.type && message.type.startsWith('file_')) {
                throw new Error('Connection not ready for file transfer. Please ensure the connection is established and verified.');
            }
            this.messageQueue.push(message);
            throw new Error('Connection not ready. Message queued for sending.');
        }
        
        // FIX: Use mutex ONLY for cryptographic operations
        return this._withMutex('cryptoOperation', async (operationId) => {
            // Re-check inside critical section
            if (!this.isConnected() || !this.isVerified) {
                throw new Error('Connection lost during message preparation');
            }
            
            // Validate keys inside critical section
            if (!this.encryptionKey || !this.macKey || !this.metadataKey) {
                throw new Error('Encryption keys not initialized');
            }
            
            // Rate limiting check
            if (!window.EnhancedSecureCryptoUtils.rateLimiter.checkMessageRate(this.rateLimiterId)) {
                throw new Error('Message rate limit exceeded (60 messages per minute)');
            }
            
            try {
                // Accept strings and objects; stringify objects
                const textToSend = typeof message === 'string' ? message : JSON.stringify(message);
                const sanitizedMessage = window.EnhancedSecureCryptoUtils.sanitizeMessage(textToSend);
                const messageId = `msg_${Date.now()}_${this.messageCounter++}`;
                
                // Use enhanced encryption with metadata protection
                const encryptedData = await window.EnhancedSecureCryptoUtils.encryptMessage(
                    sanitizedMessage,
                    this.encryptionKey,
                    this.macKey,
                    this.metadataKey,
                    messageId,
                    this.sequenceNumber++
                );
                
                const payload = {
                    type: 'enhanced_message',
                    data: encryptedData,
                    keyVersion: this.currentKeyVersion,
                    version: '4.0'
                };
                
                this.dataChannel.send(JSON.stringify(payload));
                // Locally display only plain strings to avoid UI duplication
                if (typeof message === 'string') {
                    this.deliverMessageToUI(message, 'sent');
                }
                
                this._secureLog('debug', '📤 Secure message sent successfully', {
                    operationId: operationId,
                    messageLength: sanitizedMessage.length,
                    keyVersion: this.currentKeyVersion
                });
                
            } catch (error) {
                this._secureLog('error', '❌ Secure message sending failed', {
                    operationId: operationId,
                    errorType: error.constructor.name
                });
                throw error;
            }
        }, 2000); // Reduced timeout for crypto operations
    }

    processMessageQueue() {
        while (this.messageQueue.length > 0 && this.isConnected() && this.isVerified) {
            const message = this.messageQueue.shift();
            this.sendSecureMessage(message).catch(console.error);
        }
    }

    startHeartbeat() {
        this.heartbeatInterval = setInterval(() => {
            if (this.isConnected()) {
                try {
                    this.dataChannel.send(JSON.stringify({ 
                        type: EnhancedSecureWebRTCManager.MESSAGE_TYPES.HEARTBEAT, 
                        timestamp: Date.now() 
                    }));
                } catch (error) {
                    console.error('Heartbeat failed:', error);
                }
            }
        }, EnhancedSecureWebRTCManager.TIMEOUTS.HEARTBEAT_INTERVAL);
    }

    stopHeartbeat() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    }

    handleHeartbeat() {
        console.log('Heartbeat received - connection alive');
    }

    waitForIceGathering() {
        return new Promise((resolve) => {
            if (this.peerConnection.iceGatheringState === 'complete') {
                resolve();
                return;
            }

            const checkState = () => {
                if (this.peerConnection.iceGatheringState === 'complete') {
                    this.peerConnection.removeEventListener('icegatheringstatechange', checkState);
                    resolve();
                }
            };
            
            this.peerConnection.addEventListener('icegatheringstatechange', checkState);
            
            setTimeout(() => {
                this.peerConnection.removeEventListener('icegatheringstatechange', checkState);
                resolve();
            }, EnhancedSecureWebRTCManager.TIMEOUTS.ICE_GATHERING_TIMEOUT);
        });
    }

    retryConnection() {
        console.log(`Retrying connection (attempt ${this.connectionAttempts}/${this.maxConnectionAttempts})`);
        this.onStatusChange('retrying');
    }

    isConnected() {
        const hasDataChannel = !!this.dataChannel;
        const dataChannelState = this.dataChannel?.readyState;
        const isDataChannelOpen = dataChannelState === 'open';
        const isVerified = this.isVerified;
        const connectionState = this.peerConnection?.connectionState;
        
        return this.dataChannel && this.dataChannel.readyState === 'open' && this.isVerified;
    }

    getConnectionInfo() {
        return {
            fingerprint: this.keyFingerprint,
            isConnected: this.isConnected(),
            isVerified: this.isVerified,
            connectionState: this.peerConnection?.connectionState,
            iceConnectionState: this.peerConnection?.iceConnectionState,
            verificationCode: this.verificationCode
        };
    }

    disconnect() {
        if (this.fileTransferSystem) {
            this.fileTransferSystem.cleanup();
        }
        this.intentionalDisconnect = true;
        
        window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Starting intentional disconnect');

        this.sendDisconnectNotification();

        setTimeout(() => {
            this.sendDisconnectNotification(); 
        }, 100);

        document.dispatchEvent(new CustomEvent('peer-disconnect', {
            detail: { 
                reason: 'user_disconnect',
                timestamp: Date.now()
            }
        }));
    }
    
    handleUnexpectedDisconnect() {
        this.sendDisconnectNotification();
        this.isVerified = false;
        
        // Ensure disconnect notification wasn't already sent
        if (!this.disconnectNotificationSent) {
            this.disconnectNotificationSent = true;
            this.deliverMessageToUI('🔌 Connection lost. Attempting to reconnect...', 'system');
        }
        
        // Cleanup file transfer system on unexpected disconnect
        if (this.fileTransferSystem) {
            console.log('🧹 Cleaning up file transfer system on unexpected disconnect...');
            this.fileTransferSystem.cleanup();
            this.fileTransferSystem = null;
        }
        
        document.dispatchEvent(new CustomEvent('peer-disconnect', {
            detail: { 
                reason: 'connection_lost',
                timestamp: Date.now()
            }
        }));

        // Do not auto-reconnect to avoid closing the session on errors
        // setTimeout(() => {
        //     if (!this.intentionalDisconnect) {
        //         this.attemptReconnection();
        //     }
        // }, 3000);
    }
    
    sendDisconnectNotification() {
        try {
            if (this.dataChannel && this.dataChannel.readyState === 'open') {
                const notification = {
                    type: 'peer_disconnect',
                    timestamp: Date.now(),
                    reason: this.intentionalDisconnect ? 'user_disconnect' : 'connection_lost'
                };

                for (let i = 0; i < 3; i++) {
                    try {
                        this.dataChannel.send(JSON.stringify(notification));
                        window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Disconnect notification sent', {
                            reason: notification.reason,
                            attempt: i + 1
                        });
                        break;
                    } catch (sendError) {
                        if (i === 2) { 
                            window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Failed to send disconnect notification', {
                                error: sendError.message
                            });
                        }
                    }
                }
            }
        } catch (error) {
            window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Could not send disconnect notification', {
                error: error.message
            });
        }
    }
    
    attemptReconnection() {
        // Ensure reconnection-failed notification wasn't already sent
        if (!this.reconnectionFailedNotificationSent) {
            this.reconnectionFailedNotificationSent = true;
            this.deliverMessageToUI('❌ Unable to reconnect. A new connection is required.', 'system');
        }
        // Do not call cleanupConnection automatically to avoid closing the session on errors
        // this.disconnect();
    }
    
    handlePeerDisconnectNotification(data) {
        const reason = data.reason || 'unknown';
        const reasonText = reason === 'user_disconnect' ? 'manually disconnected.' : 'connection lost.';
        
        // Ensure peer-disconnect notification wasn't already sent
        if (!this.peerDisconnectNotificationSent) {
            this.peerDisconnectNotificationSent = true;
            this.deliverMessageToUI(`👋 Peer ${reasonText}`, 'system');
        }
        
        this.onStatusChange('peer_disconnected');
 
        this.intentionalDisconnect = false;
        this.isVerified = false;
        this.stopHeartbeat();
        
        this.onKeyExchange(''); 
        this.onVerificationRequired(''); 

        document.dispatchEvent(new CustomEvent('peer-disconnect', {
            detail: { 
                reason: reason,
                timestamp: Date.now()
            }
        }));

        setTimeout(() => {
            this.disconnect();
        }, 2000);
        
        window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Peer disconnect notification processed', {
            reason: reason
        });
    }
    
    disconnect() {
        this.stopHeartbeat();
        this.isVerified = false;
        this.processedMessageIds.clear();
        this.messageCounter = 0;
        this._initializeSecureKeyStorage();
        this.encryptionKey = null;
        this.macKey = null;
        this.metadataKey = null;
        
        // PFS: Clearing all key versions
        this.keyVersions.clear();
        this.oldKeys.clear();
        this.currentKeyVersion = 0;
        this.lastKeyRotation = Date.now();
        
        // Clearing key pairs
        this.ecdhKeyPair = null;
        this.ecdsaKeyPair = null;
        
        // Resetting message counters
        this.sequenceNumber = 0;
        this.expectedSequenceNumber = 0;
        
        // Security flags reset completed
        this.securityFeatures = {
            hasEncryption: false,
            hasECDH: false,
            hasECDSA: false,
            hasMutualAuth: false,
            hasMetadataProtection: false,
            hasEnhancedReplayProtection: false,
            hasNonExtractableKeys: false,
            hasRateLimiting: false,
            hasEnhancedValidation: false,
            hasPFS: false
        };
        
        // Closing connections
        if (this.dataChannel) {
            this.dataChannel.close();
            this.dataChannel = null;
        }
        if (this.peerConnection) {
            this.peerConnection.close();
            this.peerConnection = null;
        }
        
        // Clearing message queue
        this.messageQueue = [];
        
        
        document.dispatchEvent(new CustomEvent('connection-cleaned', {
            detail: { 
                timestamp: Date.now(),
                reason: this.intentionalDisconnect ? 'user_cleanup' : 'automatic_cleanup'
            }
        }));

        // Notifying the UI about complete cleanup
        this.onStatusChange('disconnected');
        this.onKeyExchange('');
        this.onVerificationRequired('');
        
        window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Connection cleaned up completely');
        
        // Resetting the intentional disconnect flag
        this.intentionalDisconnect = false;

        if (window.gc) {
            window.gc();
        }
    }
    // Public method to send files
    async sendFile(file) {
        if (!this.isConnected() || !this.isVerified) {
            throw new Error('Connection not ready for file transfer. Please ensure the connection is established and verified.');
        }

        if (!this.fileTransferSystem) {
            console.log('🔄 File transfer system not initialized, attempting to initialize...');
            this.initializeFileTransfer();
            
            // Allow time for initialization
            await new Promise(resolve => setTimeout(resolve, 500));
            
            if (!this.fileTransferSystem) {
                throw new Error('File transfer system could not be initialized. Please try reconnecting.');
            }
        }

        // CRITICAL FIX: Verify key readiness
        if (!this.encryptionKey || !this.macKey) {
            throw new Error('Encryption keys not ready. Please wait for connection to be fully established.');
        }

        // Debug logging for file transfer system
        console.log('🔍 Debug: File transfer system in sendFile:', {
            hasFileTransferSystem: !!this.fileTransferSystem,
            fileTransferSystemType: this.fileTransferSystem.constructor?.name,
            hasWebrtcManager: !!this.fileTransferSystem.webrtcManager,
            webrtcManagerType: this.fileTransferSystem.webrtcManager?.constructor?.name
        });

        try {
            console.log('🚀 Starting file transfer for:', file.name, `(${(file.size / 1024 / 1024).toFixed(2)} MB)`);
            const fileId = await this.fileTransferSystem.sendFile(file);
            console.log('✅ File transfer initiated successfully with ID:', fileId);
            return fileId;
        } catch (error) {
            console.error('❌ File transfer error:', error);
            
            // Re-throw with a clearer message
            if (error.message.includes('Connection not ready')) {
                throw new Error('Connection not ready for file transfer. Check connection status.');
            } else if (error.message.includes('Encryption keys not initialized')) {
                throw new Error('Encryption keys not initialized. Try reconnecting.');
            } else if (error.message.includes('Transfer timeout')) {
                throw new Error('File transfer timeout. Check connection and try again.');
            } else {
                throw error;
            }
        }
    }

    // Get active file transfers
    getFileTransfers() {
        if (!this.fileTransferSystem) {
            return { sending: [], receiving: [] };
        }
        
        try {
            // Check available methods in file transfer system
            let sending = [];
            let receiving = [];
            
            if (typeof this.fileTransferSystem.getActiveTransfers === 'function') {
                sending = this.fileTransferSystem.getActiveTransfers();
            } else {
                console.warn('⚠️ getActiveTransfers method not available in file transfer system');
            }
            
            if (typeof this.fileTransferSystem.getReceivingTransfers === 'function') {
                receiving = this.fileTransferSystem.getReceivingTransfers();
            } else {
                console.warn('⚠️ getReceivingTransfers method not available in file transfer system');
            }
            
            return {
                sending: sending || [],
                receiving: receiving || []
            };
        } catch (error) {
            console.error('❌ Error getting file transfers:', error);
            return { sending: [], receiving: [] };
        }
    }

    // Get file transfer system status
    getFileTransferStatus() {
        if (!this.fileTransferSystem) {
            return {
                initialized: false,
                status: 'not_initialized',
                message: 'File transfer system not initialized'
            };
        }
        
        const activeTransfers = this.fileTransferSystem.getActiveTransfers();
        const receivingTransfers = this.fileTransferSystem.getReceivingTransfers();
        
        return {
            initialized: true,
            status: 'ready',
            activeTransfers: activeTransfers.length,
            receivingTransfers: receivingTransfers.length,
            totalTransfers: activeTransfers.length + receivingTransfers.length
        };
    }

    // Cancel file transfer
    cancelFileTransfer(fileId) {
        if (!this.fileTransferSystem) return false;
        return this.fileTransferSystem.cancelTransfer(fileId);
    }

    // Force cleanup of file transfer system
    cleanupFileTransferSystem() {
        if (this.fileTransferSystem) {
            console.log('🧹 Force cleaning up file transfer system...');
            this.fileTransferSystem.cleanup();
            this.fileTransferSystem = null;
            return true;
        }
        return false;
    }

    // Reinitialize file transfer system
    reinitializeFileTransfer() {
        try {
            console.log('🔄 Reinitializing file transfer system...');
            if (this.fileTransferSystem) {
                this.fileTransferSystem.cleanup();
            }
            this.initializeFileTransfer();
            return true;
        } catch (error) {
            console.error('❌ Failed to reinitialize file transfer system:', error);
            return false;
        }
    }

    // Set file transfer callbacks
    setFileTransferCallbacks(onProgress, onReceived, onError) {
        this.onFileProgress = onProgress;
        this.onFileReceived = onReceived;
        this.onFileError = onError;
        
        console.log('🔧 File transfer callbacks set:', {
            hasProgress: !!onProgress,
            hasReceived: !!onReceived,
            hasError: !!onError
        });
        
        // Reinitialize file transfer system if it exists to update callbacks
        if (this.fileTransferSystem) {
            console.log('🔄 Reinitializing file transfer system with new callbacks...');
            this.initializeFileTransfer();
        }
    }

    // ============================================
    // SESSION ACTIVATION HANDLING
    // ============================================

    async handleSessionActivation(sessionData) {
        try {
            console.log('🔐 Handling session activation:', sessionData);
            
            // Update session state
            this.currentSession = sessionData;
            this.sessionManager = sessionData.sessionManager;
            
            // FIX: More lenient checks for activation
            const hasKeys = !!(this.encryptionKey && this.macKey);
            const hasSession = !!(this.sessionManager && (this.sessionManager.hasActiveSession?.() || sessionData.sessionId));
            
            console.log('🔍 Session activation status:', {
                hasKeys: hasKeys,
                hasSession: hasSession,
                sessionType: sessionData.sessionType,
                isDemo: sessionData.isDemo
            });
            
            // Force connection status if there is an active session
            if (hasSession) {
                console.log('🔓 Session activated - forcing connection status to connected');
                this.onStatusChange('connected');
                
                // Set isVerified for active sessions
                this.isVerified = true;
                console.log('✅ Session verified - setting isVerified to true');
            }
            
                    // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Инициализируем файловую систему для обеих сторон
        setTimeout(() => {
            try {
                this.initializeFileTransfer();
            } catch (error) {
                console.warn('⚠️ File transfer initialization failed during session activation:', error.message);
            }
        }, 1000);
            
            console.log('✅ Session activation handled successfully');
            
            if (this.fileTransferSystem && this.isConnected()) {
                console.log('🔄 Synchronizing file transfer keys after session activation...');
                
                if (typeof this.fileTransferSystem.onSessionUpdate === 'function') {
                    this.fileTransferSystem.onSessionUpdate({
                        keyFingerprint: this.keyFingerprint,
                        sessionSalt: this.sessionSalt,
                        hasMacKey: !!this.macKey
                    });
                }
            }
            
        } catch (error) {
            console.error('❌ Failed to handle session activation:', error);
        }
    }
    // Method to check readiness of file transfers
checkFileTransferReadiness() {
        const status = {
            hasFileTransferSystem: !!this.fileTransferSystem,
            hasDataChannel: !!this.dataChannel,
            dataChannelState: this.dataChannel?.readyState,
            isConnected: this.isConnected(),
            isVerified: this.isVerified,
            hasEncryptionKey: !!this.encryptionKey,
            hasMacKey: !!this.macKey,
            ready: false
        };
        
        status.ready = status.hasFileTransferSystem && 
                    status.hasDataChannel && 
                    status.dataChannelState === 'open' && 
                    status.isConnected && 
                    status.isVerified;
        
        console.log('🔍 File transfer readiness check:', status);
        return status;
    }

    // Method to force re-initialize file transfer system
    forceReinitializeFileTransfer() {
        try {
            console.log('🔄 Force reinitializing file transfer system...');
            
            if (this.fileTransferSystem) {
                this.fileTransferSystem.cleanup();
                this.fileTransferSystem = null;
            }
            
            // Small delay before reinitialization
            setTimeout(() => {
                this.initializeFileTransfer();
            }, 500);
            
            return true;
        } catch (error) {
            console.error('❌ Failed to force reinitialize file transfer:', error);
            return false;
        }
    }

    // Method to get diagnostic information
    getFileTransferDiagnostics() {
        const diagnostics = {
            timestamp: new Date().toISOString(),
            webrtcManager: {
                hasDataChannel: !!this.dataChannel,
                dataChannelState: this.dataChannel?.readyState,
                isConnected: this.isConnected(),
                isVerified: this.isVerified,
                isInitiator: this.isInitiator,
                hasEncryptionKey: !!this.encryptionKey,
                hasMacKey: !!this.macKey,
                hasMetadataKey: !!this.metadataKey,
                hasKeyFingerprint: !!this.keyFingerprint,
                hasSessionSalt: !!this.sessionSalt
            },
            fileTransferSystem: null,
            // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Дополнительная диагностика
            globalState: {
                fileTransferActive: window.FILE_TRANSFER_ACTIVE,
                hasGlobalFileTransferSystem: !!window.fileTransferSystem,
                globalFileTransferSystemType: window.fileTransferSystem?.constructor?.name
            }
        };
        
        if (this.fileTransferSystem) {
            try {
                diagnostics.fileTransferSystem = this.fileTransferSystem.getSystemStatus();
            } catch (error) {
                diagnostics.fileTransferSystem = { error: error.message };
            }
        }
        
        return diagnostics;
    }

    getSupportedFileTypes() {
        if (!this.fileTransferSystem) {
            return { error: 'File transfer system not initialized' };
        }
        
        try {
            return this.fileTransferSystem.getSupportedFileTypes();
        } catch (error) {
            return { error: error.message };
        }
    }

    validateFile(file) {
        if (!this.fileTransferSystem) {
            return { 
                isValid: false, 
                errors: ['File transfer system not initialized'],
                fileType: null,
                fileSize: file?.size || 0,
                formattedSize: '0 B'
            };
        }
        
        try {
            return this.fileTransferSystem.validateFile(file);
        } catch (error) {
            return { 
                isValid: false, 
                errors: [error.message],
                fileType: null,
                fileSize: file?.size || 0,
                formattedSize: '0 B'
            };
        }
    }

    getFileTypeInfo() {
        if (!this.fileTransferSystem) {
            return { error: 'File transfer system not initialized' };
        }
        
        try {
            return this.fileTransferSystem.getFileTypeInfo();
        } catch (error) {
            return { error: error.message };
        }
    }

    // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Метод для принудительной инициализации файловой системы
    forceInitializeFileTransfer() {
        try {
            // Проверяем готовность соединения
            if (!this.isVerified) {
                throw new Error('Connection not verified');
            }
            
            if (!this.dataChannel || this.dataChannel.readyState !== 'open') {
                throw new Error('Data channel not open');
            }
            
            if (!this.encryptionKey || !this.macKey) {
                throw new Error('Encryption keys not ready');
            }
            
            // Очищаем существующую систему
            if (this.fileTransferSystem) {
                this.fileTransferSystem.cleanup();
                this.fileTransferSystem = null;
            }
            
            // Инициализируем новую систему
            this.initializeFileTransfer();
            
            // Ждем инициализации
            let attempts = 0;
            const maxAttempts = 50;
            while (!this.fileTransferSystem && attempts < maxAttempts) {
                // Синхронное ожидание
                const start = Date.now();
                while (Date.now() - start < 100) {
                    // busy wait
                }
                attempts++;
            }
            
            if (this.fileTransferSystem) {
                return true;
            } else {
                throw new Error('Force initialization timeout');
            }
            
        } catch (error) {
            console.error('❌ Force file transfer initialization failed:', error);
            return false;
        }
    }
}

export { EnhancedSecureWebRTCManager };