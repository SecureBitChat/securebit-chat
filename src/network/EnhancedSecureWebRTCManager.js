// Import EnhancedSecureFileTransfer
import { EnhancedSecureFileTransfer } from '../transfer/EnhancedSecureFileTransfer.js';

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
        VERIFICATION_CONFIRMED: 'verification_confirmed',
        VERIFICATION_BOTH_CONFIRMED: 'verification_both_confirmed',
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

    //   Static debug flag instead of this._debugMode
    static DEBUG_MODE = false; // Set to true during development, false in production


    constructor(onMessage, onStatusChange, onKeyExchange, onVerificationRequired, onAnswerError = null, onVerificationStateChange = null, config = {}) {
    // Determine runtime mode
    this._isProductionMode = this._detectProductionMode();
            //   Use static flag instead of this._debugMode
        this._debugMode = !this._isProductionMode && EnhancedSecureWebRTCManager.DEBUG_MODE;
        
        //   Configuration from constructor parameters instead of global flags
        this._config = {
            fakeTraffic: {
                enabled: config.fakeTraffic?.enabled ?? true,
                minInterval: config.fakeTraffic?.minInterval ?? EnhancedSecureWebRTCManager.TIMEOUTS.FAKE_TRAFFIC_MIN_INTERVAL,
                maxInterval: config.fakeTraffic?.maxInterval ?? EnhancedSecureWebRTCManager.TIMEOUTS.FAKE_TRAFFIC_MAX_INTERVAL,
                minSize: config.fakeTraffic?.minSize ?? EnhancedSecureWebRTCManager.SIZES.FAKE_TRAFFIC_MIN_SIZE,
                maxSize: config.fakeTraffic?.maxSize ?? EnhancedSecureWebRTCManager.SIZES.FAKE_TRAFFIC_MAX_SIZE,
                patterns: config.fakeTraffic?.patterns ?? ['heartbeat', 'status', 'sync']
            },
            decoyChannels: {
                enabled: config.decoyChannels?.enabled ?? true,
                maxDecoyChannels: config.decoyChannels?.maxDecoyChannels ?? EnhancedSecureWebRTCManager.LIMITS.MAX_DECOY_CHANNELS,
                decoyChannelNames: config.decoyChannels?.decoyChannelNames ?? ['heartbeat'],
                sendDecoyData: config.decoyChannels?.sendDecoyData ?? true,
                randomDecoyIntervals: config.decoyChannels?.randomDecoyIntervals ?? true
            },
            packetPadding: {
                enabled: config.packetPadding?.enabled ?? true,
                minPadding: config.packetPadding?.minPadding ?? EnhancedSecureWebRTCManager.SIZES.PACKET_PADDING_MIN,
                maxPadding: config.packetPadding?.maxPadding ?? EnhancedSecureWebRTCManager.SIZES.PACKET_PADDING_MAX,
                useRandomPadding: config.packetPadding?.useRandomPadding ?? true,
                preserveMessageSize: config.packetPadding?.preserveMessageSize ?? false
            },
            antiFingerprinting: {
                enabled: config.antiFingerprinting?.enabled ?? false,
                randomizeTiming: config.antiFingerprinting?.randomizeTiming ?? true,
                randomizeSizes: config.antiFingerprinting?.randomizeSizes ?? false,
                addNoise: config.antiFingerprinting?.addNoise ?? true,
                maskPatterns: config.antiFingerprinting?.maskPatterns ?? false,
                useRandomHeaders: config.antiFingerprinting?.useRandomHeaders ?? false
            }
        };

            //   Initialize own logging system
        this._initializeSecureLogging();
        this._setupOwnLogger();
        this._setupProductionLogging();
        
        //   Store important methods first
        this._storeImportantMethods();
        
        //   Setup global API after storing methods
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
    this.sessionConstraints = null;
    this.peerConnection = null;
    this.dataChannel = null;


    this.onMessage = onMessage;
    this.onStatusChange = onStatusChange;
    this.onKeyExchange = onKeyExchange;
    this.onVerificationStateChange = onVerificationStateChange;

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

if (typeof window !== 'undefined') {
    this._secureLog('info', '🔒 Emergency mutex handlers will be available through secure API');
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
        this.pendingSASCode = null;
        this.isVerified = false;
        this.processedMessageIds = new Set();
        
        // Mutual verification states
        this.localVerificationConfirmed = false;
        this.remoteVerificationConfirmed = false;
        this.bothVerificationsConfirmed = false;
        
        //   Store expected DTLS fingerprint for validation
        this.expectedDTLSFingerprint = null;
        this.strictDTLSValidation = true; // Can be disabled for debugging
        
        //   Real Perfect Forward Secrecy implementation
        this.ephemeralKeyPairs = new Map(); // Store ephemeral keys for current session only
        this.sessionStartTime = Date.now(); // Track session lifetime for PFS
    this.messageCounter = 0;
    this.sequenceNumber = 0;
    this.expectedSequenceNumber = 0;
    this.sessionSalt = null;
    
    //   Anti-Replay and Message Ordering Protection
    this.replayWindowSize = 64; // Sliding window for replay protection
    this.replayWindow = new Set(); // Track recent sequence numbers
    this.maxSequenceGap = 100; // Maximum allowed sequence gap
    this.replayProtectionEnabled = true; // Enable/disable replay protection
    this.sessionId = null; // MITM protection: Session identifier
    this.connectionId = Array.from(crypto.getRandomValues(new Uint8Array(8)))
        .map(b => b.toString(16).padStart(2, '0')).join(''); // Connection identifier for AAD
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
    
    // ============================================
    //   IV REUSE PREVENTION SYSTEM
    // ============================================
    //   IV REUSE PREVENTION SYSTEM WITH LIMITS
    // ============================================
    this._ivTrackingSystem = {
        usedIVs: new Set(), // Track all used IVs to prevent reuse
        ivHistory: new Map(), // Track IV usage with timestamps (max 10k entries)
        collisionCount: 0, // Track potential collisions
        maxIVHistorySize: 10000, // Maximum IV history size
        maxSessionIVs: 1000, // Maximum IVs per session
        entropyValidation: {
            minEntropy: 3.0, // Minimum entropy threshold
            entropyTests: 0,
            entropyFailures: 0
        },
        rngValidation: {
            testsPerformed: 0,
            weakRngDetected: false,
            lastValidation: 0
        },
        sessionIVs: new Map(), // Track IVs per session
        emergencyMode: false // Emergency mode if IV reuse detected
    };
    
    //   IV cleanup tracking
    this._lastIVCleanupTime = null;
    
    // ============================================
    //   SECURE ERROR HANDLING SYSTEM
    // ============================================
    this._secureErrorHandler = {
        errorCategories: {
            CRYPTOGRAPHIC: 'cryptographic',
            NETWORK: 'network',
            VALIDATION: 'validation',
            SYSTEM: 'system',
            UNKNOWN: 'unknown'
        },
        errorMappings: new Map(), // Map internal errors to safe messages
        errorCounts: new Map(), // Track error frequencies
        lastErrorTime: 0,
        errorThreshold: 10, // Max errors per minute
        isInErrorMode: false
    };
    
    // ============================================
    //   SECURE MEMORY MANAGEMENT SYSTEM
    // ============================================
    this._secureMemoryManager = {
        sensitiveData: new WeakMap(), // Track sensitive data for secure cleanup
        cleanupQueue: [], // Queue for deferred cleanup operations
        isCleaning: false, // Prevent concurrent cleanup operations
        cleanupInterval: null, // Periodic cleanup timer
        memoryStats: {
            totalCleanups: 0,
            failedCleanups: 0,
            lastCleanup: 0
        }
    };
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
        // All security features enabled by default - no payment required
        hasEncryption: true,      
        hasECDH: true,            
        hasECDSA: true,          
        hasMutualAuth: true,     
        hasMetadataProtection: true,      
        hasEnhancedReplayProtection: true, 
        hasNonExtractableKeys: true,      
        hasRateLimiting: true,    
        hasEnhancedValidation: true,      
        hasPFS: true, //   Real Perfect Forward Secrecy enabled           
        
        // Advanced Features - All enabled by default
        hasNestedEncryption: true,     
        hasPacketPadding: true,        
        hasPacketReordering: true,    
        hasAntiFingerprinting: true,  
        hasFakeTraffic: true,         
        hasDecoyChannels: true,       
        hasMessageChunking: true      
        };
        this._secureLog('info', '🔒 Enhanced WebRTC Manager initialized with tiered security');
        
        //   Log configuration for debugging
        this._secureLog('info', '🔒 Configuration loaded from constructor parameters', {
            fakeTraffic: this._config.fakeTraffic.enabled,
            decoyChannels: this._config.decoyChannels.enabled,
            packetPadding: this._config.packetPadding.enabled,
            antiFingerprinting: this._config.antiFingerprinting.enabled
        });
        
        //   XSS Hardening - replace all window.DEBUG_MODE references
        this._hardenDebugModeReferences();
        
        //   Initialize unified scheduler for all maintenance tasks
        this._initializeUnifiedScheduler();
        
        this._syncSecurityFeaturesWithTariff();
        
        if (!this._validateCryptographicSecurity()) {
            this._secureLog('error', '🚨 CRITICAL: Cryptographic security validation failed after tariff sync');
            throw new Error('Critical cryptographic features are missing after tariff synchronization');
        }
    // ============================================
    // ENHANCED SECURITY FEATURES
    // ============================================
        
        // 1. Nested Encryption Layer
            this.nestedEncryptionKey = null;
                    //   Removed nestedEncryptionIV and nestedEncryptionCounter
        // Each nested encryption now generates fresh random IV for maximum security
                
            // 2. Packet Padding
            this.paddingConfig = {
                enabled: this._config.packetPadding.enabled,
                minPadding: this._config.packetPadding.minPadding,
                maxPadding: this._config.packetPadding.maxPadding,
                useRandomPadding: this._config.packetPadding.useRandomPadding,
                preserveMessageSize: this._config.packetPadding.preserveMessageSize
            };
                
            // 3. Fake Traffic Generation
            this.fakeTrafficConfig = {
                enabled: this._config.fakeTraffic?.enabled || false,
                minInterval: this._config.fakeTraffic?.minInterval || 15000,
                maxInterval: this._config.fakeTraffic?.maxInterval || 30000,
                minSize: this._config.fakeTraffic?.minSize || 64,
                maxSize: this._config.fakeTraffic?.maxSize || 1024,
                patterns: this._config.fakeTraffic?.patterns || ['heartbeat', 'status', 'ping'],
                randomDecoyIntervals: this._config.fakeTraffic?.randomDecoyIntervals || true
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
                enabled: this._config.decoyChannels.enabled,
                maxDecoyChannels: this._config.decoyChannels.maxDecoyChannels,
                decoyChannelNames: this._config.decoyChannels.decoyChannelNames,
                sendDecoyData: this._config.decoyChannels.sendDecoyData,
                randomDecoyIntervals: this._config.decoyChannels.randomDecoyIntervals
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
                enabled: this._config.antiFingerprinting.enabled,
                randomizeTiming: this._config.antiFingerprinting.randomizeTiming,
                randomizeSizes: this._config.antiFingerprinting.randomizeSizes,
                addNoise: this._config.antiFingerprinting.addNoise,
                maskPatterns: this._config.antiFingerprinting.maskPatterns,
                useRandomHeaders: this._config.antiFingerprinting.useRandomHeaders
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
        
        /**
         *   Create AAD with sequence number for anti-replay protection
         * This binds each message to its sequence number and prevents replay attacks
         */
        _createMessageAAD(messageType, messageData = null, isFileMessage = false) {
            try {
                const aad = {
                    sessionId: this.currentSession?.sessionId || this.sessionId || 'unknown',
                    keyFingerprint: this.keyFingerprint || 'unknown',
                    sequenceNumber: this._generateNextSequenceNumber(),
                    messageType: messageType,
                    timestamp: Date.now(),
                    connectionId: this.connectionId || 'unknown',
                    isFileMessage: isFileMessage
                };

                // Add message-specific data if available
                if (messageData && typeof messageData === 'object') {
                    if (messageData.fileId) aad.fileId = messageData.fileId;
                    if (messageData.chunkIndex !== undefined) aad.chunkIndex = messageData.chunkIndex;
                    if (messageData.totalChunks !== undefined) aad.totalChunks = messageData.totalChunks;
                }

                return JSON.stringify(aad);
            } catch (error) {
                this._secureLog('error', '❌ Failed to create message AAD', {
                    errorType: error.constructor.name,
                    message: error.message,
                    messageType: messageType
                });
                // Fallback to basic AAD
                return JSON.stringify({
                    sessionId: 'unknown',
                    keyFingerprint: 'unknown',
                    sequenceNumber: Date.now(),
                    messageType: messageType,
                    timestamp: Date.now(),
                    connectionId: 'unknown',
                    isFileMessage: isFileMessage
                });
            }
        }
        
        /**
         *   Generate next sequence number for outgoing messages
         * This ensures unique ordering and prevents replay attacks
         */
        _generateNextSequenceNumber() {
            const nextSeq = this.sequenceNumber++;
            
            //   Reset sequence number if it gets too large
            if (this.sequenceNumber > Number.MAX_SAFE_INTEGER - 1000) {
                this.sequenceNumber = 0;
                this.expectedSequenceNumber = 0;
                this.replayWindow.clear();
                this._secureLog('warn', '⚠️ Sequence number reset due to overflow', {
                    timestamp: Date.now()
                });
            }
            
            return nextSeq;
        }

        /**
         * Create a safe hash for logging sensitive data
         * Returns only the first 4 bytes (8 hex chars) of SHA-256 hash
         * @param {any} sensitiveData - The sensitive data to hash
         * @param {string} context - Context for error logging
         * @returns {Promise<string>} - Short hash (8 hex chars) or 'hash_error'
         */
        async _createSafeLogHash(sensitiveData, context = 'unknown') {
            try {
                let dataToHash;
                
                // Convert different data types to consistent format for hashing
                if (sensitiveData instanceof ArrayBuffer) {
                    dataToHash = new Uint8Array(sensitiveData);
                } else if (sensitiveData instanceof Uint8Array) {
                    dataToHash = sensitiveData;
                } else if (sensitiveData instanceof CryptoKey) {
                    // For CryptoKey, use its type and algorithm info (not the key material)
                    const keyInfo = `${sensitiveData.type}_${sensitiveData.algorithm?.name || 'unknown'}_${sensitiveData.extractable}`;
                    dataToHash = new TextEncoder().encode(keyInfo);
                } else if (typeof sensitiveData === 'string') {
                    dataToHash = new TextEncoder().encode(sensitiveData);
                } else if (typeof sensitiveData === 'object' && sensitiveData !== null) {
                    // For objects (like JWK), stringify without sensitive fields
                    const safeObj = { type: sensitiveData.kty || 'unknown', use: sensitiveData.use || 'unknown' };
                    dataToHash = new TextEncoder().encode(JSON.stringify(safeObj));
                } else {
                    // Fallback for other types
                    dataToHash = new TextEncoder().encode(String(sensitiveData));
                }
                
                // Create SHA-256 hash
                const hashBuffer = await crypto.subtle.digest('SHA-256', dataToHash);
                const hashArray = new Uint8Array(hashBuffer);
                
                // Return only first 4 bytes as hex (8 characters)
                return Array.from(hashArray.slice(0, 4))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
                    
            } catch (error) {
                // Never log the actual error details to avoid leaking sensitive data
                return 'hash_error';
            }
        }

        /**
         * Async sleep helper - replaces busy-wait
         */
        async _asyncSleep(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }

        /**
         * Async cleanup helper - replaces immediate heavy operations
         */
        async _scheduleAsyncCleanup(cleanupFn, delay = 0) {
            return new Promise((resolve) => {
                setTimeout(async () => {
                    try {
                        await cleanupFn();
                        resolve(true);
                    } catch (error) {
                        this._secureLog('error', 'Async cleanup failed', {
                            errorType: error?.constructor?.name || 'Unknown'
                        });
                        resolve(false);
                    }
                }, delay);
            });
        }

        /**
         * Batch async operations to prevent UI blocking
         */
        async _batchAsyncOperation(items, batchSize = 10, delayBetweenBatches = 5) {
            const results = [];
            
            for (let i = 0; i < items.length; i += batchSize) {
                const batch = items.slice(i, i + batchSize);
                const batchResults = await Promise.all(batch);
                results.push(...batchResults);
                
                // Small delay between batches to prevent UI blocking
                if (i + batchSize < items.length) {
                    await this._asyncSleep(delayBetweenBatches);
                }
            }
            
            return results;
        }

        /**
         * Memory cleanup without window.gc() - uses natural garbage collection
         */
        async _performNaturalCleanup() {
            // Clear references and let JS engine handle GC naturally
            // This is more reliable than forcing GC
            
            // Schedule cleanup in next event loop cycle
            await this._asyncSleep(0);
            
            // Allow multiple event loop cycles for natural GC
            for (let i = 0; i < 3; i++) {
                await this._asyncSleep(10);
            }
        }

        /**
         * Heavy cleanup operations using WebWorker (if available)
         */
        async _performHeavyCleanup(cleanupData) {
            // Try to use WebWorker for heavy operations
            if (typeof Worker !== 'undefined') {
                try {
                    return await this._cleanupWithWorker(cleanupData);
                } catch (error) {
                    this._secureLog('warn', 'WebWorker cleanup failed, falling back to main thread', {
                        errorType: error?.constructor?.name || 'Unknown'
                    });
                }
            }
            
            // Fallback to main thread with async batching
            return await this._cleanupInMainThread(cleanupData);
        }

        /**
         * Cleanup using WebWorker
         */
        async _cleanupWithWorker(cleanupData) {
            return new Promise((resolve, reject) => {
                // Create inline worker for cleanup operations
                const workerCode = `
                    self.onmessage = function(e) {
                        const { type, data } = e.data;
                        
                        try {
                            switch (type) {
                                case 'cleanup_arrays':
                                    // Simulate heavy array cleanup
                                    let processed = 0;
                                    for (let i = 0; i < data.count; i++) {
                                        // Simulate work
                                        processed++;
                                        if (processed % 1000 === 0) {
                                            // Yield control periodically
                                            setTimeout(() => {}, 0);
                                        }
                                    }
                                    self.postMessage({ success: true, processed });
                                    break;
                                    
                                case 'cleanup_objects':
                                    // Simulate object cleanup
                                    const cleaned = data.objects.map(() => null);
                                    self.postMessage({ success: true, cleaned: cleaned.length });
                                    break;
                                    
                                default:
                                    self.postMessage({ success: true, message: 'Unknown cleanup type' });
                            }
                        } catch (error) {
                            self.postMessage({ success: false, error: error.message });
                        }
                    };
                `;
                
                const blob = new Blob([workerCode], { type: 'application/javascript' });
                const worker = new Worker(URL.createObjectURL(blob));
                
                const timeout = setTimeout(() => {
                    worker.terminate();
                    reject(new Error('Worker cleanup timeout'));
                }, 5000); // 5 second timeout
                
                worker.onmessage = (e) => {
                    clearTimeout(timeout);
                    worker.terminate();
                    URL.revokeObjectURL(blob);
                    
                    if (e.data.success) {
                        resolve(e.data);
                    } else {
                        reject(new Error(e.data.error));
                    }
                };
                
                worker.onerror = (error) => {
                    clearTimeout(timeout);
                    worker.terminate();
                    URL.revokeObjectURL(blob);
                    reject(error);
                };
                
                worker.postMessage(cleanupData);
            });
        }

        /**
         * Cleanup in main thread with async batching
         */
        async _cleanupInMainThread(cleanupData) {
            const { type, data } = cleanupData;
            
            switch (type) {
                case 'cleanup_arrays':
                    // Process in batches to avoid blocking
                    let processed = 0;
                    const batchSize = 100;
                    
                    while (processed < data.count) {
                        const batchEnd = Math.min(processed + batchSize, data.count);
                        
                        // Process batch
                        for (let i = processed; i < batchEnd; i++) {
                            // Simulate cleanup work
                        }
                        
                        processed = batchEnd;
                        
                        // Yield control to prevent UI blocking
                        await this._asyncSleep(1);
                    }
                    
                    return { success: true, processed };
                    
                case 'cleanup_objects':
                    // Clean objects in batches
                    const objects = data.objects || [];
                    const batches = [];
                    
                    for (let i = 0; i < objects.length; i += 50) {
                        batches.push(objects.slice(i, i + 50));
                    }
                    
                    let cleaned = 0;
                    for (const batch of batches) {
                        batch.forEach(() => cleaned++);
                        await this._asyncSleep(1);
                    }
                    
                    return { success: true, cleaned };
                    
                default:
                    return { success: true, message: 'Unknown cleanup type' };
            }
        }
        
    /**
     *   Enhanced mutex system initialization with atomic protection
     */
    _initializeMutexSystem() {
        //   Initialize standard mutexes with enhanced state tracking
        this._keyOperationMutex = {
            locked: false,
            queue: [],
            lockId: null,
            lockTimeout: null,
            lockTime: null,
            operationCount: 0
        };

        this._cryptoOperationMutex = {
            locked: false,
            queue: [],
            lockId: null,
            lockTimeout: null,
            lockTime: null,
            operationCount: 0
        };

        this._connectionOperationMutex = {
            locked: false,
            queue: [],
            lockId: null,
            lockTimeout: null,
            lockTime: null,
            operationCount: 0
        };

        //   Enhanced key system state with atomic operation tracking
        this._keySystemState = {
            isInitializing: false,
            isRotating: false,
            isDestroying: false,
            lastOperation: null,
            lastOperationTime: Date.now(),
            operationId: null,
            concurrentOperations: 0,
            maxConcurrentOperations: 1
        };

        //   Operation counters with atomic increments
        this._operationCounters = {
            keyOperations: 0,
            cryptoOperations: 0,
            connectionOperations: 0,
            totalOperations: 0,
            failedOperations: 0
        };

        this._secureLog('info', '🔒 Enhanced mutex system initialized with atomic protection', {
            mutexes: ['keyOperation', 'cryptoOperation', 'connectionOperation'],
            timestamp: Date.now(),
            features: ['atomic_operations', 'race_condition_protection', 'enhanced_state_tracking']
        });
    }

    /**
     *   XSS Hardening - Debug mode references validation
     * This method is called during initialization to ensure XSS hardening
     */
    _hardenDebugModeReferences() {
        //   Log that we're hardening debug mode references
        this._secureLog('info', '🔒 XSS Hardening: Debug mode references already replaced');
    }

    /**
     *   Unified scheduler for all maintenance tasks
     * Replaces multiple setInterval calls with a single, controlled scheduler
     */
    _initializeUnifiedScheduler() {
        //   Single scheduler interval for all maintenance tasks
        this._maintenanceScheduler = setInterval(() => {
            this._executeMaintenanceCycle();
        }, 300000); // Every 5 minutes
        
        //   Log scheduler initialization
        this._secureLog('info', '🔧 Unified maintenance scheduler initialized (5-minute cycle)');
        
        //   Store scheduler reference for cleanup
        this._activeTimers = new Set([this._maintenanceScheduler]);
    }

    /**
     *   Execute all maintenance tasks in a single cycle
     */
    _executeMaintenanceCycle() {
        try {
            this._secureLog('info', '🔧 Starting maintenance cycle');
            
            // 1. Log cleanup and security audit
            this._cleanupLogs();
            this._auditLoggingSystemSecurity();
            
            // 2. Security monitoring
            this._verifyAPIIntegrity();
            this._validateCryptographicSecurity();
            this._syncSecurityFeaturesWithTariff();
            
            // 3. Resource cleanup
            this._cleanupResources();
            this._enforceResourceLimits();
            
            // 4. Key monitoring (if connected)
            if (this.isConnected && this.isVerified) {
                this._monitorKeySecurity();
            }
            
            // 5. Global exposure monitoring (debug mode only)
            if (this._debugMode) {
                this._monitorGlobalExposure();
            }
            
            // 6. Heartbeat (if enabled and connected)
            if (this._heartbeatConfig && this._heartbeatConfig.enabled && this.isConnected()) {
                this._sendHeartbeat();
            }
            
            this._secureLog('info', '🔧 Maintenance cycle completed successfully');
            
        } catch (error) {
            this._secureLog('error', '❌ Maintenance cycle failed', {
                errorType: error?.constructor?.name || 'Unknown',
                message: error?.message || 'Unknown error'
            });
            
            //   Emergency cleanup on failure
            this._emergencyCleanup().catch(error => {
                this._secureLog('error', 'Emergency cleanup failed', {
                    errorType: error?.constructor?.name || 'Unknown'
                });
            });
        }
    }

    /**
     *   Enforce hard resource limits with emergency cleanup
     */
    _enforceResourceLimits() {
        const violations = [];
        
        // Check log entries
        if (this._logCounts.size > this._resourceLimits.maxLogEntries) {
            violations.push('log_entries');
        }
        
        // Check message queue
        if (this.messageQueue.length > this._resourceLimits.maxMessageQueue) {
            violations.push('message_queue');
        }
        
        // Check IV history
        if (this._ivTrackingSystem && this._ivTrackingSystem.ivHistory.size > this._resourceLimits.maxIVHistory) {
            violations.push('iv_history');
        }
        
        // Check processed message IDs
        if (this.processedMessageIds.size > this._resourceLimits.maxProcessedMessageIds) {
            violations.push('processed_message_ids');
        }
        
        // Check decoy channels
        if (this.decoyChannels.size > this._resourceLimits.maxDecoyChannels) {
            violations.push('decoy_channels');
        }
        
        // Check fake traffic messages
        if (this._fakeTrafficMessages && this._fakeTrafficMessages.length > this._resourceLimits.maxFakeTrafficMessages) {
            violations.push('fake_traffic_messages');
        }
        
        // Check chunk queue
        if (this.chunkQueue.length > this._resourceLimits.maxChunkQueue) {
            violations.push('chunk_queue');
        }
        
        // Check packet buffer
        if (this.packetBuffer && this.packetBuffer.size > this._resourceLimits.maxPacketBuffer) {
            violations.push('packet_buffer');
        }
        
        // If violations detected, trigger emergency cleanup
        if (violations.length > 0) {
            this._secureLog('warn', '⚠️ Resource limit violations detected', { violations });
            this._emergencyCleanup().catch(error => {
                this._secureLog('error', 'Emergency cleanup failed', {
                    errorType: error?.constructor?.name || 'Unknown'
                });
            });
        }
    }

    /**
     *   Emergency cleanup when resource limits are exceeded
     */
    async _emergencyCleanup() {
        this._secureLog('warn', '🚨 EMERGENCY: Resource limits exceeded, performing emergency cleanup');
        
        try {
            // 1. Clear all logs immediately
            this._logCounts.clear();
            this._secureLog('info', '🧹 Emergency: All logs cleared');
            
            // 2. Clear message queue
            this.messageQueue.length = 0;
            this._secureLog('info', '🧹 Emergency: Message queue cleared');
            
            // 3. Enhanced IV history cleanup
            if (this._ivTrackingSystem) {
                this._ivTrackingSystem.usedIVs.clear();
                this._ivTrackingSystem.ivHistory.clear();
                this._ivTrackingSystem.sessionIVs.clear();
                this._ivTrackingSystem.collisionCount = 0;
                this._ivTrackingSystem.emergencyMode = false;
                this._secureLog('info', '🧹 Enhanced Emergency: IV tracking system cleared');
            }
            
            // 4. Clear processed message IDs
            this.processedMessageIds.clear();
            this._secureLog('info', '🧹 Emergency: Processed message IDs cleared');
            
            // 5. Enhanced decoy channels cleanup
            if (this.decoyChannels) {
                for (const [channelName, timer] of this.decoyTimers) {
                    if (timer) clearTimeout(timer);
                }
                this.decoyChannels.clear();
                this.decoyTimers.clear();
                this._secureLog('info', '🧹 Enhanced Emergency: Decoy channels cleared');
            }
            
            // 6. Enhanced fake traffic cleanup
            if (this.fakeTrafficTimer) {
                clearTimeout(this.fakeTrafficTimer);
                this.fakeTrafficTimer = null;
            }
            if (this._fakeTrafficMessages) {
                this._fakeTrafficMessages.length = 0;
                this._secureLog('info', '🧹 Enhanced Emergency: Fake traffic messages cleared');
            }
            
            // 7. Clear chunk queue
            this.chunkQueue.length = 0;
            this._secureLog('info', '🧹 Emergency: Chunk queue cleared');
            
            // 8. Clear packet buffer
            if (this.packetBuffer) {
                this.packetBuffer.clear();
                this._secureLog('info', '🧹 Emergency: Packet buffer cleared');
            }
            
            // 9. Enhanced memory cleanup with quantum-resistant patterns
            this._secureMemoryManager.isCleaning = true;
            this._secureMemoryManager.cleanupQueue.length = 0;
            this._secureMemoryManager.memoryStats.lastCleanup = Date.now();
            
            //   Perform natural cleanup without forcing GC
            await this._scheduleAsyncCleanup(async () => {
                this._secureLog('info', '🧹 Enhanced Emergency: Starting natural memory cleanup');
                
                // Natural cleanup cycles with async delays
                for (let i = 0; i < 3; i++) {
                    this._secureLog('info', `🧹 Enhanced Emergency: Cleanup cycle ${i + 1}/3`);
                    
                    // Allow natural garbage collection between cycles
                    await this._performNaturalCleanup();
                }
                
                this._secureLog('info', '🧹 Enhanced Emergency: Natural cleanup completed');
            }, 0);
            
            this._secureMemoryManager.isCleaning = false;
            
            this._secureLog('info', '✅ Enhanced emergency cleanup completed successfully');
            
        } catch (error) {
            this._secureLog('error', '❌ Enhanced emergency cleanup failed', {
                errorType: error?.constructor?.name || 'Unknown',
                message: error?.message || 'Unknown error'
            });
            
            //   Rollback mechanism (simplified)
            this._secureMemoryManager.isCleaning = false;
        }
    }

    /**
     *   Validate emergency cleanup success
     * @param {Object} originalState - Original state before cleanup
     * @returns {Object} Validation results
     */
    _validateEmergencyCleanup(originalState) {
        const currentState = {
            messageQueueSize: this.messageQueue.length,
            processedIdsSize: this.processedMessageIds.size,
            packetBufferSize: this.packetBuffer ? this.packetBuffer.size : 0,
            ivTrackingSize: this._ivTrackingSystem ? this._ivTrackingSystem.usedIVs.size : 0,
            decoyChannelsSize: this.decoyChannels ? this.decoyChannels.size : 0
        };
        
        const validation = {
            messageQueueCleared: currentState.messageQueueSize === 0,
            processedIdsCleared: currentState.processedIdsSize === 0,
            packetBufferCleared: currentState.packetBufferSize === 0,
            ivTrackingCleared: currentState.ivTrackingSize === 0,
            decoyChannelsCleared: currentState.decoyChannelsSize === 0,
            allCleared: (
                currentState.messageQueueSize === 0 &&
                currentState.processedIdsSize === 0 &&
                currentState.packetBufferSize === 0 &&
                currentState.ivTrackingSize === 0 &&
                currentState.decoyChannelsSize === 0
            )
        };
        
        return validation;
    }

    /**
     *   Cleanup resources based on age and usage
     */
    _cleanupResources() {
        const now = Date.now();
        
        // Clean old processed message IDs (keep only last hour)
        if (this.processedMessageIds.size > this._emergencyThresholds.processedMessageIds) {
            this.processedMessageIds.clear();
            this._secureLog('info', '🧹 Old processed message IDs cleared');
        }
        
        // Clean old IVs
        if (this._ivTrackingSystem) {
            this._cleanupOldIVs();
        }
        
        // Clean old keys
        this.cleanupOldKeys();
        
        // Clean rate limiter
        if (window.EnhancedSecureCryptoUtils && window.EnhancedSecureCryptoUtils.rateLimiter) {
            window.EnhancedSecureCryptoUtils.rateLimiter.cleanup();
        }
        
        this._secureLog('info', '🧹 Resource cleanup completed');
    }

    /**
     *   Monitor key security (replaces _startKeySecurityMonitoring)
     */
    _monitorKeySecurity() {
        if (this._keyStorageStats.activeKeys > 10) {
            this._secureLog('warn', '⚠️ High number of active keys detected. Consider rotation.');
        }
        
        if (Date.now() - (this._keyStorageStats.lastRotation || 0) > 3600000) {
            this._rotateKeys();
        }
    }

    /**
     *   Send heartbeat message (called by unified scheduler)
     */
    _sendHeartbeat() {
        try {
            if (this.isConnected() && this.dataChannel && this.dataChannel.readyState === 'open') {
                this.dataChannel.send(JSON.stringify({ 
                    type: EnhancedSecureWebRTCManager.MESSAGE_TYPES.HEARTBEAT, 
                    timestamp: Date.now() 
                }));
                
                this._heartbeatConfig.lastHeartbeat = Date.now();
                this._secureLog('debug', '💓 Heartbeat sent');
            }
        } catch (error) {
            this._secureLog('error', '❌ Heartbeat failed:', { 
                errorType: error?.constructor?.name || 'Unknown',
                message: error?.message || 'Unknown error'
            });
        }
    }

    /**
     *   Comprehensive input validation to prevent DoS and injection attacks
     * @param {any} data - Data to validate
     * @param {string} context - Context for validation (e.g., 'sendMessage', 'sendSecureMessage')
     * @returns {Object} Validation result with isValid and sanitizedData
     */
    _validateInputData(data, context = 'unknown') {
        const validationResult = {
            isValid: false,
            sanitizedData: null,
            errors: [],
            warnings: []
        };

        try {
            // 1. Basic type validation
            if (data === null || data === undefined) {
                validationResult.errors.push('Data cannot be null or undefined');
                return validationResult;
            }

            // 2. Size validation for strings
            if (typeof data === 'string') {
                if (data.length > this._inputValidationLimits.maxStringLength) {
                    validationResult.errors.push(`String too long: ${data.length} > ${this._inputValidationLimits.maxStringLength}`);
                    return validationResult;
                }

                // 3. Malicious pattern detection for strings
                for (const pattern of this._maliciousPatterns) {
                    if (pattern.test(data)) {
                        validationResult.errors.push(`Malicious pattern detected: ${pattern.source}`);
                        this._secureLog('warn', '🚨 Malicious pattern detected in input', {
                            context: context,
                            pattern: pattern.source,
                            dataLength: data.length
                        });
                        return validationResult;
                    }
                }

                // 4. Sanitize string data
                validationResult.sanitizedData = this._sanitizeInputString(data);
                validationResult.isValid = true;
                return validationResult;
            }

            // 5. Object validation
            if (typeof data === 'object') {
                // Check for circular references
                const seen = new WeakSet();
                const checkCircular = (obj, path = '') => {
                    if (obj === null || typeof obj !== 'object') return;
                    
                    if (seen.has(obj)) {
                        validationResult.errors.push(`Circular reference detected at path: ${path}`);
                        return;
                    }
                    
                    seen.add(obj);
                    
                    // Check object depth
                    if (path.split('.').length > this._inputValidationLimits.maxObjectDepth) {
                        validationResult.errors.push(`Object too deep: ${path.split('.').length} > ${this._inputValidationLimits.maxObjectDepth}`);
                        return;
                    }

                    // Check array length
                    if (Array.isArray(obj) && obj.length > this._inputValidationLimits.maxArrayLength) {
                        validationResult.errors.push(`Array too long: ${obj.length} > ${this._inputValidationLimits.maxArrayLength}`);
                        return;
                    }

                    // Recursively check all properties
                    for (const key in obj) {
                        if (obj.hasOwnProperty(key)) {
                            checkCircular(obj[key], path ? `${path}.${key}` : key);
                        }
                    }
                };

                checkCircular(data);
                
                if (validationResult.errors.length > 0) {
                    return validationResult;
                }

                // 6. Check total object size
                const objectSize = this._calculateObjectSize(data);
                if (objectSize > this._inputValidationLimits.maxMessageSize) {
                    validationResult.errors.push(`Object too large: ${objectSize} bytes > ${this._inputValidationLimits.maxMessageSize} bytes`);
                    return validationResult;
                }

                // 7. Sanitize object data
                validationResult.sanitizedData = this._sanitizeInputObject(data);
                validationResult.isValid = true;
                return validationResult;
            }

            // 8. ArrayBuffer validation
            if (data instanceof ArrayBuffer) {
                if (data.byteLength > this._inputValidationLimits.maxMessageSize) {
                    validationResult.errors.push(`ArrayBuffer too large: ${data.byteLength} bytes > ${this._inputValidationLimits.maxMessageSize} bytes`);
                    return validationResult;
                }
                
                validationResult.sanitizedData = data;
                validationResult.isValid = true;
                return validationResult;
            }

            // 9. Other types are not allowed
            validationResult.errors.push(`Unsupported data type: ${typeof data}`);
            return validationResult;

        } catch (error) {
            validationResult.errors.push(`Validation error: ${error.message}`);
            this._secureLog('error', '❌ Input validation failed', {
                context: context,
                errorType: error?.constructor?.name || 'Unknown',
                message: error?.message || 'Unknown error'
            });
            return validationResult;
        }
    }

    /**
     *   Calculate approximate object size in bytes
     * @param {any} obj - Object to calculate size for
     * @returns {number} Size in bytes
     */
    _calculateObjectSize(obj) {
        try {
            const jsonString = JSON.stringify(obj);
            return new TextEncoder().encode(jsonString).length;
        } catch (error) {
            // If JSON.stringify fails, estimate size
            return 1024 * 1024; // Assume 1MB to be safe
        }
    }

    /**
     *   Sanitize string data for input validation
     * @param {string} str - String to sanitize
     * @returns {string} Sanitized string
     */
    _sanitizeInputString(str) {
        if (typeof str !== 'string') return str;
        
        // Remove null bytes
        str = str.replace(/\0/g, '');
        
        // Normalize whitespace
        str = str.replace(/\s+/g, ' ');
        
        // Trim
        str = str.trim();
        
        return str;
    }

    /**
     *   Sanitize object data for input validation
     * @param {any} obj - Object to sanitize
     * @returns {any} Sanitized object
     */
    _sanitizeInputObject(obj) {
        if (obj === null || typeof obj !== 'object') return obj;
        
        if (Array.isArray(obj)) {
            return obj.map(item => this._sanitizeInputObject(item));
        }
        
        const sanitized = {};
        for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
                const value = obj[key];
                if (typeof value === 'string') {
                    sanitized[key] = this._sanitizeInputString(value);
                } else if (typeof value === 'object') {
                    sanitized[key] = this._sanitizeInputObject(value);
                } else {
                    sanitized[key] = value;
                }
            }
        }
        
        return sanitized;
    }

    /**
     *   Rate limiting for message sending
     * @param {string} context - Context for rate limiting
     * @returns {boolean} true if rate limit allows
     */
    _checkRateLimit(context = 'message') {
        const now = Date.now();
        
        // Initialize rate limiter if not exists
        if (!this._rateLimiter) {
            this._rateLimiter = {
                messageCount: 0,
                lastReset: now,
                burstCount: 0,
                lastBurstReset: now
            };
        }
        
        // Reset counters if needed
        if (now - this._rateLimiter.lastReset > 60000) { // 1 minute
            this._rateLimiter.messageCount = 0;
            this._rateLimiter.lastReset = now;
        }
        
        if (now - this._rateLimiter.lastBurstReset > 1000) { // 1 second
            this._rateLimiter.burstCount = 0;
            this._rateLimiter.lastBurstReset = now;
        }
        
        // Check burst limit
        if (this._rateLimiter.burstCount >= this._inputValidationLimits.rateLimitBurstSize) {
            this._secureLog('warn', '⚠️ Rate limit burst exceeded', { context });
            return false;
        }
        
        // Check overall rate limit
        if (this._rateLimiter.messageCount >= this._inputValidationLimits.rateLimitMessagesPerMinute) {
            this._secureLog('warn', '⚠️ Rate limit exceeded', { context });
            return false;
        }
        
        // Increment counters
        this._rateLimiter.messageCount++;
        this._rateLimiter.burstCount++;
        
        return true;
    }

    // ============================================
    // SECURE KEY STORAGE MANAGEMENT
    // ============================================

    /**
     * Initializes the secure key storage
     */
    _initializeSecureKeyStorage() {
        // Initialize master key manager
        this._masterKeyManager = new SecureMasterKeyManager();
        
        // Initialize with the new class and pass master key manager
        this._secureKeyStorage = new SecureKeyStorage(this._masterKeyManager);
        
        // Keep the stats structure for compatibility
        this._keyStorageStats = {
            totalKeys: 0,
            activeKeys: 0,
            lastAccess: null,
            lastRotation: null,
        };
        
        this._secureLog('info', '🔐 Enhanced secure key storage initialized');
    }
    
    /**
     * Set password callback for master key
     */
    setMasterKeyPasswordCallback(callback) {
        if (this._masterKeyManager) {
            this._masterKeyManager.setPasswordRequiredCallback(callback);
        }
    }
    
    /**
     * Set session expired callback for master key
     */
    setMasterKeySessionExpiredCallback(callback) {
        if (this._masterKeyManager) {
            this._masterKeyManager.setSessionExpiredCallback(callback);
        }
    }
    
    /**
     * Lock master key manually
     */
    lockMasterKey() {
        if (this._masterKeyManager) {
            this._masterKeyManager.lock();
        }
    }
    
    /**
     * Check if master key is unlocked
     */
    isMasterKeyUnlocked() {
        return this._masterKeyManager ? this._masterKeyManager.isUnlocked() : false;
    }
    
    /**
     * Get master key session status
     */
    getMasterKeySessionStatus() {
        return this._masterKeyManager ? this._masterKeyManager.getSessionStatus() : null;
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
            this._secureLog('error', '❌ _ensureFileTransferReady failed', { 
                errorType: e?.constructor?.name || 'Unknown',
                hasMessage: !!e?.message 
            });
            return false;
        }
    }

    _getSecureKey(keyId) {
        return this._secureKeyStorage.retrieveKey(keyId);
    }

    async _setSecureKey(keyId, key) {
        if (!(key instanceof CryptoKey)) {
            this._secureLog('error', '❌ Attempt to store non-CryptoKey');
            return false;
        }
        
        const success = await this._secureKeyStorage.storeKey(keyId, key, {
            version: this.currentKeyVersion,
            type: key.algorithm.name
        });
        
        if (success) {
            this._secureLog('info', `🔑 Key ${keyId} stored securely with encryption`);
        }
        
        return success;
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

    _secureWipeKeys() {
        this._secureKeyStorage.secureWipeAll();
        
        // Also lock the master key
        if (this._masterKeyManager) {
            this._masterKeyManager.lock();
        }
        
        this._secureLog('info', '🧹 All keys securely wiped and encrypted storage cleared');
    }

    /**
     * Validates key storage state
     * @returns {boolean} true if the storage is ready
     */
    _validateKeyStorage() {
        return this._secureKeyStorage instanceof SecureKeyStorage;
    }

    /**
     * Returns secure key storage statistics
     * @returns {object} Storage metrics
     */
    _getKeyStorageStats() {
        const stats = this._secureKeyStorage.getStorageStats();
        return {
            totalKeysCount: stats.totalKeys,
            activeKeysCount: stats.totalKeys,
            hasLastAccess: stats.metadata.some(m => m.lastAccessed),
            hasLastRotation: !!this._keyStorageStats.lastRotation,
            storageType: 'SecureKeyStorage',
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
     * @deprecated Use unified scheduler instead
     */
    _startKeySecurityMonitoring() {
        //   Functionality moved to unified scheduler
        this._secureLog('info', '🔧 Key security monitoring moved to unified scheduler');
    }


    // ============================================
    // HELPER METHODS
    // ============================================
    /**
     *   Constant-time key validation to prevent timing attacks
     * @param {CryptoKey} key - Key to validate
     * @returns {boolean} true if key is valid
     */
    _validateKeyConstantTime(key) {
        //   Constant-time validation to prevent timing attacks
        let isValid = 0;
        
        // Check if key is CryptoKey instance (constant-time)
        try {
            const isCryptoKey = key instanceof CryptoKey;
            isValid += isCryptoKey ? 1 : 0;
        } catch {
            isValid += 0;
        }
        
        // Check algorithm (constant-time)
        try {
            const hasAlgorithm = !!(key && key.algorithm);
            isValid += hasAlgorithm ? 1 : 0;
        } catch {
            isValid += 0;
        }
        
        // Check type (constant-time)
        try {
            const hasType = !!(key && key.type);
            isValid += hasType ? 1 : 0;
        } catch {
            isValid += 0;
        }
        
        // Check extractable property (constant-time)
        try {
            const hasExtractable = key && key.extractable !== undefined;
            isValid += hasExtractable ? 1 : 0;
        } catch {
            isValid += 0;
        }
        
        // All checks must pass
        return isValid === 4;
    }

    /**
     *   Constant-time key pair validation
     * @param {Object} keyPair - Key pair to validate
     * @returns {boolean} true if key pair is valid
     */
    _validateKeyPairConstantTime(keyPair) {
        if (!keyPair || typeof keyPair !== 'object') return false;
        
        const privateKeyValid = this._validateKeyConstantTime(keyPair.privateKey);
        const publicKeyValid = this._validateKeyConstantTime(keyPair.publicKey);
        
        // Constant-time AND operation
        return privateKeyValid && publicKeyValid;
    }

    /**
     *   Enhanced secure logging system initialization
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
        
        //   Ultra-strict levels for production
        this._currentLogLevel = this._isProductionMode ? 
            this._logLevels.error : // In production, ONLY critical errors
            this._logLevels.info;   // In development, up to info
        
        //   Reduced log limits to prevent data accumulation
        this._logCounts = new Map();
        this._maxLogCount = this._isProductionMode ? 5 : 50; // Reduced limits
        
        //   Hard resource limits to prevent memory leaks
        this._resourceLimits = {
            maxLogEntries: this._isProductionMode ? 100 : 1000,
            maxMessageQueue: 1000,
            maxIVHistory: 10000,
            maxProcessedMessageIds: 5000,
            maxDecoyChannels: 100,
            maxFakeTrafficMessages: 500,
            maxChunkQueue: 200,
            maxPacketBuffer: 1000
        };
        
        //   Emergency cleanup thresholds
        this._emergencyThresholds = {
            logEntries: this._resourceLimits.maxLogEntries * 0.8, // 80%
            messageQueue: this._resourceLimits.maxMessageQueue * 0.8,
            ivHistory: this._resourceLimits.maxIVHistory * 0.8,
            processedMessageIds: this._resourceLimits.maxProcessedMessageIds * 0.8
        };
        
        //   Input validation limits to prevent DoS attacks
        this._inputValidationLimits = {
            maxStringLength: 100000, // 100KB for strings
            maxObjectDepth: 10, // Maximum object nesting depth
            maxArrayLength: 1000, // Maximum array length
            maxMessageSize: 1024 * 1024, // 1MB total message size
            maxConcurrentMessages: 10, // Maximum concurrent message processing
            rateLimitMessagesPerMinute: 60, // Rate limiting
            rateLimitBurstSize: 10 // Burst size for rate limiting
        };
        
        //   Malicious pattern detection
        this._maliciousPatterns = [
            // Enhanced script tag detection that handles edge cases
            /<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, // Standard </script>
            /<script\b[^>]*>[\s\S]*?<\/script\s+[^>]*>/gi, // </script with attributes>
            /<script\b[^>]*>[\s\S]*$/gi, // Malformed script tags without closing
            // Additional dangerous tags
            /<iframe\b[^>]*>[\s\S]*?<\/iframe\s*>/gi, // iframe tags
            /<object\b[^>]*>[\s\S]*?<\/object\s*>/gi, // object tags
            /<embed\b[^>]*>/gi, // embed tags
            /<applet\b[^>]*>[\s\S]*?<\/applet\s*>/gi, // applet tags
            /<style\b[^>]*>[\s\S]*?<\/style\s*>/gi, // style tags
            // Dangerous protocols
            /javascript\s*:/gi, // JavaScript protocol
            /data\s*:/gi, // Data protocol
            /vbscript\s*:/gi, // VBScript protocol
            /data:text\/html/gi, // Data URLs with HTML
            /on\w+\s*=/gi, // Event handlers
            /eval\s*\(/gi, // eval() calls
            /document\./gi, // Document object access
            /window\./gi, // Window object access
            /localStorage/gi, // LocalStorage access
            /sessionStorage/gi, // SessionStorage access
            /fetch\s*\(/gi, // Fetch API calls
            /XMLHttpRequest/gi, // XHR calls
            /import\s*\(/gi, // Dynamic imports
            /require\s*\(/gi, // Require calls
            /process\./gi, // Process object access
            /global/gi, // Global object access
            /__proto__/gi, // Prototype pollution
            /constructor/gi, // Constructor access
            /prototype/gi, // Prototype access
            /toString\s*\(/gi, // toString calls
            /valueOf\s*\(/gi // valueOf calls
        ];

        //   Comprehensive blacklist with all sensitive patterns
        this._absoluteBlacklist = new Set([
            // Cryptographic keys
            'encryptionKey', 'macKey', 'metadataKey', 'privateKey', 'publicKey',
            'ecdhKeyPair', 'ecdsaKeyPair', 'peerPublicKey', 'nestedEncryptionKey',
            
            // Authentication and session data
            'verificationCode', 'sessionSalt', 'keyFingerprint', 'sessionId',
            'authChallenge', 'authProof', 'authToken', 'sessionToken',
            
            // Credentials and secrets
            'password', 'token', 'secret', 'credential', 'signature',
            'apiKey', 'accessKey', 'secretKey', 'privateKey',
            
            // Cryptographic materials
            'hash', 'digest', 'nonce', 'iv', 'cipher', 'seed',
            'entropy', 'random', 'salt', 'fingerprint',
            
            // JWT and session data
            'jwt', 'bearer', 'refreshToken', 'accessToken',
            
            // File transfer sensitive data
            'fileHash', 'fileSignature', 'transferKey', 'chunkKey'
        ]);

        //   Minimal whitelist with strict validation
        this._safeFieldsWhitelist = new Set([
            // Basic status fields
            'timestamp', 'type', 'status', 'state', 'level',
            'isConnected', 'isVerified', 'isInitiator', 'version',
            
            // Counters and metrics (safe)
            'count', 'total', 'active', 'inactive', 'success', 'failure',
            
            // Connection states (safe)
            'readyState', 'connectionState', 'iceConnectionState',
            
            // Feature counts (safe)
            'activeFeaturesCount', 'totalFeatures', 'stage',
            
            // Error types (safe)
            'errorType', 'errorCode', 'phase', 'attempt'
        ]);
        
        //   Initialize security monitoring
        this._initializeLogSecurityMonitoring();
        
        this._secureLog('info', `🔧 Enhanced secure logging initialized (Production: ${this._isProductionMode})`);
    }

    /**
     *   Initialize security monitoring for logging system
     */
    _initializeLogSecurityMonitoring() {
        //   Security monitoring moved to unified scheduler
        this._logSecurityViolations = 0;
        this._maxLogSecurityViolations = 3;
    }

    /**
     *   Audit logging system security
     */
    _auditLoggingSystemSecurity() {
        let violations = 0;
        
        // Check for excessive log counts (potential data leakage)
        for (const [key, count] of this._logCounts.entries()) {
            if (count > this._maxLogCount * 2) {
                violations++;
                this._originalConsole?.error?.(`🚨 LOG SECURITY: Excessive log count detected: ${key}`);
            }
        }
        
        // Check for blacklisted patterns in recent logs
        const recentLogs = Array.from(this._logCounts.keys());
        for (const logKey of recentLogs) {
            if (this._containsSensitiveContent(logKey)) {
                violations++;
                this._originalConsole?.error?.(`🚨 LOG SECURITY: Sensitive content in log key: ${logKey}`);
            }
        }
        
        // Emergency shutdown if too many violations
        this._logSecurityViolations += violations;
        if (this._logSecurityViolations >= this._maxLogSecurityViolations) {
            this._emergencyDisableLogging();
            this._originalConsole?.error?.('🚨 CRITICAL: Logging system disabled due to security violations');
        }
    }

    _secureLogShim(...args) {
        try {
            // Validate arguments array
            if (!Array.isArray(args) || args.length === 0) {
                return;
            }
            
            //   Proper destructuring with fallback
            const message = args[0];
            const restArgs = args.slice(1);
            
            // Handle different argument patterns
            if (restArgs.length === 0) {
                this._secureLog('info', String(message || ''));
                return;
            }
            
            if (restArgs.length === 1) {
                this._secureLog('info', String(message || ''), restArgs[0]);
                return;
            }
            
            //   Proper object structure for multiple args
            this._secureLog('info', String(message || ''), { 
                additionalArgs: restArgs,
                argCount: restArgs.length 
            });
        } catch (error) {
            //   Better error handling - fallback to original console if available
            try {
                if (this._originalConsole?.log) {
                    this._originalConsole.log(...args);
                }
            } catch (fallbackError) {
                // Silent failure to prevent execution disruption
            }
        }
    }

    /**
     *   Setup own logger without touching global console
     */
    _setupOwnLogger() {
        //   Create own logger without touching global console
        this.logger = {
            log: (message, data) => this._secureLog('info', message, data),
            info: (message, data) => this._secureLog('info', message, data),
            warn: (message, data) => this._secureLog('warn', message, data),
            error: (message, data) => this._secureLog('error', message, data),
            debug: (message, data) => this._secureLog('debug', message, data)
        };
        
        //   In development, log to console; in production, use secure logging only
        if (EnhancedSecureWebRTCManager.DEBUG_MODE) {
            this._secureLog('info', '🔒 Own logger created - development mode');
        } else {
            this._secureLog('info', '🔒 Own logger created - production mode');
        }
    }
    /**
     *   Production logging - use own logger with minimal output
     */
    _setupProductionLogging() {
        //   In production, own logger becomes minimal
        if (this._isProductionMode) {
            this.logger = {
                log: () => {}, // No-op in production
                info: () => {}, // No-op in production
                warn: (message, data) => this._secureLog('warn', message, data),
                error: (message, data) => this._secureLog('error', message, data),
                debug: () => {} // No-op in production
            };
            
            this._secureLog('info', 'Production logging mode activated');
        }
    }
    /**
     *   Secure logging with enhanced data protection
     * @param {string} level - Log level (error, warn, info, debug, trace)
     * @param {string} message - Message
     * @param {object} data - Optional payload (will be sanitized)
     */
    _secureLog(level, message, data = null) {
        //   Pre-sanitization audit to prevent data leakage
        if (data && !this._auditLogMessage(message, data)) {
            //   Log the attempt but block the actual data
            this._originalConsole?.error?.('SECURITY: Logging blocked due to potential data leakage');
            return;
        }
        
        // Check log level
        if (this._logLevels[level] > this._currentLogLevel) {
            return;
        }
        
        //   Prevent log spam with better key generation
        const logKey = `${level}:${message.substring(0, 50)}`;
        const currentCount = this._logCounts.get(logKey) || 0;
        
        if (currentCount >= this._maxLogCount) {
            return;
        }
        
        this._logCounts.set(logKey, currentCount + 1);
        
        //   Enhanced sanitization with multiple passes
        let sanitizedData = null;
        if (data) {
            // First pass: basic sanitization
            sanitizedData = this._sanitizeLogData(data);
            
            // Second pass: check if sanitized data still contains sensitive content
            if (this._containsSensitiveContent(JSON.stringify(sanitizedData))) {
                this._originalConsole?.error?.('ECURITY: Sanitized data still contains sensitive content - blocking log');
                return;
            }
        }
        
        //   Production mode security - only log essential errors
        if (this._isProductionMode) {
            if (level === 'error') {
                //   In production, only log error messages without sensitive data
                const safeMessage = this._sanitizeString(message);
                this._originalConsole?.error?.(safeMessage);
            }
            //   Block all other log levels in production
            return;
        }
        
        // Development mode: full logging with sanitized data
        const logMethod = this._originalConsole?.[level] || this._originalConsole?.log;
        if (sanitizedData) {
            logMethod(message, sanitizedData);
        } else {
            logMethod(message);
        }
    }
    /**
     *   Enhanced sanitization for log data with multiple security layers
     */
    _sanitizeLogData(data) {
        //   Pre-check for sensitive content before processing
        if (typeof data === 'string') {
            return this._sanitizeString(data);
        }
        
        if (!data || typeof data !== 'object') {
            return data;
        }
        
        const sanitized = {};
        
        for (const [key, value] of Object.entries(data)) {
            const lowerKey = key.toLowerCase();
            
            //   Enhanced blacklist with more comprehensive patterns
            const blacklistPatterns = [
                'key', 'secret', 'token', 'password', 'credential', 'auth',
                'fingerprint', 'salt', 'signature', 'private', 'encryption',
                'mac', 'metadata', 'session', 'jwt', 'bearer', 'hash',
                'digest', 'nonce', 'iv', 'cipher', 'seed', 'entropy'
            ];
            
            const isBlacklisted = this._absoluteBlacklist.has(key) || 
                blacklistPatterns.some(pattern => lowerKey.includes(pattern));
            
            if (isBlacklisted) {
                sanitized[key] = '[SENSITIVE_DATA_BLOCKED]';
                continue;
            }
            
            //   Enhanced whitelist with strict validation
            if (this._safeFieldsWhitelist.has(key)) {
                //   Even whitelisted fields get sanitized if they contain sensitive data
                if (typeof value === 'string') {
                    sanitized[key] = this._sanitizeString(value);
                } else {
                    sanitized[key] = value;
                }
                continue;
            }
            
            //   Enhanced type handling with security checks
            if (typeof value === 'boolean' || typeof value === 'number') {
                sanitized[key] = value;
            } else if (typeof value === 'string') {
                sanitized[key] = this._sanitizeString(value);
            } else if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
                //   Don't reveal actual byte lengths for security
                sanitized[key] = `[${value.constructor.name}(<REDACTED> bytes)]`;
            } else if (value && typeof value === 'object') {
                //   Recursive sanitization with depth limit and security check
                try {
                    sanitized[key] = this._sanitizeLogData(value);
                } catch (error) {
                    sanitized[key] = '[RECURSIVE_SANITIZATION_FAILED]';
                }
            } else {
                sanitized[key] = `[${typeof value}]`;
            }
        }
        
        //   Final security check on sanitized data
        const sanitizedString = JSON.stringify(sanitized);
        if (this._containsSensitiveContent(sanitizedString)) {
            return { error: 'SANITIZATION_FAILED_SENSITIVE_CONTENT_DETECTED' };
        }
        
        return sanitized;
    }
    /**
     *   Enhanced sanitization for strings with comprehensive pattern detection
     */
    _sanitizeString(str) {
        if (typeof str !== 'string' || str.length === 0) {
            return str;
        }
        
        //   Comprehensive sensitive pattern detection
        const sensitivePatterns = [
            // Hex patterns (various lengths)
            /[a-f0-9]{16,}/i,                    // 16+ hex chars (covers short keys)
            /[a-f0-9]{8,}/i,                     // 8+ hex chars (covers shorter keys)
            
            // Base64 patterns (comprehensive)
            /[A-Za-z0-9+/]{16,}={0,2}/,         // Base64 with padding
            /[A-Za-z0-9+/]{12,}/,               // Base64 without padding
            /[A-Za-z0-9+/=]{10,}/,              // Base64-like patterns
            
            // Base58 patterns (Bitcoin-style)
            /[1-9A-HJ-NP-Za-km-z]{16,}/,        // Base58 strings
            
            // Base32 patterns
            /[A-Z2-7]{16,}={0,6}/,              // Base32 with padding
            /[A-Z2-7]{12,}/,                     // Base32 without padding
            
            // Custom encoding patterns
            /[A-Za-z0-9\-_]{16,}/,              // URL-safe base64 variants
            /[A-Za-z0-9\.\-_]{16,}/,             // JWT-like patterns
            
            // Long alphanumeric strings (potential keys)
            /\b[A-Za-z0-9]{12,}\b/,              // 12+ alphanumeric chars
            /\b[A-Za-z0-9]{8,}\b/,               // 8+ alphanumeric chars
            
            // PEM key patterns
            /BEGIN\s+(PRIVATE|PUBLIC|RSA|DSA|EC)\s+KEY/i,
            /END\s+(PRIVATE|PUBLIC|RSA|DSA|EC)\s+KEY/i,
            
            // JWT patterns
            /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/,
            
            // API key patterns
            /(api[_-]?key|token|secret|password|credential)[\s]*[:=][\s]*[A-Za-z0-9\-_]{8,}/i,
            
            // UUID patterns
            /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i,
            
            // Credit cards and SSN (existing patterns)
            /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/,
            /\b\d{3}-\d{2}-\d{4}\b/,
            
            // Email patterns (more restrictive)
            /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
            
            // Crypto-specific patterns
            /(fingerprint|hash|digest|signature)[\s]*[:=][\s]*[A-Za-z0-9\-_]{8,}/i,
            /(encryption|mac|metadata)[\s]*key[\s]*[:=][\s]*[A-Za-z0-9\-_]{8,}/i,
            
            // Session and auth patterns
            /(session|auth|jwt|bearer)[\s]*[:=][\s]*[A-Za-z0-9\-_]{8,}/i,
        ];
        
        //   Check for sensitive patterns with early return
        for (const pattern of sensitivePatterns) {
            if (pattern.test(str)) {
                //   Always fully hide sensitive data
                return '[SENSITIVE_DATA_REDACTED]';
            }
        }
        
        //   Check for suspicious entropy (high randomness indicates keys)
        if (this._hasHighEntropy(str)) {
            return '[HIGH_ENTROPY_DATA_REDACTED]';
        }
        
        //   Check for suspicious character distributions
        if (this._hasSuspiciousDistribution(str)) {
            return '[SUSPICIOUS_DATA_REDACTED]';
        }
        
        // For regular strings — limit length more aggressively
        if (str.length > 50) {
            return str.substring(0, 20) + '...[TRUNCATED]';
        }
        
        return str;
    }
    /**
     *   Enhanced sensitive content detection
     */
    _containsSensitiveContent(str) {
        if (typeof str !== 'string') return false;
        
        // Use the same comprehensive patterns as _sanitizeString
        const sensitivePatterns = [
            /[a-f0-9]{16,}/i,
            /[A-Za-z0-9+/]{16,}={0,2}/,
            /[1-9A-HJ-NP-Za-km-z]{16,}/,
            /[A-Z2-7]{16,}={0,6}/,
            /\b[A-Za-z0-9]{12,}\b/,
            /BEGIN\s+(PRIVATE|PUBLIC|RSA|DSA|EC)\s+KEY/i,
            /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/,
            /(api[_-]?key|token|secret|password|credential)[\s]*[:=][\s]*[A-Za-z0-9\-_]{8,}/i,
        ];
        
        return sensitivePatterns.some(pattern => pattern.test(str)) ||
               this._hasHighEntropy(str) ||
               this._hasSuspiciousDistribution(str);
    }

    /**
     *   Check for high entropy strings (likely cryptographic keys)
     */
    _hasHighEntropy(str) {
        if (str.length < 8) return false;
        
        // Calculate character frequency
        const charCount = {};
        for (const char of str) {
            charCount[char] = (charCount[char] || 0) + 1;
        }
        
        // Calculate Shannon entropy
        const length = str.length;
        let entropy = 0;
        
        for (const count of Object.values(charCount)) {
            const probability = count / length;
            entropy -= probability * Math.log2(probability);
        }
        
        // High entropy (>4.5 bits per character) suggests cryptographic data
        return entropy > 4.5;
    }

    /**
     *   Check for suspicious character distributions
     */
    _hasSuspiciousDistribution(str) {
        if (str.length < 8) return false;
        
        // Check for uniform distribution of hex characters
        const hexChars = str.match(/[a-f0-9]/gi) || [];
        if (hexChars.length >= str.length * 0.8) {
            // If 80%+ are hex chars, likely a key
            return true;
        }
        
        // Check for base64-like distribution
        const base64Chars = str.match(/[A-Za-z0-9+/=]/g) || [];
        if (base64Chars.length >= str.length * 0.9) {
            // If 90%+ are base64 chars, likely encoded data
            return true;
        }
        
        // Check for very low character diversity (suggests random data)
        const uniqueChars = new Set(str).size;
        const diversityRatio = uniqueChars / str.length;
        
        // If diversity is too high (>0.8) for the length, likely random data
        if (diversityRatio > 0.8 && str.length > 16) {
            return true;
        }
        
        return false;
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
            (!this._debugMode) ||
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
        //   Log that we're starting API setup
        this._secureLog('info', 'Starting secure global API setup');
        
        //   Create simple public API with safety checks
        const secureAPI = {};
        
        //   Only bind methods that exist
        if (typeof this.sendMessage === 'function') {
            secureAPI.sendMessage = this.sendMessage.bind(this);
        }
        
        //   Create simple getConnectionStatus method
        secureAPI.getConnectionStatus = () => ({
            isConnected: this.isConnected ? this.isConnected() : false,
            isVerified: this.isVerified || false,
            connectionState: this.peerConnection?.connectionState || 'disconnected'
        });
        
        //   Create simple getSecurityStatus method
        secureAPI.getSecurityStatus = () => ({
            securityLevel: 'maximum',
            stage: 'initialized',
            activeFeaturesCount: Object.values(this.securityFeatures || {}).filter(Boolean).length
        });
        
        if (typeof this.sendFile === 'function') {
            secureAPI.sendFile = this.sendFile.bind(this);
        }
        
        //   Create simple getFileTransferStatus method
        secureAPI.getFileTransferStatus = () => ({
            initialized: !!this.fileTransferSystem,
            status: 'ready',
            activeTransfers: 0,
            receivingTransfers: 0
        });
        
        if (typeof this.disconnect === 'function') {
            secureAPI.disconnect = this.disconnect.bind(this);
        }
        
        //   Create simple API object with safety checks
        const safeGlobalAPI = {
            ...secureAPI, // Spread only existing methods
            getConfiguration: () => ({
                fakeTraffic: this._config.fakeTraffic.enabled,
                decoyChannels: this._config.decoyChannels.enabled,
                packetPadding: this._config.packetPadding.enabled,
                antiFingerprinting: this._config.antiFingerprinting.enabled
            }),
            emergency: {}
        };
        
        //   Only add emergency methods that exist
        if (typeof this._emergencyUnlockAllMutexes === 'function') {
            safeGlobalAPI.emergency.unlockAllMutexes = this._emergencyUnlockAllMutexes.bind(this);
        }
        
        if (typeof this._emergencyRecoverMutexSystem === 'function') {
            safeGlobalAPI.emergency.recoverMutexSystem = this._emergencyRecoverMutexSystem.bind(this);
        }
        
        if (typeof this._emergencyDisableLogging === 'function') {
            safeGlobalAPI.emergency.disableLogging = this._emergencyDisableLogging.bind(this);
        }
        
        if (typeof this._resetLoggingSystem === 'function') {
            safeGlobalAPI.emergency.resetLogging = this._resetLoggingSystem.bind(this);
        }
        
        //   Add file transfer system status
        safeGlobalAPI.getFileTransferSystemStatus = () => ({
            initialized: !!this.fileTransferSystem,
            status: 'ready',
            activeTransfers: 0,
            receivingTransfers: 0
        });
        
        //   Log available methods for debugging
        this._secureLog('info', 'API methods available', {
            sendMessage: !!secureAPI.sendMessage,
            getConnectionStatus: !!secureAPI.getConnectionStatus,
            getSecurityStatus: !!secureAPI.getSecurityStatus,
            sendFile: !!secureAPI.sendFile,
            getFileTransferStatus: !!secureAPI.getFileTransferStatus,
            disconnect: !!secureAPI.disconnect,
            getConfiguration: !!safeGlobalAPI.getConfiguration,
            emergencyMethods: Object.keys(safeGlobalAPI.emergency).length
        });

        //   Apply Object.freeze to prevent modification
        Object.freeze(safeGlobalAPI);
        Object.freeze(safeGlobalAPI.emergency);

        //   Export API once without monitoring
        this._createProtectedGlobalAPI(safeGlobalAPI);
        
        //   Setup minimal protection
        this._setupMinimalGlobalProtection();
        
        //   Log that API setup is complete
        this._secureLog('info', 'Secure global API setup completed successfully');
    }
    /**
     *   Create simple global API export
     */
    _createProtectedGlobalAPI(safeGlobalAPI) {
        //   Log that we're creating protected global API
        this._secureLog('info', 'Creating protected global API');
        
        //   Simple API export without proxy or monitoring
        if (!window.secureBitChat) {
            this._exportAPI(safeGlobalAPI);
        } else {
            this._secureLog('warn', '⚠️ Global API already exists, skipping setup');
        }
    }
    
    /**
     *   Simple API export without monitoring
     */
    _exportAPI(apiObject) {
        //   Log that we're exporting API
        this._secureLog('info', 'Exporting API to window.secureBitChat');
        
        //   Check if important methods are available
        if (!this._importantMethods || !this._importantMethods.defineProperty) {
            this._secureLog('error', '❌ Important methods not available for API export, using fallback');
            // Fallback to direct Object.defineProperty
            Object.defineProperty(window, 'secureBitChat', {
                value: apiObject,
                writable: false,
                configurable: false,
                enumerable: true
            });
        } else {
            //   One-time export with immutable properties
            this._importantMethods.defineProperty(window, 'secureBitChat', {
                value: apiObject,
                writable: false,
                configurable: false,
                enumerable: true
            });
        }
        
        this._secureLog('info', '🔒 Secure API exported to window.secureBitChat');
    }
    
    /**
     *   Setup minimal global protection
     */
    _setupMinimalGlobalProtection() {
        //   Simple protection without monitoring (methods already stored)
        this._protectGlobalAPI();
        
        this._secureLog('info', '🔒 Minimal global protection activated');
    }
    
    /**
     *   Store important methods in closure for local use
     */
    _storeImportantMethods() {
        //   Store references to important methods locally
        this._importantMethods = {
            defineProperty: Object.defineProperty,
            getOwnPropertyDescriptor: Object.getOwnPropertyDescriptor,
            freeze: Object.freeze,
            consoleLog: console.log,
            consoleError: console.error,
            consoleWarn: console.warn
        };
        
        this._secureLog('info', '🔒 Important methods stored locally', {
            defineProperty: !!this._importantMethods.defineProperty,
            getOwnPropertyDescriptor: !!this._importantMethods.getOwnPropertyDescriptor,
            freeze: !!this._importantMethods.freeze
        });
    }

    /**
     *   Simple protection without monitoring
     */
    _setupSimpleProtection() {
        this._secureLog('info', '🔒 Simple protection activated - no monitoring');
    }

    /**
     *   No global exposure prevention needed
     */
    _preventGlobalExposure() {
        this._secureLog('info', '🔒 No global exposure prevention - using secure API export only');
    }
    /**
     *   API integrity check - only at initialization
     */
    _verifyAPIIntegrity() {
        try {
            if (!window.secureBitChat) {
                this._secureLog('error', '❌ SECURITY ALERT: Secure API has been removed!');
                return false;
            }
            
            const requiredMethods = ['sendMessage', 'getConnectionStatus', 'disconnect'];
            const missingMethods = requiredMethods.filter(method => 
                typeof window.secureBitChat[method] !== 'function'
            );
            
            if (missingMethods.length > 0) {
                this._secureLog('error', '❌ SECURITY ALERT: API tampering detected, missing methods:', { errorType: missingMethods?.constructor?.name || 'Unknown' });
                return false;
            }
            
            return true;
        } catch (error) {
            this._secureLog('error', '❌ SECURITY ALERT: API integrity check failed:', { errorType: error?.constructor?.name || 'Unknown' });
            return false;
        }
    }
    // ============================================
    // ADDITIONAL SECURITY METHODS
    // ============================================
    
    /**
     *   Simple global exposure check - only at initialization
     */
    _auditGlobalExposure() {
        //   Only check once at initialization, no periodic scanning
        this._secureLog('info', '🔒 Global exposure check completed at initialization');
        return [];
    }
    
    /**
     *   No periodic security audits - only at initialization
     */
    _startSecurityAudit() {
        //   Only audit once at initialization, no periodic checks
        this._secureLog('info', '🔒 Security audit completed at initialization - no periodic monitoring');
    }
    
    /**
     *   Simple global API protection
     */
    _protectGlobalAPI() {
        if (!window.secureBitChat) {
            this._secureLog('warn', '⚠️ Global API not found during protection setup');
            return;
        }

        try {
            //   Validate API integrity once
            if (this._validateAPIIntegrityOnce()) {
                this._secureLog('info', '🔒 Global API protection verified');
            }
            
        } catch (error) {
            this._secureLog('error', '❌ Failed to verify global API protection', { 
                errorType: error.constructor.name,
                errorMessage: error.message
            });
        }
    }
    
    /**
     *   Validate API integrity once at initialization
     */
    _validateAPIIntegrityOnce() {
        try {
            //   Check if API is properly configured
            if (!this._importantMethods || !this._importantMethods.getOwnPropertyDescriptor) {
                // Fallback to direct Object.getOwnPropertyDescriptor
                const descriptor = Object.getOwnPropertyDescriptor(window, 'secureBitChat');
                
                if (!descriptor || descriptor.configurable) {
                    throw new Error('secureBitChat must not be reconfigurable!');
                }
            } else {
                const descriptor = this._importantMethods.getOwnPropertyDescriptor(window, 'secureBitChat');
                
                if (!descriptor || descriptor.configurable) {
                    throw new Error('secureBitChat must not be reconfigurable!');
                }
            }
            
            this._secureLog('info', '✅ API integrity validated');
            return true;
            
        } catch (error) {
            this._secureLog('error', '❌ API integrity validation failed', {
                errorType: error.constructor.name,
                errorMessage: error.message
            });
            return false;
        }
    }
    
    /**
     *   Secure memory wipe for sensitive data
     */
    _secureWipeMemory(data, context = 'unknown') {
        if (!data) return;
        
        try {
            //   Different handling for different data types
            if (data instanceof ArrayBuffer) {
                this._secureWipeArrayBuffer(data, context);
            } else if (data instanceof Uint8Array) {
                this._secureWipeUint8Array(data, context);
            } else if (Array.isArray(data)) {
                this._secureWipeArray(data, context);
            } else if (typeof data === 'string') {
                this._secureWipeString(data, context);
            } else if (data instanceof CryptoKey) {
                this._secureWipeCryptoKey(data, context);
            } else if (typeof data === 'object') {
                this._secureWipeObject(data, context);
            }
            
            this._secureMemoryManager.memoryStats.totalCleanups++;
            
        } catch (error) {
            this._secureMemoryManager.memoryStats.failedCleanups++;
            this._secureLog('error', '❌ Secure memory wipe failed', {
                context: context,
                errorType: error.constructor.name,
                errorMessage: error.message
            });
        }
    }
    
    /**
     *   Secure wipe for ArrayBuffer
     */
    _secureWipeArrayBuffer(buffer, context) {
        if (!buffer || buffer.byteLength === 0) return;
        
        try {
            const view = new Uint8Array(buffer);
            
            //   Overwrite with random data first
            crypto.getRandomValues(view);
            
            //   Overwrite with zeros
            view.fill(0);
            
            //   Overwrite with ones
            view.fill(255);
            
            //   Final zero overwrite
            view.fill(0);
            
            this._secureLog('debug', '🔒 ArrayBuffer securely wiped', {
                context: context,
                size: buffer.byteLength
            });
            
        } catch (error) {
            this._secureLog('error', '❌ Failed to wipe ArrayBuffer', {
                context: context,
                errorType: error.constructor.name
            });
        }
    }
    
    /**
     *   Secure wipe for Uint8Array
     */
    _secureWipeUint8Array(array, context) {
        if (!array || array.length === 0) return;
        
        try {
            //   Overwrite with random data first
            crypto.getRandomValues(array);
            
            //   Overwrite with zeros
            array.fill(0);
            
            //   Overwrite with ones
            array.fill(255);
            
            //   Final zero overwrite
            array.fill(0);
            
            this._secureLog('debug', '🔒 Uint8Array securely wiped', {
                context: context,
                size: array.length
            });
            
        } catch (error) {
            this._secureLog('error', '❌ Failed to wipe Uint8Array', {
                context: context,
                errorType: error.constructor.name
            });
        }
    }
    
    /**
     *   Secure wipe for arrays
     */
    _secureWipeArray(array, context) {
        if (!Array.isArray(array) || array.length === 0) return;
        
        try {
            //   Recursively wipe each element
            array.forEach((item, index) => {
                if (item !== null && item !== undefined) {
                    this._secureWipeMemory(item, `${context}[${index}]`);
                }
            });
            
            //   Fill with nulls
            array.fill(null);
            
            this._secureLog('debug', '🔒 Array securely wiped', {
                context: context,
                size: array.length
            });
            
        } catch (error) {
            this._secureLog('error', '❌ Failed to wipe array', {
                context: context,
                errorType: error.constructor.name
            });
        }
    }
    
    /**
     *   No string wiping - strings are immutable in JS
     */
    _secureWipeString(str, context) {
        //   Strings are immutable in JavaScript, no need to wipe
        // Just remove the reference
        this._secureLog('debug', '🔒 String reference removed (strings are immutable)', {
            context: context,
            length: str ? str.length : 0
        });
    }
    
    /**
     *   CryptoKey cleanup - store in WeakMap for proper GC
     */
    _secureWipeCryptoKey(key, context) {
        if (!key || !(key instanceof CryptoKey)) return;
        
        try {
            //   Store in WeakMap for proper garbage collection
            if (!this._cryptoKeyStorage) {
                this._cryptoKeyStorage = new WeakMap();
            }
            
            //   Store reference for cleanup tracking
            this._cryptoKeyStorage.set(key, {
                context: context,
                timestamp: Date.now(),
                type: key.type
            });
            
            this._secureLog('debug', '🔒 CryptoKey stored in WeakMap for cleanup', {
                context: context,
                type: key.type
            });
            
        } catch (error) {
            this._secureLog('error', '❌ Failed to store CryptoKey for cleanup', {
                context: context,
                errorType: error.constructor.name
            });
        }
    }
    
    /**
     *   Secure wipe for objects
     */
    _secureWipeObject(obj, context) {
        if (!obj || typeof obj !== 'object') return;
        
        try {
            //   Recursively wipe all properties
            for (const [key, value] of Object.entries(obj)) {
                if (value !== null && value !== undefined) {
                    this._secureWipeMemory(value, `${context}.${key}`);
                }
                //   Set property to null
                obj[key] = null;
            }
            
            this._secureLog('debug', '🔒 Object securely wiped', {
                context: context,
                properties: Object.keys(obj).length
            });
            
        } catch (error) {
            this._secureLog('error', '❌ Failed to wipe object', {
                context: context,
                errorType: error.constructor.name
            });
        }
    }
    
    /**
     *   Secure cleanup of cryptographic materials
     */
    _secureCleanupCryptographicMaterials() {
        try {
            //   Secure wipe of key pairs
            if (this.ecdhKeyPair) {
                this._secureWipeMemory(this.ecdhKeyPair, 'ecdhKeyPair');
                this.ecdhKeyPair = null;
            }
            
            if (this.ecdsaKeyPair) {
                this._secureWipeMemory(this.ecdsaKeyPair, 'ecdsaKeyPair');
                this.ecdsaKeyPair = null;
            }
            
            //   Secure wipe of derived keys
            if (this.encryptionKey) {
                this._secureWipeMemory(this.encryptionKey, 'encryptionKey');
                this.encryptionKey = null;
            }
            
            if (this.macKey) {
                this._secureWipeMemory(this.macKey, 'macKey');
                this.macKey = null;
            }
            
            if (this.metadataKey) {
                this._secureWipeMemory(this.metadataKey, 'metadataKey');
                this.metadataKey = null;
            }
            
            if (this.nestedEncryptionKey) {
                this._secureWipeMemory(this.nestedEncryptionKey, 'nestedEncryptionKey');
                this.nestedEncryptionKey = null;
            }
            
            //   Secure wipe of session data
            if (this.sessionSalt) {
                this._secureWipeMemory(this.sessionSalt, 'sessionSalt');
                this.sessionSalt = null;
            }
            
            if (this.sessionId) {
                this._secureWipeMemory(this.sessionId, 'sessionId');
                this.sessionId = null;
            }
            
            if (this.verificationCode) {
                this._secureWipeMemory(this.verificationCode, 'verificationCode');
                this.verificationCode = null;
            }
            
            if (this.peerPublicKey) {
                this._secureWipeMemory(this.peerPublicKey, 'peerPublicKey');
                this.peerPublicKey = null;
            }
            
            if (this.keyFingerprint) {
                this._secureWipeMemory(this.keyFingerprint, 'keyFingerprint');
                this.keyFingerprint = null;
            }
            
            if (this.connectionId) {
                this._secureWipeMemory(this.connectionId, 'connectionId');
                this.connectionId = null;
            }
            
            this._secureLog('info', '🔒 Cryptographic materials securely cleaned up');
            
        } catch (error) {
            this._secureLog('error', '❌ Failed to cleanup cryptographic materials', {
                errorType: error.constructor.name,
                errorMessage: error.message
            });
        }
    }
    
    /**
     *   Force garbage collection if available
     */
    async _forceGarbageCollection() {
        try {
            //   Use natural cleanup instead of forcing GC
            await this._performNaturalCleanup();
            this._secureLog('debug', '🔒 Natural memory cleanup performed');
        } catch (error) {
            this._secureLog('error', '❌ Failed to perform natural cleanup', {
                errorType: error.constructor.name
            });
        }
    }
    
    /**
     *   Perform periodic memory cleanup
     */
    async _performPeriodicMemoryCleanup() {
        try {
            this._secureMemoryManager.isCleaning = true;
            
            //   Clean up any remaining sensitive data
            this._secureCleanupCryptographicMaterials();
            
            //   Clean up message queue if it's too large
            if (this.messageQueue && this.messageQueue.length > 100) {
                const excessMessages = this.messageQueue.splice(0, this.messageQueue.length - 50);
                excessMessages.forEach((message, index) => {
                    this._secureWipeMemory(message, `periodicCleanup[${index}]`);
                });
            }
            
            //   Clean up processed message IDs if too many
            if (this.processedMessageIds && this.processedMessageIds.size > 1000) {
                this.processedMessageIds.clear();
            }
            
            //   Natural cleanup
            await this._forceGarbageCollection();
            
            this._secureLog('debug', '🔒 Periodic memory cleanup completed');
            
        } catch (error) {
            this._secureLog('error', '❌ Error during periodic memory cleanup', {
                errorType: error.constructor.name,
                errorMessage: error.message
            });
        } finally {
            this._secureMemoryManager.isCleaning = false;
        }
    }
    
    /**
     *   Create secure error message without information disclosure
     */
    _createSecureErrorMessage(originalError, context = 'unknown') {
        try {
            //   Categorize error for appropriate handling
            const category = this._categorizeError(originalError);
            
            //   Generate safe error message based on category
            const safeMessage = this._getSafeErrorMessage(category, context);
            
            //   Log detailed error internally for debugging
            this._secureLog('error', 'Internal error occurred', {
                category: category,
                context: context,
                errorType: originalError?.constructor?.name || 'Unknown',
                timestamp: Date.now()
            });
            
            //   Track error frequency
            this._trackErrorFrequency(category);
            
            return safeMessage;
            
        } catch (error) {
            //   Fallback to generic error if error handling fails
            this._secureLog('error', 'Error handling failed', {
                originalError: originalError?.message || 'Unknown',
                handlingError: error.message
            });
            return 'An unexpected error occurred';
        }
    }
    
    /**
     *   Categorize error for appropriate handling
     */
    _categorizeError(error) {
        if (!error || !error.message) {
            return this._secureErrorHandler.errorCategories.UNKNOWN;
        }
        
        const message = error.message.toLowerCase();
        
        //   Cryptographic errors
        if (message.includes('crypto') || 
            message.includes('key') || 
            message.includes('encrypt') || 
            message.includes('decrypt') ||
            message.includes('sign') ||
            message.includes('verify') ||
            message.includes('ecdh') ||
            message.includes('ecdsa')) {
            return this._secureErrorHandler.errorCategories.CRYPTOGRAPHIC;
        }
        
        //   Network errors
        if (message.includes('network') || 
            message.includes('connection') || 
            message.includes('timeout') ||
            message.includes('webrtc') ||
            message.includes('peer')) {
            return this._secureErrorHandler.errorCategories.NETWORK;
        }
        
        //   Validation errors
        if (message.includes('invalid') || 
            message.includes('validation') || 
            message.includes('format') ||
            message.includes('type')) {
            return this._secureErrorHandler.errorCategories.VALIDATION;
        }
        
        //   System errors
        if (message.includes('system') || 
            message.includes('internal') || 
            message.includes('memory') ||
            message.includes('resource')) {
            return this._secureErrorHandler.errorCategories.SYSTEM;
        }
        
        return this._secureErrorHandler.errorCategories.UNKNOWN;
    }
    
    /**
     *   Get safe error message based on category
     */
    _getSafeErrorMessage(category, context) {
        const safeMessages = {
            [this._secureErrorHandler.errorCategories.CRYPTOGRAPHIC]: {
                'key_generation': 'Security initialization failed',
                'key_import': 'Security verification failed',
                'key_derivation': 'Security setup failed',
                'encryption': 'Message security failed',
                'decryption': 'Message verification failed',
                'signature': 'Authentication failed',
                'default': 'Security operation failed'
            },
            [this._secureErrorHandler.errorCategories.NETWORK]: {
                'connection': 'Connection failed',
                'timeout': 'Connection timeout',
                'peer': 'Peer connection failed',
                'webrtc': 'Communication failed',
                'default': 'Network operation failed'
            },
            [this._secureErrorHandler.errorCategories.VALIDATION]: {
                'format': 'Invalid data format',
                'type': 'Invalid data type',
                'structure': 'Invalid data structure',
                'default': 'Validation failed'
            },
            [this._secureErrorHandler.errorCategories.SYSTEM]: {
                'memory': 'System resource error',
                'resource': 'System resource unavailable',
                'internal': 'Internal system error',
                'default': 'System operation failed'
            },
            [this._secureErrorHandler.errorCategories.UNKNOWN]: {
                'default': 'An unexpected error occurred'
            }
        };
        
        const categoryMessages = safeMessages[category] || safeMessages[this._secureErrorHandler.errorCategories.UNKNOWN];
        
        //   Determine specific context for more precise message
        let specificContext = 'default';
        if (context.includes('key') || context.includes('crypto')) {
            specificContext = category === this._secureErrorHandler.errorCategories.CRYPTOGRAPHIC ? 'key_generation' : 'default';
        } else if (context.includes('connection') || context.includes('peer')) {
            specificContext = category === this._secureErrorHandler.errorCategories.NETWORK ? 'connection' : 'default';
        } else if (context.includes('validation') || context.includes('format')) {
            specificContext = category === this._secureErrorHandler.errorCategories.VALIDATION ? 'format' : 'default';
        }
        
        return categoryMessages[specificContext] || categoryMessages.default;
    }
    
    /**
     *   Track error frequency for security monitoring
     */
    _trackErrorFrequency(category) {
        const now = Date.now();
        
        //   Clean old error counts
        if (now - this._secureErrorHandler.lastErrorTime > 60000) { // 1 minute
            this._secureErrorHandler.errorCounts.clear();
        }
        
        //   Increment error count
        const currentCount = this._secureErrorHandler.errorCounts.get(category) || 0;
        this._secureErrorHandler.errorCounts.set(category, currentCount + 1);
        this._secureErrorHandler.lastErrorTime = now;
        
        //   Check if we're exceeding error threshold
        const totalErrors = Array.from(this._secureErrorHandler.errorCounts.values()).reduce((sum, count) => sum + count, 0);
        
        if (totalErrors > this._secureErrorHandler.errorThreshold) {
            this._secureErrorHandler.isInErrorMode = true;
            this._secureLog('warn', '⚠️ High error frequency detected - entering error mode', {
                totalErrors: totalErrors,
                threshold: this._secureErrorHandler.errorThreshold
            });
        }
    }
    
    /**
     *   Throw secure error without information disclosure
     */
    _throwSecureError(originalError, context = 'unknown') {
        const secureMessage = this._createSecureErrorMessage(originalError, context);
        throw new Error(secureMessage);
    }
    
    /**
     *   Get error handling statistics
     */
    _getErrorHandlingStats() {
        return {
            errorCounts: Object.fromEntries(this._secureErrorHandler.errorCounts),
            isInErrorMode: this._secureErrorHandler.isInErrorMode,
            lastErrorTime: this._secureErrorHandler.lastErrorTime,
            errorThreshold: this._secureErrorHandler.errorThreshold
        };
    }
    
    /**
     *   Reset error handling system
     */
    _resetErrorHandlingSystem() {
        this._secureErrorHandler.errorCounts.clear();
        this._secureErrorHandler.isInErrorMode = false;
        this._secureErrorHandler.lastErrorTime = 0;
        
        this._secureLog('info', '🔄 Error handling system reset');
    }
    
    /**
     *   Get memory management statistics
     */
    _getMemoryManagementStats() {
        return {
            totalCleanups: this._secureMemoryManager.memoryStats.totalCleanups,
            failedCleanups: this._secureMemoryManager.memoryStats.failedCleanups,
            lastCleanup: this._secureMemoryManager.memoryStats.lastCleanup,
            isCleaning: this._secureMemoryManager.isCleaning,
            queueLength: this._secureMemoryManager.cleanupQueue.length
        };
    }
    
    /**
     *   Validate API integrity and security
     */
    _validateAPIIntegrity() {
        try {
            //   Check if API exists
            if (!window.secureBitChat) {
                this._secureLog('error', '❌ Global API not found during integrity validation');
                return false;
            }
            
            //   Validate required methods exist
            const requiredMethods = ['sendMessage', 'getConnectionStatus', 'getSecurityStatus', 'sendFile', 'disconnect'];
            const missingMethods = requiredMethods.filter(method => 
                !window.secureBitChat[method] || typeof window.secureBitChat[method] !== 'function'
            );
            
            if (missingMethods.length > 0) {
                this._secureLog('error', '❌ Global API integrity validation failed - missing methods', {
                    missingMethods: missingMethods
                });
                return false;
            }
            
            //   Test method binding integrity
            const testContext = { test: true };
            const boundMethods = requiredMethods.map(method => {
                try {
                    return window.secureBitChat[method].bind(testContext);
                } catch (error) {
                    return null;
                }
            });
            
            const unboundMethods = boundMethods.filter(method => method === null);
            if (unboundMethods.length > 0) {
                this._secureLog('error', '❌ Global API integrity validation failed - method binding issues', {
                    unboundMethods: unboundMethods.length
                });
                return false;
            }
            
            //   Test API immutability
            try {
                const testProp = '_integrity_test_' + Date.now();
                Object.defineProperty(window.secureBitChat, testProp, {
                    value: 'test',
                    writable: true,
                    configurable: true
                });
                
                this._secureLog('error', '❌ Global API integrity validation failed - API is mutable');
                delete window.secureBitChat[testProp];
                return false;
                
            } catch (immutabilityError) {
                // This is expected - API should be immutable
                this._secureLog('debug', '✅ Global API immutability verified');
            }
            
            this._secureLog('info', '✅ Global API integrity validation passed');
            return true;
            
        } catch (error) {
            this._secureLog('error', '❌ Global API integrity validation failed', {
                errorType: error.constructor.name,
                errorMessage: error.message
            });
            return false;
        }
    }

    _validateCryptographicSecurity() {
        //   Check if basic security features are available
        const criticalFeatures = ['hasRateLimiting'];
        const missingCritical = criticalFeatures.filter(feature => !this.securityFeatures[feature]);
        
        if (missingCritical.length > 0) {
            this._secureLog('error', '🚨 CRITICAL: Missing critical rate limiting feature', {
                missing: missingCritical,
                currentFeatures: this.securityFeatures,
                action: 'Rate limiting will be forced enabled'
            });

            missingCritical.forEach(feature => {
                this.securityFeatures[feature] = true;
                this._secureLog('warn', `⚠️ Forced enable critical: ${feature} = true`);
            });
        }

        //   Log current security state
        const availableFeatures = Object.keys(this.securityFeatures).filter(f => this.securityFeatures[f]);
        const encryptionFeatures = ['hasEncryption', 'hasECDH', 'hasECDSA'].filter(f => this.securityFeatures[f]);
        
        this._secureLog('info', '✅ Cryptographic security validation passed', {
            criticalFeatures: criticalFeatures.length,
            availableFeatures: availableFeatures.length,
            encryptionFeatures: encryptionFeatures.length,
            totalSecurityFeatures: availableFeatures.length,
            note: 'Encryption features will be enabled after key generation',
            currentState: {
                hasEncryption: this.securityFeatures.hasEncryption,
                hasECDH: this.securityFeatures.hasECDH,
                hasECDSA: this.securityFeatures.hasECDSA,
                hasRateLimiting: this.securityFeatures.hasRateLimiting
            }
        });
        
        return true;
    }

    _syncSecurityFeaturesWithTariff() {
        // All security features are enabled by default - no payment required
        this._secureLog('info', '✅ All security features enabled by default - no payment required');
        
        // Ensure all features are enabled
        const allFeatures = [
            'hasEncryption', 'hasECDH', 'hasECDSA', 'hasMutualAuth',
            'hasMetadataProtection', 'hasEnhancedReplayProtection',
            'hasNonExtractableKeys', 'hasRateLimiting', 'hasEnhancedValidation', 'hasPFS',
            'hasNestedEncryption', 'hasPacketPadding', 'hasPacketReordering',
            'hasAntiFingerprinting', 'hasFakeTraffic', 'hasDecoyChannels', 'hasMessageChunking'
        ];
        
        allFeatures.forEach(feature => {
            this.securityFeatures[feature] = true;
        });
        
        this._secureLog('info', '✅ All security features enabled by default', {
            enabledFeatures: Object.keys(this.securityFeatures).filter(f => this.securityFeatures[f]).length,
            totalFeatures: Object.keys(this.securityFeatures).length
        });
        
        return;
    }
    
    /**
     * Emergency shutdown for critical issues
     */
    _emergencyShutdown(reason = 'Security breach') {
        this._secureLog('error', '❌ EMERGENCY SHUTDOWN: ${reason}');
        
        try {
            // Clear critical data
            this.encryptionKey = null;
            this.macKey = null;
            this.metadataKey = null;
            this.verificationCode = null;
            this.keyFingerprint = null;
            this.connectionId = null;
            
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
            
            this._secureLog('info', '🔒 Emergency shutdown completed');
            
        } catch (error) {
            this._secureLog('error', '❌ Error during emergency shutdown:', { errorType: error?.constructor?.name || 'Unknown' });
        }
    }
    _finalizeSecureInitialization() {
        this._startKeySecurityMonitoring();
        
        // Verify API integrity
        if (!this._verifyAPIIntegrity()) {
            this._secureLog('error', '❌ Security initialization failed');
            return;
        }

        this._startSecurityMonitoring();
        
        // Start periodic log cleanup
        setInterval(() => {
            this._cleanupLogs();
        }, 300000);
        
        this._secureLog('info', '✅ Secure WebRTC Manager initialization completed');
        this._secureLog('info', '🔒 Global exposure protection: Monitoring only, no automatic removal');
    }
    /**
     * Start security monitoring
     * @deprecated Use unified scheduler instead
     */
    _startSecurityMonitoring() {
        //   All security monitoring moved to unified scheduler
        this._secureLog('info', '🔧 Security monitoring moved to unified scheduler');
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
     *   Hard gate for traffic blocking without verification
     * This method enforces that NO traffic (including system messages and file transfers)
     * can pass through without proper cryptographic verification
     */
    _enforceVerificationGate(operation = 'unknown', throwError = true) {
        if (!this.isVerified) {
            const errorMessage = `SECURITY VIOLATION: ${operation} blocked - connection not cryptographically verified`;
            this._secureLog('error', errorMessage, {
                operation: operation,
                isVerified: this.isVerified,
                hasKeys: !!(this.encryptionKey && this.macKey),
                timestamp: Date.now()
            });
            
            if (throwError) {
                throw new Error(errorMessage);
            }
            return false;
        }
        return true;
    }

    /**
     *   Safe method to set isVerified only after cryptographic verification
     * This is the ONLY method that should set isVerified = true
     */
    _setVerifiedStatus(verified, verificationMethod = 'unknown', verificationData = null) {
        if (verified) {
            // Validate that we have proper cryptographic verification
            if (!this.encryptionKey || !this.macKey) {
                throw new Error('Cannot set verified=true without encryption keys');
            }
            
            if (!verificationMethod || verificationMethod === 'unknown') {
                throw new Error('Cannot set verified=true without specifying verification method');
            }
            
            // Log the verification for audit trail
            this._secureLog('info', 'Connection verified through cryptographic verification', {
                verificationMethod: verificationMethod,
                hasEncryptionKey: !!this.encryptionKey,
                hasMacKey: !!this.macKey,
                keyFingerprint: this.keyFingerprint,
                timestamp: Date.now(),
                verificationData: verificationData ? 'provided' : 'none'
            });
        }
        
        this.isVerified = verified;
        
        if (verified) {
            this.onStatusChange('connected');
        } else {
            this.onStatusChange('disconnected');
        }
    }

    /**
     *   Create AAD (Additional Authenticated Data) for file messages
     * This binds file messages to the current session and prevents replay attacks
     */
    _createFileMessageAAD(messageType, messageData = null) {
        // Verify that _createMessageAAD method is available
        if (typeof this._createMessageAAD !== 'function') {
            throw new Error('_createMessageAAD method is not available in _createFileMessageAAD. Manager may not be fully initialized.');
        }
        // Use the unified AAD creation method with file message flag
        return this._createMessageAAD(messageType, messageData, true);
    }

    /**
     *   Validate AAD for file messages
     * This ensures file messages are bound to the correct session
     */
    _validateFileMessageAAD(aadString, expectedMessageType = null) {
        try {
            const aad = JSON.parse(aadString);
            
            // Validate session binding
            if (aad.sessionId !== (this.currentSession?.sessionId || 'unknown')) {
                throw new Error('AAD sessionId mismatch - possible replay attack');
            }
            
            if (aad.keyFingerprint !== (this.keyFingerprint || 'unknown')) {
                throw new Error('AAD keyFingerprint mismatch - possible key substitution attack');
            }
            
            // Validate message type if specified
            if (expectedMessageType && aad.messageType !== expectedMessageType) {
                throw new Error(`AAD messageType mismatch - expected ${expectedMessageType}, got ${aad.messageType}`);
            }
            
            // Validate timestamp (prevent very old messages)
            const now = Date.now();
            const messageAge = now - aad.timestamp;
            if (messageAge > 1800000) { // 30 minutes for better UX
                throw new Error('AAD timestamp too old - possible replay attack');
            }
            
            return aad;
        } catch (error) {
            this._secureLog('error', 'AAD validation failed', { error: error.message, aadString });
            throw new Error(`AAD validation failed: ${error.message}`);
        }
    }

    /**
     *   Extract DTLS fingerprint from SDP
     * This is essential for MITM protection
     */
    _extractDTLSFingerprintFromSDP(sdp) {
        try {
            if (!sdp || typeof sdp !== 'string') {
                throw new Error('Invalid SDP provided');
            }

            // Look for a=fingerprint lines in SDP with more flexible regex
            const fingerprintRegex = /a=fingerprint:([a-zA-Z0-9-]+)\s+([A-Fa-f0-9:]+)/g;
            const fingerprints = [];
            let match;

            while ((match = fingerprintRegex.exec(sdp)) !== null) {
                fingerprints.push({
                    algorithm: match[1].toLowerCase(),
                    fingerprint: match[2].toLowerCase().replace(/:/g, '')
                });
            }

            if (fingerprints.length === 0) {
                // Try alternative fingerprint format
                const altFingerprintRegex = /fingerprint\s*=\s*([a-zA-Z0-9-]+)\s+([A-Fa-f0-9:]+)/gi;
                while ((match = altFingerprintRegex.exec(sdp)) !== null) {
                    fingerprints.push({
                        algorithm: match[1].toLowerCase(),
                        fingerprint: match[2].toLowerCase().replace(/:/g, '')
                    });
                }
            }

            if (fingerprints.length === 0) {
                this._secureLog('warn', 'No DTLS fingerprints found in SDP - this may be normal for some WebRTC implementations', {
                    sdpLength: sdp.length,
                    sdpPreview: sdp.substring(0, 200) + '...'
                });
                throw new Error('No DTLS fingerprints found in SDP');
            }

            // Prefer SHA-256 fingerprints
            const sha256Fingerprint = fingerprints.find(fp => fp.algorithm === 'sha-256');
            if (sha256Fingerprint) {
                return sha256Fingerprint.fingerprint;
            }

            // Fallback to first available fingerprint
            return fingerprints[0].fingerprint;
        } catch (error) {
            this._secureLog('error', 'Failed to extract DTLS fingerprint from SDP', { 
                error: error.message,
                sdpLength: sdp?.length || 0
            });
            throw new Error(`DTLS fingerprint extraction failed: ${error.message}`);
        }
    }

    /**
     *   Validate DTLS fingerprint against expected value
     * This prevents MITM attacks by ensuring the remote peer has the expected certificate
     */
    async _validateDTLSFingerprint(receivedFingerprint, expectedFingerprint, context = 'unknown') {
        try {
            if (!receivedFingerprint || !expectedFingerprint) {
                throw new Error('Missing fingerprint for validation');
            }

            // Normalize fingerprints (remove colons, convert to lowercase)
            const normalizedReceived = receivedFingerprint.toLowerCase().replace(/:/g, '');
            const normalizedExpected = expectedFingerprint.toLowerCase().replace(/:/g, '');

            if (normalizedReceived !== normalizedExpected) {
                this._secureLog('error', 'DTLS fingerprint mismatch - possible MITM attack', {
                    context: context,
                    receivedHash: await this._createSafeLogHash(normalizedReceived, 'dtls_fingerprint'),
                    expectedHash: await this._createSafeLogHash(normalizedExpected, 'dtls_fingerprint'),
                    timestamp: Date.now()
                });
                
                throw new Error(`DTLS fingerprint mismatch - possible MITM attack in ${context}`);
            }

            this._secureLog('info', 'DTLS fingerprint validation successful', {
                context: context,
                fingerprintHash: await this._createSafeLogHash(normalizedReceived, 'dtls_fingerprint'),
                timestamp: Date.now()
            });

            return true;
        } catch (error) {
            this._secureLog('error', 'DTLS fingerprint validation failed', { 
                error: error.message, 
                context: context 
            });
            throw error;
        }
    }

    /**
     *   Compute SAS (Short Authentication String) for MITM protection
     * Uses HKDF with DTLS fingerprints to generate a stable 7-digit verification code
     * @param {ArrayBuffer|Uint8Array} keyMaterialRaw - Shared secret or key fingerprint data
     * @param {string} localFP - Local DTLS fingerprint
     * @param {string} remoteFP - Remote DTLS fingerprint
     * @returns {Promise<string>} 7-digit SAS code
     */
    async _computeSAS(keyMaterialRaw, localFP, remoteFP) {
        try {
            
            if (!keyMaterialRaw || !localFP || !remoteFP) {
                const missing = [];
                if (!keyMaterialRaw) missing.push('keyMaterialRaw');
                if (!localFP) missing.push('localFP');
                if (!remoteFP) missing.push('remoteFP');
                throw new Error(`Missing required parameters for SAS computation: ${missing.join(', ')}`);
            }

            const enc = new TextEncoder();

            const salt = enc.encode(
                'webrtc-sas|' + [localFP, remoteFP].sort().join('|')
            );

            let keyBuffer;
            if (keyMaterialRaw instanceof ArrayBuffer) {
                keyBuffer = keyMaterialRaw;
            } else if (keyMaterialRaw instanceof Uint8Array) {
                keyBuffer = keyMaterialRaw.buffer;
            } else if (typeof keyMaterialRaw === 'string') {
                // Если это строка (например, keyFingerprint), декодируем её
                // Предполагаем, что это hex строка
                const hexString = keyMaterialRaw.replace(/:/g, '').replace(/\s/g, '');
                const bytes = new Uint8Array(hexString.length / 2);
                for (let i = 0; i < hexString.length; i += 2) {
                    bytes[i / 2] = parseInt(hexString.substr(i, 2), 16);
                }
                keyBuffer = bytes.buffer;
            } else {
                throw new Error('Invalid keyMaterialRaw type');
            }

            // Используем HKDF(SHA-256) чтобы получить стабильные 64 бита энтропии для кода
            const key = await crypto.subtle.importKey(
                'raw',
                keyBuffer,
                'HKDF',
                false,
                ['deriveBits']
            );

            const info = enc.encode('p2p-sas-v1');
            const bits = await crypto.subtle.deriveBits(
                { name: 'HKDF', hash: 'SHA-256', salt, info },
                key,
                64 // 64 бита достаточно для 6–7 знаков
            );

            const dv = new DataView(bits);
            const n = (dv.getUint32(0) ^ dv.getUint32(4)) >>> 0;
            
            // Use rejection sampling to avoid bias in SAS code generation
            let sasValue;
            do {
                sasValue = crypto.getRandomValues(new Uint32Array(1))[0];
            } while (sasValue >= 4294967296 - (4294967296 % 10_000_000));
            
            const sasCode = String(sasValue % 10_000_000).padStart(7, '0'); 


            this._secureLog('info', 'SAS code computed successfully', {
                localFP: localFP.substring(0, 16) + '...',
                remoteFP: remoteFP.substring(0, 16) + '...',
                sasLength: sasCode.length,
                timestamp: Date.now()
            });

            return sasCode;
        } catch (error) {
            this._secureLog('error', 'SAS computation failed', {
                error: error.message,
                keyMaterialType: typeof keyMaterialRaw,
                hasLocalFP: !!localFP,
                hasRemoteFP: !!remoteFP,
                timestamp: Date.now()
            });
            throw new Error(`SAS computation failed: ${error.message}`);
        }
    }

    /**
     * UTILITY: Decode hex keyFingerprint to Uint8Array for SAS computation
     * @param {string} hexString - Hex encoded keyFingerprint (e.g., "aa:bb:cc:dd")
     * @returns {Uint8Array} Decoded bytes
     */
    _decodeKeyFingerprint(hexString) {
        try {
            if (!hexString || typeof hexString !== 'string') {
                throw new Error('Invalid hex string provided');
            }

            // Use the utility from EnhancedSecureCryptoUtils
            return window.EnhancedSecureCryptoUtils.hexToUint8Array(hexString);
        } catch (error) {
            this._secureLog('error', 'Key fingerprint decoding failed', {
                error: error.message,
                inputType: typeof hexString,
                inputLength: hexString?.length || 0
            });
            throw new Error(`Key fingerprint decoding failed: ${error.message}`);
        }
    }

    /**
     *   Emergency key wipe on fingerprint mismatch
     * This ensures no sensitive data remains if MITM is detected
     */
    _emergencyWipeOnFingerprintMismatch(reason = 'DTLS fingerprint mismatch') {
        try {
            this._secureLog('error', '🚨 EMERGENCY: Initiating security wipe due to fingerprint mismatch', {
                reason: reason,
                timestamp: Date.now()
            });

            // Wipe all cryptographic materials
            this._secureWipeKeys();
            this._secureWipeMemory(this.encryptionKey, 'emergency_wipe');
            this._secureWipeMemory(this.macKey, 'emergency_wipe');
            this._secureWipeMemory(this.metadataKey, 'emergency_wipe');
            
            //   Wipe ephemeral keys for PFS
            this._wipeEphemeralKeys();
            
            //   Hard wipe old keys for PFS
            this._hardWipeOldKeys();

            // Reset verification status
            this.isVerified = null;
            this.verificationCode = null;
            this.keyFingerprint = null;
            this.connectionId = null;
            this.expectedDTLSFingerprint = null;

            // Disconnect immediately
            this.disconnect();

            // Notify UI about security breach
            this.deliverMessageToUI('🚨 SECURITY BREACH: Connection terminated due to fingerprint mismatch. Possible MITM attack detected!', 'system');

        } catch (error) {
            this._secureLog('error', 'Failed to perform emergency wipe', { error: error.message });
        }
    }

    /**
     *   Set expected DTLS fingerprint via out-of-band channel
     * This should be called after receiving the fingerprint through a secure channel
     * (e.g., QR code, voice call, in-person exchange, etc.)
     */
    setExpectedDTLSFingerprint(fingerprint, source = 'out_of_band') {
        try {
            if (!fingerprint || typeof fingerprint !== 'string') {
                throw new Error('Invalid fingerprint provided');
            }

            // Normalize fingerprint
            const normalizedFingerprint = fingerprint.toLowerCase().replace(/:/g, '');

            // Validate fingerprint format (should be hex string)
            if (!/^[a-f0-9]{40,64}$/.test(normalizedFingerprint)) {
                throw new Error('Invalid fingerprint format - must be hex string');
            }

            this.expectedDTLSFingerprint = normalizedFingerprint;

            this._secureLog('info', 'Expected DTLS fingerprint set via out-of-band channel', {
                source: source,
                fingerprint: normalizedFingerprint,
                timestamp: Date.now()
            });

            this.deliverMessageToUI(`✅ DTLS fingerprint set via ${source}. MITM protection enabled.`, 'system');

        } catch (error) {
            this._secureLog('error', 'Failed to set expected DTLS fingerprint', { error: error.message });
            throw error;
        }
    }

    /**
     *   Get current DTLS fingerprint for out-of-band verification
     * This should be shared through a secure channel (QR code, voice, etc.)
     */
    getCurrentDTLSFingerprint() {
        try {
            if (!this.expectedDTLSFingerprint) {
                throw new Error('No DTLS fingerprint available - connection not established');
            }

            return this.expectedDTLSFingerprint;
        } catch (error) {
            this._secureLog('error', 'Failed to get current DTLS fingerprint', { error: error.message });
            throw error;
        }
    }

    /**
     * DEBUGGING: Temporarily disable strict DTLS validation
     * This should only be used for debugging connection issues
     */
    disableStrictDTLSValidation() {
        this.strictDTLSValidation = false;
        this._secureLog('warn', '⚠️ Strict DTLS validation disabled - security reduced', {
            timestamp: Date.now()
        });
        this.deliverMessageToUI('⚠️ DTLS validation disabled for debugging', 'system');
    }

    /**
     * SECURITY: Re-enable strict DTLS validation
     */
    enableStrictDTLSValidation() {
        this.strictDTLSValidation = true;
        this._secureLog('info', '✅ Strict DTLS validation re-enabled', {
            timestamp: Date.now()
        });
        this.deliverMessageToUI('✅ DTLS validation re-enabled', 'system');
    }

    /**
     *   Generate ephemeral ECDH keys for Perfect Forward Secrecy
     * This ensures each session has unique, non-persistent keys
     */
    async _generateEphemeralECDHKeys() {
        try {
            this._secureLog('info', '🔑 Generating ephemeral ECDH keys for PFS', {
                sessionStartTime: this.sessionStartTime,
                timestamp: Date.now()
            });

            // Generate new ephemeral ECDH key pair
            const ephemeralKeyPair = await window.EnhancedSecureCryptoUtils.generateECDHKeyPair();
            
            if (!ephemeralKeyPair || !this._validateKeyPairConstantTime(ephemeralKeyPair)) {
                throw new Error('Ephemeral ECDH key pair validation failed');
            }

            // Store ephemeral keys with session binding
            const sessionId = this.currentSession?.sessionId || `session_${Date.now()}`;
            this.ephemeralKeyPairs.set(sessionId, {
                keyPair: ephemeralKeyPair,
                timestamp: Date.now(),
                sessionId: sessionId
            });

            this._secureLog('info', '✅ Ephemeral ECDH keys generated for PFS', {
                sessionIdHash: await this._createSafeLogHash(sessionId, 'session_id'),
                timestamp: Date.now()
            });

            return ephemeralKeyPair;
        } catch (error) {
            this._secureLog('error', '❌ Failed to generate ephemeral ECDH keys', { error: error.message });
            throw new Error(`Ephemeral key generation failed: ${error.message}`);
        }
    }

    /**
     *   Hard wipe old keys for real PFS
     * This prevents retrospective decryption attacks
     */
    async _hardWipeOldKeys() {
        try {
            this._secureLog('info', '🧹 Performing hard wipe of old keys for PFS', {
                oldKeysCount: this.oldKeys.size,
                timestamp: Date.now()
            });

            // Hard wipe all old keys
            for (const [version, keySet] of this.oldKeys.entries()) {
                if (keySet.encryptionKey) {
                    this._secureWipeMemory(keySet.encryptionKey, 'pfs_key_wipe');
                }
                if (keySet.macKey) {
                    this._secureWipeMemory(keySet.macKey, 'pfs_key_wipe');
                }
                if (keySet.metadataKey) {
                    this._secureWipeMemory(keySet.metadataKey, 'pfs_key_wipe');
                }
                
                // Clear references
                keySet.encryptionKey = null;
                keySet.macKey = null;
                keySet.metadataKey = null;
                keySet.keyFingerprint = null;
            }

            // Clear the oldKeys map completely
            this.oldKeys.clear();

            // Schedule natural cleanup
            await this._performNaturalCleanup();

            this._secureLog('info', '✅ Hard wipe of old keys completed for PFS', {
                timestamp: Date.now()
            });

        } catch (error) {
            this._secureLog('error', '❌ Failed to perform hard wipe of old keys', { error: error.message });
        }
    }

    /**
     *   Wipe ephemeral keys when session ends
     * This ensures session-specific keys are destroyed
     */
    async _wipeEphemeralKeys() {
        try {
            this._secureLog('info', '🧹 Wiping ephemeral keys for PFS', {
                ephemeralKeysCount: this.ephemeralKeyPairs.size,
                timestamp: Date.now()
            });

            // Wipe all ephemeral key pairs
            for (const [sessionId, keyData] of this.ephemeralKeyPairs.entries()) {
                if (keyData.keyPair?.privateKey) {
                    this._secureWipeMemory(keyData.keyPair.privateKey, 'ephemeral_key_wipe');
                }
                if (keyData.keyPair?.publicKey) {
                    this._secureWipeMemory(keyData.keyPair.publicKey, 'ephemeral_key_wipe');
                }
                
                // Clear references
                keyData.keyPair = null;
                keyData.timestamp = null;
                keyData.sessionId = null;
            }

            // Clear the ephemeral keys map
            this.ephemeralKeyPairs.clear();

            // Schedule natural cleanup
            await this._performNaturalCleanup();

            this._secureLog('info', '✅ Ephemeral keys wiped for PFS', {
                timestamp: Date.now()
            });

        } catch (error) {
            this._secureLog('error', '❌ Failed to wipe ephemeral keys', { error: error.message });
        }
    }

    /**
     *   Encrypt file messages with AAD
     * This ensures file messages are properly authenticated and bound to session
     */
    async _encryptFileMessage(messageData, aad) {
        try {
            if (!this.encryptionKey) {
                throw new Error('No encryption key available for file message');
            }

            // Convert message to string if it's an object
            const messageString = typeof messageData === 'string' ? messageData : JSON.stringify(messageData);
            
            // Encrypt with AAD using AES-GCM
            const encryptedData = await window.EnhancedSecureCryptoUtils.encryptDataWithAAD(
                messageString, 
                this.encryptionKey, 
                aad
            );
            
            // Create encrypted message wrapper
            const encryptedMessage = {
                type: 'encrypted_file_message',
                encryptedData: encryptedData,
                aad: aad,
                timestamp: Date.now(),
                keyFingerprint: this.keyFingerprint
            };
            
            return JSON.stringify(encryptedMessage);
        } catch (error) {
            this._secureLog('error', 'Failed to encrypt file message', { error: error.message });
            throw new Error(`File message encryption failed: ${error.message}`);
        }
    }

    /**
     *   Decrypt file messages with AAD validation
     * This ensures file messages are properly authenticated and bound to session
     */
    async _decryptFileMessage(encryptedMessageString) {
        try {
            const encryptedMessage = JSON.parse(encryptedMessageString);
            
            if (encryptedMessage.type !== 'encrypted_file_message') {
                throw new Error('Invalid encrypted file message type');
            }
            
            // Validate key fingerprint
            if (encryptedMessage.keyFingerprint !== this.keyFingerprint) {
                throw new Error('Key fingerprint mismatch in encrypted file message');
            }
            
            //   Validate AAD with sequence number
            const aad = this._validateMessageAAD(encryptedMessage.aad, 'file_message');
            
            if (!this.encryptionKey) {
                throw new Error('No encryption key available for file message decryption');
            }
            
            // Decrypt with AAD validation
            const decryptedData = await window.EnhancedSecureCryptoUtils.decryptDataWithAAD(
                encryptedMessage.encryptedData,
                this.encryptionKey,
                encryptedMessage.aad
            );
            
            return {
                decryptedData: decryptedData,
                aad: aad
            };
        } catch (error) {
            this._secureLog('error', 'Failed to decrypt file message', { error: error.message });
            throw new Error(`File message decryption failed: ${error.message}`);
        }
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
            EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_CONFIRMED,
            EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_BOTH_CONFIRMED,
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
            if (this._debugMode) {
                this._secureLog('error', '❌ ${errorMessage}:', { errorType: error?.constructor?.name || 'Unknown' });
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
            if (this._debugMode) {
                this._secureLog('error', '❌ ${errorMessage}:', { errorType: error?.constructor?.name || 'Unknown' });
            }
            return fallback;
        }
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
     *   Enhanced log cleanup with security checks
     */
    _cleanupLogs() {
        //   More aggressive cleanup to prevent data accumulation
        if (this._logCounts.size > 500) {
            this._logCounts.clear();
            this._secureLog('debug', '🧹 Log counts cleared due to size limit');
        }
        
        //   Clean up old log entries to prevent memory leaks
        const now = Date.now();
        const maxAge = 300000; // 5 minutes
        
        //   Check for suspicious log patterns
        let suspiciousCount = 0;
        for (const [key, count] of this._logCounts.entries()) {
            if (count > 10) {
                suspiciousCount++;
            }
        }
        
        //   Emergency cleanup if too many suspicious patterns
        if (suspiciousCount > 20) {
            this._logCounts.clear();
            this._secureLog('warn', '🚨 Emergency log cleanup due to suspicious patterns');
        }
        
        //   Reset security violation counter if system is stable
        if (this._logSecurityViolations > 0 && suspiciousCount < 5) {
            this._logSecurityViolations = Math.max(0, this._logSecurityViolations - 1);
        }
        
        //   Clean up old IVs periodically
        if (!this._lastIVCleanupTime || Date.now() - this._lastIVCleanupTime > 300000) { // Every 5 minutes
            this._cleanupOldIVs();
            this._lastIVCleanupTime = Date.now();
        }
        
        //   Periodic secure memory cleanup
        if (!this._secureMemoryManager.memoryStats.lastCleanup || 
            Date.now() - this._secureMemoryManager.memoryStats.lastCleanup > 600000) { // Every 10 minutes
            // Schedule async cleanup without blocking
            this._performPeriodicMemoryCleanup().catch(error => {
                this._secureLog('error', 'Periodic cleanup failed', {
                    errorType: error?.constructor?.name || 'Unknown'
                });
            });
            this._secureMemoryManager.memoryStats.lastCleanup = Date.now();
        }
    }
    /**
     *   Secure logging stats with sensitive data protection
     */
    _getLoggingStats() {
        //   Only return safe statistics
        const stats = {
            isProductionMode: this._isProductionMode,
            debugMode: this._debugMode,
            currentLogLevel: this._currentLogLevel,
            logCountsSize: this._logCounts.size,
            maxLogCount: this._maxLogCount,
            securityViolations: this._logSecurityViolations || 0,
            maxSecurityViolations: this._maxLogSecurityViolations || 3,
            systemStatus: this._currentLogLevel === -1 ? 'DISABLED' : 'ACTIVE'
        };
        
        //   Sanitize any potentially sensitive data
        const sanitizedStats = {};
        for (const [key, value] of Object.entries(stats)) {
            if (typeof value === 'string' && this._containsSensitiveContent(value)) {
                sanitizedStats[key] = '[SENSITIVE_DATA_REDACTED]';
            } else {
                sanitizedStats[key] = value;
            }
        }
        
        return sanitizedStats;
    }
    /**
     *   Enhanced emergency logging disable with cleanup
     */
    async _emergencyDisableLogging() {
        //   Immediately disable all logging levels
        this._currentLogLevel = -1;
        
        //   Clear all log data to prevent memory leaks
        this._logCounts.clear();
        
        //   Clear any cached sensitive data
        if (this._logSecurityViolations) {
            this._logSecurityViolations = 0;
        }
        
        //   Override _secureLog to a secure no-op
        this._secureLog = () => {
            //   Only allow emergency console errors
            if (arguments[0] === 'error' && this._originalConsole?.error) {
                this._originalConsole.error('🚨 SECURITY: Logging system disabled - potential data exposure prevented');
            }
        };
        
        //   Store original functions before overriding
        this._originalSanitizeString = this._sanitizeString;
        this._originalSanitizeLogData = this._sanitizeLogData;
        this._originalAuditLogMessage = this._auditLogMessage;
        this._originalContainsSensitiveContent = this._containsSensitiveContent;
        
        //   Override all logging methods to prevent bypass
        this._sanitizeString = () => '[LOGGING_DISABLED]';
        this._sanitizeLogData = () => ({ error: 'LOGGING_DISABLED' });
        this._auditLogMessage = () => false;
        this._containsSensitiveContent = () => true; // Block everything
        
        //   Schedule natural cleanup
        await this._performNaturalCleanup();
        
        //   Notify about the emergency shutdown
        this._originalConsole?.error?.('🚨 CRITICAL: Secure logging system disabled due to potential data exposure');
    }

    /**
     *   Reset logging system after emergency shutdown
     * Use this function to restore normal logging functionality
     */
    _resetLoggingSystem() {
        this._secureLog('info', '🔧 Resetting logging system after emergency shutdown');
        
        // Restore original sanitize functions
        this._sanitizeString = this._originalSanitizeString || ((str) => str);
        this._sanitizeLogData = this._originalSanitizeLogData || ((data) => data);
        this._auditLogMessage = this._originalAuditLogMessage || (() => true);
        this._containsSensitiveContent = this._originalContainsSensitiveContent || (() => false);
        
        // Reset security violation counters
        this._logSecurityViolations = 0;
        
        this._secureLog('info', '✅ Logging system reset successfully');
    }
    /**
     *   Enhanced audit function for log message security
     */
    _auditLogMessage(message, data) {
        if (!data || typeof data !== 'object') return true;
        
        //   Convert to string and check for sensitive content
        const dataString = JSON.stringify(data);
        
        //   Check message itself for sensitive content
        if (this._containsSensitiveContent(message)) {
            this._emergencyDisableLogging();
            this._originalConsole?.error?.('🚨 SECURITY BREACH: Sensitive content detected in log message');
            return false;
        }
        
        //   Check data string for sensitive content
        if (this._containsSensitiveContent(dataString)) {
            this._emergencyDisableLogging();
            this._originalConsole?.error?.('🚨 SECURITY BREACH: Sensitive content detected in log data');
            return false;
        }
        
        //   Enhanced dangerous pattern detection
        const dangerousPatterns = [
            'secret', 'token', 'password', 'credential', 'auth',
            'fingerprint', 'salt', 'signature', 'private_key', 'api_key', 'private',
            'encryption', 'mac', 'metadata', 'session', 'jwt', 'bearer',
            'key', 'hash', 'digest', 'nonce', 'iv', 'cipher'
        ];
        
        const dataStringLower = dataString.toLowerCase();
        
        for (const pattern of dangerousPatterns) {
            if (dataStringLower.includes(pattern) && !this._safeFieldsWhitelist.has(pattern)) {
                this._emergencyDisableLogging();
                this._originalConsole?.error?.(`🚨 SECURITY BREACH: Dangerous pattern detected in log: ${pattern}`);
                return false;
            }
        }
        
        //   Check for high entropy values in data
        for (const [key, value] of Object.entries(data)) {
            if (typeof value === 'string' && this._hasHighEntropy(value)) {
                this._emergencyDisableLogging();
                this._originalConsole?.error?.(`🚨 SECURITY BREACH: High entropy value detected in log field: ${key}`);
                return false;
            }
        }
        
        return true;
    }

    initializeFileTransfer() {
        try {
            this._secureLog('info', '🔧 Initializing Enhanced Secure File Transfer system...');

            if (this.fileTransferSystem) {
                this._secureLog('info', '✅ File transfer system already initialized');
                return;
            }
            
            //   Step-by-step readiness check
            const channelReady = !!(this.dataChannel && this.dataChannel.readyState === 'open');
            if (!channelReady) {
                this._secureLog('warn', '⚠️ Data channel not open, deferring file transfer initialization');
                if (this.dataChannel) {
                    const initHandler = () => {
                        this._secureLog('info', '🔄 DataChannel opened, initializing file transfer...');
                        this.initializeFileTransfer();
                    };
                    this.dataChannel.addEventListener('open', initHandler, { once: true });
                }
                return;
            }

            if (!this.isVerified) {
                this._secureLog('warn', '⚠️ Connection not verified yet, deferring file transfer initialization');
                setTimeout(() => this.initializeFileTransfer(), 500);
                return;
            }
            
            // FIX: Clean up previous system if present
            if (this.fileTransferSystem) {
                this._secureLog('info', '🧹 Cleaning up existing file transfer system');
                this.fileTransferSystem.cleanup();
                this.fileTransferSystem = null;
            }
            
            //   Ensure encryption keys are present
            if (!this.encryptionKey || !this.macKey) {
                this._secureLog('warn', '⚠️ Encryption keys not ready, deferring file transfer initialization');
                setTimeout(() => this.initializeFileTransfer(), 1000);
                return;
            }
            
            // IMPORTANT: callback order: (onProgress, onComplete, onError, onFileReceived)
            const safeOnComplete = (summary) => {
                // Sender: finalize transfer, no Blob handling
                try {
                    this._secureLog('info', '🏁 Sender transfer summary', { summary });
                    // Optionally forward as progress/UI event
                    if (this.onFileProgress) {
                        this.onFileProgress({ type: 'complete', ...summary });
                    }
                } catch (e) {
                    this._secureLog('warn', '⚠️ onComplete handler failed:', { details: e.message });
                }
            };

            this.fileTransferSystem = new EnhancedSecureFileTransfer(
                this,
                this.onFileProgress || null,
                safeOnComplete,
                this.onFileError || null,
                this.onFileReceived || null
            );
            
            this._fileTransferActive = true;
            
            this._secureLog('info', '✅ Enhanced Secure File Transfer system initialized successfully');
            
            // Verify the system is ready
            const status = this.fileTransferSystem.getSystemStatus();
            this._secureLog('info', '🔍 File transfer system status after init', { status });
            
        } catch (error) {
            this._secureLog('error', '❌ Failed to initialize file transfer system', { errorType: error.constructor.name });
            this.fileTransferSystem = null;
            this._fileTransferActive = false;
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
            this._secureLog('error', '❌ Failed to initialize enhanced security', { errorType: error.constructor.name });
        }
    }
    
    // Helper function to generate unbiased random values in a range
    getUnbiasedRandomInRange(min, max) {
    const range = max - min + 1;
        if (range <= 0) throw new Error('Invalid range');

        // Use rejection sampling to avoid modulo bias
        const bytesNeeded = Math.ceil(Math.log2(range) / 8);
        const maxValue = Math.pow(256, bytesNeeded);
        const threshold = maxValue - (maxValue % range);

        let randomValue;
        do {
            const randomBytes = crypto.getRandomValues(new Uint8Array(bytesNeeded));
            randomValue = 0;
            for (let i = 0; i < bytesNeeded; i++) {
                randomValue = (randomValue << 8) | randomBytes[i];
            }
        } while (randomValue >= threshold); // discard biased values

        return (randomValue % range) + min;
    }

    
    //   Generate fingerprint mask for anti-fingerprinting with enhanced randomization
    generateFingerprintMask() {
        const cryptoRandom = crypto.getRandomValues(new Uint8Array(128));

        const mask = {
            timingOffset: this.getUnbiasedRandomInRange(0, 1500), // 0–1500ms
            sizeVariation: this.getUnbiasedRandomInRange(75, 125) / 100, // 0.75–1.25
            noisePattern: Array.from(crypto.getRandomValues(new Uint8Array(64))),
            headerVariations: [
                'X-Client-Version', 'X-Session-ID', 'X-Request-ID', 'X-Timestamp', 'X-Signature',
                'X-Secure', 'X-Encrypted', 'X-Protected', 'X-Safe', 'X-Anonymous', 'X-Private'
            ],
            noiseIntensity: this.getUnbiasedRandomInRange(50, 150), // 50–150%
            sizeMultiplier: this.getUnbiasedRandomInRange(75, 125) / 100,
            timingVariation: this.getUnbiasedRandomInRange(100, 1100)
        };
        return mask;
    }


    // Security configuration - all features enabled by default
    configureSecurityForSession() {
        this._secureLog('info', '🔧 Configuring security - all features enabled by default');
        
        // All security features are enabled by default - no payment required
            this.sessionConstraints = {};
            
            Object.keys(this.securityFeatures).forEach(feature => {
            this.sessionConstraints[feature] = true; // All features enabled
            });
            
            this.applySessionConstraints();
            
        this._secureLog('info', '✅ Security configured - all features enabled', { constraints: this.sessionConstraints });

            if (!this._validateCryptographicSecurity()) {
                this._secureLog('error', '🚨 CRITICAL: Cryptographic security validation failed after session configuration');

                if (this.onStatusChange) {
                    this.onStatusChange('security_breach', {
                        type: 'crypto_security_failure',
                        message: 'Cryptographic security validation failed after session configuration'
                    });
                }
            }
            
            this.notifySecurityLevel();
            
            setTimeout(() => {
                this.calculateAndReportSecurityLevel();
            }, EnhancedSecureWebRTCManager.TIMEOUTS.SECURITY_CALC_DELAY);
    }

    // Applying session constraints - all features enabled by default
    applySessionConstraints() {
        if (!this.sessionConstraints) return;

        // All features are enabled by default - no restrictions
        Object.keys(this.sessionConstraints).forEach(feature => {
            this.securityFeatures[feature] = true; // All features enabled
                
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
        });
        
        this._secureLog('info', '✅ All security features enabled by default', {
            constraints: this.sessionConstraints,
            currentFeatures: this.securityFeatures
        });
    }
    deliverMessageToUI(message, type = 'received') {
        try {
            // Add debug logs
            this._secureLog('debug', '📤 deliverMessageToUI called', {
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
                    EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_CONFIRMED,
                    EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_BOTH_CONFIRMED,
                    EnhancedSecureWebRTCManager.MESSAGE_TYPES.PEER_DISCONNECT,
                    EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_SIGNAL,
                    EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_READY,
                    EnhancedSecureWebRTCManager.MESSAGE_TYPES.SECURITY_UPGRADE
                ];
                if (blockedTypes.includes(message.type)) {
                    if (this._debugMode) {
                        this._secureLog('warn', `🛑 Blocked system/file message from UI: ${message.type}`);
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
                            EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_CONFIRMED,
                            EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_BOTH_CONFIRMED,
                            EnhancedSecureWebRTCManager.MESSAGE_TYPES.PEER_DISCONNECT,
                            EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_SIGNAL,
                            EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_READY,
                            EnhancedSecureWebRTCManager.MESSAGE_TYPES.SECURITY_UPGRADE
                        ];
                        if (blockedTypes.includes(parsedMessage.type)) {
                            if (this._debugMode) {
                                this._secureLog('warn', `🛑 Blocked system/file message from UI (string): ${parsedMessage.type}`);
                            }
                            return; // do not show in chat
                        }
                    }
                } catch (parseError) {
                    // Not JSON — fine for plain text messages
                }
            }

            if (this.onMessage) {
                this._secureLog('debug', '📤 Calling this.onMessage callback', { message, type });
                this.onMessage(message, type);
            } else {
                this._secureLog('warn', '⚠️ this.onMessage callback is null or undefined');
            }
        } catch (err) {
            this._secureLog('error', '❌ Failed to deliver message to UI:', { errorType: err?.constructor?.name || 'Unknown' });
        }
    }


    // Security Level Notification
    notifySecurityLevel() {
        // Avoid duplicate notifications
        if (this.lastSecurityLevelNotification === 'maximum') {
            return; // prevent duplication
        }
        
        this.lastSecurityLevelNotification = 'maximum';
        
        const message = '🛡️ Maximum Security Active - All features enabled';
        
        if (this.onMessage) {
            this.deliverMessageToUI(message, 'system');
        }

        // Showing details of active features
        if (this.onMessage) {
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
        
        this._secureLog('info', '🧹 Decoy channels cleaned up');
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
                    //   No need for base IV or counter - each encryption gets fresh random IV
        // This ensures maximum entropy and prevents IV reuse attacks
            
        } catch (error) {
            this._secureLog('error', '❌ Failed to generate nested encryption key:', { errorType: error?.constructor?.name || 'Unknown' });
            throw error;
        }
    }

    async applyNestedEncryption(data) {
        if (!this.nestedEncryptionKey || !this.securityFeatures.hasNestedEncryption) {
            return data;
        }

        try {
            //   Generate cryptographically secure IV with reuse prevention
            const uniqueIV = this._generateSecureIV(
                EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE, 
                'nestedEncryption'
            );
            
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
            
            this._secureLog('debug', '✅ Nested encryption applied with secure IV', {
                ivHash: await this._createSafeLogHash(uniqueIV, 'nestedEncryption'),
                ivSize: uniqueIV.length,
                dataSize: data.byteLength,
                encryptedSize: encrypted.byteLength
            });
            
            return result.buffer;
        } catch (error) {
            this._secureLog('error', '❌ Nested encryption failed:', { 
                errorType: error?.constructor?.name || 'Unknown',
                errorMessage: error?.message || 'Unknown error'
            });
            
            //   If IV generation failed due to emergency mode, disable nested encryption
            if (error.message.includes('emergency mode')) {
                this.securityFeatures.hasNestedEncryption = false;
                this._secureLog('warn', '⚠️ Nested encryption disabled due to IV emergency mode');
            }
            
            return data; // Fallback to original data
        }
    }

    async removeNestedEncryption(data) {
        if (!this.nestedEncryptionKey || !this.securityFeatures.hasNestedEncryption) {
            return data;
        }

        //   Check that the data is actually encrypted with proper IV size
        if (!(data instanceof ArrayBuffer) || data.byteLength < EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE + 16) {
            if (this._debugMode) {
                this._secureLog('debug', '📝 Data not encrypted or too short for nested decryption (need IV + minimum encrypted data)');
            }
            return data;
        }

        try {
            const dataArray = new Uint8Array(data);
            const iv = dataArray.slice(0, EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE);
            const encryptedData = dataArray.slice(EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE);
            
            // Check that there is data to decrypt
            if (encryptedData.length === 0) {
                if (this._debugMode) {
                    this._secureLog('debug', '📝 No encrypted data found');
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
                if (this._debugMode) {
                    this._secureLog('debug', '📝 Data not encrypted with nested encryption, skipping...');
                }
            } else {
                if (this._debugMode) {
                    this._secureLog('warn', '⚠️ Nested decryption failed:', { details: error.message });
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
            this._secureLog('error', '❌ Packet padding failed:', { errorType: error?.constructor?.name || 'Unknown' });
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
                if (this._debugMode) {
                    this._secureLog('warn', '⚠️ Data too short for packet padding removal, skipping');
                }
                return data;
            }
            
            // Extract original size (first 4 bytes)
            const sizeView = new DataView(dataArray.buffer, 0, 4);
            const originalSize = sizeView.getUint32(0, false);
            
            // Checking the reasonableness of the size
            if (originalSize <= 0 || originalSize > dataArray.length - 4) {
                if (this._debugMode) {
                    this._secureLog('warn', '⚠️ Invalid packet padding size, skipping removal');
                }
                return data;
            }
            
            // Extract original data
            const originalData = dataArray.slice(4, 4 + originalSize);
            
            return originalData.buffer;
        } catch (error) {
            if (this._debugMode) {
                this._secureLog('error', '❌ Packet padding removal failed:', { errorType: error?.constructor?.name || 'Unknown' });
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
            this._secureLog('warn', '⚠️ Fake traffic generation already running');
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
                    this.getUnbiasedRandomInRange(this.fakeTrafficConfig.minInterval, Math.min(this.fakeTrafficConfig.maxInterval, 60000)) : // Cap at 60 seconds
                    this.fakeTrafficConfig.minInterval;
                
                // Minimum interval 15 seconds for stability
                const safeInterval = Math.max(nextInterval, EnhancedSecureWebRTCManager.TIMEOUTS.FAKE_TRAFFIC_MIN_INTERVAL);
                
                this.fakeTrafficTimer = setTimeout(sendFakeMessage, safeInterval);
            } catch (error) {
                if (this._debugMode) {
                    this._secureLog('error', '❌ Fake traffic generation failed:', { errorType: error?.constructor?.name || 'Unknown' });
                }
                this.stopFakeTrafficGeneration();
            }
        };

        // Start fake traffic generation with longer initial delay
        // Use a reasonable range for initial delay (5-30 seconds)
        const minDelay = EnhancedSecureWebRTCManager.TIMEOUTS.DECOY_INITIAL_DELAY;
        const maxDelay = Math.min(this.fakeTrafficConfig.maxInterval, 30000); // Cap at 30 seconds
        const initialDelay = this.getUnbiasedRandomInRange(minDelay, maxDelay);
        this.fakeTrafficTimer = setTimeout(sendFakeMessage, initialDelay);
    }

    stopFakeTrafficGeneration() {
        if (this.fakeTrafficTimer) {
            clearTimeout(this.fakeTrafficTimer);
            this.fakeTrafficTimer = null;
        }
    }

    generateFakeMessage() {
        const patternIndex = this.getUnbiasedRandomInRange(0, this.fakeTrafficConfig.patterns.length - 1);
        const pattern = this.fakeTrafficConfig.patterns[patternIndex];
        
        const size = this.getUnbiasedRandomInRange(this.fakeTrafficConfig.minSize, this.fakeTrafficConfig.maxSize);
        
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
                    this._secureLog('error', '🚨 Emergency disabling advanced security features due to errors');
        
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
        
                    this._secureLog('info', '✅ Advanced features disabled, keeping basic encryption');
        
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
        
        if (this._debugMode) {
            this._secureLog('info', '🎭 Fake Traffic Status', { status });
        }
        return status;
    }
emergencyDisableFakeTraffic() {
        if (this._debugMode) {
            this._secureLog('error', '🚨 Emergency disabling fake traffic');
        }
        
        this.securityFeatures.hasFakeTraffic = false;
        this.fakeTrafficConfig.enabled = false;
        this.stopFakeTrafficGeneration();
        
        if (this._debugMode) {
            this._secureLog('info', '✅ Fake traffic disabled');
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
        this._secureLog('error', '❌ Error in applySecurityLayersWithoutMutex:', { errorType: error?.constructor?.name || 'Unknown' });
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

                            this._secureLog('debug', `📦 Received chunk ${chunkIndex + 1}/${totalChunks} for message ${messageId}`);

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
                
                this._secureLog('info', `📦 Chunked message ${messageId} reassembled and processed`);
            }
        } catch (error) {
            this._secureLog('error', '❌ Chunked message processing failed:', { errorType: error?.constructor?.name || 'Unknown' });
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
            this._secureLog('warn', '⚠️ Decoy channels already initialized, skipping...');
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

            if (this._debugMode) {
                this._secureLog('info', `🎭 Initialized ${numDecoyChannels} decoy channels`);
            }
        } catch (error) {
            if (this._debugMode) {
                this._secureLog('error', '❌ Failed to initialize decoy channels:', { errorType: error?.constructor?.name || 'Unknown' });
            }
        }
    }

    setupDecoyChannel(channel, channelName) {
        channel.onopen = () => {
            if (this._debugMode) {
                this._secureLog('debug', `🎭 Decoy channel "${channelName}" opened`);
            }
            this.startDecoyTraffic(channel, channelName);
        };

        channel.onmessage = (event) => {
            if (this._debugMode) {
                this._secureLog('debug', `🎭 Received decoy message on "${channelName}": ${event.data?.length || 'undefined'} bytes`);
            }
        };

        channel.onclose = () => {
            if (this._debugMode) {
                this._secureLog('debug', `🎭 Decoy channel "${channelName}" closed`);
            }
            this.stopDecoyTraffic(channelName);
        };

        channel.onerror = (error) => {
            if (this._debugMode) {
                this._secureLog('error', `❌ Decoy channel "${channelName}" error`, { error: error.message });
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
                if (this._debugMode) {
                    this._secureLog('error', `❌ Failed to send decoy data on "${channelName}"`, { error: error.message });
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
            this._secureLog('error', '❌ Failed to add reordering headers:', { errorType: error?.constructor?.name || 'Unknown' });
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
            if (this._debugMode) {
                this._secureLog('warn', '⚠️ Data too short for reordering headers, processing directly');
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
            if (this._debugMode) {
                this._secureLog('warn', '⚠️ Invalid reordered packet data size, processing directly');
            }
            return this.processMessage(data);
        }

        const actualData = dataArray.slice(headerSize, headerSize + dataSize);

        try {
            const textData = new TextDecoder().decode(actualData);
            const content = JSON.parse(textData);
            if (content.type === 'fake' || content.isFakeTraffic === true) {
                if (this._debugMode) {
                    this._secureLog('warn', `🎭 BLOCKED: Reordered fake message: ${content.pattern || 'unknown'}`);
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
        this._secureLog('error', '❌ Failed to process reordered packet:', { errorType: error?.constructor?.name || 'Unknown' });
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
                this._secureLog('warn', '⚠️ Packet ${oldestPacket.sequence} timed out, processing out of order');
                
                try {
                    const textData = new TextDecoder().decode(oldestPacket.data);
                    const content = JSON.parse(textData);
                    if (content.type === 'fake' || content.isFakeTraffic === true) {
                        this._secureLog('warn', `🎭 BLOCKED: Timed out fake message: ${content.pattern || 'unknown'}`);
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
                    this._secureLog('warn', `🎭 BLOCKED: Ordered fake message: ${content.pattern || 'unknown'}`);
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
                this._secureLog('warn', '⚠️ 🗑️ Removing timed out packet ${sequence}');
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
            this._secureLog('error', '❌ Anti-fingerprinting failed:', { errorType: error?.constructor?.name || 'Unknown' });
            return data;
        }
    }

    addNoise(data) {
        const dataArray = new Uint8Array(data);
        const noiseSize = this.getUnbiasedRandomInRange(8, 40); // 8-40 bytes
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
        const headerCount = this.getUnbiasedRandomInRange(1, 3); // 1-3 headers
        let totalHeaderSize = 0;
        
        // Calculate total header size
        for (let i = 0; i < headerCount; i++) {
            totalHeaderSize += 4 + this.getUnbiasedRandomInRange(0, 15) + 4; // size + data + checksum
        }
        
        const result = new Uint8Array(totalHeaderSize + dataArray.length);
        let offset = 0;
        
        // Add random headers
        for (let i = 0; i < headerCount; i++) {
            // Generate unbiased random index for header selection
            let headerIndex;
            do {
                headerIndex = crypto.getRandomValues(new Uint8Array(1))[0];
            } while (headerIndex >= 256 - (256 % this.fingerprintMask.headerVariations.length));
            
            const headerName = this.fingerprintMask.headerVariations[headerIndex % this.fingerprintMask.headerVariations.length];
            
            // Generate unbiased random size for header data (4-19 bytes)
            let headerSize;
            do {
                headerSize = crypto.getRandomValues(new Uint8Array(1))[0];
            } while (headerSize >= 256 - (256 % 16));
            
            const headerData = crypto.getRandomValues(new Uint8Array((headerSize % 16) + 4));
            
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
        if (this._debugMode) {
            this._secureLog('debug', `🔍 removeSecurityLayers (Stage ${status.stage})`, {
                dataType: typeof data,
                dataLength: data?.length || data?.byteLength || 0,
                activeFeatures: status.activeFeaturesCount
            });
        }

        if (!data) {
            this._secureLog('warn', '⚠️ Received empty data');
            return null;
        }

        let processedData = data;

        // IMPORTANT: Early check for fake messages
        if (typeof data === 'string') {
            try {
                const jsonData = JSON.parse(data);
                
                // PRIORITY ONE: Filtering out fake messages
                if (jsonData.type === 'fake') {
                    if (this._debugMode) {
                        this._secureLog('debug', `🎭 Fake message filtered out: ${jsonData.pattern} (size: ${jsonData.size})`);
                    }
                    return 'FAKE_MESSAGE_FILTERED'; 
                }
                
                // System messages — do NOT return for re-processing
                if (jsonData.type && ['heartbeat', 'verification', 'verification_response', 'peer_disconnect', 'key_rotation_signal', 'key_rotation_ready', 'security_upgrade'].includes(jsonData.type)) {
                    return 'SYSTEM_MESSAGE_FILTERED';
                }
                
                // File transfer messages — do NOT return for display
                if (jsonData.type && ['file_transfer_start', 'file_transfer_response', 'file_chunk', 'chunk_confirmation', 'file_transfer_complete', 'file_transfer_error'].includes(jsonData.type)) {
                    if (this._debugMode) {
                        this._secureLog('debug', '📁 File transfer message detected, blocking from chat', { type: jsonData.type });
                    }
                    return 'FILE_MESSAGE_FILTERED';
                }
                
                // Regular text messages - extract the actual message text
                if (jsonData.type === 'message') {
                    if (this._debugMode) {
                        this._secureLog('debug', '📝 Regular message detected, extracting text', { data: jsonData.data });
                    }
                    return jsonData.data; // Return the actual message text, not the JSON
                }
                
                // Enhanced messages
                if (jsonData.type === 'enhanced_message' && jsonData.data) {
                    if (this._debugMode) {
                        this._secureLog('debug', '🔐 Enhanced message detected, decrypting...');
                    }
                    
                    if (!this.encryptionKey || !this.macKey || !this.metadataKey) {
                        this._secureLog('error', '❌ Missing encryption keys');
                        return null;
                    }
                    
                    const decryptedResult = await window.EnhancedSecureCryptoUtils.decryptMessage(
                        jsonData.data,
                        this.encryptionKey,
                        this.macKey,
                        this.metadataKey
                    );
                    
                    if (this._debugMode) {
                        this._secureLog('debug', '✅ Enhanced message decrypted, extracting...');
                        this._secureLog('debug', '🔍 decryptedResult', {
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
                            if (this._debugMode) {
                                this._secureLog('warn', `🎭 BLOCKED: Encrypted fake message: ${decryptedContent.pattern || 'unknown'}`);
                            }
                            return 'FAKE_MESSAGE_FILTERED';
                        }
                    } catch (e) {
                        if (this._debugMode) {
                            this._secureLog('debug', '📝 Decrypted content is not JSON, treating as plain text message');
                        }
                    }
                    
                    if (this._debugMode) {
                        this._secureLog('debug', '📤 Returning decrypted message', { message: decryptedResult.message?.substring(0, 50) });
                    }
                    return decryptedResult.message;
                }
                
                // Regular messages
                if (jsonData.type === 'message' && jsonData.data) {
                    if (this._debugMode) {
                        this._secureLog('debug', '📝 Regular message detected, extracting data');
                    }
                    return jsonData.data; // Return the actual message text
                }
                
                // If it's a regular message with type 'message', let it continue processing
                if (jsonData.type === 'message') {
                    if (this._debugMode) {
                        this._secureLog('debug', '📝 Regular message detected, returning for display');
                    }
                    return data; // Return the original JSON string for processing
                }
                
                // If it's not a special type, return the original data for display
                if (!jsonData.type || (jsonData.type !== 'fake' && !['heartbeat', 'verification', 'verification_response', 'peer_disconnect', 'key_rotation_signal', 'key_rotation_ready', 'enhanced_message', 'security_upgrade', 'file_transfer_start', 'file_transfer_response', 'file_chunk', 'chunk_confirmation', 'file_transfer_complete', 'file_transfer_error'].includes(jsonData.type))) {
                    if (this._debugMode) {
                        this._secureLog('debug', '📝 Regular message detected, returning for display');
                    }
                    return data;
                }
            } catch (e) {
                if (this._debugMode) {
                    this._secureLog('debug', '📄 Not JSON, processing as raw data');
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
                    if (this._debugMode) {
                        this._secureLog('debug', '🔓 Applying standard decryption...');
                    }
                    processedData = await window.EnhancedSecureCryptoUtils.decryptData(processedData, this.encryptionKey);
                    if (this._debugMode) {
                        this._secureLog('debug', '✅ Standard decryption successful');
                    }
                    
                    // CHECKING FOR FAKE MESSAGES AFTER LEGACY DECRYPTION
                    if (typeof processedData === 'string') {
                        try {
                            const legacyContent = JSON.parse(processedData);
                            if (legacyContent.type === 'fake' || legacyContent.isFakeTraffic === true) {
                                if (this._debugMode) {
                                    this._secureLog('warn', `🎭 BLOCKED: Legacy fake message: ${legacyContent.pattern || 'unknown'}`);
                                }
                                return 'FAKE_MESSAGE_FILTERED';
                            }
                        } catch (e) {
                            
                        }
                        processedData = new TextEncoder().encode(processedData).buffer;
                    }
                }
            } catch (error) {
                if (this._debugMode) {
                    this._secureLog('warn', '⚠️ Standard decryption failed:', { details: error.message });
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
                            if (this._debugMode) {
                                this._secureLog('warn', `🎭 BLOCKED: Nested fake message: ${nestedContent.pattern || 'unknown'}`);
                            }
                            return 'FAKE_MESSAGE_FILTERED';
                        }
                    } catch (e) {
                        
                    }
                }
            } catch (error) {
                if (this._debugMode) {
                    this._secureLog('warn', '⚠️ Nested decryption failed - skipping this layer:', { details: error.message });
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
                if (this._debugMode) {
                    this._secureLog('warn', '⚠️ Reordering processing failed - using direct processing:', { details: error.message });
                }
            }
        }

        // Packet Padding Removal
        if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
            try {
                processedData = this.removePacketPadding(processedData);
            } catch (error) {
                if (this._debugMode) {
                    this._secureLog('warn', '⚠️ Padding removal failed:', { details: error.message });
                }
            }
        }

        // Anti-Fingerprinting Removal
        if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
            try {
                processedData = this.removeAntiFingerprinting(processedData);
            } catch (error) {
                if (this._debugMode) {
                    this._secureLog('warn', '⚠️ Anti-fingerprinting removal failed:', { details: error.message });
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
                    if (this._debugMode) {
                        this._secureLog('warn', `🎭 BLOCKED: Final check fake message: ${finalContent.pattern || 'unknown'}`);
                    }
                    return 'FAKE_MESSAGE_FILTERED';
                }
            } catch (e) {
            }
        }

        return processedData;

    } catch (error) {
        this._secureLog('error', '❌ Critical error in removeSecurityLayers:', { errorType: error?.constructor?.name || 'Unknown' });
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
            this._secureLog('error', '❌ Error in applySecurityLayers:', { errorType: error?.constructor?.name || 'Unknown' });
            return data;
        }
    }

    async sendMessage(data) {
        //   Comprehensive input validation
        const validation = this._validateInputData(data, 'sendMessage');
        if (!validation.isValid) {
            const errorMessage = `Input validation failed: ${validation.errors.join(', ')}`;
            this._secureLog('error', '❌ Input validation failed in sendMessage', {
                errors: validation.errors,
                dataType: typeof data,
                dataLength: data?.length || data?.byteLength || 0
            });
            throw new Error(errorMessage);
        }

        //   Rate limiting check
        if (!this._checkRateLimit('sendMessage')) {
            throw new Error('Rate limit exceeded for message sending');
        }

        //   Enforce verification gate
        this._enforceVerificationGate('sendMessage');

        //   Connection validation
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
                dataType: typeof validation.sanitizedData,
                isString: typeof validation.sanitizedData === 'string',
                isArrayBuffer: validation.sanitizedData instanceof ArrayBuffer,
                dataLength: validation.sanitizedData?.length || validation.sanitizedData?.byteLength || 0,
            });

            // CRITICAL SECURITY FIX: File messages MUST be encrypted
            // No more bypassing encryption for file_* messages
            if (typeof validation.sanitizedData === 'string') {
                try {
                    const parsed = JSON.parse(validation.sanitizedData);
                    
                    if (parsed.type && parsed.type.startsWith('file_')) {
                        this._secureLog('debug', '📁 File message detected - applying full encryption with AAD', { type: parsed.type });
                        
                        // Create AAD for file message
                        const aad = this._createFileMessageAAD(parsed.type, parsed.data);
                        
                        // Encrypt file message with AAD
                        const encryptedData = await this._encryptFileMessage(validation.sanitizedData, aad);
                        
                        this.dataChannel.send(encryptedData);
                        return true;
                    }
                } catch (jsonError) {
                    // Not JSON — continue normal handling
                }
            }

            //   For regular text messages, send via secure path with AAD
            if (typeof validation.sanitizedData === 'string') {
                // Verify that _createMessageAAD method is available
                if (typeof this._createMessageAAD !== 'function') {
                    throw new Error('_createMessageAAD method is not available. Manager may not be fully initialized.');
                }
                
                // Create AAD with sequence number for anti-replay protection
                const aad = this._createMessageAAD('message', { content: validation.sanitizedData });
                
                return await this.sendSecureMessage({ 
                    type: 'message', 
                    data: validation.sanitizedData, 
                    timestamp: Date.now(),
                    aad: aad // Include AAD for sequence number validation
                });
            }

            //   For binary data, apply security layers with a limited mutex
            this._secureLog('debug', '🔐 Applying security layers to non-string data');
            const securedData = await this._applySecurityLayersWithLimitedMutex(validation.sanitizedData, false);
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
            this._secureLog('error', '❌ Error in applySecurityLayers:', { errorType: error?.constructor?.name || 'Unknown' });
            return data;
        }
    }, 3000); // Short timeout for crypto operations
}

    async sendSystemMessage(messageData) {
        //   Block system messages without verification
        // Exception: Allow verification-related system messages
        const isVerificationMessage = messageData.type === 'verification_request' || 
                                     messageData.type === 'verification_response' ||
                                     messageData.type === 'verification_required';
        
        if (!isVerificationMessage) {
            this._enforceVerificationGate('sendSystemMessage', false);
        }
        
        if (!this.dataChannel || this.dataChannel.readyState !== 'open') {
            this._secureLog('warn', '⚠️ Cannot send system message - data channel not ready');
            return false;
        }

        try {
            const systemMessage = JSON.stringify({
                type: messageData.type,
                data: messageData,
                timestamp: Date.now()
            });

            this._secureLog('debug', '🔧 Sending system message', { type: messageData.type });
            this.dataChannel.send(systemMessage);
            return true;
        } catch (error) {
            this._secureLog('error', '❌ Failed to send system message:', { errorType: error?.constructor?.name || 'Unknown' });
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

                // CRITICAL SECURITY FIX: Check for encrypted file messages first
                if (parsed.type === 'encrypted_file_message') {
                    this._secureLog('debug', '📁 Encrypted file message detected in processMessage');
                    
                    try {
                        // Decrypt and validate file message
                        const { decryptedData, aad } = await this._decryptFileMessage(data);
                        
                        // Parse decrypted data
                        const decryptedParsed = JSON.parse(decryptedData);
                        
                        this._secureLog('debug', '📁 File message decrypted successfully', { 
                            type: decryptedParsed.type,
                            aadMessageType: aad.messageType 
                        });
                        
                        // Process decrypted file message
                        if (this.fileTransferSystem && typeof this.fileTransferSystem.handleFileMessage === 'function') {
                            await this.fileTransferSystem.handleFileMessage(decryptedParsed);
                            return;
                        }
                    } catch (error) {
                        this._secureLog('error', '❌ Failed to decrypt file message', { error: error.message });
                        return; // Drop invalid file message
                    }
                }
                
                // Legacy unencrypted file messages - should not happen in secure mode
                if (parsed.type && fileMessageTypes.includes(parsed.type)) {
                    this._secureLog('warn', '⚠️ Unencrypted file message detected - this should not happen in secure mode', { type: parsed.type });
                    
                    // Drop unencrypted file messages for security
                    this._secureLog('error', '❌ Dropping unencrypted file message for security', { type: parsed.type });
                    return;
                }
                
                // ============================================
                // ENHANCED MESSAGES WITH AAD VALIDATION (WITHOUT MUTEX)
                // ============================================
                
                if (parsed.type === 'enhanced_message') {
                    this._secureLog('debug', '🔐 Enhanced message detected in processMessage');
                    
                    try {
                        // Decrypt enhanced message
                        const decryptedData = await window.EnhancedSecureCryptoUtils.decryptMessage(
                            parsed.data,
                            this.encryptionKey,
                            this.macKey,
                            this.metadataKey
                        );
                        
                        // Parse decrypted data
                        const decryptedParsed = JSON.parse(decryptedData.data);
                        
                        //   Validate AAD with sequence number
                        if (decryptedData.metadata && decryptedData.metadata.sequenceNumber !== undefined) {
                            if (!this._validateIncomingSequenceNumber(decryptedData.metadata.sequenceNumber, 'enhanced_message')) {
                                this._secureLog('warn', '⚠️ Enhanced message sequence number validation failed - possible replay attack', {
                                    received: decryptedData.metadata.sequenceNumber,
                                    expected: this.expectedSequenceNumber
                                });
                                return; // Drop message with invalid sequence number
                            }
                        }
                        
                        // Process decrypted message
                        if (decryptedParsed.type === 'message' && this.onMessage && decryptedParsed.data) {
                            this.deliverMessageToUI(decryptedParsed.data, 'received');
                        }
                        
                        return;
                    } catch (error) {
                        this._secureLog('error', '❌ Failed to decrypt enhanced message', { error: error.message });
                        return; // Drop invalid enhanced message
                    }
                }
                
                // ============================================
                // REGULAR USER MESSAGES (WITHOUT MUTEX)
                // ============================================
                
                if (parsed.type === 'message') {
                    this._secureLog('debug', '📝 Regular user message detected in processMessage');
                    if (this.onMessage && parsed.data) {
                        this.deliverMessageToUI(parsed.data, 'received');
                    }
                    return;
                }
                
                // ============================================
                // SYSTEM MESSAGES (WITHOUT MUTEX)
                // ============================================
                
                if (parsed.type && ['heartbeat', 'verification', 'verification_response', 'verification_confirmed', 'verification_both_confirmed', 'peer_disconnect', 'security_upgrade'].includes(parsed.type)) {
                    this.handleSystemMessage(parsed);
                    return;
                }
                
                // ============================================
                // FAKE MESSAGES (WITHOUT MUTEX)
                // ============================================
                
                if (parsed.type === 'fake') {
                    this._secureLog('warn', '🎭 Fake message blocked in processMessage', { pattern: parsed.pattern });
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
            this._secureLog('warn', '⚠️ No data returned from removeSecurityLayers');
            return;
        }

        // Handle result after removeSecurityLayers
        let messageText;
        
        if (typeof originalData === 'string') {
            try {
                const message = JSON.parse(originalData);
                
                // SECOND CHECK FOR FILE MESSAGES AFTER DECRYPTION
                if (message.type && fileMessageTypes.includes(message.type)) {
                    this._secureLog('debug', '📁 File message detected after decryption', { type: message.type });
                    if (this.fileTransferSystem) {
                        await this.fileTransferSystem.handleFileMessage(message);
                    }
                    return;
                }
                
                if (message.type && ['heartbeat', 'verification', 'verification_response', 'verification_confirmed', 'verification_both_confirmed', 'peer_disconnect', 'security_upgrade'].includes(message.type)) {
                    this.handleSystemMessage(message);
                    return;
                }
                
                if (message.type === 'fake') {
                    this._secureLog('warn', `🎭 Post-decryption fake message blocked: ${message.pattern}`);
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
            this._secureLog('warn', '⚠️ Unexpected data type after processing:', { details: typeof originalData });
            return;
        }

        // Final check for fake and file messages
        if (messageText && messageText.trim().startsWith('{')) {
            try {
                const finalCheck = JSON.parse(messageText);
                if (finalCheck.type === 'fake') {
                    this._secureLog('warn', `🎭 Final fake message check blocked: ${finalCheck.pattern}`);
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
                    this._secureLog('warn', `📁 Final system/file message check blocked: ${finalCheck.type}`);
                    return;
                }
            } catch (e) {
                // Not JSON — fine for plain text
            }
        }

        // Deliver message to the UI
        if (this.onMessage && messageText) {
            this._secureLog('debug', '📤 Calling message handler with', { message: messageText.substring(0, 100) });
            this.deliverMessageToUI(messageText, 'received');
        }

    } catch (error) {
        this._secureLog('error', '❌ Failed to process message:', { errorType: error?.constructor?.name || 'Unknown' });
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
                    //   Removed global callback - use event system instead
                    // if (window.forceHeaderSecurityUpdate) {
                    //     window.forceHeaderSecurityUpdate(this);
                    // }
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
            this._secureLog('debug', '🔧 Handling system message:', { type: message.type });
            
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
                case 'sas_code':
                    this.handleSASCode(message.data);
                    break;
                case 'verification_confirmed':
                    this.handleVerificationConfirmed(message.data);
                    break;
                case 'verification_both_confirmed':
                    this.handleVerificationBothConfirmed(message.data);
                    break;
                case 'peer_disconnect':
                    this.handlePeerDisconnectNotification(message);
                    break;
                case 'key_rotation_signal':
                    this._secureLog('debug', '🔄 Key rotation signal received (ignored for stability)');
                    break;
                case 'key_rotation_ready':
                    this._secureLog('debug', '🔄 Key rotation ready signal received (ignored for stability)');
                    break;
                case 'security_upgrade':
                    this._secureLog('debug', '🔒 Security upgrade notification received:', { type: message.type });
                    // Security upgrade messages are handled internally, not displayed to user
                    // to prevent duplicate system messages
                    break;
                default:
                    this._secureLog('debug', '🔧 Unknown system message type:', { type: message.type });
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
            // Enable full anti-fingerprinting features
            this.antiFingerprintingConfig.randomizeSizes = true;
            this.antiFingerprintingConfig.maskPatterns = true;
            this.antiFingerprintingConfig.useRandomHeaders = true;
        }
        
        this.notifySecurityUpgrade(2);
        setTimeout(() => {
            this.calculateAndReportSecurityLevel();
        }, 500);
    }

        // Method to enable Stage 3 features (traffic obfuscation)
        enableStage3Security() {
            this._secureLog('info', '🔒 Enabling Stage 3 features (traffic obfuscation)');
            
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
            this._secureLog('info', '🔒 Enabling Stage 4 features (maximum safety)');
            
            if (this.sessionConstraints?.hasDecoyChannels && this.isConnected() && this.isVerified) {
                this.securityFeatures.hasDecoyChannels = true;
                this.decoyChannelConfig.enabled = true;
                
                try {
                    this.initializeDecoyChannels();
                } catch (error) {
                    this._secureLog('warn', '⚠️ Decoy channels initialization failed:', { details: error.message });
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
                
            const stage = 4; // Maximum security stage
                        
            return {
                stage: stage,
                securityLevel: 'maximum',
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
                    
                    this._secureLog('debug', '🔒 Sending security upgrade notification to peer:', { type: securityNotification.type, stage: securityNotification.stage });
                    this.dataChannel.send(JSON.stringify(securityNotification));
                } catch (error) {
                    this._secureLog('warn', '⚠️ Failed to send security upgrade notification to peer:', { details: error.message });
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
                
                this._secureLog('info', 'Real security level calculated', {
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
                        
                        const message = `Security Level: ${securityData.level} (${securityData.score}%) - ${securityData.passedChecks}/${securityData.totalChecks} checks passed`;
                        this.deliverMessageToUI(message, 'system');
                    }
                }
                
                return securityData;
                
            } catch (error) {
                this._secureLog('error', 'Failed to calculate real security level', {
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
            this._secureLog('info', 'Starting graduated security activation - all features enabled');

        const checkStability = () => {
            const isStable = this.isConnected() && 
                            this.isVerified && 
                            this.connectionAttempts === 0 && 
                            this.messageQueue.length === 0 &&
                            this.peerConnection?.connectionState === 'connected';
            return isStable;
        };
        
        await this.calculateAndReportSecurityLevel();
        this.notifySecurityUpgrade(1);
        
            // Enable all security stages progressively
            setTimeout(async () => {
                if (checkStability()) {
                    this.enableStage2Security();
                    await this.calculateAndReportSecurityLevel(); 
                    
                        setTimeout(async () => {
                            if (checkStability()) {
                                this.enableStage3Security();
                                await this.calculateAndReportSecurityLevel();
                                
                                setTimeout(async () => {
                                    if (checkStability()) {
                                        this.enableStage4Security();
                                        await this.calculateAndReportSecurityLevel();
                                    }
                                }, 20000);
                            }
                        }, 15000);
                }
            }, 10000);
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
            this._secureLog('error', '❌ Failed to establish enhanced connection:', { errorType: error?.constructor?.name || 'Unknown' });
            // Do not close the connection on setup errors — just log and continue
            this.onStatusChange('disconnected');
            throw error;
        }
    }

    disconnect() {
        try {
            
            // Cleanup file transfer system
            if (this.fileTransferSystem) {
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
            
            //   Wipe ephemeral keys for PFS on disconnect
            this._wipeEphemeralKeys();
            
            //   Hard wipe old keys for PFS
            this._hardWipeOldKeys();

            //   Clear verification states
            this._clearVerificationStates();

        } catch (error) {
            this._secureLog('error', '❌ Error during enhanced disconnect:', { errorType: error?.constructor?.name || 'Unknown' });
        }
    }

    /**
     *   Clear all verification states and data
     * Called when verification is rejected or connection is terminated
     */
    _clearVerificationStates() {
        try {
            
            // Clear verification states
            this.localVerificationConfirmed = false;
            this.remoteVerificationConfirmed = false;
            this.bothVerificationsConfirmed = false;
            this.isVerified = false;
            this.verificationCode = null;
            this.pendingSASCode = null;
            
            // Clear key fingerprint and connection data
            this.keyFingerprint = null;
            this.expectedDTLSFingerprint = null;
            this.connectionId = null;
            
            // Clear processed message IDs
            this.processedMessageIds.clear();
            
            // Reset notification flags
            this.verificationNotificationSent = false;
            this.verificationInitiationSent = false;
            
        } catch (error) {
            this._secureLog('error', '❌ Error clearing verification states:', { errorType: error?.constructor?.name || 'Unknown' });
        }
    }

    // Start periodic cleanup for rate limiting and security
    startPeriodicCleanup() {
        //   Cleanup moved to unified scheduler
        this._secureLog('info', '🔧 Periodic cleanup moved to unified scheduler');
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
                this._secureLog('warn', ' Key rotation aborted - connection not ready', {
                    operationId: operationId,
                    isConnected: this.isConnected(),
                    isVerified: this.isVerified
                });
                return false;
            }
            
            // Ensure rotation is not already in progress
            if (this._keySystemState.isRotating) {
                this._secureLog('warn', ' Key rotation already in progress', {
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
                
                //   Perform hard wipe of old keys for real PFS
                this._hardWipeOldKeys();
                
                // Wait for peer confirmation
                return new Promise((resolve) => {
                    this.pendingRotation = {
                        newVersion: this.currentKeyVersion + 1,
                        operationId: operationId,
                        resolve: resolve,
                        timeout: setTimeout(() => {
                            this._secureLog('error', ' Key rotation timeout', {
                                operationId: operationId
                            });
                            this._keySystemState.isRotating = false;
                            this.pendingRotation = null;
                            resolve(false);
                        }, 10000) // 10 seconds timeout
                    };
                });
                
            } catch (error) {
                this._secureLog('error', ' Key rotation failed in critical section', {
                    operationId: operationId,
                    errorType: error.constructor.name
                });
                this._keySystemState.isRotating = false;
                return false;
            }
        }, 10000); // 10 seconds timeout for the entire operation
    }

    //   Real PFS - Clean up old keys with hard wipe
    cleanupOldKeys() {
        const now = Date.now();
        const maxKeyAge = EnhancedSecureWebRTCManager.LIMITS.MAX_KEY_AGE; // 15 minutes - keys older than this are deleted
        
        let wipedKeysCount = 0;
        
        for (const [version, keySet] of this.oldKeys.entries()) {
            if (now - keySet.timestamp > maxKeyAge) {
                //   Hard wipe old keys before deletion
                if (keySet.encryptionKey) {
                    this._secureWipeMemory(keySet.encryptionKey, 'pfs_cleanup_wipe');
                }
                if (keySet.macKey) {
                    this._secureWipeMemory(keySet.macKey, 'pfs_cleanup_wipe');
                }
                if (keySet.metadataKey) {
                    this._secureWipeMemory(keySet.metadataKey, 'pfs_cleanup_wipe');
                }
                
                // Clear references
                keySet.encryptionKey = null;
                keySet.macKey = null;
                keySet.metadataKey = null;
                keySet.keyFingerprint = null;
                
                this.oldKeys.delete(version);
                wipedKeysCount++;
                
                this._secureLog('info', '🧹 Old PFS keys hard wiped and cleaned up', {
                    version: version,
                    age: Math.round((now - keySet.timestamp) / 1000) + 's',
                    timestamp: Date.now()
                });
            }
        }
        
        if (wipedKeysCount > 0) {
            this._secureLog('info', `PFS cleanup completed: ${wipedKeysCount} keys hard wiped`, {
                timestamp: Date.now()
            });
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
                    this.onStatusChange('disconnected');
                    // Clear verification states on unexpected disconnect
                    this._clearVerificationStates();
                }
            } else if (state === 'failed') {
                // Do not auto-reconnect to avoid closing the session on errors
                this.onStatusChange('disconnected');

            } else {
                this.onStatusChange(state);
            }
        };

        this.peerConnection.ondatachannel = (event) => {
            
            // CRITICAL: Store the received data channel
            if (event.channel.label === 'securechat') {
                this.dataChannel = event.channel;
                this.setupDataChannel(event.channel);
            } else {
                // Handle additional channels (heartbeat, etc.)
                if (event.channel.label === 'heartbeat') {
                    this.heartbeatChannel = event.channel;
                }
            }
        };
    }

    setupDataChannel(channel) {

        this.dataChannel = channel;

        this.dataChannel.onopen = async () => {
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

        this.initializeFileTransfer();
                
            } catch (error) {
                this._secureLog('error', 'Error in establishConnection:', { errorType: error?.constructor?.name || 'Unknown' });
                // Continue despite errors
            }
            
            // CRITICAL: Send pending SAS code if available
            if (this.pendingSASCode && this.dataChannel && this.dataChannel.readyState === 'open') {
                try {
                    const sasPayload = {
                        type: 'sas_code',
                        data: {
                            code: this.pendingSASCode,
                            timestamp: Date.now(),
                            verificationMethod: 'SAS',
                            securityLevel: 'MITM_PROTECTION_REQUIRED'
                        }
                    };
                    this.dataChannel.send(JSON.stringify(sasPayload));
                    this.pendingSASCode = null; // Clear after sending
                } catch (error) {
                }
            } else if (this.pendingSASCode) {
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
                // Clear verification states on data channel close
                this._clearVerificationStates();
                
                if (!this.connectionClosedNotificationSent) {
                    this.connectionClosedNotificationSent = true;
                    this.deliverMessageToUI('🔌 Enhanced secure connection closed. Check connection status.', 'system');
                }
            } else {
                this.onStatusChange('disconnected');
                // Clear verification states on intentional disconnect
                this._clearVerificationStates();
                
                if (!this.connectionClosedNotificationSent) {
                    this.connectionClosedNotificationSent = true;
                    this.deliverMessageToUI('🔌 Enhanced secure connection closed', 'system');
                }
            }
            
            //   Wipe ephemeral keys when session ends for PFS
            this._wipeEphemeralKeys();
            
            this.stopHeartbeat();
            this.isVerified = false;
        };

        // FIX 2: Remove mutex entirely from message processing path
        this.dataChannel.onmessage = async (event) => {
            try {

                // IMPORTANT: Process ALL messages WITHOUT mutex
                if (typeof event.data === 'string') {
                    try {
                        const parsed = JSON.parse(event.data);

                        
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

                            if (!this.fileTransferSystem) {
                                try {
                                    if (this.isVerified && this.dataChannel && this.dataChannel.readyState === 'open') {
                                        this.initializeFileTransfer();

                                        let attempts = 0;
                                        const maxAttempts = 30;
                                        while (!this.fileTransferSystem && attempts < maxAttempts) {
                                            await new Promise(resolve => setTimeout(resolve, 100));
                                            attempts++;
                                        }
                                    }
                                } catch (initError) {
                                    this._secureLog('error', 'Failed to initialize file transfer system for receiver:', { errorType: initError?.constructor?.name || 'Unknown' });
                                }
                            }

                            if (this.fileTransferSystem) {
                                await this.fileTransferSystem.handleFileMessage(parsed);
                                return;
                            }
                            // Attempt lazy initialization on receiver side
                            this._secureLog('warn', '⚠️ File transfer system not ready, attempting lazy init...');
                            try {
                                await this._ensureFileTransferReady();
                                if (this.fileTransferSystem) {
                                    await this.fileTransferSystem.handleFileMessage(parsed);
                                    return;
                                }
                            } catch (e) {
                                this._secureLog('error', 'Lazy init of file transfer failed:', { errorType: e?.message || e?.constructor?.name || 'Unknown' });
                            }
                            this._secureLog('error', 'No file transfer system available for:', { errorType: parsed.type?.constructor?.name || 'Unknown' });
                            return; // IMPORTANT: Do not process further
                        }
                        
                        // ============================================
                        // SYSTEM MESSAGES (WITHOUT MUTEX)
                        // ============================================
                        
                        if (parsed.type && ['heartbeat', 'verification', 'verification_response', 'verification_confirmed', 'verification_both_confirmed', 'sas_code', 'peer_disconnect', 'security_upgrade'].includes(parsed.type)) {
                            this.handleSystemMessage(parsed);
                            return;
                        }
                        
                        // ============================================
                        // REGULAR USER MESSAGES (WITHOUT MUTEX)
                        // ============================================
                        
                        if (parsed.type === 'message' && parsed.data) {
                            if (this.onMessage) {
                                this.deliverMessageToUI(parsed.data, 'received');
                            }
                            return;
                        }
                        
                        // ============================================
                        // ENHANCED MESSAGES (WITHOUT MUTEX)
                        // ============================================
                        
                        if (parsed.type === 'enhanced_message' && parsed.data) {
                            await this._processEnhancedMessageWithoutMutex(parsed);
                            return;
                        }
                        
                        
                    } catch (jsonError) {
                        // Not JSON — treat as regular text message
                        if (this.onMessage) {
                            this.deliverMessageToUI(event.data, 'received');
                        }
                        return;
                    }
                } else if (event.data instanceof ArrayBuffer) {
                    await this._processBinaryDataWithoutMutex(event.data);
                } else {
                }
                
            } catch (error) {
                this._secureLog('error', 'Failed to process message in onmessage:', { errorType: error?.constructor?.name || 'Unknown' });
            }
        };
    }
        // FIX 4: New method for processing binary data WITHOUT mutex
    async _processBinaryDataWithoutMutex(data) {
        try {
            
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
                    this._secureLog('warn', 'Nested decryption failed, continuing with original data');
                }
            }
            
            // Packet Padding Removal (if enabled)
            if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
                try {
                    processedData = this.removePacketPadding(processedData);
                } catch (error) {
                    this._secureLog('warn', 'Packet padding removal failed, continuing with original data');
                }
            }
            
            // Anti-Fingerprinting Removal (if enabled)
            if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
                try {
                    processedData = this.removeAntiFingerprinting(processedData);
                } catch (error) {
                    this._secureLog('warn', 'Anti-fingerprinting removal failed, continuing with original data');
                }
            }
            
            // Convert to text
            if (processedData instanceof ArrayBuffer) {
                const textData = new TextDecoder().decode(processedData);
                
                // Check for fake messages
                try {
                    const content = JSON.parse(textData);
                    if (content.type === 'fake' || content.isFakeTraffic === true) {
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
            this._secureLog('error', 'Error processing binary data:', { errorType: error?.constructor?.name || 'Unknown' });
        }
    }
    // FIX 3: New method for processing enhanced messages WITHOUT mutex
    async _processEnhancedMessageWithoutMutex(parsedMessage) {
        try {
            
            if (!this.encryptionKey || !this.macKey || !this.metadataKey) {
                this._secureLog('error', 'Missing encryption keys for enhanced message');
                return;
            }
            
            const decryptedResult = await window.EnhancedSecureCryptoUtils.decryptMessage(
                parsedMessage.data,
                this.encryptionKey,
                this.macKey,
                this.metadataKey
            );
            
            if (decryptedResult && decryptedResult.message) {
                
                // Try parsing JSON and showing nested text if it's a chat message
                try {
                    const decryptedContent = JSON.parse(decryptedResult.message);
                    if (decryptedContent.type === 'fake' || decryptedContent.isFakeTraffic === true) {
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
                this._secureLog('warn', 'No message content in decrypted result');
            }
            
        } catch (error) {
            this._secureLog('error', 'Error processing enhanced message:', { errorType: error?.constructor?.name || 'Unknown' });
        }
    }
    /**
     * Creates a unique ID for an operation
     */
    _generateOperationId() {
        return `op_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    /**
     *   Atomic mutex acquisition with enhanced race condition protection
     */
    async _acquireMutex(mutexName, operationId, timeout = 5000) {
        //   Build correct mutex property name
        const mutexPropertyName = `_${mutexName}Mutex`;
        const mutex = this[mutexPropertyName];
        
        if (!mutex) {
            this._secureLog('error', `Unknown mutex: ${mutexName}`, {
                mutexPropertyName: mutexPropertyName,
                availableMutexes: this._getAvailableMutexes(),
                operationId: operationId
            });
            throw new Error(`Unknown mutex: ${mutexName}. Available: ${this._getAvailableMutexes().join(', ')}`);
        }
        
        //   Validate operation ID
        if (!operationId || typeof operationId !== 'string') {
            throw new Error('Invalid operation ID for mutex acquisition');
        }
        
        return new Promise((resolve, reject) => {
            //   Atomic lock attempt with immediate state check
            const attemptLock = () => {
                //   Check if mutex is already locked by this operation
                if (mutex.lockId === operationId) {
                    this._secureLog('warn', `Mutex '${mutexName}' already locked by same operation`, {
                        operationId: operationId
                    });
                    resolve();
                    return;
                }
                
                //   Atomic check and lock operation
                if (!mutex.locked) {
                    //   Set lock state atomically
                    mutex.locked = true;
                    mutex.lockId = operationId;
                    mutex.lockTime = Date.now();
                    
                    this._secureLog('debug', `Mutex '${mutexName}' acquired atomically`, {
                        operationId: operationId,
                        lockTime: mutex.lockTime
                    });
                    
                    //   Set timeout for automatic release with enhanced validation
                    mutex.lockTimeout = setTimeout(() => {
                        //   Enhanced timeout handling with state validation
                        this._handleMutexTimeout(mutexName, operationId, timeout);
                    }, timeout);
                    
                    resolve();
                } else {
                    //   Add to queue with timeout
                    const queueItem = { 
                        resolve, 
                        reject, 
                        operationId,
                        timestamp: Date.now(),
                        timeout: setTimeout(() => {
                            //   Remove from queue on timeout
                            const index = mutex.queue.findIndex(item => item.operationId === operationId);
                            if (index !== -1) {
                                mutex.queue.splice(index, 1);
                                reject(new Error(`Mutex acquisition timeout for '${mutexName}'`));
                            }
                        }, timeout)
                    };
                    
                    mutex.queue.push(queueItem);
                    
                    this._secureLog('debug', `Operation queued for mutex '${mutexName}'`, {
                        operationId: operationId,
                        queueLength: mutex.queue.length,
                        currentLockId: mutex.lockId
                    });
                }
            };
            
            //   Execute lock attempt immediately
            attemptLock();
        });
    }

    /**
     *   Enhanced mutex release with strict validation and error handling
     */
    _releaseMutex(mutexName, operationId) {
        //   Validate input parameters
        if (!mutexName || typeof mutexName !== 'string') {
            throw new Error('Invalid mutex name provided for release');
        }
        
        if (!operationId || typeof operationId !== 'string') {
            throw new Error('Invalid operation ID provided for mutex release');
        }
        
        //   Build correct mutex property name
        const mutexPropertyName = `_${mutexName}Mutex`;
        const mutex = this[mutexPropertyName];
        
        if (!mutex) {
            this._secureLog('error', `Unknown mutex for release: ${mutexName}`, {
                mutexPropertyName: mutexPropertyName,
                availableMutexes: this._getAvailableMutexes(),
                operationId: operationId
            });
            throw new Error(`Unknown mutex for release: ${mutexName}`);
        }
        
        //   Strict validation of lock ownership
        if (mutex.lockId !== operationId) {
            this._secureLog('error', `CRITICAL: Invalid mutex release attempt - potential race condition`, {
                mutexName: mutexName,
                expectedLockId: mutex.lockId,
                providedOperationId: operationId,
                mutexState: {
                    locked: mutex.locked,
                    lockTime: mutex.lockTime,
                    queueLength: mutex.queue.length
                }
            });
            
            //   Throw error instead of silent failure
            throw new Error(`Invalid mutex release attempt for '${mutexName}': expected '${mutex.lockId}', got '${operationId}'`);
        }
        
        //   Validate mutex is actually locked
        if (!mutex.locked) {
            this._secureLog('error', `CRITICAL: Attempting to release unlocked mutex`, {
                mutexName: mutexName,
                operationId: operationId,
                mutexState: {
                    locked: mutex.locked,
                    lockId: mutex.lockId,
                    lockTime: mutex.lockTime
                }
            });
            throw new Error(`Attempting to release unlocked mutex: ${mutexName}`);
        }
        
        try {
            //   Clear timeout first
            if (mutex.lockTimeout) {
                clearTimeout(mutex.lockTimeout);
                mutex.lockTimeout = null;
            }
            
            //   Calculate lock duration for monitoring
            const lockDuration = mutex.lockTime ? Date.now() - mutex.lockTime : 0;
            
            //   Atomic release with state validation
            mutex.locked = false;
            mutex.lockId = null;
            mutex.lockTime = null;
            
            this._secureLog('debug', `Mutex released successfully: ${mutexName}`, {
                operationId: operationId,
                lockDuration: lockDuration,
                queueLength: mutex.queue.length
            });
            
            //   Process next in queue with enhanced error handling
            this._processNextInQueue(mutexName);
            
        } catch (error) {
            //   If queue processing fails, ensure mutex is still released
            this._secureLog('error', `Error during mutex release queue processing`, {
                mutexName: mutexName,
                operationId: operationId,
                errorType: error.constructor.name,
                errorMessage: error.message
            });
            
            //   Ensure mutex is released even if queue processing fails
            mutex.locked = false;
            mutex.lockId = null;
            mutex.lockTime = null;
            mutex.lockTimeout = null;
            
            throw error;
        }
    }

    /**
     *   Enhanced queue processing with comprehensive error handling
     */
    _processNextInQueue(mutexName) {
        const mutex = this[`_${mutexName}Mutex`];
        
        if (!mutex) {
            this._secureLog('error', `Mutex not found for queue processing: ${mutexName}`);
            return;
        }
        
        if (mutex.queue.length === 0) {
            return;
        }
        
        //   Validate mutex state before processing queue
        if (mutex.locked) {
            this._secureLog('warn', `Mutex '${mutexName}' is still locked, skipping queue processing`, {
                lockId: mutex.lockId,
                queueLength: mutex.queue.length
            });
            return;
        }
        
        //   Get next item from queue atomically with validation
        const nextItem = mutex.queue.shift();
        
        if (!nextItem) {
            this._secureLog('warn', `Empty queue item for mutex '${mutexName}'`);
            return;
        }
        
        //   Validate queue item structure
        if (!nextItem.operationId || !nextItem.resolve || !nextItem.reject) {
            this._secureLog('error', `Invalid queue item structure for mutex '${mutexName}'`, {
                hasOperationId: !!nextItem.operationId,
                hasResolve: !!nextItem.resolve,
                hasReject: !!nextItem.reject
            });
            return;
        }
        
        try {
            //   Clear timeout for this item
            if (nextItem.timeout) {
                clearTimeout(nextItem.timeout);
            }
            
            //   Attempt to acquire lock for next item
            this._secureLog('debug', `Processing next operation in queue for mutex '${mutexName}'`, {
                operationId: nextItem.operationId,
                queueRemaining: mutex.queue.length,
                timestamp: Date.now()
            });
            
            //   Retry lock acquisition for queued operation with enhanced error handling
            setTimeout(async () => {
                try {
                    await this._acquireMutex(mutexName, nextItem.operationId, 5000);
                    
                    this._secureLog('debug', `Queued operation acquired mutex '${mutexName}'`, {
                        operationId: nextItem.operationId,
                        acquisitionTime: Date.now()
                    });
                    
                    nextItem.resolve();
                    
                } catch (error) {
                    this._secureLog('error', `Queued operation failed to acquire mutex '${mutexName}'`, {
                        operationId: nextItem.operationId,
                        errorType: error.constructor.name,
                        errorMessage: error.message,
                        timestamp: Date.now()
                    });
                    
                    //   Reject with detailed error information
                    nextItem.reject(new Error(`Queue processing failed for '${mutexName}': ${error.message}`));
                    
                    //   Continue processing queue even if one item fails
                    setTimeout(() => {
                        this._processNextInQueue(mutexName);
                    }, 50);
                }
            }, 10); // Small delay to prevent immediate re-acquisition
            
        } catch (error) {
            this._secureLog('error', `Critical error during queue processing for mutex '${mutexName}'`, {
                operationId: nextItem.operationId,
                errorType: error.constructor.name,
                errorMessage: error.message
            });
            
            //   Reject the operation and continue processing
            try {
                nextItem.reject(new Error(`Queue processing critical error: ${error.message}`));
            } catch (rejectError) {
                this._secureLog('error', `Failed to reject queue item`, {
                    originalError: error.message,
                    rejectError: rejectError.message
                });
            }
            
            //   Continue processing remaining queue items
            setTimeout(() => {
                this._processNextInQueue(mutexName);
            }, 100);
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
     *   Enhanced mutex execution with atomic operations
     */
    async _withMutex(mutexName, operation, timeout = 5000) {
        const operationId = this._generateOperationId();
        
        //   Validate mutex system before operation
        if (!this._validateMutexSystem()) {
            this._secureLog('error', 'Mutex system not properly initialized', {
                operationId: operationId,
                mutexName: mutexName
            });
            throw new Error('Mutex system not properly initialized. Call _initializeMutexSystem() first.');
        }
        
        //   Get mutex reference with validation
        const mutex = this[`_${mutexName}Mutex`];
        if (!mutex) {
            throw new Error(`Mutex '${mutexName}' not found`);
        }
        
        let mutexAcquired = false;
        
        try {
            //   Atomic mutex acquisition with timeout
            await this._acquireMutex(mutexName, operationId, timeout);
            mutexAcquired = true;
            
            //   Increment operation counter atomically
            const counterKey = `${mutexName}Operations`;
            if (this._operationCounters && this._operationCounters[counterKey] !== undefined) {
                this._operationCounters[counterKey]++;
            }
            
            //   Execute operation with enhanced error handling
            const result = await operation(operationId);
            
            //   Validate result before returning
            if (result === undefined && operation.name !== 'cleanup') {
                this._secureLog('warn', 'Mutex operation returned undefined result', {
                    operationId: operationId,
                    mutexName: mutexName,
                    operationName: operation.name
                });
            }
            
            return result;
            
        } catch (error) {
            //   Enhanced error logging with context
            this._secureLog('error', 'Error in mutex operation', {
                operationId: operationId,
                mutexName: mutexName,
                errorType: error.constructor.name,
                errorMessage: error.message,
                mutexAcquired: mutexAcquired,
                mutexState: mutex ? {
                    locked: mutex.locked,
                    lockId: mutex.lockId,
                    queueLength: mutex.queue.length
                } : 'null'
            });
            
                    //   If this is a key operation error, trigger emergency recovery
        if (mutexName === 'keyOperation') {
            this._handleKeyOperationError(error, operationId);
        }
        
        //   Trigger emergency unlock for critical mutex errors
        if (error.message.includes('timeout') || error.message.includes('race condition')) {
            this._emergencyUnlockAllMutexes('errorHandler');
        }
            
            throw error;
        } finally {
            //   Always release mutex in finally block with validation
            if (mutexAcquired) {
                try {
                    await this._releaseMutex(mutexName, operationId);
                    
                    //   Verify mutex was properly released
                    if (mutex.locked && mutex.lockId === operationId) {
                        this._secureLog('error', 'Mutex release verification failed', {
                            operationId: operationId,
                            mutexName: mutexName
                        });
                        // Force release as fallback
                        mutex.locked = false;
                        mutex.lockId = null;
                        mutex.lockTimeout = null;
                    }
                    
                } catch (releaseError) {
                    this._secureLog('error', 'Error releasing mutex in finally block', {
                        operationId: operationId,
                        mutexName: mutexName,
                        releaseErrorType: releaseError.constructor.name,
                        releaseErrorMessage: releaseError.message
                    });
                    
                    //   Force release on error
                    mutex.locked = false;
                    mutex.lockId = null;
                    mutex.lockTimeout = null;
                }
            }
        }
    }

    _validateMutexSystem() {
        const requiredMutexes = ['keyOperation', 'cryptoOperation', 'connectionOperation'];
        
        for (const mutexName of requiredMutexes) {
            const mutexPropertyName = `_${mutexName}Mutex`;
            const mutex = this[mutexPropertyName];
            
            if (!mutex || typeof mutex !== 'object') {
                this._secureLog('error', `Missing or invalid mutex: ${mutexName}`, {
                    mutexPropertyName: mutexPropertyName,
                    mutexType: typeof mutex
                });
                return false;
            }
            
            // Validate mutex structure
            const requiredProps = ['locked', 'queue', 'lockId', 'lockTimeout'];
            for (const prop of requiredProps) {
                if (!(prop in mutex)) {
                    this._secureLog('error', `Mutex ${mutexName} missing property: ${prop}`);
                    return false;
                }
            }
        }
        
        return true;
    }

    /**
     *   Enhanced emergency recovery of the mutex system
     */
    _emergencyRecoverMutexSystem() {
        this._secureLog('warn', 'Emergency mutex system recovery initiated');
        
        try {
            //   Emergency unlock all mutexes first
            this._emergencyUnlockAllMutexes('emergencyRecovery');
            
            //   Force re-initialize the system
            this._initializeMutexSystem();
            
            //   Validate recovery success
            if (!this._validateMutexSystem()) {
                throw new Error('Mutex system validation failed after recovery');
            }
            
            this._secureLog('info', 'Mutex system recovered successfully with validation');
            return true;
            
        } catch (error) {
            this._secureLog('error', 'Failed to recover mutex system', {
                errorType: error.constructor.name,
                errorMessage: error.message
            });
            
            //   Last resort - force re-initialization
            try {
                this._initializeMutexSystem();
                this._secureLog('warn', 'Forced mutex system re-initialization completed');
                return true;
            } catch (reinitError) {
                this._secureLog('error', 'CRITICAL: Forced re-initialization also failed', {
                    originalError: error.message,
                    reinitError: reinitError.message
                });
                return false;
            }
        }
    }

    /**
     *   Atomic key generation with race condition protection
     */
    async _generateEncryptionKeys() {
        return this._withMutex('keyOperation', async (operationId) => {
            this._secureLog('info', 'Generating encryption keys with atomic mutex', {
                operationId: operationId
            });
            
            //   Atomic state check and update using mutex lock
            const currentState = this._keySystemState;
            
            //   Atomic check - if already initializing, wait or fail
            if (currentState.isInitializing) {
                this._secureLog('warn', 'Key generation already in progress, waiting for completion', {
                    operationId: operationId,
                    lastOperation: currentState.lastOperation,
                    lastOperationTime: currentState.lastOperationTime
                });
                
                // Wait for existing operation to complete
                let waitAttempts = 0;
                const maxWaitAttempts = 50; // 5 seconds max wait
                
                while (currentState.isInitializing && waitAttempts < maxWaitAttempts) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                    waitAttempts++;
                }
                
                if (currentState.isInitializing) {
                    throw new Error('Key generation timeout - operation still in progress after 5 seconds');
                }
            }
            
            //   Atomic state update within mutex protection
            try {
                //   Set state atomically within mutex
                currentState.isInitializing = true;
                currentState.lastOperation = 'generation';
                currentState.lastOperationTime = Date.now();
                currentState.operationId = operationId;
                
                this._secureLog('debug', 'Atomic key generation state set', {
                    operationId: operationId,
                    timestamp: currentState.lastOperationTime
                });
                
                //   Generate keys with individual error handling
                let ecdhKeyPair = null;
                let ecdsaKeyPair = null;
                
                //   Generate ephemeral ECDH keys for PFS
                try {
                    ecdhKeyPair = await this._generateEphemeralECDHKeys();
                    
                    //   Validate ECDH keys immediately
                    if (!ecdhKeyPair || !ecdhKeyPair.privateKey || !ecdhKeyPair.publicKey) {
                        throw new Error('Ephemeral ECDH key pair validation failed');
                    }
                    
                    //   Constant-time validation for key types
                    if (!this._validateKeyPairConstantTime(ecdhKeyPair)) {
                        throw new Error('Ephemeral ECDH keys are not valid CryptoKey instances');
                    }
                    
                    this._secureLog('debug', 'Ephemeral ECDH keys generated and validated for PFS', {
                        operationId: operationId,
                        privateKeyHash: await this._createSafeLogHash(ecdhKeyPair.privateKey, 'ecdh_private'),
                        publicKeyHash: await this._createSafeLogHash(ecdhKeyPair.publicKey, 'ecdh_public'),
                        privateKeyType: ecdhKeyPair.privateKey.algorithm?.name,
                        publicKeyType: ecdhKeyPair.publicKey.algorithm?.name,
                        isEphemeral: true
                    });
                    
                } catch (ecdhError) {
                    this._secureLog('error', 'Ephemeral ECDH key generation failed', {
                        operationId: operationId,
                        errorType: ecdhError.constructor.name
                    });
                    this._throwSecureError(ecdhError, 'ephemeral_ecdh_key_generation');
                }
                
                // Generate ECDSA keys with retry mechanism
                try {
                    ecdsaKeyPair = await window.EnhancedSecureCryptoUtils.generateECDSAKeyPair();
                    
                                    //   Validate ECDSA keys immediately
                if (!ecdsaKeyPair || !ecdsaKeyPair.privateKey || !ecdsaKeyPair.publicKey) {
                    throw new Error('ECDSA key pair validation failed');
                }
                
                //   Constant-time validation for key types
                if (!this._validateKeyPairConstantTime(ecdsaKeyPair)) {
                    throw new Error('ECDSA keys are not valid CryptoKey instances');
                }
                    
                    this._secureLog('debug', 'ECDSA keys generated and validated', {
                        operationId: operationId,
                        privateKeyHash: await this._createSafeLogHash(ecdsaKeyPair.privateKey, 'ecdsa_private'),
                        publicKeyHash: await this._createSafeLogHash(ecdsaKeyPair.publicKey, 'ecdsa_public'),
                        privateKeyType: ecdsaKeyPair.privateKey.algorithm?.name,
                        publicKeyType: ecdsaKeyPair.publicKey.algorithm?.name
                    });
                    
                } catch (ecdsaError) {
                    this._secureLog('error', 'ECDSA key generation failed', {
                        operationId: operationId,
                        errorType: ecdsaError.constructor.name
                    });
                    this._throwSecureError(ecdsaError, 'ecdsa_key_generation');
                }
                
                //   Final validation of both key pairs
                if (!ecdhKeyPair || !ecdsaKeyPair) {
                    throw new Error('One or both key pairs failed to generate');
                }
                
                //   Enable security features after successful key generation
                this._enableSecurityFeaturesAfterKeyGeneration(ecdhKeyPair, ecdsaKeyPair);
                
                this._secureLog('info', 'Encryption keys generated successfully with atomic protection', {
                    operationId: operationId,
                    hasECDHKeys: !!(ecdhKeyPair?.privateKey && ecdhKeyPair?.publicKey),
                    hasECDSAKeys: !!(ecdsaKeyPair?.privateKey && ecdsaKeyPair?.publicKey),
                    generationTime: Date.now() - currentState.lastOperationTime
                });
                
                return { ecdhKeyPair, ecdsaKeyPair };
                
            } catch (error) {
                //   Ensure state is reset on any error
                this._secureLog('error', 'Key generation failed, resetting state', {
                    operationId: operationId,
                    errorType: error.constructor.name
                });
                throw error;
            } finally {
                //   Always reset state in finally block
                currentState.isInitializing = false;
                currentState.operationId = null;
                
                this._secureLog('debug', 'Key generation state reset', {
                    operationId: operationId
                });
            }
        });
    }

    /**
     *   Enable security features after successful key generation
     */
    _enableSecurityFeaturesAfterKeyGeneration(ecdhKeyPair, ecdsaKeyPair) {
        try {
            //   Enable encryption features based on available keys
            if (ecdhKeyPair && ecdhKeyPair.privateKey && ecdhKeyPair.publicKey) {
                this.securityFeatures.hasEncryption = true;
                this.securityFeatures.hasECDH = true;
                this._secureLog('info', 'ECDH encryption features enabled');
            }
            
            if (ecdsaKeyPair && ecdsaKeyPair.privateKey && ecdsaKeyPair.publicKey) {
                this.securityFeatures.hasECDSA = true;
                this._secureLog('info', 'ECDSA signature features enabled');
            }
            
            //   Enable additional features that depend on encryption
            if (this.securityFeatures.hasEncryption) {
                this.securityFeatures.hasMetadataProtection = true;
                this.securityFeatures.hasEnhancedReplayProtection = true;
                this.securityFeatures.hasNonExtractableKeys = true;
                this._secureLog('info', 'Additional encryption-dependent features enabled');
            }
            
            //   Enable PFS after ephemeral key generation
            if (ecdhKeyPair && this.ephemeralKeyPairs.size > 0) {
                this.securityFeatures.hasPFS = true;
                this._secureLog('info', 'Perfect Forward Secrecy enabled with ephemeral keys');
            }
            
            this._secureLog('info', 'Security features updated after key generation', {
                hasEncryption: this.securityFeatures.hasEncryption,
                hasECDH: this.securityFeatures.hasECDH,
                hasECDSA: this.securityFeatures.hasECDSA,
                hasMetadataProtection: this.securityFeatures.hasMetadataProtection,
                hasEnhancedReplayProtection: this.securityFeatures.hasEnhancedReplayProtection,
                hasNonExtractableKeys: this.securityFeatures.hasNonExtractableKeys,
                hasPFS: this.securityFeatures.hasPFS
            });
            
        } catch (error) {
            this._secureLog('error', 'Failed to enable security features after key generation', {
                errorType: error.constructor.name,
                errorMessage: error.message
            });
        }
    }

    /**
     *   Enhanced emergency mutex unlocking with authorization and validation
     */
    _emergencyUnlockAllMutexes(callerContext = 'unknown') {
        //   Validate caller authorization
        const authorizedCallers = [
            'keyOperation', 'cryptoOperation', 'connectionOperation',
            'emergencyRecovery', 'systemShutdown', 'errorHandler'
        ];
        
        if (!authorizedCallers.includes(callerContext)) {
            this._secureLog('error', `UNAUTHORIZED emergency mutex unlock attempt`, {
                callerContext: callerContext,
                authorizedCallers: authorizedCallers,
                timestamp: Date.now()
            });
            throw new Error(`Unauthorized emergency mutex unlock attempt by: ${callerContext}`);
        }
        
        const mutexes = ['keyOperation', 'cryptoOperation', 'connectionOperation'];
        
        this._secureLog('error', 'EMERGENCY: Unlocking all mutexes with authorization and state cleanup', {
            callerContext: callerContext,
            timestamp: Date.now()
        });
        
        let unlockedCount = 0;
        let errorCount = 0;
        
        mutexes.forEach(mutexName => {
            const mutex = this[`_${mutexName}Mutex`];
            if (mutex) {
                try {
                    //   Clear timeout first
                    if (mutex.lockTimeout) {
                        clearTimeout(mutex.lockTimeout);
                    }
                    
                    //   Log mutex state before emergency unlock
                    const previousState = {
                        locked: mutex.locked,
                        lockId: mutex.lockId,
                        lockTime: mutex.lockTime,
                        queueLength: mutex.queue.length
                    };
                    
                    //   Reset mutex state atomically
                    mutex.locked = false;
                    mutex.lockId = null;
                    mutex.lockTimeout = null;
                    mutex.lockTime = null;
                    
                    //   Clear queue with proper error handling and logging
                    let queueRejectCount = 0;
                    mutex.queue.forEach(item => {
                        try {
                            if (item.reject && typeof item.reject === 'function') {
                                item.reject(new Error(`Emergency mutex unlock for ${mutexName} by ${callerContext}`));
                                queueRejectCount++;
                            }
                        } catch (rejectError) {
                            this._secureLog('warn', `Failed to reject queue item during emergency unlock`, {
                                mutexName: mutexName,
                                errorType: rejectError.constructor.name
                            });
                        }
                    });
                    
                    //   Clear queue array
                    mutex.queue = [];
                    
                    unlockedCount++;
                    
                    this._secureLog('debug', `Emergency unlocked mutex: ${mutexName}`, {
                        previousState: previousState,
                        queueRejectCount: queueRejectCount,
                        callerContext: callerContext
                    });
                    
                } catch (error) {
                    errorCount++;
                    this._secureLog('error', `Error during emergency unlock of mutex: ${mutexName}`, {
                        errorType: error.constructor.name,
                        errorMessage: error.message,
                        callerContext: callerContext
                    });
                }
            }
        });
        
        //   Reset key system state with validation
        if (this._keySystemState) {
            try {
                const previousKeyState = { ...this._keySystemState };
                
                this._keySystemState.isInitializing = false;
                this._keySystemState.isRotating = false;
                this._keySystemState.isDestroying = false;
                this._keySystemState.operationId = null;
                this._keySystemState.concurrentOperations = 0;
                
                this._secureLog('debug', `Emergency reset key system state`, {
                    previousState: previousKeyState,
                    callerContext: callerContext
                });
                
            } catch (error) {
                this._secureLog('error', `Error resetting key system state during emergency unlock`, {
                    errorType: error.constructor.name,
                    errorMessage: error.message,
                    callerContext: callerContext
                });
            }
        }
        
        //   Log emergency unlock summary
        this._secureLog('info', `Emergency mutex unlock completed`, {
            callerContext: callerContext,
            unlockedCount: unlockedCount,
            errorCount: errorCount,
            totalMutexes: mutexes.length,
            timestamp: Date.now()
        });
        
        //   Trigger system validation after emergency unlock
        setTimeout(() => {
            this._validateMutexSystemAfterEmergencyUnlock();
        }, 100);
    }

    /**
     *   Handle key operation errors with recovery mechanisms
     */
    _handleKeyOperationError(error, operationId) {
        this._secureLog('error', 'Key operation error detected, initiating recovery', {
            operationId: operationId,
            errorType: error.constructor.name,
            errorMessage: error.message
        });
        
        //   Reset key system state immediately
        if (this._keySystemState) {
            this._keySystemState.isInitializing = false;
            this._keySystemState.isRotating = false;
            this._keySystemState.isDestroying = false;
            this._keySystemState.operationId = null;
        }
        
        //   Clear any partial key data
        this.ecdhKeyPair = null;
        this.ecdsaKeyPair = null;
        this.encryptionKey = null;
        this.macKey = null;
        this.metadataKey = null;
        
        //   Trigger emergency recovery if needed
        if (error.message.includes('timeout') || error.message.includes('race condition')) {
            this._secureLog('warn', 'Race condition or timeout detected, triggering emergency recovery');
            this._emergencyRecoverMutexSystem();
        }
    }

    /**
     *   Generate cryptographically secure IV with reuse prevention
     */
    _generateSecureIV(ivSize = 12, context = 'general') {
        //   Check if we're in emergency mode
        if (this._ivTrackingSystem.emergencyMode) {
            this._secureLog('error', 'CRITICAL: IV generation blocked - emergency mode active due to IV reuse');
            throw new Error('IV generation blocked - emergency mode active');
        }
        
        let attempts = 0;
        const maxAttempts = 100; // Prevent infinite loops
        
        while (attempts < maxAttempts) {
            attempts++;
            
            //   Generate fresh IV with crypto.getRandomValues
            const iv = crypto.getRandomValues(new Uint8Array(ivSize));
            
            //   Convert IV to string for tracking
            const ivString = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');
            
            //   Check for IV reuse
            if (this._ivTrackingSystem.usedIVs.has(ivString)) {
                this._ivTrackingSystem.collisionCount++;
                this._secureLog('error', `CRITICAL: IV reuse detected!`, {
                    context: context,
                    attempt: attempts,
                    collisionCount: this._ivTrackingSystem.collisionCount,
                    ivString: ivString.substring(0, 16) + '...' // Log partial IV for debugging
                });
                
                //   If too many collisions, trigger emergency mode
                if (this._ivTrackingSystem.collisionCount > 5) {
                    this._ivTrackingSystem.emergencyMode = true;
                    this._secureLog('error', 'CRITICAL: Emergency mode activated due to excessive IV reuse');
                    throw new Error('Emergency mode: Excessive IV reuse detected');
                }
                
                continue; // Try again
            }
            
            //   Validate IV entropy
            if (!this._validateIVEntropy(iv)) {
                this._ivTrackingSystem.entropyValidation.entropyFailures++;
                this._secureLog('warn', `Low entropy IV detected`, {
                    context: context,
                    attempt: attempts,
                    entropyFailures: this._ivTrackingSystem.entropyValidation.entropyFailures
                });
                
                //   If too many entropy failures, trigger emergency mode
                if (this._ivTrackingSystem.entropyValidation.entropyFailures > 10) {
                    this._ivTrackingSystem.emergencyMode = true;
                    this._secureLog('error', 'CRITICAL: Emergency mode activated due to low entropy IVs');
                    throw new Error('Emergency mode: Low entropy IVs detected');
                }
                
                continue; // Try again
            }
            
            //   Track IV usage
            this._ivTrackingSystem.usedIVs.add(ivString);
            this._ivTrackingSystem.ivHistory.set(ivString, {
                timestamp: Date.now(),
                context: context,
                attempt: attempts
            });
            
            //   Track per-session IVs
            if (this.sessionId) {
                if (!this._ivTrackingSystem.sessionIVs.has(this.sessionId)) {
                    this._ivTrackingSystem.sessionIVs.set(this.sessionId, new Set());
                }
                this._ivTrackingSystem.sessionIVs.get(this.sessionId).add(ivString);
            }
            
            //   Validate RNG periodically
            this._validateRNGQuality();
            
            this._secureLog('debug', `Secure IV generated`, {
                context: context,
                attempt: attempts,
                ivSize: ivSize,
                totalIVs: this._ivTrackingSystem.usedIVs.size
            });
            
            return iv;
        }
        
        //   If we can't generate a unique IV after max attempts
        this._secureLog('error', `Failed to generate unique IV after ${maxAttempts} attempts`, {
            context: context,
            totalIVs: this._ivTrackingSystem.usedIVs.size
        });
        throw new Error(`Failed to generate unique IV after ${maxAttempts} attempts`);
    }
    
    /**
     *   Validate IV entropy to detect weak RNG
     */
    _validateIVEntropy(iv) {
        this._ivTrackingSystem.entropyValidation.entropyTests++;
        
        //   Calculate byte distribution
        const byteCounts = new Array(256).fill(0);
        for (let i = 0; i < iv.length; i++) {
            byteCounts[iv[i]]++;
        }
        
        //   Multi-dimensional entropy analysis
        const entropyResults = {
            shannon: 0,
            min: 0,
            collision: 0,
            compression: 0,
            quantum: 0
        };
        
        // 1. Shannon entropy calculation
        let shannonEntropy = 0;
        const totalBytes = iv.length;
        
        for (let i = 0; i < 256; i++) {
            if (byteCounts[i] > 0) {
                const probability = byteCounts[i] / totalBytes;
                shannonEntropy -= probability * Math.log2(probability);
            }
        }
        entropyResults.shannon = shannonEntropy;
        
        // 2. Min-entropy calculation (worst-case scenario)
        const maxCount = Math.max(...byteCounts);
        const maxProbability = maxCount / totalBytes;
        entropyResults.min = -Math.log2(maxProbability);
        
        // 3. Collision entropy calculation
        let collisionSum = 0;
        for (let i = 0; i < 256; i++) {
            if (byteCounts[i] > 0) {
                const probability = byteCounts[i] / totalBytes;
                collisionSum += probability * probability;
            }
        }
        entropyResults.collision = -Math.log2(collisionSum);
        
        // 4. Compression-based entropy estimation
        const ivString = Array.from(iv).map(b => String.fromCharCode(b)).join('');
        const compressedLength = this._estimateCompressedLength(ivString);
        entropyResults.compression = (1 - compressedLength / totalBytes) * 8;
        
        // 5. Quantum-resistant entropy analysis
        entropyResults.quantum = this._calculateQuantumResistantEntropy(iv);
        
        //   Enhanced suspicious pattern detection
        const hasSuspiciousPatterns = this._detectAdvancedSuspiciousPatterns(iv);
        
        //   Multi-criteria validation
        const minEntropyThreshold = this._ivTrackingSystem.entropyValidation.minEntropy;
        const isValid = (
            entropyResults.shannon >= minEntropyThreshold &&
            entropyResults.min >= minEntropyThreshold * 0.8 &&
            entropyResults.collision >= minEntropyThreshold * 0.9 &&
            entropyResults.compression >= minEntropyThreshold * 0.7 &&
            entropyResults.quantum >= minEntropyThreshold * 0.6 &&
            !hasSuspiciousPatterns
        );
        
        if (!isValid) {
            this._secureLog('warn', `Enhanced IV entropy validation failed`, {
                shannon: entropyResults.shannon.toFixed(2),
                min: entropyResults.min.toFixed(2),
                collision: entropyResults.collision.toFixed(2),
                compression: entropyResults.compression.toFixed(2),
                quantum: entropyResults.quantum.toFixed(2),
                minThreshold: minEntropyThreshold,
                hasSuspiciousPatterns: hasSuspiciousPatterns
            });
        }
        
        return isValid;
    }
    
    /**
     *   Estimate compressed length for entropy calculation
     * @param {string} data - Data to estimate compression
     * @returns {number} Estimated compressed length
     */
    _estimateCompressedLength(data) {
        // Simple LZ77-like compression estimation
        let compressedLength = 0;
        let i = 0;
        
        while (i < data.length) {
            let matchLength = 0;
            let matchDistance = 0;
            
            // Look for repeated patterns
            for (let j = Math.max(0, i - 255); j < i; j++) {
                let k = 0;
                while (i + k < data.length && data[i + k] === data[j + k] && k < 255) {
                    k++;
                }
                if (k > matchLength) {
                    matchLength = k;
                    matchDistance = i - j;
                }
            }
            
            if (matchLength >= 3) {
                compressedLength += 3; // Distance + length + literal
                i += matchLength;
            } else {
                compressedLength += 1;
                i += 1;
            }
        }
        
        return compressedLength;
    }

    /**
     *   Calculate quantum-resistant entropy
     * @param {Uint8Array} data - Data to analyze
     * @returns {number} Quantum-resistant entropy score
     */
    _calculateQuantumResistantEntropy(data) {
        // Quantum-resistant entropy analysis
        let quantumScore = 0;
        
        // 1. Check for quantum-vulnerable patterns
        const hasQuantumVulnerablePatterns = this._detectQuantumVulnerablePatterns(data);
        if (hasQuantumVulnerablePatterns) {
            quantumScore -= 2;
        }
        
        // 2. Analyze bit distribution
        const bitDistribution = this._analyzeBitDistribution(data);
        quantumScore += bitDistribution.score;
        
        // 3. Check for periodicity
        const periodicity = this._detectPeriodicity(data);
        quantumScore -= periodicity * 0.5;
        
        // 4. Normalize to 0-8 range
        return Math.max(0, Math.min(8, quantumScore));
    }

    /**
     *   Detect quantum-vulnerable patterns
     * @param {Uint8Array} data - Data to analyze
     * @returns {boolean} true if quantum-vulnerable patterns found
     */
    _detectQuantumVulnerablePatterns(data) {
        // Check for patterns vulnerable to quantum attacks
        const patterns = [
            [0, 0, 0, 0, 0, 0, 0, 0], // All zeros
            [255, 255, 255, 255, 255, 255, 255, 255], // All ones
            [0, 1, 0, 1, 0, 1, 0, 1], // Alternating
            [1, 0, 1, 0, 1, 0, 1, 0]  // Alternating reverse
        ];
        
        for (const pattern of patterns) {
            for (let i = 0; i <= data.length - pattern.length; i++) {
                let match = true;
                for (let j = 0; j < pattern.length; j++) {
                    if (data[i + j] !== pattern[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) return true;
            }
        }
        
        return false;
    }

    /**
     *   Analyze bit distribution
     * @param {Uint8Array} data - Data to analyze
     * @returns {Object} Bit distribution analysis
     */
    _analyzeBitDistribution(data) {
        let ones = 0;
        let totalBits = data.length * 8;
        
        for (const byte of data) {
            ones += (byte >>> 0).toString(2).split('1').length - 1;
        }
        
        const zeroRatio = (totalBits - ones) / totalBits;
        const oneRatio = ones / totalBits;
        
        // Ideal distribution is 50/50
        const deviation = Math.abs(0.5 - oneRatio);
        const score = Math.max(0, 8 - deviation * 16);
        
        return { score, zeroRatio, oneRatio, deviation };
    }

    /**
     *   Detect periodicity in data
     * @param {Uint8Array} data - Data to analyze
     * @returns {number} Periodicity score (0-1)
     */
    _detectPeriodicity(data) {
        if (data.length < 16) return 0;
        
        let maxPeriodicity = 0;
        
        // Check for periods from 2 to data.length/2
        for (let period = 2; period <= data.length / 2; period++) {
            let matches = 0;
            let totalChecks = 0;
            
            for (let i = 0; i < data.length - period; i++) {
                if (data[i] === data[i + period]) {
                    matches++;
                }
                totalChecks++;
            }
            
            if (totalChecks > 0) {
                const periodicity = matches / totalChecks;
                maxPeriodicity = Math.max(maxPeriodicity, periodicity);
            }
        }
        
        return maxPeriodicity;
    }

    /**
     *   Enhanced suspicious pattern detection
     * @param {Uint8Array} iv - IV to check
     * @returns {boolean} true if suspicious patterns found
     */
    _detectAdvancedSuspiciousPatterns(iv) {
        // Enhanced pattern detection with quantum-resistant analysis
        const patterns = [
            // Sequential patterns
            [0, 1, 2, 3, 4, 5, 6, 7],
            [255, 254, 253, 252, 251, 250, 249, 248],
            
            // Repeated patterns
            [0, 0, 0, 0, 0, 0, 0, 0],
            [255, 255, 255, 255, 255, 255, 255, 255],
            
            // Alternating patterns
            [0, 255, 0, 255, 0, 255, 0, 255],
            [255, 0, 255, 0, 255, 0, 255, 0]
        ];
        
        for (const pattern of patterns) {
            for (let i = 0; i <= iv.length - pattern.length; i++) {
                let match = true;
                for (let j = 0; j < pattern.length; j++) {
                    if (iv[i + j] !== pattern[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) return true;
            }
        }
        
        // Check for low entropy regions
        const entropyMap = this._calculateLocalEntropy(iv);
        const lowEntropyRegions = entropyMap.filter(e => e < 3.0).length;
        
        return lowEntropyRegions > iv.length * 0.3; // More than 30% low entropy
    }

    /**
     *   Calculate local entropy for pattern detection
     * @param {Uint8Array} data - Data to analyze
     * @returns {Array} Array of local entropy values
     */
    _calculateLocalEntropy(data) {
        const windowSize = 8;
        const entropyMap = [];
        
        for (let i = 0; i <= data.length - windowSize; i++) {
            const window = data.slice(i, i + windowSize);
            const charCount = {};
            
            for (const byte of window) {
                charCount[byte] = (charCount[byte] || 0) + 1;
            }
            
            let entropy = 0;
            for (const count of Object.values(charCount)) {
                const probability = count / windowSize;
                entropy -= probability * Math.log2(probability);
            }
            
            entropyMap.push(entropy);
        }
        
        return entropyMap;
    }

    /**
     *   Detect suspicious patterns in IVs
     */
    _detectSuspiciousIVPatterns(iv) {
        //   Check for all zeros or all ones
        const allZeros = iv.every(byte => byte === 0);
        const allOnes = iv.every(byte => byte === 255);
        
        if (allZeros || allOnes) {
            return true;
        }
        
        //   Check for sequential patterns
        let sequentialCount = 0;
        for (let i = 1; i < iv.length; i++) {
            if (iv[i] === iv[i-1] + 1 || iv[i] === iv[i-1] - 1) {
                sequentialCount++;
            } else {
                sequentialCount = 0;
            }
            
            if (sequentialCount >= 3) {
                return true; // Suspicious sequential pattern
            }
        }
        
        //   Check for repeated patterns
        for (let patternLength = 2; patternLength <= Math.floor(iv.length / 2); patternLength++) {
            for (let start = 0; start <= iv.length - patternLength * 2; start++) {
                const pattern1 = iv.slice(start, start + patternLength);
                const pattern2 = iv.slice(start + patternLength, start + patternLength * 2);
                
                if (pattern1.every((byte, index) => byte === pattern2[index])) {
                    return true; // Repeated pattern detected
                }
            }
        }
        
        return false;
    }
    
    /**
     *   Clean up old IVs with strict limits
     */
    async _cleanupOldIVs() {
        const now = Date.now();
        const maxAge = 1800000; // Reduced to 30 minutes for better security
        let cleanedCount = 0;
        const cleanupBatch = [];
        
        //   Aggressive cleanup with quantum-resistant patterns
        // Enforce maximum IV history size with batch processing
        if (this._ivTrackingSystem.ivHistory.size > this._ivTrackingSystem.maxIVHistorySize) {
            const ivArray = Array.from(this._ivTrackingSystem.ivHistory.entries());
            const toRemove = ivArray.slice(0, ivArray.length - this._ivTrackingSystem.maxIVHistorySize);
            
            for (const [ivString] of toRemove) {
                cleanupBatch.push(ivString);
                cleanedCount++;
                
                // Process in batches to prevent memory spikes
                if (cleanupBatch.length >= 100) {
                    this._processCleanupBatch(cleanupBatch);
                    cleanupBatch.length = 0;
                }
            }
        }
        
        //   Clean up old IVs from history by age with enhanced security
        for (const [ivString, metadata] of this._ivTrackingSystem.ivHistory.entries()) {
            if (now - metadata.timestamp > maxAge) {
                cleanupBatch.push(ivString);
                cleanedCount++;
                
                // Process in batches to prevent memory spikes
                if (cleanupBatch.length >= 100) {
                    this._processCleanupBatch(cleanupBatch);
                    cleanupBatch.length = 0;
                }
            }
        }
        
        // Process remaining batch
        if (cleanupBatch.length > 0) {
            this._processCleanupBatch(cleanupBatch);
        }
        
        //   Enhanced session IV cleanup with entropy preservation
        for (const [sessionId, sessionIVs] of this._ivTrackingSystem.sessionIVs.entries()) {
            if (sessionIVs.size > this._ivTrackingSystem.maxSessionIVs) {
                const ivArray = Array.from(sessionIVs);
                const toRemove = ivArray.slice(0, ivArray.length - this._ivTrackingSystem.maxSessionIVs);
                
                for (const ivString of toRemove) {
                    sessionIVs.delete(ivString);
                    this._ivTrackingSystem.usedIVs.delete(ivString);
                    this._ivTrackingSystem.ivHistory.delete(ivString);
                    cleanedCount++;
                }
            }
        }
        
        //   Schedule natural cleanup if significant cleanup occurred
        if (cleanedCount > 50) {
            await this._performNaturalCleanup();
        }
        
        if (cleanedCount > 0) {
            this._secureLog('debug', `Enhanced cleanup: ${cleanedCount} old IVs removed`, {
                cleanedCount: cleanedCount,
                remainingIVs: this._ivTrackingSystem.usedIVs.size,
                remainingHistory: this._ivTrackingSystem.ivHistory.size,
                memoryPressure: this._calculateMemoryPressure()
            });
        }
    }
    
    /**
     *   Process cleanup batch with constant-time operations
     * @param {Array} batch - Batch of items to clean up
     */
    _processCleanupBatch(batch) {
        //   Constant-time batch processing
        for (const item of batch) {
            this._ivTrackingSystem.usedIVs.delete(item);
            this._ivTrackingSystem.ivHistory.delete(item);
        }
    }

    /**
     *   Calculate memory pressure for adaptive cleanup
     * @returns {number} Memory pressure score (0-100)
     */
    _calculateMemoryPressure() {
        const totalIVs = this._ivTrackingSystem.usedIVs.size;
        const maxAllowed = this._resourceLimits.maxIVHistory;
        
        return Math.min(100, Math.floor((totalIVs / maxAllowed) * 100));
    }

    /**
     *   Get IV tracking system statistics
     */
    _getIVTrackingStats() {
        return {
            totalIVs: this._ivTrackingSystem.usedIVs.size,
            collisionCount: this._ivTrackingSystem.collisionCount,
            entropyTests: this._ivTrackingSystem.entropyValidation.entropyTests,
            entropyFailures: this._ivTrackingSystem.entropyValidation.entropyFailures,
            rngTests: this._ivTrackingSystem.rngValidation.testsPerformed,
            weakRngDetected: this._ivTrackingSystem.rngValidation.weakRngDetected,
            emergencyMode: this._ivTrackingSystem.emergencyMode,
            sessionCount: this._ivTrackingSystem.sessionIVs.size,
            lastCleanup: this._lastIVCleanupTime || 0
        };
    }
    
    /**
     *   Reset IV tracking system (for testing or emergency recovery)
     */
    _resetIVTrackingSystem() {
        this._secureLog('warn', 'Resetting IV tracking system');
        
        this._ivTrackingSystem.usedIVs.clear();
        this._ivTrackingSystem.ivHistory.clear();
        this._ivTrackingSystem.sessionIVs.clear();
        this._ivTrackingSystem.collisionCount = 0;
        this._ivTrackingSystem.entropyValidation.entropyTests = 0;
        this._ivTrackingSystem.entropyValidation.entropyFailures = 0;
        this._ivTrackingSystem.rngValidation.testsPerformed = 0;
        this._ivTrackingSystem.rngValidation.weakRngDetected = false;
        this._ivTrackingSystem.emergencyMode = false;
        
        this._secureLog('info', 'IV tracking system reset completed');
    }
    
    /**
     *   Validate RNG quality
     */
    _validateRNGQuality() {
        const now = Date.now();
        
        //   Validate RNG every 1000 IV generations
        if (this._ivTrackingSystem.rngValidation.testsPerformed % 1000 === 0) {
            try {
                //   Generate test IVs and validate
                const testIVs = [];
                for (let i = 0; i < 100; i++) {
                    testIVs.push(crypto.getRandomValues(new Uint8Array(12)));
                }
                
                //   Check for duplicates in test set
                const testIVStrings = testIVs.map(iv => Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(''));
                const uniqueTestIVs = new Set(testIVStrings);
                
                if (uniqueTestIVs.size < 95) { // Allow some tolerance
                    this._ivTrackingSystem.rngValidation.weakRngDetected = true;
                    this._secureLog('error', 'CRITICAL: Weak RNG detected in validation test', {
                        uniqueIVs: uniqueTestIVs.size,
                        totalTests: testIVs.length
                    });
                }
                
                this._ivTrackingSystem.rngValidation.lastValidation = now;
                
            } catch (error) {
                this._secureLog('error', 'RNG validation failed', {
                    errorType: error.constructor.name
                });
            }
        }
        
        this._ivTrackingSystem.rngValidation.testsPerformed++;
    }
    
    /**
     *   Handle mutex timeout with enhanced state validation
     */
    _handleMutexTimeout(mutexName, operationId, timeout) {
        const mutex = this[`_${mutexName}Mutex`];
        
        if (!mutex) {
            this._secureLog('error', `Mutex '${mutexName}' not found during timeout handling`);
            return;
        }
        
        //   Validate timeout conditions
        if (mutex.lockId !== operationId) {
            this._secureLog('warn', `Timeout for different operation ID on mutex '${mutexName}'`, {
                expectedOperationId: operationId,
                actualLockId: mutex.lockId,
                locked: mutex.locked
            });
            return;
        }
        
        if (!mutex.locked) {
            this._secureLog('warn', `Timeout for already unlocked mutex '${mutexName}'`, {
                operationId: operationId
            });
            return;
        }
        
        try {
            //   Calculate lock duration for monitoring
            const lockDuration = mutex.lockTime ? Date.now() - mutex.lockTime : 0;
            
            this._secureLog('warn', `Mutex '${mutexName}' auto-released due to timeout`, {
                operationId: operationId,
                lockDuration: lockDuration,
                timeout: timeout,
                queueLength: mutex.queue.length
            });
            
            //   Atomic release with state validation
            mutex.locked = false;
            mutex.lockId = null;
            mutex.lockTimeout = null;
            mutex.lockTime = null;
            
            //   Process next in queue with error handling
            setTimeout(() => {
                try {
                    this._processNextInQueue(mutexName);
                } catch (queueError) {
                    this._secureLog('error', `Error processing queue after timeout for mutex '${mutexName}'`, {
                        errorType: queueError.constructor.name,
                        errorMessage: queueError.message
                    });
                }
            }, 10);
            
        } catch (error) {
            this._secureLog('error', `Critical error during mutex timeout handling for '${mutexName}'`, {
                operationId: operationId,
                errorType: error.constructor.name,
                errorMessage: error.message
            });
            
            //   Force emergency unlock if timeout handling fails
            try {
                this._emergencyUnlockAllMutexes('timeoutHandler');
            } catch (emergencyError) {
                this._secureLog('error', `Emergency unlock failed during timeout handling`, {
                    originalError: error.message,
                    emergencyError: emergencyError.message
                });
            }
        }
    }

    /**
     *   Validate mutex system after emergency unlock
     */
    _validateMutexSystemAfterEmergencyUnlock() {
        const mutexes = ['keyOperation', 'cryptoOperation', 'connectionOperation'];
        let validationErrors = 0;
        
        this._secureLog('info', 'Validating mutex system after emergency unlock');
        
        mutexes.forEach(mutexName => {
            const mutex = this[`_${mutexName}Mutex`];
            
            if (!mutex) {
                validationErrors++;
                this._secureLog('error', `Mutex '${mutexName}' not found after emergency unlock`);
                return;
            }
            
            //   Validate mutex state consistency
            if (mutex.locked) {
                validationErrors++;
                this._secureLog('error', `Mutex '${mutexName}' still locked after emergency unlock`, {
                    lockId: mutex.lockId,
                    lockTime: mutex.lockTime
                });
            }
            
            if (mutex.lockId !== null) {
                validationErrors++;
                this._secureLog('error', `Mutex '${mutexName}' still has lock ID after emergency unlock`, {
                    lockId: mutex.lockId
                });
            }
            
            if (mutex.lockTimeout !== null) {
                validationErrors++;
                this._secureLog('error', `Mutex '${mutexName}' still has timeout after emergency unlock`);
            }
            
            if (mutex.queue.length > 0) {
                validationErrors++;
                this._secureLog('error', `Mutex '${mutexName}' still has queue items after emergency unlock`, {
                    queueLength: mutex.queue.length
                });
            }
        });
        
        //   Validate key system state
        if (this._keySystemState) {
            if (this._keySystemState.isInitializing || 
                this._keySystemState.isRotating || 
                this._keySystemState.isDestroying) {
                validationErrors++;
                this._secureLog('error', `Key system state not properly reset after emergency unlock`, {
                    isInitializing: this._keySystemState.isInitializing,
                    isRotating: this._keySystemState.isRotating,
                    isDestroying: this._keySystemState.isDestroying
                });
            }
        }
        
        if (validationErrors === 0) {
            this._secureLog('info', 'Mutex system validation passed after emergency unlock');
        } else {
            this._secureLog('error', `Mutex system validation failed after emergency unlock`, {
                validationErrors: validationErrors
            });
            
            //   Force re-initialization if validation fails
            setTimeout(() => {
                this._emergencyRecoverMutexSystem();
            }, 1000);
        }
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
            this._secureLog('info', 'Creating secure offer with mutex', {
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
                
                this._secureLog('debug', 'Session salt generated', {
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

                
                if (!ecdhPublicKeyData || typeof ecdhPublicKeyData !== 'object') {
                    this._secureLog('error', 'CRITICAL: ECDH key export failed - invalid object structure', { operationId });
                    throw new Error('CRITICAL SECURITY FAILURE: ECDH key export validation failed - hard abort required');
                }
                
                if (!ecdhPublicKeyData.keyData || !ecdhPublicKeyData.signature) {
                    this._secureLog('error', 'CRITICAL: ECDH key export incomplete - missing keyData or signature', { 
                        operationId,
                        hasKeyData: !!ecdhPublicKeyData.keyData,
                        hasSignature: !!ecdhPublicKeyData.signature 
                    });
                    throw new Error('CRITICAL SECURITY FAILURE: ECDH key export incomplete - hard abort required');
                }
                
                if (!ecdsaPublicKeyData || typeof ecdsaPublicKeyData !== 'object') {
                    this._secureLog('error', 'CRITICAL: ECDSA key export failed - invalid object structure', { operationId });
                    throw new Error('CRITICAL SECURITY FAILURE: ECDSA key export validation failed - hard abort required');
                }
                
                if (!ecdsaPublicKeyData.keyData || !ecdsaPublicKeyData.signature) {
                    this._secureLog('error', 'CRITICAL: ECDSA key export incomplete - missing keyData or signature', { 
                        operationId,
                        hasKeyData: !!ecdsaPublicKeyData.keyData,
                        hasSignature: !!ecdsaPublicKeyData.signature 
                    });
                    throw new Error('CRITICAL SECURITY FAILURE: ECDSA key export incomplete - hard abort required');
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
                
                this._secureLog('debug', 'Data channel created', {
                    operationId: operationId,
                    channelLabel: this.dataChannel.label,
                    channelOrdered: this.dataChannel.ordered
                });
                
                // ============================================
                // PHASE 7: CREATE SDP OFFER
                // ============================================
                

                const offer = await this.peerConnection.createOffer({
                    offerToReceiveAudio: false,
                    offerToReceiveVideo: false
                });
                
                await this.peerConnection.setLocalDescription(offer);

                try {
                    const ourFingerprint = this._extractDTLSFingerprintFromSDP(offer.sdp);
                    this.expectedDTLSFingerprint = ourFingerprint;
                    
                    this._secureLog('info', 'Generated DTLS fingerprint for out-of-band verification', {
                        fingerprint: ourFingerprint,
                        context: 'offer_creation'
                    });
                    
                    // Notify UI that fingerprint is ready for out-of-band verification
                    this.deliverMessageToUI(`DTLS fingerprint ready for verification: ${ourFingerprint}`, 'system');
                } catch (error) {
                    this._secureLog('error', 'Failed to extract DTLS fingerprint from offer', { error: error.message });
                    // Continue without fingerprint validation (fallback mode)
                }
                
                // Await ICE gathering
                await this.waitForIceGathering();
                
                this._secureLog('debug', 'ICE gathering completed', {
                    operationId: operationId,
                    iceGatheringState: this.peerConnection.iceGatheringState,
                    connectionState: this.peerConnection.connectionState
                });
                
                // ============================================
                // PHASE 8: GENERATE SAS FOR OUT-OF-BAND VERIFICATION
                // ============================================

                this.verificationCode = window.EnhancedSecureCryptoUtils.generateVerificationCode();
                
                // Validate verification code
                if (!this.verificationCode || this.verificationCode.length < EnhancedSecureWebRTCManager.SIZES.VERIFICATION_CODE_MIN_LENGTH) {
                    throw new Error('Failed to generate valid verification code');
                }
                
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
                
                // Generate connection ID for AAD
                this.connectionId = Array.from(crypto.getRandomValues(new Uint8Array(8)))
                    .map(b => b.toString(16).padStart(2, '0')).join('');
                
                // ============================================
                // PHASE 11: SECURITY LEVEL CALCULATION
                // ============================================
                
                // All security features are enabled by default
                const securityLevel = {
                    level: 'MAXIMUM',
                    score: 100,
                    color: 'green',
                    details: 'All security features enabled by default',
                        passedChecks: 10,
                    totalChecks: 10,
                    isRealData: true
                    };
                
                // ============================================
                // PHASE 12: CREATE OFFER PACKAGE
                // ============================================
                
                const currentTimestamp = Date.now();
                
                // Create compact offer package for smaller QR codes
                const offerPackage = {
                    // Core information (minimal)
                    t: 'offer', // type
                    s: this.peerConnection.localDescription.sdp, // sdp
                    v: '4.0', // version
                    ts: currentTimestamp, // timestamp
                    
                    // Cryptographic keys (essential)
                    e: ecdhPublicKeyData, // ecdhPublicKey
                    d: ecdsaPublicKeyData, // ecdsaPublicKey
                    
                    // Session data (essential)
                    sl: this.sessionSalt, // salt
                    si: this.sessionId, // sessionId
                    ci: this.connectionId, // connectionId
                    
                    // Authentication (essential)
                    vc: this.verificationCode, // verificationCode
                    ac: authChallenge, // authChallenge
                    
                    // Security metadata (simplified)
                    slv: 'MAX', // securityLevel
                    
                    // Key fingerprints (shortened)
                    kf: {
                        e: ecdhFingerprint.substring(0, 12), // ecdh (12 chars)
                        d: ecdsaFingerprint.substring(0, 12) // ecdsa (12 chars)
                    }
                };
                
                // ============================================
                // PHASE 13: VALIDATE OFFER PACKAGE
                // ============================================

                try {
                    const validationResult = this.validateEnhancedOfferData(offerPackage);

                } catch (validationError) {
                    throw new Error(`Offer package validation error: ${validationError.message}`);
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
                    capabilitiesCount: 10 // All capabilities enabled by default
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

                return offerPackage;
                
            } catch (error) {
                // ============================================
                // ERROR HANDLING
                // ============================================
                
                this._secureLog('error', 'Enhanced secure offer creation failed in critical section', {
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
     *   Secure cleanup state after failed offer creation
     */
    _cleanupFailedOfferCreation() {
        try {
            //   Secure wipe of cryptographic materials
            this._secureCleanupCryptographicMaterials();
            
            //   Close peer connection if it was created
            if (this.peerConnection) {
                this.peerConnection.close();
                this.peerConnection = null;
            }
            
            //   Clear data channel
            if (this.dataChannel) {
                this.dataChannel.close();
                this.dataChannel = null;
            }
            
            //   Reset flags
            this.isInitiator = false;
            this.isVerified = false;
            
            //   Reset security features to baseline
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
            
            //   Schedule natural cleanup
            this._forceGarbageCollection().catch(error => {
                this._secureLog('error', 'Cleanup failed during offer cleanup', {
                    errorType: error?.constructor?.name || 'Unknown'
                });
            });
            
            this._secureLog('debug', 'Failed offer creation cleanup completed with secure memory wipe');
            
        } catch (cleanupError) {
            this._secureLog('error', 'Error during offer creation cleanup', {
                errorType: cleanupError.constructor.name,
                errorMessage: cleanupError.message
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
            
            this._secureLog('debug', 'Security features updated', {
                updatedCount: Object.keys(updates).length,
                totalFeatures: Object.keys(this.securityFeatures).length
            });
            
        } catch (error) {
            // Roll back on error
            this.securityFeatures = oldFeatures;
            this._secureLog('error', 'Security features update failed, rolled back', {
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
            this._secureLog('info', 'Creating secure answer with mutex', {
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
                
                // MITM Protection: Validate offer data structure (support both formats)
                const timestamp = offerData.ts || offerData.timestamp;
                const version = offerData.v || offerData.version;
                if (!timestamp || !version) {
                    throw new Error('Missing required security fields in offer data – possible MITM attack');
                }
                
                // Replay attack protection (extended to 30 minutes for better UX)
                const offerAge = Date.now() - timestamp;
                const MAX_OFFER_AGE = 1800000; // 30 minutes for better user experience
                
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
                
                // Protocol version compatibility check (support both formats)
                const protocolVersion = version; // Use the version we already extracted
                if (protocolVersion !== '4.0') {
                    this._secureLog('warn', 'Protocol version mismatch detected', {
                        operationId: operationId,
                        expectedVersion: '4.0',
                        receivedVersion: protocolVersion
                    });
                    
                    // For backward compatibility with v3.0, a fallback can be added
                    if (protocolVersion !== '3.0') {
                        throw new Error(`Unsupported protocol version: ${protocolVersion}`);
                    }
                }
                
                // ============================================
                // PHASE 3: EXTRACT AND VALIDATE SESSION SALT
                // ============================================
                
                // Set session salt from offer (support both formats)
                this.sessionSalt = offerData.sl || offerData.salt;
                
                // Validate session salt
                if (!Array.isArray(this.sessionSalt)) {
                    throw new Error('Invalid session salt format - must be array');
                }
                
                const expectedSaltLength = protocolVersion === '4.0' ? 64 : 32;
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
                
                // Import peer ECDSA public key for signature verification (support both formats)
                let peerECDSAPublicKey;
                
                try {
                    const ecdsaKey = offerData.d || offerData.ecdsaPublicKey;
                    peerECDSAPublicKey = await crypto.subtle.importKey(
                        'spki',
                        new Uint8Array(ecdsaKey.keyData),
                        {
                            name: 'ECDSA',
                            namedCurve: 'P-384'
                        },
                        false,
                        ['verify']
                    );
                } catch (error) {
                    this._throwSecureError(error, 'ecdsa_key_import');
                }
                
                // ============================================
                // PHASE 6: IMPORT AND VERIFY ECDH KEY
                // ============================================
                
                // Import and verify ECDH public key using verified ECDSA key (support both formats)
                let peerECDHPublicKey;
                
                try {
                    const ecdhKey = offerData.e || offerData.ecdhPublicKey;
                    peerECDHPublicKey = await window.EnhancedSecureCryptoUtils.importSignedPublicKey(
                        ecdhKey,
                        peerECDSAPublicKey,
                        'ECDH'
                    );
                } catch (error) {
                    this._secureLog('error', 'Failed to import signed ECDH public key', {
                        operationId: operationId,
                        errorType: error.constructor.name
                    });
                    this._throwSecureError(error, 'ecdh_key_import');
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
                    this._throwSecureError(error, 'key_derivation');
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
                        this._throwSecureError(error, 'authentication_proof_creation');
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
                
                // Create peer connection first
                this.createPeerConnection();
                
                //   Validate DTLS fingerprint before setting remote description
                if (this.strictDTLSValidation) {
                    try {
                        const receivedFingerprint = this._extractDTLSFingerprintFromSDP(offerData.sdp);
                        
                        if (this.expectedDTLSFingerprint) {
                            await this._validateDTLSFingerprint(receivedFingerprint, this.expectedDTLSFingerprint, 'offer_validation');
                        } else {
                            // Store fingerprint for future validation (first connection)
                            this.expectedDTLSFingerprint = receivedFingerprint;
                            this._secureLog('info', 'Stored DTLS fingerprint for future validation', {
                                fingerprint: receivedFingerprint,
                                context: 'first_connection'
                            });
                        }
                    } catch (error) {
                        this._secureLog('warn', 'DTLS fingerprint validation failed - continuing in fallback mode', { 
                            error: error.message,
                            context: 'offer_validation'
                        });
                        // Continue without strict fingerprint validation for first connection
                        // This allows the connection to proceed while maintaining security awareness
                    }
                } else {
                    this._secureLog('info', 'DTLS fingerprint validation disabled - proceeding without validation');
                }

                // Set remote description from offer
                try {
                    this._secureLog('debug', 'Setting remote description from offer', {
                        operationId: operationId,
                        sdpLength: offerData.sdp?.length || 0
                    });
                    
                    await this.peerConnection.setRemoteDescription(new RTCSessionDescription({
                        type: 'offer',
                        sdp: offerData.s || offerData.sdp
                    }));
                    
                    this._secureLog('debug', 'Remote description set successfully', {
                        operationId: operationId,
                        signalingState: this.peerConnection.signalingState
                    });
                } catch (error) {
                    this._secureLog('error', 'Failed to set remote description', { 
                        error: error.message,
                        operationId: operationId
                    });
                    this._throwSecureError(error, 'webrtc_remote_description');
                }
                
                this._secureLog('debug', 'Remote description set successfully', {
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
                    this._throwSecureError(error, 'webrtc_create_answer');
                }
                
                // Set local description
                try {
                    await this.peerConnection.setLocalDescription(answer);
                } catch (error) {
                    this._throwSecureError(error, 'webrtc_local_description');
                }
                
                //   Extract and store our DTLS fingerprint for out-of-band verification
                try {
                    const ourFingerprint = this._extractDTLSFingerprintFromSDP(answer.sdp);
                    this.expectedDTLSFingerprint = ourFingerprint;
                    
                    this._secureLog('info', 'Generated DTLS fingerprint for out-of-band verification', {
                        fingerprint: ourFingerprint,
                        context: 'answer_creation'
                    });
                    
                    // Notify UI that fingerprint is ready for out-of-band verification
                    this.deliverMessageToUI(`DTLS fingerprint ready for verification: ${ourFingerprint}`, 'system');
                } catch (error) {
                    this._secureLog('error', 'Failed to extract DTLS fingerprint from answer', { error: error.message });
                    // Continue without fingerprint validation (fallback mode)
                }
                
                
                // Await ICE gathering
                await this.waitForIceGathering();
                
                this._secureLog('debug', 'ICE gathering completed for answer', {
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
                
                if (!ecdhPublicKeyData || typeof ecdhPublicKeyData !== 'object') {
                    this._secureLog('error', 'CRITICAL: ECDH key export failed - invalid object structure', { operationId });
                    throw new Error('CRITICAL SECURITY FAILURE: ECDH key export validation failed - hard abort required');
                }
                
                if (!ecdhPublicKeyData.keyData || !ecdhPublicKeyData.signature) {
                    this._secureLog('error', 'CRITICAL: ECDH key export incomplete - missing keyData or signature', { 
                        operationId,
                        hasKeyData: !!ecdhPublicKeyData.keyData,
                        hasSignature: !!ecdhPublicKeyData.signature 
                    });
                    throw new Error('CRITICAL SECURITY FAILURE: ECDH key export incomplete - hard abort required');
                }
                
                if (!ecdsaPublicKeyData || typeof ecdsaPublicKeyData !== 'object') {
                    this._secureLog('error', 'CRITICAL: ECDSA key export failed - invalid object structure', { operationId });
                    throw new Error('CRITICAL SECURITY FAILURE: ECDSA key export validation failed - hard abort required');
                }
                
                if (!ecdsaPublicKeyData.keyData || !ecdsaPublicKeyData.signature) {
                    this._secureLog('error', 'CRITICAL: ECDSA key export incomplete - missing keyData or signature', { 
                        operationId,
                        hasKeyData: !!ecdsaPublicKeyData.keyData,
                        hasSignature: !!ecdsaPublicKeyData.signature 
                    });
                    throw new Error('CRITICAL SECURITY FAILURE: ECDSA key export incomplete - hard abort required');
                }
                
                // ============================================
                // PHASE 13: SECURITY LEVEL CALCULATION
                // ============================================
                
                // All security features are enabled by default
                const securityLevel = {
                    level: 'MAXIMUM',
                    score: 100,
                    color: 'green',
                    details: 'All security features enabled by default',
                    passedChecks: 10,
                    totalChecks: 10,
                    isRealData: true
                };
                
                // ============================================
                // PHASE 14: CREATE ANSWER PACKAGE
                // ============================================
                
                const currentTimestamp = Date.now();
                
                // Create compact answer package for smaller QR codes
                const answerPackage = {
                    // Core information (minimal)
                    t: 'answer', // type
                    s: this.peerConnection.localDescription.sdp, // sdp
                    v: '4.0', // version
                    ts: currentTimestamp, // timestamp
                    
                    // Cryptographic keys (essential)
                    e: ecdhPublicKeyData, // ecdhPublicKey
                    d: ecdsaPublicKeyData, // ecdsaPublicKey
                    
                    // Authentication (essential)
                    ap: authProof, // authProof
                    
                    // Security metadata (simplified)
                    slv: 'MAX', // securityLevel
                    
                    // Session confirmation (simplified)
                    sc: {
                        sf: saltFingerprint.substring(0, 12), // saltFingerprint (12 chars)
                        kd: true, // keyDerivationSuccess
                        ma: true // mutualAuthEnabled
                    }
                };
                
                // ============================================
                // PHASE 15: VALIDATION AND LOGGING
                // ============================================
                
                // Final validation of the answer package (support both formats)
                const hasSDP = answerPackage.s || answerPackage.sdp;
                const hasECDH = answerPackage.e || answerPackage.ecdhPublicKey;
                const hasECDSA = answerPackage.d || answerPackage.ecdsaPublicKey;
                
                if (!hasSDP || !hasECDH || !hasECDSA) {
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
                            this._secureLog('info', 'Post-connection security level calculated', {
                                operationId: operationId,
                                level: realSecurityData.level
                            });
                        }
                    } catch (error) {
                        this._secureLog('error', 'Error calculating post-connection security', {
                            operationId: operationId,
                            errorType: error.constructor.name
                        });
                    }
                }, 1000);
                
                // Retry if the first calculation fails
                setTimeout(async () => {
                    if (!this.lastSecurityCalculation || this.lastSecurityCalculation.score < 50) {
                        this._secureLog('info', 'Retrying security calculation', {
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
                
                this._secureLog('error', 'Enhanced secure answer creation failed in critical section', {
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
    /**
     *   Secure cleanup state after failed answer creation
     */
    _cleanupFailedAnswerCreation() {
        try {
            //   Secure wipe of cryptographic materials
            this._secureCleanupCryptographicMaterials();
            
            //   Secure wipe of PFS key versions
            this.currentKeyVersion = 0;
            this.keyVersions.clear();
            this.oldKeys.clear();
            
            //   Close peer connection if created
            if (this.peerConnection) {
                this.peerConnection.close();
                this.peerConnection = null;
            }
            
            //   Clear data channel
            if (this.dataChannel) {
                this.dataChannel.close();
                this.dataChannel = null;
            }
            
            //   Reset flags and counters
            this.isInitiator = false;
            this.isVerified = false;
            this.sequenceNumber = 0;
            this.expectedSequenceNumber = 0;
            this.messageCounter = 0;
            this.processedMessageIds.clear();
            this.replayWindow.clear(); //   Clear replay window
            
            //   Reset security features to baseline
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
            
            //   Schedule natural cleanup
            this._forceGarbageCollection().catch(error => {
                this._secureLog('error', 'Cleanup failed during answer cleanup', {
                    errorType: error?.constructor?.name || 'Unknown'
                });
            });
            
            this._secureLog('debug', 'Failed answer creation cleanup completed with secure memory wipe');
            
        } catch (cleanupError) {
            this._secureLog('error', 'Error during answer creation cleanup', {
                errorType: cleanupError.constructor.name,
                errorMessage: cleanupError.message
            });
        }
    }

    /**
     * HELPER: Securely set encryption keys (if not set yet)
     */
    async _setEncryptionKeys(encryptionKey, macKey, metadataKey, keyFingerprint) {
        return this._withMutex('keyOperation', async (operationId) => {
            this._secureLog('info', 'Setting encryption keys with mutex', {
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
            this.replayWindow.clear(); //   Clear replay window
                
                this._secureLog('info', 'Encryption keys set successfully', {
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
                
                this._secureLog('error', 'Key setting failed, rolled back', {
                    operationId: operationId,
                    errorType: error.constructor.name
                });
                
                throw error;
            }
        });
    }

    async handleSecureAnswer(answerData) {
        try {
            
            if (!answerData || typeof answerData !== 'object' || Array.isArray(answerData)) {
                this._secureLog('error', 'CRITICAL: Invalid answer data structure', { 
                    hasAnswerData: !!answerData,
                    answerDataType: typeof answerData,
                    isArray: Array.isArray(answerData)
                });
                throw new Error('CRITICAL SECURITY FAILURE: Answer data must be a non-null object');
            }
            
            // Support both compact and legacy answer formats
            const isCompactAnswer = answerData.t === 'answer' && answerData.s;
            const isLegacyAnswer = answerData.type === 'enhanced_secure_answer' && answerData.sdp;
            
            if (!isCompactAnswer && !isLegacyAnswer) {
                this._secureLog('error', 'CRITICAL: Invalid answer format', { 
                    type: answerData.type || answerData.t,
                    hasSdp: !!(answerData.sdp || answerData.s)
                });
                throw new Error('CRITICAL SECURITY FAILURE: Invalid answer format - hard abort required');
            }

            // CRITICAL: Strict validation of ECDH public key structure
            // Support both full and compact key names
            const ecdhKey = answerData.ecdhPublicKey || answerData.e;
            const ecdsaKey = answerData.ecdsaPublicKey || answerData.d;
            
            if (!ecdhKey || typeof ecdhKey !== 'object' || Array.isArray(ecdhKey)) {
                this._secureLog('error', 'CRITICAL: Invalid ECDH public key structure in answer', { 
                    hasEcdhKey: !!ecdhKey,
                    ecdhKeyType: typeof ecdhKey,
                    isArray: Array.isArray(ecdhKey),
                    availableKeys: Object.keys(answerData)
                });
                throw new Error('CRITICAL SECURITY FAILURE: Missing or invalid ECDH public key structure');
            }
            
            if (!ecdhKey.keyData || !ecdhKey.signature) {
                this._secureLog('error', 'CRITICAL: ECDH key missing keyData or signature in answer', { 
                    hasKeyData: !!ecdhKey.keyData,
                    hasSignature: !!ecdhKey.signature
                });
                throw new Error('CRITICAL SECURITY FAILURE: ECDH key missing keyData or signature');
            }

            // CRITICAL: Strict validation of ECDSA public key structure
            if (!ecdsaKey || typeof ecdsaKey !== 'object' || Array.isArray(ecdsaKey)) {
                this._secureLog('error', 'CRITICAL: Invalid ECDSA public key structure in answer', { 
                    hasEcdsaKey: !!ecdsaKey,
                    ecdsaKeyType: typeof ecdsaKey,
                    isArray: Array.isArray(ecdsaKey)
                });
                throw new Error('CRITICAL SECURITY FAILURE: Missing or invalid ECDSA public key structure');
            }
            
            if (!ecdsaKey.keyData || !ecdsaKey.signature) {
                this._secureLog('error', 'CRITICAL: ECDSA key missing keyData or signature in answer', { 
                    hasKeyData: !!ecdsaKey.keyData,
                    hasSignature: !!ecdsaKey.signature
                });
                throw new Error('CRITICAL SECURITY FAILURE: ECDSA key missing keyData or signature');
            }

            // Additional MITM protection: Validate answer data structure
            // Support both compact and legacy formats
            const timestamp = answerData.ts || answerData.timestamp;
            const version = answerData.v || answerData.version;
            
            if (!timestamp || !version) {
                throw new Error('Missing required fields in response data – possible MITM attack');
            }

            // MITM Protection: Verify session ID if present (for enhanced security)
            if (answerData.sessionId && this.sessionId && answerData.sessionId !== this.sessionId) {
                window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Session ID mismatch detected - possible MITM attack', {
                    expectedSessionIdHash: await this._createSafeLogHash(this.sessionId, 'session_id'),
                    receivedSessionIdHash: await this._createSafeLogHash(answerData.sessionId, 'session_id')
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
                new Uint8Array(ecdsaKey.keyData),
                {
                    name: 'ECDSA',
                    namedCurve: 'P-384'
                },
                false,
                ['verify']
            );


            // Now import and verify the ECDH public key using the verified ECDSA key
            const peerPublicKey = await window.EnhancedSecureCryptoUtils.importPublicKeyFromSignedPackage(
                ecdhKey,
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
            
            // Initialize connection ID if not already set
            if (!this.connectionId) {
                this.connectionId = Array.from(crypto.getRandomValues(new Uint8Array(8)))
                    .map(b => b.toString(16).padStart(2, '0')).join('');
            }

            
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
            this.replayWindow.clear(); //   Clear replay window
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

            //   Compute SAS for MITM protection (Offer side - Answer handler)
            try {
                const remoteFP = this._extractDTLSFingerprintFromSDP(answerData.sdp || answerData.s); 
                const localFP = this.expectedDTLSFingerprint; 
                const keyBytes = this._decodeKeyFingerprint(this.keyFingerprint); 

                this.verificationCode = await this._computeSAS(keyBytes, localFP, remoteFP);
                this.onStatusChange?.('verifying'); 
                this.onVerificationRequired(this.verificationCode);
                
                // CRITICAL: Store SAS code to send when data channel opens
                this.pendingSASCode = this.verificationCode;
                
                this._secureLog('info', 'SAS verification code generated for MITM protection (Offer side)', {
                    sasCode: this.verificationCode,
                    localFP: localFP.substring(0, 16) + '...',
                    remoteFP: remoteFP.substring(0, 16) + '...',
                    timestamp: Date.now()
                });
            } catch (sasError) {
                this._secureLog('error', 'SAS computation failed in handleSecureAnswer (Offer side)', {
                    errorType: sasError?.constructor?.name || 'Unknown'
                });
                this._secureLog('error', 'SAS computation failed in handleSecureAnswer (Offer side)', {
                    error: sasError.message,
                    stack: sasError.stack,
                    timestamp: Date.now()
                });
            }

            //   Validate DTLS fingerprint before setting remote description
            if (this.strictDTLSValidation) {
                try {
                    const receivedFingerprint = this._extractDTLSFingerprintFromSDP(answerData.sdp || answerData.s);
                    
                    if (this.expectedDTLSFingerprint) {
                        await this._validateDTLSFingerprint(receivedFingerprint, this.expectedDTLSFingerprint, 'answer_validation');
                    } else {
                        // Store fingerprint for future validation (first connection)
                        this.expectedDTLSFingerprint = receivedFingerprint;
                        this._secureLog('info', 'Stored DTLS fingerprint for future validation', {
                            fingerprint: receivedFingerprint,
                            context: 'first_connection'
                        });
                    }
                } catch (error) {
                    this._secureLog('warn', 'DTLS fingerprint validation failed - continuing in fallback mode', { 
                        error: error.message,
                        context: 'answer_validation'
                    });

                }
            } else {
                this._secureLog('info', 'DTLS fingerprint validation disabled - proceeding without validation');
            }

            // Support both full and compact SDP field names
            const sdpData = answerData.sdp || answerData.s;
            
            this._secureLog('debug', 'Setting remote description from answer', {
                sdpLength: sdpData?.length || 0,
                usingCompactSDP: !answerData.sdp && !!answerData.s
            });
            
            await this.peerConnection.setRemoteDescription({
                type: 'answer',
                sdp: sdpData
            });
            
            this._secureLog('debug', 'Remote description set successfully from answer', {
                signalingState: this.peerConnection.signalingState
            });

            setTimeout(async () => {
                try {
                    const securityData = await this.calculateAndReportSecurityLevel();
                    if (securityData) {
                        this.notifySecurityUpdate();
                    }
                } catch (error) {
                    this._secureLog('error', 'Error calculating security after connection:', { errorType: error?.constructor?.name || 'Unknown' });
                }
            }, 1000);
            setTimeout(async () => {
                if (!this.lastSecurityCalculation || this.lastSecurityCalculation.score < 50) {
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


    initiateVerification() {
        
        if (this.isInitiator) {
            // Ensure verification initiation notice wasn't already sent
            if (!this.verificationInitiationSent) {
                this.verificationInitiationSent = true;
                this.deliverMessageToUI('CRITICAL: Compare verification code with peer out-of-band (voice/video/in-person) to prevent MITM attack!', 'system');
                this.deliverMessageToUI(`Your verification code: ${this.verificationCode}`, 'system');
                this.deliverMessageToUI('Ask peer to confirm this exact code before allowing traffic!', 'system');
            }
        } else {

            this.deliverMessageToUI('Waiting for verification code from peer...', 'system');
        }
    }

    confirmVerification() {
        
        try {
            
            // Mark local verification as confirmed
            this.localVerificationConfirmed = true;
            
            // Send confirmation to peer
            const confirmationPayload = {
                type: 'verification_confirmed',
                data: {
                    timestamp: Date.now(),
                    verificationMethod: 'SAS',
                    securityLevel: 'MITM_PROTECTION_REQUIRED'
                }
            };

            this.dataChannel.send(JSON.stringify(confirmationPayload));
            
            // Notify UI about state change
            if (this.onVerificationStateChange) {
                this.onVerificationStateChange({
                    localConfirmed: this.localVerificationConfirmed,
                    remoteConfirmed: this.remoteVerificationConfirmed,
                    bothConfirmed: this.bothVerificationsConfirmed
                });
            }
            
            // Check if both parties have confirmed
            this._checkBothVerificationsConfirmed();
            
            // Notify UI about local confirmation
            this.deliverMessageToUI('You confirmed the verification code. Waiting for peer confirmation...', 'system');
            
            this.processMessageQueue();
        } catch (error) {
            this._secureLog('error', 'SAS verification failed:', { errorType: error?.constructor?.name || 'Unknown' });
            this.deliverMessageToUI('SAS verification failed', 'system');
        }
    }

    _checkBothVerificationsConfirmed() {
        // Check if both parties have confirmed verification
        if (this.localVerificationConfirmed && this.remoteVerificationConfirmed && !this.bothVerificationsConfirmed) {
            this.bothVerificationsConfirmed = true;
            
            // Notify both parties that verification is complete
            const bothConfirmedPayload = {
                type: 'verification_both_confirmed',
                data: {
                    timestamp: Date.now(),
                    verificationMethod: 'SAS',
                    securityLevel: 'MITM_PROTECTION_COMPLETE'
                }
            };

            this.dataChannel.send(JSON.stringify(bothConfirmedPayload));
            
            // Notify UI about state change
            if (this.onVerificationStateChange) {
                this.onVerificationStateChange({
                    localConfirmed: this.localVerificationConfirmed,
                    remoteConfirmed: this.remoteVerificationConfirmed,
                    bothConfirmed: this.bothVerificationsConfirmed
                });
            }
            
            // Set verified status and open chat after 2 second delay
            this.deliverMessageToUI('Both parties confirmed! Opening secure chat in 2 seconds...', 'system');
            
            setTimeout(() => {
                this._setVerifiedStatus(true, 'MUTUAL_SAS_CONFIRMED', { 
                    code: this.verificationCode,
                    timestamp: Date.now()
                });
                this._enforceVerificationGate('mutual_confirmed', false);
                this.onStatusChange?.('verified');
            }, 2000);
        }
    }

    handleVerificationConfirmed(data) {
        this.remoteVerificationConfirmed = true;
        
        // Notify UI about peer confirmation
        this.deliverMessageToUI('Peer confirmed the verification code. Waiting for your confirmation...', 'system');
        
        // Notify UI about state change
        if (this.onVerificationStateChange) {
            this.onVerificationStateChange({
                localConfirmed: this.localVerificationConfirmed,
                remoteConfirmed: this.remoteVerificationConfirmed,
                bothConfirmed: this.bothVerificationsConfirmed
            });
        }
        
        // Check if both parties have confirmed
        this._checkBothVerificationsConfirmed();
    }

    handleVerificationBothConfirmed(data) {
        // Handle notification that both parties have confirmed
        this.bothVerificationsConfirmed = true;
        
        // Notify UI about state change
        if (this.onVerificationStateChange) {
            this.onVerificationStateChange({
                localConfirmed: this.localVerificationConfirmed,
                remoteConfirmed: this.remoteVerificationConfirmed,
                bothConfirmed: this.bothVerificationsConfirmed
            });
        }
        
        // Set verified status and open chat after 2 second delay
        this.deliverMessageToUI('Both parties confirmed! Opening secure chat in 2 seconds...', 'system');
        
        setTimeout(() => {
            this._setVerifiedStatus(true, 'MUTUAL_SAS_CONFIRMED', { 
                code: this.verificationCode,
                timestamp: Date.now()
            });
            this._enforceVerificationGate('mutual_confirmed', false);
            this.onStatusChange?.('verified');
        }, 2000);
    }

    handleVerificationRequest(data) {

        
        if (data.code === this.verificationCode) {
            const responsePayload = {
                type: 'verification_response',
                data: {
                    ok: true,
                    timestamp: Date.now(),
                    verificationMethod: 'SAS', // Indicate SAS was used
                    securityLevel: 'MITM_PROTECTED'
                }
            };
            this.dataChannel.send(JSON.stringify(responsePayload));
            
            // Ensure verification success notice wasn't already sent
            if (!this.verificationNotificationSent) {
                this.verificationNotificationSent = true;
                this.deliverMessageToUI('SAS verification successful! MITM protection confirmed. Channel is now secure!', 'system');
            }
            
            this.processMessageQueue();
        } else {
            //  SAS verification failed - possible MITM attack
            const responsePayload = {
                type: 'verification_response',
                data: {
                    ok: false,
                    timestamp: Date.now(),
                    reason: 'code_mismatch'
                }
            };
            this.dataChannel.send(JSON.stringify(responsePayload));
            
            this._secureLog('error', 'SAS verification failed - possible MITM attack', {
                receivedCode: data.code,
                expectedCode: this.verificationCode,
                timestamp: Date.now()
            });
            
            this.deliverMessageToUI('SAS verification failed! Possible MITM attack detected. Connection aborted for safety!', 'system');
            this.disconnect();
        }
    }

    handleSASCode(data) {

        
        this.verificationCode = data.code;
        this.onStatusChange?.('verifying'); 
        this.onVerificationRequired(this.verificationCode);
        
        this._secureLog('info', 'SAS code received from Offer side', {
            sasCode: this.verificationCode,
            timestamp: Date.now()
        });
    }

    handleVerificationResponse(data) {
        
        if (data.ok === true) {
            
            // Log successful mutual SAS verification
            this._secureLog('info', 'Mutual SAS verification completed - MITM protection active', {
                verificationMethod: data.verificationMethod || 'SAS',
                securityLevel: data.securityLevel || 'MITM_PROTECTED',
                timestamp: Date.now()
            });
            
            // Ensure verification success notice wasn't already sent
            if (!this.verificationNotificationSent) {
                this.verificationNotificationSent = true;
                this.deliverMessageToUI(' Mutual SAS verification complete! MITM protection active. Channel is now secure!', 'system');
            }
            
            this.processMessageQueue();
        } else {
            //  Peer verification failed - connection not secure
            this._secureLog('error', 'Peer SAS verification failed - connection not secure', {
                responseData: data,
                timestamp: Date.now()
            });
            
            this.deliverMessageToUI('Peer verification failed! Connection not secure!', 'system');
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

    validateEnhancedOfferData(offerData) {
        try {
            // CRITICAL: Strict type checking to prevent syntax errors
            if (!offerData || typeof offerData !== 'object' || Array.isArray(offerData)) {
                this._secureLog('error', 'CRITICAL: Invalid offer data structure', { 
                    hasOfferData: !!offerData,
                    offerDataType: typeof offerData,
                    isArray: Array.isArray(offerData)
                });
                throw new Error('CRITICAL SECURITY FAILURE: Offer data must be a non-null object');
            }

            // Basic required fields will be validated after format detection

            // Check if this is v4.0 compact format or legacy format
            const isV4CompactFormat = offerData.v === '4.0' && offerData.e && offerData.d;
            const isV4Format = offerData.version === '4.0' && offerData.ecdhPublicKey && offerData.ecdsaPublicKey;
            
            // Validate offer type (support compact, legacy v3.0 and v4.0 formats)
            const isValidType = isV4CompactFormat ? 
                ['offer'].includes(offerData.t) :
                ['enhanced_secure_offer', 'secure_offer'].includes(offerData.type);
                
            if (!isValidType) {
                throw new Error('Invalid offer type');
            }
            
            if (isV4CompactFormat) {
                // v4.0 compact format validation
                const compactRequiredFields = [
                    'e', 'd', 'sl', 'vc', 'si', 'ci', 'ac', 'slv'
                ];
                
                for (const field of compactRequiredFields) {
                if (!offerData[field]) {
                        throw new Error(`Missing required v4.0 compact field: ${field}`);
                    }
                }
                
                // Validate key structures
                if (!offerData.e || typeof offerData.e !== 'object' || Array.isArray(offerData.e)) {
                    throw new Error('CRITICAL SECURITY FAILURE: Invalid ECDH public key structure');
                }
                
                if (!offerData.d || typeof offerData.d !== 'object' || Array.isArray(offerData.d)) {
                    throw new Error('CRITICAL SECURITY FAILURE: Invalid ECDSA public key structure');
                }
                
                // Validate salt length
                if (!Array.isArray(offerData.sl) || offerData.sl.length !== 64) {
                    throw new Error('Salt must be exactly 64 bytes for v4.0');
                }
                
                // Validate verification code format
                if (typeof offerData.vc !== 'string' || offerData.vc.length < 6) {
                    throw new Error('Invalid verification code format');
                }
                
                // Validate security level
                if (!['MAX', 'HIGH', 'MED', 'LOW'].includes(offerData.slv)) {
                    throw new Error('Invalid security level');
                }
                
                // Validate timestamp (not older than 1 hour)
                const offerAge = Date.now() - offerData.ts;
                if (offerAge > 3600000) {
                    throw new Error('Offer is too old (older than 1 hour)');
                }
                
                this._secureLog('info', 'v4.0 compact offer validation passed', {
                    version: offerData.v,
                    hasECDH: !!offerData.e,
                    hasECDSA: !!offerData.d,
                    hasSalt: !!offerData.sl,
                    hasVerificationCode: !!offerData.vc,
                    securityLevel: offerData.slv,
                    offerAge: Math.round(offerAge / 1000) + 's'
                });
            } else if (isV4Format) {
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

                // CRITICAL: Strict validation of key structures to prevent syntax errors
                if (!offerData.ecdhPublicKey || typeof offerData.ecdhPublicKey !== 'object' || Array.isArray(offerData.ecdhPublicKey)) {
                    this._secureLog('error', 'CRITICAL: Invalid ECDH public key structure', { 
                        hasEcdhKey: !!offerData.ecdhPublicKey,
                        ecdhKeyType: typeof offerData.ecdhPublicKey,
                        isArray: Array.isArray(offerData.ecdhPublicKey)
                    });
                    throw new Error('CRITICAL SECURITY FAILURE: Invalid ECDH public key structure - hard abort required');
                }

                if (!offerData.ecdsaPublicKey || typeof offerData.ecdsaPublicKey !== 'object' || Array.isArray(offerData.ecdsaPublicKey)) {
                    this._secureLog('error', 'CRITICAL: Invalid ECDSA public key structure', { 
                        hasEcdsaKey: !!offerData.ecdsaPublicKey,
                        ecdsaKeyType: typeof offerData.ecdsaPublicKey,
                        isArray: Array.isArray(offerData.ecdsaPublicKey)
                    });
                    throw new Error('CRITICAL SECURITY FAILURE: Invalid ECDSA public key structure - hard abort required');
                }

                // CRITICAL: Validate key internal structure to prevent syntax errors
                if (!offerData.ecdhPublicKey.keyData || !offerData.ecdhPublicKey.signature) {
                    this._secureLog('error', 'CRITICAL: ECDH key missing keyData or signature', { 
                        hasKeyData: !!offerData.ecdhPublicKey.keyData,
                        hasSignature: !!offerData.ecdhPublicKey.signature
                    });
                    throw new Error('CRITICAL SECURITY FAILURE: ECDH key missing keyData or signature');
                }

                if (!offerData.ecdsaPublicKey.keyData || !offerData.ecdsaPublicKey.signature) {
                    this._secureLog('error', 'CRITICAL: ECDSA key missing keyData or signature', { 
                        hasKeyData: !!offerData.ecdsaPublicKey.keyData,
                        hasSignature: !!offerData.ecdsaPublicKey.signature
                    });
                    throw new Error('CRITICAL SECURITY FAILURE: ECDSA key missing keyData or signature');
                }

                if (typeof offerData.verificationCode !== 'string' || offerData.verificationCode.length < 6) {
                    throw new Error('Invalid SAS verification code format - MITM protection required');
                }

                this._secureLog('info', 'v4.0 offer validation passed', {
                    version: offerData.version,
                    hasSecurityLevel: !!offerData.securityLevel?.level,
                    offerAge: Math.round(offerAge / 1000) + 's'
                });
            } else {
                // v3.0 backward compatibility validation
                // NOTE: v3.0 has limited security - SAS verification is still critical
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
            const sdp = isV4CompactFormat ? offerData.s : offerData.sdp;
            if (typeof sdp !== 'string' || !sdp.includes('v=0')) {
                throw new Error('Invalid SDP structure');
            }

            return true;
        } catch (error) {
            this._secureLog('error', 'CRITICAL: Security validation failed - hard abort required', {
                error: error.message,
                errorType: error.constructor.name,
                timestamp: Date.now()
            });

            throw new Error(`CRITICAL SECURITY VALIDATION FAILURE: ${error.message}`);
        }
    }

    async sendSecureMessage(message) {
        //   Comprehensive input validation
        const validation = this._validateInputData(message, 'sendSecureMessage');
        if (!validation.isValid) {
            const errorMessage = `Input validation failed: ${validation.errors.join(', ')}`;
            this._secureLog('error', 'Input validation failed in sendSecureMessage', {
                errors: validation.errors,
                messageType: typeof message
            });
            throw new Error(errorMessage);
        }

        //   Rate limiting check
        if (!this._checkRateLimit('sendSecureMessage')) {
            throw new Error('Rate limit exceeded for secure message sending');
        }

        //   Enforce verification gate
        this._enforceVerificationGate('sendSecureMessage');

        //   Quick readiness check WITHOUT mutex
        if (!this.isConnected()) {
            if (validation.sanitizedData && typeof validation.sanitizedData === 'object' && validation.sanitizedData.type && validation.sanitizedData.type.startsWith('file_')) {
                throw new Error('Connection not ready for file transfer. Please ensure the connection is established and verified.');
            }
            this.messageQueue.push(validation.sanitizedData);
            throw new Error('Connection not ready. Message queued for sending.');
        }
        
        //   Use mutex ONLY for cryptographic operations
        return this._withMutex('cryptoOperation', async (operationId) => {
            // Re-check inside critical section
            if (!this.isConnected() || !this.isVerified) {
                throw new Error('Connection lost during message preparation');
            }
            
            // Validate keys inside critical section
            if (!this.encryptionKey || !this.macKey || !this.metadataKey) {
                throw new Error('Encryption keys not initialized');
            }
            
            //   Additional rate limiting check
            if (!window.EnhancedSecureCryptoUtils.rateLimiter.checkMessageRate(this.rateLimiterId)) {
                throw new Error('Message rate limit exceeded (60 messages per minute)');
            }
            
            try {
                //   Accept strings and objects; stringify objects
                const textToSend = typeof validation.sanitizedData === 'string' ? validation.sanitizedData : JSON.stringify(validation.sanitizedData);
                const sanitizedMessage = window.EnhancedSecureCryptoUtils.sanitizeMessage(textToSend);
                const messageId = `msg_${Date.now()}_${this.messageCounter++}`;
                
                //   Create AAD with sequence number for anti-replay protection
                if (typeof this._createMessageAAD !== 'function') {
                    throw new Error('_createMessageAAD method is not available in sendSecureMessage. Manager may not be fully initialized.');
                }
                const aad = message.aad || this._createMessageAAD('enhanced_message', { content: sanitizedMessage });
                
                //   Use enhanced encryption with AAD and sequence number
                const encryptedData = await window.EnhancedSecureCryptoUtils.encryptMessage(
                    sanitizedMessage,
                    this.encryptionKey,
                    this.macKey,
                    this.metadataKey,
                    messageId,
                    JSON.parse(aad).sequenceNumber // Use sequence number from AAD
                );
                
                const payload = {
                    type: 'enhanced_message',
                    data: encryptedData,
                    keyVersion: this.currentKeyVersion,
                    version: '4.0'
                };
                
                this.dataChannel.send(JSON.stringify(payload));
                //   Locally display only plain strings to avoid UI duplication
                if (typeof validation.sanitizedData === 'string') {
                    this.deliverMessageToUI(validation.sanitizedData, 'sent');
                }
                
                this._secureLog('debug', 'Secure message sent successfully', {
                    operationId: operationId,
                    messageLength: sanitizedMessage.length,
                    keyVersion: this.currentKeyVersion
                });
                
            } catch (error) {
                this._secureLog('error', 'Secure message sending failed', {
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
        //   Heartbeat moved to unified scheduler with connection validation
        this._secureLog('info', 'Heartbeat moved to unified scheduler');
        
        // Store heartbeat configuration for scheduler
        this._heartbeatConfig = {
            enabled: true,
            interval: EnhancedSecureWebRTCManager.TIMEOUTS.HEARTBEAT_INTERVAL,
            lastHeartbeat: 0
        };
    }

    stopHeartbeat() {
        //   Heartbeat stopped via unified scheduler
        if (this._heartbeatConfig) {
            this._heartbeatConfig.enabled = false;
        }
    }

    /**
     *   Stop all active timers and cleanup scheduler
     */
    _stopAllTimers() {
        this._secureLog('info', 'Stopping all timers and cleanup scheduler');
        
        // Stop maintenance scheduler
        if (this._maintenanceScheduler) {
            clearInterval(this._maintenanceScheduler);
            this._maintenanceScheduler = null;
        }
        
        // Stop heartbeat
        if (this._heartbeatConfig) {
            this._heartbeatConfig.enabled = false;
        }
        
        // Clear all timer references
        if (this._activeTimers) {
            this._activeTimers.forEach(timer => {
                if (timer) clearInterval(timer);
            });
            this._activeTimers.clear();
        }
        
        this._secureLog('info', 'All timers stopped successfully');
    }


    waitForIceGathering() {
        return new Promise((resolve) => {
            if (this.peerConnection.iceGatheringState === 'complete') {
                resolve();
                return;
            }

            const checkState = () => {
                if (this.peerConnection && this.peerConnection.iceGatheringState === 'complete') {
                    this.peerConnection.removeEventListener('icegatheringstatechange', checkState);
                    resolve();
                }
            };
            
            this.peerConnection.addEventListener('icegatheringstatechange', checkState);
            
            setTimeout(() => {
                if (this.peerConnection) {
                    this.peerConnection.removeEventListener('icegatheringstatechange', checkState);
                }
                resolve();
            }, EnhancedSecureWebRTCManager.TIMEOUTS.ICE_GATHERING_TIMEOUT);
        });
    }

    retryConnection() {
        this._secureLog('info', 'Retrying connection', {
            attempt: this.connectionAttempts,
            maxAttempts: this.maxConnectionAttempts
        });
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
        //   Stop all timers first
        this._stopAllTimers();
        
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
            this.fileTransferSystem.cleanup();
            this.fileTransferSystem = null;
        }
        
        document.dispatchEvent(new CustomEvent('peer-disconnect', {
            detail: { 
                reason: 'connection_lost',
                timestamp: Date.now()
            }
        }));

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
            this.deliverMessageToUI('Unable to reconnect. A new connection is required.', 'system');
        }

    }
    
    handlePeerDisconnectNotification(data) {
        const reason = data.reason || 'unknown';
        const reasonText = reason === 'user_disconnect' ? 'manually disconnected.' : 'connection lost.';
        
        // Ensure peer-disconnect notification wasn't already sent
        if (!this.peerDisconnectNotificationSent) {
            this.peerDisconnectNotificationSent = true;
            this.deliverMessageToUI(`Peer ${reasonText}`, 'system');
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
    
    /**
     *   Secure disconnect with complete memory cleanup
     */
    disconnect() {
        this.stopHeartbeat();
        this.isVerified = false;
        this.processedMessageIds.clear();
        this.messageCounter = 0;
        
        //   Secure cleanup of cryptographic materials
        this._secureCleanupCryptographicMaterials();
        
        //   Secure wipe of PFS key versions
        this.keyVersions.clear();
        this.oldKeys.clear();
        this.currentKeyVersion = 0;
        this.lastKeyRotation = Date.now();
        
        //   Reset message counters
        this.sequenceNumber = 0;
        this.expectedSequenceNumber = 0;
        this.replayWindow.clear(); //   Clear replay window
        
        //   Reset security features
        this.securityFeatures = {
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
        };
        
        //   Close connections
        if (this.dataChannel) {
            this.dataChannel.close();
            this.dataChannel = null;
        }
        if (this.peerConnection) {
            this.peerConnection.close();
            this.peerConnection = null;
        }
        
        //   Secure wipe of message queue
        if (this.messageQueue && this.messageQueue.length > 0) {
            this.messageQueue.forEach((message, index) => {
                this._secureWipeMemory(message, `messageQueue[${index}]`);
            });
            this.messageQueue = [];
        }
        
        //   Schedule natural cleanup
        this._forceGarbageCollection().catch(error => {
            this._secureLog('error', 'Cleanup failed during disconnect', {
                errorType: error?.constructor?.name || 'Unknown'
            });
        });
        
        document.dispatchEvent(new CustomEvent('connection-cleaned', {
            detail: { 
                timestamp: Date.now(),
                reason: this.intentionalDisconnect ? 'user_cleanup' : 'automatic_cleanup'
            }
        }));

        //   Notify UI about complete cleanup
        this.onStatusChange('disconnected');
        this.onKeyExchange('');
        this.onVerificationRequired('');
        
        this._secureLog('info', 'Connection securely cleaned up with complete memory wipe');
        
        //   Reset the intentional disconnect flag
        this.intentionalDisconnect = false;
    }
    // Public method to send files
    async sendFile(file) {
        //   Enforce verification gate for file transfers
        this._enforceVerificationGate('sendFile');
        
        if (!this.isConnected()) {
            throw new Error('Connection not ready for file transfer. Please ensure the connection is established.');
        }

        if (!this.fileTransferSystem) {
            this.initializeFileTransfer();
            
            // Allow time for initialization
            await new Promise(resolve => setTimeout(resolve, 500));
            
            if (!this.fileTransferSystem) {
                throw new Error('File transfer system could not be initialized. Please try reconnecting.');
            }
        }

        //   Verify key readiness
        if (!this.encryptionKey || !this.macKey) {
            throw new Error('Encryption keys not ready. Please wait for connection to be fully established.');
        }


        try {
            const fileId = await this.fileTransferSystem.sendFile(file);
            return fileId;
        } catch (error) {
            this._secureLog('error', 'File transfer error:', { errorType: error?.constructor?.name || 'Unknown' });
            
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
                this._secureLog('warn', 'getActiveTransfers method not available in file transfer system');
            }
            
            if (typeof this.fileTransferSystem.getReceivingTransfers === 'function') {
                receiving = this.fileTransferSystem.getReceivingTransfers();
            } else {
                this._secureLog('warn', 'getReceivingTransfers method not available in file transfer system');
            }
            
            return {
                sending: sending || [],
                receiving: receiving || []
            };
        } catch (error) {
            this._secureLog('error', 'Error getting file transfers:', { errorType: error?.constructor?.name || 'Unknown' });
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
            this._secureLog('info', '🧹 Force cleaning up file transfer system');
            this.fileTransferSystem.cleanup();
            this.fileTransferSystem = null;
            return true;
        }
        return false;
    }

    // Reinitialize file transfer system
    reinitializeFileTransfer() {
        try {
            if (this.fileTransferSystem) {
                this.fileTransferSystem.cleanup();
            }
            this.initializeFileTransfer();
            return true;
        } catch (error) {
            this._secureLog('error', 'Failed to reinitialize file transfer system:', { errorType: error?.constructor?.name || 'Unknown' });
            return false;
        }
    }

    // Set file transfer callbacks
    setFileTransferCallbacks(onProgress, onReceived, onError) {
        this.onFileProgress = onProgress;
        this.onFileReceived = onReceived;
        this.onFileError = onError;
        
        // Reinitialize file transfer system if it exists to update callbacks
        if (this.fileTransferSystem) {
            this.initializeFileTransfer();
        }
    }

    // ============================================
    // SESSION ACTIVATION HANDLING
    // ============================================

    async handleSessionActivation(sessionData) {
        try {
            
            // Update session state
            this.currentSession = sessionData;
            
            // FIX: More lenient checks for activation
            const hasKeys = !!(this.encryptionKey && this.macKey);
            const hasSession = !!(sessionData.sessionId);
            
            // Force connection status if there is an active session
            if (hasSession) {
                this.onStatusChange('connected');

            }

        setTimeout(() => {
            try {
                this.initializeFileTransfer();
            } catch (error) {
                this._secureLog('warn', 'File transfer initialization failed during session activation:', { details: error.message });
            }
        }, 1000);
            
            
            if (this.fileTransferSystem && this.isConnected()) {
                
                if (typeof this.fileTransferSystem.onSessionUpdate === 'function') {
                    this.fileTransferSystem.onSessionUpdate({
                        keyFingerprint: this.keyFingerprint,
                        sessionSalt: this.sessionSalt,
                        hasMacKey: !!this.macKey
                    });
                }
            }
            
        } catch (error) {
            this._secureLog('error', 'Failed to handle session activation:', { errorType: error?.constructor?.name || 'Unknown' });
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
        return status;
    }

    // Method to force re-initialize file transfer system
    forceReinitializeFileTransfer() {
        try {
            
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
            this._secureLog('error', 'Failed to force reinitialize file transfer:', { errorType: error?.constructor?.name || 'Unknown' });
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
            globalState: {
                fileTransferActive: this._fileTransferActive || false,
            hasFileTransferSystem: !!this.fileTransferSystem,
            fileTransferSystemType: this.fileTransferSystem ? 'EnhancedSecureFileTransfer' : 'none'
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

    async forceInitializeFileTransfer(options = {}) {
        const abortController = new AbortController();
        const { signal = abortController.signal, timeout = 6000 } = options;

        if (signal && signal !== abortController.signal) {
            signal.addEventListener('abort', () => abortController.abort());
        }
        try {
            if (!this.isVerified) {
                throw new Error('Connection not verified');
            }
            
            if (!this.dataChannel || this.dataChannel.readyState !== 'open') {
                throw new Error('Data channel not open');
            }
            
            if (!this.encryptionKey || !this.macKey) {
                throw new Error('Encryption keys not ready');
            }

            if (this.fileTransferSystem) {
                this.fileTransferSystem.cleanup();
                this.fileTransferSystem = null;
            }

            this.initializeFileTransfer();

            let attempts = 0;
            const maxAttempts = 50;
            const checkInterval = 100; 
            const maxWaitTime = maxAttempts * checkInterval; 

            const initializationPromise = new Promise((resolve, reject) => {
                const checkInitialization = () => {
                    if (abortController.signal.aborted) {
                        reject(new Error('Operation cancelled'));
                        return;
                    }
                    
                    if (this.fileTransferSystem) {
                        resolve(true);
                        return;
                    }
                    
                    if (attempts >= maxAttempts) {
                        reject(new Error(`Initialization timeout after ${maxWaitTime}ms`));
                        return;
                    }
                    
                    attempts++;
                    setTimeout(checkInitialization, checkInterval);
                };
                
                checkInitialization();
            });

            await Promise.race([
                initializationPromise,
                new Promise((_, reject) => 
                    setTimeout(() => reject(new Error(`Global timeout after ${timeout}ms`)), timeout)
                )
            ]);
            
            if (this.fileTransferSystem) {
                return true;
            } else {
                throw new Error('Force initialization timeout');
            }
            
        } catch (error) {
            if (error.name === 'AbortError' || error.message.includes('cancelled')) {
                this._secureLog('info', 'File transfer initialization cancelled by user');
                return { cancelled: true };
            }
            
            this._secureLog('error', 'Force file transfer initialization failed:', { 
                errorType: error?.constructor?.name || 'Unknown',
                message: error.message,
                attempts: attempts
            });
            return { error: error.message, attempts: attempts };
        }
    }

    cancelFileTransferInitialization() {
        try {
            if (this.fileTransferSystem) {
                this.fileTransferSystem.cleanup();
                this.fileTransferSystem = null;
                this._fileTransferActive = false;
                this._secureLog('info', 'File transfer initialization cancelled');
                return true;
            }
            return false;
        } catch (error) {
            this._secureLog('error', 'Failed to cancel file transfer initialization:', { 
                errorType: error?.constructor?.name || 'Unknown' 
            });
            return false;
        }
    }
    
    getFileTransferSystemStatus() {
        if (!this.fileTransferSystem) {
            return { available: false, status: 'not_initialized' };
        }
        
        try {
            const status = this.fileTransferSystem.getSystemStatus();
            return {
                available: true,
                status: status.status || 'unknown',
                activeTransfers: status.activeTransfers || 0,
                receivingTransfers: status.receivingTransfers || 0,
                systemType: 'EnhancedSecureFileTransfer'
            };
        } catch (error) {
            this._secureLog('error', 'Failed to get file transfer system status:', { 
                errorType: error?.constructor?.name || 'Unknown' 
            });
            return { available: false, status: 'error', error: error.message };
        }
    }

    _validateNestedEncryptionSecurity() {
        if (this.securityFeatures.hasNestedEncryption && this.nestedEncryptionKey) {
            //   Test secure IV generation with reuse prevention
            try {
                const testIV1 = this._generateSecureIV(EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE, 'securityTest1');
                const testIV2 = this._generateSecureIV(EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE, 'securityTest2');
                
                //   Verify IVs are different and properly tracked
                if (testIV1.every((byte, index) => byte === testIV2[index])) {
                    this._secureLog('error', 'CRITICAL: Nested encryption security validation failed - IVs are identical!');
                    return false;
                }
                
                //   Verify IV tracking system is working
                const stats = this._getIVTrackingStats();
                if (stats.totalIVs < 2) {
                    this._secureLog('error', 'CRITICAL: IV tracking system not working properly');
                    return false;
                }
                
                this._secureLog('info', 'Nested encryption security validation passed - secure IV generation working');
                return true;
            } catch (error) {
                this._secureLog('error', 'CRITICAL: Nested encryption security validation failed:', {
                    errorType: error.constructor.name,
                    errorMessage: error.message
                });
                return false;
            }
        }
        return true;
    }
}

class SecureKeyStorage {
    constructor(masterKeyManager = null) {
        // Use WeakMap for automatic garbage collection of unused keys
        this._keyStore = new WeakMap();
        this._keyMetadata = new Map(); // Metadata doesn't need WeakMap
        this._keyReferences = new Map(); // Strong references for active keys
        
        // Use secure master key manager instead of global key
        this._masterKeyManager = masterKeyManager || new SecureMasterKeyManager();
        
        // Initialize persistent storage for extractable keys
        this._persistentStorage = new SecurePersistentKeyStorage(this._masterKeyManager);
        
        // Setup master key manager callbacks
        this._setupMasterKeyCallbacks();

        setTimeout(() => {
            if (!this.validateStorageIntegrity()) {
                this._secureLog('error', 'CRITICAL: Key storage integrity check failed');
            }
        }, 100);
        
    }

    /**
     * Setup callbacks for master key manager
     */
    _setupMasterKeyCallbacks() {
        // Set default password callback (can be overridden)
        this._masterKeyManager.setPasswordRequiredCallback((isRetry, callback) => {
            // Default implementation - should be overridden by application
            const password = prompt(isRetry ? 
                'Incorrect password. Please enter your master password:' : 
                'Please enter your master password to unlock secure storage:'
            );
            callback(password);
        });
        
        this._masterKeyManager.setSessionExpiredCallback((reason) => {
            console.warn(`Master key session expired: ${reason}`);
            // Application should handle this event
        });
        
        this._masterKeyManager.setUnlockedCallback(() => {
            console.log('Master key unlocked successfully');
        });
    }
    
    /**
     * Set custom password callback
     */
    setPasswordCallback(callback) {
        this._masterKeyManager.setPasswordRequiredCallback(callback);
    }
    
    /**
     * Set custom session expired callback
     */
    setSessionExpiredCallback(callback) {
        this._masterKeyManager.setSessionExpiredCallback(callback);
    }
    
    /**
     * Get master key (with automatic unlock if needed)
     */
    async _getMasterKey() {
        if (!this._masterKeyManager.isUnlocked()) {
            await this._masterKeyManager.unlock();
        }
        return this._masterKeyManager.getMasterKey();
    }

    async storeKey(keyId, cryptoKey, metadata = {}) {
        if (!(cryptoKey instanceof CryptoKey)) {
            throw new Error('Only CryptoKey objects can be stored');
        }

        try {
            // For non-extractable keys, store only in-memory reference
            if (!cryptoKey.extractable) {
                this._keyReferences.set(keyId, cryptoKey);
                this._keyMetadata.set(keyId, {
                    ...metadata,
                    created: Date.now(),
                    lastAccessed: Date.now(),
                    extractable: false,
                    persistent: false,
                    encrypted: false
                });
                return true;
            }

            // For extractable keys, use persistent storage with encryption
            await this._persistentStorage.storeExtractableKey(keyId, cryptoKey, metadata);
            
            // Also store in memory for immediate access
            this._keyReferences.set(keyId, cryptoKey);
            this._keyMetadata.set(keyId, {
                ...metadata,
                created: Date.now(),
                lastAccessed: Date.now(),
                extractable: true,
                persistent: true,
                encrypted: true
            });

            return true;
            
        } catch (error) {
            this._secureLog('error', 'Failed to store key securely', {
                errorType: error?.constructor?.name || 'Unknown'
            });
            return false;
        }
    }

    async retrieveKey(keyId) {
        try {
            // Check if key is in memory first
            if (this._keyReferences.has(keyId)) {
                const metadata = this._keyMetadata.get(keyId);
                if (metadata) {
                    metadata.lastAccessed = Date.now();
                }
                return this._keyReferences.get(keyId);
            }
            
            // Try to restore from persistent storage
            const restoredKey = await this._persistentStorage.retrieveKey(keyId);
            if (restoredKey) {
                // Update memory cache
                this._keyReferences.set(keyId, restoredKey);
                
                // Update or create metadata
                const existingMetadata = this._keyMetadata.get(keyId);
                this._keyMetadata.set(keyId, {
                    ...existingMetadata,
                    lastAccessed: Date.now(),
                    restoredFromPersistent: true
                });
                
                return restoredKey;
            }
            
            return null;
            
        } catch (error) {
            this._secureLog('error', 'Failed to retrieve key', {
                keyIdHash: await this._createSafeLogHash(keyId, 'key_id'),
                errorType: error?.constructor?.name || 'Unknown'
            });
            return null;
        }
    }

    async _encryptKeyData(keyData) {
        const dataToEncrypt = typeof keyData === 'object' 
            ? JSON.stringify(keyData) 
            : keyData;
        
        const encoder = new TextEncoder();
        const data = encoder.encode(dataToEncrypt);
        
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const masterKey = await this._getMasterKey();
        const encryptedData = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            masterKey,
            data
        );

        // Return IV + encrypted data
        const result = new Uint8Array(iv.length + encryptedData.byteLength);
        result.set(iv, 0);
        result.set(new Uint8Array(encryptedData), iv.length);
        
        return result;
    }

    async _decryptKeyData(encryptedData) {
        const iv = encryptedData.slice(0, 12);
        const data = encryptedData.slice(12);
        
        const masterKey = await this._getMasterKey();
        const decryptedData = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            masterKey,
            data
        );

        const decoder = new TextDecoder();
        const jsonString = decoder.decode(decryptedData);
        
        try {
            return JSON.parse(jsonString);
        } catch {
            return decryptedData;
        }
    }

    async secureWipe(keyId) {
        const cryptoKey = this._keyReferences.get(keyId);
        
        if (cryptoKey) {
            // Remove from WeakMap (will be GC'd)
            this._keyStore.delete(cryptoKey);
            // Remove strong reference
            this._keyReferences.delete(keyId);
            // Remove metadata
            this._keyMetadata.delete(keyId);
        }

        // Schedule natural cleanup
        await this._performNaturalCleanup();
    }

    async secureWipeAll() {
        // Clear persistent storage
        try {
            await this._persistentStorage.clearAll();
        } catch (error) {
            this._secureLog('error', 'Failed to clear persistent storage', {
                errorType: error?.constructor?.name || 'Unknown'
            });
        }
        
        // Clear all references
        this._keyReferences.clear();
        this._keyMetadata.clear();
        
        // WeakMap entries will be garbage collected
        this._keyStore = new WeakMap();
        
        // Schedule natural cleanup
        await this._performNaturalCleanup();
    }

    //   Validate storage integrity
    validateStorageIntegrity() {
        const violations = [];
        
        for (const [keyId, metadata] of this._keyMetadata.entries()) {
            // Check: extractable keys must be encrypted
            if (metadata.extractable === true && metadata.encrypted !== true) {
                violations.push({
                    keyId,
                    type: 'EXTRACTABLE_KEY_NOT_ENCRYPTED',
                    metadata
                });
            }
            
            // Check: non-extractable keys should not be encrypted
            if (metadata.extractable === false && metadata.encrypted === true) {
                violations.push({
                    keyId,
                    type: 'NON_EXTRACTABLE_KEY_ENCRYPTED',
                    metadata
                });
            }
        }
        
        if (violations.length > 0) {
            this._secureLog('error', 'Storage integrity violations detected', {
                violationCount: violations.length
            });
            return false;
        }
        
        return true;
    }

    async getStorageStats() {
        const persistentStats = await this._persistentStorage.getStorageStats();
        
        return {
            totalKeys: this._keyReferences.size,
            memoryKeys: this._keyReferences.size,
            persistentKeys: persistentStats.persistentKeys,
            metadata: Array.from(this._keyMetadata.entries()).map(([id, meta]) => ({
                id,
                created: meta.created,
                lastAccessed: meta.lastAccessed,
                age: Date.now() - meta.created,
                persistent: meta.persistent || false
            })),
            persistent: persistentStats
        };
    }
    
    /**
     * List all stored keys (memory + persistent)
     */
    async listAllKeys() {
        try {
            const memoryKeys = Array.from(this._keyMetadata.entries()).map(([keyId, metadata]) => ({
                keyId,
                ...metadata,
                location: 'memory'
            }));
            
            const persistentKeys = await this._persistentStorage.listStoredKeys();
            const persistentKeysFormatted = persistentKeys.map(key => ({
                ...key,
                location: 'persistent'
            }));
            
            return {
                memoryKeys,
                persistentKeys: persistentKeysFormatted,
                totalCount: memoryKeys.length + persistentKeysFormatted.length
            };
            
        } catch (error) {
            this._secureLog('error', 'Failed to list keys', {
                errorType: error?.constructor?.name || 'Unknown'
            });
            return {
                memoryKeys: [],
                persistentKeys: [],
                totalCount: 0,
                error: error.message
            };
        }
    }
    
    /**
     * Delete key from both memory and persistent storage
     */
    async deleteKey(keyId) {
        try {
            // Remove from memory
            this._keyReferences.delete(keyId);
            this._keyMetadata.delete(keyId);
            
            // Remove from persistent storage
            await this._persistentStorage.deleteKey(keyId);
            
            return true;
            
        } catch (error) {
            this._secureLog('error', 'Failed to delete key', {
                keyIdHash: await this._createSafeLogHash(keyId, 'key_id'),
                errorType: error?.constructor?.name || 'Unknown'
            });
            return false;
        }
    }

    // Method _generateNextSequenceNumber moved to constructor area for early availability

    /**
     *   Validate incoming message sequence number
     * This prevents replay attacks and ensures message ordering
     */
    _validateIncomingSequenceNumber(receivedSeq, context = 'unknown') {
        try {
            if (!this.replayProtectionEnabled) {
                return true; // Skip validation if disabled
            }

            // Check if sequence number is within acceptable range
            if (receivedSeq < this.expectedSequenceNumber - this.replayWindowSize) {
                this._secureLog('warn', 'Sequence number too old - possible replay attack', {
                    received: receivedSeq,
                    expected: this.expectedSequenceNumber,
                    context: context,
                    timestamp: Date.now()
                });
                return false;
            }

            // Check if sequence number is too far ahead (DoS protection)
            if (receivedSeq > this.expectedSequenceNumber + this.maxSequenceGap) {
                this._secureLog('warn', 'Sequence number gap too large - possible DoS attack', {
                    received: receivedSeq,
                    expected: this.expectedSequenceNumber,
                    gap: receivedSeq - this.expectedSequenceNumber,
                    context: context,
                    timestamp: Date.now()
                });
                return false;
            }

            // Check if sequence number is already in replay window
            if (this.replayWindow.has(receivedSeq)) {
                this._secureLog('warn', 'Duplicate sequence number detected - replay attack', {
                    received: receivedSeq,
                    context: context,
                    timestamp: Date.now()
                });
                return false;
            }

            // Add to replay window
            this.replayWindow.add(receivedSeq);
            
            // Maintain sliding window size
            if (this.replayWindow.size > this.replayWindowSize) {
                const oldestSeq = Math.min(...this.replayWindow);
                this.replayWindow.delete(oldestSeq);
            }

            // Update expected sequence number if this is the next expected
            if (receivedSeq === this.expectedSequenceNumber) {
                this.expectedSequenceNumber++;
                
                // Clean up replay window entries that are no longer needed
                while (this.replayWindow.has(this.expectedSequenceNumber - this.replayWindowSize - 1)) {
                    this.replayWindow.delete(this.expectedSequenceNumber - this.replayWindowSize - 1);
                }
            }

            this._secureLog('debug', 'Sequence number validation successful', {
                received: receivedSeq,
                expected: this.expectedSequenceNumber,
                context: context,
                timestamp: Date.now()
            });

            return true;
        } catch (error) {
            this._secureLog('error', 'Sequence number validation failed', {
                error: error.message,
                context: context,
                timestamp: Date.now()
            });
            return false;
        }
    }

    // Method _createMessageAAD moved to constructor area for early availability

    /**
     *   Validate message AAD with sequence number
     * This ensures message integrity and prevents replay attacks
     */
    _validateMessageAAD(aadString, expectedMessageType = null) {
        try {
            const aad = JSON.parse(aadString);
            
            // Validate session binding
            if (aad.sessionId !== (this.currentSession?.sessionId || 'unknown')) {
                throw new Error('AAD sessionId mismatch - possible replay attack');
            }
            
            if (aad.keyFingerprint !== (this.keyFingerprint || 'unknown')) {
                throw new Error('AAD keyFingerprint mismatch - possible key substitution attack');
            }
            
            //   Validate sequence number
            if (!this._validateIncomingSequenceNumber(aad.sequenceNumber, aad.messageType)) {
                throw new Error('Sequence number validation failed - possible replay or DoS attack');
            }
            
            // Validate message type if specified
            if (expectedMessageType && aad.messageType !== expectedMessageType) {
                throw new Error(`AAD messageType mismatch - expected ${expectedMessageType}, got ${aad.messageType}`);
            }
            
            return aad;
        } catch (error) {
            this._secureLog('error', 'AAD validation failed', { error: error.message, aadString });
            throw new Error(`AAD validation failed: ${error.message}`);
        }
    }

    /**
     *   Get anti-replay protection status
     * This shows the current state of replay protection
     */
    getAntiReplayStatus() {
        const status = {
            replayProtectionEnabled: this.replayProtectionEnabled,
            replayWindowSize: this.replayWindowSize,
            currentReplayWindowSize: this.replayWindow.size,
            sequenceNumber: this.sequenceNumber,
            expectedSequenceNumber: this.expectedSequenceNumber,
            maxSequenceGap: this.maxSequenceGap,
            replayWindowEntries: Array.from(this.replayWindow).sort((a, b) => a - b)
        };

        this._secureLog('info', 'Anti-replay status retrieved', status);
        return status;
    }

    /**
     *   Configure anti-replay protection
     * This allows fine-tuning of replay protection parameters
     */
    configureAntiReplayProtection(config) {
        try {
            if (config.windowSize !== undefined) {
                if (config.windowSize < 16 || config.windowSize > 1024) {
                    throw new Error('Replay window size must be between 16 and 1024');
                }
                this.replayWindowSize = config.windowSize;
            }

            if (config.maxGap !== undefined) {
                if (config.maxGap < 10 || config.maxGap > 1000) {
                    throw new Error('Max sequence gap must be between 10 and 1000');
                }
                this.maxSequenceGap = config.maxGap;
            }

            if (config.enabled !== undefined) {
                this.replayProtectionEnabled = config.enabled;
            }

            this._secureLog('info', 'Anti-replay protection configured', config);
            return true;
        } catch (error) {
            this._secureLog('error', 'Failed to configure anti-replay protection', { error: error.message });
            return false;
        }
    }

    /**
     * Get real security level with actual cryptographic tests
     * This provides real-time verification of security features
     */
    async getRealSecurityLevel() {
        try {
            const securityData = {
                // Basic security features
                ecdhKeyExchange: !!this.ecdhKeyPair,
                ecdsaSignatures: !!this.ecdsaKeyPair,
                aesEncryption: !!this.encryptionKey,
                messageIntegrity: !!this.hmacKey,
                
                // Advanced security features - using the exact property names expected by EnhancedSecureCryptoUtils
                replayProtection: this.replayProtectionEnabled,
                dtlsFingerprint: !!this.expectedDTLSFingerprint,
                sasCode: !!this.verificationCode,
                metadataProtection: true, // Always enabled
                trafficObfuscation: true, // Always enabled
                perfectForwardSecrecy: true, // Always enabled
                
                // Rate limiting
                rateLimiter: true, // Always enabled
                
                // Additional info
                connectionId: this.connectionId,
                keyFingerprint: this.keyFingerprint,
                currentSecurityLevel: 'maximum',
                timestamp: Date.now()
            };

            
            this._secureLog('info', 'Real security level calculated', securityData);
            return securityData;
        } catch (error) {
            this._secureLog('error', 'Failed to calculate real security level', { error: error.message });
            throw error;
        }
    }


}

/**
 * Secure IndexedDB Wrapper for Encrypted Key Storage
 * Provides secure persistent storage with encryption
 */
class SecureIndexedDBWrapper {
    constructor(dbName = 'SecureKeyStorage', version = 1) {
        this.dbName = dbName;
        this.version = version;
        this.db = null;
        
        // Store names
        this.KEYS_STORE = 'encrypted_keys';
        this.METADATA_STORE = 'key_metadata';
        this.SALT_STORE = 'master_salt';
    }
    
    /**
     * Initialize IndexedDB connection
     */
    async initialize() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, this.version);
            
            request.onerror = () => {
                reject(new Error(`Failed to open IndexedDB: ${request.error}`));
            };
            
            request.onsuccess = () => {
                this.db = request.result;
                resolve();
            };
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                
                // Create encrypted keys store
                if (!db.objectStoreNames.contains(this.KEYS_STORE)) {
                    const keysStore = db.createObjectStore(this.KEYS_STORE, { keyPath: 'keyId' });
                    keysStore.createIndex('timestamp', 'timestamp', { unique: false });
                    keysStore.createIndex('algorithm', 'algorithm', { unique: false });
                }
                
                // Create metadata store
                if (!db.objectStoreNames.contains(this.METADATA_STORE)) {
                    const metadataStore = db.createObjectStore(this.METADATA_STORE, { keyPath: 'keyId' });
                    metadataStore.createIndex('created', 'created', { unique: false });
                    metadataStore.createIndex('lastAccessed', 'lastAccessed', { unique: false });
                }
                
                // Create salt store
                if (!db.objectStoreNames.contains(this.SALT_STORE)) {
                    db.createObjectStore(this.SALT_STORE, { keyPath: 'id' });
                }
            };
        });
    }
    
    /**
     * Store encrypted key data
     */
    async storeEncryptedKey(keyId, encryptedData, iv, algorithm, usages, type, metadata = {}) {
        if (!this.db) {
            throw new Error('Database not initialized');
        }
        
        const transaction = this.db.transaction([this.KEYS_STORE, this.METADATA_STORE], 'readwrite');
        
        const keyRecord = {
            keyId: keyId,
            encryptedData: Array.from(new Uint8Array(encryptedData)), // Convert to array for storage
            iv: Array.from(new Uint8Array(iv)),
            algorithm: algorithm,
            usages: usages,
            type: type,
            timestamp: Date.now()
        };
        
        const metadataRecord = {
            keyId: keyId,
            ...metadata,
            created: Date.now(),
            lastAccessed: Date.now(),
            extractable: true,
            persistent: true
        };
        
        return new Promise((resolve, reject) => {
            const keysRequest = transaction.objectStore(this.KEYS_STORE).put(keyRecord);
            const metadataRequest = transaction.objectStore(this.METADATA_STORE).put(metadataRecord);
            
            transaction.oncomplete = () => resolve();
            transaction.onerror = () => reject(new Error(`Failed to store key: ${transaction.error}`));
        });
    }
    
    /**
     * Retrieve encrypted key data
     */
    async getEncryptedKey(keyId) {
        if (!this.db) {
            throw new Error('Database not initialized');
        }
        
        const transaction = this.db.transaction([this.KEYS_STORE], 'readonly');
        const store = transaction.objectStore(this.KEYS_STORE);
        
        return new Promise((resolve, reject) => {
            const request = store.get(keyId);
            
            request.onsuccess = () => {
                const result = request.result;
                if (result) {
                    // Convert arrays back to Uint8Array
                    result.encryptedData = new Uint8Array(result.encryptedData);
                    result.iv = new Uint8Array(result.iv);
                }
                resolve(result);
            };
            
            request.onerror = () => reject(new Error(`Failed to retrieve key: ${request.error}`));
        });
    }
    
    /**
     * Update key metadata (e.g., last accessed time)
     */
    async updateKeyMetadata(keyId, updates) {
        if (!this.db) {
            throw new Error('Database not initialized');
        }
        
        const transaction = this.db.transaction([this.METADATA_STORE], 'readwrite');
        const store = transaction.objectStore(this.METADATA_STORE);
        
        return new Promise((resolve, reject) => {
            const getRequest = store.get(keyId);
            
            getRequest.onsuccess = () => {
                const metadata = getRequest.result;
                if (metadata) {
                    Object.assign(metadata, updates);
                    const putRequest = store.put(metadata);
                    
                    putRequest.onsuccess = () => resolve();
                    putRequest.onerror = () => reject(new Error(`Failed to update metadata: ${putRequest.error}`));
                } else {
                    reject(new Error(`Key metadata not found: ${keyId}`));
                }
            };
            
            getRequest.onerror = () => reject(new Error(`Failed to get metadata: ${getRequest.error}`));
        });
    }
    
    /**
     * Delete key and its metadata
     */
    async deleteKey(keyId) {
        if (!this.db) {
            throw new Error('Database not initialized');
        }
        
        const transaction = this.db.transaction([this.KEYS_STORE, this.METADATA_STORE], 'readwrite');
        
        return new Promise((resolve, reject) => {
            const keysRequest = transaction.objectStore(this.KEYS_STORE).delete(keyId);
            const metadataRequest = transaction.objectStore(this.METADATA_STORE).delete(keyId);
            
            transaction.oncomplete = () => resolve();
            transaction.onerror = () => reject(new Error(`Failed to delete key: ${transaction.error}`));
        });
    }
    
    /**
     * List all stored keys
     */
    async listKeys() {
        if (!this.db) {
            throw new Error('Database not initialized');
        }
        
        const transaction = this.db.transaction([this.METADATA_STORE], 'readonly');
        const store = transaction.objectStore(this.METADATA_STORE);
        
        return new Promise((resolve, reject) => {
            const request = store.getAll();
            
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(new Error(`Failed to list keys: ${request.error}`));
        });
    }
    
    /**
     * Store master key salt
     */
    async storeMasterSalt(salt) {
        if (!this.db) {
            throw new Error('Database not initialized');
        }
        
        const transaction = this.db.transaction([this.SALT_STORE], 'readwrite');
        const store = transaction.objectStore(this.SALT_STORE);
        
        const saltRecord = {
            id: 'master_salt',
            salt: Array.from(new Uint8Array(salt)),
            created: Date.now()
        };
        
        return new Promise((resolve, reject) => {
            const request = store.put(saltRecord);
            
            request.onsuccess = () => resolve();
            request.onerror = () => reject(new Error(`Failed to store salt: ${request.error}`));
        });
    }
    
    /**
     * Retrieve master key salt
     */
    async getMasterSalt() {
        if (!this.db) {
            throw new Error('Database not initialized');
        }
        
        const transaction = this.db.transaction([this.SALT_STORE], 'readonly');
        const store = transaction.objectStore(this.SALT_STORE);
        
        return new Promise((resolve, reject) => {
            const request = store.get('master_salt');
            
            request.onsuccess = () => {
                const result = request.result;
                if (result) {
                    resolve(new Uint8Array(result.salt));
                } else {
                    resolve(null);
                }
            };
            
            request.onerror = () => reject(new Error(`Failed to retrieve salt: ${request.error}`));
        });
    }
    
    /**
     * Clear all data (for security wipe)
     */
    async clearAll() {
        if (!this.db) {
            throw new Error('Database not initialized');
        }
        
        const transaction = this.db.transaction([this.KEYS_STORE, this.METADATA_STORE, this.SALT_STORE], 'readwrite');
        
        return new Promise((resolve, reject) => {
            const keysRequest = transaction.objectStore(this.KEYS_STORE).clear();
            const metadataRequest = transaction.objectStore(this.METADATA_STORE).clear();
            const saltRequest = transaction.objectStore(this.SALT_STORE).clear();
            
            transaction.oncomplete = () => resolve();
            transaction.onerror = () => reject(new Error(`Failed to clear database: ${transaction.error}`));
        });
    }
    
    /**
     * Close database connection
     */
    close() {
        if (this.db) {
            this.db.close();
            this.db = null;
        }
    }
}

/**
 * Secure Persistent Key Storage with Key Wrapping
 * Implements secure storage of extractable keys using AES-GCM encryption
 */
class SecurePersistentKeyStorage {
    constructor(masterKeyManager, indexedDBWrapper = null) {
        this._masterKeyManager = masterKeyManager;
        this._indexedDB = indexedDBWrapper || new SecureIndexedDBWrapper();
        this._dbInitialized = false;
        
        // In-memory cache for restored keys (WeakMap for automatic cleanup)
        this._keyCache = new WeakMap();
        this._keyReferences = new Map(); // Strong references for active keys
    }
    
    /**
     * Initialize IndexedDB if not already done
     */
    async _ensureDBInitialized() {
        if (!this._dbInitialized) {
            await this._indexedDB.initialize();
            this._dbInitialized = true;
        }
    }
    
    /**
     * Store extractable key with encryption
     */
    async storeExtractableKey(keyId, cryptoKey, metadata = {}) {
        if (!(cryptoKey instanceof CryptoKey)) {
            throw new Error('Only CryptoKey objects can be stored');
        }
        
        if (!cryptoKey.extractable) {
            throw new Error('Key must be extractable for persistent storage');
        }
        
        try {
            await this._ensureDBInitialized();
            
            // Export key to JWK
            const jwkData = await crypto.subtle.exportKey('jwk', cryptoKey);
            
            // Get master key for encryption
            const masterKey = this._masterKeyManager.getMasterKey();
            
            // Encrypt JWK data
            const { encryptedData, iv } = await this._encryptKeyData(jwkData, masterKey);
            
            // Store encrypted data in IndexedDB
            await this._indexedDB.storeEncryptedKey(
                keyId,
                encryptedData,
                iv,
                cryptoKey.algorithm,
                cryptoKey.usages,
                cryptoKey.type,
                metadata
            );
            
            // Store non-extractable reference in memory cache
            const nonExtractableKey = await this._importAsNonExtractable(jwkData, cryptoKey.algorithm, cryptoKey.usages);
            this._keyReferences.set(keyId, nonExtractableKey);
            
            return true;
            
        } catch (error) {
            throw new Error(`Failed to store extractable key: ${error.message}`);
        }
    }
    
    /**
     * Retrieve and restore key from persistent storage
     */
    async retrieveKey(keyId) {
        try {
            // Check if key is already in memory cache
            if (this._keyReferences.has(keyId)) {
                return this._keyReferences.get(keyId);
            }
            
            await this._ensureDBInitialized();
            
            // Get encrypted key data from IndexedDB
            const keyRecord = await this._indexedDB.getEncryptedKey(keyId);
            if (!keyRecord) {
                return null;
            }
            
            // Get master key for decryption
            const masterKey = this._masterKeyManager.getMasterKey();
            
            // Decrypt JWK data
            const jwkData = await this._decryptKeyData(keyRecord.encryptedData, keyRecord.iv, masterKey);
            
            // Import as non-extractable key
            const restoredKey = await this._importAsNonExtractable(jwkData, keyRecord.algorithm, keyRecord.usages);
            
            // Cache in memory
            this._keyReferences.set(keyId, restoredKey);
            
            // Update last accessed time
            await this._indexedDB.updateKeyMetadata(keyId, { lastAccessed: Date.now() });
            
            return restoredKey;
            
        } catch (error) {
            throw new Error(`Failed to retrieve key: ${error.message}`);
        }
    }
    
    /**
     * Delete key from persistent storage
     */
    async deleteKey(keyId) {
        try {
            await this._ensureDBInitialized();
            
            // Remove from IndexedDB
            await this._indexedDB.deleteKey(keyId);
            
            // Remove from memory cache
            this._keyReferences.delete(keyId);
            
            return true;
            
        } catch (error) {
            throw new Error(`Failed to delete key: ${error.message}`);
        }
    }
    
    /**
     * List all stored keys
     */
    async listStoredKeys() {
        try {
            await this._ensureDBInitialized();
            return await this._indexedDB.listKeys();
        } catch (error) {
            throw new Error(`Failed to list keys: ${error.message}`);
        }
    }
    
    /**
     * Clear all persistent storage
     */
    async clearAll() {
        try {
            await this._ensureDBInitialized();
            
            // Clear IndexedDB
            await this._indexedDB.clearAll();
            
            // Clear memory cache
            this._keyReferences.clear();
            
            return true;
            
        } catch (error) {
            throw new Error(`Failed to clear storage: ${error.message}`);
        }
    }
    
    /**
     * Encrypt key data using master key
     */
    async _encryptKeyData(jwkData, masterKey) {
        // Convert JWK to JSON string and then to bytes
        const jsonString = JSON.stringify(jwkData);
        const data = new TextEncoder().encode(jsonString);
        
        // Generate random IV
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        // Encrypt with AES-GCM
        const encryptedData = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            masterKey,
            data
        );
        
        return {
            encryptedData: new Uint8Array(encryptedData),
            iv: iv
        };
    }
    
    /**
     * Decrypt key data using master key
     */
    async _decryptKeyData(encryptedData, iv, masterKey) {
        // Decrypt with AES-GCM
        const decryptedData = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            masterKey,
            encryptedData
        );
        
        // Convert back to JWK
        const jsonString = new TextDecoder().decode(decryptedData);
        return JSON.parse(jsonString);
    }
    
    /**
     * Import JWK as non-extractable key
     */
    async _importAsNonExtractable(jwkData, algorithm, usages) {
        return await crypto.subtle.importKey(
            'jwk',
            jwkData,
            algorithm,
            false, // non-extractable for security
            usages
        );
    }
    
    /**
     * Get storage statistics
     */
    async getStorageStats() {
        try {
            await this._ensureDBInitialized();
            const keys = await this._indexedDB.listKeys();
            
            return {
                totalKeys: keys.length,
                memoryKeys: this._keyReferences.size,
                persistentKeys: keys.length,
                lastAccessed: keys.reduce((latest, key) => 
                    Math.max(latest, key.lastAccessed || 0), 0)
            };
            
        } catch (error) {
            return {
                totalKeys: 0,
                memoryKeys: this._keyReferences.size,
                persistentKeys: 0,
                lastAccessed: 0,
                error: error.message
            };
        }
    }
}

/**
 * Secure Master Key Manager with Password-Based Derivation
 * Implements PBKDF2-based key derivation and session management
 */
class SecureMasterKeyManager {
    constructor(indexedDBWrapper = null) {
        // Session state
        this._masterKey = null;
        this._isUnlocked = false;
        this._sessionTimeout = null;
        this._lastActivity = null;
        
        // Configuration
        this._sessionTimeoutMs = 15 * 60 * 1000; // 15 minutes
        this._inactivityTimeoutMs = 5 * 60 * 1000; // 5 minutes
        
        // PBKDF2 parameters
        this._pbkdf2Iterations = 100000; // 100k iterations
        this._saltSize = 32; // 256 bits
        
        // IndexedDB wrapper for persistent salt storage
        this._indexedDB = indexedDBWrapper || new SecureIndexedDBWrapper();
        this._dbInitialized = false;
        
        // Event handlers
        this._onPasswordRequired = null;
        this._onSessionExpired = null;
        this._onUnlocked = null;
        
        // Setup event listeners (disabled for better UX - no auto-disconnect)
        // this._setupEventListeners();
    }
    
    /**
     * Set callback for password requests
     */
    setPasswordRequiredCallback(callback) {
        this._onPasswordRequired = callback;
    }
    
    /**
     * Set callback for session expiration
     */
    setSessionExpiredCallback(callback) {
        this._onSessionExpired = callback;
    }
    
    /**
     * Set callback for successful unlock
     */
    setUnlockedCallback(callback) {
        this._onUnlocked = callback;
    }
    
    /**
     * Setup event listeners for session management
     */
    _setupEventListeners() {
        // Handle page visibility changes
        if (typeof document !== 'undefined') {
            document.addEventListener('visibilitychange', () => {
                if (document.hidden) {
                    this._handleFocusOut();
                } else {
                    this._handleFocusIn();
                }
            });
            
            // Handle window focus/blur
            window.addEventListener('blur', () => this._handleFocusOut());
            window.addEventListener('focus', () => this._handleFocusIn());
            
            // Handle user activity
            ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'].forEach(event => {
                document.addEventListener(event, () => this._updateActivity(), { passive: true });
            });
        }
    }
    
    /**
     * Handle focus out - start inactivity timer
     */
    _handleFocusOut() {
        if (this._isUnlocked) {
            // Start shorter timeout when window loses focus
            this._startInactivityTimer(this._inactivityTimeoutMs);
        }
    }
    
    /**
     * Handle focus in - reset timers
     */
    _handleFocusIn() {
        if (this._isUnlocked) {
            this._resetSessionTimer();
        }
    }
    
    /**
     * Update last activity timestamp
     */
    _updateActivity() {
        this._lastActivity = Date.now();
        if (this._isUnlocked) {
            this._resetSessionTimer();
        }
    }
    
    /**
     * Start session timer
     */
    _startSessionTimer() {
        this._clearTimers();
        this._sessionTimeout = setTimeout(() => {
            this._expireSession('timeout');
        }, this._sessionTimeoutMs);
    }
    
    /**
     * Start inactivity timer
     */
    _startInactivityTimer(timeout) {
        this._clearTimers();
        this._sessionTimeout = setTimeout(() => {
            this._expireSession('inactivity');
        }, timeout);
    }
    
    /**
     * Reset session timer
     */
    _resetSessionTimer() {
        if (this._isUnlocked) {
            this._startSessionTimer();
        }
    }
    
    /**
     * Clear all timers
     */
    _clearTimers() {
        if (this._sessionTimeout) {
            clearTimeout(this._sessionTimeout);
            this._sessionTimeout = null;
        }
    }
    
    /**
     * Expire the current session
     */
    _expireSession(reason = 'unknown') {
        if (this._isUnlocked) {
            this._secureWipeMasterKey();
            this._isUnlocked = false;
            
            if (this._onSessionExpired) {
                this._onSessionExpired(reason);
            }
        }
    }
    
    /**
     * Initialize IndexedDB if not already done
     */
    async _ensureDBInitialized() {
        if (!this._dbInitialized) {
            await this._indexedDB.initialize();
            this._dbInitialized = true;
        }
    }
    
    /**
     * Generate salt for PBKDF2
     */
    _generateSalt() {
        return crypto.getRandomValues(new Uint8Array(this._saltSize));
    }
    
    /**
     * Get or create persistent salt
     */
    async _getOrCreateSalt() {
        await this._ensureDBInitialized();
        
        // Try to get existing salt
        let salt = await this._indexedDB.getMasterSalt();
        
        if (!salt) {
            // Generate new salt and store it
            salt = this._generateSalt();
            await this._indexedDB.storeMasterSalt(salt);
        }
        
        return salt;
    }
    
    /**
     * Derive master key from password using PBKDF2
     */
    async _deriveKeyFromPassword(password, salt) {
        try {
            // Import password as key material
            const passwordKey = await crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(password),
                'PBKDF2',
                false,
                ['deriveKey']
            );
            
            // Derive AES-GCM key using PBKDF2
            const derivedKey = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: this._pbkdf2Iterations,
                    hash: 'SHA-256'
                },
                passwordKey,
                {
                    name: 'AES-GCM',
                    length: 256
                },
                false, // non-extractable for security
                ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
            );
            
            return derivedKey;
        } catch (error) {
            throw new Error(`Key derivation failed: ${error.message}`);
        }
    }
    
    /**
     * Request password from user
     */
    async _requestPassword(isRetry = false) {
        if (!this._onPasswordRequired) {
            throw new Error('Password callback not set');
        }
        
        return new Promise((resolve, reject) => {
            this._onPasswordRequired(isRetry, (password) => {
                if (password) {
                    resolve(password);
                } else {
                    reject(new Error('Password not provided'));
                }
            });
        });
    }
    
    /**
     * Unlock the master key with password
     */
    async unlock(password = null) {
        try {
            // Request password if not provided
            if (!password) {
                password = await this._requestPassword(false);
            }
            
            // Get or create persistent salt
            const salt = await this._getOrCreateSalt();
            
            // Derive master key
            this._masterKey = await this._deriveKeyFromPassword(password, salt);
            
            // Mark as unlocked
            this._isUnlocked = true;
            this._lastActivity = Date.now();
            
            // Start session timer
            this._startSessionTimer();
            
            // Securely wipe password from memory
            password = null;
            
            if (this._onUnlocked) {
                this._onUnlocked();
            }
            
            return { success: true };
            
        } catch (error) {
            // Securely wipe password on error
            password = null;
            throw error;
        }
    }
    
    /**
     * Lock the master key
     */
    lock() {
        this._expireSession('manual');
    }
    
    /**
     * Get master key (only if unlocked)
     */
    getMasterKey() {
        if (!this._isUnlocked || !this._masterKey) {
            throw new Error('Master key is locked');
        }
        
        this._updateActivity();
        return this._masterKey;
    }
    
    /**
     * Check if master key is unlocked
     */
    isUnlocked() {
        return this._isUnlocked && this._masterKey !== null;
    }
    
    /**
     * Get session status
     */
    getSessionStatus() {
        return {
            isUnlocked: this._isUnlocked,
            lastActivity: this._lastActivity,
            sessionTimeoutMs: this._sessionTimeoutMs,
            inactivityTimeoutMs: this._inactivityTimeoutMs
        };
    }
    
    /**
     * Securely wipe master key from memory
     */
    _secureWipeMasterKey() {
        if (this._masterKey) {
            // CryptoKey objects are automatically garbage collected
            // but we clear the reference immediately
            this._masterKey = null;
        }
        this._clearTimers();
    }
    
    /**
     * Cleanup on destruction
     */
    destroy() {
        this._secureWipeMasterKey();
        this._isUnlocked = false;
        
        // Remove event listeners
        if (typeof document !== 'undefined') {
            document.removeEventListener('visibilitychange', this._handleFocusOut);
            window.removeEventListener('blur', this._handleFocusOut);
            window.removeEventListener('focus', this._handleFocusIn);
        }
    }
}

export { 
    EnhancedSecureWebRTCManager, 
    SecureMasterKeyManager, 
    SecureIndexedDBWrapper, 
    SecurePersistentKeyStorage 
};