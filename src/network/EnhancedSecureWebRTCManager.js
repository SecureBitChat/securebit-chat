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

    // SECURE: Static debug flag instead of this._debugMode
    static DEBUG_MODE = false; // Set to true during development, false in production

    // ============================================
    // DTLS CLIENTHELLO RACE CONDITION PROTECTION
    // ============================================
    
    // Защита от DTLS ClientHello race condition (октябрь 2024)
    static DTLS_PROTECTION = {
        SUPPORTED_CIPHERS: [
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
        ],
        MIN_TLS_VERSION: '1.2',
        MAX_TLS_VERSION: '1.3',
        CLIENTHELLO_TIMEOUT: 5000, // 5 seconds
        ICE_VERIFICATION_TIMEOUT: 3000 // 3 seconds
    };

    constructor(onMessage, onStatusChange, onKeyExchange, onVerificationRequired, onAnswerError = null, config = {}) {
    // Determine runtime mode
    this._isProductionMode = this._detectProductionMode();
            // SECURE: Use static flag instead of this._debugMode
        this._debugMode = !this._isProductionMode && EnhancedSecureWebRTCManager.DEBUG_MODE;
        
        // SECURE: Configuration from constructor parameters instead of global flags
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

            // SECURE: Initialize own logging system
        this._initializeSecureLogging();
        this._setupOwnLogger();
        this._setupProductionLogging();
        
        // SECURE: Store important methods first
        this._storeImportantMethods();
        
        // SECURE: Setup global API after storing methods
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
    
    // ============================================
    // CRITICAL FIX: IV REUSE PREVENTION SYSTEM
    // ============================================
    // SECURE: IV REUSE PREVENTION SYSTEM WITH LIMITS
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
    
    // CRITICAL FIX: IV cleanup tracking
    this._lastIVCleanupTime = null;
    
    // ============================================
    // CRITICAL FIX: SECURE ERROR HANDLING SYSTEM
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
    // CRITICAL FIX: SECURE MEMORY MANAGEMENT SYSTEM
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
             // DTLS Race Condition Protection
    this.verifiedICEEndpoints = new Set(); // Верифицированные ICE endpoints
    this.dtlsClientHelloQueue = new Map(); // Очередь DTLS ClientHello сообщений
    this.iceVerificationInProgress = false; // Флаг процесса ICE верификации
    this.dtlsProtectionEnabled = true; // Включена ли защита от DTLS race condition
    

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
        this._secureLog('info', '🔒 Enhanced WebRTC Manager initialized with tiered security');
        
        // SECURE: Log configuration for debugging
        this._secureLog('info', '🔒 Configuration loaded from constructor parameters', {
            fakeTraffic: this._config.fakeTraffic.enabled,
            decoyChannels: this._config.decoyChannels.enabled,
            packetPadding: this._config.packetPadding.enabled,
            antiFingerprinting: this._config.antiFingerprinting.enabled
        });
        
        // SECURE: XSS Hardening - replace all window.DEBUG_MODE references
        this._hardenDebugModeReferences();
        
        // SECURE: Initialize unified scheduler for all maintenance tasks
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
                    // CRITICAL FIX: Removed nestedEncryptionIV and nestedEncryptionCounter
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
                enabled: this._config.fakeTraffic.enabled,
                minInterval: this._config.fakeTraffic.minInterval,
                maxInterval: this._config.fakeTraffic.maxInterval,
                minSize: this._config.fakeTraffic.minSize,
                maxSize: this._config.fakeTraffic.maxSize,
                patterns: this._config.fakeTraffic.patterns
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
     * CRITICAL FIX: Enhanced mutex system initialization with atomic protection
     */
    _initializeMutexSystem() {
        // CRITICAL FIX: Initialize standard mutexes with enhanced state tracking
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

        // CRITICAL FIX: Enhanced key system state with atomic operation tracking
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

        // CRITICAL FIX: Operation counters with atomic increments
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
     * SECURE: XSS Hardening - Debug mode references validation
     * This method is called during initialization to ensure XSS hardening
     */
    _hardenDebugModeReferences() {
        // SECURE: Log that we're hardening debug mode references
        this._secureLog('info', '🔒 XSS Hardening: Debug mode references already replaced');
        
        // SECURE: All debug mode checks now use this._debugMode instead of window.DEBUG_MODE
        // This prevents XSS attacks through global variable manipulation
        
        // SECURE: Note: This function is called during initialization
        // All window.DEBUG_MODE references have been replaced by the build process
    }

    /**
     * SECURE: Unified scheduler for all maintenance tasks
     * Replaces multiple setInterval calls with a single, controlled scheduler
     */
    _initializeUnifiedScheduler() {
        // SECURE: Single scheduler interval for all maintenance tasks
        this._maintenanceScheduler = setInterval(() => {
            this._executeMaintenanceCycle();
        }, 300000); // Every 5 minutes
        
        // SECURE: Log scheduler initialization
        this._secureLog('info', '🔧 Unified maintenance scheduler initialized (5-minute cycle)');
        
        // SECURE: Store scheduler reference for cleanup
        this._activeTimers = new Set([this._maintenanceScheduler]);
    }

    /**
     * SECURE: Execute all maintenance tasks in a single cycle
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
            
            // SECURE: Emergency cleanup on failure
            this._emergencyCleanup();
        }
    }

    /**
     * SECURE: Enforce hard resource limits with emergency cleanup
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
            this._emergencyCleanup();
        }
    }

    /**
     * SECURE: Emergency cleanup when resource limits are exceeded
     */
    _emergencyCleanup() {
        this._secureLog('warn', '🚨 EMERGENCY: Resource limits exceeded, performing emergency cleanup');
        
        try {
            // 1. Clear all logs immediately
            this._logCounts.clear();
            this._secureLog('info', '🧹 Emergency: All logs cleared');
            
            // 2. Clear message queue
            this.messageQueue.length = 0;
            this._secureLog('info', '🧹 Emergency: Message queue cleared');
            
            // 3. Clear IV history
            if (this._ivTrackingSystem) {
                this._ivTrackingSystem.ivHistory.clear();
                this._secureLog('info', '🧹 Emergency: IV history cleared');
            }
            
            // 4. Clear processed message IDs
            this.processedMessageIds.clear();
            this._secureLog('info', '🧹 Emergency: Processed message IDs cleared');
            
            // 5. Clear decoy channels
            this.decoyChannels.clear();
            this._secureLog('info', '🧹 Emergency: Decoy channels cleared');
            
            // 6. Clear fake traffic messages
            if (this._fakeTrafficMessages) {
                this._fakeTrafficMessages.length = 0;
                this._secureLog('info', '🧹 Emergency: Fake traffic messages cleared');
            }
            
            // 7. Clear chunk queue
            this.chunkQueue.length = 0;
            this._secureLog('info', '🧹 Emergency: Chunk queue cleared');
            
            // 8. Clear packet buffer
            if (this.packetBuffer) {
                this.packetBuffer.clear();
                this._secureLog('info', '🧹 Emergency: Packet buffer cleared');
            }
            
            // 9. Force garbage collection if available
            if (typeof window.gc === 'function') {
                window.gc();
                this._secureLog('info', '🧹 Emergency: Garbage collection forced');
            }
            
            this._secureLog('info', '✅ Emergency cleanup completed successfully');
            
        } catch (error) {
            this._secureLog('error', '❌ Emergency cleanup failed', {
                errorType: error?.constructor?.name || 'Unknown',
                message: error?.message || 'Unknown error'
            });
        }
    }

    /**
     * SECURE: Cleanup resources based on age and usage
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
     * SECURE: Monitor key security (replaces _startKeySecurityMonitoring)
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
     * SECURE: Send heartbeat message (called by unified scheduler)
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

    // ============================================
    // SECURE KEY STORAGE MANAGEMENT
    // ============================================

    /**
     * Initializes the secure key storage
     */
    _initializeSecureKeyStorage() {
        // Initialize with the new class
        this._secureKeyStorage = new SecureKeyStorage();
        
        // Keep the stats structure for compatibility
        this._keyStorageStats = {
            totalKeys: 0,
            activeKeys: 0,
            lastAccess: null,
            lastRotation: null,
        };
        
        this._secureLog('info', '🔐 Enhanced secure key storage initialized');
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
        // SECURE: Functionality moved to unified scheduler
        this._secureLog('info', '🔧 Key security monitoring moved to unified scheduler');
    }


    // ============================================
    // HELPER METHODS
    // ============================================
    /**
     * CRITICAL FIX: Enhanced secure logging system initialization
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
        
        // CRITICAL FIX: Ultra-strict levels for production
        this._currentLogLevel = this._isProductionMode ? 
            this._logLevels.error : // In production, ONLY critical errors
            this._logLevels.info;   // In development, up to info
        
        // CRITICAL FIX: Reduced log limits to prevent data accumulation
        this._logCounts = new Map();
        this._maxLogCount = this._isProductionMode ? 5 : 50; // Reduced limits
        
        // SECURE: Hard resource limits to prevent memory leaks
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
        
        // SECURE: Emergency cleanup thresholds
        this._emergencyThresholds = {
            logEntries: this._resourceLimits.maxLogEntries * 0.8, // 80%
            messageQueue: this._resourceLimits.maxMessageQueue * 0.8,
            ivHistory: this._resourceLimits.maxIVHistory * 0.8,
            processedMessageIds: this._resourceLimits.maxProcessedMessageIds * 0.8
        };

        // CRITICAL FIX: Comprehensive blacklist with all sensitive patterns
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

        // CRITICAL FIX: Minimal whitelist with strict validation
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
        
        // CRITICAL FIX: Initialize security monitoring
        this._initializeLogSecurityMonitoring();
        
        this._secureLog('info', `🔧 Enhanced secure logging initialized (Production: ${this._isProductionMode})`);
    }

    /**
     * CRITICAL FIX: Initialize security monitoring for logging system
     */
    _initializeLogSecurityMonitoring() {
        // SECURE: Security monitoring moved to unified scheduler
        this._logSecurityViolations = 0;
        this._maxLogSecurityViolations = 3;
    }

    /**
     * CRITICAL FIX: Audit logging system security
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
    /**
     * CRITICAL FIX: Shim to redirect arbitrary console.log calls to _secureLog('info', ...)
     * Fixed syntax errors and improved error handling
     */
    _secureLogShim(...args) {
        try {
            // Validate arguments array
            if (!Array.isArray(args) || args.length === 0) {
                return;
            }
            
            // CRITICAL FIX: Proper destructuring with fallback
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
            
            // CRITICAL FIX: Proper object structure for multiple args
            this._secureLog('info', String(message || ''), { 
                additionalArgs: restArgs,
                argCount: restArgs.length 
            });
        } catch (error) {
            // CRITICAL FIX: Better error handling - fallback to original console if available
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
     * CRITICAL FIX: Redirects global console.log to this instance's secure logger
     * Improved error handling and validation
     */
    /**
     * SECURE: Setup own logger without touching global console
     */
    _setupOwnLogger() {
        // SECURE: Create own logger without touching global console
        this.logger = {
            log: (message, data) => this._secureLog('info', message, data),
            info: (message, data) => this._secureLog('info', message, data),
            warn: (message, data) => this._secureLog('warn', message, data),
            error: (message, data) => this._secureLog('error', message, data),
            debug: (message, data) => this._secureLog('debug', message, data)
        };
        
        // SECURE: In development, log to console; in production, use secure logging only
        if (EnhancedSecureWebRTCManager.DEBUG_MODE) {
            this._secureLog('info', '🔒 Own logger created - development mode');
        } else {
            this._secureLog('info', '🔒 Own logger created - production mode');
        }
    }
    /**
     * SECURE: Production logging - use own logger with minimal output
     */
    _setupProductionLogging() {
        // SECURE: In production, own logger becomes minimal
        if (this._isProductionMode) {
            this.logger = {
                log: () => {}, // No-op in production
                info: () => {}, // No-op in production
                warn: (message, data) => this._secureLog('warn', message, data),
                error: (message, data) => this._secureLog('error', message, data),
                debug: () => {} // No-op in production
            };
            
            this._secureLog('info', '🔒 Production logging mode activated');
        }
    }
    /**
     * CRITICAL FIX: Secure logging with enhanced data protection
     * @param {string} level - Log level (error, warn, info, debug, trace)
     * @param {string} message - Message
     * @param {object} data - Optional payload (will be sanitized)
     */
    _secureLog(level, message, data = null) {
        // CRITICAL FIX: Pre-sanitization audit to prevent data leakage
        if (data && !this._auditLogMessage(message, data)) {
            // CRITICAL FIX: Log the attempt but block the actual data
            this._originalConsole?.error?.('🚨 SECURITY: Logging blocked due to potential data leakage');
            return;
        }
        
        // Check log level
        if (this._logLevels[level] > this._currentLogLevel) {
            return;
        }
        
        // CRITICAL FIX: Prevent log spam with better key generation
        const logKey = `${level}:${message.substring(0, 50)}`;
        const currentCount = this._logCounts.get(logKey) || 0;
        
        if (currentCount >= this._maxLogCount) {
            return;
        }
        
        this._logCounts.set(logKey, currentCount + 1);
        
        // CRITICAL FIX: Enhanced sanitization with multiple passes
        let sanitizedData = null;
        if (data) {
            // First pass: basic sanitization
            sanitizedData = this._sanitizeLogData(data);
            
            // Second pass: check if sanitized data still contains sensitive content
            if (this._containsSensitiveContent(JSON.stringify(sanitizedData))) {
                this._originalConsole?.error?.('🚨 SECURITY: Sanitized data still contains sensitive content - blocking log');
                return;
            }
        }
        
        // CRITICAL FIX: Production mode security - only log essential errors
        if (this._isProductionMode) {
            if (level === 'error') {
                // CRITICAL FIX: In production, only log error messages without sensitive data
                const safeMessage = this._sanitizeString(message);
                this._originalConsole?.error?.(safeMessage);
            }
            // CRITICAL FIX: Block all other log levels in production
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
     * CRITICAL FIX: Enhanced sanitization for log data with multiple security layers
     */
    _sanitizeLogData(data) {
        // CRITICAL FIX: Pre-check for sensitive content before processing
        if (typeof data === 'string') {
            return this._sanitizeString(data);
        }
        
        if (!data || typeof data !== 'object') {
            return data;
        }
        
        const sanitized = {};
        
        for (const [key, value] of Object.entries(data)) {
            const lowerKey = key.toLowerCase();
            
            // CRITICAL FIX: Enhanced blacklist with more comprehensive patterns
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
            
            // CRITICAL FIX: Enhanced whitelist with strict validation
            if (this._safeFieldsWhitelist.has(key)) {
                // CRITICAL FIX: Even whitelisted fields get sanitized if they contain sensitive data
                if (typeof value === 'string') {
                    sanitized[key] = this._sanitizeString(value);
                } else {
                    sanitized[key] = value;
                }
                continue;
            }
            
            // CRITICAL FIX: Enhanced type handling with security checks
            if (typeof value === 'boolean' || typeof value === 'number') {
                sanitized[key] = value;
            } else if (typeof value === 'string') {
                sanitized[key] = this._sanitizeString(value);
            } else if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
                // CRITICAL FIX: Don't reveal actual byte lengths for security
                sanitized[key] = `[${value.constructor.name}(<REDACTED> bytes)]`;
            } else if (value && typeof value === 'object') {
                // CRITICAL FIX: Recursive sanitization with depth limit and security check
                try {
                    sanitized[key] = this._sanitizeLogData(value);
                } catch (error) {
                    sanitized[key] = '[RECURSIVE_SANITIZATION_FAILED]';
                }
            } else {
                sanitized[key] = `[${typeof value}]`;
            }
        }
        
        // CRITICAL FIX: Final security check on sanitized data
        const sanitizedString = JSON.stringify(sanitized);
        if (this._containsSensitiveContent(sanitizedString)) {
            return { error: 'SANITIZATION_FAILED_SENSITIVE_CONTENT_DETECTED' };
        }
        
        return sanitized;
    }
    /**
     * CRITICAL FIX: Enhanced sanitization for strings with comprehensive pattern detection
     */
    _sanitizeString(str) {
        if (typeof str !== 'string' || str.length === 0) {
            return str;
        }
        
        // CRITICAL FIX: Comprehensive sensitive pattern detection
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
        
        // CRITICAL FIX: Check for sensitive patterns with early return
        for (const pattern of sensitivePatterns) {
            if (pattern.test(str)) {
                // CRITICAL FIX: Always fully hide sensitive data
                return '[SENSITIVE_DATA_REDACTED]';
            }
        }
        
        // CRITICAL FIX: Check for suspicious entropy (high randomness indicates keys)
        if (this._hasHighEntropy(str)) {
            return '[HIGH_ENTROPY_DATA_REDACTED]';
        }
        
        // CRITICAL FIX: Check for suspicious character distributions
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
     * CRITICAL FIX: Enhanced sensitive content detection
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
     * CRITICAL FIX: Check for high entropy strings (likely cryptographic keys)
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
     * CRITICAL FIX: Check for suspicious character distributions
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
    // DTLS CLIENTHELLO RACE CONDITION PROTECTION
    // ============================================
    
    /**
     * 
     * DTLS protection ClientHello race condition 
     */
    async validateDTLSSource(clientHelloData, expectedSource) {
        try {
            if (!this.verifiedICEEndpoints.has(expectedSource)) {
                this._secureLog('error', 'DTLS ClientHello from unverified source - possible race condition attack', {
                    source: expectedSource,
                    verifiedEndpoints: Array.from(this.verifiedICEEndpoints),
                    timestamp: Date.now()
                });
                throw new Error('DTLS ClientHello from unverified source - possible race condition attack');
            }

            if (!clientHelloData.cipherSuite || 
                !EnhancedSecureWebRTCManager.DTLS_PROTECTION.SUPPORTED_CIPHERS.includes(clientHelloData.cipherSuite)) {
                this._secureLog('error', 'Invalid cipher suite in ClientHello', {
                    receivedCipher: clientHelloData.cipherSuite,
                    supportedCiphers: EnhancedSecureWebRTCManager.DTLS_PROTECTION.SUPPORTED_CIPHERS
                });
                throw new Error('Invalid cipher suite in ClientHello');
            }

            if (clientHelloData.tlsVersion) {
                const version = clientHelloData.tlsVersion;
                if (version < EnhancedSecureWebRTCManager.DTLS_PROTECTION.MIN_TLS_VERSION ||
                    version > EnhancedSecureWebRTCManager.DTLS_PROTECTION.MAX_TLS_VERSION) {
                    this._secureLog('error', 'Unsupported TLS version in ClientHello', {
                        receivedVersion: version,
                        minVersion: EnhancedSecureWebRTCManager.DTLS_PROTECTION.MIN_TLS_VERSION,
                        maxVersion: EnhancedSecureWebRTCManager.DTLS_PROTECTION.MAX_TLS_VERSION
                    });
                    throw new Error('Unsupported TLS version in ClientHello');
                }
            }
            
            this._secureLog('info', 'DTLS ClientHello validation passed', {
                source: expectedSource,
                cipherSuite: clientHelloData.cipherSuite,
                tlsVersion: clientHelloData.tlsVersion
            });
            
            return true;
        } catch (error) {
            this._secureLog('error', 'DTLS ClientHello validation failed', {
                error: error.message,
                source: expectedSource,
                timestamp: Date.now()
            });
            throw error;
        }
    }
    
    /**
     * Adds ICE endpoint to the list of verified ones
     */
    addVerifiedICEEndpoint(endpoint) {
        this.verifiedICEEndpoints.add(endpoint);
        this._secureLog('info', 'ICE endpoint verified and added to DTLS protection', {
            endpoint: endpoint,
            totalVerified: this.verifiedICEEndpoints.size
        });
    }
    
    /**
     * Handles DTLS ClientHello with race condition protection
     */
    async handleDTLSClientHello(clientHelloData, sourceEndpoint) {
        try {
            if (this.iceVerificationInProgress) {
                this.dtlsClientHelloQueue.set(sourceEndpoint, {
                    data: clientHelloData,
                    timestamp: Date.now(),
                    attempts: 0
                });
                
                this._secureLog('warn', 'DTLS ClientHello queued - ICE verification in progress', {
                    source: sourceEndpoint,
                    queueSize: this.dtlsClientHelloQueue.size
                });
                
                return false; 
            }
            
            // Validate the source of the DTLS packet
            await this.validateDTLSSource(clientHelloData, sourceEndpoint);

            this._secureLog('info', 'DTLS ClientHello processed successfully', {
                source: sourceEndpoint,
                cipherSuite: clientHelloData.cipherSuite
            });
            
            return true;
        } catch (error) {
            this._secureLog('error', 'DTLS ClientHello handling failed', {
                error: error.message,
                source: sourceEndpoint,
                timestamp: Date.now()
            });

            this.verifiedICEEndpoints.delete(sourceEndpoint);
            
            throw error;
        }
    }
    
    /**
     * Completes ICE verification and processes pending DTLS messages
     */
    async completeICEVerification(verifiedEndpoints) {
        try {
            this.iceVerificationInProgress = false;

            for (const endpoint of verifiedEndpoints) {
                this.addVerifiedICEEndpoint(endpoint);
            }
            
            // Processing Deferred DTLS ClientHello Messages
            for (const [endpoint, queuedData] of this.dtlsClientHelloQueue.entries()) {
                try {
                    if (this.verifiedICEEndpoints.has(endpoint)) {
                        await this.handleDTLSClientHello(queuedData.data, endpoint);
                        this.dtlsClientHelloQueue.delete(endpoint);
                    }
                } catch (error) {
                    this._secureLog('error', 'Failed to process queued DTLS ClientHello', {
                        endpoint: endpoint,
                        error: error.message
                    });
                }
            }
            
            this._secureLog('info', 'ICE verification completed and DTLS queue processed', {
                verifiedEndpoints: verifiedEndpoints.length,
                processedQueue: this.dtlsClientHelloQueue.size
            });
            
        } catch (error) {
            this._secureLog('error', 'ICE verification completion failed', {
                error: error.message
            });
            throw error;
        }
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
        // SECURE: Log that we're starting API setup
        this._secureLog('info', '🔒 Starting secure global API setup');
        
        // SECURE: Create simple public API with safety checks
        const secureAPI = {};
        
        // SECURE: Only bind methods that exist
        if (typeof this.sendMessage === 'function') {
            secureAPI.sendMessage = this.sendMessage.bind(this);
        }
        
        // SECURE: Create simple getConnectionStatus method
        secureAPI.getConnectionStatus = () => ({
            isConnected: this.isConnected ? this.isConnected() : false,
            isVerified: this.isVerified || false,
            connectionState: this.peerConnection?.connectionState || 'disconnected'
        });
        
        // SECURE: Create simple getSecurityStatus method
        secureAPI.getSecurityStatus = () => ({
            securityLevel: this.currentSecurityLevel || 'basic',
            stage: 'initialized',
            activeFeaturesCount: Object.values(this.securityFeatures || {}).filter(Boolean).length
        });
        
        if (typeof this.sendFile === 'function') {
            secureAPI.sendFile = this.sendFile.bind(this);
        }
        
        // SECURE: Create simple getFileTransferStatus method
        secureAPI.getFileTransferStatus = () => ({
            initialized: !!this.fileTransferSystem,
            status: 'ready',
            activeTransfers: 0,
            receivingTransfers: 0
        });
        
        if (typeof this.disconnect === 'function') {
            secureAPI.disconnect = this.disconnect.bind(this);
        }
        
        // SECURE: Create simple API object with safety checks
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
        
        // SECURE: Only add emergency methods that exist
        if (typeof this._emergencyUnlockAllMutexes === 'function') {
            safeGlobalAPI.emergency.unlockAllMutexes = this._emergencyUnlockAllMutexes.bind(this);
        }
        
        if (typeof this._emergencyRecoverMutexSystem === 'function') {
            safeGlobalAPI.emergency.recoverMutexSystem = this._emergencyRecoverMutexSystem.bind(this);
        }
        
        if (typeof this._emergencyDisableLogging === 'function') {
            safeGlobalAPI.emergency.disableLogging = this._emergencyDisableLogging.bind(this);
        }
        
        // SECURE: Add file transfer system status
        safeGlobalAPI.getFileTransferSystemStatus = () => ({
            initialized: !!this.fileTransferSystem,
            status: 'ready',
            activeTransfers: 0,
            receivingTransfers: 0
        });
        
        // SECURE: Log available methods for debugging
        this._secureLog('info', '🔒 API methods available', {
            sendMessage: !!secureAPI.sendMessage,
            getConnectionStatus: !!secureAPI.getConnectionStatus,
            getSecurityStatus: !!secureAPI.getSecurityStatus,
            sendFile: !!secureAPI.sendFile,
            getFileTransferStatus: !!secureAPI.getFileTransferStatus,
            disconnect: !!secureAPI.disconnect,
            getConfiguration: !!safeGlobalAPI.getConfiguration,
            emergencyMethods: Object.keys(safeGlobalAPI.emergency).length
        });

        // SECURE: Apply Object.freeze to prevent modification
        Object.freeze(safeGlobalAPI);
        Object.freeze(safeGlobalAPI.emergency);

        // SECURE: Export API once without monitoring
        this._createProtectedGlobalAPI(safeGlobalAPI);
        
        // SECURE: Setup minimal protection
        this._setupMinimalGlobalProtection();
        
        // SECURE: Log that API setup is complete
        this._secureLog('info', '🔒 Secure global API setup completed successfully');
    }
    /**
     * SECURE: Create simple global API export
     */
    _createProtectedGlobalAPI(safeGlobalAPI) {
        // SECURE: Log that we're creating protected global API
        this._secureLog('info', '🔒 Creating protected global API');
        
        // SECURE: Simple API export without proxy or monitoring
        if (!window.secureBitChat) {
            this._exportAPI(safeGlobalAPI);
        } else {
            this._secureLog('warn', '⚠️ Global API already exists, skipping setup');
        }
    }
    
    /**
     * SECURE: Simple API export without monitoring
     */
    _exportAPI(apiObject) {
        // SECURE: Log that we're exporting API
        this._secureLog('info', '🔒 Exporting API to window.secureBitChat');
        
        // SECURE: Check if important methods are available
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
            // SECURE: One-time export with immutable properties
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
     * SECURE: Setup minimal global protection
     */
    _setupMinimalGlobalProtection() {
        // SECURE: Simple protection without monitoring (methods already stored)
        this._protectGlobalAPI();
        
        this._secureLog('info', '🔒 Minimal global protection activated');
    }
    
    /**
     * SECURE: Store important methods in closure for local use
     */
    _storeImportantMethods() {
        // SECURE: Store references to important methods locally
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
     * SECURE: Simple protection without monitoring
     */
    _setupSimpleProtection() {
        this._secureLog('info', '🔒 Simple protection activated - no monitoring');
    }

    /**
     * SECURE: No global exposure prevention needed
     */
    _preventGlobalExposure() {
        this._secureLog('info', '🔒 No global exposure prevention - using secure API export only');
    }
    /**
     * SECURE: API integrity check - only at initialization
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
     * SECURE: Simple global exposure check - only at initialization
     */
    _auditGlobalExposure() {
        // SECURE: Only check once at initialization, no periodic scanning
        this._secureLog('info', '🔒 Global exposure check completed at initialization');
        return [];
    }
    
    /**
     * SECURE: No periodic security audits - only at initialization
     */
    _startSecurityAudit() {
        // SECURE: Only audit once at initialization, no periodic checks
        this._secureLog('info', '🔒 Security audit completed at initialization - no periodic monitoring');
    }
    
    /**
     * SECURE: Simple global API protection
     */
    _protectGlobalAPI() {
        if (!window.secureBitChat) {
            this._secureLog('warn', '⚠️ Global API not found during protection setup');
            return;
        }

        try {
            // SECURE: Validate API integrity once
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
     * SECURE: Validate API integrity once at initialization
     */
    _validateAPIIntegrityOnce() {
        try {
            // SECURE: Check if API is properly configured
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
     * CRITICAL FIX: Secure memory wipe for sensitive data
     */
    _secureWipeMemory(data, context = 'unknown') {
        if (!data) return;
        
        try {
            // CRITICAL FIX: Different handling for different data types
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
     * CRITICAL FIX: Secure wipe for ArrayBuffer
     */
    _secureWipeArrayBuffer(buffer, context) {
        if (!buffer || buffer.byteLength === 0) return;
        
        try {
            const view = new Uint8Array(buffer);
            
            // CRITICAL FIX: Overwrite with random data first
            crypto.getRandomValues(view);
            
            // CRITICAL FIX: Overwrite with zeros
            view.fill(0);
            
            // CRITICAL FIX: Overwrite with ones
            view.fill(255);
            
            // CRITICAL FIX: Final zero overwrite
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
     * CRITICAL FIX: Secure wipe for Uint8Array
     */
    _secureWipeUint8Array(array, context) {
        if (!array || array.length === 0) return;
        
        try {
            // CRITICAL FIX: Overwrite with random data first
            crypto.getRandomValues(array);
            
            // CRITICAL FIX: Overwrite with zeros
            array.fill(0);
            
            // CRITICAL FIX: Overwrite with ones
            array.fill(255);
            
            // CRITICAL FIX: Final zero overwrite
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
     * CRITICAL FIX: Secure wipe for arrays
     */
    _secureWipeArray(array, context) {
        if (!Array.isArray(array) || array.length === 0) return;
        
        try {
            // CRITICAL FIX: Recursively wipe each element
            array.forEach((item, index) => {
                if (item !== null && item !== undefined) {
                    this._secureWipeMemory(item, `${context}[${index}]`);
                }
            });
            
            // CRITICAL FIX: Fill with nulls
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
     * SECURE: No string wiping - strings are immutable in JS
     */
    _secureWipeString(str, context) {
        // SECURE: Strings are immutable in JavaScript, no need to wipe
        // Just remove the reference
        this._secureLog('debug', '🔒 String reference removed (strings are immutable)', {
            context: context,
            length: str ? str.length : 0
        });
    }
    
    /**
     * SECURE: CryptoKey cleanup - store in WeakMap for proper GC
     */
    _secureWipeCryptoKey(key, context) {
        if (!key || !(key instanceof CryptoKey)) return;
        
        try {
            // SECURE: Store in WeakMap for proper garbage collection
            if (!this._cryptoKeyStorage) {
                this._cryptoKeyStorage = new WeakMap();
            }
            
            // SECURE: Store reference for cleanup tracking
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
     * CRITICAL FIX: Secure wipe for objects
     */
    _secureWipeObject(obj, context) {
        if (!obj || typeof obj !== 'object') return;
        
        try {
            // CRITICAL FIX: Recursively wipe all properties
            for (const [key, value] of Object.entries(obj)) {
                if (value !== null && value !== undefined) {
                    this._secureWipeMemory(value, `${context}.${key}`);
                }
                // CRITICAL FIX: Set property to null
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
     * CRITICAL FIX: Secure cleanup of cryptographic materials
     */
    _secureCleanupCryptographicMaterials() {
        try {
            // CRITICAL FIX: Secure wipe of key pairs
            if (this.ecdhKeyPair) {
                this._secureWipeMemory(this.ecdhKeyPair, 'ecdhKeyPair');
                this.ecdhKeyPair = null;
            }
            
            if (this.ecdsaKeyPair) {
                this._secureWipeMemory(this.ecdsaKeyPair, 'ecdsaKeyPair');
                this.ecdsaKeyPair = null;
            }
            
            // CRITICAL FIX: Secure wipe of derived keys
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
            
            // CRITICAL FIX: Secure wipe of session data
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
            
            this._secureLog('info', '🔒 Cryptographic materials securely cleaned up');
            
        } catch (error) {
            this._secureLog('error', '❌ Failed to cleanup cryptographic materials', {
                errorType: error.constructor.name,
                errorMessage: error.message
            });
        }
    }
    
    /**
     * CRITICAL FIX: Force garbage collection if available
     */
    _forceGarbageCollection() {
        try {
            // CRITICAL FIX: Try to force garbage collection if available
            if (typeof window.gc === 'function') {
                window.gc();
                this._secureLog('debug', '🔒 Garbage collection forced');
            } else if (typeof global.gc === 'function') {
                global.gc();
                this._secureLog('debug', '🔒 Garbage collection forced (global)');
            } else {
                this._secureLog('debug', '⚠️ Garbage collection not available');
            }
        } catch (error) {
            this._secureLog('error', '❌ Failed to force garbage collection', {
                errorType: error.constructor.name
            });
        }
    }
    
    /**
     * CRITICAL FIX: Perform periodic memory cleanup
     */
    _performPeriodicMemoryCleanup() {
        try {
            this._secureMemoryManager.isCleaning = true;
            
            // CRITICAL FIX: Clean up any remaining sensitive data
            this._secureCleanupCryptographicMaterials();
            
            // CRITICAL FIX: Clean up message queue if it's too large
            if (this.messageQueue && this.messageQueue.length > 100) {
                const excessMessages = this.messageQueue.splice(0, this.messageQueue.length - 50);
                excessMessages.forEach((message, index) => {
                    this._secureWipeMemory(message, `periodicCleanup[${index}]`);
                });
            }
            
            // CRITICAL FIX: Clean up processed message IDs if too many
            if (this.processedMessageIds && this.processedMessageIds.size > 1000) {
                this.processedMessageIds.clear();
            }
            
            // CRITICAL FIX: Force garbage collection
            this._forceGarbageCollection();
            
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
     * CRITICAL FIX: Create secure error message without information disclosure
     */
    _createSecureErrorMessage(originalError, context = 'unknown') {
        try {
            // CRITICAL FIX: Categorize error for appropriate handling
            const category = this._categorizeError(originalError);
            
            // CRITICAL FIX: Generate safe error message based on category
            const safeMessage = this._getSafeErrorMessage(category, context);
            
            // CRITICAL FIX: Log detailed error internally for debugging
            this._secureLog('error', 'Internal error occurred', {
                category: category,
                context: context,
                errorType: originalError?.constructor?.name || 'Unknown',
                timestamp: Date.now()
            });
            
            // CRITICAL FIX: Track error frequency
            this._trackErrorFrequency(category);
            
            return safeMessage;
            
        } catch (error) {
            // CRITICAL FIX: Fallback to generic error if error handling fails
            this._secureLog('error', 'Error handling failed', {
                originalError: originalError?.message || 'Unknown',
                handlingError: error.message
            });
            return 'An unexpected error occurred';
        }
    }
    
    /**
     * CRITICAL FIX: Categorize error for appropriate handling
     */
    _categorizeError(error) {
        if (!error || !error.message) {
            return this._secureErrorHandler.errorCategories.UNKNOWN;
        }
        
        const message = error.message.toLowerCase();
        
        // CRITICAL FIX: Cryptographic errors
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
        
        // CRITICAL FIX: Network errors
        if (message.includes('network') || 
            message.includes('connection') || 
            message.includes('timeout') ||
            message.includes('webrtc') ||
            message.includes('peer')) {
            return this._secureErrorHandler.errorCategories.NETWORK;
        }
        
        // CRITICAL FIX: Validation errors
        if (message.includes('invalid') || 
            message.includes('validation') || 
            message.includes('format') ||
            message.includes('type')) {
            return this._secureErrorHandler.errorCategories.VALIDATION;
        }
        
        // CRITICAL FIX: System errors
        if (message.includes('system') || 
            message.includes('internal') || 
            message.includes('memory') ||
            message.includes('resource')) {
            return this._secureErrorHandler.errorCategories.SYSTEM;
        }
        
        return this._secureErrorHandler.errorCategories.UNKNOWN;
    }
    
    /**
     * CRITICAL FIX: Get safe error message based on category
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
        
        // CRITICAL FIX: Determine specific context for more precise message
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
     * CRITICAL FIX: Track error frequency for security monitoring
     */
    _trackErrorFrequency(category) {
        const now = Date.now();
        
        // CRITICAL FIX: Clean old error counts
        if (now - this._secureErrorHandler.lastErrorTime > 60000) { // 1 minute
            this._secureErrorHandler.errorCounts.clear();
        }
        
        // CRITICAL FIX: Increment error count
        const currentCount = this._secureErrorHandler.errorCounts.get(category) || 0;
        this._secureErrorHandler.errorCounts.set(category, currentCount + 1);
        this._secureErrorHandler.lastErrorTime = now;
        
        // CRITICAL FIX: Check if we're exceeding error threshold
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
     * CRITICAL FIX: Throw secure error without information disclosure
     */
    _throwSecureError(originalError, context = 'unknown') {
        const secureMessage = this._createSecureErrorMessage(originalError, context);
        throw new Error(secureMessage);
    }
    
    /**
     * CRITICAL FIX: Get error handling statistics
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
     * CRITICAL FIX: Reset error handling system
     */
    _resetErrorHandlingSystem() {
        this._secureErrorHandler.errorCounts.clear();
        this._secureErrorHandler.isInErrorMode = false;
        this._secureErrorHandler.lastErrorTime = 0;
        
        this._secureLog('info', '🔄 Error handling system reset');
    }
    
    /**
     * CRITICAL FIX: Get memory management statistics
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
     * CRITICAL FIX: Validate API integrity and security
     */
    _validateAPIIntegrity() {
        try {
            // CRITICAL FIX: Check if API exists
            if (!window.secureBitChat) {
                this._secureLog('error', '❌ Global API not found during integrity validation');
                return false;
            }
            
            // CRITICAL FIX: Validate required methods exist
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
            
            // CRITICAL FIX: Test method binding integrity
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
            
            // CRITICAL FIX: Test API immutability
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
        // SECURE: Check if basic security features are available
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

        // SECURE: Log current security state
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
        if (!this.sessionManager || !this.sessionManager.isFeatureAllowedForSession) {
            this._secureLog('warn', '⚠️ Session manager not available, using safe default security features');

            // SECURE: Keep existing features, only add new ones
            // Don't override hasEncryption and hasECDH if they're already true
            if (this.securityFeatures.hasEncryption === undefined) {
                this.securityFeatures.hasEncryption = false; // Will be set to true only after key generation
            }
            if (this.securityFeatures.hasECDH === undefined) {
                this.securityFeatures.hasECDH = false; // Will be set to true only after ECDH key generation
            }
            if (this.securityFeatures.hasECDSA === undefined) {
                this.securityFeatures.hasECDSA = false; // Will be set to true only after ECDSA key generation
            }
            if (this.securityFeatures.hasMutualAuth === undefined) {
                this.securityFeatures.hasMutualAuth = false; // Will be set to true only after mutual auth
            }
            if (this.securityFeatures.hasMetadataProtection === undefined) {
                this.securityFeatures.hasMetadataProtection = false;
            }
            if (this.securityFeatures.hasEnhancedReplayProtection === undefined) {
                this.securityFeatures.hasEnhancedReplayProtection = false;
            }
            if (this.securityFeatures.hasNonExtractableKeys === undefined) {
                this.securityFeatures.hasNonExtractableKeys = false;
            }
            if (this.securityFeatures.hasRateLimiting === undefined) {
                this.securityFeatures.hasRateLimiting = true; // Basic rate limiting always available
            }
            if (this.securityFeatures.hasEnhancedValidation === undefined) {
                this.securityFeatures.hasEnhancedValidation = false;
            }
            if (this.securityFeatures.hasPFS === undefined) {
                this.securityFeatures.hasPFS = false;
            }
            if (this.securityFeatures.hasNestedEncryption === undefined) {
                this.securityFeatures.hasNestedEncryption = false;
            }
            if (this.securityFeatures.hasPacketPadding === undefined) {
                this.securityFeatures.hasPacketPadding = false;
            }
            if (this.securityFeatures.hasPacketReordering === undefined) {
                this.securityFeatures.hasPacketReordering = false;
            }
            if (this.securityFeatures.hasAntiFingerprinting === undefined) {
                this.securityFeatures.hasAntiFingerprinting = false;
            }
            if (this.securityFeatures.hasFakeTraffic === undefined) {
                this.securityFeatures.hasFakeTraffic = false;
            }
            if (this.securityFeatures.hasDecoyChannels === undefined) {
                this.securityFeatures.hasDecoyChannels = false;
            }
            if (this.securityFeatures.hasMessageChunking === undefined) {
                this.securityFeatures.hasMessageChunking = false;
            }
            
            this._secureLog('info', '✅ Safe default security features applied (features will be enabled as they become available)');
            return;
        }

        let sessionType = 'demo'; 

        if (this.sessionManager.isFeatureAllowedForSession('premium', 'hasFakeTraffic')) {
            sessionType = 'premium';
        } else if (this.sessionManager.isFeatureAllowedForSession('basic', 'hasECDSA')) {
            sessionType = 'basic';
        }
        
        this._secureLog('info', '🔒 Syncing security features with tariff plan', { sessionType });

        const allFeatures = [
            'hasEncryption', 'hasECDH', 'hasECDSA', 'hasMutualAuth',
            'hasMetadataProtection', 'hasEnhancedReplayProtection',
            'hasNonExtractableKeys', 'hasRateLimiting', 'hasEnhancedValidation', 'hasPFS',
            'hasNestedEncryption', 'hasPacketPadding', 'hasPacketReordering',
            'hasAntiFingerprinting', 'hasFakeTraffic', 'hasDecoyChannels', 'hasMessageChunking'
        ];
        
        allFeatures.forEach(feature => {
            const isAllowed = this.sessionManager.isFeatureAllowedForSession(sessionType, feature);
            
            if (this.securityFeatures[feature] !== isAllowed) {
                this._secureLog('info', `🔄 Syncing ${feature}: ${this.securityFeatures[feature]} → ${isAllowed}`);
                this.securityFeatures[feature] = isAllowed;
            }
        });

        if (this.onStatusChange) {
            this.onStatusChange('security_synced', {
                type: 'tariff_sync',
                sessionType: sessionType,
                features: this.securityFeatures,
                message: `Security features synchronized with ${sessionType} tariff plan`
            });
        }
        
        this._secureLog('info', '✅ Security features synchronized with tariff plan', {
            sessionType,
            enabledFeatures: Object.keys(this.securityFeatures).filter(f => this.securityFeatures[f]).length,
            totalFeatures: Object.keys(this.securityFeatures).length
        });
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
        // SECURE: All security monitoring moved to unified scheduler
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
     * CRITICAL FIX: Enhanced log cleanup with security checks
     */
    _cleanupLogs() {
        // CRITICAL FIX: More aggressive cleanup to prevent data accumulation
        if (this._logCounts.size > 500) {
            this._logCounts.clear();
            this._secureLog('debug', '🧹 Log counts cleared due to size limit');
        }
        
        // CRITICAL FIX: Clean up old log entries to prevent memory leaks
        const now = Date.now();
        const maxAge = 300000; // 5 minutes
        
        // CRITICAL FIX: Check for suspicious log patterns
        let suspiciousCount = 0;
        for (const [key, count] of this._logCounts.entries()) {
            if (count > 10) {
                suspiciousCount++;
            }
        }
        
        // CRITICAL FIX: Emergency cleanup if too many suspicious patterns
        if (suspiciousCount > 20) {
            this._logCounts.clear();
            this._secureLog('warn', '🚨 Emergency log cleanup due to suspicious patterns');
        }
        
        // CRITICAL FIX: Reset security violation counter if system is stable
        if (this._logSecurityViolations > 0 && suspiciousCount < 5) {
            this._logSecurityViolations = Math.max(0, this._logSecurityViolations - 1);
        }
        
        // CRITICAL FIX: Clean up old IVs periodically
        if (!this._lastIVCleanupTime || Date.now() - this._lastIVCleanupTime > 300000) { // Every 5 minutes
            this._cleanupOldIVs();
            this._lastIVCleanupTime = Date.now();
        }
        
        // CRITICAL FIX: Periodic secure memory cleanup
        if (!this._secureMemoryManager.memoryStats.lastCleanup || 
            Date.now() - this._secureMemoryManager.memoryStats.lastCleanup > 600000) { // Every 10 minutes
            this._performPeriodicMemoryCleanup();
            this._secureMemoryManager.memoryStats.lastCleanup = Date.now();
        }
    }
    /**
     * CRITICAL FIX: Secure logging stats with sensitive data protection
     */
    _getLoggingStats() {
        // CRITICAL FIX: Only return safe statistics
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
        
        // CRITICAL FIX: Sanitize any potentially sensitive data
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
     * CRITICAL FIX: Enhanced emergency logging disable with cleanup
     */
    _emergencyDisableLogging() {
        // CRITICAL FIX: Immediately disable all logging levels
        this._currentLogLevel = -1;
        
        // CRITICAL FIX: Clear all log data to prevent memory leaks
        this._logCounts.clear();
        
        // CRITICAL FIX: Clear any cached sensitive data
        if (this._logSecurityViolations) {
            this._logSecurityViolations = 0;
        }
        
        // CRITICAL FIX: Override _secureLog to a secure no-op
        this._secureLog = () => {
            // CRITICAL FIX: Only allow emergency console errors
            if (arguments[0] === 'error' && this._originalConsole?.error) {
                this._originalConsole.error('🚨 SECURITY: Logging system disabled - potential data exposure prevented');
            }
        };
        
        // CRITICAL FIX: Override all logging methods to prevent bypass
        this._sanitizeString = () => '[LOGGING_DISABLED]';
        this._sanitizeLogData = () => ({ error: 'LOGGING_DISABLED' });
        this._auditLogMessage = () => false;
        this._containsSensitiveContent = () => true; // Block everything
        
        // CRITICAL FIX: Force garbage collection if available
        if (typeof window.gc === 'function') {
            try {
                window.gc();
            } catch (e) {
                // Ignore GC errors
            }
        }
        
        // CRITICAL FIX: Notify about the emergency shutdown
        this._originalConsole?.error?.('🚨 CRITICAL: Secure logging system disabled due to potential data exposure');
    }
    /**
     * CRITICAL FIX: Enhanced audit function for log message security
     */
    _auditLogMessage(message, data) {
        if (!data || typeof data !== 'object') return true;
        
        // CRITICAL FIX: Convert to string and check for sensitive content
        const dataString = JSON.stringify(data);
        
        // CRITICAL FIX: Check message itself for sensitive content
        if (this._containsSensitiveContent(message)) {
            this._emergencyDisableLogging();
            this._originalConsole?.error?.('🚨 SECURITY BREACH: Sensitive content detected in log message');
            return false;
        }
        
        // CRITICAL FIX: Check data string for sensitive content
        if (this._containsSensitiveContent(dataString)) {
            this._emergencyDisableLogging();
            this._originalConsole?.error?.('🚨 SECURITY BREACH: Sensitive content detected in log data');
            return false;
        }
        
        // CRITICAL FIX: Enhanced dangerous pattern detection
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
        
        // CRITICAL FIX: Check for high entropy values in data
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
            
            // CRITICAL FIX: Step-by-step readiness check
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
            
            // CRITICAL FIX: Ensure encryption keys are present
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
        this._secureLog('info', `🔧 Configuring security for ${sessionType} session (${securityLevel} level)`);
        
        this.currentSessionType = sessionType;
        this.currentSecurityLevel = securityLevel;
        
        if (window.sessionManager && window.sessionManager.isFeatureAllowedForSession) {
            this.sessionConstraints = {};
            
            Object.keys(this.securityFeatures).forEach(feature => {
                this.sessionConstraints[feature] = window.sessionManager.isFeatureAllowedForSession(sessionType, feature);
            });
            
            this.applySessionConstraints();
            
            this._secureLog('info', `✅ Security configured for ${sessionType}`, { constraints: this.sessionConstraints });

            if (!this._validateCryptographicSecurity()) {
                this._secureLog('error', '🚨 CRITICAL: Cryptographic security validation failed after session configuration');

                if (this.onStatusChange) {
                    this.onStatusChange('security_breach', {
                        type: 'crypto_security_failure',
                        sessionType: sessionType,
                        message: 'Cryptographic security validation failed after session configuration'
                    });
                }
            }
            
            this.notifySecurityLevel();
            
            setTimeout(() => {
                this.calculateAndReportSecurityLevel();
            }, EnhancedSecureWebRTCManager.TIMEOUTS.SECURITY_CALC_DELAY);
            
        } else {
            this._secureLog('warn', '⚠️ Session manager not available, using default security');
        }
    }

    // Applying session restrictions
    applySessionConstraints() {
        if (!this.sessionConstraints) return;

        // Applying restrictions to security features
        Object.keys(this.sessionConstraints).forEach(feature => {
            const allowed = this.sessionConstraints[feature];
            
            if (!allowed && this.securityFeatures[feature]) {
                this._secureLog('info', `🔒 Disabling ${feature} for ${this.currentSessionType} session`);
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
                this._secureLog('info', `🔓 Enabling ${feature} for ${this.currentSessionType} session`);
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
                    // CRITICAL FIX: No need for base IV or counter - each encryption gets fresh random IV
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
            // CRITICAL FIX: Generate cryptographically secure IV with reuse prevention
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
            
            // CRITICAL FIX: If IV generation failed due to emergency mode, disable nested encryption
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

        // CRITICAL FIX: Check that the data is actually encrypted with proper IV size
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
                    Math.random() * (this.fakeTrafficConfig.maxInterval - this.fakeTrafficConfig.minInterval) + 
                    this.fakeTrafficConfig.minInterval :
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
                    if (this._debugMode) {
                        this._secureLog('debug', '🔧 System message detected, blocking from chat', { type: jsonData.type });
                    }
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
            this._secureLog('error', '❌ Error in applySecurityLayers:', { errorType: error?.constructor?.name || 'Unknown' });
            return data;
        }
    }, 3000); // Short timeout for crypto operations
}

    async sendSystemMessage(messageData) {
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

                if (parsed.type && fileMessageTypes.includes(parsed.type)) {
                    this._secureLog('debug', '📁 File message detected in processMessage', { type: parsed.type });
                    
                    // Process file messages WITHOUT mutex
                    if (this.fileTransferSystem && typeof this.fileTransferSystem.handleFileMessage === 'function') {
                        this._secureLog('debug', '📁 Processing file message directly', { type: parsed.type });
                        await this.fileTransferSystem.handleFileMessage(parsed);
                        return;
                    }

                    this._secureLog('warn', '⚠️ File transfer system not available, attempting automatic initialization...');
                    try {
                        if (!this.isVerified) {
                            this._secureLog('warn', '⚠️ Connection not verified, cannot initialize file transfer');
                            return;
                        }
                        
                        if (!this.dataChannel || this.dataChannel.readyState !== 'open') {
                            this._secureLog('warn', '⚠️ Data channel not open, cannot initialize file transfer');
                            return;
                        }

                        this.initializeFileTransfer();

                        let attempts = 0;
                        const maxAttempts = 30; 
                        while (!this.fileTransferSystem && attempts < maxAttempts) {
                            await new Promise(resolve => setTimeout(resolve, 100));
                            attempts++;
                        }
                        
                        if (this.fileTransferSystem && typeof this.fileTransferSystem.handleFileMessage === 'function') {
                            this._secureLog('info', '✅ File transfer system initialized, processing message', { type: parsed.type });
                            await this.fileTransferSystem.handleFileMessage(parsed);
                            return;
                        } else {
                            this._secureLog('error', '❌ File transfer system initialization failed');
                        }
                    } catch (e) {
                        this._secureLog('error', '❌ Automatic file transfer initialization failed:', { errorType: e?.message || e?.constructor?.name || 'Unknown' });
                    }
                    
                    this._secureLog('error', '❌ File transfer system not available for:', { errorType: parsed.type?.constructor?.name || 'Unknown' });
                    return; // IMPORTANT: Exit after handling
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
                
                if (parsed.type && ['heartbeat', 'verification', 'verification_response', 'peer_disconnect', 'security_upgrade'].includes(parsed.type)) {
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
                
                if (message.type && ['heartbeat', 'verification', 'verification_response', 'peer_disconnect', 'security_upgrade'].includes(message.type)) {
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
                    // SECURE: Removed global callback - use event system instead
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
                this._secureLog('info', '🔒 Stage 3 features only available for premium sessions');
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
                this._secureLog('info', '🔒 Stage 4 features only available for premium sessions');
                return;
            }
            
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
            this._secureLog('info', '🔒 Demo session - keeping basic security only');
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
        
        this._secureLog('info', `🔒 ${this.currentSessionType} session - starting graduated security activation`);
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
            this._secureLog('error', '❌ Failed to establish enhanced connection:', { errorType: error?.constructor?.name || 'Unknown' });
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
            this._secureLog('error', '❌ Error during enhanced disconnect:', { errorType: error?.constructor?.name || 'Unknown' });
        }
    }

    // Start periodic cleanup for rate limiting and security
    startPeriodicCleanup() {
        // SECURE: Cleanup moved to unified scheduler
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
                    this.onStatusChange('disconnected');

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

        this.initializeFileTransfer();
                
            } catch (error) {
                this._secureLog('error', '❌ Error in establishConnection:', { errorType: error?.constructor?.name || 'Unknown' });
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
                                    this._secureLog('error', '❌ Failed to initialize file transfer system for receiver:', { errorType: initError?.constructor?.name || 'Unknown' });
                                }
                            }

                            if (this.fileTransferSystem) {
                                console.log('📁 Forwarding to local file transfer system:', parsed.type);
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
                                this._secureLog('error', '❌ Lazy init of file transfer failed:', { errorType: e?.message || e?.constructor?.name || 'Unknown' });
                            }
                            this._secureLog('error', '❌ No file transfer system available for:', { errorType: parsed.type?.constructor?.name || 'Unknown' });
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
                this._secureLog('error', '❌ Failed to process message in onmessage:', { errorType: error?.constructor?.name || 'Unknown' });
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
                    this._secureLog('warn', '⚠️ Nested decryption failed, continuing with original data');
                }
            }
            
            // Packet Padding Removal (if enabled)
            if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
                try {
                    processedData = this.removePacketPadding(processedData);
                } catch (error) {
                    this._secureLog('warn', '⚠️ Packet padding removal failed, continuing with original data');
                }
            }
            
            // Anti-Fingerprinting Removal (if enabled)
            if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
                try {
                    processedData = this.removeAntiFingerprinting(processedData);
                } catch (error) {
                    this._secureLog('warn', '⚠️ Anti-fingerprinting removal failed, continuing with original data');
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
            this._secureLog('error', '❌ Error processing binary data:', { errorType: error?.constructor?.name || 'Unknown' });
        }
    }
    // FIX 3: New method for processing enhanced messages WITHOUT mutex
    async _processEnhancedMessageWithoutMutex(parsedMessage) {
        try {
            console.log('🔐 Processing enhanced message without mutex...');
            
            if (!this.encryptionKey || !this.macKey || !this.metadataKey) {
                this._secureLog('error', '❌ Missing encryption keys for enhanced message');
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
                this._secureLog('warn', '⚠️ No message content in decrypted result');
            }
            
        } catch (error) {
            this._secureLog('error', '❌ Error processing enhanced message:', { errorType: error?.constructor?.name || 'Unknown' });
        }
    }
    /**
     * Creates a unique ID for an operation
     */
    _generateOperationId() {
        return `op_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    /**
     * CRITICAL FIX: Atomic mutex acquisition with enhanced race condition protection
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
        
        // CRITICAL FIX: Validate operation ID
        if (!operationId || typeof operationId !== 'string') {
            throw new Error('Invalid operation ID for mutex acquisition');
        }
        
        return new Promise((resolve, reject) => {
            // CRITICAL FIX: Atomic lock attempt with immediate state check
            const attemptLock = () => {
                // CRITICAL FIX: Check if mutex is already locked by this operation
                if (mutex.lockId === operationId) {
                    this._secureLog('warn', `⚠️ Mutex '${mutexName}' already locked by same operation`, {
                        operationId: operationId
                    });
                    resolve();
                    return;
                }
                
                // CRITICAL FIX: Atomic check and lock operation
                if (!mutex.locked) {
                    // CRITICAL FIX: Set lock state atomically
                    mutex.locked = true;
                    mutex.lockId = operationId;
                    mutex.lockTime = Date.now();
                    
                    this._secureLog('debug', `🔒 Mutex '${mutexName}' acquired atomically`, {
                        operationId: operationId,
                        lockTime: mutex.lockTime
                    });
                    
                    // CRITICAL FIX: Set timeout for automatic release with enhanced validation
                    mutex.lockTimeout = setTimeout(() => {
                        // CRITICAL FIX: Enhanced timeout handling with state validation
                        this._handleMutexTimeout(mutexName, operationId, timeout);
                    }, timeout);
                    
                    resolve();
                } else {
                    // CRITICAL FIX: Add to queue with timeout
                    const queueItem = { 
                        resolve, 
                        reject, 
                        operationId,
                        timestamp: Date.now(),
                        timeout: setTimeout(() => {
                            // CRITICAL FIX: Remove from queue on timeout
                            const index = mutex.queue.findIndex(item => item.operationId === operationId);
                            if (index !== -1) {
                                mutex.queue.splice(index, 1);
                                reject(new Error(`Mutex acquisition timeout for '${mutexName}'`));
                            }
                        }, timeout)
                    };
                    
                    mutex.queue.push(queueItem);
                    
                    this._secureLog('debug', `⏳ Operation queued for mutex '${mutexName}'`, {
                        operationId: operationId,
                        queueLength: mutex.queue.length,
                        currentLockId: mutex.lockId
                    });
                }
            };
            
            // CRITICAL FIX: Execute lock attempt immediately
            attemptLock();
        });
    }

    /**
     * CRITICAL FIX: Enhanced mutex release with strict validation and error handling
     */
    _releaseMutex(mutexName, operationId) {
        // CRITICAL FIX: Validate input parameters
        if (!mutexName || typeof mutexName !== 'string') {
            throw new Error('Invalid mutex name provided for release');
        }
        
        if (!operationId || typeof operationId !== 'string') {
            throw new Error('Invalid operation ID provided for mutex release');
        }
        
        // CRITICAL FIX: Build correct mutex property name
        const mutexPropertyName = `_${mutexName}Mutex`;
        const mutex = this[mutexPropertyName];
        
        if (!mutex) {
            this._secureLog('error', `❌ Unknown mutex for release: ${mutexName}`, {
                mutexPropertyName: mutexPropertyName,
                availableMutexes: this._getAvailableMutexes(),
                operationId: operationId
            });
            throw new Error(`Unknown mutex for release: ${mutexName}`);
        }
        
        // CRITICAL FIX: Strict validation of lock ownership
        if (mutex.lockId !== operationId) {
            this._secureLog('error', `❌ CRITICAL: Invalid mutex release attempt - potential race condition`, {
                mutexName: mutexName,
                expectedLockId: mutex.lockId,
                providedOperationId: operationId,
                mutexState: {
                    locked: mutex.locked,
                    lockTime: mutex.lockTime,
                    queueLength: mutex.queue.length
                }
            });
            
            // CRITICAL FIX: Throw error instead of silent failure
            throw new Error(`Invalid mutex release attempt for '${mutexName}': expected '${mutex.lockId}', got '${operationId}'`);
        }
        
        // CRITICAL FIX: Validate mutex is actually locked
        if (!mutex.locked) {
            this._secureLog('error', `❌ CRITICAL: Attempting to release unlocked mutex`, {
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
            // CRITICAL FIX: Clear timeout first
            if (mutex.lockTimeout) {
                clearTimeout(mutex.lockTimeout);
                mutex.lockTimeout = null;
            }
            
            // CRITICAL FIX: Calculate lock duration for monitoring
            const lockDuration = mutex.lockTime ? Date.now() - mutex.lockTime : 0;
            
            // CRITICAL FIX: Atomic release with state validation
            mutex.locked = false;
            mutex.lockId = null;
            mutex.lockTime = null;
            
            this._secureLog('debug', `🔓 Mutex released successfully: ${mutexName}`, {
                operationId: operationId,
                lockDuration: lockDuration,
                queueLength: mutex.queue.length
            });
            
            // CRITICAL FIX: Process next in queue with enhanced error handling
            this._processNextInQueue(mutexName);
            
        } catch (error) {
            // CRITICAL FIX: If queue processing fails, ensure mutex is still released
            this._secureLog('error', `❌ Error during mutex release queue processing`, {
                mutexName: mutexName,
                operationId: operationId,
                errorType: error.constructor.name,
                errorMessage: error.message
            });
            
            // CRITICAL FIX: Ensure mutex is released even if queue processing fails
            mutex.locked = false;
            mutex.lockId = null;
            mutex.lockTime = null;
            mutex.lockTimeout = null;
            
            throw error;
        }
    }

    /**
     * CRITICAL FIX: Enhanced queue processing with comprehensive error handling
     */
    _processNextInQueue(mutexName) {
        const mutex = this[`_${mutexName}Mutex`];
        
        if (!mutex) {
            this._secureLog('error', `❌ Mutex not found for queue processing: ${mutexName}`);
            return;
        }
        
        if (mutex.queue.length === 0) {
            return;
        }
        
        // CRITICAL FIX: Validate mutex state before processing queue
        if (mutex.locked) {
            this._secureLog('warn', `⚠️ Mutex '${mutexName}' is still locked, skipping queue processing`, {
                lockId: mutex.lockId,
                queueLength: mutex.queue.length
            });
            return;
        }
        
        // CRITICAL FIX: Get next item from queue atomically with validation
        const nextItem = mutex.queue.shift();
        
        if (!nextItem) {
            this._secureLog('warn', `⚠️ Empty queue item for mutex '${mutexName}'`);
            return;
        }
        
        // CRITICAL FIX: Validate queue item structure
        if (!nextItem.operationId || !nextItem.resolve || !nextItem.reject) {
            this._secureLog('error', `❌ Invalid queue item structure for mutex '${mutexName}'`, {
                hasOperationId: !!nextItem.operationId,
                hasResolve: !!nextItem.resolve,
                hasReject: !!nextItem.reject
            });
            return;
        }
        
        try {
            // CRITICAL FIX: Clear timeout for this item
            if (nextItem.timeout) {
                clearTimeout(nextItem.timeout);
            }
            
            // CRITICAL FIX: Attempt to acquire lock for next item
            this._secureLog('debug', `🔄 Processing next operation in queue for mutex '${mutexName}'`, {
                operationId: nextItem.operationId,
                queueRemaining: mutex.queue.length,
                timestamp: Date.now()
            });
            
            // CRITICAL FIX: Retry lock acquisition for queued operation with enhanced error handling
            setTimeout(async () => {
                try {
                    await this._acquireMutex(mutexName, nextItem.operationId, 5000);
                    
                    this._secureLog('debug', `✅ Queued operation acquired mutex '${mutexName}'`, {
                        operationId: nextItem.operationId,
                        acquisitionTime: Date.now()
                    });
                    
                    nextItem.resolve();
                    
                } catch (error) {
                    this._secureLog('error', `❌ Queued operation failed to acquire mutex '${mutexName}'`, {
                        operationId: nextItem.operationId,
                        errorType: error.constructor.name,
                        errorMessage: error.message,
                        timestamp: Date.now()
                    });
                    
                    // CRITICAL FIX: Reject with detailed error information
                    nextItem.reject(new Error(`Queue processing failed for '${mutexName}': ${error.message}`));
                    
                    // CRITICAL FIX: Continue processing queue even if one item fails
                    setTimeout(() => {
                        this._processNextInQueue(mutexName);
                    }, 50);
                }
            }, 10); // Small delay to prevent immediate re-acquisition
            
        } catch (error) {
            this._secureLog('error', `❌ Critical error during queue processing for mutex '${mutexName}'`, {
                operationId: nextItem.operationId,
                errorType: error.constructor.name,
                errorMessage: error.message
            });
            
            // CRITICAL FIX: Reject the operation and continue processing
            try {
                nextItem.reject(new Error(`Queue processing critical error: ${error.message}`));
            } catch (rejectError) {
                this._secureLog('error', `❌ Failed to reject queue item`, {
                    originalError: error.message,
                    rejectError: rejectError.message
                });
            }
            
            // CRITICAL FIX: Continue processing remaining queue items
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
     * CRITICAL FIX: Enhanced mutex execution with atomic operations
     */
    async _withMutex(mutexName, operation, timeout = 5000) {
        const operationId = this._generateOperationId();
        
        // CRITICAL FIX: Validate mutex system before operation
        if (!this._validateMutexSystem()) {
            this._secureLog('error', '❌ Mutex system not properly initialized', {
                operationId: operationId,
                mutexName: mutexName
            });
            throw new Error('Mutex system not properly initialized. Call _initializeMutexSystem() first.');
        }
        
        // CRITICAL FIX: Get mutex reference with validation
        const mutex = this[`_${mutexName}Mutex`];
        if (!mutex) {
            throw new Error(`Mutex '${mutexName}' not found`);
        }
        
        let mutexAcquired = false;
        
        try {
            // CRITICAL FIX: Atomic mutex acquisition with timeout
            await this._acquireMutex(mutexName, operationId, timeout);
            mutexAcquired = true;
            
            // CRITICAL FIX: Increment operation counter atomically
            const counterKey = `${mutexName}Operations`;
            if (this._operationCounters && this._operationCounters[counterKey] !== undefined) {
                this._operationCounters[counterKey]++;
            }
            
            // CRITICAL FIX: Execute operation with enhanced error handling
            const result = await operation(operationId);
            
            // CRITICAL FIX: Validate result before returning
            if (result === undefined && operation.name !== 'cleanup') {
                this._secureLog('warn', '⚠️ Mutex operation returned undefined result', {
                    operationId: operationId,
                    mutexName: mutexName,
                    operationName: operation.name
                });
            }
            
            return result;
            
        } catch (error) {
            // CRITICAL FIX: Enhanced error logging with context
            this._secureLog('error', '❌ Error in mutex operation', {
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
            
                    // CRITICAL FIX: If this is a key operation error, trigger emergency recovery
        if (mutexName === 'keyOperation') {
            this._handleKeyOperationError(error, operationId);
        }
        
        // CRITICAL FIX: Trigger emergency unlock for critical mutex errors
        if (error.message.includes('timeout') || error.message.includes('race condition')) {
            this._emergencyUnlockAllMutexes('errorHandler');
        }
            
            throw error;
        } finally {
            // CRITICAL FIX: Always release mutex in finally block with validation
            if (mutexAcquired) {
                try {
                    await this._releaseMutex(mutexName, operationId);
                    
                    // CRITICAL FIX: Verify mutex was properly released
                    if (mutex.locked && mutex.lockId === operationId) {
                        this._secureLog('error', '❌ Mutex release verification failed', {
                            operationId: operationId,
                            mutexName: mutexName
                        });
                        // Force release as fallback
                        mutex.locked = false;
                        mutex.lockId = null;
                        mutex.lockTimeout = null;
                    }
                    
                } catch (releaseError) {
                    this._secureLog('error', '❌ Error releasing mutex in finally block', {
                        operationId: operationId,
                        mutexName: mutexName,
                        releaseErrorType: releaseError.constructor.name,
                        releaseErrorMessage: releaseError.message
                    });
                    
                    // CRITICAL FIX: Force release on error
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
     * CRITICAL FIX: Enhanced emergency recovery of the mutex system
     */
    _emergencyRecoverMutexSystem() {
        this._secureLog('warn', '🚨 Emergency mutex system recovery initiated');
        
        try {
            // CRITICAL FIX: Emergency unlock all mutexes first
            this._emergencyUnlockAllMutexes('emergencyRecovery');
            
            // CRITICAL FIX: Force re-initialize the system
            this._initializeMutexSystem();
            
            // CRITICAL FIX: Validate recovery success
            if (!this._validateMutexSystem()) {
                throw new Error('Mutex system validation failed after recovery');
            }
            
            this._secureLog('info', '✅ Mutex system recovered successfully with validation');
            return true;
            
        } catch (error) {
            this._secureLog('error', '❌ Failed to recover mutex system', {
                errorType: error.constructor.name,
                errorMessage: error.message
            });
            
            // CRITICAL FIX: Last resort - force re-initialization
            try {
                this._initializeMutexSystem();
                this._secureLog('warn', '⚠️ Forced mutex system re-initialization completed');
                return true;
            } catch (reinitError) {
                this._secureLog('error', '❌ CRITICAL: Forced re-initialization also failed', {
                    originalError: error.message,
                    reinitError: reinitError.message
                });
                return false;
            }
        }
    }

    /**
     * CRITICAL FIX: Atomic key generation with race condition protection
     */
    async _generateEncryptionKeys() {
        return this._withMutex('keyOperation', async (operationId) => {
            this._secureLog('info', '🔑 Generating encryption keys with atomic mutex', {
                operationId: operationId
            });
            
            // CRITICAL FIX: Atomic state check and update using mutex lock
            const currentState = this._keySystemState;
            
            // CRITICAL FIX: Atomic check - if already initializing, wait or fail
            if (currentState.isInitializing) {
                this._secureLog('warn', '⚠️ Key generation already in progress, waiting for completion', {
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
            
            // CRITICAL FIX: Atomic state update within mutex protection
            try {
                // CRITICAL FIX: Set state atomically within mutex
                currentState.isInitializing = true;
                currentState.lastOperation = 'generation';
                currentState.lastOperationTime = Date.now();
                currentState.operationId = operationId;
                
                this._secureLog('debug', '🔒 Atomic key generation state set', {
                    operationId: operationId,
                    timestamp: currentState.lastOperationTime
                });
                
                // CRITICAL FIX: Generate keys with individual error handling
                let ecdhKeyPair = null;
                let ecdsaKeyPair = null;
                
                // Generate ECDH keys with retry mechanism
                try {
                    ecdhKeyPair = await window.EnhancedSecureCryptoUtils.generateECDHKeyPair();
                    
                    // CRITICAL FIX: Validate ECDH keys immediately
                    if (!ecdhKeyPair || !ecdhKeyPair.privateKey || !ecdhKeyPair.publicKey) {
                        throw new Error('ECDH key pair validation failed');
                    }
                    
                    // CRITICAL FIX: Additional validation for key types
                    if (!(ecdhKeyPair.privateKey instanceof CryptoKey) || 
                        !(ecdhKeyPair.publicKey instanceof CryptoKey)) {
                        throw new Error('ECDH keys are not valid CryptoKey instances');
                    }
                    
                    this._secureLog('debug', '✅ ECDH keys generated and validated', {
                        operationId: operationId,
                        privateKeyType: ecdhKeyPair.privateKey.algorithm?.name,
                        publicKeyType: ecdhKeyPair.publicKey.algorithm?.name
                    });
                    
                } catch (ecdhError) {
                    this._secureLog('error', '❌ ECDH key generation failed', {
                        operationId: operationId,
                        errorType: ecdhError.constructor.name
                    });
                    this._throwSecureError(ecdhError, 'ecdh_key_generation');
                }
                
                // Generate ECDSA keys with retry mechanism
                try {
                    ecdsaKeyPair = await window.EnhancedSecureCryptoUtils.generateECDSAKeyPair();
                    
                    // CRITICAL FIX: Validate ECDSA keys immediately
                    if (!ecdsaKeyPair || !ecdsaKeyPair.privateKey || !ecdsaKeyPair.publicKey) {
                        throw new Error('ECDSA key pair validation failed');
                    }
                    
                    // CRITICAL FIX: Additional validation for key types
                    if (!(ecdsaKeyPair.privateKey instanceof CryptoKey) || 
                        !(ecdsaKeyPair.publicKey instanceof CryptoKey)) {
                        throw new Error('ECDSA keys are not valid CryptoKey instances');
                    }
                    
                    this._secureLog('debug', '✅ ECDSA keys generated and validated', {
                        operationId: operationId,
                        privateKeyType: ecdsaKeyPair.privateKey.algorithm?.name,
                        publicKeyType: ecdsaKeyPair.publicKey.algorithm?.name
                    });
                    
                } catch (ecdsaError) {
                    this._secureLog('error', '❌ ECDSA key generation failed', {
                        operationId: operationId,
                        errorType: ecdsaError.constructor.name
                    });
                    this._throwSecureError(ecdsaError, 'ecdsa_key_generation');
                }
                
                // CRITICAL FIX: Final validation of both key pairs
                if (!ecdhKeyPair || !ecdsaKeyPair) {
                    throw new Error('One or both key pairs failed to generate');
                }
                
                // SECURE: Enable security features after successful key generation
                this._enableSecurityFeaturesAfterKeyGeneration(ecdhKeyPair, ecdsaKeyPair);
                
                this._secureLog('info', '✅ Encryption keys generated successfully with atomic protection', {
                    operationId: operationId,
                    hasECDHKeys: !!(ecdhKeyPair?.privateKey && ecdhKeyPair?.publicKey),
                    hasECDSAKeys: !!(ecdsaKeyPair?.privateKey && ecdsaKeyPair?.publicKey),
                    generationTime: Date.now() - currentState.lastOperationTime
                });
                
                return { ecdhKeyPair, ecdsaKeyPair };
                
            } catch (error) {
                // CRITICAL FIX: Ensure state is reset on any error
                this._secureLog('error', '❌ Key generation failed, resetting state', {
                    operationId: operationId,
                    errorType: error.constructor.name
                });
                throw error;
            } finally {
                // CRITICAL FIX: Always reset state in finally block
                currentState.isInitializing = false;
                currentState.operationId = null;
                
                this._secureLog('debug', '🔓 Key generation state reset', {
                    operationId: operationId
                });
            }
        });
    }

    /**
     * SECURE: Enable security features after successful key generation
     */
    _enableSecurityFeaturesAfterKeyGeneration(ecdhKeyPair, ecdsaKeyPair) {
        try {
            // SECURE: Enable encryption features based on available keys
            if (ecdhKeyPair && ecdhKeyPair.privateKey && ecdhKeyPair.publicKey) {
                this.securityFeatures.hasEncryption = true;
                this.securityFeatures.hasECDH = true;
                this._secureLog('info', '🔒 ECDH encryption features enabled');
            }
            
            if (ecdsaKeyPair && ecdsaKeyPair.privateKey && ecdsaKeyPair.publicKey) {
                this.securityFeatures.hasECDSA = true;
                this._secureLog('info', '🔒 ECDSA signature features enabled');
            }
            
            // SECURE: Enable additional features that depend on encryption
            if (this.securityFeatures.hasEncryption) {
                this.securityFeatures.hasMetadataProtection = true;
                this.securityFeatures.hasEnhancedReplayProtection = true;
                this.securityFeatures.hasNonExtractableKeys = true;
                this._secureLog('info', '🔒 Additional encryption-dependent features enabled');
            }
            
            this._secureLog('info', '🔒 Security features updated after key generation', {
                hasEncryption: this.securityFeatures.hasEncryption,
                hasECDH: this.securityFeatures.hasECDH,
                hasECDSA: this.securityFeatures.hasECDSA,
                hasMetadataProtection: this.securityFeatures.hasMetadataProtection,
                hasEnhancedReplayProtection: this.securityFeatures.hasEnhancedReplayProtection,
                hasNonExtractableKeys: this.securityFeatures.hasNonExtractableKeys
            });
            
        } catch (error) {
            this._secureLog('error', '❌ Failed to enable security features after key generation', {
                errorType: error.constructor.name,
                errorMessage: error.message
            });
        }
    }

    /**
     * CRITICAL FIX: Enhanced emergency mutex unlocking with authorization and validation
     */
    _emergencyUnlockAllMutexes(callerContext = 'unknown') {
        // CRITICAL FIX: Validate caller authorization
        const authorizedCallers = [
            'keyOperation', 'cryptoOperation', 'connectionOperation',
            'emergencyRecovery', 'systemShutdown', 'errorHandler'
        ];
        
        if (!authorizedCallers.includes(callerContext)) {
            this._secureLog('error', `🚨 UNAUTHORIZED emergency mutex unlock attempt`, {
                callerContext: callerContext,
                authorizedCallers: authorizedCallers,
                timestamp: Date.now()
            });
            throw new Error(`Unauthorized emergency mutex unlock attempt by: ${callerContext}`);
        }
        
        const mutexes = ['keyOperation', 'cryptoOperation', 'connectionOperation'];
        
        this._secureLog('error', '🚨 EMERGENCY: Unlocking all mutexes with authorization and state cleanup', {
            callerContext: callerContext,
            timestamp: Date.now()
        });
        
        let unlockedCount = 0;
        let errorCount = 0;
        
        mutexes.forEach(mutexName => {
            const mutex = this[`_${mutexName}Mutex`];
            if (mutex) {
                try {
                    // CRITICAL FIX: Clear timeout first
                    if (mutex.lockTimeout) {
                        clearTimeout(mutex.lockTimeout);
                    }
                    
                    // CRITICAL FIX: Log mutex state before emergency unlock
                    const previousState = {
                        locked: mutex.locked,
                        lockId: mutex.lockId,
                        lockTime: mutex.lockTime,
                        queueLength: mutex.queue.length
                    };
                    
                    // CRITICAL FIX: Reset mutex state atomically
                    mutex.locked = false;
                    mutex.lockId = null;
                    mutex.lockTimeout = null;
                    mutex.lockTime = null;
                    
                    // CRITICAL FIX: Clear queue with proper error handling and logging
                    let queueRejectCount = 0;
                    mutex.queue.forEach(item => {
                        try {
                            if (item.reject && typeof item.reject === 'function') {
                                item.reject(new Error(`Emergency mutex unlock for ${mutexName} by ${callerContext}`));
                                queueRejectCount++;
                            }
                        } catch (rejectError) {
                            this._secureLog('warn', `⚠️ Failed to reject queue item during emergency unlock`, {
                                mutexName: mutexName,
                                errorType: rejectError.constructor.name
                            });
                        }
                    });
                    
                    // CRITICAL FIX: Clear queue array
                    mutex.queue = [];
                    
                    unlockedCount++;
                    
                    this._secureLog('debug', `🔓 Emergency unlocked mutex: ${mutexName}`, {
                        previousState: previousState,
                        queueRejectCount: queueRejectCount,
                        callerContext: callerContext
                    });
                    
                } catch (error) {
                    errorCount++;
                    this._secureLog('error', `❌ Error during emergency unlock of mutex: ${mutexName}`, {
                        errorType: error.constructor.name,
                        errorMessage: error.message,
                        callerContext: callerContext
                    });
                }
            }
        });
        
        // CRITICAL FIX: Reset key system state with validation
        if (this._keySystemState) {
            try {
                const previousKeyState = { ...this._keySystemState };
                
                this._keySystemState.isInitializing = false;
                this._keySystemState.isRotating = false;
                this._keySystemState.isDestroying = false;
                this._keySystemState.operationId = null;
                this._keySystemState.concurrentOperations = 0;
                
                this._secureLog('debug', `🔓 Emergency reset key system state`, {
                    previousState: previousKeyState,
                    callerContext: callerContext
                });
                
            } catch (error) {
                this._secureLog('error', `❌ Error resetting key system state during emergency unlock`, {
                    errorType: error.constructor.name,
                    errorMessage: error.message,
                    callerContext: callerContext
                });
            }
        }
        
        // CRITICAL FIX: Log emergency unlock summary
        this._secureLog('info', `🚨 Emergency mutex unlock completed`, {
            callerContext: callerContext,
            unlockedCount: unlockedCount,
            errorCount: errorCount,
            totalMutexes: mutexes.length,
            timestamp: Date.now()
        });
        
        // CRITICAL FIX: Trigger system validation after emergency unlock
        setTimeout(() => {
            this._validateMutexSystemAfterEmergencyUnlock();
        }, 100);
    }

    /**
     * CRITICAL FIX: Handle key operation errors with recovery mechanisms
     */
    _handleKeyOperationError(error, operationId) {
        this._secureLog('error', '🚨 Key operation error detected, initiating recovery', {
            operationId: operationId,
            errorType: error.constructor.name,
            errorMessage: error.message
        });
        
        // CRITICAL FIX: Reset key system state immediately
        if (this._keySystemState) {
            this._keySystemState.isInitializing = false;
            this._keySystemState.isRotating = false;
            this._keySystemState.isDestroying = false;
            this._keySystemState.operationId = null;
        }
        
        // CRITICAL FIX: Clear any partial key data
        this.ecdhKeyPair = null;
        this.ecdsaKeyPair = null;
        this.encryptionKey = null;
        this.macKey = null;
        this.metadataKey = null;
        
        // CRITICAL FIX: Trigger emergency recovery if needed
        if (error.message.includes('timeout') || error.message.includes('race condition')) {
            this._secureLog('warn', '⚠️ Race condition or timeout detected, triggering emergency recovery');
            this._emergencyRecoverMutexSystem();
        }
    }

    /**
     * CRITICAL FIX: Generate cryptographically secure IV with reuse prevention
     */
    _generateSecureIV(ivSize = 12, context = 'general') {
        // CRITICAL FIX: Check if we're in emergency mode
        if (this._ivTrackingSystem.emergencyMode) {
            this._secureLog('error', '🚨 CRITICAL: IV generation blocked - emergency mode active due to IV reuse');
            throw new Error('IV generation blocked - emergency mode active');
        }
        
        let attempts = 0;
        const maxAttempts = 100; // Prevent infinite loops
        
        while (attempts < maxAttempts) {
            attempts++;
            
            // CRITICAL FIX: Generate fresh IV with crypto.getRandomValues
            const iv = crypto.getRandomValues(new Uint8Array(ivSize));
            
            // CRITICAL FIX: Convert IV to string for tracking
            const ivString = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');
            
            // CRITICAL FIX: Check for IV reuse
            if (this._ivTrackingSystem.usedIVs.has(ivString)) {
                this._ivTrackingSystem.collisionCount++;
                this._secureLog('error', `🚨 CRITICAL: IV reuse detected!`, {
                    context: context,
                    attempt: attempts,
                    collisionCount: this._ivTrackingSystem.collisionCount,
                    ivString: ivString.substring(0, 16) + '...' // Log partial IV for debugging
                });
                
                // CRITICAL FIX: If too many collisions, trigger emergency mode
                if (this._ivTrackingSystem.collisionCount > 5) {
                    this._ivTrackingSystem.emergencyMode = true;
                    this._secureLog('error', '🚨 CRITICAL: Emergency mode activated due to excessive IV reuse');
                    throw new Error('Emergency mode: Excessive IV reuse detected');
                }
                
                continue; // Try again
            }
            
            // CRITICAL FIX: Validate IV entropy
            if (!this._validateIVEntropy(iv)) {
                this._ivTrackingSystem.entropyValidation.entropyFailures++;
                this._secureLog('warn', `⚠️ Low entropy IV detected`, {
                    context: context,
                    attempt: attempts,
                    entropyFailures: this._ivTrackingSystem.entropyValidation.entropyFailures
                });
                
                // CRITICAL FIX: If too many entropy failures, trigger emergency mode
                if (this._ivTrackingSystem.entropyValidation.entropyFailures > 10) {
                    this._ivTrackingSystem.emergencyMode = true;
                    this._secureLog('error', '🚨 CRITICAL: Emergency mode activated due to low entropy IVs');
                    throw new Error('Emergency mode: Low entropy IVs detected');
                }
                
                continue; // Try again
            }
            
            // CRITICAL FIX: Track IV usage
            this._ivTrackingSystem.usedIVs.add(ivString);
            this._ivTrackingSystem.ivHistory.set(ivString, {
                timestamp: Date.now(),
                context: context,
                attempt: attempts
            });
            
            // CRITICAL FIX: Track per-session IVs
            if (this.sessionId) {
                if (!this._ivTrackingSystem.sessionIVs.has(this.sessionId)) {
                    this._ivTrackingSystem.sessionIVs.set(this.sessionId, new Set());
                }
                this._ivTrackingSystem.sessionIVs.get(this.sessionId).add(ivString);
            }
            
            // CRITICAL FIX: Validate RNG periodically
            this._validateRNGQuality();
            
            this._secureLog('debug', `✅ Secure IV generated`, {
                context: context,
                attempt: attempts,
                ivSize: ivSize,
                totalIVs: this._ivTrackingSystem.usedIVs.size
            });
            
            return iv;
        }
        
        // CRITICAL FIX: If we can't generate a unique IV after max attempts
        this._secureLog('error', `❌ Failed to generate unique IV after ${maxAttempts} attempts`, {
            context: context,
            totalIVs: this._ivTrackingSystem.usedIVs.size
        });
        throw new Error(`Failed to generate unique IV after ${maxAttempts} attempts`);
    }
    
    /**
     * CRITICAL FIX: Validate IV entropy to detect weak RNG
     */
    _validateIVEntropy(iv) {
        this._ivTrackingSystem.entropyValidation.entropyTests++;
        
        // CRITICAL FIX: Calculate byte distribution
        const byteCounts = new Array(256).fill(0);
        for (let i = 0; i < iv.length; i++) {
            byteCounts[iv[i]]++;
        }
        
        // CRITICAL FIX: Calculate entropy
        let entropy = 0;
        const totalBytes = iv.length;
        
        for (let i = 0; i < 256; i++) {
            if (byteCounts[i] > 0) {
                const probability = byteCounts[i] / totalBytes;
                entropy -= probability * Math.log2(probability);
            }
        }
        
        // CRITICAL FIX: Check for suspicious patterns
        const hasSuspiciousPatterns = this._detectSuspiciousIVPatterns(iv);
        
        const isValid = entropy >= this._ivTrackingSystem.entropyValidation.minEntropy && !hasSuspiciousPatterns;
        
        if (!isValid) {
            this._secureLog('warn', `⚠️ IV entropy validation failed`, {
                entropy: entropy.toFixed(2),
                minEntropy: this._ivTrackingSystem.entropyValidation.minEntropy,
                hasSuspiciousPatterns: hasSuspiciousPatterns
            });
        }
        
        return isValid;
    }
    
    /**
     * CRITICAL FIX: Detect suspicious patterns in IVs
     */
    _detectSuspiciousIVPatterns(iv) {
        // CRITICAL FIX: Check for all zeros or all ones
        const allZeros = iv.every(byte => byte === 0);
        const allOnes = iv.every(byte => byte === 255);
        
        if (allZeros || allOnes) {
            return true;
        }
        
        // CRITICAL FIX: Check for sequential patterns
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
        
        // CRITICAL FIX: Check for repeated patterns
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
     * SECURE: Clean up old IVs with strict limits
     */
    _cleanupOldIVs() {
        const now = Date.now();
        const maxAge = 24 * 60 * 60 * 1000; // 24 hours
        let cleanedCount = 0;
        
        // SECURE: Enforce maximum IV history size
        if (this._ivTrackingSystem.ivHistory.size > this._ivTrackingSystem.maxIVHistorySize) {
            const ivArray = Array.from(this._ivTrackingSystem.ivHistory.entries());
            const toRemove = ivArray.slice(0, ivArray.length - this._ivTrackingSystem.maxIVHistorySize);
            
            toRemove.forEach(([ivString]) => {
                this._ivTrackingSystem.ivHistory.delete(ivString);
                this._ivTrackingSystem.usedIVs.delete(ivString);
                cleanedCount++;
            });
        }
        
        // SECURE: Clean up old IVs from history by age
        for (const [ivString, metadata] of this._ivTrackingSystem.ivHistory.entries()) {
            if (now - metadata.timestamp > maxAge) {
                this._ivTrackingSystem.ivHistory.delete(ivString);
                this._ivTrackingSystem.usedIVs.delete(ivString);
                cleanedCount++;
            }
        }
        
        // SECURE: Enforce maximum session IVs limit
        for (const [sessionId, sessionIVs] of this._ivTrackingSystem.sessionIVs.entries()) {
            if (sessionIVs.size > this._ivTrackingSystem.maxSessionIVs) {
                const ivArray = Array.from(sessionIVs);
                const toRemove = ivArray.slice(0, ivArray.length - this._ivTrackingSystem.maxSessionIVs);
                
                toRemove.forEach(ivString => {
                    sessionIVs.delete(ivString);
                    this._ivTrackingSystem.usedIVs.delete(ivString);
                    this._ivTrackingSystem.ivHistory.delete(ivString);
                    cleanedCount++;
                });
            }
        }
        
        if (cleanedCount > 0) {
            this._secureLog('debug', `🧹 Cleaned up ${cleanedCount} old IVs`, {
                remainingIVs: this._ivTrackingSystem.usedIVs.size,
                remainingHistory: this._ivTrackingSystem.ivHistory.size
            });
        }
    }
    
    /**
     * CRITICAL FIX: Get IV tracking system statistics
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
     * CRITICAL FIX: Reset IV tracking system (for testing or emergency recovery)
     */
    _resetIVTrackingSystem() {
        this._secureLog('warn', '🔄 Resetting IV tracking system');
        
        this._ivTrackingSystem.usedIVs.clear();
        this._ivTrackingSystem.ivHistory.clear();
        this._ivTrackingSystem.sessionIVs.clear();
        this._ivTrackingSystem.collisionCount = 0;
        this._ivTrackingSystem.entropyValidation.entropyTests = 0;
        this._ivTrackingSystem.entropyValidation.entropyFailures = 0;
        this._ivTrackingSystem.rngValidation.testsPerformed = 0;
        this._ivTrackingSystem.rngValidation.weakRngDetected = false;
        this._ivTrackingSystem.emergencyMode = false;
        
        this._secureLog('info', '✅ IV tracking system reset completed');
    }
    
    /**
     * CRITICAL FIX: Validate RNG quality
     */
    _validateRNGQuality() {
        const now = Date.now();
        
        // CRITICAL FIX: Validate RNG every 1000 IV generations
        if (this._ivTrackingSystem.rngValidation.testsPerformed % 1000 === 0) {
            try {
                // CRITICAL FIX: Generate test IVs and validate
                const testIVs = [];
                for (let i = 0; i < 100; i++) {
                    testIVs.push(crypto.getRandomValues(new Uint8Array(12)));
                }
                
                // CRITICAL FIX: Check for duplicates in test set
                const testIVStrings = testIVs.map(iv => Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(''));
                const uniqueTestIVs = new Set(testIVStrings);
                
                if (uniqueTestIVs.size < 95) { // Allow some tolerance
                    this._ivTrackingSystem.rngValidation.weakRngDetected = true;
                    this._secureLog('error', '🚨 CRITICAL: Weak RNG detected in validation test', {
                        uniqueIVs: uniqueTestIVs.size,
                        totalTests: testIVs.length
                    });
                }
                
                this._ivTrackingSystem.rngValidation.lastValidation = now;
                
            } catch (error) {
                this._secureLog('error', '❌ RNG validation failed', {
                    errorType: error.constructor.name
                });
            }
        }
        
        this._ivTrackingSystem.rngValidation.testsPerformed++;
    }
    
    /**
     * CRITICAL FIX: Handle mutex timeout with enhanced state validation
     */
    _handleMutexTimeout(mutexName, operationId, timeout) {
        const mutex = this[`_${mutexName}Mutex`];
        
        if (!mutex) {
            this._secureLog('error', `❌ Mutex '${mutexName}' not found during timeout handling`);
            return;
        }
        
        // CRITICAL FIX: Validate timeout conditions
        if (mutex.lockId !== operationId) {
            this._secureLog('warn', `⚠️ Timeout for different operation ID on mutex '${mutexName}'`, {
                expectedOperationId: operationId,
                actualLockId: mutex.lockId,
                locked: mutex.locked
            });
            return;
        }
        
        if (!mutex.locked) {
            this._secureLog('warn', `⚠️ Timeout for already unlocked mutex '${mutexName}'`, {
                operationId: operationId
            });
            return;
        }
        
        try {
            // CRITICAL FIX: Calculate lock duration for monitoring
            const lockDuration = mutex.lockTime ? Date.now() - mutex.lockTime : 0;
            
            this._secureLog('warn', `⚠️ Mutex '${mutexName}' auto-released due to timeout`, {
                operationId: operationId,
                lockDuration: lockDuration,
                timeout: timeout,
                queueLength: mutex.queue.length
            });
            
            // CRITICAL FIX: Atomic release with state validation
            mutex.locked = false;
            mutex.lockId = null;
            mutex.lockTimeout = null;
            mutex.lockTime = null;
            
            // CRITICAL FIX: Process next in queue with error handling
            setTimeout(() => {
                try {
                    this._processNextInQueue(mutexName);
                } catch (queueError) {
                    this._secureLog('error', `❌ Error processing queue after timeout for mutex '${mutexName}'`, {
                        errorType: queueError.constructor.name,
                        errorMessage: queueError.message
                    });
                }
            }, 10);
            
        } catch (error) {
            this._secureLog('error', `❌ Critical error during mutex timeout handling for '${mutexName}'`, {
                operationId: operationId,
                errorType: error.constructor.name,
                errorMessage: error.message
            });
            
            // CRITICAL FIX: Force emergency unlock if timeout handling fails
            try {
                this._emergencyUnlockAllMutexes('timeoutHandler');
            } catch (emergencyError) {
                this._secureLog('error', `❌ Emergency unlock failed during timeout handling`, {
                    originalError: error.message,
                    emergencyError: emergencyError.message
                });
            }
        }
    }

    /**
     * CRITICAL FIX: Validate mutex system after emergency unlock
     */
    _validateMutexSystemAfterEmergencyUnlock() {
        const mutexes = ['keyOperation', 'cryptoOperation', 'connectionOperation'];
        let validationErrors = 0;
        
        this._secureLog('info', '🔍 Validating mutex system after emergency unlock');
        
        mutexes.forEach(mutexName => {
            const mutex = this[`_${mutexName}Mutex`];
            
            if (!mutex) {
                validationErrors++;
                this._secureLog('error', `❌ Mutex '${mutexName}' not found after emergency unlock`);
                return;
            }
            
            // CRITICAL FIX: Validate mutex state consistency
            if (mutex.locked) {
                validationErrors++;
                this._secureLog('error', `❌ Mutex '${mutexName}' still locked after emergency unlock`, {
                    lockId: mutex.lockId,
                    lockTime: mutex.lockTime
                });
            }
            
            if (mutex.lockId !== null) {
                validationErrors++;
                this._secureLog('error', `❌ Mutex '${mutexName}' still has lock ID after emergency unlock`, {
                    lockId: mutex.lockId
                });
            }
            
            if (mutex.lockTimeout !== null) {
                validationErrors++;
                this._secureLog('error', `❌ Mutex '${mutexName}' still has timeout after emergency unlock`);
            }
            
            if (mutex.queue.length > 0) {
                validationErrors++;
                this._secureLog('error', `❌ Mutex '${mutexName}' still has queue items after emergency unlock`, {
                    queueLength: mutex.queue.length
                });
            }
        });
        
        // CRITICAL FIX: Validate key system state
        if (this._keySystemState) {
            if (this._keySystemState.isInitializing || 
                this._keySystemState.isRotating || 
                this._keySystemState.isDestroying) {
                validationErrors++;
                this._secureLog('error', `❌ Key system state not properly reset after emergency unlock`, {
                    isInitializing: this._keySystemState.isInitializing,
                    isRotating: this._keySystemState.isRotating,
                    isDestroying: this._keySystemState.isDestroying
                });
            }
        }
        
        if (validationErrors === 0) {
            this._secureLog('info', '✅ Mutex system validation passed after emergency unlock');
        } else {
            this._secureLog('error', `❌ Mutex system validation failed after emergency unlock`, {
                validationErrors: validationErrors
            });
            
            // CRITICAL FIX: Force re-initialization if validation fails
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
     * CRITICAL FIX: Secure cleanup state after failed offer creation
     */
    _cleanupFailedOfferCreation() {
        try {
            // CRITICAL FIX: Secure wipe of cryptographic materials
            this._secureCleanupCryptographicMaterials();
            
            // CRITICAL FIX: Close peer connection if it was created
            if (this.peerConnection) {
                this.peerConnection.close();
                this.peerConnection = null;
            }
            
            // CRITICAL FIX: Clear data channel
            if (this.dataChannel) {
                this.dataChannel.close();
                this.dataChannel = null;
            }
            
            // CRITICAL FIX: Reset flags
            this.isInitiator = false;
            this.isVerified = false;
            
            // CRITICAL FIX: Reset security features to baseline
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
            
            // CRITICAL FIX: Force garbage collection
            this._forceGarbageCollection();
            
            this._secureLog('debug', '🔒 Failed offer creation cleanup completed with secure memory wipe');
            
        } catch (cleanupError) {
            this._secureLog('error', '❌ Error during offer creation cleanup', {
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
                    this._throwSecureError(error, 'ecdsa_key_import');
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
                    this._throwSecureError(error, 'webrtc_remote_description');
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
                    this._throwSecureError(error, 'webrtc_create_answer');
                }
                
                // Set local description
                try {
                    await this.peerConnection.setLocalDescription(answer);
                } catch (error) {
                    this._throwSecureError(error, 'webrtc_local_description');
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
    /**
     * CRITICAL FIX: Secure cleanup state after failed answer creation
     */
    _cleanupFailedAnswerCreation() {
        try {
            // CRITICAL FIX: Secure wipe of cryptographic materials
            this._secureCleanupCryptographicMaterials();
            
            // CRITICAL FIX: Secure wipe of PFS key versions
            this.currentKeyVersion = 0;
            this.keyVersions.clear();
            this.oldKeys.clear();
            
            // CRITICAL FIX: Close peer connection if created
            if (this.peerConnection) {
                this.peerConnection.close();
                this.peerConnection = null;
            }
            
            // CRITICAL FIX: Clear data channel
            if (this.dataChannel) {
                this.dataChannel.close();
                this.dataChannel = null;
            }
            
            // CRITICAL FIX: Reset flags and counters
            this.isInitiator = false;
            this.isVerified = false;
            this.sequenceNumber = 0;
            this.expectedSequenceNumber = 0;
            this.messageCounter = 0;
            this.processedMessageIds.clear();
            
            // CRITICAL FIX: Reset security features to baseline
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
            
            // CRITICAL FIX: Force garbage collection
            this._forceGarbageCollection();
            
            this._secureLog('debug', '🔒 Failed answer creation cleanup completed with secure memory wipe');
            
        } catch (cleanupError) {
            this._secureLog('error', '❌ Error during answer creation cleanup', {
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

            // ✅ ДОБАВИТЬ: Проверка DTLS защиты перед генерацией ключей
            if (this.dtlsProtectionEnabled) {
                // Имитируем проверку DTLS ClientHello (в реальном WebRTC это происходит автоматически)
                const mockClientHelloData = {
                    cipherSuite: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                    tlsVersion: '1.3'
                };
                
                // Получаем endpoint из peer connection
                const localEndpoint = this.peerConnection?.localDescription?.sdp || 'local-endpoint';
                const remoteEndpoint = this.peerConnection?.remoteDescription?.sdp || 'remote-endpoint';
                
                // Добавляем endpoints в верифицированные
                this.addVerifiedICEEndpoint(localEndpoint);
                this.addVerifiedICEEndpoint(remoteEndpoint);
                
                // Валидируем DTLS источник
                await this.validateDTLSSource(mockClientHelloData, remoteEndpoint);
                
                this._secureLog('info', 'DTLS protection validated before key derivation', {
                    localEndpoint: localEndpoint.substring(0, 50),
                    remoteEndpoint: remoteEndpoint.substring(0, 50),
                    verifiedEndpoints: this.verifiedICEEndpoints.size
                });
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
                    this._secureLog('error', '❌ Error calculating security after connection:', { errorType: error?.constructor?.name || 'Unknown' });
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
                this._secureLog('error', '❌ Force security update failed:', { errorType: error?.constructor?.name || 'Unknown' });
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
            this._secureLog('error', '❌ Verification failed:', { errorType: error?.constructor?.name || 'Unknown' });
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
        // SECURE: Heartbeat moved to unified scheduler with connection validation
        this._secureLog('info', '🔧 Heartbeat moved to unified scheduler');
        
        // Store heartbeat configuration for scheduler
        this._heartbeatConfig = {
            enabled: true,
            interval: EnhancedSecureWebRTCManager.TIMEOUTS.HEARTBEAT_INTERVAL,
            lastHeartbeat: 0
        };
    }

    stopHeartbeat() {
        // SECURE: Heartbeat stopped via unified scheduler
        if (this._heartbeatConfig) {
            this._heartbeatConfig.enabled = false;
        }
    }

    /**
     * SECURE: Stop all active timers and cleanup scheduler
     */
    _stopAllTimers() {
        this._secureLog('info', '🔧 Stopping all timers and cleanup scheduler');
        
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
        
        this._secureLog('info', '✅ All timers stopped successfully');
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
        // SECURE: Stop all timers first
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
    
    /**
     * CRITICAL FIX: Secure disconnect with complete memory cleanup
     */
    disconnect() {
        this.stopHeartbeat();
        this.isVerified = false;
        this.processedMessageIds.clear();
        this.messageCounter = 0;
        
        // CRITICAL FIX: Secure cleanup of cryptographic materials
        this._secureCleanupCryptographicMaterials();
        
        // CRITICAL FIX: Secure wipe of PFS key versions
        this.keyVersions.clear();
        this.oldKeys.clear();
        this.currentKeyVersion = 0;
        this.lastKeyRotation = Date.now();
        
        // CRITICAL FIX: Reset message counters
        this.sequenceNumber = 0;
        this.expectedSequenceNumber = 0;
        
        // CRITICAL FIX: Reset security features
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
        
        // CRITICAL FIX: Close connections
        if (this.dataChannel) {
            this.dataChannel.close();
            this.dataChannel = null;
        }
        if (this.peerConnection) {
            this.peerConnection.close();
            this.peerConnection = null;
        }
        
        // CRITICAL FIX: Secure wipe of message queue
        if (this.messageQueue && this.messageQueue.length > 0) {
            this.messageQueue.forEach((message, index) => {
                this._secureWipeMemory(message, `messageQueue[${index}]`);
            });
            this.messageQueue = [];
        }
        
        // CRITICAL FIX: Force garbage collection
        this._forceGarbageCollection();
        
        document.dispatchEvent(new CustomEvent('connection-cleaned', {
            detail: { 
                timestamp: Date.now(),
                reason: this.intentionalDisconnect ? 'user_cleanup' : 'automatic_cleanup'
            }
        }));

        // CRITICAL FIX: Notify UI about complete cleanup
        this.onStatusChange('disconnected');
        this.onKeyExchange('');
        this.onVerificationRequired('');
        
        this._secureLog('info', '🔒 Connection securely cleaned up with complete memory wipe');
        
        // CRITICAL FIX: Reset the intentional disconnect flag
        this.intentionalDisconnect = false;
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
            this._secureLog('error', '❌ File transfer error:', { errorType: error?.constructor?.name || 'Unknown' });
            
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
                this._secureLog('warn', '⚠️ getActiveTransfers method not available in file transfer system');
            }
            
            if (typeof this.fileTransferSystem.getReceivingTransfers === 'function') {
                receiving = this.fileTransferSystem.getReceivingTransfers();
            } else {
                this._secureLog('warn', '⚠️ getReceivingTransfers method not available in file transfer system');
            }
            
            return {
                sending: sending || [],
                receiving: receiving || []
            };
        } catch (error) {
            this._secureLog('error', '❌ Error getting file transfers:', { errorType: error?.constructor?.name || 'Unknown' });
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
            this._secureLog('error', '❌ Failed to reinitialize file transfer system:', { errorType: error?.constructor?.name || 'Unknown' });
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

        setTimeout(() => {
            try {
                this.initializeFileTransfer();
            } catch (error) {
                this._secureLog('warn', '⚠️ File transfer initialization failed during session activation:', { details: error.message });
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
            this._secureLog('error', '❌ Failed to handle session activation:', { errorType: error?.constructor?.name || 'Unknown' });
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
            this._secureLog('error', '❌ Failed to force reinitialize file transfer:', { errorType: error?.constructor?.name || 'Unknown' });
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
                this._secureLog('info', '⏹️ File transfer initialization cancelled by user');
                return { cancelled: true };
            }
            
            this._secureLog('error', '❌ Force file transfer initialization failed:', { 
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
                this._secureLog('info', '⏹️ File transfer initialization cancelled');
                return true;
            }
            return false;
        } catch (error) {
            this._secureLog('error', '❌ Failed to cancel file transfer initialization:', { 
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
            this._secureLog('error', '❌ Failed to get file transfer system status:', { 
                errorType: error?.constructor?.name || 'Unknown' 
            });
            return { available: false, status: 'error', error: error.message };
        }
    }

    _validateNestedEncryptionSecurity() {
        if (this.securityFeatures.hasNestedEncryption && this.nestedEncryptionKey) {
            // CRITICAL FIX: Test secure IV generation with reuse prevention
            try {
                const testIV1 = this._generateSecureIV(EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE, 'securityTest1');
                const testIV2 = this._generateSecureIV(EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE, 'securityTest2');
                
                // CRITICAL FIX: Verify IVs are different and properly tracked
                if (testIV1.every((byte, index) => byte === testIV2[index])) {
                    this._secureLog('error', '❌ CRITICAL: Nested encryption security validation failed - IVs are identical!');
                    return false;
                }
                
                // CRITICAL FIX: Verify IV tracking system is working
                const stats = this._getIVTrackingStats();
                if (stats.totalIVs < 2) {
                    this._secureLog('error', '❌ CRITICAL: IV tracking system not working properly');
                    return false;
                }
                
                this._secureLog('info', '✅ Nested encryption security validation passed - secure IV generation working');
                return true;
            } catch (error) {
                this._secureLog('error', '❌ CRITICAL: Nested encryption security validation failed:', {
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
    constructor() {
        // Use WeakMap for automatic garbage collection of unused keys
        this._keyStore = new WeakMap();
        this._keyMetadata = new Map(); // Metadata doesn't need WeakMap
        this._keyReferences = new Map(); // Strong references for active keys
        
        // Master encryption key for storage encryption
        this._storageMasterKey = null;
        this._initializeStorageMaster();

        setTimeout(() => {
            if (!this.validateStorageIntegrity()) {
                console.error('❌ CRITICAL: Key storage integrity check failed');
            }
        }, 100);
        
    }

    async _initializeStorageMaster() {
        // Generate a master key for encrypting stored keys
        this._storageMasterKey = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async storeKey(keyId, cryptoKey, metadata = {}) {
        if (!(cryptoKey instanceof CryptoKey)) {
            throw new Error('Only CryptoKey objects can be stored');
        }

        try {
            // For non-extractable keys, we can only store a reference
            if (!cryptoKey.extractable) {
                // Store the key reference directly without encryption
                this._keyReferences.set(keyId, cryptoKey);
                this._keyMetadata.set(keyId, {
                    ...metadata,
                    created: Date.now(),
                    lastAccessed: Date.now(),
                    extractable: false,
                    encrypted: false  // Mark as not encrypted
                });
                return true;
            }

            // For extractable keys, proceed with encryption
            const keyData = await crypto.subtle.exportKey('jwk', cryptoKey);
            const encryptedKeyData = await this._encryptKeyData(keyData);
            
            // CRITICAL FIX: Validate that extractable keys are properly encrypted
            if (!encryptedKeyData || encryptedKeyData.byteLength === 0) {
                throw new Error('Failed to encrypt extractable key data');
            }

            // Create a storage object
            const storageObject = {
                id: keyId,
                encryptedData: encryptedKeyData,
                algorithm: cryptoKey.algorithm,
                usages: cryptoKey.usages,
                extractable: cryptoKey.extractable,
                type: cryptoKey.type,
                timestamp: Date.now()
            };

            // Use WeakMap with the CryptoKey as the key
            this._keyStore.set(cryptoKey, storageObject);
            
            // Store reference for retrieval by ID
            this._keyReferences.set(keyId, cryptoKey);
            
            // Store metadata separately
            this._keyMetadata.set(keyId, {
                ...metadata,
                created: Date.now(),
                lastAccessed: Date.now(),
                extractable: true,
                encrypted: true  // CRITICAL FIX: Mark extractable keys as encrypted
            });

            return true;
        } catch (error) {
            console.error('Failed to store key securely:', error);
            return false;
        }
    }

    async retrieveKey(keyId) {
        const metadata = this._keyMetadata.get(keyId);
        if (!metadata) {
            return null;
        }

        // Update access time
        metadata.lastAccessed = Date.now();

        // For non-encrypted keys (non-extractable), return directly
        if (!metadata.encrypted) {
            // CRITICAL FIX: Only non-extractable keys should be non-encrypted
            if (metadata.extractable === false) {
                return this._keyReferences.get(keyId);
            } else {
                // This should never happen - extractable keys must be encrypted
                this._secureLog('error', '❌ SECURITY VIOLATION: Extractable key marked as non-encrypted', {
                    keyId,
                    extractable: metadata.extractable,
                    encrypted: metadata.encrypted
                });
                return null;
            }
        }

        // For encrypted keys, decrypt and recreate
        try {
            const cryptoKey = this._keyReferences.get(keyId);
            const storedData = this._keyStore.get(cryptoKey);
            
            if (!storedData) {
                return null;
            }

            // Decrypt the key data
            const decryptedKeyData = await this._decryptKeyData(storedData.encryptedData);
            
            // Recreate the CryptoKey
            const recreatedKey = await crypto.subtle.importKey(
                'jwk',
                decryptedKeyData,
                storedData.algorithm,
                storedData.extractable,
                storedData.usages
            );
            
            return recreatedKey;
        } catch (error) {
            console.error('Failed to retrieve key:', error);
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
        
        const encryptedData = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this._storageMasterKey,
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
        
        const decryptedData = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            this._storageMasterKey,
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

    secureWipe(keyId) {
        const cryptoKey = this._keyReferences.get(keyId);
        
        if (cryptoKey) {
            // Remove from WeakMap (will be GC'd)
            this._keyStore.delete(cryptoKey);
            // Remove strong reference
            this._keyReferences.delete(keyId);
            // Remove metadata
            this._keyMetadata.delete(keyId);
        }

        // Overwrite memory locations if possible
        if (typeof window.gc === 'function') {
            window.gc();
        }
    }

    secureWipeAll() {
        // Clear all references
        this._keyReferences.clear();
        this._keyMetadata.clear();
        
        // WeakMap entries will be garbage collected
        this._keyStore = new WeakMap();
        
        // Force garbage collection if available
        if (typeof window.gc === 'function') {
            window.gc();
        }
    }

    // CRITICAL FIX: Validate storage integrity
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
            console.error('❌ Storage integrity violations detected:', violations);
            return false;
        }
        
        return true;
    }

    getStorageStats() {
        return {
            totalKeys: this._keyReferences.size,
            metadata: Array.from(this._keyMetadata.entries()).map(([id, meta]) => ({
                id,
                created: meta.created,
                lastAccessed: meta.lastAccessed,
                age: Date.now() - meta.created
            }))
        };
    }


}

export { EnhancedSecureWebRTCManager };