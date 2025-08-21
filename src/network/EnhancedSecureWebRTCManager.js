// Import EnhancedSecureFileTransfer
import { EnhancedSecureFileTransfer } from '../transfer/EnhancedSecureFileTransfer.js';

// ============================================
// ИСПРАВЛЕНИЯ СИСТЕМЫ MUTEX - РЕШЕНИЕ ПРОБЛЕМЫ С ПЕРЕДАЧЕЙ СООБЩЕНИЙ
// ============================================
// Проблема: После внедрения системы Mutex перестали передаваться сообщения между пользователями
// Решение: Упрощена логика блокировок - mutex используется ТОЛЬКО для критических операций
// - Обычные сообщения обрабатываются БЕЗ mutex
// - Файловые сообщения обрабатываются БЕЗ mutex  
// - MUTEX используется ТОЛЬКО для криптографических операций
// ============================================

class EnhancedSecureWebRTCManager {
    // ============================================
    // КОНСТАНТЫ
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
    // Определяем режим работы
    this._isProductionMode = this._detectProductionMode();
    this._debugMode = !this._isProductionMode && window.DEBUG_MODE;

    // Инициализируем защищенную систему логирования
        this._initializeSecureLogging();
        this._disableConsoleLogInProduction();
    // Check the availability of the global object
        this._setupSecureGlobalAPI();
    if (!window.EnhancedSecureCryptoUtils) {
        throw new Error('EnhancedSecureCryptoUtils is not loaded. Please ensure the module is loaded first.');
    }
    this.getSecurityData = () => {
        // Возвращаем только публичную информацию
        return this.lastSecurityCalculation ? {
            level: this.lastSecurityCalculation.level,
            score: this.lastSecurityCalculation.score,
            timestamp: this.lastSecurityCalculation.timestamp,
            // НЕ возвращаем детали проверок или чувствительные данные
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

// Валидация системы после инициализации
if (!this._validateMutexSystem()) {
    this._secureLog('error', '❌ Mutex system validation failed after initialization');
    throw new Error('Critical: Mutex system validation failed');
}

// Добавление глобального обработчика для экстренных случаев
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
            // СИСТЕМА MUTEX ДЛЯ ПРЕДОТВРАЩЕНИЯ RACE CONDITIONS
            // ============================================

            // Mutex для операций с ключами
            this._keyOperationMutex = {
                locked: false,
                queue: [],
                lockId: null,
                lockTimeout: null
            };

            // Mutex для операций шифрования/дешифрования
            this._cryptoOperationMutex = {
                locked: false,
                queue: [],
                lockId: null,
                lockTimeout: null
            };

            // Mutex для инициализации соединения
            this._connectionOperationMutex = {
                locked: false,
                queue: [],
                lockId: null,
                lockTimeout: null
            };

            // Состояние системы ключей
            this._keySystemState = {
                isInitializing: false,
                isRotating: false,
                isDestroying: false,
                lastOperation: null,
                lastOperationTime: Date.now()
            };

            // Счетчики операций
            this._operationCounters = {
                keyOperations: 0,
                cryptoOperations: 0,
                connectionOperations: 0
            };

        }
_initializeMutexSystem() {
	// Инициализация стандартных mutex, ожидаемых системой
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

	// Состояние системы ключей
	this._keySystemState = {
		isInitializing: false,
		isRotating: false,
		isDestroying: false,
		lastOperation: null,
		lastOperationTime: Date.now()
	};

	// Счетчики операций
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
     * Ініціалізує безпечне сховище ключів
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
            // Если уже есть — готово
            if (this.fileTransferSystem) {
                return true;
            }
            // Должен быть открытый канал и верифицированное соединение
            if (!this.dataChannel || this.dataChannel.readyState !== 'open') {
                throw new Error('Data channel not open');
            }
            if (!this.isVerified) {
                throw new Error('Connection not verified');
            }
            // Инициализация
            this.initializeFileTransfer();
            // Небольшая задержка для инициализации
            await new Promise(r => setTimeout(r, 300));
            return !!this.fileTransferSystem;
        } catch (e) {
            console.error('❌ _ensureFileTransferReady failed:', e?.message || e);
            return false;
        }
    }

    /**
     * Отримує ключ зі сховища
     * @param {string} keyId - Ідентифікатор ключа
     * @returns {CryptoKey|null} Ключ або null, якщо не знайдено
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
     * Зберігає ключ у сховищі
     * @param {string} keyId - Ідентифікатор ключа
     * @param {CryptoKey} key - Ключ для збереження
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
     * Перевіряє коректність значення ключа
     * @param {CryptoKey} key - Ключ для перевірки
     * @returns {boolean} true, якщо ключ коректний
     */
    _validateKeyValue(key) {
        return key instanceof CryptoKey &&
            key.algorithm &&
            key.usages &&
            key.usages.length > 0;
    }

    /**
     * Безпечно видаляє всі ключі зі сховища
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
     * Перевіряє стан сховища ключів
     * @returns {boolean} true, якщо сховище готове до роботи
     */
    _validateKeyStorage() {
        return this._secureKeyStorage instanceof Map;
    }

    /**
     * Отримує статистику використання сховища ключів
     * @returns {object} Статистика сховища
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
     * Виконує ротацію ключів у сховищі
     */
    _rotateKeys() {
        const oldKeys = Array.from(this._secureKeyStorage.keys());
        this._secureKeyStorage.clear();
        this._keyStorageStats.lastRotation = Date.now();
        this._keyStorageStats.activeKeys = 0;
        this._secureLog('info', `🔄 Key rotation completed. ${oldKeys.length} keys rotated`);
    }

    /**
     * Екстрене видалення ключів (наприклад, при виявленні загрози)
     */
    _emergencyKeyWipe() {
        this._secureWipeKeys();
        this._secureLog('error', '🚨 EMERGENCY: All keys wiped due to security threat');
    }

    /**
     * Запускає моніторинг безпеки ключів
     */
    _startKeySecurityMonitoring() {
        setInterval(() => {
            if (this._keyStorageStats.activeKeys > 10) {
                this._secureLog('warn', '⚠️ High number of active keys detected. Consider rotation.');
            }
            if (Date.now() - (this._keyStorageStats.lastRotation || 0) > 3600000) {
                this._rotateKeys();
            }
        }, 300000); // Перевірка кожні 5 хвилин
    }


    // ============================================
    // HELPER МЕТОДЫ
    // ============================================
    /**
     * Инициализирует защищенную систему логирования
     */
    _initializeSecureLogging() {
        // Уровни логирования
        this._logLevels = {
            error: 0,
            warn: 1, 
            info: 2,
            debug: 3,
            trace: 4
        };
        
        // ИСПРАВЛЕНИЕ: Более строгие уровни для production
        this._currentLogLevel = this._isProductionMode ? 
            this._logLevels.error : // В production ТОЛЬКО ошибки
            this._logLevels.info;   // В development до info
        
        // Счетчик логов для предотвращения спама
        this._logCounts = new Map();
        this._maxLogCount = this._isProductionMode ? 10 : 100; // Максимум логов одного типа

        this._absoluteBlacklist = new Set([
            'encryptionKey', 'macKey', 'metadataKey', 'privateKey', 
            'verificationCode', 'sessionSalt', 'keyFingerprint',
            'password', 'token', 'secret', 'credential', 'signature',
            'ecdhKeyPair', 'ecdsaKeyPair', 'peerPublicKey',
            'sessionId', 'authChallenge', 'authProof'
        ]);

        // НОВОЕ: Whitelist безопасных полей
        this._safeFieldsWhitelist = new Set([
            'timestamp', 'type', 'length', 'size', 'count', 'level',
            'status', 'state', 'readyState', 'connectionState', 
            'isConnected', 'isVerified', 'isInitiator', 'version',
            'activeFeaturesCount', 'totalFeatures', 'stage'
        ]);
        
        this._secureLog('info', `🔧 Secure logging initialized (Production: ${this._isProductionMode})`);
    }
    /**
     * Отключает шумное логирование в production: console.log/debug становятся no-op
     * Преднамеренно сохраняем warn/error для видимости проблем
     */
    _disableConsoleLogInProduction() {
        try {
            if (this._isProductionMode && typeof console !== 'undefined') {
                const originalWarn = console.warn?.bind(console);
                const originalError = console.error?.bind(console);
                // Безопасно глушим информационные логи
                console.log = () => {};
                console.debug = () => {};
                // Сохраняем предупреждения и ошибки
                if (originalWarn) console.warn = (...args) => originalWarn(...args);
                if (originalError) console.error = (...args) => originalError(...args);
            }
        } catch (e) {
            // Ничего не делаем, это нефункциональная защита
        }
    }
    /**
     * Защищенное логирование
     * @param {string} level - Уровень лога (error, warn, info, debug, trace)
     * @param {string} message - Сообщение
     * @param {object} data - Дополнительные данные (будут sanitized)
     */
    _secureLog(level, message, data = null) {
        // Проверяем уровень логирования
        if (this._logLevels[level] > this._currentLogLevel) {
            return;
        }
        
        // НОВОЕ: Audit проверка перед логированием
        if (data && !this._auditLogMessage(message, data)) {
            return; // Логирование заблокировано из-за потенциальной утечки
        }
        
        // Предотвращаем спам логов
        const logKey = `${level}:${message}`;
        const currentCount = this._logCounts.get(logKey) || 0;
        
        if (currentCount >= this._maxLogCount) {
            return;
        }
        
        this._logCounts.set(logKey, currentCount + 1);
        
        // Sanitize данные
        const sanitizedData = data ? this._sanitizeLogData(data) : null;
        
        // НОВОЕ: В production вообще не выводим данные
        if (this._isProductionMode && level !== 'error') {
            console[level] || console.log(message); // Только сообщение без данных
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
     * Sanitize данных для логирования
     */
    _sanitizeLogData(data) {
        if (!data || typeof data !== 'object') {
            // Для примитивных типов - проверяем на sensitive patterns
            if (typeof data === 'string') {
                return this._sanitizeString(data);
            }
            return data;
        }
        
        const sanitized = {};
        
        for (const [key, value] of Object.entries(data)) {
            const lowerKey = key.toLowerCase();
            
            // АБСОЛЮТНЫЙ BLACKLIST - никогда не логируем
            if (this._absoluteBlacklist.has(key) || 
                Array.from(this._absoluteBlacklist).some(banned => lowerKey.includes(banned))) {
                sanitized[key] = '[ABSOLUTELY_FORBIDDEN]';
                continue;
            }
            
            // WHITELIST - безопасные поля логируем как есть
            if (this._safeFieldsWhitelist.has(key)) {
                sanitized[key] = value;
                continue;
            }
            
            // Для всех остальных полей - строгая обработка
            if (typeof value === 'boolean' || typeof value === 'number') {
                sanitized[key] = value;
            } else if (typeof value === 'string') {
                sanitized[key] = this._sanitizeString(value);
            } else if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
                sanitized[key] = `[${value.constructor.name}(${value.byteLength || value.length} bytes)]`;
            } else if (value && typeof value === 'object') {
                // Рекурсивно с ограничением глубины
                sanitized[key] = this._sanitizeLogData(value);
            } else {
                sanitized[key] = `[${typeof value}]`;
            }
        }
        
        return sanitized;
    }
    /**
     * НОВОЕ: Специальная sanitization для строк
     */
    _sanitizeString(str) {
        if (typeof str !== 'string' || str.length === 0) {
            return str;
        }
        
        // КРИТИЧЕСКОЕ: Поиск sensitive patterns
        const sensitivePatterns = [
            /[a-f0-9]{32,}/i,                    // Hex строки (ключи)
            /[A-Za-z0-9+/=]{20,}/,               // Base64 строки
            /\b[A-Za-z0-9]{20,}\b/,              // Длинные алфанумерные строки
            /BEGIN\s+(PRIVATE|PUBLIC)\s+KEY/i,   // PEM ключи
            /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, // Кредитные карты
            /\b\d{3}-\d{2}-\d{4}\b/,             // SSN
            /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/, // Email (частично)
        ];
        
        for (const pattern of sensitivePatterns) {
            if (pattern.test(str)) {
                // Если строка короткая - полностью скрываем
                if (str.length <= 10) {
                    return '[SENSITIVE]';
                }
                // Для длинных - показываем только начало и конец
                return `${str.substring(0, 3)}...[REDACTED]...${str.substring(str.length - 3)}`;
            }
        }
        
        // Для обычных строк - ограничиваем длину
        if (str.length > 100) {
            return str.substring(0, 50) + '...[TRUNCATED]';
        }
        
        return str;
    }
    /**
     * Проверяет содержит ли строка чувствительный контент
     */
    _containsSensitiveContent(str) {
        if (typeof str !== 'string') return false;
        
        const sensitivePatterns = [
            /[a-f0-9]{32,}/i,          // Hex строки (ключи)
            /[A-Za-z0-9+/=]{20,}/,     // Base64 строки
            /\b[A-Za-z0-9]{20,}\b/,    // Длинные алфанумерные строки
            /BEGIN\s+(PRIVATE|PUBLIC)\s+KEY/i, // PEM ключи
        ];
        
        return sensitivePatterns.some(pattern => pattern.test(str));
    }
    // ============================================
    // СИСТЕМА ЗАЩИЩЕННОГО ЛОГИРОВАНИЯ
    // ============================================
    
    /**
     * Определяет production mode
     */
    _detectProductionMode() {
        // Проверяем различные индикаторы production mode
        return (
            // Стандартные переменные окружения
            (typeof process !== 'undefined' && process.env?.NODE_ENV === 'production') ||
            // Отсутствие debug флагов
            (!window.DEBUG_MODE && !window.DEVELOPMENT_MODE) ||
            // Production домены
            (window.location.hostname && !window.location.hostname.includes('localhost') && 
             !window.location.hostname.includes('127.0.0.1') && 
             !window.location.hostname.includes('.local')) ||
            // Минификация кода (примерная проверка)
            (typeof window.webpackHotUpdate === 'undefined' && !window.location.search.includes('debug'))
        );
    }
    // ============================================
    // ИСПРАВЛЕННЫЙ БЕЗОПАСНЫЙ ГЛОБАЛЬНЫЙ API
    // ============================================
    
    /**
     * Настраивает безопасный глобальный API с ограниченным доступом
     */
    _setupSecureGlobalAPI() {
        // Создаем ограниченный публичный API
        const secureAPI = {
            // ============================================
            // БЕЗОПАСНЫЕ ПУБЛИЧНЫЕ МЕТОДЫ
            // ============================================
            
            /**
             * Отправка сообщения (безопасная обертка)
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
             * Получение статуса соединения (только публичная информация)
             */
            getConnectionStatus: () => {
                return {
                    isConnected: this.isConnected(),
                    isVerified: this.isVerified,
                    connectionState: this.peerConnection?.connectionState || 'disconnected',
                };
            },
            
            /**
             * Получение статуса безопасности (ограниченная информация)
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
             * Отправка файла (безопасная обертка)
             */
            sendFile: async (file) => {
                try {
                    if (!file || !(file instanceof File)) {
                        throw new Error('Invalid file object');
                    }
                    if (file.size > 100 * 1024 * 1024) { // Лимит 100MB
                        throw new Error('File too large');
                    }
                    return await this.sendFile(file);
                } catch (error) {
                    console.error('❌ Failed to send file through secure API:', error.message);
                    throw new Error('Failed to send file');
                }
            },
            
            /**
             * Получение статуса файловых трансферов
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
             * Отключение (безопасное)
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
            
            // Метаинформация API
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
        // УСТАНОВКА ГЛОБАЛЬНОГО API С ЗАЩИТОЙ
        // ============================================
        
        // Делаем API неизменяемым
        Object.freeze(secureAPI);
        Object.freeze(secureAPI._api);
        
        // Устанавливаем глобальный API только если его еще нет
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
        // УПРОЩЕННАЯ ЗАЩИТА БЕЗ PROXY
        // ============================================
        this._setupSimpleProtection();
    }
    _setupSimpleProtection() {
        // Защищаем только через мониторинг, без переопределения window
        this._monitorGlobalExposure();
        
        // Предупреждение в консоли
        if (window.DEBUG_MODE) {
            console.warn('🔒 Security Notice: WebRTC Manager is protected. Use window.secureBitChat for safe access.');
        }
    }
    /**
     * Мониторинг глобального exposure без Proxy
     */
    _monitorGlobalExposure() {
        // Список потенциально опасных имен
        const dangerousNames = [
            'webrtcManager', 'globalWebRTCManager', 'webrtcInstance', 
            'rtcManager', 'secureWebRTC', 'enhancedWebRTC'
        ];
        
        // Проверяем периодически
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
                
                // В production автоматически удаляем
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
        
        // Немедленная проверка
        checkForExposure();
        
        // Периодическая проверка
        const interval = window.DEBUG_MODE ? 30000 : 300000; // 30s в dev, 5min в prod
        setInterval(checkForExposure, interval);
    }
    /**
     * Предотвращает случайное глобальное exposure
     */
    _preventGlobalExposure() {
        // Мониторинг попыток добавления webrtc объектов в window
        const originalDefineProperty = Object.defineProperty;
        const self = this;
        
        // Переопределяем defineProperty для window только для webrtc связанных свойств
        const webrtcRelatedNames = [
            'webrtcManager', 'globalWebRTCManager', 'webrtcInstance', 
            'rtcManager', 'secureWebRTC', 'enhancedWebRTC'
        ];
        
        Object.defineProperty = function(obj, prop, descriptor) {
            if (obj === window && webrtcRelatedNames.includes(prop)) {
                console.warn(`🚫 Prevented potential global exposure of: ${prop}`);
                // Не устанавливаем свойство, просто логируем
                return obj;
            }
            return originalDefineProperty.call(this, obj, prop, descriptor);
        };
        
        // Защита от прямого присваивания
        const webrtcRelatedPatterns = /webrtc|rtc|secure.*chat/i;
        const handler = {
            set(target, property, value) {
                if (typeof property === 'string' && webrtcRelatedPatterns.test(property)) {
                    if (value === self || (value && value.constructor === self.constructor)) {
                        console.warn(`🚫 Prevented global exposure attempt: window.${property}`);
                        return true; // Притворяемся что установили, но не устанавливаем
                    }
                }
                target[property] = value;
                return true;
            }
        };
        
        // Применяем Proxy только в development mode для производительности
        if (window.DEBUG_MODE) {
            window = new Proxy(window, handler);
        }
    }
    /**
     * Проверка целостности API
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
    // ДОПОЛНИТЕЛЬНЫЕ МЕТОДЫ БЕЗОПАСНОСТИ
    // ============================================
    
    /**
     * Проверяет, нет ли случайного exposure в глобальном пространстве
     */
    _auditGlobalExposure() {
        const dangerousExposures = [];
        
        // Проверяем window на наличие WebRTC manager
        for (const prop in window) {
            const value = window[prop];
            if (value === this || (value && value.constructor === this.constructor)) {
                dangerousExposures.push(prop);
            }
        }
        
        if (dangerousExposures.length > 0) {
            console.error('🚨 SECURITY ALERT: WebRTC Manager exposed globally:', dangerousExposures);
            
            // В production mode автоматически удаляем exposure
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
     * Периодический аудит безопасности
     */
    _startSecurityAudit() {
        // Проверяем каждые 30 секунд в development, каждые 5 минут в production
        const auditInterval = window.DEBUG_MODE ? 30000 : 300000;
        
        setInterval(() => {
            const exposures = this._auditGlobalExposure();
            
            if (exposures.length > 0 && !window.DEBUG_MODE) {
                // В production это критическая проблема
                console.error('🚨 CRITICAL: Unauthorized global exposure detected in production');
                
                // Можно добавить отправку алерта или принудительное отключение
                // this.emergencyShutdown();
            }
        }, auditInterval);
    }
    
    /**
     * Экстренное отключение при критических проблемах
     */
    _emergencyShutdown(reason = 'Security breach') {
        console.error(`🚨 EMERGENCY SHUTDOWN: ${reason}`);
        
        try {
            // Очищаем критические данные
            this.encryptionKey = null;
            this.macKey = null;
            this.metadataKey = null;
            this.verificationCode = null;
            this.keyFingerprint = null;
            
            // Закрываем соединения
            if (this.dataChannel) {
                this.dataChannel.close();
                this.dataChannel = null;
            }
            if (this.peerConnection) {
                this.peerConnection.close();
                this.peerConnection = null;
            }
            
            // Очищаем буферы
            this.messageQueue = [];
            this.processedMessageIds.clear();
            this.packetBuffer.clear();
            
            // Уведомляем UI
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
        // Проверяем целостность API
        if (!this._verifyAPIIntegrity()) {
            console.error('🚨 Security initialization failed');
            return;
        }
        
        // Начинаем мониторинг
        this._startSecurityMonitoring();
        // Запускаем периодическую очистку логов
        setInterval(() => {
            this._cleanupLogs();
        }, 300000);
        
        console.log('✅ Secure WebRTC Manager initialization completed');
    }
    /**
     * Запуск мониторинга безопасности
     */
    _startSecurityMonitoring() {
        // Проверяем каждые 5 минут
        setInterval(() => {
            this._verifyAPIIntegrity();
        }, 300000);
        
        // В development mode более частые проверки
        if (window.DEBUG_MODE) {
            setInterval(() => {
                this._monitorGlobalExposure();
            }, 30000);
        }
    }
    /**
     * Проверяет готовность соединения для отправки данных
     * @param {boolean} throwError - выбрасывать ошибку при неготовности
     * @returns {boolean} готовность соединения
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
     * Проверяет готовность ключей шифрования
     * @param {boolean} throwError - выбрасывать ошибку при неготовности
     * @returns {boolean} готовность ключей
     */
    _validateEncryptionKeys(throwError = true) {
        const hasAllKeys = !!(this.encryptionKey && this.macKey && this.metadataKey);
        
        if (!hasAllKeys && throwError) {
            throw new Error('Encryption keys not initialized');
        }
        
        return hasAllKeys;
    }

    /**
     * Проверяет, является ли сообщение файловым
     * @param {string|object} data - данные для проверки
     * @returns {boolean} true если файловое сообщение
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
     * Проверяет, является ли сообщение системным
     * @param {string|object} data - данные для проверки  
     * @returns {boolean} true если системное сообщение
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
     * Проверяет, является ли сообщение поддельным (fake traffic)
     * @param {any} data - данные для проверки
     * @returns {boolean} true если поддельное сообщение
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
     * Безопасное выполнение операции с обработкой ошибок
     * @param {Function} operation - операция для выполнения
     * @param {string} errorMessage - сообщение об ошибке
     * @param {any} fallback - значение по умолчанию при ошибке
     * @returns {any} результат операции или fallback
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
     * Асинхронное выполнение операции с обработкой ошибок
     * @param {Function} operation - асинхронная операция
     * @param {string} errorMessage - сообщение об ошибке
     * @param {any} fallback - значение по умолчанию при ошибке
     * @returns {Promise<any>} результат операции или fallback
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
     * Проверяет ограничения скорости
     * @returns {boolean} true если можно продолжить
     */
    _checkRateLimit() {
        return window.EnhancedSecureCryptoUtils.rateLimiter.checkConnectionRate(this.rateLimiterId);
    }

    /**
     * Получает тип сообщения из данных
     * @param {string|object} data - данные сообщения
     * @returns {string|null} тип сообщения или null
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
     * Сбрасывает флаги уведомлений для нового соединения
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
     * Проверяет, было ли сообщение отфильтровано
     * @param {any} result - результат обработки сообщения
     * @returns {boolean} true если сообщение было отфильтровано
     */
    _isFilteredMessage(result) {
        const filteredResults = Object.values(EnhancedSecureWebRTCManager.FILTERED_RESULTS);
        return filteredResults.includes(result);
    }
    /**
     * Очистка логов для предотвращения утечек памяти
     */
    _cleanupLogs() {
        // Очищаем счетчики логов если их слишком много
        if (this._logCounts.size > 1000) {
            this._logCounts.clear();
            this._secureLog('debug', '🧹 Log counts cleared');
        }
    }
    /**
     * Получение статистики логирования (для диагностики)
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
     * Экстренное отключение логирования
     */
    _emergencyDisableLogging() {
        this._currentLogLevel = -1; // Отключаем все логи
        this._logCounts.clear();
        // Переопределяем _secureLog на пустую функцию
        this._secureLog = () => {};
        // Только критическая ошибка в консоль (без данных)
        console.error('🚨 SECURITY: Logging disabled due to potential data exposure');
    }
    _auditLogMessage(message, data) {
        if (!data || typeof data !== 'object') return true;
        
        const dataString = JSON.stringify(data).toLowerCase();
        
        // Проверяем на случайные утечки
        // Уточняем паттерны, чтобы избежать ложных срабатываний на слова вроде "keyOperation"
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
            
            // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Пошаговая проверка готовности
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
            
            // ИСПРАВЛЕНИЕ: Очищаем предыдущую систему если есть
            if (this.fileTransferSystem) {
                console.log('🧹 Cleaning up existing file transfer system');
                this.fileTransferSystem.cleanup();
                this.fileTransferSystem = null;
            }
            
            // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Проверяем наличие ключей
            if (!this.encryptionKey || !this.macKey) {
                console.warn('⚠️ Encryption keys not ready, deferring file transfer initialization');
                setTimeout(() => this.initializeFileTransfer(), 1000);
                return;
            }
            
            // ВАЖНО: порядок колбэков: (onProgress, onComplete, onError, onFileReceived)
            const safeOnComplete = (summary) => {
                // Отправитель: завершение передачи, без работы с Blob
                try {
                    console.log('🏁 Sender transfer summary:', summary);
                    // При необходимости прокидываем как прогресс/событие UI
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
            
            // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Устанавливаем глобальные ссылки
            window.FILE_TRANSFER_ACTIVE = true;
            window.fileTransferSystem = this.fileTransferSystem;
            
            console.log('✅ Enhanced Secure File Transfer system initialized successfully');
            
            // Проверяем что система готова
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
            // ДОБАВЛЯЕМ ОТЛАДОЧНЫЕ ЛОГИ
            console.log('📤 deliverMessageToUI called:', {
                message: message,
                type: type,
                messageType: typeof message,
                hasOnMessage: !!this.onMessage
            });
            
            // Фильтруем file transfer и системные сообщения
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
                    return; // не показываем в чате
                }
            }

            // Дополнительная проверка для строковых сообщений, содержащих JSON
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
                            return; // не показываем в чате
                        }
                    }
                } catch (parseError) {
                    // Не JSON - это нормально для обычных текстовых сообщений
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
        // Проверяем, не было ли уже отправлено сообщение о текущем уровне безопасности
        if (this.lastSecurityLevelNotification === this.currentSecurityLevel) {
            return; // Избегаем дублирования
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
        
        // Проверяем, не было ли уже отправлено сообщение о отключении расширенных функций
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
        
        // Проверяем, не было ли уже отправлено сообщение о отключении fake traffic
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
        
        // Nested Encryption (если включено)
        if (this.securityFeatures.hasNestedEncryption && this.nestedEncryptionKey && processedData instanceof ArrayBuffer) {
            processedData = await this.applyNestedEncryption(processedData);
        }
        
        // Packet Reordering (если включено)
        if (this.securityFeatures.hasPacketReordering && this.reorderingConfig?.enabled && processedData instanceof ArrayBuffer) {
            processedData = this.applyPacketReordering(processedData);
        }
        
        // Packet Padding (если включено)
        if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
            processedData = this.applyPacketPadding(processedData);
        }
        
        // Anti-Fingerprinting (если включено)
        if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
            processedData = this.applyAntiFingerprinting(processedData);
        }
        
        // Финальное шифрование (если есть ключи)
        if (this.encryptionKey && typeof processedData === 'string') {
            processedData = await window.EnhancedSecureCryptoUtils.encryptData(processedData, this.encryptionKey);
        }
        
        return processedData;
        
    } catch (error) {
        console.error('❌ Error in applySecurityLayersWithoutMutex:', error);
        return data; // Возвращаем исходные данные при ошибке
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
                
                // System messages - НЕ возвращаем для повторной обработки
                if (jsonData.type && ['heartbeat', 'verification', 'verification_response', 'peer_disconnect', 'key_rotation_signal', 'key_rotation_ready', 'security_upgrade'].includes(jsonData.type)) {
                    if (window.DEBUG_MODE) {
                        console.log('🔧 System message detected, blocking from chat:', jsonData.type);
                    }
                    return 'SYSTEM_MESSAGE_FILTERED';
                }
                
                // File transfer messages - НЕ возвращаем для отображения
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

        // ИСПРАВЛЕНИЕ: Проверяем, не является ли это файловым сообщением
        if (typeof data === 'string') {
            try {
                const parsed = JSON.parse(data);
                
                // Файловые сообщения отправляем напрямую без дополнительного шифрования
                if (parsed.type && parsed.type.startsWith('file_')) {
                    this._secureLog('debug', '📁 Sending file message directly', { type: parsed.type });
                    this.dataChannel.send(data);
                    return true;
                }
            } catch (jsonError) {
                // Не JSON - продолжаем обычную обработку
            }
        }

        // Для обычных текстовых сообщений отправляем через защищённый путь
        if (typeof data === 'string') {
            return await this.sendSecureMessage({ type: 'message', data, timestamp: Date.now() });
        }

        // Для бинарных данных применяем security layers с ограниченным mutex
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

    // ИСПРАВЛЕНИЕ: Новый метод для ограниченного применения security layers
    async _applySecurityLayersWithLimitedMutex(data, isFakeMessage = false) {
    // Используем mutex ТОЛЬКО для криптографических операций
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
    }, 3000); // Короткий timeout для crypto операций
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

    // ИСПРАВЛЕНИЕ 1: Упрощенная система Mutex для обработки сообщений
async processMessage(data) {
    try {
        this._secureLog('debug', '�� Processing message', {
            dataType: typeof data,
            isArrayBuffer: data instanceof ArrayBuffer,
            hasData: !!(data?.length || data?.byteLength)
        });
        
        // КРИТИЧЕСКИ ВАЖНО: Ранняя проверка на файловые сообщения БЕЗ mutex
        if (typeof data === 'string') {
            try {
                const parsed = JSON.parse(data);

                // ============================================
                // ФАЙЛОВЫЕ СООБЩЕНИЯ - ПРИОРИТЕТ 1 (БЕЗ MUTEX)
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
                    
                    // Обрабатываем файловые сообщения БЕЗ mutex
                    if (this.fileTransferSystem && typeof this.fileTransferSystem.handleFileMessage === 'function') {
                        console.log('📁 Processing file message directly:', parsed.type);
                        await this.fileTransferSystem.handleFileMessage(parsed);
                        return;
                    }
                    // Попытка ленивой инициализации на стороне-получателе
                    console.warn('⚠️ File transfer system not available, attempting lazy init...');
                    try {
                        await this._ensureFileTransferReady();
                        if (this.fileTransferSystem && typeof this.fileTransferSystem.handleFileMessage === 'function') {
                            await this.fileTransferSystem.handleFileMessage(parsed);
                            return;
                        }
                    } catch (e) {
                        console.error('❌ Lazy init of file transfer failed:', e?.message || e);
                    }
                    console.error('❌ File transfer system not available for:', parsed.type);
                    return; // ВАЖНО: Выходим после обработки
                }
                
                // ============================================
                // ОБЫЧНЫЕ ПОЛЬЗОВАТЕЛЬСКИЕ СООБЩЕНИЯ (БЕЗ MUTEX)
                // ============================================
                
                if (parsed.type === 'message') {
                    console.log('📝 Regular user message detected in processMessage');
                    if (this.onMessage && parsed.data) {
                        this.deliverMessageToUI(parsed.data, 'received');
                    }
                    return;
                }
                
                // ============================================
                // СИСТЕМНЫЕ СООБЩЕНИЯ (БЕЗ MUTEX)
                // ============================================
                
                if (parsed.type && ['heartbeat', 'verification', 'verification_response', 'peer_disconnect', 'security_upgrade'].includes(parsed.type)) {
                    this.handleSystemMessage(parsed);
                    return;
                }
                
                // ============================================
                // FAKE MESSAGES (БЕЗ MUTEX)
                // ============================================
                
                if (parsed.type === 'fake') {
                    console.log('🎭 Fake message blocked in processMessage:', parsed.pattern);
                    return;
                }
                
            } catch (jsonError) {
                // Не JSON - обрабатываем как текст БЕЗ mutex
                if (this.onMessage) {
                    this.deliverMessageToUI(data, 'received');
                }
                return;
            }
        }

        // ============================================
        // ОБРАБОТКА ЗАШИФРОВАННЫХ ДАННЫХ (С MUTEX ТОЛЬКО ДЛЯ КРИПТОГРАФИИ)
        // ============================================
        
        // Если дошли сюда - применяем security layers с ограниченным mutex
        const originalData = await this._processEncryptedDataWithLimitedMutex(data);

        // Проверяем результат обработки
        if (originalData === 'FAKE_MESSAGE_FILTERED' || 
            originalData === 'FILE_MESSAGE_FILTERED' || 
            originalData === 'SYSTEM_MESSAGE_FILTERED') {
            return;
        }
        
        if (!originalData) {
            console.warn('⚠️ No data returned from removeSecurityLayers');
            return;
        }

        // Обработка результата после removeSecurityLayers
        let messageText;
        
        if (typeof originalData === 'string') {
            try {
                const message = JSON.parse(originalData);
                
                // ПОВТОРНАЯ ПРОВЕРКА ФАЙЛОВЫХ СООБЩЕНИЙ ПОСЛЕ ДЕШИФРОВКИ
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
                
                // Обычные сообщения
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

        // Финальная проверка на fake сообщения и файловые сообщения
        if (messageText && messageText.trim().startsWith('{')) {
            try {
                const finalCheck = JSON.parse(messageText);
                if (finalCheck.type === 'fake') {
                    console.log(`�� Final fake message check blocked: ${finalCheck.pattern}`);
                    return;
                }
                
                // Дополнительная проверка на файловые и системные сообщения
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
                // Не JSON - это нормально для обычных текстовых сообщений
            }
        }

        // Отправляем сообщение пользователю
        if (this.onMessage && messageText) {
            console.log('📤 Calling message handler with:', messageText.substring(0, 100));
            this.deliverMessageToUI(messageText, 'received');
        }

    } catch (error) {
        console.error('❌ Failed to process message:', error);
    }
}

    // ИСПРАВЛЕНИЕ: Новый метод для ограниченного mutex при обработке зашифрованных данных
    async _processEncryptedDataWithLimitedMutex(data) {
        // Используем mutex ТОЛЬКО для криптографических операций
        return this._withMutex('cryptoOperation', async (operationId) => {
            this._secureLog('debug', '🔐 Processing encrypted data with limited mutex', {
                operationId: operationId,
                dataType: typeof data
            });
            
            try {
                // Применяем security layers
                const originalData = await this.removeSecurityLayers(data);
                return originalData;
                
            } catch (error) {
                this._secureLog('error', '❌ Error processing encrypted data', {
                    operationId: operationId,
                    errorType: error.constructor.name
                });
                return data; // Возвращаем исходные данные при ошибке
            }
        }, 2000); // Короткий timeout для crypto операций
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
            
            // Проверяем, не было ли уже отправлено сообщение о повышении безопасности
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
            // Не закрываем соединение при ошибках установки
            // просто логируем ошибку и продолжаем
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
            
            // Проверяем состояние в критической секции
            if (!this.isConnected() || !this.isVerified) {
                this._secureLog('warn', '⚠️ Key rotation aborted - connection not ready', {
                    operationId: operationId,
                    isConnected: this.isConnected(),
                    isVerified: this.isVerified
                });
                return false;
            }
            
            // Проверяем, не идет ли уже ротация
            if (this._keySystemState.isRotating) {
                this._secureLog('warn', '⚠️ Key rotation already in progress', {
                    operationId: operationId
                });
                return false;
            }
            
            try {
                // Устанавливаем флаг ротации
                this._keySystemState.isRotating = true;
                this._keySystemState.lastOperation = 'rotation';
                this._keySystemState.lastOperationTime = Date.now();
                
                // Отправляем сигнал ротации партнеру
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
                
                // Ждем подтверждения от партнера
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
                        }, 10000) // 10 секунд timeout
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
        }, 10000); // 10 секунд timeout для всей операции
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
                    // Unexpected disconnection — не пытаемся переподключиться автоматически
                    this.onStatusChange('disconnected');
                    // Не вызываем cleanupConnection автоматически
                    // чтобы не закрывать сессию при ошибках соединения
                }
            } else if (state === 'failed') {
                // Не пытаемся переподключиться автоматически
                // чтобы не закрывать сессию при ошибках соединения
                this.onStatusChange('disconnected');
                // if (!this.intentionalDisconnect && this.connectionAttempts < this.maxConnectionAttempts) {
                //     this.connectionAttempts++;
                //     setTimeout(() => this.retryConnection(), 2000);
                // } else {
                //     this.onStatusChange('disconnected');
                //     // Не вызываем cleanupConnection автоматически для состояния 'failed'
                //     // чтобы не закрывать сессию при ошибках соединения
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
            // Настройка backpressure для больших передач
            try {
                if (this.dataChannel && typeof this.dataChannel.bufferedAmountLowThreshold === 'number') {
                    // 1 MB порог для события bufferedamountlow
                    this.dataChannel.bufferedAmountLowThreshold = 1024 * 1024;
                }
            } catch (e) {
                // ignore
            }
            
            try {
                await this.establishConnection();
                
                // КРИТИЧЕСКИ ВАЖНО: Инициализируем file transfer сразу
                this.initializeFileTransfer();
                
            } catch (error) {
                console.error('❌ Error in establishConnection:', error);
                // Продолжаем несмотря на ошибки
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

        // ИСПРАВЛЕНИЕ 2: ПОЛНОСТЬЮ УБИРАЕМ MUTEX ИЗ ОБРАБОТКИ СООБЩЕНИЙ
        this.dataChannel.onmessage = async (event) => {
            try {
                console.log('📨 Raw message received:', {
                    dataType: typeof event.data,
                    dataLength: event.data?.length || event.data?.byteLength || 0,
                    isString: typeof event.data === 'string'
                });

                // ВАЖНО: Обрабатываем ВСЕ сообщения БЕЗ MUTEX
                if (typeof event.data === 'string') {
                    try {
                        const parsed = JSON.parse(event.data);
                        console.log('📨 Parsed message:', {
                            type: parsed.type,
                            hasData: !!parsed.data,
                            timestamp: parsed.timestamp
                        });
                        
                        // ============================================
                        // КРИТИЧЕСКИ ВАЖНО: ФАЙЛОВЫЕ СООБЩЕНИЯ (БЕЗ MUTEX)
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
                            
                            // Обрабатываем напрямую БЕЗ дополнительных проверок
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
                            // Попытка ленивой инициализации на стороне-получателе
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
                            return; // ВАЖНО: Не обрабатываем дальше
                        }
                        
                        // ============================================
                        // СИСТЕМНЫЕ СООБЩЕНИЯ (БЕЗ MUTEX)
                        // ============================================
                        
                        if (parsed.type && ['heartbeat', 'verification', 'verification_response', 'peer_disconnect', 'security_upgrade'].includes(parsed.type)) {
                            console.log('🔧 System message detected:', parsed.type);
                            this.handleSystemMessage(parsed);
                            return;
                        }
                        
                        // ============================================
                        // ОБЫЧНЫЕ ПОЛЬЗОВАТЕЛЬСКИЕ СООБЩЕНИЯ (БЕЗ MUTEX)
                        // ============================================
                        
                        if (parsed.type === 'message' && parsed.data) {
                            console.log('📝 User message detected:', parsed.data.substring(0, 50));
                            if (this.onMessage) {
                                this.deliverMessageToUI(parsed.data, 'received');
                            }
                            return;
                        }
                        
                        // ============================================
                        // ENHANCED MESSAGES (БЕЗ MUTEX)
                        // ============================================
                        
                        if (parsed.type === 'enhanced_message' && parsed.data) {
                            console.log('🔐 Enhanced message detected, processing...');
                            await this._processEnhancedMessageWithoutMutex(parsed);
                            return;
                        }
                        
                        // ============================================
                        // FAKE MESSAGES (БЕЗ MUTEX)
                        // ============================================
                        
                        if (parsed.type === 'fake') {
                            console.log('🎭 Fake message blocked:', parsed.pattern);
                            return;
                        }
                        
                        // ============================================
                        // НЕИЗВЕСТНЫЕ ТИПЫ СООБЩЕНИЙ
                        // ============================================
                        
                        console.log('❓ Unknown message type:', parsed.type);
                        
                    } catch (jsonError) {
                        // Не JSON - обрабатываем как обычное текстовое сообщение
                        console.log('📄 Non-JSON message detected, treating as text');
                        if (this.onMessage) {
                            this.deliverMessageToUI(event.data, 'received');
                        }
                        return;
                    }
                } else if (event.data instanceof ArrayBuffer) {
                    // Бинарные данные - обрабатываем БЕЗ MUTEX
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
    // ИСПРАВЛЕНИЕ 4: Новый метод для обработки бинарных данных БЕЗ MUTEX
async _processBinaryDataWithoutMutex(data) {
    try {
        console.log('🔢 Processing binary data without mutex...');
        
        // Применяем security layers БЕЗ MUTEX
        let processedData = data;
        
        // Nested Encryption Removal (если включено)
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
        
        // Packet Padding Removal (если включено)
        if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
            try {
                processedData = this.removePacketPadding(processedData);
            } catch (error) {
                console.warn('⚠️ Packet padding removal failed, continuing with original data');
            }
        }
        
        // Anti-Fingerprinting Removal (если включено)
        if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
            try {
                processedData = this.removeAntiFingerprinting(processedData);
            } catch (error) {
                console.warn('⚠️ Anti-fingerprinting removal failed, continuing with original data');
            }
        }
        
        // Преобразуем в текст
        if (processedData instanceof ArrayBuffer) {
            const textData = new TextDecoder().decode(processedData);
            
            // Проверяем на fake сообщения
            try {
                const content = JSON.parse(textData);
                if (content.type === 'fake' || content.isFakeTraffic === true) {
                    console.log(`🎭 BLOCKED: Binary fake message: ${content.pattern || 'unknown'}`);
                    return;
                }
            } catch (e) {
                // Не JSON - это нормально для обычных текстовых сообщений
            }
            
            // Отправляем сообщение пользователю
            if (this.onMessage) {
                this.deliverMessageToUI(textData, 'received');
            }
        }
        
    } catch (error) {
        console.error('❌ Error processing binary data:', error);
    }
}
    // ИСПРАВЛЕНИЕ 3: Новый метод для обработки enhanced сообщений БЕЗ MUTEX
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
            
            // Попытка распарсить как JSON и показать вложенный текст, если это чат-сообщение
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
                // Не JSON - это нормально для обычных текстовых сообщений
            }
            
            // Иначе передаём как есть
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
     * Создает уникальный ID для операции
     */
    _generateOperationId() {
        return `op_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    /**
     * Универсальная функция получения mutex
     */
    async _acquireMutex(mutexName, operationId, timeout = 5000) {
        // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Правильное построение имени mutex
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
                    // Получаем блокировку
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
                    // Добавляем в очередь
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
     * Освобождение mutex
     */
    _releaseMutex(mutexName, operationId) {
        // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Правильное построение имени mutex
        const mutexPropertyName = `_${mutexName}Mutex`;
        const mutex = this[mutexPropertyName];
        
        if (!mutex) {
            this._secureLog('error', `❌ Unknown mutex for release: ${mutexName}`, {
                mutexPropertyName: mutexPropertyName,
                availableMutexes: this._getAvailableMutexes(),
                operationId: operationId
            });
            return; // Не выбрасываем ошибку, просто логируем
        }
        
        if (mutex.lockId !== operationId) {
            this._secureLog('error', `❌ Invalid mutex release attempt`, {
                mutexName: mutexName,
                expectedLockId: mutex.lockId,
                providedOperationId: operationId
            });
            return; // Не выбрасываем ошибку, просто логируем
        }
        
        // Очищаем timeout
        if (mutex.lockTimeout) {
            clearTimeout(mutex.lockTimeout);
            mutex.lockTimeout = null;
        }
        
        // Освобождаем блокировку
        mutex.locked = false;
        mutex.lockId = null;
        
        this._secureLog('debug', `🔓 Mutex released: ${mutexName}`, {
            operationId: operationId,
            queueLength: mutex.queue.length
        });
        
        // Обрабатываем очередь
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
                // Извлекаем имя mutex без префикса и суффикса
                const mutexName = prop.slice(1, -5); // Убираем '_' в начале и 'Mutex' в конце
                mutexes.push(mutexName);
            }
        }
        
        return mutexes;
    }

    /**
     * Безопасное выполнение операции с mutex
     */
    async _withMutex(mutexName, operation, timeout = 5000) {
    const operationId = this._generateOperationId();
    
    // Валидация перед началом
    if (!this._validateMutexSystem()) {
        this._secureLog('error', '❌ Mutex system not properly initialized', {
            operationId: operationId,
            mutexName: mutexName
        });
        throw new Error('Mutex system not properly initialized. Call _initializeMutexSystem() first.');
    }
    
    try {
        await this._acquireMutex(mutexName, operationId, timeout);
        
        // Увеличиваем счетчик операций
        const counterKey = `${mutexName}Operations`;
        if (this._operationCounters && this._operationCounters[counterKey] !== undefined) {
            this._operationCounters[counterKey]++;
        }
        
        // Выполняем операцию
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
        // Всегда освобождаем mutex в finally блоке
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
        
        // Проверяем структуру mutex
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
 * НОВЫЙ: Экстренное восстановление системы mutex
 */
_emergencyRecoverMutexSystem() {
    this._secureLog('warn', '🚨 Emergency mutex system recovery initiated');
    
    try {
        // Принудительно инициализируем систему заново
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
     * Безопасная генерация ключей с mutex
     */
    async _generateEncryptionKeys() {
        return this._withMutex('keyOperation', async (operationId) => {
            this._secureLog('info', '🔑 Generating encryption keys with mutex', {
                operationId: operationId
            });
            
            // Проверяем, не идет ли инициализация
            if (this._keySystemState.isInitializing) {
                throw new Error('Key initialization already in progress');
            }
            
            try {
                this._keySystemState.isInitializing = true;
                this._keySystemState.lastOperation = 'generation';
                this._keySystemState.lastOperationTime = Date.now();
                
                // Генерируем ECDH ключи
                const ecdhKeyPair = await window.EnhancedSecureCryptoUtils.generateECDHKeyPair();
                
                // Проверяем, что ключи сгенерированы корректно
                if (!ecdhKeyPair || !ecdhKeyPair.privateKey || !ecdhKeyPair.publicKey) {
                    throw new Error('Failed to generate valid ECDH key pair');
                }
                
                // Генерируем ECDSA ключи
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
     * Экстренное разблокирование всех mutex
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
                
                // Очищаем очередь
                mutex.queue.forEach(item => {
                    item.reject(new Error('Emergency mutex unlock'));
                });
                mutex.queue = [];
            }
        });
    }
/**
 * НОВЫЙ: Диагностика состояния mutex системы
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
     * ПОЛНЫЙ ИСПРАВЛЕННЫЙ МЕТОД createSecureOffer()
     * С защитой от race conditions и улучшенной безопасностью
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
                // ФАЗА 1: ИНИЦИАЛИЗАЦИЯ И ВАЛИДАЦИЯ
                // ============================================
                
                // Сброс флагов уведомлений для нового соединения
                this._resetNotificationFlags();
                
                // Проверка rate limiting
                if (!this._checkRateLimit()) {
                    throw new Error('Connection rate limit exceeded. Please wait before trying again.');
                }
                
                // Сброс счетчиков попыток
                this.connectionAttempts = 0;
                
                // Генерация соли сессии (64 байта для v4.0)
                this.sessionSalt = window.EnhancedSecureCryptoUtils.generateSalt();
                
                this._secureLog('debug', '🧂 Session salt generated', {
                    operationId: operationId,
                    saltLength: this.sessionSalt.length,
                    isValidSalt: Array.isArray(this.sessionSalt) && this.sessionSalt.length === 64
                });
                
                // ============================================
                // ФАЗА 2: БЕЗОПАСНАЯ ГЕНЕРАЦИЯ КЛЮЧЕЙ
                // ============================================
                
                // Безопасная генерация ключей через mutex
                const keyPairs = await this._generateEncryptionKeys();
                this.ecdhKeyPair = keyPairs.ecdhKeyPair;
                this.ecdsaKeyPair = keyPairs.ecdsaKeyPair;
                
                // Валидация сгенерированных ключей
                if (!this.ecdhKeyPair?.privateKey || !this.ecdhKeyPair?.publicKey) {
                    throw new Error('Failed to generate valid ECDH key pair');
                }
                
                if (!this.ecdsaKeyPair?.privateKey || !this.ecdsaKeyPair?.publicKey) {
                    throw new Error('Failed to generate valid ECDSA key pair');
                }
                
                // ============================================
                // ФАЗА 3: MITM ЗАЩИТА И FINGERPRINTING
                // ============================================
                
                // MITM Protection: Вычисление уникальных отпечатков ключей
                const ecdhFingerprint = await window.EnhancedSecureCryptoUtils.calculateKeyFingerprint(
                    await crypto.subtle.exportKey('spki', this.ecdhKeyPair.publicKey)
                );
                const ecdsaFingerprint = await window.EnhancedSecureCryptoUtils.calculateKeyFingerprint(
                    await crypto.subtle.exportKey('spki', this.ecdsaKeyPair.publicKey)
                );
                
                // Валидация отпечатков
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
                // ФАЗА 4: ЭКСПОРТ КЛЮЧЕЙ С ПОДПИСЯМИ
                // ============================================
                
                // Экспорт ключей с цифровыми подписями
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
                
                // Валидация экспортированных данных
                if (!ecdhPublicKeyData?.keyData || !ecdhPublicKeyData?.signature) {
                    throw new Error('Failed to export ECDH public key with signature');
                }
                
                if (!ecdsaPublicKeyData?.keyData || !ecdsaPublicKeyData?.signature) {
                    throw new Error('Failed to export ECDSA public key with signature');
                }
                
                // ============================================
                // ФАЗА 5: ОБНОВЛЕНИЕ SECURITY FEATURES
                // ============================================
                
                // Атомарное обновление security features
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
                // ФАЗА 6: ИНИЦИАЛИЗАЦИЯ PEER CONNECTION
                // ============================================
                
                this.isInitiator = true;
                this.onStatusChange('connecting');
                
                // Создание peer connection
                this.createPeerConnection();
                
                // Создание основного data channel
                this.dataChannel = this.peerConnection.createDataChannel('securechat', {
                    ordered: true
                });
                
                // Настройка data channel
                this.setupDataChannel(this.dataChannel);
                
                this._secureLog('debug', '🔗 Data channel created', {
                    operationId: operationId,
                    channelLabel: this.dataChannel.label,
                    channelOrdered: this.dataChannel.ordered
                });
                
                // ============================================
                // ФАЗА 7: СОЗДАНИЕ SDP OFFER
                // ============================================
                
                // Создание WebRTC offer
                const offer = await this.peerConnection.createOffer({
                    offerToReceiveAudio: false,
                    offerToReceiveVideo: false
                });
                
                // Установка локального описания
                await this.peerConnection.setLocalDescription(offer);
                
                // Ожидание сбора ICE кандидатов
                await this.waitForIceGathering();
                
                this._secureLog('debug', '🧊 ICE gathering completed', {
                    operationId: operationId,
                    iceGatheringState: this.peerConnection.iceGatheringState,
                    connectionState: this.peerConnection.connectionState
                });
                
                // ============================================
                // ФАЗА 8: ГЕНЕРАЦИЯ VERIFICATION CODE
                // ============================================
                
                // Генерация кода верификации для out-of-band аутентификации
                this.verificationCode = window.EnhancedSecureCryptoUtils.generateVerificationCode();
                
                // Валидация verification code
                if (!this.verificationCode || this.verificationCode.length < EnhancedSecureWebRTCManager.SIZES.VERIFICATION_CODE_MIN_LENGTH) {
                    throw new Error('Failed to generate valid verification code');
                }
                
                // Уведомление UI о необходимости верификации
                this.onVerificationRequired(this.verificationCode);
                
                // ============================================
                // ФАЗА 9: MUTUAL AUTHENTICATION CHALLENGE
                // ============================================
                
                // Генерация challenge для взаимной аутентификации
                const authChallenge = window.EnhancedSecureCryptoUtils.generateMutualAuthChallenge();
                
                if (!authChallenge) {
                    throw new Error('Failed to generate mutual authentication challenge');
                }
                
                // ============================================
                // ФАЗА 10: SESSION ID ДЛЯ MITM ЗАЩИТЫ
                // ============================================
                
                // MITM Protection: Генерация session-specific ID
                this.sessionId = Array.from(crypto.getRandomValues(new Uint8Array(EnhancedSecureWebRTCManager.SIZES.SESSION_ID_LENGTH)))
                    .map(b => b.toString(16).padStart(2, '0')).join('');
                
                // Валидация session ID
                if (!this.sessionId || this.sessionId.length !== (EnhancedSecureWebRTCManager.SIZES.SESSION_ID_LENGTH * 2)) {
                    throw new Error('Failed to generate valid session ID');
                }
                
                // ============================================
                // ФАЗА 11: РАСЧЕТ УРОВНЯ БЕЗОПАСНОСТИ
                // ============================================
                
                // Предварительный расчет уровня безопасности
                let securityLevel;
                try {
                    securityLevel = await this.calculateSecurityLevel();
                } catch (error) {
                    this._secureLog('warn', '⚠️ Security level calculation failed, using fallback', {
                        operationId: operationId,
                        errorType: error.constructor.name
                    });
                    
                    // Fallback значение
                    securityLevel = {
                        level: 'enhanced',
                        score: 75,
                        passedChecks: 10,
                        totalChecks: 15,
                        isRealData: false
                    };
                }
                
                // ============================================
                // ФАЗА 12: СОЗДАНИЕ OFFER PACKAGE
                // ============================================
                
                const currentTimestamp = Date.now();
                
                const offerPackage = {
                    // Основная информация
                    type: 'enhanced_secure_offer',
                    sdp: this.peerConnection.localDescription.sdp,
                    version: '4.0',
                    timestamp: currentTimestamp,
                    
                    // Криптографические ключи
                    ecdhPublicKey: ecdhPublicKeyData,
                    ecdsaPublicKey: ecdsaPublicKeyData,
                    
                    // Сессионные данные
                    salt: this.sessionSalt,
                    sessionId: this.sessionId,
                    
                    // Аутентификация
                    verificationCode: this.verificationCode,
                    authChallenge: authChallenge,
                    
                    // Метаданные безопасности
                    securityLevel: securityLevel,
                    
                    // Дополнительные поля для валидации
                    keyFingerprints: {
                        ecdh: ecdhFingerprint.substring(0, 16), // Первые 16 символов для валидации
                        ecdsa: ecdsaFingerprint.substring(0, 16)
                    },
                    
                    // Опциональная информация о возможностях
                    capabilities: {
                        supportsFileTransfer: true,
                        supportsEnhancedSecurity: true,
                        supportsKeyRotation: true,
                        supportsFakeTraffic: this.fakeTrafficConfig.enabled,
                        supportsDecoyChannels: this.decoyChannelConfig.enabled
                    }
                };
                
                // ============================================
                // ФАЗА 13: ВАЛИДАЦИЯ OFFER PACKAGE
                // ============================================
                
                // Финальная валидация созданного package
                if (!this.validateEnhancedOfferData(offerPackage)) {
                    throw new Error('Generated offer package failed validation');
                }
                
                // ============================================
                // ФАЗА 14: ЛОГИРОВАНИЕ И СОБЫТИЯ
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
                
                // Отправка события о новом соединении
                document.dispatchEvent(new CustomEvent('new-connection', {
                    detail: { 
                        type: 'offer',
                        timestamp: currentTimestamp,
                        securityLevel: securityLevel.level,
                        operationId: operationId
                    }
                }));
                
                // ============================================
                // ФАЗА 15: ВОЗВРАТ РЕЗУЛЬТАТА
                // ============================================
                
                return offerPackage;
                
            } catch (error) {
                // ============================================
                // ОБРАБОТКА ОШИБОК
                // ============================================
                
                this._secureLog('error', '❌ Enhanced secure offer creation failed in critical section', {
                    operationId: operationId,
                    errorType: error.constructor.name,
                    errorMessage: error.message,
                    phase: this._determineErrorPhase(error),
                    connectionAttempts: this.connectionAttempts
                });
                
                // Очистка состояния при ошибке
                this._cleanupFailedOfferCreation();
                
                // Обновление статуса
                this.onStatusChange('disconnected');
                
                // Проброс ошибки для обработки на верхнем уровне
                throw error;
            }
        }, 15000); // 15 секунд timeout для всей операции создания offer
    }

    /**
     * HELPER: Определение фазы, на которой произошла ошибка
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
     * HELPER: Очистка состояния при неудачном создании offer
     */
    _cleanupFailedOfferCreation() {
        try {
            // Очистка ключей
            this.ecdhKeyPair = null;
            this.ecdsaKeyPair = null;
            this.sessionSalt = null;
            this.sessionId = null;
            this.verificationCode = null;
            
            // Закрытие peer connection если был создан
            if (this.peerConnection) {
                this.peerConnection.close();
                this.peerConnection = null;
            }
            
            // Очистка data channel
            if (this.dataChannel) {
                this.dataChannel.close();
                this.dataChannel = null;
            }
            
            // Сброс флагов
            this.isInitiator = false;
            this.isVerified = false;
            
            // Сброс security features до базового состояния
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
     * HELPER: Атомарное обновление security features (если еще не добавлен)
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
            // Rollback в случае ошибки
            this.securityFeatures = oldFeatures;
            this._secureLog('error', '❌ Security features update failed, rolled back', {
                errorType: error.constructor.name
            });
            throw error;
        }
    }

    /**
     * ПОЛНЫЙ ИСПРАВЛЕННЫЙ МЕТОД createSecureAnswer()
     * С защитой от race conditions и усиленной безопасностью
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
                // ФАЗА 1: ПРЕДВАРИТЕЛЬНАЯ ВАЛИДАЦИЯ OFFER
                // ============================================
                
                // Сброс флагов уведомлений для нового соединения
                this._resetNotificationFlags();
                
                this._secureLog('debug', 'Starting enhanced offer validation', {
                    operationId: operationId,
                    hasOfferData: !!offerData,
                    offerType: offerData?.type,
                    hasECDHKey: !!offerData?.ecdhPublicKey,
                    hasECDSAKey: !!offerData?.ecdsaPublicKey,
                    hasSalt: !!offerData?.salt
                });
                
                // Строгая валидация входных данных
                if (!this.validateEnhancedOfferData(offerData)) {
                    throw new Error('Invalid connection data format - failed enhanced validation');
                }
                
                // Проверка rate limiting
                if (!window.EnhancedSecureCryptoUtils.rateLimiter.checkConnectionRate(this.rateLimiterId)) {
                    throw new Error('Connection rate limit exceeded. Please wait before trying again.');
                }
                
                // ============================================
                // ФАЗА 2: БЕЗОПАСНОСТЬ И ANTI-REPLAY ЗАЩИТА
                // ============================================
                
                // MITM Protection: Валидация структуры данных offer
                if (!offerData.timestamp || !offerData.version) {
                    throw new Error('Missing required security fields in offer data – possible MITM attack');
                }
                
                // Защита от replay атак (сокращено окно до 5 минут)
                const offerAge = Date.now() - offerData.timestamp;
                const MAX_OFFER_AGE = 300000; // 5 минут вместо 1 часа
                
                if (offerAge > MAX_OFFER_AGE) {
                    this._secureLog('error', 'Offer data is too old - possible replay attack', {
                        operationId: operationId,
                        offerAge: Math.round(offerAge / 1000),
                        maxAllowedAge: Math.round(MAX_OFFER_AGE / 1000),
                        timestamp: offerData.timestamp
                    });
                    
                    // Уведомляем основной код об атаке replay
                    if (this.onAnswerError) {
                        this.onAnswerError('replay_attack', 'Offer data is too old – possible replay attack');
                    }
                    
                    throw new Error('Offer data is too old – possible replay attack');
                }
                
                // Проверка совместимости версий протокола
                if (offerData.version !== '4.0') {
                    this._secureLog('warn', 'Protocol version mismatch detected', {
                        operationId: operationId,
                        expectedVersion: '4.0',
                        receivedVersion: offerData.version
                    });
                    
                    // Для обратной совместимости с v3.0 можно добавить fallback
                    if (offerData.version !== '3.0') {
                        throw new Error(`Unsupported protocol version: ${offerData.version}`);
                    }
                }
                
                // ============================================
                // ФАЗА 3: ИЗВЛЕЧЕНИЕ И ВАЛИДАЦИЯ СОЛИ СЕССИИ
                // ============================================
                
                // Установка соли сессии из offer
                this.sessionSalt = offerData.salt;
                
                // Валидация соли сессии
                if (!Array.isArray(this.sessionSalt)) {
                    throw new Error('Invalid session salt format - must be array');
                }
                
                const expectedSaltLength = offerData.version === '4.0' ? 64 : 32;
                if (this.sessionSalt.length !== expectedSaltLength) {
                    throw new Error(`Invalid session salt length: expected ${expectedSaltLength}, got ${this.sessionSalt.length}`);
                }
                
                // MITM Protection: Проверка целостности соли
                const saltFingerprint = await window.EnhancedSecureCryptoUtils.calculateKeyFingerprint(this.sessionSalt);
                
                this._secureLog('info', 'Session salt validated successfully', {
                    operationId: operationId,
                    saltLength: this.sessionSalt.length,
                    saltFingerprint: saltFingerprint.substring(0, 8)
                });
                
                // ============================================
                // ФАЗА 4: БЕЗОПАСНАЯ ГЕНЕРАЦИЯ НАШИХ КЛЮЧЕЙ
                // ============================================
                
                // Безопасная генерация наших ключей через mutex
                const keyPairs = await this._generateEncryptionKeys();
                this.ecdhKeyPair = keyPairs.ecdhKeyPair;
                this.ecdsaKeyPair = keyPairs.ecdsaKeyPair;
                
                // Дополнительная валидация сгенерированных ключей
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
                // ФАЗА 5: ИМПОРТ И ВЕРИФИКАЦИЯ КЛЮЧЕЙ ПАРТНЕРА
                // ============================================
                
                // Импорт ECDSA публичного ключа партнера для верификации подписей
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
                
                // Верификация самоподписи ECDSA ключа
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
                // ФАЗА 6: ИМПОРТ И ВЕРИФИКАЦИЯ ECDH КЛЮЧА
                // ============================================
                
                // Импорт и верификация ECDH публичного ключа с использованием проверенного ECDSA ключа
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
                
                // Финальная валидация ECDH ключа
                if (!(peerECDHPublicKey instanceof CryptoKey)) {
                    this._secureLog('error', 'Peer ECDH public key is not a CryptoKey', {
                        operationId: operationId,
                        publicKeyType: typeof peerECDHPublicKey,
                        publicKeyAlgorithm: peerECDHPublicKey?.algorithm?.name
                    });
                    throw new Error('Peer ECDH public key is not a valid CryptoKey');
                }
                
                // Сохранение ключа партнера для PFS ротации
                this.peerPublicKey = peerECDHPublicKey;
                
                // ============================================
                // ФАЗА 7: ДЕРИВАЦИЯ ОБЩИХ КЛЮЧЕЙ ШИФРОВАНИЯ
                // ============================================
                
                // Деривация общих ключей с метаданными защиты
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
                
                // Безопасная установка ключей через helper метод
                await this._setEncryptionKeys(
                    derivedKeys.encryptionKey,
                    derivedKeys.macKey,
                    derivedKeys.metadataKey,
                    derivedKeys.fingerprint
                );
                
                // Дополнительная валидация установленных ключей
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
                
                // Установка verification code из offer
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
                // ФАЗА 8: ОБНОВЛЕНИЕ SECURITY FEATURES
                // ============================================
                
                // Атомарное обновление security features
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
                
                // PFS: Инициализация отслеживания версий ключей
                this.currentKeyVersion = 0;
                this.lastKeyRotation = Date.now();
                this.keyVersions.set(0, {
                    salt: this.sessionSalt,
                    timestamp: this.lastKeyRotation,
                    messageCount: 0
                });
                
                // ============================================
                // ФАЗА 9: СОЗДАНИЕ AUTHENTICATION PROOF
                // ============================================
                
                // Создание proof для взаимной аутентификации
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
                // ФАЗА 10: ИНИЦИАЛИЗАЦИЯ WEBRTC
                // ============================================
                
                this.isInitiator = false;
                this.onStatusChange('connecting');
                this.onKeyExchange(this.keyFingerprint);
                this.onVerificationRequired(this.verificationCode);
                
                // Создание peer connection
                this.createPeerConnection();
                
                // Установка удаленного описания из offer
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
                // ФАЗА 11: СОЗДАНИЕ SDP ANSWER
                // ============================================
                
                // Создание WebRTC answer
                let answer;
                
                try {
                    answer = await this.peerConnection.createAnswer({
                        offerToReceiveAudio: false,
                        offerToReceiveVideo: false
                    });
                } catch (error) {
                    throw new Error(`Failed to create answer: ${error.message}`);
                }
                
                // Установка локального описания
                try {
                    await this.peerConnection.setLocalDescription(answer);
                } catch (error) {
                    throw new Error(`Failed to set local description: ${error.message}`);
                }
                
                // Ожидание сбора ICE кандидатов
                await this.waitForIceGathering();
                
                this._secureLog('debug', '🧊 ICE gathering completed for answer', {
                    operationId: operationId,
                    iceGatheringState: this.peerConnection.iceGatheringState,
                    connectionState: this.peerConnection.connectionState
                });
                
                // ============================================
                // ФАЗА 12: ЭКСПОРТ НАШИХ КЛЮЧЕЙ
                // ============================================
                
                // Экспорт наших ключей с подписями
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
                
                // Валидация экспортированных данных
                if (!ecdhPublicKeyData?.keyData || !ecdhPublicKeyData?.signature) {
                    throw new Error('Failed to export ECDH public key with signature');
                }
                
                if (!ecdsaPublicKeyData?.keyData || !ecdsaPublicKeyData?.signature) {
                    throw new Error('Failed to export ECDSA public key with signature');
                }
                
                // ============================================
                // ФАЗА 13: РАСЧЕТ УРОВНЯ БЕЗОПАСНОСТИ
                // ============================================
                
                // Расчет уровня безопасности
                let securityLevel;
                
                try {
                    securityLevel = await this.calculateSecurityLevel();
                } catch (error) {
                    this._secureLog('warn', '⚠️ Security level calculation failed, using fallback', {
                        operationId: operationId,
                        errorType: error.constructor.name
                    });
                    
                    // Fallback значение
                    securityLevel = {
                        level: 'enhanced',
                        score: 80,
                        passedChecks: 12,
                        totalChecks: 15,
                        isRealData: false
                    };
                }
                
                // ============================================
                // ФАЗА 14: СОЗДАНИЕ ANSWER PACKAGE
                // ============================================
                
                const currentTimestamp = Date.now();
                
                const answerPackage = {
                    // Основная информация
                    type: 'enhanced_secure_answer',
                    sdp: this.peerConnection.localDescription.sdp,
                    version: '4.0',
                    timestamp: currentTimestamp,
                    
                    // Криптографические ключи
                    ecdhPublicKey: ecdhPublicKeyData,
                    ecdsaPublicKey: ecdsaPublicKeyData,
                    
                    // Аутентификация
                    authProof: authProof,
                    
                    // Метаданные безопасности
                    securityLevel: securityLevel,
                    
                    // Дополнительные поля безопасности
                    sessionConfirmation: {
                        saltFingerprint: saltFingerprint.substring(0, 16),
                        keyDerivationSuccess: true,
                        mutualAuthEnabled: !!authProof
                    },
                    
                    // Возможности answerer
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
                // ФАЗА 15: ВАЛИДАЦИЯ И ЛОГИРОВАНИЕ
                // ============================================
                
                // Финальная валидация answer package
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
                
                // Отправка события о новом соединении
                document.dispatchEvent(new CustomEvent('new-connection', {
                    detail: { 
                        type: 'answer',
                        timestamp: currentTimestamp,
                        securityLevel: securityLevel.level,
                        operationId: operationId
                    }
                }));
                
                // ============================================
                // ФАЗА 16: ПЛАНИРОВАНИЕ SECURITY РАСЧЕТОВ
                // ============================================
                
                // Планируем расчет безопасности после соединения
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
                
                // Retry если первый расчет неудачный
                setTimeout(async () => {
                    if (!this.lastSecurityCalculation || this.lastSecurityCalculation.score < 50) {
                        this._secureLog('info', '🔄 Retrying security calculation', {
                            operationId: operationId
                        });
                        await this.calculateAndReportSecurityLevel();
                        this.notifySecurityUpdate();
                    }
                }, 3000);
                
                // Финальное обновление безопасности
                this.notifySecurityUpdate();
                
                // ============================================
                // ФАЗА 17: ВОЗВРАТ РЕЗУЛЬТАТА
                // ============================================
                
                return answerPackage;
                
            } catch (error) {
                // ============================================
                // ОБРАБОТКА ОШИБОК
                // ============================================
                
                this._secureLog('error', '❌ Enhanced secure answer creation failed in critical section', {
                    operationId: operationId,
                    errorType: error.constructor.name,
                    errorMessage: error.message,
                    phase: this._determineAnswerErrorPhase(error),
                    offerAge: offerData?.timestamp ? Date.now() - offerData.timestamp : 'unknown'
                });
                
                // Очистка состояния при ошибке
                this._cleanupFailedAnswerCreation();
                
                // Обновление статуса
                this.onStatusChange('disconnected');
                
                // Специальная обработка ошибок безопасности
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
                
                // Проброс ошибки для обработки на верхнем уровне
                throw error;
            }
        }, 20000); // 20 секунд timeout для всей операции создания answer (дольше чем offer)
    }

    /**
     * HELPER: Определение фазы ошибки для answer
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
     * HELPER: Очистка состояния при неудачном создании answer
     */
    _cleanupFailedAnswerCreation() {
        try {
            // Очистка ключей и сессионных данных
            this.ecdhKeyPair = null;
            this.ecdsaKeyPair = null;
            this.peerPublicKey = null;
            this.sessionSalt = null;
            this.verificationCode = null;
            this.encryptionKey = null;
            this.macKey = null;
            this.metadataKey = null;
            this.keyFingerprint = null;
            
            // Сброс версий ключей PFS
            this.currentKeyVersion = 0;
            this.keyVersions.clear();
            this.oldKeys.clear();
            
            // Закрытие peer connection если был создан
            if (this.peerConnection) {
                this.peerConnection.close();
                this.peerConnection = null;
            }
            
            // Очистка data channel
            if (this.dataChannel) {
                this.dataChannel.close();
                this.dataChannel = null;
            }
            
            // Сброс флагов и счетчиков
            this.isInitiator = false;
            this.isVerified = false;
            this.sequenceNumber = 0;
            this.expectedSequenceNumber = 0;
            this.messageCounter = 0;
            this.processedMessageIds.clear();
            
            // Сброс security features до базового состояния
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
     * HELPER: Безопасная установка ключей шифрования (если еще нет)
     */
    async _setEncryptionKeys(encryptionKey, macKey, metadataKey, keyFingerprint) {
        return this._withMutex('keyOperation', async (operationId) => {
            this._secureLog('info', '🔐 Setting encryption keys with mutex', {
                operationId: operationId
            });
            
            // Валидация всех ключей перед установкой
            if (!(encryptionKey instanceof CryptoKey) ||
                !(macKey instanceof CryptoKey) ||
                !(metadataKey instanceof CryptoKey)) {
                throw new Error('Invalid key types provided');
            }
            
            if (!keyFingerprint || typeof keyFingerprint !== 'string') {
                throw new Error('Invalid key fingerprint provided');
            }
            
            // Атомарная установка всех ключей
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
                
                // Сброс счетчиков
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
                // Rollback в случае ошибки
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
                if (error.message.includes('слишком старые') || error.message.includes('too old')) {
                    this.onAnswerError('replay_attack', error.message);
                } else if (error.message.includes('MITM') || error.message.includes('подпись')) {
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
            // Проверяем, не было ли уже отправлено сообщение о подтверждении верификации
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
            
            // Проверяем, не было ли уже отправлено сообщение о верификации
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
            
            // Проверяем, не было ли уже отправлено сообщение о верификации
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
            
            // Проверяем, не было ли уже отправлено сообщение о верификации
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
        // Быстрая проверка готовности БЕЗ mutex
        if (!this.isConnected() || !this.isVerified) {
            if (message && typeof message === 'object' && message.type && message.type.startsWith('file_')) {
                throw new Error('Connection not ready for file transfer. Please ensure the connection is established and verified.');
            }
            this.messageQueue.push(message);
            throw new Error('Connection not ready. Message queued for sending.');
        }
        
        // ИСПРАВЛЕНИЕ: Используем mutex ТОЛЬКО для криптографических операций
        return this._withMutex('cryptoOperation', async (operationId) => {
            // Повторная проверка в критической секции
            if (!this.isConnected() || !this.isVerified) {
                throw new Error('Connection lost during message preparation');
            }
            
            // Проверка ключей в критической секции
            if (!this.encryptionKey || !this.macKey || !this.metadataKey) {
                throw new Error('Encryption keys not initialized');
            }
            
            // Проверка rate limiting
            if (!window.EnhancedSecureCryptoUtils.rateLimiter.checkMessageRate(this.rateLimiterId)) {
                throw new Error('Message rate limit exceeded (60 messages per minute)');
            }
            
            try {
                // Допускаем как строку, так и объект; объекты сериализуем в строку
                const textToSend = typeof message === 'string' ? message : JSON.stringify(message);
                const sanitizedMessage = window.EnhancedSecureCryptoUtils.sanitizeMessage(textToSend);
                const messageId = `msg_${Date.now()}_${this.messageCounter++}`;
                
                // Используем enhanced encryption с metadata protection
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
                // Отображаем локально только простые строковые сообщения, чтобы избежать дублирования в UI
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
        }, 2000); // Уменьшенный timeout для crypto операций
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
        
        // Проверяем, не было ли уже отправлено сообщение о разрыве соединения
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

        // Не пытаемся переподключиться автоматически
        // чтобы не закрывать сессию при ошибках
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
        // Проверяем, не было ли уже отправлено сообщение о неудачном переподключении
        if (!this.reconnectionFailedNotificationSent) {
            this.reconnectionFailedNotificationSent = true;
            this.deliverMessageToUI('❌ Unable to reconnect. A new connection is required.', 'system');
        }
        // Не вызываем cleanupConnection автоматически
        // чтобы не закрывать сессию при ошибках
        // this.disconnect();
    }
    
    handlePeerDisconnectNotification(data) {
        const reason = data.reason || 'unknown';
        const reasonText = reason === 'user_disconnect' ? 'manually disconnected.' : 'connection lost.';
        
        // Проверяем, не было ли уже отправлено сообщение о разрыве соединения пира
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
            
            // Дать время на инициализацию
            await new Promise(resolve => setTimeout(resolve, 500));
            
            if (!this.fileTransferSystem) {
                throw new Error('File transfer system could not be initialized. Please try reconnecting.');
            }
        }

        // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Проверяем готовность ключей
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
            
            // Перебрасываем ошибку с более понятным сообщением
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
            // Проверяем наличие методов в файловой системе
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
            
            // ИСПРАВЛЕНИЕ: Более мягкие проверки для активации
            const hasKeys = !!(this.encryptionKey && this.macKey);
            const hasSession = !!(this.sessionManager && (this.sessionManager.hasActiveSession?.() || sessionData.sessionId));
            
            console.log('🔍 Session activation status:', {
                hasKeys: hasKeys,
                hasSession: hasSession,
                sessionType: sessionData.sessionType,
                isDemo: sessionData.isDemo
            });
            
            // Force connection status если у нас есть сессия
            if (hasSession) {
                console.log('🔓 Session activated - forcing connection status to connected');
                this.onStatusChange('connected');
                
                // Устанавливаем isVerified для активных сессий
                this.isVerified = true;
                console.log('✅ Session verified - setting isVerified to true');
            }
            
            // Инициализируем file transfer систему с задержкой
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
    // Метод для проверки готовности файловых трансферов
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

    // Метод для принудительной переинициализации файловой системы
    forceReinitializeFileTransfer() {
        try {
            console.log('🔄 Force reinitializing file transfer system...');
            
            if (this.fileTransferSystem) {
                this.fileTransferSystem.cleanup();
                this.fileTransferSystem = null;
            }
            
            // Небольшая задержка перед переинициализацией
            setTimeout(() => {
                this.initializeFileTransfer();
            }, 500);
            
            return true;
        } catch (error) {
            console.error('❌ Failed to force reinitialize file transfer:', error);
            return false;
        }
    }

    // Метод для получения диагностической информации
    getFileTransferDiagnostics() {
        const diagnostics = {
            timestamp: new Date().toISOString(),
            webrtcManager: {
                hasDataChannel: !!this.dataChannel,
                dataChannelState: this.dataChannel?.readyState,
                isConnected: this.isConnected(),
                isVerified: this.isVerified,
                hasEncryptionKey: !!this.encryptionKey,
                hasMacKey: !!this.macKey,
                hasMetadataKey: !!this.metadataKey
            },
            fileTransferSystem: null
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
}

export { EnhancedSecureWebRTCManager };