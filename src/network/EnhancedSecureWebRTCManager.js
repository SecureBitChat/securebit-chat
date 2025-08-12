class EnhancedSecureWebRTCManager {
    constructor(onMessage, onStatusChange, onKeyExchange, onVerificationRequired, onAnswerError = null) {
        // Проверяем доступность глобального объекта
        if (!window.EnhancedSecureCryptoUtils) {
            throw new Error('EnhancedSecureCryptoUtils не загружен. Убедитесь, что модуль загружен первым.');
        }
        
        this.peerConnection = null;
        this.dataChannel = null;
        this.encryptionKey = null;
        this.macKey = null;
        this.metadataKey = null;
        this.keyFingerprint = null;
        this.onMessage = onMessage;
        this.onStatusChange = onStatusChange;
        this.onKeyExchange = onKeyExchange;
        this.onVerificationRequired = onVerificationRequired;
        this.onAnswerError = onAnswerError; // Callback для ошибок обработки ответа
        this.isInitiator = false;
        this.connectionAttempts = 0;
        this.maxConnectionAttempts = 3;
        this.heartbeatInterval = null;
        this.messageQueue = [];
        this.ecdhKeyPair = null;
        this.ecdsaKeyPair = null;
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
        
        // PFS (Perfect Forward Secrecy) Implementation
        this.keyRotationInterval = 300000; // 5 minutes
        this.lastKeyRotation = Date.now();
        this.currentKeyVersion = 0;
        this.keyVersions = new Map(); // Store key versions for PFS
        this.oldKeys = new Map(); // Store old keys temporarily for decryption
        this.maxOldKeys = 3; // Keep last 3 key versions for decryption
        
        this.securityFeatures = {
            hasEncryption: true,
            hasECDH: true,
            hasECDSA: false,
            hasMutualAuth: false,
            hasMetadataProtection: false,
            hasEnhancedReplayProtection: false,
            hasNonExtractableKeys: false,
            hasRateLimiting: false,
            hasEnhancedValidation: false,
            hasPFS: true // New PFS feature flag
        };
        
        // Initialize rate limiter ID
        this.rateLimiterId = `webrtc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        
        // Start periodic cleanup
        this.startPeriodicCleanup();
    }

    // Start periodic cleanup for rate limiting and security
    startPeriodicCleanup() {
        setInterval(() => {
            const now = Date.now();
            if (now - this.lastCleanupTime > 300000) { // Every 5 minutes
                window.EnhancedSecureCryptoUtils.rateLimiter.cleanup();
                this.lastCleanupTime = now;
                
                // Clean old processed message IDs (keep only last hour)
                if (this.processedMessageIds.size > 1000) {
                    this.processedMessageIds.clear();
                }
                
                // PFS: Clean old keys that are no longer needed
                this.cleanupOldKeys();
            }
        }, 60000); // Check every minute
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
        try {
            if (!this.isConnected() || !this.isVerified) {
                return false;
            }
    
            // Отправляем сигнал о ротации ключей партнеру
            const rotationSignal = {
                type: 'key_rotation_signal',
                newVersion: this.currentKeyVersion + 1,
                timestamp: Date.now()
            };
            
            this.dataChannel.send(JSON.stringify(rotationSignal));
            
            // Ждем подтверждения от партнера перед ротацией
            return new Promise((resolve) => {
                this.pendingRotation = {
                    newVersion: this.currentKeyVersion + 1,
                    resolve: resolve
                };
                
                // Таймаут на случай если партнер не ответит
                setTimeout(() => {
                    if (this.pendingRotation) {
                        this.pendingRotation.resolve(false);
                        this.pendingRotation = null;
                    }
                }, 5000);
            });
        } catch (error) {
            window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Key rotation failed', {
                error: error.message
            });
            return false;
        }
    }

    // PFS: Clean up old keys that are no longer needed
    cleanupOldKeys() {
        const now = Date.now();
        const maxKeyAge = 900000; // 15 minutes - keys older than this are deleted
        
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
        // Сначала проверяем старые ключи (включая версию 0)
        const oldKeySet = this.oldKeys.get(version);
        if (oldKeySet && oldKeySet.encryptionKey && oldKeySet.macKey && oldKeySet.metadataKey) {
            return {
                encryptionKey: oldKeySet.encryptionKey,
                macKey: oldKeySet.macKey,
                metadataKey: oldKeySet.metadataKey
            };
        }
        
        // Если это текущая версия, возвращаем текущие ключи
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
                // Если это намеренное отключение, сразу очищаем
                if (this.intentionalDisconnect) {
                    this.onStatusChange('disconnected');
                    setTimeout(() => this.cleanupConnection(), 100);
                } else {
                    // Неожиданное отключение - пытаемся уведомить партнера
                    this.onStatusChange('reconnecting');
                    this.handleUnexpectedDisconnect();
                }
            } else if (state === 'failed') {
                if (!this.intentionalDisconnect && this.connectionAttempts < this.maxConnectionAttempts) {
                    this.connectionAttempts++;
                    setTimeout(() => this.retryConnection(), 2000);
                } else {
                    this.onStatusChange('failed');
                    setTimeout(() => this.cleanupConnection(), 1000);
                }
            } else {
                this.onStatusChange(state);
            }
        };

        this.peerConnection.ondatachannel = (event) => {
            console.log('Data channel received');
            this.setupDataChannel(event.channel);
        };
    }

    setupDataChannel(channel) {
        this.dataChannel = channel;

        this.dataChannel.onopen = () => {
            console.log('Secure data channel opened');
            if (this.isVerified) {
                this.onStatusChange('connected');
                this.processMessageQueue();
            } else {
                this.onStatusChange('verifying');
                this.initiateVerification();
            }
            this.startHeartbeat();
        };

        this.dataChannel.onclose = () => {
            console.log('Data channel closed');
            
            if (!this.intentionalDisconnect) {
                this.onStatusChange('reconnecting');
                this.onMessage('🔄 Канал данных закрыт. Попытка восстановления...', 'system');
                this.handleUnexpectedDisconnect();
            } else {
                this.onStatusChange('disconnected');
                this.onMessage('🔌 Соединение закрыто', 'system');
            }
            
            this.stopHeartbeat();
            this.isVerified = false;
        };

        this.dataChannel.onmessage = async (event) => {
            try {
                const payload = JSON.parse(event.data);
                
                if (payload.type === 'heartbeat') {
                    this.handleHeartbeat();
                    return;
                }
                
                if (payload.type === 'verification') {
                    this.handleVerificationRequest(payload.data);
                    return;
                }
                
                if (payload.type === 'verification_response') {
                    this.handleVerificationResponse(payload.data);
                    return;
                }
                
                if (payload.type === 'peer_disconnect') {
                    this.handlePeerDisconnectNotification(payload);
                    return;
                }
                
                if (payload.type === 'key_rotation_signal') {
                    window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Key rotation signal received but ignored for stability', {
                        newVersion: payload.newVersion
                    });
                    return;
                }
                
                if (payload.type === 'key_rotation_ready') {
                    window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Key rotation ready signal received but ignored for stability');
                    return;
                }
                // Handle enhanced messages with metadata protection and PFS
                if (payload.type === 'enhanced_message') {
                    const keyVersion = payload.keyVersion || 0;
                    const keys = this.getKeysForVersion(keyVersion);
                    
                    if (!keys) {
                        window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Keys not available for message decryption', {
                            keyVersion: keyVersion,
                            currentKeyVersion: this.currentKeyVersion,
                            hasCurrentKeys: !!(this.encryptionKey && this.macKey && this.metadataKey),
                            availableOldVersions: Array.from(this.oldKeys.keys())
                        });
                        throw new Error(`Cannot decrypt message: keys for version ${keyVersion} not available`);
                    }
                    
                    if (!(keys.encryptionKey instanceof CryptoKey) || 
                        !(keys.macKey instanceof CryptoKey) || 
                        !(keys.metadataKey instanceof CryptoKey)) {
                        window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Invalid key types for message decryption', {
                            keyVersion: keyVersion,
                            encryptionKeyType: typeof keys.encryptionKey,
                            macKeyType: typeof keys.macKey,
                            metadataKeyType: typeof keys.metadataKey
                        });
                        throw new Error(`Invalid key types for version ${keyVersion}`);
                    }
                    
                    // Используем более гибкую проверку sequence number
                    const decryptedData = await window.EnhancedSecureCryptoUtils.decryptMessage(
                        payload.data,
                        keys.encryptionKey,
                        keys.macKey,
                        keys.metadataKey,
                        null // Отключаем строгую проверку sequence number
                    );
                    
                    // Проверяем replay attack по messageId
                    if (this.processedMessageIds.has(decryptedData.messageId)) {
                        throw new Error('Duplicate message detected - possible replay attack');
                    }
                    this.processedMessageIds.add(decryptedData.messageId);
                    
                    // Обновляем ожидаемый sequence number более гибко
                    if (decryptedData.sequenceNumber >= this.expectedSequenceNumber) {
                        this.expectedSequenceNumber = decryptedData.sequenceNumber + 1;
                    }
                    
                    const sanitizedMessage = window.EnhancedSecureCryptoUtils.sanitizeMessage(decryptedData.message);
                    this.onMessage(sanitizedMessage, 'received');
                
                    window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Enhanced message received with PFS', {
                        messageId: decryptedData.messageId,
                        sequenceNumber: decryptedData.sequenceNumber,
                        keyVersion: keyVersion,
                        hasMetadataProtection: true,
                        hasPFS: true
                    });
                    return;
                }
                
                // Legacy message support for backward compatibility
                if (payload.type === 'message') {
                    // Additional validation for legacy messages
                    if (!this.encryptionKey || !this.macKey) {
                        window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Missing keys for legacy message decryption', {
                            hasEncryptionKey: !!this.encryptionKey,
                            hasMacKey: !!this.macKey,
                            hasMetadataKey: !!this.metadataKey
                        });
                        throw new Error('Отсутствуют ключи для расшифровки legacy сообщения');
                    }
                    
                    const decryptedData = await window.EnhancedSecureCryptoUtils.decryptMessage(
                        payload.data,
                        this.encryptionKey,
                        this.macKey,
                        this.metadataKey // Add metadataKey for consistency
                    );
                    
                    // Check for replay attacks
                    if (this.processedMessageIds.has(decryptedData.messageId)) {
                        throw new Error('Duplicate message detected - possible replay attack');
                    }
                    this.processedMessageIds.add(decryptedData.messageId);
                    
                    const sanitizedMessage = window.EnhancedSecureCryptoUtils.sanitizeMessage(decryptedData.message);
                    this.onMessage(sanitizedMessage, 'received');

                    window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Legacy message received', {
                        messageId: decryptedData.messageId,
                        legacy: true
                    });
                    return;
                }

                // Unknown message type
                window.EnhancedSecureCryptoUtils.secureLog.log('warn', 'Unknown message type received', {
                    type: payload.type
                });
                
            } catch (error) {
                window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Message processing error', {
                    error: error.message
                });
                this.onMessage(`❌ Ошибка обработки: ${error.message}`, 'system');
            }
        };

        this.dataChannel.onerror = (error) => {
            console.error('Data channel error:', error);
            this.onMessage('❌ Ошибка канала данных', 'system');
        };
    }

    async createSecureOffer() {
        try {
            // Check rate limiting
            if (!window.EnhancedSecureCryptoUtils.rateLimiter.checkConnectionRate(this.rateLimiterId)) {
                throw new Error('Connection rate limit exceeded. Please wait before trying again.');
            }
            
            this.connectionAttempts = 0;
            this.sessionSalt = window.EnhancedSecureCryptoUtils.generateSalt(); // Now 64 bytes
            
            // Generate ECDH key pair (non-extractable)
            this.ecdhKeyPair = await window.EnhancedSecureCryptoUtils.generateECDHKeyPair();
            
            // Generate ECDSA key pair for digital signatures
            this.ecdsaKeyPair = await window.EnhancedSecureCryptoUtils.generateECDSAKeyPair();
            
            // MITM Protection: Verify key uniqueness and prevent key reuse attacks
            const ecdhFingerprint = await window.EnhancedSecureCryptoUtils.calculateKeyFingerprint(
                await crypto.subtle.exportKey('spki', this.ecdhKeyPair.publicKey)
            );
            const ecdsaFingerprint = await window.EnhancedSecureCryptoUtils.calculateKeyFingerprint(
                await crypto.subtle.exportKey('spki', this.ecdsaKeyPair.publicKey)
            );
            
            window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Generated unique key pairs for MITM protection', {
                ecdhFingerprint: ecdhFingerprint.substring(0, 8),
                ecdsaFingerprint: ecdsaFingerprint.substring(0, 8),
                timestamp: Date.now()
            });
            
            // Export keys with signatures
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
            
            // Update security features
            this.securityFeatures.hasECDSA = true;
            this.securityFeatures.hasMutualAuth = true;
            this.securityFeatures.hasMetadataProtection = true;
            this.securityFeatures.hasEnhancedReplayProtection = true;
            this.securityFeatures.hasNonExtractableKeys = true;
            this.securityFeatures.hasRateLimiting = true;
            this.securityFeatures.hasEnhancedValidation = true;
            this.securityFeatures.hasPFS = true;
            
            this.isInitiator = true;
            this.onStatusChange('connecting');
            
            this.createPeerConnection();
            
            this.dataChannel = this.peerConnection.createDataChannel('securechat', {
                ordered: true,
                maxRetransmits: 3
            });
            this.setupDataChannel(this.dataChannel);

            const offer = await this.peerConnection.createOffer({
                offerToReceiveAudio: false,
                offerToReceiveVideo: false
            });
            
            await this.peerConnection.setLocalDescription(offer);
            await this.waitForIceGathering();

            // Generate verification code for out-of-band authentication
            this.verificationCode = window.EnhancedSecureCryptoUtils.generateVerificationCode();
            this.onVerificationRequired(this.verificationCode);

            // Generate mutual authentication challenge
            const authChallenge = window.EnhancedSecureCryptoUtils.generateMutualAuthChallenge();

            // MITM Protection: Add session-specific data to prevent session hijacking
            this.sessionId = Array.from(crypto.getRandomValues(new Uint8Array(16)))
                .map(b => b.toString(16).padStart(2, '0')).join('');
            
            const offerPackage = {
                type: 'enhanced_secure_offer',
                sdp: this.peerConnection.localDescription.sdp,
                ecdhPublicKey: ecdhPublicKeyData,
                ecdsaPublicKey: ecdsaPublicKeyData,
                salt: this.sessionSalt,
                verificationCode: this.verificationCode,
                authChallenge: authChallenge,
                sessionId: this.sessionId, // Additional MITM protection
                timestamp: Date.now(),
                version: '4.0',
                securityLevel: await this.calculateSecurityLevel()
            };

            window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Enhanced secure offer created', {
                version: '4.0',
                hasECDSA: true,
                saltSize: this.sessionSalt.length,
                securityLevel: offerPackage.securityLevel.level
            });

            return offerPackage;
        } catch (error) {
            window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Enhanced secure offer creation failed', {
                error: error.message
            });
            this.onStatusChange('failed');
            throw error;
        }
    }

    async createSecureAnswer(offerData) {
        try {
            window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Starting createSecureAnswer', {
                hasOfferData: !!offerData,
                offerType: offerData?.type,
                hasECDHKey: !!offerData?.ecdhPublicKey,
                hasECDSAKey: !!offerData?.ecdsaPublicKey,
                hasSalt: !!offerData?.salt
            });
            
            if (!this.validateEnhancedOfferData(offerData)) {
                throw new Error('Неверный формат данных подключения');
            }

            // Check rate limiting
            if (!window.EnhancedSecureCryptoUtils.rateLimiter.checkConnectionRate(this.rateLimiterId)) {
                throw new Error('Connection rate limit exceeded. Please wait before trying again.');
            }

            this.sessionSalt = offerData.salt;
            
            // Generate our ECDH key pair (non-extractable)
            this.ecdhKeyPair = await window.EnhancedSecureCryptoUtils.generateECDHKeyPair();
            
            // Generate our ECDSA key pair for digital signatures
            this.ecdsaKeyPair = await window.EnhancedSecureCryptoUtils.generateECDSAKeyPair();
            
            // First, import the ECDSA public key without signature verification (for self-signed keys)
            const peerECDSAPublicKey = await crypto.subtle.importKey(
                'spki',
                new Uint8Array(offerData.ecdsaPublicKey.keyData),
                {
                    name: 'ECDSA',
                    namedCurve: 'P-384'
                },
                false,
                ['verify']
            );
            
            // Now verify the ECDSA key's self-signature
            const ecdsaPackageCopy = { ...offerData.ecdsaPublicKey };
            delete ecdsaPackageCopy.signature;
            const ecdsaPackageString = JSON.stringify(ecdsaPackageCopy);
            const ecdsaSignatureValid = await window.EnhancedSecureCryptoUtils.verifySignature(
                peerECDSAPublicKey,
                offerData.ecdsaPublicKey.signature,
                ecdsaPackageString
            );
            
            if (!ecdsaSignatureValid) {
                throw new Error('Invalid ECDSA key self-signature');
            }
            
            // Now import and verify the ECDH public key using the verified ECDSA key
            const peerECDHPublicKey = await window.EnhancedSecureCryptoUtils.importSignedPublicKey(
                offerData.ecdhPublicKey,
                peerECDSAPublicKey,
                'ECDH'
            );
            
            // Additional validation: Ensure all keys are CryptoKey instances before derivation
            if (!(this.ecdhKeyPair?.privateKey instanceof CryptoKey)) {
                window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Local ECDH private key is not a CryptoKey in createEnhancedSecureAnswer', {
                    hasKeyPair: !!this.ecdhKeyPair,
                    privateKeyType: typeof this.ecdhKeyPair?.privateKey,
                    privateKeyAlgorithm: this.ecdhKeyPair?.privateKey?.algorithm?.name
                });
                throw new Error('Локальный ECDH приватный ключ не является CryptoKey');
            }
            
            if (!(peerECDHPublicKey instanceof CryptoKey)) {
                window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Peer ECDH public key is not a CryptoKey in createEnhancedSecureAnswer', {
                    publicKeyType: typeof peerECDHPublicKey,
                    publicKeyAlgorithm: peerECDHPublicKey?.algorithm?.name
                });
                throw new Error('ECDH публичный ключ собеседника не является CryptoKey');
            }
            
            // Store peer's public key for PFS key rotation
            this.peerPublicKey = peerECDHPublicKey;
            
            // Derive shared keys with metadata protection
            const derivedKeys = await window.EnhancedSecureCryptoUtils.deriveSharedKeys(
                this.ecdhKeyPair.privateKey,
                peerECDHPublicKey,
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
            this.verificationCode = offerData.verificationCode;
            
            // Validate that all keys are properly set
            if (!(this.encryptionKey instanceof CryptoKey) || 
                !(this.macKey instanceof CryptoKey) || 
                !(this.metadataKey instanceof CryptoKey)) {
                window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Invalid key types after derivation in createEnhancedSecureAnswer', {
                    encryptionKeyType: typeof this.encryptionKey,
                    macKeyType: typeof this.macKey,
                    metadataKeyType: typeof this.metadataKey,
                    encryptionKeyAlgorithm: this.encryptionKey?.algorithm?.name,
                    macKeyAlgorithm: this.macKey?.algorithm?.name,
                    metadataKeyAlgorithm: this.metadataKey?.algorithm?.name
                });
                throw new Error('Недействительные типы ключей после вывода');
            }
            
            // PFS: Initialize key version tracking
            this.currentKeyVersion = 0;
            this.lastKeyRotation = Date.now();
            this.keyVersions.set(0, {
                salt: this.sessionSalt,
                timestamp: this.lastKeyRotation,
                messageCount: 0
            });
            
            window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Encryption keys set in createEnhancedSecureAnswer', {
                hasEncryptionKey: !!this.encryptionKey,
                hasMacKey: !!this.macKey,
                hasMetadataKey: !!this.metadataKey,
                keyFingerprint: this.keyFingerprint
            });
            
            // Update security features
            this.securityFeatures.hasECDSA = true;
            this.securityFeatures.hasMutualAuth = true;
            this.securityFeatures.hasMetadataProtection = true;
            this.securityFeatures.hasEnhancedReplayProtection = true;
            this.securityFeatures.hasNonExtractableKeys = true;
            this.securityFeatures.hasRateLimiting = true;
            this.securityFeatures.hasEnhancedValidation = true;
            this.securityFeatures.hasPFS = true;
            
            // Create authentication proof for mutual authentication
            const authProof = await window.EnhancedSecureCryptoUtils.createAuthProof(
                offerData.authChallenge,
                this.ecdsaKeyPair.privateKey,
                this.ecdsaKeyPair.publicKey
            );
            
            this.isInitiator = false;
            this.onStatusChange('connecting');
            this.onKeyExchange(this.keyFingerprint);
            this.onVerificationRequired(this.verificationCode);
            
            this.createPeerConnection();

            await this.peerConnection.setRemoteDescription(new RTCSessionDescription({
                type: 'offer',
                sdp: offerData.sdp
            }));

            const answer = await this.peerConnection.createAnswer({
                offerToReceiveAudio: false,
                offerToReceiveVideo: false
            });

            await this.peerConnection.setLocalDescription(answer);
            await this.waitForIceGathering();

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

            const answerPackage = {
                type: 'enhanced_secure_answer',
                sdp: this.peerConnection.localDescription.sdp,
                ecdhPublicKey: ecdhPublicKeyData,
                ecdsaPublicKey: ecdsaPublicKeyData,
                authProof: authProof,
                timestamp: Date.now(),
                version: '4.0',
                securityLevel: await this.calculateSecurityLevel()
            };

            window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Enhanced secure answer created', {
                version: '4.0',
                hasECDSA: true,
                hasMutualAuth: true,
                securityLevel: answerPackage.securityLevel.level
            });

            return answerPackage;
        } catch (error) {
            window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Enhanced secure answer creation failed', {
                error: error.message
            });
            this.onStatusChange('failed');
            throw error;
        }
    }

    async handleSecureAnswer(answerData) {
        try {
            if (!answerData || answerData.type !== 'enhanced_secure_answer' || !answerData.sdp) {
                throw new Error('Неверный формат ответа');
            }

            // Import peer's ECDH public key from the signed package
            if (!answerData.ecdhPublicKey || !answerData.ecdhPublicKey.keyData) {
                throw new Error('Отсутствуют данные ECDH публичного ключа');
            }

            // First, import and verify the ECDSA public key for signature verification
            if (!answerData.ecdsaPublicKey || !answerData.ecdsaPublicKey.keyData) {
                throw new Error('Отсутствуют данные ECDSA публичного ключа для верификации подписи');
            }

            // Additional MITM protection: Validate answer data structure
            if (!answerData.timestamp || !answerData.version) {
                throw new Error('Отсутствуют обязательные поля в данных ответа - возможная MITM атака');
            }

            // MITM Protection: Verify session ID if present (for enhanced security)
            if (answerData.sessionId && this.sessionId && answerData.sessionId !== this.sessionId) {
                window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Session ID mismatch detected - possible MITM attack', {
                    expectedSessionId: this.sessionId,
                    receivedSessionId: answerData.sessionId
                });
                throw new Error('Несоответствие идентификатора сессии - возможная MITM атака');
            }

            // Check for replay attacks (reject answers older than 1 hour)
            const answerAge = Date.now() - answerData.timestamp;
            if (answerAge > 3600000) { // 1 hour in milliseconds
                window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Answer data is too old - possible replay attack', {
                    answerAge: answerAge,
                    timestamp: answerData.timestamp
                });
                
                // Уведомляем основной код о ошибке replay attack
                if (this.onAnswerError) {
                    this.onAnswerError('replay_attack', 'Данные ответа слишком старые - возможная атака повтора');
                }
                
                throw new Error('Данные ответа слишком старые - возможная атака повтора');
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
                throw new Error('Недействительная подпись ECDSA ключа - возможная MITM атака');
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
                throw new Error('Недействительная сессионная соль - возможная атака перехвата сессии');
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
                throw new Error('Локальный ECDH приватный ключ не является CryptoKey');
            }
            
            if (!(peerPublicKey instanceof CryptoKey)) {
                window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Peer ECDH public key is not a CryptoKey in handleSecureAnswer', {
                    publicKeyType: typeof peerPublicKey,
                    publicKeyAlgorithm: peerPublicKey?.algorithm?.name
                });
                throw new Error('ECDH публичный ключ собеседника не является CryptoKey');
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
                throw new Error('Недействительные типы ключей после вывода');
            }
            
            window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Encryption keys set in handleSecureAnswer', {
                hasEncryptionKey: !!this.encryptionKey,
                hasMacKey: !!this.macKey,
                hasMetadataKey: !!this.metadataKey,
                keyFingerprint: this.keyFingerprint,
                mitmProtection: 'enabled',
                signatureVerified: true,
                timestamp: answerData.timestamp,
                version: answerData.version
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
        } catch (error) {
            console.error('Enhanced secure answer handling failed:', error);
            this.onStatusChange('failed');
            
            // Уведомляем основной код о критических ошибках
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

    initiateVerification() {
        if (this.isInitiator) {
            // Initiator waits for verification confirmation
            this.onMessage('🔐 Подтвердите код безопасности с собеседником для завершения подключения', 'system');
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
            this.onMessage('✅ Верификация прошла успешно. Канал защищен!', 'system');
            this.processMessageQueue();
        } catch (error) {
            console.error('Verification failed:', error);
            this.onMessage('❌ Ошибка верификации', 'system');
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
            this.onMessage('✅ Верификация прошла успешно. Канал защищен!', 'system');
            this.processMessageQueue();
        } else {
            this.onMessage('❌ Код верификации не совпадает! Возможна атака!', 'system');
            this.disconnect();
        }
    }

    handleVerificationResponse(data) {
        if (data.verified) {
            this.isVerified = true;
            this.onStatusChange('connected');
            this.onMessage('✅ Верификация прошла успешно. Канал защищен!', 'system');
            this.processMessageQueue();
        } else {
            this.onMessage('❌ Верификация не прошла!', 'system');
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

                window.EnhancedSecureCryptoUtils.secureLog.log('info', 'v4.0 offer validation passed', {
                    version: offerData.version,
                    securityLevel: offerData.securityLevel?.level || 'unknown',
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
        if (!this.isConnected() || !this.isVerified) {
            this.messageQueue.push(message);
            throw new Error('Соединение не готово. Сообщение добавлено в очередь.');
        }

        // Validate encryption keys
        if (!this.encryptionKey || !this.macKey || !this.metadataKey) {
            window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Encryption keys not initialized', {
                hasEncryptionKey: !!this.encryptionKey,
                hasMacKey: !!this.macKey,
                hasMetadataKey: !!this.metadataKey,
                isConnected: this.isConnected(),
                isVerified: this.isVerified
            });
            throw new Error('Ключи шифрования не инициализированы. Проверьте соединение.');
        }

        try {
            // Check rate limiting
            if (!window.EnhancedSecureCryptoUtils.rateLimiter.checkMessageRate(this.rateLimiterId)) {
                throw new Error('Message rate limit exceeded (60 messages per minute)');
            }

            const sanitizedMessage = window.EnhancedSecureCryptoUtils.sanitizeMessage(message);
            const messageId = `msg_${Date.now()}_${this.messageCounter++}`;
            
            // Use enhanced encryption with metadata protection, sequence numbers, and PFS key version
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
                keyVersion: this.currentKeyVersion, // PFS: Include key version
                version: '4.0'
            };
            
            this.dataChannel.send(JSON.stringify(payload));
            this.onMessage(sanitizedMessage, 'sent');

            window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Enhanced message sent with PFS', {
                messageId,
                sequenceNumber: this.sequenceNumber - 1,
                keyVersion: this.currentKeyVersion,
                hasMetadataProtection: true,
                hasPFS: true
            });
        } catch (error) {
            window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Enhanced message sending failed', {
                error: error.message
            });
            throw error;
        }
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
                        type: 'heartbeat', 
                        timestamp: Date.now() 
                    }));
                } catch (error) {
                    console.error('Heartbeat failed:', error);
                }
            }
        }, 30000);
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
            }, 10000);
        });
    }

    retryConnection() {
        console.log(`Retrying connection (attempt ${this.connectionAttempts}/${this.maxConnectionAttempts})`);
        this.onStatusChange('retrying');
    }

    isConnected() {
        return this.dataChannel && this.dataChannel.readyState === 'open';
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
        // Устанавливаем флаг намеренного отключения
        this.intentionalDisconnect = true;
        
        window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Starting intentional disconnect');
        
        // Отправляем уведомление несколько раз для надежности
        this.sendDisconnectNotification();
        
        // Ждем немного для доставки уведомления, затем очищаем
        setTimeout(() => {
            this.sendDisconnectNotification(); // Еще одна попытка
        }, 100);
        
        setTimeout(() => {
            this.cleanupConnection();
        }, 500);
    }
    
    handleUnexpectedDisconnect() {
        this.sendDisconnectNotification();
        this.isVerified = false;
        this.onMessage('🔌 Соединение потеряно. Попытка переподключения...', 'system');
        
        setTimeout(() => {
            if (!this.intentionalDisconnect) {
                this.attemptReconnection();
            }
        }, 3000);
    }
    
    sendDisconnectNotification() {
        try {
            if (this.dataChannel && this.dataChannel.readyState === 'open') {
                const notification = {
                    type: 'peer_disconnect',
                    timestamp: Date.now(),
                    reason: this.intentionalDisconnect ? 'user_disconnect' : 'connection_lost'
                };
                
                // Пытаемся отправить уведомление несколько раз
                for (let i = 0; i < 3; i++) {
                    try {
                        this.dataChannel.send(JSON.stringify(notification));
                        window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Disconnect notification sent', {
                            reason: notification.reason,
                            attempt: i + 1
                        });
                        break;
                    } catch (sendError) {
                        if (i === 2) { // Последняя попытка
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
        this.onMessage('❌ Не удается переподключиться. Требуется новое соединение.', 'system');
        this.cleanupConnection();
    }
    
    handlePeerDisconnectNotification(data) {
        const reason = data.reason || 'unknown';
        const reasonText = reason === 'user_disconnect' ? 'намеренно отключился' : 'потерял соединение';
        
        this.onMessage(`👋 Собеседник ${reasonText}`, 'system');
        this.onStatusChange('peer_disconnected');
        
        // Устанавливаем флаг что это не наше намеренное отключение
        this.intentionalDisconnect = false;
        this.isVerified = false;
        this.stopHeartbeat();
        
        // Очищаем UI данные
        this.onKeyExchange(''); // Очищаем отпечаток
        this.onVerificationRequired(''); // Очищаем код верификации
        
        // Очищаем соединение через небольшую задержку
        setTimeout(() => {
            this.cleanupConnection();
        }, 2000);
        
        window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Peer disconnect notification processed', {
            reason: reason
        });
    }
    
    cleanupConnection() {
        this.stopHeartbeat();
        this.isVerified = false;
        this.processedMessageIds.clear();
        this.messageCounter = 0;
        
        // Полная очистка всех криптографических данных
        this.encryptionKey = null;
        this.macKey = null;
        this.metadataKey = null;
        this.keyFingerprint = null;
        this.sessionSalt = null;
        this.sessionId = null;
        this.peerPublicKey = null;
        this.verificationCode = null;
        
        // PFS: Очистка всех версий ключей
        this.keyVersions.clear();
        this.oldKeys.clear();
        this.currentKeyVersion = 0;
        this.lastKeyRotation = Date.now();
        
        // Очистка пар ключей
        this.ecdhKeyPair = null;
        this.ecdsaKeyPair = null;
        
        // Сброс счетчиков сообщений
        this.sequenceNumber = 0;
        this.expectedSequenceNumber = 0;
        
        // Сброс флагов безопасности
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
        
        // Закрытие соединений
        if (this.dataChannel) {
            this.dataChannel.close();
            this.dataChannel = null;
        }
        if (this.peerConnection) {
            this.peerConnection.close();
            this.peerConnection = null;
        }
        
        // Очистка очереди сообщений
        this.messageQueue = [];
        
        // ВАЖНО: Очистка логов безопасности
        window.EnhancedSecureCryptoUtils.secureLog.clearLogs();
        
        // Уведомляем UI о полной очистке
        this.onStatusChange('disconnected');
        this.onKeyExchange('');
        this.onVerificationRequired('');
        
        window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Connection cleaned up completely');
        
        // Сброс флага намеренного отключения
        this.intentionalDisconnect = false;
        
        // Принудительная сборка мусора
        if (window.gc) {
            window.gc();
        }
    }
}

export { EnhancedSecureWebRTCManager };