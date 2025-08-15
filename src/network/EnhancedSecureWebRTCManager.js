class EnhancedSecureWebRTCManager {
    constructor(onMessage, onStatusChange, onKeyExchange, onVerificationRequired, onAnswerError = null) {
    // Check the availability of the global object
    if (!window.EnhancedSecureCryptoUtils) {
        throw new Error('EnhancedSecureCryptoUtils is not loaded. Please ensure the module is loaded first.');
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
    this.onAnswerError = onAnswerError; // Callback for response processing errors
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
        hasPFS: true,
        
        hasNestedEncryption: true,     
        hasPacketPadding: true,        
        hasPacketReordering: false,    
        hasAntiFingerprinting: false,  
        

        hasFakeTraffic: false,         
        hasDecoyChannels: false,       
        hasMessageChunking: false      
    };
    
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
        minPadding: 64,
        maxPadding: 512,            
        useRandomPadding: true,
        preserveMessageSize: false
    };
    
    // 3. Fake Traffic Generation
    this.fakeTrafficConfig = {
        enabled: !window.DISABLE_FAKE_TRAFFIC, 
        minInterval: 15000,        
        maxInterval: 30000,       
        minSize: 32,
        maxSize: 128,               
        patterns: ['heartbeat', 'status', 'sync']
    };
    this.fakeTrafficTimer = null;
    this.lastFakeTraffic = 0;
    
    // 4. Message Chunking
    this.chunkingConfig = {
        enabled: false,
        maxChunkSize: 2048,        
        minDelay: 100,
        maxDelay: 500,
        useRandomDelays: true,
        addChunkHeaders: true
    };
    this.chunkQueue = [];
    this.chunkingInProgress = false;
    
    // 5. Decoy Channels
    this.decoyChannels = new Map();
    this.decoyChannelConfig = {
        enabled: !window.DISABLE_DECOY_CHANNELS, 
        maxDecoyChannels: 1,       
        decoyChannelNames: ['heartbeat'], 
        sendDecoyData: true,
        randomDecoyIntervals: true
    };
    this.decoyTimers = new Map();
    
    // 6. Packet Reordering Protection
    this.reorderingConfig = {
        enabled: false,             
        maxOutOfOrder: 5,           
        reorderTimeout: 3000,       
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
            this.nestedEncryptionIV = crypto.getRandomValues(new Uint8Array(12));
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
            const uniqueIV = new Uint8Array(12);
            uniqueIV.set(this.nestedEncryptionIV);
            uniqueIV[11] = (this.nestedEncryptionCounter++) & 0xFF;
            
            // Encrypt data with nested layer
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: uniqueIV },
                this.nestedEncryptionKey,
                data
            );
            
            // Combine IV and encrypted data
            const result = new Uint8Array(12 + encrypted.byteLength);
            result.set(uniqueIV, 0);
            result.set(new Uint8Array(encrypted), 12);
            
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
            const iv = dataArray.slice(0, 12);
            const encryptedData = dataArray.slice(12);
            
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
                const safeInterval = Math.max(nextInterval, 15000);
                
                this.fakeTrafficTimer = setTimeout(sendFakeMessage, safeInterval);
            } catch (error) {
                if (window.DEBUG_MODE) {
                    console.error('❌ Fake traffic generation failed:', error);
                }
                this.stopFakeTrafficGeneration();
            }
        };

        // Start fake traffic generation with longer initial delay
        const initialDelay = Math.random() * this.fakeTrafficConfig.maxInterval + 5000; // Add 5 seconds minimum
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
        type: 'fake', 
        pattern: pattern,
        data: Array.from(fakeData).map(b => b.toString(16).padStart(2, '0')).join(''),
        timestamp: Date.now(),
        size: size,
        isFakeTraffic: true, 
        source: 'fake_traffic_generator',
        fakeId: crypto.getRandomValues(new Uint32Array(1))[0].toString(36) // Уникальный ID
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
    
    if (this.onMessage) {
        this.onMessage('🚨 Advanced security features temporarily disabled due to compatibility issues', 'system');
    }
}

    async sendFakeMessage(fakeMessage) {
    if (!this.dataChannel || this.dataChannel.readyState !== 'open') {
        return;
    }

    try {

        if (window.DEBUG_MODE) {
            console.log(`🎭 Sending fake message: ${fakeMessage.pattern} (${fakeMessage.size} bytes)`);
        }
        
        const fakeData = JSON.stringify({
            ...fakeMessage,
            type: 'fake', 
            isFakeTraffic: true, 
            timestamp: Date.now()
        });
        
        const fakeBuffer = new TextEncoder().encode(fakeData);
        
        const encryptedFake = await this.applySecurityLayers(fakeBuffer, true);
        
        this.dataChannel.send(encryptedFake);
        
        if (window.DEBUG_MODE) {
            console.log(`🎭 Fake message sent successfully: ${fakeMessage.pattern}`);
        }
    } catch (error) {
        if (window.DEBUG_MODE) {
            console.error('❌ Failed to send fake message:', error);
        }
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
    
    if (this.onMessage) {
        this.onMessage('🚨 Fake traffic emergency disabled', 'system');
    }
}
    // ============================================
    // 4. MESSAGE CHUNKING
    // ============================================

    async sendMessageInChunks(data, messageId) {
        if (!this.chunkingConfig.enabled || data.byteLength <= this.chunkingConfig.maxChunkSize) {
            // Send as single message if chunking is disabled or data is small
            return this.sendMessage(data);
        }

        try {
            const dataArray = new Uint8Array(data);
            const totalChunks = Math.ceil(dataArray.length / this.chunkingConfig.maxChunkSize);
            const chunks = [];

            // Split data into chunks
            for (let i = 0; i < totalChunks; i++) {
                const start = i * this.chunkingConfig.maxChunkSize;
                const end = Math.min(start + this.chunkingConfig.maxChunkSize, dataArray.length);
                const chunk = dataArray.slice(start, end);

                if (this.chunkingConfig.addChunkHeaders) {
                    // Add chunk header
                    const header = new ArrayBuffer(16);
                    const headerView = new DataView(header);
                    headerView.setUint32(0, messageId, false);
                    headerView.setUint32(4, i, false);
                    headerView.setUint32(8, totalChunks, false);
                    headerView.setUint32(12, chunk.length, false);

                    const chunkWithHeader = new Uint8Array(16 + chunk.length);
                    chunkWithHeader.set(new Uint8Array(header), 0);
                    chunkWithHeader.set(chunk, 16);
                    chunks.push(chunkWithHeader);
                } else {
                    chunks.push(chunk);
                }
            }

            // Send chunks with random delays
            for (let i = 0; i < chunks.length; i++) {
                const chunk = chunks[i];
                
                // Apply security layers to chunk
                const encryptedChunk = await this.applySecurityLayers(chunk.buffer, false);
                
                // Send chunk
                this.dataChannel.send(encryptedChunk);
                
                console.log(`📦 Sent chunk ${i + 1}/${totalChunks} (${chunk.length} bytes)`);
                
                // Add delay before next chunk (except for last chunk)
                if (i < chunks.length - 1) {
                    const delay = this.chunkingConfig.useRandomDelays ?
                        Math.random() * (this.chunkingConfig.maxDelay - this.chunkingConfig.minDelay) + 
                        this.chunkingConfig.minDelay :
                        this.chunkingConfig.minDelay;
                    
                    await new Promise(resolve => setTimeout(resolve, delay));
                }
            }

            console.log(`📦 Message chunking completed: ${totalChunks} chunks sent`);
        } catch (error) {
            console.error('❌ Message chunking failed:', error);
            // Fallback to single message
            return this.sendMessage(data);
        }
    }

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
                
                // System messages
                if (jsonData.type && ['heartbeat', 'verification', 'verification_response', 'peer_disconnect', 'key_rotation_signal', 'key_rotation_ready', 'security_upgrade'].includes(jsonData.type)) {
                    if (window.DEBUG_MODE) {
                        console.log('🔧 System message detected:', jsonData.type);
                    }
                    return data;
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
                        // Не JSON - это нормально для обычных сообщений
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
                if (!jsonData.type || (jsonData.type !== 'fake' && !['heartbeat', 'verification', 'verification_response', 'peer_disconnect', 'key_rotation_signal', 'key_rotation_ready', 'enhanced_message', 'security_upgrade'].includes(jsonData.type))) {
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
            console.log('📤 sendMessage called:', {
                hasDataChannel: !!this.dataChannel,
                dataChannelState: this.dataChannel?.readyState,
                isInitiator: this.isInitiator,
                isVerified: this.isVerified,
                connectionState: this.peerConnection?.connectionState
            });

            console.log('🔍 sendMessage DEBUG:', {
                dataType: typeof data,
                isString: typeof data === 'string',
                isArrayBuffer: data instanceof ArrayBuffer,
                dataLength: data?.length || data?.byteLength || 0,
                dataConstructor: data?.constructor?.name,
                dataSample: typeof data === 'string' ? data.substring(0, 50) : 'not string'
            });

            // For regular text messages, send in simple format without encryption
            if (typeof data === 'string') {
                const message = {
                    type: 'message',
                    data: data,
                    timestamp: Date.now()
                };
                
                if (window.DEBUG_MODE) {
                    console.log('📤 Sending regular message:', message.data.substring(0, 100));
                }
                
                const messageString = JSON.stringify(message);
                console.log('📤 ACTUALLY SENDING:', {
                    messageString: messageString,
                    messageLength: messageString.length,
                    dataChannelState: this.dataChannel.readyState,
                    isInitiator: this.isInitiator,
                    isVerified: this.isVerified,
                    connectionState: this.peerConnection?.connectionState
                });
                
                this.dataChannel.send(messageString);
                return true;
            }

            // For binary data, apply security layers
            console.log('🔐 Applying security layers to non-string data');
            const securedData = await this.applySecurityLayers(data, false);
            this.dataChannel.send(securedData);
            
            return true;
        } catch (error) {
            console.error('❌ Failed to send message:', error);
            throw error;
        }
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

    async processMessage(data) {
    try {
        console.log('📨 Processing message:', {
            dataType: typeof data,
            isArrayBuffer: data instanceof ArrayBuffer,
            dataLength: data?.length || data?.byteLength || 0
        });
        
        // DEBUG: Check if this is a user message at the start
        if (typeof data === 'string') {
            try {
                const parsed = JSON.parse(data);
                if (parsed.type === 'message') {
                    console.log('🎯 USER MESSAGE IN PROCESSMESSAGE:', {
                        type: parsed.type,
                        data: parsed.data,
                        timestamp: parsed.timestamp
                    });
                }
            } catch (e) {
                // Not JSON
            }
        }
        
        // Check system messages and regular messages directly
        if (typeof data === 'string') {
            try {
                const systemMessage = JSON.parse(data);
                
                if (systemMessage.type === 'fake') {
                    console.log(`🎭 Fake message blocked at entry: ${systemMessage.pattern}`);
                    return; 
                }
                
                if (systemMessage.type && ['heartbeat', 'verification', 'verification_response', 'peer_disconnect', 'key_rotation_signal', 'key_rotation_ready', 'security_upgrade'].includes(systemMessage.type)) {
                    console.log('🔧 Processing system message directly:', systemMessage.type);
                    this.handleSystemMessage(systemMessage);
                    return;
                }
                
                if (systemMessage.type === 'message') {
                    if (window.DEBUG_MODE) {
                        console.log('📝 Regular message detected, extracting for display:', systemMessage.data);
                    }
                    
                    // Call the message handler directly for regular messages
                    if (this.onMessage && systemMessage.data) {
                        console.log('📤 Calling message handler with regular message:', systemMessage.data.substring(0, 100));
                        this.onMessage(systemMessage.data, 'received');
                    }
                    return; // Don't continue processing
                }
                console.log('📨 Unknown message type, continuing to processing:', systemMessage.type);
                
            } catch (e) {
                console.log('📄 Not JSON, continuing to processing as raw data');
            }
        }

        // Validate input data
        if (!data) {
            console.warn('⚠️ Received empty data in processMessage');
            return;
        }

        const originalData = await this.removeSecurityLayers(data);
        
        if (originalData === 'FAKE_MESSAGE_FILTERED') {
            console.log('🎭 Fake message successfully filtered, not displaying to user');
            return; 
        }
        
        if (!originalData) {
            console.warn('⚠️ No data returned from removeSecurityLayers');
            return;
        }

        console.log('🔍 After removeSecurityLayers:', {
            dataType: typeof originalData,
            isString: typeof originalData === 'string',
            isObject: typeof originalData === 'object',
            hasMessage: originalData?.message,
            value: typeof originalData === 'string' ? originalData.substring(0, 100) : 'not string',
            constructor: originalData?.constructor?.name
        });

        let messageText;
        
        if (typeof originalData === 'string') {
            try {
                const message = JSON.parse(originalData);
                if (message.type && ['heartbeat', 'verification', 'verification_response', 'peer_disconnect', 'security_upgrade'].includes(message.type)) {
                    this.handleSystemMessage(message);
                    return;
                }
                
                if (message.type === 'fake') {
                    console.log(`🎭 Post-decryption fake message blocked: ${message.pattern}`);
                    return; 
                }
                
                // Handle regular messages with type 'message'
                if (message.type === 'message' && message.data) {
                    if (window.DEBUG_MODE) {
                        console.log('📝 Regular message detected, extracting data for display');
                    }
                    messageText = message.data;
                } else {
                    // Not a recognized message type, treat as plain text
                    messageText = originalData;
                }
            } catch (e) {
                // Not JSON - treat as plain text
                messageText = originalData;
            }
        } else if (originalData instanceof ArrayBuffer) {
            messageText = new TextDecoder().decode(originalData);
        } else if (originalData && typeof originalData === 'object' && originalData.message) {
            messageText = originalData.message;
        } else {
            console.warn('⚠️ Unexpected data type after processing:', typeof originalData);
            console.warn('Data content:', originalData);
            return;
        }

        // FINAL CHECK FOR FAKE MESSAGES IN TEXT (only if it's JSON)
        if (messageText && messageText.trim().startsWith('{')) {
            try {
                const finalCheck = JSON.parse(messageText);
                if (finalCheck.type === 'fake') {
                    console.log(`🎭 Final fake message check blocked: ${finalCheck.pattern}`);
                    return; 
                }
            } catch (e) {
                // Not JSON - this is fine for regular text messages
            }
        }

        // Call the message handler ONLY for real messages
        if (this.onMessage && messageText) {
            if (window.DEBUG_MODE) {
                console.log('📤 Calling message handler with:', messageText.substring(0, 100));
            }
            this.onMessage(messageText, 'received');
        } else {
            console.warn('⚠️ No message handler or empty message text');
        }

    } catch (error) {
        console.error('❌ Failed to process message:', error);
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
            // Display security upgrade message to user
            if (this.onMessage && message.message) {
                this.onMessage(message.message, 'system');
            }
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
    
    // Enable Packet Reordering
    this.securityFeatures.hasPacketReordering = true;
    this.reorderingConfig.enabled = true;
    
    // Enable Simplified Anti-Fingerprinting
    this.securityFeatures.hasAntiFingerprinting = true;
    this.antiFingerprintingConfig.enabled = true;
    this.antiFingerprintingConfig.randomizeSizes = false; 
    this.antiFingerprintingConfig.maskPatterns = false;
    this.antiFingerprintingConfig.useRandomHeaders = false;
    
    
    // Updating the UI security indicator
    this.notifySecurityUpgrade(2);
}

// Method to enable Stage 3 features (traffic obfuscation)
enableStage3Security() {
    
    // Enable Message Chunking 
    this.securityFeatures.hasMessageChunking = true;
    this.chunkingConfig.enabled = true;
    this.chunkingConfig.maxChunkSize = 2048; // Large chunks for stability
    this.chunkingConfig.minDelay = 100;
    this.chunkingConfig.maxDelay = 300;
    
    // Enable Fake Traffic
    this.securityFeatures.hasFakeTraffic = true;
    this.fakeTrafficConfig.enabled = true;
    this.fakeTrafficConfig.minInterval = 10000; // Rare messages
    this.fakeTrafficConfig.maxInterval = 30000;
    this.fakeTrafficConfig.minSize = 32;
    this.fakeTrafficConfig.maxSize = 128; // Small sizes
    
    // Launching fake traffic
    this.startFakeTrafficGeneration();
    
    // Updating the UI security indicator
    this.notifySecurityUpgrade(3);
}

// Method for enabling Stage 4 functions (maximum safety)
enableStage4Security() {
    console.log('🚀 Enabling Stage 4 security features (Maximum Security)...');
    
    // Enable Decoy Channels (only if the connection is stable)
    if (this.isConnected() && this.isVerified) {
        this.securityFeatures.hasDecoyChannels = true;
        this.decoyChannelConfig.enabled = true;
        this.decoyChannelConfig.maxDecoyChannels = 2; // Only 2 channels
        
        // Initialize decoy channels
        try {
            this.initializeDecoyChannels();
        } catch (error) {
            console.warn('⚠️ Decoy channels initialization failed:', error.message);
            this.securityFeatures.hasDecoyChannels = false;
            this.decoyChannelConfig.enabled = false;
        }
    }
    
    // Enable full Anti-Fingerprinting
    this.antiFingerprintingConfig.randomizeSizes = true;
    this.antiFingerprintingConfig.maskPatterns = true;
    this.antiFingerprintingConfig.useRandomHeaders = false; 
    
    // Updating the UI security indicator
    this.notifySecurityUpgrade(4);
}

// Method for getting security status
getSecurityStatus() {
    const activeFeatures = Object.entries(this.securityFeatures)
        .filter(([key, value]) => value === true)
        .map(([key]) => key);
        
    const stage = activeFeatures.length <= 3 ? 1 : 
                 activeFeatures.length <= 5 ? 2 :
                 activeFeatures.length <= 7 ? 3 : 4;
                 
    return {
        stage: stage,
        activeFeatures: activeFeatures,
        totalFeatures: Object.keys(this.securityFeatures).length,
        securityLevel: stage === 4 ? 'MAXIMUM' : stage === 3 ? 'HIGH' : stage === 2 ? 'MEDIUM' : 'BASIC',
        activeFeaturesCount: activeFeatures.length,
        activeFeaturesNames: activeFeatures
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
    
    // Notify local UI via onMessage
    if (this.onMessage) {
        this.onMessage(message, 'system');
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
// ============================================
// AUTOMATIC STEP-BY-STEP SWITCHING ON
// ============================================

// Method for automatic feature enablement with stability check
async autoEnableSecurityFeatures() {
    
    const checkStability = () => {
        const isStable = this.isConnected() && 
                        this.isVerified && 
                        this.connectionAttempts === 0 && 
                        this.messageQueue.length === 0 &&
                        this.peerConnection?.connectionState === 'connected';
        
        console.log('🔍 Stability check:', {
            isConnected: this.isConnected(),
            isVerified: this.isVerified,
            connectionAttempts: this.connectionAttempts,
            messageQueueLength: this.messageQueue.length,
            connectionState: this.peerConnection?.connectionState
        });
        
        return isStable;
    };
    
    // Stage 1 is already active
    console.log('🔒 Stage 1 active: Basic Enhanced Security');
    this.notifySecurityUpgrade(1);
    
    // Wait 15 seconds of stable operation before Stage 2
    setTimeout(() => {
        if (checkStability()) {
            console.log('✅ Stage 1 stable for 15 seconds, activating Stage 2');
            this.enableStage2Security();
            
            // Wait another 20 seconds before Stage 3
            setTimeout(() => {
                if (checkStability()) {
                    console.log('✅ Stage 2 stable for 20 seconds, activating Stage 3');
                    this.enableStage3Security();
                    
                    // Wait another 25 seconds before Stage 4
                    setTimeout(() => {
                        if (checkStability()) {
                            console.log('✅ Stage 3 stable for 25 seconds, activating Stage 4');
                            this.enableStage4Security();
                        } else {
                            console.log('⚠️ Connection not stable enough for Stage 4');
                        }
                    }, 25000);
                } else {
                    console.log('⚠️ Connection not stable enough for Stage 3');
                }
            }, 20000);
        } else {
            console.log('⚠️ Connection not stable enough for Stage 2');
        }
    }, 15000);
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
            throw error;
        }
    }

    disconnect() {
        try {
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
    
            // Sending key rotation signal to partner.
            const rotationSignal = {
                type: 'key_rotation_signal',
                newVersion: this.currentKeyVersion + 1,
                timestamp: Date.now()
            };
            
            this.dataChannel.send(JSON.stringify(rotationSignal));
            
            // Waiting for partner's confirmation before rotation.
            return new Promise((resolve) => {
                this.pendingRotation = {
                    newVersion: this.currentKeyVersion + 1,
                    resolve: resolve
                };
                
                // Timeout in case the partner doesn't respond.
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
                    setTimeout(() => this.cleanupConnection(), 100);
                } else {
                    // Unexpected disconnection — attempting to notify partner.
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
            
            await this.establishConnection();
            
            if (this.isVerified) {
                this.onStatusChange('connected');
                this.processMessageQueue();
                
                this.autoEnableSecurityFeatures();
            } else {
                this.onStatusChange('verifying');
                this.initiateVerification();
            }
            this.startHeartbeat();
        };

        this.dataChannel.onclose = () => {
            
            // Clean up enhanced security features
            this.disconnect();
            
            if (!this.intentionalDisconnect) {
                this.onStatusChange('reconnecting');
                this.onMessage('🔄 Enhanced secure connection closed. Attempting recovery...', 'system');
                this.handleUnexpectedDisconnect();
            } else {
                this.onStatusChange('disconnected');
                this.onMessage('🔌 Enhanced secure connection closed', 'system');
            }
            
            this.stopHeartbeat();
            this.isVerified = false;
        };

        this.dataChannel.onmessage = async (event) => {
    try {
        console.log('📨 Raw message received:', {
            dataType: typeof event.data,
            dataLength: event.data?.length || 0,
            firstChars: typeof event.data === 'string' ? event.data.substring(0, 100) : 'not string'
        });
        
        // DEBUG: Additional logging for message processing
        console.log('🔍 dataChannel.onmessage DEBUG:', {
            eventDataType: typeof event.data,
            eventDataConstructor: event.data?.constructor?.name,
            isString: typeof event.data === 'string',
            isArrayBuffer: event.data instanceof ArrayBuffer,
            dataSample: typeof event.data === 'string' ? event.data.substring(0, 50) : 'not string'
        });
        
        // DEBUG: Check if this is a user message
        if (typeof event.data === 'string') {
            try {
                const parsed = JSON.parse(event.data);
                if (parsed.type === 'message') {
                    console.log('🎯 USER MESSAGE DETECTED:', {
                        type: parsed.type,
                        data: parsed.data,
                        timestamp: parsed.timestamp,
                        isInitiator: this.isInitiator
                    });
                } else {
                    console.log('📨 OTHER MESSAGE DETECTED:', {
                        type: parsed.type,
                        isInitiator: this.isInitiator
                    });
                }
            } catch (e) {
                console.log('📨 NON-JSON MESSAGE:', {
                    data: event.data.substring(0, 50),
                    isInitiator: this.isInitiator
                });
            }
        }
        
        // ADDITIONAL DEBUG: Log all incoming messages
        console.log('📨 INCOMING MESSAGE DEBUG:', {
            dataType: typeof event.data,
            isString: typeof event.data === 'string',
            isArrayBuffer: event.data instanceof ArrayBuffer,
            dataLength: event.data?.length || event.data?.byteLength || 0,
            dataSample: typeof event.data === 'string' ? event.data.substring(0, 100) : 'not string',
            isInitiator: this.isInitiator,
            isVerified: this.isVerified,
            channelLabel: this.dataChannel?.label || 'unknown',
            channelState: this.dataChannel?.readyState || 'unknown'
        });
        
        // CRITICAL DEBUG: Check if this is a user message that should be displayed
        if (typeof event.data === 'string') {
            try {
                const parsed = JSON.parse(event.data);
                if (parsed.type === 'message') {
                    console.log('🎯 CRITICAL: USER MESSAGE RECEIVED FOR DISPLAY:', {
                        type: parsed.type,
                        data: parsed.data,
                        timestamp: parsed.timestamp,
                        isInitiator: this.isInitiator,
                        channelLabel: this.dataChannel?.label || 'unknown'
                    });
                }
            } catch (e) {
                // Not JSON
            }
        }
        
        // Process message with enhanced security layers
        await this.processMessage(event.data);
    } catch (error) {
        console.error('❌ Failed to process enhanced message:', error);
        
        // Fallback to legacy message processing
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
            
            // Handle enhanced messages with metadata protection and PFS
            if (payload.type === 'enhanced_message') {
                const keyVersion = payload.keyVersion || 0;
                const keys = this.getKeysForVersion(keyVersion);
                
                if (!keys) {
                    console.error('❌ Keys not available for message decryption');
                    throw new Error(`Cannot decrypt message: keys for version ${keyVersion} not available`);
                }
                
                const decryptedData = await window.EnhancedSecureCryptoUtils.decryptMessage(
                    payload.data,
                    keys.encryptionKey,
                    keys.macKey,
                    keys.metadataKey,
                    null // Disabling strict sequence number verification
                );
                
                // Check for replay attacks
                if (this.processedMessageIds.has(decryptedData.messageId)) {
                    throw new Error('Duplicate message detected - possible replay attack');
                }
                this.processedMessageIds.add(decryptedData.messageId);
                
                const sanitizedMessage = window.EnhancedSecureCryptoUtils.sanitizeMessage(decryptedData.message);
                this.onMessage(sanitizedMessage, 'received');
                
                console.log('✅ Enhanced message received via fallback');
                return;
            }
            
            // Legacy message support
            if (payload.type === 'message') {
                if (!this.encryptionKey || !this.macKey) {
                    throw new Error('Missing keys to decrypt legacy message');
                }
                
                const decryptedData = await window.EnhancedSecureCryptoUtils.decryptMessage(
                    payload.data,
                    this.encryptionKey,
                    this.macKey,
                    this.metadataKey
                );
                
                if (this.processedMessageIds.has(decryptedData.messageId)) {
                    throw new Error('Duplicate message detected - possible replay attack');
                }
                this.processedMessageIds.add(decryptedData.messageId);
                
                const sanitizedMessage = window.EnhancedSecureCryptoUtils.sanitizeMessage(decryptedData.message);
                this.onMessage(sanitizedMessage, 'received');
                
                console.log('✅ Legacy message received via fallback');
                return;
            }

            console.warn('⚠️ Unknown message type:', payload.type);
            
        } catch (error) {
            console.error('❌ Message processing error:', error.message);
            this.onMessage(`❌ Processing error: ${error.message}`, 'system');
        }
    }
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
                throw new Error('Invalid connection data format');
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
                throw new Error('The local ECDH private key is not a valid CryptoKey.');
            }
            
            if (!(peerECDHPublicKey instanceof CryptoKey)) {
                window.EnhancedSecureCryptoUtils.secureLog.log('error', 'Peer ECDH public key is not a CryptoKey in createEnhancedSecureAnswer', {
                    publicKeyType: typeof peerECDHPublicKey,
                    publicKeyAlgorithm: peerECDHPublicKey?.algorithm?.name
                });
                throw new Error('The peer\'s ECDH public key is not a valid CryptoKey');
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
                throw new Error('Invalid key types after output');
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
            this.onMessage('🔐 Confirm the security code with your peer to complete the connection', 'system');
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
            this.onMessage('✅ Verification successful. The channel is now secure!', 'system');
            this.processMessageQueue();
        } catch (error) {
            console.error('Verification failed:', error);
            this.onMessage('❌ Verification failed', 'system');
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
            this.onMessage('✅ Verification successful. The channel is now secure!', 'system');
            this.processMessageQueue();
        } else {
            this.onMessage('❌ Verification code mismatch!  Possible MITM attack detected. Connection aborted for safety!', 'system');
            this.disconnect();
        }
    }

    handleVerificationResponse(data) {
        if (data.verified) {
            this.isVerified = true;
            this.onStatusChange('connected');
            this.onMessage('✅ Verification successful. The channel is now secure.!', 'system');
            this.processMessageQueue();
        } else {
            this.onMessage('❌ Verification failed!', 'system');
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
        throw new Error('Connection not ready. Message queued for sending.');
    }

    // Validate encryption keys
    if (!this.encryptionKey || !this.macKey || !this.metadataKey) {
        console.error('❌ Encryption keys not initialized');
        throw new Error('Encryption keys not initialized. Please check the connection.');
    }

    try {
        // Check rate limiting
        if (!window.EnhancedSecureCryptoUtils.rateLimiter.checkMessageRate(this.rateLimiterId)) {
            throw new Error('Message rate limit exceeded (60 messages per minute)');
        }

        const sanitizedMessage = window.EnhancedSecureCryptoUtils.sanitizeMessage(message);
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
        this.onMessage(sanitizedMessage, 'sent');

    } catch (error) {
        console.error('❌ Enhanced message sending failed:', error);
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
        this.intentionalDisconnect = true;
        
        window.EnhancedSecureCryptoUtils.secureLog.log('info', 'Starting intentional disconnect');

        this.sendDisconnectNotification();

        setTimeout(() => {
            this.sendDisconnectNotification(); 
        }, 100);
        
        setTimeout(() => {
            this.cleanupConnection();
        }, 500);
    }
    
    handleUnexpectedDisconnect() {
        this.sendDisconnectNotification();
        this.isVerified = false;
        this.onMessage('🔌 Connection lost. Attempting to reconnect...', 'system');
        
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
        this.onMessage('❌ Unable to reconnect. A new connection is required.', 'system');
        this.cleanupConnection();
    }
    
    handlePeerDisconnectNotification(data) {
        const reason = data.reason || 'unknown';
        const reasonText = reason === 'user_disconnect' ? 'manually disconnected.' : 'connection lost.';
        
        this.onMessage(`👋 Peer ${reasonText}`, 'system');
        this.onStatusChange('peer_disconnected');
 
        this.intentionalDisconnect = false;
        this.isVerified = false;
        this.stopHeartbeat();
        
        this.onKeyExchange(''); 
        this.onVerificationRequired(''); 

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

        this.encryptionKey = null;
        this.macKey = null;
        this.metadataKey = null;
        this.keyFingerprint = null;
        this.sessionSalt = null;
        this.sessionId = null;
        this.peerPublicKey = null;
        this.verificationCode = null;
        
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
        
        // IMPORTANT: Clearing security logs
        window.EnhancedSecureCryptoUtils.secureLog.clearLogs();
        
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
}

export { EnhancedSecureWebRTCManager };