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
        
        console.log('🔍 Debug: webrtcManager in constructor:', {
            hasWebrtcManager: !!webrtcManager,
            webrtcManagerType: webrtcManager.constructor?.name,
            hasEncryptionKey: !!webrtcManager.encryptionKey,
            hasMacKey: !!webrtcManager.macKey,
            hasEcdhKeyPair: !!webrtcManager.ecdhKeyPair
        });
        
        // Transfer settings
        this.CHUNK_SIZE = 65536; // 64 KB chunks
        this.MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB limit
        this.MAX_CONCURRENT_TRANSFERS = 3;
        this.CHUNK_TIMEOUT = 30000; // 30 seconds per chunk
        this.RETRY_ATTEMPTS = 3;
        
        // Active transfers tracking
        this.activeTransfers = new Map(); // fileId -> transfer state
        this.receivingTransfers = new Map(); // fileId -> receiving state
        this.transferQueue = []; // Queue for pending transfers
        this.pendingChunks = new Map();
        
        // Session key derivation - КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ
        this.sessionKeys = new Map(); // fileId -> derived session key
        this.sharedSecretCache = new Map(); // Кэш для shared secret чтобы sender и receiver использовали одинаковый
        
        // Security
        this.processedChunks = new Set(); // Prevent replay attacks
        this.transferNonces = new Map(); // fileId -> current nonce counter
        
        // Initialize message handlers
        this.setupFileMessageHandlers();
        
        console.log('🔒 Enhanced Secure File Transfer initialized');
    }

    // ============================================
    // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: ДЕТЕРМИНИСТИЧЕСКОЕ СОЗДАНИЕ КЛЮЧЕЙ
    // ============================================

    async createDeterministicSharedSecret(fileId, fileSize, salt = null) {
        try {
            console.log('🔑 Creating deterministic shared secret for:', fileId);
            
            // Создаем уникальную строку-идентификатор для файла
            const fileIdentifier = `${fileId}-${fileSize}`;
            
            // Проверяем кэш
            if (this.sharedSecretCache.has(fileIdentifier)) {
                console.log('✅ Using cached shared secret for:', fileIdentifier);
                return this.sharedSecretCache.get(fileIdentifier);
            }
            
            const encoder = new TextEncoder();
            let seedComponents = [];
            
            // 1. Добавляем fileId и размер файла (одинаково у отправителя и получателя)
            seedComponents.push(encoder.encode(fileIdentifier));
            
            // 2. Пытаемся использовать существующие ключи сессии
            if (this.webrtcManager.encryptionKey) {
                try {
                    // Создаем детерминистическую производную из существующего ключа шифрования
                    const keyMaterial = encoder.encode(`FileTransfer-Session-${fileIdentifier}`);
                    const derivedKeyMaterial = await crypto.subtle.sign(
                        'HMAC',
                        this.webrtcManager.macKey, // Используем MAC ключ для HMAC
                        keyMaterial
                    );
                    seedComponents.push(new Uint8Array(derivedKeyMaterial));
                    console.log('✅ Used session MAC key for deterministic seed');
                } catch (error) {
                    console.warn('⚠️ Could not use MAC key, using alternative approach:', error.message);
                }
            }
            
            // 3. Добавляем соль если есть (от sender к receiver)
            if (salt && Array.isArray(salt)) {
                seedComponents.push(new Uint8Array(salt));
                console.log('✅ Added salt to deterministic seed');
            }
            
            // 4. Если нет других источников, используем fingerprint сессии
            if (this.webrtcManager.keyFingerprint) {
                seedComponents.push(encoder.encode(this.webrtcManager.keyFingerprint));
                console.log('✅ Added session fingerprint to seed');
            }
            
            // Объединяем все компоненты
            const totalLength = seedComponents.reduce((sum, comp) => sum + comp.length, 0);
            const combinedSeed = new Uint8Array(totalLength);
            let offset = 0;
            
            for (const component of seedComponents) {
                combinedSeed.set(component, offset);
                offset += component.length;
            }
            
            // Хешируем для получения консистентной длины
            const sharedSecret = await crypto.subtle.digest('SHA-384', combinedSeed);
            
            // Кэшируем результат
            this.sharedSecretCache.set(fileIdentifier, sharedSecret);
            
            console.log('🔑 Created deterministic shared secret, length:', sharedSecret.byteLength);
            return sharedSecret;
            
        } catch (error) {
            console.error('❌ Failed to create deterministic shared secret:', error);
            throw error;
        }
    }

    // ============================================
    // ИСПРАВЛЕННЫЙ МЕТОД СОЗДАНИЯ КЛЮЧА СЕССИИ
    // ============================================

    async deriveFileSessionKey(fileId, fileSize, providedSalt = null) {
        try {
            console.log('🔑 Deriving file session key for:', fileId);
            
            // Получаем детерминистический shared secret
            const sharedSecret = await this.createDeterministicSharedSecret(fileId, fileSize, providedSalt);
            
            // Создаем или используем предоставленную соль
            let salt;
            if (providedSalt && Array.isArray(providedSalt)) {
                salt = new Uint8Array(providedSalt);
                console.log('🔑 Using provided salt from metadata');
            } else {
                salt = crypto.getRandomValues(new Uint8Array(32));
                console.log('🔑 Generated new salt for file transfer');
            }
            
            // Импортируем shared secret как PBKDF2 ключ
            const keyForDerivation = await crypto.subtle.importKey(
                'raw',
                sharedSecret,
                { name: 'PBKDF2' },
                false,
                ['deriveKey']
            );
            
            // Создаем файловый ключ сессии с PBKDF2
            const fileSessionKey = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: 100000,
                    hash: 'SHA-384'
                },
                keyForDerivation,
                {
                    name: 'AES-GCM',
                    length: 256
                },
                false,
                ['encrypt', 'decrypt']
            );

            // Сохраняем ключ сессии
            this.sessionKeys.set(fileId, {
                key: fileSessionKey,
                salt: Array.from(salt),
                created: Date.now()
            });

            console.log('✅ File session key derived successfully for:', fileId);
            return { key: fileSessionKey, salt: Array.from(salt) };

        } catch (error) {
            console.error('❌ Failed to derive file session key:', error);
            throw error;
        }
    }

    // ============================================
    // ИСПРАВЛЕННЫЙ МЕТОД ДЛЯ ПОЛУЧАТЕЛЯ
    // ============================================

    async deriveFileSessionKeyFromSalt(fileId, fileSize, saltArray) {
        try {
            console.log('🔑 Deriving session key from salt for receiver:', fileId);
            
            if (!saltArray || !Array.isArray(saltArray)) {
                throw new Error('Invalid salt provided for key derivation');
            }
            
            // Получаем тот же детерминистический shared secret что и отправитель
            const sharedSecret = await this.createDeterministicSharedSecret(fileId, fileSize, saltArray);
            
            const salt = new Uint8Array(saltArray);
            
            // Импортируем shared secret как PBKDF2 ключ
            const keyForDerivation = await crypto.subtle.importKey(
                'raw',
                sharedSecret,
                { name: 'PBKDF2' },
                false,
                ['deriveKey']
            );
            
            // Создаем точно такой же ключ как у отправителя
            const fileSessionKey = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: 100000, // Те же параметры что у отправителя
                    hash: 'SHA-384'
                },
                keyForDerivation,
                {
                    name: 'AES-GCM',
                    length: 256
                },
                false,
                ['encrypt', 'decrypt']
            );

            this.sessionKeys.set(fileId, {
                key: fileSessionKey,
                salt: saltArray,
                created: Date.now()
            });

            console.log('✅ Session key derived successfully for receiver:', fileId);
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
            
            console.log('🔍 Debug: webrtcManager in sendFile:', {
                hasWebrtcManager: !!this.webrtcManager,
                webrtcManagerType: this.webrtcManager.constructor?.name,
                hasEncryptionKey: !!this.webrtcManager.encryptionKey,
                hasMacKey: !!this.webrtcManager.macKey,
                hasEcdhKeyPair: !!this.webrtcManager.ecdhKeyPair,
                isConnected: this.webrtcManager.isConnected?.(),
                isVerified: this.webrtcManager.isVerified
            });
            
            // Validate file
            if (!file || !file.size) {
                throw new Error('Invalid file object');
            }

            if (file.size > this.MAX_FILE_SIZE) {
                throw new Error(`File too large. Maximum size: ${this.MAX_FILE_SIZE / 1024 / 1024} MB`);
            }

            if (this.activeTransfers.size >= this.MAX_CONCURRENT_TRANSFERS) {
                throw new Error('Maximum concurrent transfers reached');
            }

            // Generate unique file ID
            const fileId = `file_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            
            // Calculate file hash for integrity verification
            const fileHash = await this.calculateFileHash(file);
            
            // Derive session key for this file - ИСПРАВЛЕНИЕ
            const keyResult = await this.deriveFileSessionKey(fileId, file.size);
            const sessionKey = keyResult.key;
            const salt = keyResult.salt;
            
            // Create transfer state
            const transferState = {
                fileId: fileId,
                file: file,
                fileHash: fileHash,
                sessionKey: sessionKey,
                salt: salt, // Сохраняем соль для отправки
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
            console.error('❌ File sending failed:', error);
            if (this.onError) this.onError(error.message);
            throw error;
        }
    }

    // ИСПРАВЛЕННЫЙ метод отправки метаданных
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
                salt: transferState.salt, // Отправляем соль получателю
                timestamp: Date.now(),
                version: '1.0'
            };

            console.log('📁 Sending file metadata for:', transferState.file.name);
            
            // Send metadata through secure channel
            await this.sendSecureMessage(metadata);
            
            transferState.status = 'metadata_sent';
            
            // Notify progress
            if (this.onProgress) {
                this.onProgress({
                    fileId: transferState.fileId,
                    fileName: transferState.file.name,
                    progress: 5, // 5% for metadata sent
                    status: 'metadata_sent',
                    totalChunks: transferState.totalChunks,
                    sentChunks: 0
                });
            }

        } catch (error) {
            console.error('❌ Failed to send file metadata:', error);
            transferState.status = 'failed';
            throw error;
        }
    }

    // Start chunk transmission
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
                
                // Send chunk
                await this.sendFileChunk(transferState, chunkIndex, chunkData);
                
                // Update progress
                transferState.sentChunks++;
                const progress = Math.round((transferState.sentChunks / totalChunks) * 95) + 5; // 5-100%
                
                if (this.onProgress) {
                    this.onProgress({
                        fileId: transferState.fileId,
                        fileName: transferState.file.name,
                        progress: progress,
                        status: 'transmitting',
                        totalChunks: totalChunks,
                        sentChunks: transferState.sentChunks
                    });
                }
                
                // Small delay between chunks to prevent overwhelming
                if (chunkIndex < totalChunks - 1) {
                    await new Promise(resolve => setTimeout(resolve, 10));
                }
            }
            
            transferState.status = 'waiting_confirmation';
            console.log('✅ All chunks sent, waiting for completion confirmation');
            
            // Timeout for completion confirmation
            setTimeout(() => {
                if (this.activeTransfers.has(transferState.fileId)) {
                    const state = this.activeTransfers.get(transferState.fileId);
                    if (state.status === 'waiting_confirmation') {
                        console.log('⏰ Transfer completion timeout, cleaning up');
                        this.cleanupTransfer(transferState.fileId);
                    }
                }
            }, 30000);
            
        } catch (error) {
            console.error('❌ Chunk transmission failed:', error);
            transferState.status = 'failed';
            throw error;
        }
    }

    // Read file chunk
    async readFileChunk(file, start, end) {
        try {
            const blob = file.slice(start, end);
            return await blob.arrayBuffer();
        } catch (error) {
            console.error('❌ Failed to read file chunk:', error);
            throw error;
        }
    }

    // Send file chunk
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
            
            const chunkMessage = {
                type: 'file_chunk',
                fileId: transferState.fileId,
                chunkIndex: chunkIndex,
                totalChunks: transferState.totalChunks,
                nonce: Array.from(nonce),
                encryptedData: Array.from(new Uint8Array(encryptedChunk)),
                chunkSize: chunkData.byteLength,
                timestamp: Date.now()
            };
            
            // Send chunk through secure channel
            await this.sendSecureMessage(chunkMessage);
            
        } catch (error) {
            console.error('❌ Failed to send file chunk:', error);
            throw error;
        }
    }

    // Send secure message through WebRTC
    async sendSecureMessage(message) {
        try {
            // Send through existing Double Ratchet channel
            const messageString = JSON.stringify(message);
            
            // Use the WebRTC manager's sendMessage method
            if (this.webrtcManager.sendMessage) {
                await this.webrtcManager.sendMessage(messageString);
            } else {
                throw new Error('WebRTC manager sendMessage method not available');
            }
        } catch (error) {
            console.error('❌ Failed to send secure message:', error);
            throw error;
        }
    }

    // Calculate file hash for integrity verification
    async calculateFileHash(file) {
        try {
            const arrayBuffer = await file.arrayBuffer();
            const hashBuffer = await crypto.subtle.digest('SHA-384', arrayBuffer);
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

    setupFileMessageHandlers() {
        // Store original message handler
        const originalHandler = this.webrtcManager.onMessage;
        
        // Wrap message handler to intercept file transfer messages
        this.webrtcManager.onMessage = (message, type) => {
            try {
                // Try to parse as JSON for file transfer messages
                if (typeof message === 'string' && message.startsWith('{')) {
                    const parsed = JSON.parse(message);
                    
                    switch (parsed.type) {
                        case 'file_transfer_start':
                            this.handleFileTransferStart(parsed);
                            return;
                        case 'file_chunk':
                            this.handleFileChunk(parsed);
                            return;
                        case 'file_transfer_response':
                            this.handleTransferResponse(parsed);
                            return;
                        case 'chunk_confirmation':
                            this.handleChunkConfirmation(parsed);
                            return;
                        case 'file_transfer_complete':
                            this.handleTransferComplete(parsed);
                            return;
                        case 'file_transfer_error':
                            this.handleTransferError(parsed);
                            return;
                    }
                }
            } catch (e) {
                // Not a file transfer message, continue with normal handling
            }
            
            // Pass to original handler for regular messages
            if (originalHandler) {
                originalHandler(message, type);
            }
        };
    }

    // ИСПРАВЛЕННЫЙ Handle incoming file transfer start
    async handleFileTransferStart(metadata) {
        try {
            console.log('📥 Receiving file transfer:', metadata.fileName);
            
            // Validate metadata
            if (!metadata.fileId || !metadata.fileName || !metadata.fileSize) {
                throw new Error('Invalid file transfer metadata');
            }
            
            // Check if we already have this transfer
            if (this.receivingTransfers.has(metadata.fileId)) {
                console.warn('⚠️ File transfer already in progress:', metadata.fileId);
                return;
            }
            
            // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Используем соль из метаданных
            const sessionKey = await this.deriveFileSessionKeyFromSalt(
                metadata.fileId, 
                metadata.fileSize, 
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
            
            // Notify progress
            if (this.onProgress) {
                this.onProgress({
                    fileId: receivingState.fileId,
                    fileName: receivingState.fileName,
                    progress: 0,
                    status: 'receiving',
                    totalChunks: receivingState.totalChunks,
                    receivedChunks: 0
                });
            }

            // Process buffered chunks if any
            if (this.pendingChunks.has(metadata.fileId)) {
                console.log('🔄 Processing buffered chunks for:', metadata.fileId);
                const bufferedChunks = this.pendingChunks.get(metadata.fileId);
                
                for (const [chunkIndex, chunkMessage] of bufferedChunks.entries()) {
                    console.log('📦 Processing buffered chunk:', chunkIndex);
                    await this.handleFileChunk(chunkMessage);
                }
                
                this.pendingChunks.delete(metadata.fileId);
            }
            
        } catch (error) {
            console.error('❌ Failed to handle file transfer start:', error);
            
            // Send error response
            try {
                const errorResponse = {
                    type: 'file_transfer_response',
                    fileId: metadata.fileId,
                    accepted: false,
                    error: error.message,
                    timestamp: Date.now()
                };
                await this.sendSecureMessage(errorResponse);
            } catch (responseError) {
                console.error('❌ Failed to send error response:', responseError);
            }
        }
    }

    // ИСПРАВЛЕННЫЙ Handle incoming file chunk
    async handleFileChunk(chunkMessage) {
        try {
            let receivingState = this.receivingTransfers.get(chunkMessage.fileId);
        
            // Buffer early chunks if transfer not yet initialized
            if (!receivingState) {
                console.log('📦 Buffering early chunk for:', chunkMessage.fileId, 'chunk:', chunkMessage.chunkIndex);
                
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
                console.log('⚠️ Duplicate chunk received:', chunkMessage.chunkIndex);
                return;
            }
            
            // Validate chunk
            if (chunkMessage.chunkIndex < 0 || chunkMessage.chunkIndex >= receivingState.totalChunks) {
                throw new Error(`Invalid chunk index: ${chunkMessage.chunkIndex}`);
            }
            
            // ИСПРАВЛЕНИЕ: Улучшенное декодирование чанка
            const nonce = new Uint8Array(chunkMessage.nonce);
            const encryptedData = new Uint8Array(chunkMessage.encryptedData);
            
            console.log('🔓 Decrypting chunk:', chunkMessage.chunkIndex, {
                nonceLength: nonce.length,
                encryptedDataLength: encryptedData.length,
                expectedSize: chunkMessage.chunkSize
            });
            
            // Decrypt chunk with better error handling
            let decryptedChunk;
            try {
                decryptedChunk = await crypto.subtle.decrypt(
                    {
                        name: 'AES-GCM',
                        iv: nonce
                    },
                    receivingState.sessionKey,
                    encryptedData
                );
            } catch (decryptError) {
                console.error('❌ Chunk decryption failed:', decryptError);
                console.error('Decryption details:', {
                    chunkIndex: chunkMessage.chunkIndex,
                    fileId: chunkMessage.fileId,
                    nonceLength: nonce.length,
                    encryptedDataLength: encryptedData.length,
                    sessionKeyType: receivingState.sessionKey?.constructor?.name,
                    sessionKeyAlgorithm: receivingState.sessionKey?.algorithm?.name
                });
                
                // Send specific error message
                const errorMessage = {
                    type: 'file_transfer_error',
                    fileId: chunkMessage.fileId,
                    error: `Chunk ${chunkMessage.chunkIndex} decryption failed: ${decryptError.message}`,
                    chunkIndex: chunkMessage.chunkIndex,
                    timestamp: Date.now()
                };
                await this.sendSecureMessage(errorMessage);
                return;
            }
            
            // Verify chunk size
            if (decryptedChunk.byteLength !== chunkMessage.chunkSize) {
                throw new Error(`Chunk size mismatch: expected ${chunkMessage.chunkSize}, got ${decryptedChunk.byteLength}`);
            }
            
            // Store chunk
            receivingState.receivedChunks.set(chunkMessage.chunkIndex, decryptedChunk);
            receivingState.receivedCount++;
            
            // Update progress
            const progress = Math.round((receivingState.receivedCount / receivingState.totalChunks) * 100);
            
            console.log(`📥 Received chunk ${chunkMessage.chunkIndex + 1}/${receivingState.totalChunks} (${progress}%)`);
            
            // Notify progress
            if (this.onProgress) {
                this.onProgress({
                    fileId: receivingState.fileId,
                    fileName: receivingState.fileName,
                    progress: progress,
                    status: 'receiving',
                    totalChunks: receivingState.totalChunks,
                    receivedChunks: receivingState.receivedCount
                });
            }
            
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
            console.error('❌ Failed to handle file chunk:', error);
            
            // Send error notification
            try {
                const errorMessage = {
                    type: 'file_transfer_error',
                    fileId: chunkMessage.fileId,
                    error: error.message,
                    timestamp: Date.now()
                };
                await this.sendSecureMessage(errorMessage);
            } catch (errorSendError) {
                console.error('❌ Failed to send chunk error:', errorSendError);
            }
        }
    }

    // Assemble received file
    async assembleFile(receivingState) {
        try {
            console.log('🔄 Assembling file:', receivingState.fileName);
            
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
            
            // Create blob and notify
            const fileBlob = new Blob([fileData], { type: receivingState.fileType });
            
            receivingState.endTime = Date.now();
            receivingState.status = 'completed';
            
            // Notify file received
            if (this.onFileReceived) {
                this.onFileReceived({
                    fileId: receivingState.fileId,
                    fileName: receivingState.fileName,
                    fileSize: receivingState.fileSize,
                    fileBlob: fileBlob,
                    transferTime: receivingState.endTime - receivingState.startTime
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
            this.cleanupReceivingTransfer(receivingState.fileId);
            
            console.log('✅ File assembly completed:', receivingState.fileName);
            
        } catch (error) {
            console.error('❌ File assembly failed:', error);
            receivingState.status = 'failed';
            
            if (this.onError) {
                this.onError(`File assembly failed: ${error.message}`);
            }
            
            // Send error notification
            try {
                const errorMessage = {
                    type: 'file_transfer_complete',
                    fileId: receivingState.fileId,
                    success: false,
                    error: error.message,
                    timestamp: Date.now()
                };
                await this.sendSecureMessage(errorMessage);
            } catch (errorSendError) {
                console.error('❌ Failed to send assembly error:', errorSendError);
            }
            
            // Cleanup failed transfer
            this.cleanupReceivingTransfer(receivingState.fileId);
        }
    }

    // Calculate hash from data
    async calculateFileHashFromData(data) {
        try {
            const hashBuffer = await crypto.subtle.digest('SHA-384', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (error) {
            console.error('❌ Hash calculation failed:', error);
            throw error;
        }
    }

    // Handle transfer response
    handleTransferResponse(response) {
        try {
            console.log('📨 File transfer response:', response);
            
            const transferState = this.activeTransfers.get(response.fileId);
            
            if (!transferState) {
                console.warn('⚠️ Received response for unknown transfer:', response.fileId);
                return;
            }
            
            if (response.accepted) {
                console.log('✅ File transfer accepted by peer');
                transferState.status = 'accepted';
            } else {
                console.log('❌ File transfer rejected by peer:', response.error);
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

    // Handle chunk confirmation
    handleChunkConfirmation(confirmation) {
        try {
            const transferState = this.activeTransfers.get(confirmation.fileId);
            if (!transferState) {
                return;
            }
            
            transferState.confirmedChunks++;
            transferState.lastChunkTime = Date.now();
            
            console.log(`✅ Chunk ${confirmation.chunkIndex} confirmed for ${confirmation.fileId}`);
        } catch (error) {
            console.error('❌ Failed to handle chunk confirmation:', error);
        }
    }

    // Handle transfer completion
    handleTransferComplete(completion) {
        try {
            console.log('🏁 Transfer completion:', completion);
            
            const transferState = this.activeTransfers.get(completion.fileId);
            if (!transferState) {
                return;
            }
            
            if (completion.success) {
                console.log('✅ File transfer completed successfully');
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
                console.log('❌ File transfer failed:', completion.error);
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

    // Handle transfer error
    handleTransferError(errorMessage) {
        try {
            console.error('❌ Transfer error received:', errorMessage);
            
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

    // Get active transfers
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

    // Get receiving transfers
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

    // Cancel transfer
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

    // Cleanup transfer
    cleanupTransfer(fileId) {
        this.activeTransfers.delete(fileId);
        this.sessionKeys.delete(fileId);
        this.transferNonces.delete(fileId);
        
        // Remove from shared secret cache
        const transfers = this.activeTransfers.get(fileId) || this.receivingTransfers.get(fileId);
        if (transfers && transfers.file) {
            const fileIdentifier = `${fileId}-${transfers.file.size}`;
            this.sharedSecretCache.delete(fileIdentifier);
        }
        
        // Remove processed chunk IDs for this transfer
        for (const chunkId of this.processedChunks) {
            if (chunkId.startsWith(fileId)) {
                this.processedChunks.delete(chunkId);
            }
        }
    }

    // Cleanup receiving transfer
    cleanupReceivingTransfer(fileId) {
        this.pendingChunks.delete(fileId);
        const receivingState = this.receivingTransfers.get(fileId);
        if (receivingState) {
            // Clear chunk data from memory
            receivingState.receivedChunks.clear();
            
            // Remove from shared secret cache
            const fileIdentifier = `${fileId}-${receivingState.fileSize}`;
            this.sharedSecretCache.delete(fileIdentifier);
        }
        
        this.receivingTransfers.delete(fileId);
        this.sessionKeys.delete(fileId);
        
        // Remove processed chunk IDs
        for (const chunkId of this.processedChunks) {
            if (chunkId.startsWith(fileId)) {
                this.processedChunks.delete(chunkId);
            }
        }
    }

    // Get transfer status
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

    // Get system status
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
            sharedSecretCacheSize: this.sharedSecretCache.size
        };
    }

    // Cleanup all transfers (called on disconnect)
    cleanup() {
        console.log('🧹 Cleaning up file transfer system');
        
        // Cleanup all active transfers
        for (const fileId of this.activeTransfers.keys()) {
            this.cleanupTransfer(fileId);
        }
        
        for (const fileId of this.receivingTransfers.keys()) {
            this.cleanupReceivingTransfer(fileId);
        }
        
        // Clear all state
        this.pendingChunks.clear();
        this.activeTransfers.clear();
        this.receivingTransfers.clear();
        this.transferQueue.length = 0;
        this.sessionKeys.clear();
        this.transferNonces.clear();
        this.processedChunks.clear();
        this.sharedSecretCache.clear(); // Очищаем кэш shared secret
    }

    // ============================================
    // DEBUGGING AND DIAGNOSTICS
    // ============================================

    // Debug method to check key derivation
    async debugKeyDerivation(fileId, fileSize, salt = null) {
        try {
            console.log('🔍 Debug: Testing key derivation for:', fileId);
            
            const sharedSecret = await this.createDeterministicSharedSecret(fileId, fileSize, salt);
            console.log('🔍 Shared secret created, length:', sharedSecret.byteLength);
            
            const testSalt = salt ? new Uint8Array(salt) : crypto.getRandomValues(new Uint8Array(32));
            console.log('🔍 Using salt, length:', testSalt.length);
            
            const keyForDerivation = await crypto.subtle.importKey(
                'raw',
                sharedSecret,
                { name: 'PBKDF2' },
                false,
                ['deriveKey']
            );
            
            const derivedKey = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: testSalt,
                    iterations: 100000,
                    hash: 'SHA-384'
                },
                keyForDerivation,
                {
                    name: 'AES-GCM',
                    length: 256
                },
                false,
                ['encrypt', 'decrypt']
            );
            
            console.log('✅ Key derivation test successful');
            console.log('🔍 Derived key:', derivedKey.algorithm);
            
            return {
                success: true,
                sharedSecretLength: sharedSecret.byteLength,
                saltLength: testSalt.length,
                keyAlgorithm: derivedKey.algorithm
            };
            
        } catch (error) {
            console.error('❌ Key derivation test failed:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Debug method to verify encryption/decryption
    async debugEncryptionDecryption(fileId, fileSize, testData = 'test data') {
        try {
            console.log('🔍 Debug: Testing encryption/decryption for:', fileId);
            
            const keyResult = await this.deriveFileSessionKey(fileId, fileSize);
            const sessionKey = keyResult.key;
            const salt = keyResult.salt;
            
            // Test encryption
            const nonce = crypto.getRandomValues(new Uint8Array(12));
            const testDataBuffer = new TextEncoder().encode(testData);
            
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: nonce },
                sessionKey,
                testDataBuffer
            );
            
            console.log('✅ Encryption test successful');
            
            // Test decryption with same key
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: nonce },
                sessionKey,
                encrypted
            );
            
            const decryptedText = new TextDecoder().decode(decrypted);
            
            if (decryptedText === testData) {
                console.log('✅ Decryption test successful');
                
                // Test with receiver key derivation
                const receiverKey = await this.deriveFileSessionKeyFromSalt(fileId, fileSize, salt);
                
                const decryptedByReceiver = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: nonce },
                    receiverKey,
                    encrypted
                );
                
                const receiverDecryptedText = new TextDecoder().decode(decryptedByReceiver);
                
                if (receiverDecryptedText === testData) {
                    console.log('✅ Receiver key derivation test successful');
                    return { success: true, message: 'All tests passed' };
                } else {
                    throw new Error('Receiver decryption failed');
                }
            } else {
                throw new Error('Decryption verification failed');
            }
            
        } catch (error) {
            console.error('❌ Encryption/decryption test failed:', error);
            return { success: false, error: error.message };
        }
    }
}

export { EnhancedSecureFileTransfer };