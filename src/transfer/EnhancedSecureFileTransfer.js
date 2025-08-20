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
        
        // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Устанавливаем глобальный флаг
        window.FILE_TRANSFER_ACTIVE = true;
        window.fileTransferSystem = this;
        
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
        
        // Session key derivation
        this.sessionKeys = new Map(); // fileId -> derived session key
        
        // Security
        this.processedChunks = new Set(); // Prevent replay attacks
        this.transferNonces = new Map(); // fileId -> current nonce counter
        
        // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Регистрируем обработчик сообщений
        this.setupFileMessageHandlers();
        
        console.log('🔒 Enhanced Secure File Transfer initialized');
    }

    // ============================================
    // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ - ОБРАБОТКА СООБЩЕНИЙ
    // ============================================

    setupFileMessageHandlers() {
        console.log('🔧 Setting up file message handlers');
        
        // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Ждем готовности dataChannel
        if (!this.webrtcManager.dataChannel) {
            console.log('⏰ DataChannel not ready, deferring setup...');
            // Попытаемся настроить через небольшой интервал
            const setupRetry = setInterval(() => {
                if (this.webrtcManager.dataChannel) {
                    clearInterval(setupRetry);
                    console.log('🔄 DataChannel ready, setting up handlers...');
                    this.setupMessageInterception();
                }
            }, 100);
            
            // Timeout для предотвращения бесконечного ожидания
            setTimeout(() => {
                clearInterval(setupRetry);
                console.warn('⚠️ DataChannel setup timeout');
            }, 5000);
            
            return;
        }
        
        // Если dataChannel уже готов, сразу настраиваем
        this.setupMessageInterception();
        
        console.log('✅ File message handlers configured');
    }

    // В методе setupMessageInterception(), замените весь метод на:
    setupMessageInterception() {
        try {
            if (!this.webrtcManager.dataChannel) {
                console.warn('⚠️ WebRTC manager data channel not available yet');
                return;
            }

            // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Глобальный флаг для блокировки файловых сообщений
            window.FILE_TRANSFER_ACTIVE = true;
            window.fileTransferSystem = this;

            // 1. ПЕРЕХВАТ НА УРОВНЕ dataChannel.onmessage
            if (this.webrtcManager.dataChannel.onmessage) {
                this.originalOnMessage = this.webrtcManager.dataChannel.onmessage;
                console.log('💾 Original onmessage handler saved');
            }

            this.webrtcManager.dataChannel.onmessage = async (event) => {
                try {
                    // Проверяем файловые сообщения ПЕРВЫМИ
                    if (typeof event.data === 'string') {
                        try {
                            const parsed = JSON.parse(event.data);
                            
                            if (this.isFileTransferMessage(parsed)) {
                                console.log('🛑 FILE MESSAGE BLOCKED FROM CHAT:', parsed.type);
                                await this.handleFileMessage(parsed);
                                return; // КРИТИЧЕСКИ ВАЖНО: НЕ передаем дальше
                            }
                        } catch (parseError) {
                            // Не JSON - передаем оригинальному обработчику
                        }
                    }

                    // Передаем обычные сообщения оригинальному обработчику
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

            console.log('✅ Message interception set up successfully');
        } catch (error) {
            console.error('❌ Failed to set up message interception:', error);
        }
    }

    // Проверяем, является ли сообщение файловым
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
        
        const isFileMessage = fileMessageTypes.includes(message.type);
        
        if (isFileMessage) {
            console.log(`🎯 CONFIRMED FILE MESSAGE: ${message.type} - WILL BE BLOCKED FROM CHAT`);
        }
        
        return isFileMessage;
    }

    // Обрабатываем файловые сообщения
    async handleFileMessage(message) {
        try {
            console.log(`🔄 Handling file message: ${message.type}`, {
                fileId: message.fileId,
                type: message.type
            });
            
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
            
            // Отправляем сообщение об ошибке
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
            console.log('🔑 Deriving file session key for:', fileId);
            
            // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Используем keyFingerprint и sessionSalt
            // которые уже согласованы между пирами
            
            if (!this.webrtcManager.keyFingerprint || !this.webrtcManager.sessionSalt) {
                throw new Error('WebRTC session data not available');
            }
            
            // Генерируем соль для этого конкретного файла
            const fileSalt = crypto.getRandomValues(new Uint8Array(32));
            
            // Создаем seed из согласованных данных
            const encoder = new TextEncoder();
            const fingerprintData = encoder.encode(this.webrtcManager.keyFingerprint);
            const fileIdData = encoder.encode(fileId);
            
            // Объединяем все компоненты для создания уникального seed
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
            
            // Хешируем для получения ключевого материала
            const keyMaterial = await crypto.subtle.digest('SHA-256', combinedSeed);
            
            // Импортируем как AES ключ напрямую
            const fileSessionKey = await crypto.subtle.importKey(
                'raw',
                keyMaterial,
                { name: 'AES-GCM' },
                false,
                ['encrypt', 'decrypt']
            );

            // Сохраняем ключ и соль
            this.sessionKeys.set(fileId, {
                key: fileSessionKey,
                salt: Array.from(fileSalt),
                created: Date.now()
            });

            console.log('✅ File session key derived successfully for:', fileId);
            return { key: fileSessionKey, salt: Array.from(fileSalt) };

        } catch (error) {
            console.error('❌ Failed to derive file session key:', error);
            throw error;
        }
    }

    async deriveFileSessionKeyFromSalt(fileId, saltArray) {
        try {
            console.log('🔑 Deriving session key from salt for receiver:', fileId);
            
            // Проверка соли
            if (!saltArray || !Array.isArray(saltArray) || saltArray.length !== 32) {
                throw new Error(`Invalid salt: ${saltArray?.length || 0} bytes`);
            }
            
            if (!this.webrtcManager.keyFingerprint || !this.webrtcManager.sessionSalt) {
                throw new Error('WebRTC session data not available');
            }
            
            // Используем тот же процесс что и отправитель
            const encoder = new TextEncoder();
            const fingerprintData = encoder.encode(this.webrtcManager.keyFingerprint);
            const fileIdData = encoder.encode(fileId);
            
            // Используем полученную соль файла
            const fileSalt = new Uint8Array(saltArray);
            const sessionSaltArray = new Uint8Array(this.webrtcManager.sessionSalt);
            
            // Объединяем компоненты в том же порядке
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
            
            // Хешируем для получения того же ключевого материала
            const keyMaterial = await crypto.subtle.digest('SHA-256', combinedSeed);
            
            // Импортируем как AES ключ
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
                version: '2.0'
            };

            console.log('📁 Sending file metadata for:', transferState.file.name);
            
            // Send metadata through secure channel
            await this.sendSecureMessage(metadata);
            
            transferState.status = 'metadata_sent';
            
            // ИСПРАВЛЕНИЕ: НЕ отправляем системные сообщения в чат
            // Только логируем
            console.log(`📁 File metadata sent: ${transferState.file.name} (5% progress)`);

        } catch (error) {
            console.error('❌ Failed to send file metadata:', error);
            transferState.status = 'failed';
            throw error;
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
                
                // Send chunk
                await this.sendFileChunk(transferState, chunkIndex, chunkData);
                
                // Update progress
                transferState.sentChunks++;
                const progress = Math.round((transferState.sentChunks / totalChunks) * 95) + 5; // 5-100%
                
                // ИСПРАВЛЕНИЕ: НЕ отправляем каждый чанк в чат
                // Только логируем
                console.log(`📤 Chunk sent ${transferState.sentChunks}/${totalChunks} (${progress}%)`);
                
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

    async readFileChunk(file, start, end) {
        try {
            const blob = file.slice(start, end);
            return await blob.arrayBuffer();
        } catch (error) {
            console.error('❌ Failed to read file chunk:', error);
            throw error;
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

    async sendSecureMessage(message) {
        try {
            // Send through existing WebRTC channel
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
            
            // ИСПРАВЛЕНИЕ: НЕ отправляем уведомления в чат
            // Только логируем
            console.log(`📥 Started receiving file: ${receivingState.fileName} (${(receivingState.fileSize / 1024 / 1024).toFixed(2)} MB)`);

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
            const errorResponse = {
                type: 'file_transfer_response',
                fileId: metadata.fileId,
                accepted: false,
                error: error.message,
                timestamp: Date.now()
            };
            await this.sendSecureMessage(errorResponse);
        }
    }

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
            
            // Decrypt chunk
            const nonce = new Uint8Array(chunkMessage.nonce);
            const encryptedData = new Uint8Array(chunkMessage.encryptedData);
            
            console.log('🔓 Decrypting chunk:', chunkMessage.chunkIndex);
            
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
            
            // Update progress
            const progress = Math.round((receivingState.receivedCount / receivingState.totalChunks) * 100);
            
            console.log(`📥 Received chunk ${chunkMessage.chunkIndex + 1}/${receivingState.totalChunks} (${progress}%)`);
            
            // ИСПРАВЛЕНИЕ: НЕ отправляем уведомления о прогрессе в чат
            // Только логируем
            
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
            const errorMessage = {
                type: 'file_transfer_error',
                fileId: chunkMessage.fileId,
                error: error.message,
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
                this.onError(`Chunk processing failed: ${error.message}`);
            }
        }
    }

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

    handleChunkConfirmation(confirmation) {
        try {
            const transferState = this.activeTransfers.get(confirmation.fileId);
            if (!transferState) {
                console.warn('⚠️ Received chunk confirmation for unknown transfer:', confirmation.fileId);
                return;
            }
            
            transferState.confirmedChunks++;
            transferState.lastChunkTime = Date.now();
            
            console.log(`✅ Chunk ${confirmation.chunkIndex} confirmed for ${confirmation.fileId}`);
        } catch (error) {
            console.error('❌ Failed to handle chunk confirmation:', error);
        }
    }

    handleTransferComplete(completion) {
        try {
            console.log('🏁 Transfer completion:', completion);
            
            const transferState = this.activeTransfers.get(completion.fileId);
            if (!transferState) {
                console.warn('⚠️ Received completion for unknown transfer:', completion.fileId);
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

    cleanupReceivingTransfer(fileId) {
        this.pendingChunks.delete(fileId);
        const receivingState = this.receivingTransfers.get(fileId);
        if (receivingState) {
            // Clear chunk data from memory
            receivingState.receivedChunks.clear();
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
            isConnected: this.webrtcManager?.isConnected?.() || false
        };
    }

    cleanup() {
        console.log('🧹 Cleaning up file transfer system');
        
        // ИСПРАВЛЕНИЕ: Очищаем глобальные флаги
        window.FILE_TRANSFER_ACTIVE = false;
        window.fileTransferSystem = null;
        
        // ИСПРАВЛЕНИЕ: Восстанавливаем ВСЕ перехваченные методы
        if (this.webrtcManager && this.webrtcManager.dataChannel && this.originalOnMessage) {
            console.log('🔄 Restoring original onmessage handler');
            this.webrtcManager.dataChannel.onmessage = this.originalOnMessage;
            this.originalOnMessage = null;
        }
        
        if (this.webrtcManager && this.originalProcessMessage) {
            console.log('🔄 Restoring original processMessage handler');
            this.webrtcManager.processMessage = this.originalProcessMessage;
            this.originalProcessMessage = null;
        }
        
        if (this.webrtcManager && this.originalRemoveSecurityLayers) {
            console.log('🔄 Restoring original removeSecurityLayers handler');
            this.webrtcManager.removeSecurityLayers = this.originalRemoveSecurityLayers;
            this.originalRemoveSecurityLayers = null;
        }
        
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
        
        console.log('✅ File transfer system cleaned up');
    }

    // ============================================
    // SESSION UPDATE HANDLER - FIXED
    // ============================================
    
    onSessionUpdate(sessionData) {
        console.log('🔄 File transfer system: session updated', sessionData);
        
        // Clear session keys cache for resync
        this.sessionKeys.clear();
        
        console.log('✅ File transfer keys cache cleared for resync');
        
        // If there are active transfers, log warning
        if (this.activeTransfers.size > 0 || this.receivingTransfers.size > 0) {
            console.warn('⚠️ Session updated during active file transfers - may cause issues');
        }
    }

    // ============================================
    // DEBUGGING AND DIAGNOSTICS
    // ============================================

    async debugKeyDerivation(fileId) {
        try {
            console.log('🔍 Debug: Testing key derivation for:', fileId);
            
            if (!this.webrtcManager.keyFingerprint || !this.webrtcManager.sessionSalt) {
                throw new Error('Session data not available');
            }
            
            // Test sender derivation
            const senderResult = await this.deriveFileSessionKey(fileId);
            console.log('✅ Sender key derived successfully');
            
            // Test receiver derivation with same salt
            const receiverKey = await this.deriveFileSessionKeyFromSalt(fileId, senderResult.salt);
            console.log('✅ Receiver key derived successfully');
            
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
                console.log('✅ Cross-key encryption/decryption test successful');
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
    // АЛЬТЕРНАТИВНЫЙ МЕТОД ИНИЦИАЛИЗАЦИИ ОБРАБОТЧИКОВ
    // ============================================
    
    // Если переопределение processMessage не работает, 
    // используйте этот метод для явной регистрации обработчика
    registerWithWebRTCManager() {
        console.log('🔧 Registering file transfer handler with WebRTC manager');
        
        if (!this.webrtcManager) {
            throw new Error('WebRTC manager not available');
        }
        
        // Сохраняем ссылку на файловую систему в WebRTC менеджере
        this.webrtcManager.fileTransferSystem = this;
        
        // КРИТИЧЕСКИ ВАЖНО: Устанавливаем обработчик файловых сообщений
        this.webrtcManager.setFileMessageHandler = (handler) => {
            this.webrtcManager._fileMessageHandler = handler;
            console.log('✅ File message handler registered in WebRTC manager');
        };
        
        // Регистрируем наш обработчик
        this.webrtcManager.setFileMessageHandler((message) => {
            console.log('📁 File message via registered handler:', message.type);
            return this.handleFileMessage(message);
        });
        
        console.log('✅ File transfer handler registered');
    }

    // Метод для прямого вызова из WebRTC менеджера
    static createFileMessageFilter(fileTransferSystem) {
        return async (event) => {
            try {
                if (typeof event.data === 'string') {
                    const parsed = JSON.parse(event.data);
                    
                    if (fileTransferSystem.isFileTransferMessage(parsed)) {
                        console.log('📁 File message filtered by static method:', parsed.type);
                        await fileTransferSystem.handleFileMessage(parsed);
                        return true; // Сообщение обработано
                    }
                }
            } catch (error) {
                // Не файловое сообщение или ошибка парсинга
            }
            
            return false; // Сообщение не обработано
        };
    }
}

export { EnhancedSecureFileTransfer };