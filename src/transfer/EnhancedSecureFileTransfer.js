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
        

        
        // Transfer settings
        // Размер чанка по умолчанию (баланс нагрузки и стабильности очереди)
        this.CHUNK_SIZE = 64 * 1024; // 64 KB
        this.MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB limit
        this.MAX_CONCURRENT_TRANSFERS = 3;
        this.CHUNK_TIMEOUT = 30000; // 30 seconds per chunk
        this.RETRY_ATTEMPTS = 3;
        
        // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Система ограничений по типам файлов
        this.FILE_TYPE_RESTRICTIONS = {
            // Документы
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
            
            // Изображения
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
            
            // Архивы
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
            
            // Медиа файлы
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
            
            // Общие файлы (любые другие типы)
            general: {
                extensions: [], // Пустой массив означает "все остальные"
                mimeTypes: [], // Пустой массив означает "все остальные"
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
        
        // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Регистрируем обработчик сообщений
        this.setupFileMessageHandlers();
        
        // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Устанавливаем ссылку в WebRTC менеджере
        if (this.webrtcManager) {
            this.webrtcManager.fileTransferSystem = this;
        }
    }

    // ============================================
    // FILE TYPE VALIDATION SYSTEM
    // ============================================
    
    // Определяем тип файла по расширению и MIME типу
    getFileType(file) {
        const fileName = file.name.toLowerCase();
        const fileExtension = fileName.substring(fileName.lastIndexOf('.'));
        const mimeType = file.type.toLowerCase();
        
        // Проверяем каждый тип файла
        for (const [typeKey, typeConfig] of Object.entries(this.FILE_TYPE_RESTRICTIONS)) {
            if (typeKey === 'general') continue; // Пропускаем общий тип
            
            // Проверяем расширение
            if (typeConfig.extensions.includes(fileExtension)) {
                return {
                    type: typeKey,
                    category: typeConfig.category,
                    description: typeConfig.description,
                    maxSize: typeConfig.maxSize,
                    allowed: true
                };
            }
            
            // Проверяем MIME тип
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
        
        // Если не найден в специфических типах, используем общий
        const generalConfig = this.FILE_TYPE_RESTRICTIONS.general;
        return {
            type: 'general',
            category: generalConfig.category,
            description: generalConfig.description,
            maxSize: generalConfig.maxSize,
            allowed: true
        };
    }
    
    // Проверяем, разрешен ли файл для передачи
    validateFile(file) {
        const fileType = this.getFileType(file);
        const errors = [];
        
        // Проверяем размер файла
        if (file.size > fileType.maxSize) {
            errors.push(`File size (${this.formatFileSize(file.size)}) exceeds maximum allowed for ${fileType.category} (${this.formatFileSize(fileType.maxSize)})`);
        }
        
        // Проверяем, разрешен ли тип файла
        if (!fileType.allowed) {
            errors.push(`File type not allowed. Supported types: ${fileType.description}`);
        }
        
        // Проверяем общий лимит размера
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
    
    // Форматируем размер файла для отображения
    formatFileSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    // Получаем список поддерживаемых типов файлов
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
    
    // Получаем общую информацию о поддерживаемых типах
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

    // ============================================
    // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ - ОБРАБОТКА СООБЩЕНИЙ
    // ============================================

    setupFileMessageHandlers() {
        // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Ждем готовности dataChannel
        if (!this.webrtcManager.dataChannel) {
            // Попытаемся настроить через небольшой интервал
            const setupRetry = setInterval(() => {
                if (this.webrtcManager.dataChannel) {
                    clearInterval(setupRetry);
                    this.setupMessageInterception();
                }
            }, 100);
            
            // Timeout для предотвращения бесконечного ожидания
            setTimeout(() => {
                clearInterval(setupRetry);
            }, 5000);
            
            return;
        }
        
        // Если dataChannel уже готов, сразу настраиваем
        this.setupMessageInterception();
    }

    // В методе setupMessageInterception(), замените весь метод на:
    setupMessageInterception() {
        try {
            if (!this.webrtcManager.dataChannel) {
                return;
            }

            // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Глобальный флаг для блокировки файловых сообщений
            window.FILE_TRANSFER_ACTIVE = true;
            window.fileTransferSystem = this;

            // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Устанавливаем ссылку в WebRTC менеджере
            if (this.webrtcManager) {
                this.webrtcManager.fileTransferSystem = this;
            }

            // 1. ПЕРЕХВАТ НА УРОВНЕ dataChannel.onmessage
            if (this.webrtcManager.dataChannel.onmessage) {
                this.originalOnMessage = this.webrtcManager.dataChannel.onmessage;
            }

            this.webrtcManager.dataChannel.onmessage = async (event) => {
                try {
                    // Проверяем файловые сообщения ПЕРВЫМИ
                    if (typeof event.data === 'string') {
                        try {
                            const parsed = JSON.parse(event.data);
                            
                            if (this.isFileTransferMessage(parsed)) {
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
        
        return fileMessageTypes.includes(message.type);
    }

    // Обрабатываем файловые сообщения
    async handleFileMessage(message) {
        try {
            // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Проверяем готовность файловой системы
            if (!this.webrtcManager.fileTransferSystem) {
                try {
                    // Попытка инициализации файловой системы
                    if (typeof this.webrtcManager.initializeFileTransfer === 'function') {
                        this.webrtcManager.initializeFileTransfer();
                        
                        // Ждем инициализации
                        let attempts = 0;
                        const maxAttempts = 50; // 5 секунд максимум
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
                    // Отправляем ошибку отправителю
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

            return { key: fileSessionKey, salt: Array.from(fileSalt) };

        } catch (error) {
            console.error('❌ Failed to derive file session key:', error);
            throw error;
        }
    }

    async deriveFileSessionKeyFromSalt(fileId, saltArray) {
        try {
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
            
            // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Валидация файла с новой системой типов
            if (!file || !file.size) {
                throw new Error('Invalid file object');
            }

            // Проверяем тип и размер файла
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

            // Send metadata through secure channel
            await this.sendSecureMessage(metadata);
            
            transferState.status = 'metadata_sent';

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
                
                // Send chunk (с учётом backpressure)
                await this.sendFileChunk(transferState, chunkIndex, chunkData);
                
                // Update progress
                transferState.sentChunks++;
                const progress = Math.round((transferState.sentChunks / totalChunks) * 95) + 5; // 5-100%
                
                // Backpressure: ждём разгрузки очереди перед следующим чанком
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
            
            // Перед отправкой проверяем backpressure (доп. защита)
            await this.waitForBackpressure();
            // Send chunk through secure channel
            await this.sendSecureMessage(chunkMessage);
            
        } catch (error) {
            console.error('❌ Failed to send file chunk:', error);
            throw error;
        }
    }

    async sendSecureMessage(message) {
        // ВАЖНО: отправляем напрямую в DataChannel, чтобы file_* и chunk_confirmation
        // приходили верхнего уровня и перехватывались файловой системой, без обёртки type: 'message'
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
                // Если буфер превышает порог — ждём события снижения
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

            // Фолбэк: опрашиваем bufferedAmount и ждём пока не упадёт ниже 4MB
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
            
            // Lazy: храним буфер, но для совместимости формируем Blob для onFileReceived
            const fileBuffer = fileData.buffer;
            const fileBlob = new Blob([fileBuffer], { type: receivingState.fileType });
            
            receivingState.endTime = Date.now();
            receivingState.status = 'completed';
            
            // Сохраняем в кэше до запроса скачивания
            this.receivedFileBuffers.set(receivingState.fileId, {
                buffer: fileBuffer,
                type: receivingState.fileType,
                name: receivingState.fileName,
                size: receivingState.fileSize
            });

            // Сообщаем UI о готовности файла и даём ленивые методы получения
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
            // Не удаляем буфер сразу, оставляем до загрузки пользователем
            // Очистим метаданные чанков, оставив итоговый буфер
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

    cleanupReceivingTransfer(fileId) {
        this.pendingChunks.delete(fileId);
        const receivingState = this.receivingTransfers.get(fileId);
        if (receivingState) {
            // Clear chunk data from memory
            receivingState.receivedChunks.clear();
        }
        
        this.receivingTransfers.delete(fileId);
        this.sessionKeys.delete(fileId);
        // Также очищаем финальный буфер, если он ещё хранится
        this.receivedFileBuffers.delete(fileId);
        
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
            isConnected: this.webrtcManager?.isConnected?.() || false,
            // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Дополнительная диагностика
            hasDataChannel: !!this.webrtcManager?.dataChannel,
            dataChannelState: this.webrtcManager?.dataChannel?.readyState,
            isVerified: this.webrtcManager?.isVerified,
            hasEncryptionKey: !!this.webrtcManager?.encryptionKey,
            hasMacKey: !!this.webrtcManager?.macKey,
            linkedToWebRTCManager: this.webrtcManager?.fileTransferSystem === this,
            // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Информация о поддерживаемых типах файлов
            supportedFileTypes: this.getSupportedFileTypes(),
            fileTypeInfo: this.getFileTypeInfo()
        };
    }

    cleanup() {
        // ИСПРАВЛЕНИЕ: Очищаем глобальные флаги
        window.FILE_TRANSFER_ACTIVE = false;
        window.fileTransferSystem = null;
        
        // ИСПРАВЛЕНИЕ: Восстанавливаем ВСЕ перехваченные методы
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

    // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Метод для диагностики проблем с передачей файлов
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
            globalState: {
                fileTransferActive: window.FILE_TRANSFER_ACTIVE,
                hasGlobalFileTransferSystem: !!window.fileTransferSystem,
                globalFileTransferSystemType: window.fileTransferSystem?.constructor?.name
            },
            transfers: {
                activeTransfers: this.activeTransfers.size,
                receivingTransfers: this.receivingTransfers.size,
                pendingChunks: this.pendingChunks.size,
                sessionKeys: this.sessionKeys.size
            },
            // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Информация о поддерживаемых типах файлов
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
    // АЛЬТЕРНАТИВНЫЙ МЕТОД ИНИЦИАЛИЗАЦИИ ОБРАБОТЧИКОВ
    // ============================================
    
    // Если переопределение processMessage не работает, 
    // используйте этот метод для явной регистрации обработчика
    registerWithWebRTCManager() {
        if (!this.webrtcManager) {
            throw new Error('WebRTC manager not available');
        }
        
        // Сохраняем ссылку на файловую систему в WebRTC менеджере
        this.webrtcManager.fileTransferSystem = this;
        
        // КРИТИЧЕСКИ ВАЖНО: Устанавливаем обработчик файловых сообщений
        this.webrtcManager.setFileMessageHandler = (handler) => {
            this.webrtcManager._fileMessageHandler = handler;
        };
        
        // Регистрируем наш обработчик
        this.webrtcManager.setFileMessageHandler((message) => {
            return this.handleFileMessage(message);
        });
    }

    // Метод для прямого вызова из WebRTC менеджера
    static createFileMessageFilter(fileTransferSystem) {
        return async (event) => {
            try {
                if (typeof event.data === 'string') {
                    const parsed = JSON.parse(event.data);
                    
                    if (fileTransferSystem.isFileTransferMessage(parsed)) {
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