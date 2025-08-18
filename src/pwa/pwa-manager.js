// PWA Offline Manager for SecureBit.chat
// Enhanced Security Edition v4.01.212
// Handles offline functionality, data synchronization, and user experience

class PWAOfflineManager {
    constructor() {
        this.isOnline = navigator.onLine;
        this.offlineDB = null;
        this.offlineQueue = [];
        this.syncInProgress = false;
        this.lastSyncTime = null;
        this.offlineIndicator = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectInterval = null;
        
        // Offline storage configuration
        this.dbConfig = {
            name: 'SecureBitOffline',
            version: 2,
            stores: {
                offlineQueue: {
                    keyPath: 'id',
                    autoIncrement: true,
                    indexes: {
                        timestamp: { unique: false },
                        type: { unique: false },
                        priority: { unique: false }
                    }
                },
                sessionData: {
                    keyPath: 'key'
                },
                messageQueue: {
                    keyPath: 'id',
                    autoIncrement: true,
                    indexes: {
                        timestamp: { unique: false },
                        channelId: { unique: false }
                    }
                },
                appState: {
                    keyPath: 'component'
                }
            }
        };
        
        this.init();
    }

    async init() {
        console.log('📴 PWA Offline Manager initializing...');
        
        try {
            // Initialize offline database
            await this.initOfflineDB();
            
            // Setup event listeners
            this.setupEventListeners();
            
            // Create offline indicator
            this.createOfflineIndicator();
            
            // Register background sync
            this.registerBackgroundSync();
            
            // Setup periodic cleanup
            this.setupPeriodicCleanup();
            
            // Show initial connection status
            this.updateConnectionStatus(this.isOnline);
            
            // Try to process any pending queue items
            if (this.isOnline) {
                await this.processOfflineQueue();
            }
            
            console.log('✅ PWA Offline Manager initialized');
            
        } catch (error) {
            console.error('❌ Offline Manager initialization failed:', error);
            this.handleInitializationError(error);
        }
    }

    async initOfflineDB() {
        if (!('indexedDB' in window)) {
            throw new Error('IndexedDB not supported');
        }

        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbConfig.name, this.dbConfig.version);
            
            request.onerror = () => {
                reject(new Error('Failed to open offline database'));
            };
            
            request.onsuccess = () => {
                this.offlineDB = request.result;
                console.log('💾 Offline database opened successfully');
                resolve(this.offlineDB);
            };
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                
                // Create object stores
                Object.entries(this.dbConfig.stores).forEach(([storeName, config]) => {
                    if (!db.objectStoreNames.contains(storeName)) {
                        console.log(`📦 Creating object store: ${storeName}`);
                        
                        const store = db.createObjectStore(storeName, {
                            keyPath: config.keyPath,
                            autoIncrement: config.autoIncrement || false
                        });
                        
                        // Create indexes
                        if (config.indexes) {
                            Object.entries(config.indexes).forEach(([indexName, indexConfig]) => {
                                store.createIndex(indexName, indexName, indexConfig);
                            });
                        }
                    }
                });
            };
        });
    }

    setupEventListeners() {
        // Network status changes
        window.addEventListener('online', () => {
            console.log('🌐 Connection restored');
            this.isOnline = true;
            this.reconnectAttempts = 0;
            this.updateConnectionStatus(true);
            this.handleConnectionRestored();
        });

        window.addEventListener('offline', () => {
            console.log('📴 Connection lost');
            this.isOnline = false;
            this.updateConnectionStatus(false);
            this.handleConnectionLost();
        });

        // App visibility changes
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden && this.isOnline) {
                // Try to sync when app becomes visible
                setTimeout(() => this.processOfflineQueue(), 1000);
            }
        });

        // Listen for WebRTC connection events
        document.addEventListener('peer-disconnect', (event) => {
            if (!this.isOnline) {
                this.handleOfflineDisconnection(event.detail);
            }
        });

        // Listen for failed network requests
        window.addEventListener('unhandledrejection', (event) => {
            if (this.isNetworkError(event.reason)) {
                this.handleNetworkFailure(event.reason);
            }
        });

        // Listen for beforeunload to save state
        window.addEventListener('beforeunload', () => {
            this.saveApplicationState();
        });
    }

    createOfflineIndicator() {
        this.offlineIndicator = document.createElement('div');
        this.offlineIndicator.id = 'pwa-connection-status';
        this.offlineIndicator.className = 'hidden fixed top-4 left-1/2 transform -translate-x-1/2 z-50 transition-all duration-300';
        document.body.appendChild(this.offlineIndicator);
    }

    updateConnectionStatus(isOnline) {
        if (!this.offlineIndicator) return;

        if (isOnline) {
            this.offlineIndicator.innerHTML = `
                <div class="pwa-online-indicator flex items-center space-x-2 bg-green-500/90 text-white px-4 py-2 rounded-full backdrop-blur-sm">
                    <div class="w-2 h-2 bg-green-200 rounded-full animate-pulse"></div>
                    <span class="text-sm font-medium">🌐 Back online</span>
                </div>
            `;
            this.offlineIndicator.classList.remove('hidden');
            
            // Hide after 3 seconds
            setTimeout(() => {
                this.offlineIndicator.classList.add('hidden');
            }, 3000);
        } else {
            this.offlineIndicator.innerHTML = `
                <div class="pwa-offline-indicator flex items-center space-x-2 bg-red-500/90 text-white px-4 py-2 rounded-full backdrop-blur-sm">
                    <div class="w-2 h-2 bg-red-200 rounded-full"></div>
                    <span class="text-sm font-medium">📴 Offline mode</span>
                    <button onclick="this.parentElement.parentElement.classList.add('hidden')" 
                            class="ml-2 text-red-200 hover:text-white">
                        <i class="fas fa-times text-xs"></i>
                    </button>
                </div>
            `;
            this.offlineIndicator.classList.remove('hidden');
        }
    }

    async handleConnectionRestored() {
        console.log('🔄 Handling connection restoration...');
        
        try {
            // Process offline queue
            await this.processOfflineQueue();
            
            // Restore WebRTC connections if needed
            await this.attemptWebRTCReconnection();
            
            // Show success notification
            this.showReconnectionSuccess();
            
        } catch (error) {
            console.error('❌ Connection restoration failed:', error);
            this.showReconnectionError(error);
        }
    }

    handleConnectionLost() {
        console.log('📴 Handling connection loss...');
        
        // Show offline guidance
        this.showOfflineGuidance();
        
        // Save current application state
        this.saveApplicationState();
        
        // Start reconnection attempts
        this.startReconnectionAttempts();
    }

    showOfflineGuidance() {
        // Don't show if already shown recently
        const lastShown = localStorage.getItem('offline_guidance_shown');
        if (lastShown && Date.now() - parseInt(lastShown) < 60000) { // 1 minute
            return;
        }

        const guidance = document.createElement('div');
        guidance.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4 backdrop-blur-sm';
        guidance.innerHTML = `
            <div class="bg-gray-800 rounded-xl p-6 max-w-md w-full text-center">
                <div class="w-16 h-16 bg-red-500/10 rounded-full flex items-center justify-center mx-auto mb-4">
                    <i class="fas fa-wifi-slash text-red-400 text-2xl"></i>
                </div>
                <h3 class="text-xl font-semibold text-white mb-3">Connection Lost</h3>
                <p class="text-gray-300 mb-4 text-sm leading-relaxed">
                    SecureBit.chat is now in offline mode. Some features are limited, but your data is safe.
                </p>
                
                <div class="space-y-3 text-left mb-6">
                    <div class="flex items-center text-sm">
                        <div class="w-6 h-6 bg-green-500/20 rounded flex items-center justify-center mr-3">
                            <i class="fas fa-check text-green-400 text-xs"></i>
                        </div>
                        <span class="text-gray-300">Your session and keys are preserved</span>
                    </div>
                    <div class="flex items-center text-sm">
                        <div class="w-6 h-6 bg-green-500/20 rounded flex items-center justify-center mr-3">
                            <i class="fas fa-shield-alt text-green-400 text-xs"></i>
                        </div>
                        <span class="text-gray-300">No data is stored on servers</span>
                    </div>
                    <div class="flex items-center text-sm">
                        <div class="w-6 h-6 bg-blue-500/20 rounded flex items-center justify-center mr-3">
                            <i class="fas fa-sync-alt text-blue-400 text-xs"></i>
                        </div>
                        <span class="text-gray-300">Messages will sync when online</span>
                    </div>
                </div>
                
                <div class="flex space-x-3">
                    <button onclick="this.parentElement.parentElement.remove()" 
                            class="flex-1 bg-orange-500 hover:bg-orange-600 text-white py-3 px-4 rounded-lg font-medium transition-colors">
                        Continue Offline
                    </button>
                    <button onclick="window.pwaOfflineManager.showOfflineHelp(); this.parentElement.parentElement.parentElement.remove();" 
                            class="flex-1 bg-gray-600 hover:bg-gray-500 text-white py-3 px-4 rounded-lg font-medium transition-colors">
                        Learn More
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(guidance);
        
        // Save that we showed the guidance
        localStorage.setItem('offline_guidance_shown', Date.now().toString());
        
        // Auto-remove after 15 seconds
        setTimeout(() => {
            if (guidance.parentElement) {
                guidance.remove();
            }
        }, 15000);
    }

    startReconnectionAttempts() {
        if (this.reconnectInterval) {
            clearInterval(this.reconnectInterval);
        }

        this.reconnectInterval = setInterval(() => {
            if (this.isOnline) {
                clearInterval(this.reconnectInterval);
                this.reconnectInterval = null;
                return;
            }

            this.reconnectAttempts++;
            console.log(`🔄 Reconnection attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts}`);
            
            // Try to detect if we're actually back online
            this.checkOnlineStatus();
            
            if (this.reconnectAttempts >= this.maxReconnectAttempts) {
                clearInterval(this.reconnectInterval);
                this.reconnectInterval = null;
                console.log('❌ Max reconnection attempts reached');
            }
        }, 10000); // Try every 10 seconds
    }

    async checkOnlineStatus() {
        try {
            // Try to fetch a small resource to check connectivity
            const response = await fetch('/favicon.ico', {
                method: 'HEAD',
                cache: 'no-cache',
                signal: AbortSignal.timeout(5000)
            });
            
            if (response.ok && !this.isOnline) {
                // We're actually online but navigator.onLine is wrong
                console.log('🌐 Detected online status, updating...');
                this.isOnline = true;
                this.handleConnectionRestored();
            }
        } catch (error) {
            // Still offline
            console.log('📴 Still offline');
        }
    }

    async queueOfflineAction(action) {
        if (!this.offlineDB) {
            console.warn('⚠️ Offline database not available');
            this.offlineQueue.push(action);
            return;
        }

        const queueItem = {
            ...action,
            id: Date.now() + Math.random(),
            timestamp: Date.now(),
            priority: action.priority || 1,
            retryCount: 0,
            maxRetries: action.maxRetries || 3
        };

        try {
            const transaction = this.offlineDB.transaction(['offlineQueue'], 'readwrite');
            const store = transaction.objectStore('offlineQueue');
            await this.promisifyRequest(store.add(queueItem));
            
            console.log('📤 Action queued for offline sync:', action.type);
            this.offlineQueue.push(queueItem);
            
            // Try to register background sync
            if (this.registration) {
                await this.registration.sync.register('offline-sync');
            }
        } catch (error) {
            console.error('❌ Failed to queue offline action:', error);
            // Fallback to memory queue
            this.offlineQueue.push(queueItem);
        }
    }

    async processOfflineQueue() {
        if (this.syncInProgress || !this.isOnline) {
            return;
        }

        this.syncInProgress = true;
        console.log('🔄 Processing offline queue...');
        
        let processedCount = 0;
        let errorCount = 0;

        try {
            // Process database queue
            if (this.offlineDB) {
                const transaction = this.offlineDB.transaction(['offlineQueue'], 'readwrite');
                const store = transaction.objectStore('offlineQueue');
                const allItems = await this.promisifyRequest(store.getAll());
                
                // Sort by priority and timestamp
                allItems.sort((a, b) => {
                    if (a.priority !== b.priority) {
                        return b.priority - a.priority; // Higher priority first
                    }
                    return a.timestamp - b.timestamp; // Older first
                });
                
                for (const item of allItems) {
                    try {
                        await this.processQueueItem(item);
                        await this.promisifyRequest(store.delete(item.id));
                        processedCount++;
                        console.log('✅ Processed offline action:', item.type);
                    } catch (error) {
                        console.error('❌ Failed to process offline action:', error);
                        errorCount++;
                        
                        // Increment retry count
                        item.retryCount = (item.retryCount || 0) + 1;
                        
                        if (item.retryCount >= item.maxRetries) {
                            // Max retries reached, remove from queue
                            await this.promisifyRequest(store.delete(item.id));
                            console.log('❌ Max retries reached for action:', item.type);
                        } else {
                            // Update retry count in database
                            await this.promisifyRequest(store.put(item));
                        }
                    }
                }
            }

            // Process in-memory queue as fallback
            const memoryQueue = [...this.offlineQueue];
            this.offlineQueue = [];
            
            for (const item of memoryQueue) {
                try {
                    await this.processQueueItem(item);
                    processedCount++;
                } catch (error) {
                    console.error('❌ Failed to process memory queue item:', error);
                    errorCount++;
                    
                    item.retryCount = (item.retryCount || 0) + 1;
                    if (item.retryCount < item.maxRetries) {
                        this.offlineQueue.push(item); // Re-queue for retry
                    }
                }
            }

            this.lastSyncTime = Date.now();
            
            if (processedCount > 0 || errorCount > 0) {
                this.showSyncNotification(processedCount, errorCount);
            }

        } catch (error) {
            console.error('❌ Error processing offline queue:', error);
        } finally {
            this.syncInProgress = false;
        }
    }

    async processQueueItem(item) {
        switch (item.type) {
            case 'message':
                return this.retryMessage(item.data);
            case 'connection':
                return this.retryConnection(item.data);
            case 'payment_check':
                return this.retryPaymentCheck(item.data);
            case 'session_verification':
                return this.retrySessionVerification(item.data);
            case 'key_exchange':
                return this.retryKeyExchange(item.data);
            default:
                console.warn('Unknown queue item type:', item.type);
                throw new Error(`Unknown queue item type: ${item.type}`);
        }
    }

    async retryMessage(messageData) {
        // Retry sending message when back online
        if (window.webrtcManager && window.webrtcManager.isConnected()) {
            return window.webrtcManager.sendMessage(messageData.content);
        }
        throw new Error('WebRTC not connected');
    }

    async retryConnection(connectionData) {
        // Retry connection establishment
        if (window.webrtcManager) {
            return window.webrtcManager.retryConnection();
        }
        throw new Error('WebRTC manager not available');
    }

    async retryPaymentCheck(paymentData) {
        // Retry payment verification
        if (window.sessionManager) {
            return window.sessionManager.checkPaymentStatus(paymentData.checkingId);
        }
        throw new Error('Session manager not available');
    }

    async retrySessionVerification(sessionData) {
        // Retry session verification
        if (window.sessionManager) {
            return window.sessionManager.verifyPayment(sessionData.preimage, sessionData.paymentHash);
        }
        throw new Error('Session manager not available');
    }

    async retryKeyExchange(keyData) {
        // Retry key exchange
        if (window.webrtcManager) {
            return window.webrtcManager.handleKeyExchange(keyData);
        }
        throw new Error('WebRTC manager not available');
    }

    showSyncNotification(successCount, errorCount) {
        const notification = document.createElement('div');
        notification.className = 'fixed bottom-4 right-4 bg-green-500 text-white p-4 rounded-lg shadow-lg z-50 max-w-sm transform translate-x-full transition-transform duration-300';
        
        let message = '';
        if (successCount > 0 && errorCount === 0) {
            message = `✅ Synced ${successCount} offline action${successCount > 1 ? 's' : ''}`;
        } else if (successCount > 0 && errorCount > 0) {
            message = `⚠️ Synced ${successCount}, ${errorCount} failed`;
        } else if (errorCount > 0) {
            message = `❌ ${errorCount} sync error${errorCount > 1 ? 's' : ''}`;
        }
        
        notification.innerHTML = `
            <div class="flex items-center space-x-3">
                <i class="fas fa-sync-alt text-lg"></i>
                <div>
                    <div class="font-medium">Sync Complete</div>
                    <div class="text-sm opacity-90">${message}</div>
                </div>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        // Animate in
        setTimeout(() => {
            notification.classList.remove('translate-x-full');
        }, 100);
        
        // Auto-remove after 4 seconds
        setTimeout(() => {
            notification.classList.add('translate-x-full');
            setTimeout(() => notification.remove(), 300);
        }, 4000);
    }

    async attemptWebRTCReconnection() {
        if (!window.webrtcManager) return;
        
        try {
            // Check if we had an active connection before going offline
            const savedConnectionState = await this.getStoredData('sessionData', 'connection_state');
            
            if (savedConnectionState && savedConnectionState.wasConnected) {
                console.log('🔄 Attempting WebRTC reconnection...');
                
                // Show reconnection indicator
                this.showReconnectionIndicator();
                
                // Attempt to restore connection
                // This would depend on your specific WebRTC implementation
                if (window.webrtcManager.attemptReconnection) {
                    await window.webrtcManager.attemptReconnection(savedConnectionState.data);
                }
            }
        } catch (error) {
            console.error('❌ WebRTC reconnection failed:', error);
        }
    }

    showReconnectionIndicator() {
        const indicator = document.createElement('div');
        indicator.className = 'fixed top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 bg-blue-500/90 text-white px-6 py-4 rounded-lg backdrop-blur-sm z-50';
        indicator.innerHTML = `
            <div class="flex items-center space-x-3">
                <i class="fas fa-sync-alt animate-spin text-lg"></i>
                <div>
                    <div class="font-medium">Reconnecting...</div>
                    <div class="text-sm opacity-90">Restoring secure connection</div>
                </div>
            </div>
        `;
        
        document.body.appendChild(indicator);
        
        // Remove after 5 seconds or when connection is restored
        setTimeout(() => {
            if (indicator.parentElement) {
                indicator.remove();
            }
        }, 5000);
    }

    showReconnectionSuccess() {
        const notification = document.createElement('div');
        notification.className = 'fixed top-4 right-4 bg-green-500 text-white p-4 rounded-lg shadow-lg z-50 max-w-sm';
        notification.innerHTML = `
            <div class="flex items-center space-x-3">
                <i class="fas fa-check-circle text-lg"></i>
                <div>
                    <div class="font-medium">Reconnected!</div>
                    <div class="text-sm opacity-90">All services restored</div>
                </div>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => notification.remove(), 3000);
    }

    showReconnectionError(error) {
        const notification = document.createElement('div');
        notification.className = 'fixed top-4 right-4 bg-yellow-500 text-black p-4 rounded-lg shadow-lg z-50 max-w-sm';
        notification.innerHTML = `
            <div class="flex items-center space-x-3">
                <i class="fas fa-exclamation-triangle text-lg"></i>
                <div>
                    <div class="font-medium">Reconnection Issue</div>
                    <div class="text-sm opacity-90">Some features may need manual restart</div>
                </div>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => notification.remove(), 5000);
    }

    async saveApplicationState() {
        if (!this.offlineDB) return;

        try {
            const appState = {
                component: 'app_state',
                timestamp: Date.now(),
                url: window.location.href,
                
                // Save WebRTC connection state
                webrtc: window.webrtcManager ? {
                    isConnected: window.webrtcManager.isConnected(),
                    connectionState: window.webrtcManager.getConnectionInfo(),
                } : null,
                
                // Save session state
                session: window.sessionManager ? {
                    hasActiveSession: window.sessionManager.hasActiveSession(),
                    sessionInfo: window.sessionManager.getSessionInfo(),
                } : null,
                
                // Save UI state
                ui: {
                    currentTab: document.querySelector('.active')?.id,
                    scrollPosition: window.pageYOffset,
                }
            };

            const transaction = this.offlineDB.transaction(['appState'], 'readwrite');
            const store = transaction.objectStore('appState');
            await this.promisifyRequest(store.put(appState));
            
            console.log('💾 Application state saved for offline recovery');
        } catch (error) {
            console.error('❌ Failed to save application state:', error);
        }
    }

    async restoreApplicationState() {
        if (!this.offlineDB) return null;

        try {
            const savedState = await this.getStoredData('appState', 'app_state');
            
            if (savedState && Date.now() - savedState.timestamp < 24 * 60 * 60 * 1000) { // 24 hours
                console.log('🔄 Restoring application state from offline storage');
                return savedState;
            }
        } catch (error) {
            console.error('❌ Failed to restore application state:', error);
        }
        
        return null;
    }

    async storeData(storeName, data) {
        if (!this.offlineDB) {
            throw new Error('Offline database not available');
        }

        const transaction = this.offlineDB.transaction([storeName], 'readwrite');
        const store = transaction.objectStore(storeName);
        return this.promisifyRequest(store.put(data));
    }

    async getStoredData(storeName, key) {
        if (!this.offlineDB) {
            return null;
        }

        try {
            const transaction = this.offlineDB.transaction([storeName], 'readonly');
            const store = transaction.objectStore(storeName);
            const result = await this.promisifyRequest(store.get(key));
            return result;
        } catch (error) {
            console.error(`❌ Failed to get stored data from ${storeName}:`, error);
            return null;
        }
    }

    async clearStoredData(storeName, key = null) {
        if (!this.offlineDB) return;

        try {
            const transaction = this.offlineDB.transaction([storeName], 'readwrite');
            const store = transaction.objectStore(storeName);
            
            if (key) {
                await this.promisifyRequest(store.delete(key));
            } else {
                await this.promisifyRequest(store.clear());
            }
            
            console.log(`🗑️ Cleared stored data from ${storeName}`);
        } catch (error) {
            console.error(`❌ Failed to clear stored data from ${storeName}:`, error);
        }
    }

    registerBackgroundSync() {
        if ('serviceWorker' in navigator && 'sync' in window.ServiceWorkerRegistration.prototype) {
            navigator.serviceWorker.ready.then(registration => {
                this.registration = registration;
                console.log('📡 Background sync registered');
            });
        } else {
            console.warn('⚠️ Background sync not supported');
        }
    }

    setupPeriodicCleanup() {
        // Clean up old data every hour
        setInterval(() => {
            this.cleanupOldData();
        }, 60 * 60 * 1000);
    }

    async cleanupOldData() {
        if (!this.offlineDB) return;

        const maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days
        const cutoffTime = Date.now() - maxAge;

        try {
            const transaction = this.offlineDB.transaction(['offlineQueue', 'messageQueue'], 'readwrite');
            
            // Clean offline queue
            const queueStore = transaction.objectStore('offlineQueue');
            const queueIndex = queueStore.index('timestamp');
            const queueRange = IDBKeyRange.upperBound(cutoffTime);
            
            const queueRequest = queueIndex.openCursor(queueRange);
            queueRequest.onsuccess = (event) => {
                const cursor = event.target.result;
                if (cursor) {
                    cursor.delete();
                    cursor.continue();
                }
            };

            // Clean message queue
            const messageStore = transaction.objectStore('messageQueue');
            const messageIndex = messageStore.index('timestamp');
            const messageRange = IDBKeyRange.upperBound(cutoffTime);
            
            const messageRequest = messageIndex.openCursor(messageRange);
            messageRequest.onsuccess = (event) => {
                const cursor = event.target.result;
                if (cursor) {
                    cursor.delete();
                    cursor.continue();
                }
            };

            console.log('🧹 Old offline data cleaned up');
        } catch (error) {
            console.error('❌ Failed to cleanup old data:', error);
        }
    }

    handleOfflineDisconnection(details) {
        console.log('🔌 WebRTC disconnected while offline:', details);
        
        // Save connection state for recovery
        this.storeData('sessionData', {
            key: 'connection_state',
            wasConnected: true,
            disconnectReason: details.reason,
            timestamp: Date.now(),
            data: details
        });
        
        // Show user feedback
        this.showOfflineDisconnectionNotice();
    }

    showOfflineDisconnectionNotice() {
        const notice = document.createElement('div');
        notice.className = 'fixed bottom-4 left-4 right-4 bg-yellow-500/90 text-black p-4 rounded-lg backdrop-blur-sm z-50';
        notice.innerHTML = `
            <div class="flex items-start space-x-3">
                <i class="fas fa-exclamation-triangle text-lg mt-0.5"></i>
                <div class="flex-1">
                    <div class="font-medium">Connection Interrupted</div>
                    <div class="text-sm mt-1">
                        Your secure connection was lost due to network issues. 
                        It will be restored automatically when you're back online.
                    </div>
                </div>
                <button onclick="this.parentElement.remove()" 
                        class="text-black hover:text-gray-700 transition-colors">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
        
        document.body.appendChild(notice);
        
        setTimeout(() => {
            if (notice.parentElement) {
                notice.remove();
            }
        }, 8000);
    }

    handleNetworkFailure(error) {
        console.log('🌐 Network failure detected:', error?.message);
        
        // Queue the failed action for retry if appropriate
        if (this.shouldQueueFailedRequest(error)) {
            this.queueOfflineAction({
                type: 'network_retry',
                data: { error: error?.message },
                priority: 1,
                maxRetries: 2
            });
        }
    }

    shouldQueueFailedRequest(error) {
        if (!error) return false;
        
        const queueableErrors = [
            'fetch',
            'network',
            'connection',
            'timeout',
            'offline',
            'ERR_NETWORK',
            'ERR_INTERNET_DISCONNECTED'
        ];
        
        const errorString = error.toString().toLowerCase();
        return queueableErrors.some(err => errorString.includes(err)) && !this.isOnline;
    }

    isNetworkError(error) {
        if (!error) return false;
        
        const networkErrorPatterns = [
            /fetch/i,
            /network/i,
            /connection/i,
            /timeout/i,
            /offline/i,
            /ERR_NETWORK/i,
            /ERR_INTERNET_DISCONNECTED/i
        ];
        
        const errorString = error.toString();
        return networkErrorPatterns.some(pattern => pattern.test(errorString));
    }

    handleInitializationError(error) {
        console.error('🚨 Offline manager initialization error:', error);
        
        // Show fallback UI
        const fallback = document.createElement('div');
        fallback.className = 'fixed bottom-4 right-4 bg-red-500 text-white p-4 rounded-lg shadow-lg z-50 max-w-sm';
        fallback.innerHTML = `
            <div class="flex items-start space-x-3">
                <i class="fas fa-exclamation-triangle text-lg mt-0.5"></i>
                <div>
                    <div class="font-medium">Offline Mode Unavailable</div>
                    <div class="text-sm opacity-90 mt-1">
                        Some offline features may not work properly. 
                        Please ensure you have a stable internet connection.
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(fallback);
        
        setTimeout(() => fallback.remove(), 8000);
    }

    showOfflineHelp() {
        const helpModal = document.createElement('div');
        helpModal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4 backdrop-blur-sm';
        helpModal.innerHTML = `
            <div class="bg-gray-800 rounded-xl p-6 max-w-lg w-full max-h-[80vh] overflow-y-auto">
                <div class="flex items-center mb-6">
                    <div class="w-12 h-12 bg-blue-500/10 rounded-full flex items-center justify-center mr-4">
                        <i class="fas fa-question-circle text-blue-400 text-xl"></i>
                    </div>
                    <h3 class="text-xl font-semibold text-white">Offline Mode Guide</h3>
                </div>
                
                <div class="space-y-6 text-gray-300 text-sm">
                    <div>
                        <h4 class="font-medium text-white mb-3 flex items-center">
                            <i class="fas fa-check-circle text-green-400 mr-2"></i>
                            What works offline:
                        </h4>
                        <ul class="space-y-2 ml-6">
                            <li>• App interface and navigation</li>
                            <li>• Previously cached resources</li>
                            <li>• Session data and keys (preserved in memory)</li>
                            <li>• Message queuing for later delivery</li>
                            <li>• Basic cryptographic operations</li>
                        </ul>
                    </div>
                    
                    <div>
                        <h4 class="font-medium text-white mb-3 flex items-center">
                            <i class="fas fa-times-circle text-red-400 mr-2"></i>
                            What requires internet:
                        </h4>
                        <ul class="space-y-2 ml-6">
                            <li>• P2P connections (WebRTC)</li>
                            <li>• Lightning Network payments</li>
                            <li>• Real-time messaging</li>
                            <li>• Session verification</li>
                            <li>• Key exchange with new peers</li>
                        </ul>
                    </div>
                    
                    <div>
                        <h4 class="font-medium text-white mb-3 flex items-center">
                            <i class="fas fa-sync-alt text-blue-400 mr-2"></i>
                            Automatic sync:
                        </h4>
                        <p class="ml-6">
                            When you're back online, all queued messages and actions 
                            will be automatically synchronized. No data is lost.
                        </p>
                    </div>
                    
                    <div class="bg-orange-500/10 border border-orange-500/20 rounded-lg p-4">
                        <h4 class="font-medium text-orange-300 mb-2 flex items-center">
                            <i class="fas fa-shield-alt mr-2"></i>
                            Security Notice
                        </h4>
                        <p class="text-orange-200 text-xs">
                            Your encryption keys and session data remain secure even offline. 
                            SecureBit.chat never stores sensitive information on servers.
                        </p>
                    </div>
                </div>
                
                <button onclick="this.parentElement.parentElement.remove()" 
                        class="w-full bg-blue-500 hover:bg-blue-600 text-white py-3 px-4 rounded-lg font-medium transition-colors mt-6">
                    Close Guide
                </button>
            </div>
        `;
        
        document.body.appendChild(helpModal);
    }

    promisifyRequest(request) {
        return new Promise((resolve, reject) => {
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    // Public API methods
    async addToQueue(type, data, priority = 1) {
        return this.queueOfflineAction({ type, data, priority });
    }

    async forceSync() {
        if (this.isOnline) {
            return this.processOfflineQueue();
        } else {
            console.warn('⚠️ Cannot sync while offline');
            return Promise.resolve();
        }
    }

    getStatus() {
        return {
            isOnline: this.isOnline,
            queueLength: this.offlineQueue.length,
            syncInProgress: this.syncInProgress,
            hasOfflineDB: !!this.offlineDB,
            lastSyncTime: this.lastSyncTime,
            reconnectAttempts: this.reconnectAttempts
        };
    }

    clearOfflineData() {
        return Promise.all([
            this.clearStoredData('offlineQueue'),
            this.clearStoredData('messageQueue'),
            this.clearStoredData('sessionData'),
            this.clearStoredData('appState')
        ]).then(() => {
            this.offlineQueue = [];
            console.log('🗑️ All offline data cleared');
        });
    }

    // Cleanup method
    destroy() {
        if (this.reconnectInterval) {
            clearInterval(this.reconnectInterval);
        }
        
        if (this.offlineDB) {
            this.offlineDB.close();
        }
        
        console.log('🧹 Offline Manager destroyed');
    }
}

// Singleton pattern
let instance = null;

const PWAOfflineManager = {
    getInstance() {
        if (!instance) {
            instance = new PWAOfflineManager();
        }
        return instance;
    },
    
    init() {
        return this.getInstance();
    }
};

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PWAOfflineManager;
} else if (typeof window !== 'undefined' && !window.PWAOfflineManager) {
    window.PWAOfflineManager = PWAOfflineManager;
}

// Auto-initialize when DOM is ready
if (typeof window !== 'undefined' && !window.pwaOfflineManager) {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            if (!window.pwaOfflineManager) {
                window.pwaOfflineManager = PWAOfflineManager.init();
            }
        });
    } else {
        if (!window.pwaOfflineManager) {
            window.pwaOfflineManager = PWAOfflineManager.init();
        }
    }
}