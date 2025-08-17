// PWA Offline Component for SecureBit.chat
// Handles offline functionality and user experience

window.PWAOfflineManager = (() => {
    'use strict';

    class PWAOfflineManager {
        constructor() {
            this.isOnline = navigator.onLine;
            this.offlineQueue = [];
            this.syncInProgress = false;
            this.offlineIndicator = null;
            
            this.init();
        }

        init() {
            console.log('📴 PWA Offline Manager initializing...');
            
            this.setupEventListeners();
            this.createOfflineIndicator();
            this.setupOfflineStorage();
            this.registerBackgroundSync();
            
            // Show initial status
            this.updateConnectionStatus(this.isOnline);
            
            console.log('✅ PWA Offline Manager initialized');
        }

        setupEventListeners() {
            window.addEventListener('online', () => {
                console.log('🌐 Connection restored');
                this.isOnline = true;
                this.updateConnectionStatus(true);
                this.processOfflineQueue();
            });

            window.addEventListener('offline', () => {
                console.log('📴 Connection lost');
                this.isOnline = false;
                this.updateConnectionStatus(false);
                this.showOfflineGuidance();
            });

            // Monitor WebRTC connection status
            document.addEventListener('peer-disconnect', () => {
                if (!this.isOnline) {
                    this.handleOfflineDisconnect();
                }
            });

            // Monitor failed network requests
            window.addEventListener('unhandledrejection', (event) => {
                if (this.isNetworkError(event.reason)) {
                    this.handleNetworkFailure(event.reason);
                }
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
                    <div class="pwa-online-indicator flex items-center space-x-2">
                        <div class="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                        <span>🌐 Back online</span>
                    </div>
                `;
                this.offlineIndicator.classList.remove('hidden');
                
                // Hide after 3 seconds
                setTimeout(() => {
                    this.offlineIndicator.classList.add('hidden');
                }, 3000);
            } else {
                this.offlineIndicator.innerHTML = `
                    <div class="pwa-offline-indicator flex items-center space-x-2">
                        <div class="w-2 h-2 bg-red-400 rounded-full"></div>
                        <span>📴 Offline mode</span>
                    </div>
                `;
                this.offlineIndicator.classList.remove('hidden');
            }
        }

        showOfflineGuidance() {
            const guidance = document.createElement('div');
            guidance.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4';
            guidance.innerHTML = `
                <div class="bg-gray-800 rounded-xl p-6 max-w-md w-full text-center">
                    <div class="w-16 h-16 bg-red-500/10 rounded-full flex items-center justify-center mx-auto mb-4">
                        <i class="fas fa-wifi-slash text-red-400 text-2xl"></i>
                    </div>
                    <h3 class="text-xl font-semibold text-white mb-3">Connection Lost</h3>
                    <p class="text-gray-300 mb-4 text-sm leading-relaxed">
                        Your internet connection was lost. SecureBit.chat requires an active connection for secure P2P communication.
                    </p>
                    <div class="space-y-3 text-left mb-6">
                        <div class="flex items-center text-sm text-gray-400">
                            <i class="fas fa-info-circle mr-2 text-blue-400"></i>
                            <span>Your session and keys are preserved</span>
                        </div>
                        <div class="flex items-center text-sm text-gray-400">
                            <i class="fas fa-shield-alt mr-2 text-green-400"></i>
                            <span>No data is stored on servers</span>
                        </div>
                        <div class="flex items-center text-sm text-gray-400">
                            <i class="fas fa-sync-alt mr-2 text-yellow-400"></i>
                            <span>Connection will resume automatically</span>
                        </div>
                    </div>
                    <button onclick="this.parentElement.parentElement.remove()" 
                            class="w-full bg-orange-500 hover:bg-orange-600 text-white py-3 px-4 rounded-lg font-medium transition-colors">
                        Continue in Offline Mode
                    </button>
                </div>
            `;
            
            document.body.appendChild(guidance);
            
            // Auto-remove after 10 seconds
            setTimeout(() => {
                if (guidance.parentElement) {
                    guidance.remove();
                }
            }, 10000);
        }

        setupOfflineStorage() {
            // Initialize IndexedDB for offline data storage
            this.initOfflineDB().catch(error => {
                console.warn('⚠️ Offline storage not available:', error);
            });
        }

        async initOfflineDB() {
            return new Promise((resolve, reject) => {
                const request = indexedDB.open('SecureBitOffline', 1);
                
                request.onerror = () => reject(request.error);
                request.onsuccess = () => {
                    this.offlineDB = request.result;
                    resolve(this.offlineDB);
                };
                
                request.onupgradeneeded = (event) => {
                    const db = event.target.result;
                    
                    // Store for offline queue
                    if (!db.objectStoreNames.contains('offlineQueue')) {
                        const queueStore = db.createObjectStore('offlineQueue', { 
                            keyPath: 'id', 
                            autoIncrement: true 
                        });
                        queueStore.createIndex('timestamp', 'timestamp', { unique: false });
                        queueStore.createIndex('type', 'type', { unique: false });
                    }
                    
                    // Store for session recovery
                    if (!db.objectStoreNames.contains('sessionData')) {
                        const sessionStore = db.createObjectStore('sessionData', { 
                            keyPath: 'key' 
                        });
                    }
                };
            });
        }

        registerBackgroundSync() {
            if ('serviceWorker' in navigator && 'sync' in window.ServiceWorkerRegistration.prototype) {
                navigator.serviceWorker.ready.then(registration => {
                    console.log('📡 Background sync registered');
                    this.swRegistration = registration;
                });
            } else {
                console.warn('⚠️ Background sync not supported');
            }
        }

        async queueOfflineAction(action) {
            if (!this.offlineDB) {
                console.warn('⚠️ Offline storage not available');
                return;
            }

            const queueItem = {
                ...action,
                timestamp: Date.now(),
                id: Date.now() + Math.random()
            };

            try {
                const transaction = this.offlineDB.transaction(['offlineQueue'], 'readwrite');
                const store = transaction.objectStore('offlineQueue');
                await store.add(queueItem);
                
                console.log('📤 Action queued for when online:', action.type);
                this.offlineQueue.push(queueItem);
                
                // Try to sync in background
                if (this.swRegistration) {
                    await this.swRegistration.sync.register('retry-offline-actions');
                }
            } catch (error) {
                console.error('❌ Failed to queue offline action:', error);
            }
        }

        async processOfflineQueue() {
            if (this.syncInProgress || !this.isOnline) {
                return;
            }

            this.syncInProgress = true;
            console.log('🔄 Processing offline queue...');

            try {
                if (this.offlineDB) {
                    const transaction = this.offlineDB.transaction(['offlineQueue'], 'readwrite');
                    const store = transaction.objectStore('offlineQueue');
                    const allItems = await this.getAllFromStore(store);
                    
                    for (const item of allItems) {
                        try {
                            await this.processQueueItem(item);
                            await store.delete(item.id);
                            console.log('✅ Processed offline action:', item.type);
                        } catch (error) {
                            console.error('❌ Failed to process offline action:', error);
                            // Keep item in queue for retry
                        }
                    }
                }

                // Process in-memory queue as fallback
                const memoryQueue = [...this.offlineQueue];
                this.offlineQueue = [];
                
                for (const item of memoryQueue) {
                    try {
                        await this.processQueueItem(item);
                    } catch (error) {
                        console.error('❌ Failed to process memory queue item:', error);
                        this.offlineQueue.push(item); // Re-queue on failure
                    }
                }

                if (memoryQueue.length > 0) {
                    this.showSyncNotification(memoryQueue.length);
                }

            } catch (error) {
                console.error('❌ Error processing offline queue:', error);
            } finally {
                this.syncInProgress = false;
            }
        }

        async getAllFromStore(store) {
            return new Promise((resolve, reject) => {
                const request = store.getAll();
                request.onsuccess = () => resolve(request.result);
                request.onerror = () => reject(request.error);
            });
        }

        async processQueueItem(item) {
            switch (item.type) {
                case 'message':
                    return this.retryMessage(item.data);
                case 'connection':
                    return this.retryConnection(item.data);
                case 'payment_check':
                    return this.retryPaymentCheck(item.data);
                default:
                    console.warn('Unknown queue item type:', item.type);
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

        showSyncNotification(count) {
            const notification = document.createElement('div');
            notification.className = 'fixed bottom-4 right-4 bg-green-500 text-white p-4 rounded-lg shadow-lg z-50 max-w-sm';
            notification.innerHTML = `
                <div class="flex items-center space-x-3">
                    <i class="fas fa-sync-alt text-lg"></i>
                    <div>
                        <div class="font-medium">Sync Complete</div>
                        <div class="text-sm opacity-90">${count} offline action(s) processed</div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(notification);
            
            // Auto-remove after 4 seconds
            setTimeout(() => {
                notification.remove();
            }, 4000);
        }

        handleOfflineDisconnect() {
            // Handle WebRTC disconnection while offline
            console.log('🔌 WebRTC disconnected while offline');
            
            const reconnectBanner = document.createElement('div');
            reconnectBanner.className = 'fixed top-0 left-0 right-0 bg-yellow-500 text-black p-3 z-50 text-center';
            reconnectBanner.innerHTML = `
                <div class="flex items-center justify-center space-x-2">
                    <i class="fas fa-exclamation-triangle"></i>
                    <span>Connection lost. Will attempt to reconnect when online.</span>
                </div>
            `;
            
            document.body.appendChild(reconnectBanner);
            
            setTimeout(() => {
                if (reconnectBanner.parentElement) {
                    reconnectBanner.remove();
                }
            }, 5000);
        }

        handleNetworkFailure(error) {
            console.log('🌐 Network failure detected:', error?.message);
            
            // Queue the failed action for retry
            if (this.shouldQueueAction(error)) {
                this.queueOfflineAction({
                    type: 'network_retry',
                    data: { error: error?.message },
                    timestamp: Date.now()
                });
            }
        }

        isNetworkError(error) {
            if (!error) return false;
            
            const networkErrorMessages = [
                'fetch',
                'network',
                'connection',
                'timeout',
                'offline',
                'ERR_NETWORK',
                'ERR_INTERNET_DISCONNECTED'
            ];
            
            const errorString = error.toString().toLowerCase();
            return networkErrorMessages.some(msg => errorString.includes(msg));
        }

        shouldQueueAction(error) {
            // Determine if the action should be queued for retry
            return this.isNetworkError(error) && !this.isOnline;
        }

        async saveSessionForRecovery(sessionData) {
            if (!this.offlineDB) return;

            try {
                const transaction = this.offlineDB.transaction(['sessionData'], 'readwrite');
                const store = transaction.objectStore('sessionData');
                
                await store.put({
                    key: 'current_session',
                    data: sessionData,
                    timestamp: Date.now()
                });
                
                console.log('💾 Session data saved for offline recovery');
            } catch (error) {
                console.error('❌ Failed to save session data:', error);
            }
        }

        async recoverSession() {
            if (!this.offlineDB) return null;

            try {
                const transaction = this.offlineDB.transaction(['sessionData'], 'readonly');
                const store = transaction.objectStore('sessionData');
                const result = await this.getFromStore(store, 'current_session');
                
                if (result && Date.now() - result.timestamp < 24 * 60 * 60 * 1000) { // 24 hours
                    console.log('🔄 Session data recovered from offline storage');
                    return result.data;
                }
            } catch (error) {
                console.error('❌ Failed to recover session data:', error);
            }
            
            return null;
        }

        async getFromStore(store, key) {
            return new Promise((resolve, reject) => {
                const request = store.get(key);
                request.onsuccess = () => resolve(request.result);
                request.onerror = () => reject(request.error);
            });
        }

        clearOfflineData() {
            if (!this.offlineDB) return;

            try {
                const transaction = this.offlineDB.transaction(['offlineQueue', 'sessionData'], 'readwrite');
                transaction.objectStore('offlineQueue').clear();
                transaction.objectStore('sessionData').clear();
                
                this.offlineQueue = [];
                console.log('🗑️ Offline data cleared');
            } catch (error) {
                console.error('❌ Failed to clear offline data:', error);
            }
        }

        getOfflineStatus() {
            return {
                isOnline: this.isOnline,
                queueLength: this.offlineQueue.length,
                syncInProgress: this.syncInProgress,
                hasOfflineDB: !!this.offlineDB,
                lastSync: this.lastSyncTime || null
            };
        }

        // Public API methods
        async addToOfflineQueue(type, data) {
            return this.queueOfflineAction({ type, data });
        }

        forceSync() {
            if (this.isOnline) {
                return this.processOfflineQueue();
            } else {
                console.warn('⚠️ Cannot sync while offline');
                return Promise.resolve();
            }
        }

        showOfflineHelp() {
            const helpModal = document.createElement('div');
            helpModal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4';
            helpModal.innerHTML = `
                <div class="bg-gray-800 rounded-xl p-6 max-w-lg w-full">
                    <div class="flex items-center mb-4">
                        <div class="w-12 h-12 bg-blue-500/10 rounded-full flex items-center justify-center mr-4">
                            <i class="fas fa-question-circle text-blue-400 text-xl"></i>
                        </div>
                        <h3 class="text-xl font-semibold text-white">Offline Mode Help</h3>
                    </div>
                    
                    <div class="space-y-4 text-gray-300 text-sm">
                        <div>
                            <h4 class="font-medium text-white mb-2">What works offline:</h4>
                            <ul class="space-y-1 ml-4">
                                <li>• App interface and navigation</li>
                                <li>• Previously cached resources</li>
                                <li>• Session data recovery</li>
                                <li>• Offline message queuing</li>
                            </ul>
                        </div>
                        
                        <div>
                            <h4 class="font-medium text-white mb-2">What needs internet:</h4>
                            <ul class="space-y-1 ml-4">
                                <li>• P2P connections (WebRTC)</li>
                                <li>• Lightning payments</li>
                                <li>• Real-time messaging</li>
                                <li>• Session verification</li>
                            </ul>
                        </div>
                        
                        <div class="bg-blue-500/10 border border-blue-500/20 rounded-lg p-3">
                            <p class="text-blue-300 text-xs">
                                <i class="fas fa-info-circle mr-1"></i>
                                Your messages and actions will be automatically synced when you're back online.
                            </p>
                        </div>
                    </div>
                    
                    <button onclick="this.parentElement.parentElement.remove()" 
                            class="w-full bg-blue-500 hover:bg-blue-600 text-white py-3 px-4 rounded-lg font-medium transition-colors mt-6">
                        Got it
                    </button>
                </div>
            `;
            
            document.body.appendChild(helpModal);
        }
    }

    // Initialize and return singleton
    let instance = null;
    
    return {
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
})();

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.pwaOfflineManager = window.PWAOfflineManager.init();
    });
} else {
    window.pwaOfflineManager = window.PWAOfflineManager.init();
}