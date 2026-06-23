// PWA Offline Manager for SecureBit.chat
// Enhanced Security Edition v4.02.442
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
                
                // Listen for database close events
                this.offlineDB.onclose = () => {
                    console.log('🔒 IndexedDB connection closed');
                    this.offlineDB = null;
                };
                
                // Listen for database errors
                this.offlineDB.onerror = (event) => {
                    console.error('❌ IndexedDB error:', event);
                };
                
                resolve(this.offlineDB);
            };
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                
                // Create object stores
                Object.entries(this.dbConfig.stores).forEach(([storeName, config]) => {
                    if (!db.objectStoreNames.contains(storeName)) {
                        
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

    /**
     * Ensure database is open, reopen if necessary
     */
    async ensureDatabaseOpen() {
        // Check if database exists and is open
        if (this.offlineDB && this.offlineDB.objectStoreNames.length > 0) {
            // Check if database connection is still valid
            try {
                // Try to access objectStoreNames to verify connection is active
                const storeNames = this.offlineDB.objectStoreNames;
                if (storeNames.length > 0) {
                    return; // Database is open and valid
                }
            } catch (error) {
                // Database connection is invalid, need to reopen
                console.warn('⚠️ Database connection invalid, reopening...');
                this.offlineDB = null;
            }
        }

        // Database is closed or invalid, reopen it
        if (!this.offlineDB) {
            try {
                await this.initOfflineDB();
            } catch (error) {
                console.error('❌ Failed to reopen database:', error);
                throw new Error('Database unavailable');
            }
        }
    }

    setupEventListeners() {
        // Network status changes
        window.addEventListener('online', () => {
            this.isOnline = true;
            this.reconnectAttempts = 0;
            this.updateConnectionStatus(true);
            this.handleConnectionRestored();
        });

        window.addEventListener('offline', () => {
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

        // Clean pill matching the app's design language (no emoji, no FontAwesome,
        // proper SVG close wired via a real listener — the old inline onclick was
        // blocked by the CSP anyway).
        const PILL = "display:inline-flex; align-items:center; gap:10px; padding:9px 14px; border-radius:11px; background:#161618; box-shadow:0 12px 30px rgba(0,0,0,0.45); font-family:'Manrope',system-ui,-apple-system,sans-serif; font-size:13px; font-weight:600; color:#e8e8eb;";

        if (isOnline) {
            this.offlineIndicator.innerHTML =
                `<div style="${PILL} border:1px solid rgba(62,207,142,0.3);">
                    <span style="width:8px; height:8px; border-radius:50%; background:#3ecf8e; box-shadow:0 0 8px rgba(62,207,142,0.6);"></span>
                    <span>Back online</span>
                </div>`;
            this.offlineIndicator.classList.remove('hidden');
            // Auto-hide after 3 seconds.
            setTimeout(() => {
                if (this.offlineIndicator) this.offlineIndicator.classList.add('hidden');
            }, 3000);
        } else {
            this.offlineIndicator.innerHTML =
                `<div style="${PILL} border:1px solid rgba(227,179,65,0.32);">
                    <span style="width:8px; height:8px; border-radius:50%; background:#e3b341;"></span>
                    <span>Offline mode</span>
                    <button class="oi-close" type="button" aria-label="Dismiss" style="margin-left:4px; width:22px; height:22px; padding:0; display:grid; place-items:center; border:none; background:transparent; color:#8a8a92; cursor:pointer; border-radius:6px; transition:color .15s ease;">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="pointer-events:none;"><path d="M6 6l12 12M18 6L6 18"/></svg>
                    </button>
                </div>`;
            this.offlineIndicator.classList.remove('hidden');
            const closeBtn = this.offlineIndicator.querySelector('.oi-close');
            if (closeBtn) {
                closeBtn.addEventListener('mouseenter', () => { closeBtn.style.color = '#e8e8eb'; });
                closeBtn.addEventListener('mouseleave', () => { closeBtn.style.color = '#8a8a92'; });
                closeBtn.addEventListener('click', () => this.offlineIndicator.classList.add('hidden'));
            }
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

        // Offline modal — translated from the Claude Design component
        // (Offline Modal.dc.html). Two views (main + details) inside one card.
        if (!document.getElementById('pwa-offline-modal-kf')) {
            const style = document.createElement('style');
            style.id = 'pwa-offline-modal-kf';
            style.textContent =
                '@keyframes omPop{from{opacity:0;transform:scale(.96) translateY(10px)}to{opacity:1;transform:scale(1) translateY(0)}}' +
                '@keyframes omFade{from{opacity:0}to{opacity:1}}' +
                '@keyframes omSwap{from{opacity:0;transform:translateX(10px)}to{opacity:1;transform:translateX(0)}}';
            document.head.appendChild(style);
        }

        const guidance = document.createElement('div');
        guidance.id = 'pwa-offline-modal';
        guidance.style.cssText = "position:fixed; inset:0; z-index:9999; display:flex; align-items:center; justify-content:center; padding:24px; background:rgba(8,8,10,0.55); backdrop-filter:blur(3px); -webkit-backdrop-filter:blur(3px); animation:omFade .3s ease; font-family:'Manrope',system-ui,-apple-system,sans-serif;";

        const feature = (bg, bd, stroke, sw, icon, text) => `
            <div style="display:flex; align-items:center; gap:13px;">
                <span style="flex:none; width:34px; height:34px; border-radius:9px; display:grid; place-items:center; background:${bg}; border:1px solid ${bd};"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="${stroke}" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round">${icon}</svg></span>
                <span style="font-size:14.5px; color:#e8e8eb;">${text}</span>
            </div>`;

        const card = (bg, bd, stroke, icon, title, desc) => `
            <div style="display:flex; align-items:flex-start; gap:13px; padding:14px 16px; border-radius:13px; background:#161618; border:1px solid rgba(255,255,255,0.06);">
                <span style="flex:none; width:36px; height:36px; border-radius:10px; display:grid; place-items:center; background:${bg}; border:1px solid ${bd};"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="${stroke}" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">${icon}</svg></span>
                <div><div style="font-size:14.5px; font-weight:700; color:#f4f4f6; margin-bottom:2px;">${title}</div><div style="font-size:13px; line-height:1.5; color:#8a8a92;">${desc}</div></div>
            </div>`;

        const GREEN_BG = 'rgba(62,207,142,0.12)', GREEN_BD = 'rgba(62,207,142,0.24)';
        const ORANGE_BG = 'rgba(240,137,42,0.12)', ORANGE_BD = 'rgba(240,137,42,0.24)';

        const mainHTML = `
            <div style="animation:omSwap .26s cubic-bezier(.2,.7,.3,1);">
                <div style="text-align:center; margin-bottom:22px;">
                    <div style="display:inline-flex; width:64px; height:64px; border-radius:50%; align-items:center; justify-content:center; background:rgba(227,179,65,0.12); border:1px solid rgba(227,179,65,0.3); margin-bottom:18px;">
                        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#e3b341" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M2 8.8a15 15 0 0 1 20 0"/><path d="M5 12.5a11 11 0 0 1 14 0"/><path d="M8.5 16.3a6 6 0 0 1 7 0"/><path d="M12 20h.01"/><path d="M2 2l20 20"/></svg>
                    </div>
                    <h3 style="margin:0 0 10px; font-size:24px; font-weight:800; letter-spacing:-0.6px; color:#f4f4f6;">Connection lost</h3>
                    <p style="margin:0 auto; max-width:380px; font-size:14px; line-height:1.55; color:#9a9aa2;">SecureBit is now in offline mode. Some features are limited, but your data stays safe.</p>
                </div>
                <div style="display:flex; flex-direction:column; gap:14px; margin-bottom:24px; padding:0 6px;">
                    ${feature(GREEN_BG, GREEN_BD, '#3ecf8e', '2.3', '<path d="M5 13l4 4 10-11"/>', 'Your session and keys are preserved')}
                    ${feature(GREEN_BG, GREEN_BD, '#3ecf8e', '1.9', '<path d="M12 3l8 4v5c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V7l8-4z"/>', 'No data is stored on servers')}
                    ${feature(ORANGE_BG, ORANGE_BD, '#f0892a', '1.9', '<path d="M21 8a8.5 8.5 0 0 0-15.6-2.5M3 4v4h4"/><path d="M3 16a8.5 8.5 0 0 0 15.6 2.5M21 20v-4h-4"/>', 'Messages &amp; files sync when you reconnect')}
                </div>
                <div style="display:flex; flex-direction:column; gap:11px;">
                    <div style="display:flex; gap:12px;">
                        <button class="om-continue" type="button" style="flex:1; padding:14px 18px; border-radius:13px; border:none; background:#f0892a; color:#1a0f04; font-family:inherit; font-size:15px; font-weight:700; cursor:pointer; box-shadow:0 8px 24px rgba(240,137,42,0.28); transition:all .2s cubic-bezier(.2,.7,.3,1);">Continue offline</button>
                        <button class="om-disconnect" type="button" style="flex:1; display:inline-flex; align-items:center; justify-content:center; gap:9px; padding:14px 18px; border-radius:13px; border:1px solid rgba(229,114,122,0.3); background:rgba(229,114,122,0.08); color:#e5727a; font-family:inherit; font-size:15px; font-weight:700; cursor:pointer; transition:all .2s cubic-bezier(.2,.7,.3,1);">
                            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="pointer-events:none;"><path d="M12 4v8"/><path d="M7 7a8 8 0 1 0 10 0"/></svg>
                            Disconnect
                        </button>
                    </div>
                    <button class="om-learn" type="button" style="width:100%; display:inline-flex; align-items:center; justify-content:center; gap:8px; padding:12px 18px; border-radius:13px; border:none; background:transparent; color:#9a9aa2; font-family:inherit; font-size:14px; font-weight:600; cursor:pointer; transition:color .18s cubic-bezier(.2,.7,.3,1);">
                        Learn more
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" style="pointer-events:none;"><path d="M5 12h14M13 6l6 6-6 6"/></svg>
                    </button>
                </div>
            </div>`;

        const detailsHTML = `
            <div style="animation:omSwap .26s cubic-bezier(.2,.7,.3,1);">
                <div style="display:flex; align-items:center; gap:12px; margin-bottom:18px;">
                    <button class="om-back" type="button" title="Back" style="flex:none; width:34px; height:34px; border-radius:10px; display:grid; place-items:center; border:1px solid rgba(255,255,255,0.1); background:rgba(255,255,255,0.025); color:#cfcfd4; cursor:pointer; transition:all .18s cubic-bezier(.2,.7,.3,1);">
                        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" style="pointer-events:none;"><path d="M15 6l-6 6 6 6"/></svg>
                    </button>
                    <h3 style="margin:0; font-size:20px; font-weight:800; letter-spacing:-0.5px; color:#f4f4f6;">When you reconnect</h3>
                </div>
                <p style="margin:0 0 20px; font-size:14px; line-height:1.6; color:#9a9aa2;">A dropped connection costs you nothing. SecureBit queues everything locally and resumes the encrypted session the instant you're back online.</p>
                <div style="display:flex; flex-direction:column; gap:11px; margin-bottom:22px;">
                    ${card(GREEN_BG, GREEN_BD, '#3ecf8e', '<path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4z"/>', 'Your messages get delivered', 'Everything you wrote while offline is sent to your contact automatically.')}
                    ${card(GREEN_BG, GREEN_BD, '#3ecf8e', '<path d="M14 3v5h5"/><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M12 18v-6M9.5 14.5L12 12l2.5 2.5"/>', 'Files finish transferring', 'Uploads resume from where they stopped — no need to resend.')}
                    ${card(GREEN_BG, GREEN_BD, '#3ecf8e', '<path d="M12 3v12"/><path d="M7.5 10.5L12 15l4.5-4.5"/><path d="M5 20h14"/>', 'Their messages &amp; files arrive', 'Whatever your contact sent during the outage is delivered to you in order.')}
                    ${card(ORANGE_BG, ORANGE_BD, '#f0892a', '<path d="M12 3l8 4v5c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V7l8-4z"/><path d="M9.2 12.2l2 2 3.6-3.8"/>', 'Nothing is lost', "After reconnect there's no gap — the conversation continues exactly where it paused.")}
                </div>
                <button class="om-gotit" type="button" style="width:100%; padding:14px 18px; border-radius:13px; border:none; background:#f0892a; color:#1a0f04; font-family:inherit; font-size:15px; font-weight:700; cursor:pointer; box-shadow:0 8px 24px rgba(240,137,42,0.28); transition:all .2s cubic-bezier(.2,.7,.3,1);">Got it</button>
            </div>`;

        const cardWrap = document.createElement('div');
        cardWrap.style.cssText = "position:relative; z-index:2; width:470px; max-width:calc(100vw - 48px); border-radius:22px; background:#121214; border:1px solid rgba(255,255,255,0.08); padding:34px 30px 26px; box-shadow:0 30px 70px rgba(0,0,0,0.6); animation:omPop .32s cubic-bezier(.2,.7,.3,1);";
        guidance.appendChild(cardWrap);

        const hoverLift = (btn) => {
            btn.addEventListener('mouseenter', () => { btn.style.background = '#ff9637'; btn.style.transform = 'translateY(-2px)'; });
            btn.addEventListener('mouseleave', () => { btn.style.background = '#f0892a'; btn.style.transform = 'none'; });
        };
        const close = () => guidance.remove();

        const renderMain = () => {
            cardWrap.innerHTML = mainHTML;
            const cont = cardWrap.querySelector('.om-continue');
            hoverLift(cont);
            cont.addEventListener('click', close);

            const disc = cardWrap.querySelector('.om-disconnect');
            disc.addEventListener('mouseenter', () => { disc.style.background = 'rgba(229,114,122,0.14)'; disc.style.borderColor = 'rgba(229,114,122,0.5)'; });
            disc.addEventListener('mouseleave', () => { disc.style.background = 'rgba(229,114,122,0.08)'; disc.style.borderColor = 'rgba(229,114,122,0.3)'; });
            disc.addEventListener('click', () => {
                try {
                    if (window.webrtcManager && typeof window.webrtcManager.disconnect === 'function') {
                        window.webrtcManager.disconnect();
                    }
                } catch (e) { console.warn('Offline modal disconnect failed:', e); }
                close();
            });

            const learn = cardWrap.querySelector('.om-learn');
            learn.addEventListener('mouseenter', () => { learn.style.color = '#f0892a'; });
            learn.addEventListener('mouseleave', () => { learn.style.color = '#9a9aa2'; });
            learn.addEventListener('click', renderDetails);
        };

        const renderDetails = () => {
            cardWrap.innerHTML = detailsHTML;
            const back = cardWrap.querySelector('.om-back');
            back.addEventListener('mouseenter', () => { back.style.color = '#f0892a'; back.style.borderColor = 'rgba(240,137,42,0.45)'; });
            back.addEventListener('mouseleave', () => { back.style.color = '#cfcfd4'; back.style.borderColor = 'rgba(255,255,255,0.1)'; });
            back.addEventListener('click', renderMain);

            const gotit = cardWrap.querySelector('.om-gotit');
            hoverLift(gotit);
            gotit.addEventListener('click', renderMain);
        };

        renderMain();
        // Click on the backdrop (outside the card) dismisses.
        guidance.addEventListener('click', (e) => { if (e.target === guidance) close(); });

        document.body.appendChild(guidance);

        // Save that we showed the guidance
        localStorage.setItem('offline_guidance_shown', Date.now().toString());
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
            
            // Try to detect if we're actually back online
            this.checkOnlineStatus();
            
            if (this.reconnectAttempts >= this.maxReconnectAttempts) {
                clearInterval(this.reconnectInterval);
                this.reconnectInterval = null;
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
                this.isOnline = true;
                this.handleConnectionRestored();
            }
        } catch (error) {
            // Still offline
            console.log('📴 Still offline');
        }
    }

    async queueOfflineAction(action) {
        const queueItem = {
            ...action,
            id: Date.now() + Math.random(),
            timestamp: Date.now(),
            priority: action.priority || 1,
            retryCount: 0,
            maxRetries: action.maxRetries || 3
        };

        // Always add to memory queue as fallback
        this.offlineQueue.push(queueItem);

        if (!this.offlineDB) {
            console.warn('⚠️ Offline database not available, using memory queue only');
            return;
        }

        try {
            await this.ensureDatabaseOpen();
            
            const transaction = this.offlineDB.transaction(['offlineQueue'], 'readwrite');
            const store = transaction.objectStore('offlineQueue');
            await this.promisifyRequest(store.add(queueItem));
            
            // Try to register background sync
            if (this.registration) {
                await this.registration.sync.register('offline-sync');
            }
        } catch (error) {
            if (error.name === 'InvalidStateError' || error.message.includes('closing')) {
                console.warn('⚠️ Database was closing, item added to memory queue only');
            } else {
                console.error('❌ Failed to queue offline action:', error);
            }
            // Item already in memory queue, so no action needed
        }
    }

    async processOfflineQueue() {
        if (this.syncInProgress || !this.isOnline) {
            return;
        }

        this.syncInProgress = true;
        
        let processedCount = 0;
        let errorCount = 0;

        try {
            // Process database queue
            if (this.offlineDB) {
                // Ensure database is open before processing
                await this.ensureDatabaseOpen();
                
                // Check if database is still open
                if (!this.offlineDB || this.offlineDB.objectStoreNames.length === 0) {
                    console.warn('⚠️ Database not available, skipping queue processing');
                    return;
                }

                // Get all items first in a single transaction
                let allItems = [];
                try {
                    const readTransaction = this.offlineDB.transaction(['offlineQueue'], 'readonly');
                    const readStore = readTransaction.objectStore('offlineQueue');
                    allItems = await this.promisifyRequest(readStore.getAll());
                } catch (error) {
                    if (error.name === 'InvalidStateError' || error.message.includes('closing')) {
                        console.warn('⚠️ Database was closing during read, retrying...');
                        await this.ensureDatabaseOpen();
                        const retryTransaction = this.offlineDB.transaction(['offlineQueue'], 'readonly');
                        const retryStore = retryTransaction.objectStore('offlineQueue');
                        allItems = await this.promisifyRequest(retryStore.getAll());
                    } else {
                        throw error;
                    }
                }
                
                // Sort by priority and timestamp
                allItems.sort((a, b) => {
                    if (a.priority !== b.priority) {
                        return b.priority - a.priority; // Higher priority first
                    }
                    return a.timestamp - b.timestamp; // Older first
                });
                
                // Process each item with its own transaction to avoid "database closing" errors
                for (const item of allItems) {
                    try {
                        await this.processQueueItem(item);
                        
                        // Create a new transaction for each delete operation
                        await this.ensureDatabaseOpen();
                        const deleteTransaction = this.offlineDB.transaction(['offlineQueue'], 'readwrite');
                        const deleteStore = deleteTransaction.objectStore('offlineQueue');
                        await this.promisifyRequest(deleteStore.delete(item.id));
                        
                        processedCount++;
                    } catch (error) {
                        console.error('❌ Failed to process offline action:', error);
                        errorCount++;
                        
                        // Increment retry count
                        item.retryCount = (item.retryCount || 0) + 1;
                        
                        if (item.retryCount >= item.maxRetries) {
                            // Max retries reached, remove from queue
                            try {
                                await this.ensureDatabaseOpen();
                                const removeTransaction = this.offlineDB.transaction(['offlineQueue'], 'readwrite');
                                const removeStore = removeTransaction.objectStore('offlineQueue');
                                await this.promisifyRequest(removeStore.delete(item.id));
                                console.log('❌ Max retries reached for action:', item.type);
                            } catch (removeError) {
                                console.error('❌ Failed to remove item after max retries:', removeError);
                            }
                        } else {
                            // Update retry count in database
                            try {
                                await this.ensureDatabaseOpen();
                                const updateTransaction = this.offlineDB.transaction(['offlineQueue'], 'readwrite');
                                const updateStore = updateTransaction.objectStore('offlineQueue');
                                await this.promisifyRequest(updateStore.put(item));
                            } catch (updateError) {
                                console.error('❌ Failed to update retry count:', updateError);
                            }
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
            await this.ensureDatabaseOpen();
            
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

        } catch (error) {
            if (error.name === 'InvalidStateError' || error.message.includes('closing')) {
                console.warn('⚠️ Database was closing, could not save application state');
            } else {
                console.error('❌ Failed to save application state:', error);
            }
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

        try {
            await this.ensureDatabaseOpen();
            const transaction = this.offlineDB.transaction([storeName], 'readwrite');
            const store = transaction.objectStore(storeName);
            return await this.promisifyRequest(store.put(data));
        } catch (error) {
            if (error.name === 'InvalidStateError' || error.message.includes('closing')) {
                await this.ensureDatabaseOpen();
                const retryTransaction = this.offlineDB.transaction([storeName], 'readwrite');
                const retryStore = retryTransaction.objectStore(storeName);
                return await this.promisifyRequest(retryStore.put(data));
            }
            throw error;
        }
    }

    async getStoredData(storeName, key) {
        if (!this.offlineDB) {
            return null;
        }

        try {
            await this.ensureDatabaseOpen();
            const transaction = this.offlineDB.transaction([storeName], 'readonly');
            const store = transaction.objectStore(storeName);
            const result = await this.promisifyRequest(store.get(key));
            return result;
        } catch (error) {
            if (error.name === 'InvalidStateError' || error.message.includes('closing')) {
                console.warn(`⚠️ Database was closing during get from ${storeName}, retrying...`);
                try {
                    await this.ensureDatabaseOpen();
                    const retryTransaction = this.offlineDB.transaction([storeName], 'readonly');
                    const retryStore = retryTransaction.objectStore(storeName);
                    return await this.promisifyRequest(retryStore.get(key));
                } catch (retryError) {
                    console.error(`❌ Failed to get stored data from ${storeName} after retry:`, retryError);
                    return null;
                }
            }
            console.error(`❌ Failed to get stored data from ${storeName}:`, error);
            return null;
        }
    }

    async clearStoredData(storeName, key = null) {
        if (!this.offlineDB) return;

        try {
            await this.ensureDatabaseOpen();
            const transaction = this.offlineDB.transaction([storeName], 'readwrite');
            const store = transaction.objectStore(storeName);
            
            if (key) {
                await this.promisifyRequest(store.delete(key));
            } else {
                await this.promisifyRequest(store.clear());
            }

        } catch (error) {
            if (error.name === 'InvalidStateError' || error.message.includes('closing')) {
                console.warn(`⚠️ Database was closing during clear from ${storeName}`);
            } else {
                console.error(`❌ Failed to clear stored data from ${storeName}:`, error);
            }
        }
    }

    registerBackgroundSync() {
        if ('serviceWorker' in navigator && 'sync' in window.ServiceWorkerRegistration.prototype) {
            navigator.serviceWorker.ready.then(registration => {
                this.registration = registration;
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
            await this.ensureDatabaseOpen();
            
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
            if (error.name === 'InvalidStateError' || error.message.includes('closing')) {
                console.warn('⚠️ Database was closing during cleanup, skipping...');
            } else {
                console.error('❌ Failed to cleanup old data:', error);
            }
        }
    }

    handleOfflineDisconnection(details) {
        
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
            this.reconnectInterval = null;
        }
        
        // Set sync flag to prevent new operations
        this.syncInProgress = true;
        
        // Close database connection
        if (this.offlineDB) {
            try {
                // Only close if database is not in a transaction
                // IndexedDB will automatically close when all transactions complete
                if (this.offlineDB.objectStoreNames.length > 0) {
                    this.offlineDB.close();
                }
                this.offlineDB = null;
            } catch (error) {
                console.warn('⚠️ Error closing database:', error);
                this.offlineDB = null;
            }
        }
        
        console.log('🧹 Offline Manager destroyed');
    }
}

// Singleton pattern
let instance = null;

const PWAOfflineManagerAPI = {
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
    module.exports = PWAOfflineManagerAPI;
} else if (typeof window !== 'undefined' && !window.PWAOfflineManager) {
    window.PWAOfflineManager = PWAOfflineManagerAPI;
}

// Auto-initialize when DOM is ready
if (typeof window !== 'undefined' && !window.pwaOfflineManager) {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            if (!window.pwaOfflineManager) {
                window.pwaOfflineManager = PWAOfflineManagerAPI.init();
            }
        });
    } else {
        if (!window.pwaOfflineManager) {
            window.pwaOfflineManager = PWAOfflineManagerAPI.init();
        }
    }
}