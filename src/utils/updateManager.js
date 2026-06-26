/**
 * UpdateManager - Comprehensive PWA update management system
 * 
 * Automatically detects new application versions and forcefully
 * updates all cache levels: Service Worker, browser cache, localStorage
 * 
 * @class UpdateManager
 */
class UpdateManager {
    constructor(options = {}) {
        this.options = {
            // URL for version check (meta.json)
            versionUrl: options.versionUrl || '/meta.json',
            
            // Update check interval (ms)
            checkInterval: options.checkInterval || 60000, // 1 minute
            
            // Local storage key for version
            versionKey: options.versionKey || 'app_version',
            
            // Keys for preserving critical data before cleanup
            preserveKeys: options.preserveKeys || [
                'auth_token',
                'user_settings',
                'encryption_keys',
                'peer_connections'
            ],
            
            // Callback on update detection
            onUpdateAvailable: options.onUpdateAvailable || null,
            
            // Callback on error
            onError: options.onError || null,
            
            // Logging
            debug: options.debug || false,
            
            // Force check on load
            checkOnLoad: options.checkOnLoad !== false,
            
            // Request timeout
            requestTimeout: options.requestTimeout || 10000
        };
        
        this.currentVersion = null;
        this.serverVersion = null;
        this.checkIntervalId = null;
        this.isUpdating = false;
        this.updatePromise = null;
        
        // Initialization
        this.init();
    }
    
    /**
     * Initialize update manager
     */
    async init() {
        try {
            // Load current version from localStorage
            this.currentVersion = this.getLocalVersion();
            
            if (this.options.debug) {
                console.log('🔄 UpdateManager initialized', {
                    currentVersion: this.currentVersion,
                    versionUrl: this.options.versionUrl
                });
            }
            
            // Check version on load
            if (this.options.checkOnLoad) {
                await this.checkForUpdates();
            }
            
            // Start periodic check
            this.startPeriodicCheck();
            
            // Listen to Service Worker events
            this.setupServiceWorkerListeners();
            
        } catch (error) {
            this.handleError('Init failed', error);
        }
    }
    
    /**
     * Get local version from localStorage
     */
    getLocalVersion() {
        try {
            return localStorage.getItem(this.options.versionKey) || null;
        } catch (error) {
            this.handleError('Failed to get local version', error);
            return null;
        }
    }
    
    /**
     * Save version to localStorage
     */
    setLocalVersion(version) {
        try {
            localStorage.setItem(this.options.versionKey, version);
            this.currentVersion = version;
            
            if (this.options.debug) {
                console.log('✅ Version saved:', version);
            }
        } catch (error) {
            this.handleError('Failed to save version', error);
        }
    }
    
    /**
     * Check for updates on server
     */
    async checkForUpdates() {
        // Prevent parallel checks
        if (this.updatePromise) {
            return this.updatePromise;
        }
        
        this.updatePromise = this._performCheck();
        const result = await this.updatePromise;
        this.updatePromise = null;
        
        return result;
    }
    
    /**
     * Perform version check
     */
    async _performCheck() {
        try {
            if (this.options.debug) {
                console.log('🔍 Checking for updates...');
            }
            
            // Request meta.json with cache-busting
            const response = await this.fetchWithTimeout(
                `${this.options.versionUrl}?t=${Date.now()}`,
                {
                    method: 'GET',
                    cache: 'no-store',
                    headers: {
                        'Cache-Control': 'no-cache, no-store, must-revalidate',
                        'Pragma': 'no-cache',
                        'Expires': '0'
                    }
                }
            );
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const meta = await response.json();

            // The service worker returns a fallback meta { error: 'Network unavailable',
            // version: <default> } when it can't reach the network. That default ("v4.7.56")
            // must NOT be treated as a real server version — otherwise a transient drop pops a
            // bogus "Update available → v4.7.56". Ignore any error-tagged response.
            if (meta && meta.error) {
                if (this.options.debug) {
                    console.warn('⚠️ meta.json came from offline fallback — skipping update check:', meta.error);
                }
                return { hasUpdate: false, error: meta.error };
            }

            this.serverVersion = meta.version || meta.buildVersion || null;

            if (!this.serverVersion) {
                throw new Error('Version not found in meta.json');
            }
            
            if (this.options.debug) {
                console.log('📦 Server version:', this.serverVersion, 'Local:', this.currentVersion);
            }
            
            // Compare versions
            if (this.currentVersion === null) {
                // First load - save version
                this.setLocalVersion(this.serverVersion);
                return { hasUpdate: false, version: this.serverVersion };
            }
            
            if (this.currentVersion !== this.serverVersion) {
                // New version detected
                if (this.options.debug) {
                    console.log('🆕 New version detected!', {
                        current: this.currentVersion,
                        new: this.serverVersion
                    });
                }
                
                // Call callback
                if (this.options.onUpdateAvailable) {
                    this.options.onUpdateAvailable({
                        currentVersion: this.currentVersion,
                        newVersion: this.serverVersion,
                        updateManager: this
                    });
                }
                
                return {
                    hasUpdate: true,
                    currentVersion: this.currentVersion,
                    newVersion: this.serverVersion
                };
            }
            
            return { hasUpdate: false, version: this.serverVersion };
            
        } catch (error) {
            // Graceful degradation - if meta.json is unavailable, continue working
            if (this.options.debug) {
                console.warn('⚠️ Update check failed (non-critical):', error.message);
            }
            
            if (this.options.onError) {
                this.options.onError(error);
            }
            
            return { hasUpdate: false, error: error.message };
        }
    }
    
    /**
     * Fetch with timeout
     */
    async fetchWithTimeout(url, options = {}) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.options.requestTimeout);
        
        try {
            const response = await fetch(url, {
                ...options,
                signal: controller.signal
            });
            clearTimeout(timeoutId);
            return response;
        } catch (error) {
            clearTimeout(timeoutId);
            if (error.name === 'AbortError') {
                throw new Error('Request timeout');
            }
            throw error;
        }
    }
    
    /**
     * Force application update
     * Clears all cache levels and reloads the page
     */
    async forceUpdate() {
        if (this.isUpdating) {
            if (this.options.debug) {
                console.log('⏳ Update already in progress...');
            }
            return;
        }
        
        this.isUpdating = true;

        // Step logging (always on) so we can see exactly where an update stalls.
        const log = (m) => { try { console.log('🔧 [update] ' + m); } catch (_) {} };
        // Run a cleanup step but never let it block the reload: it still executes fully, we just
        // stop AWAITING it past `ms`. This keeps all the security cleanup (SW caches, SW
        // unregister, storage wipe) while guaranteeing the page reloads.
        const capped = (label, promise, ms) => Promise.race([
            Promise.resolve(promise).then(() => log(label + ' done')).catch((e) => log(label + ' error: ' + (e && e.message))),
            new Promise((resolve) => setTimeout(() => { log(label + ' still running after ' + ms + 'ms — continuing'); resolve(); }, ms))
        ]);
        const navigate = () => {
            log('navigating to new version…');
            try { window.location.href = `${window.location.pathname}?v=${Date.now()}&_update=true`; }
            catch (_) { try { window.location.reload(); } catch (__) {} }
        };

        try {
            log('start (online=' + (typeof navigator !== 'undefined' ? navigator.onLine : 'n/a') + ')');

            // Step 1: Preserve critical data
            const preservedData = this.preserveCriticalData();

            // Step 2: Clear Service Worker caches (time-boxed, still runs fully)
            await capped('clearServiceWorkerCaches', this.clearServiceWorkerCaches(), 3000);

            // Step 3: Unregister Service Workers (time-boxed, still runs fully)
            await capped('unregisterServiceWorkers', this.unregisterServiceWorkers(), 3000);

            // Step 4: Clear browser cache (localStorage, sessionStorage)
            this.clearBrowserCaches();
            log('browser caches cleared');

            // Step 5: Update version
            if (this.serverVersion) {
                this.setLocalVersion(this.serverVersion);
            }

            // Step 6: Restore critical data
            this.restoreCriticalData(preservedData);

            // Step 7: Force reload with cache-busting
            await new Promise(resolve => setTimeout(resolve, 300));
            navigate();

        } catch (error) {
            this.handleError('Force update failed', error);
            this.isUpdating = false;
            // The new build loads from the network regardless — never leave the user stuck.
            navigate();
        }
    }
    
    /**
     * Preserve critical data before cleanup
     */
    preserveCriticalData() {
        const data = {};
        
        this.options.preserveKeys.forEach(key => {
            try {
                const value = localStorage.getItem(key);
                if (value !== null) {
                    data[key] = value;
                }
            } catch (error) {
                if (this.options.debug) {
                    console.warn(`⚠️ Failed to preserve ${key}:`, error);
                }
            }
        });
        
        if (this.options.debug) {
            console.log('💾 Preserved critical data:', Object.keys(data));
        }
        
        return data;
    }
    
    /**
     * Restore critical data after cleanup
     */
    restoreCriticalData(data) {
        Object.entries(data).forEach(([key, value]) => {
            try {
                localStorage.setItem(key, value);
            } catch (error) {
                if (this.options.debug) {
                    console.warn(`⚠️ Failed to restore ${key}:`, error);
                }
            }
        });
        
        if (this.options.debug) {
            console.log('✅ Restored critical data');
        }
    }
    
    /**
     * Clear all Service Worker caches
     */
    async clearServiceWorkerCaches() {
        try {
            if ('caches' in window) {
                const cacheNames = await caches.keys();
                
                if (this.options.debug) {
                    console.log('🗑️ Clearing Service Worker caches:', cacheNames);
                }
                
                await Promise.all(
                    cacheNames.map(cacheName => caches.delete(cacheName))
                );
                
                // Send message to Service Worker for cleanup
                if (navigator.serviceWorker.controller) {
                    navigator.serviceWorker.controller.postMessage({
                        type: 'CACHE_CLEAR'
                    });
                }
                
                if (this.options.debug) {
                    console.log('✅ Service Worker caches cleared');
                }
            }
        } catch (error) {
            this.handleError('Failed to clear SW caches', error);
        }
    }
    
    /**
     * Unregister all Service Workers
     */
    async unregisterServiceWorkers() {
        try {
            if ('serviceWorker' in navigator) {
                const registrations = await navigator.serviceWorker.getRegistrations();
                
                if (this.options.debug) {
                    console.log('🔌 Unregistering Service Workers:', registrations.length);
                }
                
                await Promise.all(
                    registrations.map(registration => {
                        // Send skipWaiting command before unregistering
                        if (registration.waiting) {
                            registration.waiting.postMessage({ type: 'SKIP_WAITING' });
                        }
                        if (registration.installing) {
                            registration.installing.postMessage({ type: 'SKIP_WAITING' });
                        }
                        return registration.unregister();
                    })
                );
                
                if (this.options.debug) {
                    console.log('✅ Service Workers unregistered');
                }
            }
        } catch (error) {
            this.handleError('Failed to unregister SW', error);
        }
    }
    
    /**
     * Clear browser caches (localStorage, sessionStorage)
     */
    clearBrowserCaches() {
        try {
            // Clear sessionStorage
            sessionStorage.clear();
            
            // Clear localStorage (except critical data that is already preserved)
            const keysToRemove = [];
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (key && !this.options.preserveKeys.includes(key) && key !== this.options.versionKey) {
                    keysToRemove.push(key);
                }
            }
            
            keysToRemove.forEach(key => {
                try {
                    localStorage.removeItem(key);
                } catch (error) {
                    if (this.options.debug) {
                        console.warn(`⚠️ Failed to remove ${key}:`, error);
                    }
                }
            });
            
            if (this.options.debug) {
                console.log('✅ Browser caches cleared');
            }
        } catch (error) {
            this.handleError('Failed to clear browser caches', error);
        }
    }
    
    /**
     * Start periodic update check
     */
    startPeriodicCheck() {
        if (this.checkIntervalId) {
            clearInterval(this.checkIntervalId);
        }
        
        this.checkIntervalId = setInterval(() => {
            this.checkForUpdates();
        }, this.options.checkInterval);
        
        if (this.options.debug) {
            console.log(`⏰ Periodic check started (${this.options.checkInterval}ms)`);
        }
    }
    
    /**
     * Stop periodic check
     */
    stopPeriodicCheck() {
        if (this.checkIntervalId) {
            clearInterval(this.checkIntervalId);
            this.checkIntervalId = null;
            
            if (this.options.debug) {
                console.log('⏹️ Periodic check stopped');
            }
        }
    }
    
    /**
     * Setup Service Worker event listeners
     */
    setupServiceWorkerListeners() {
        if ('serviceWorker' in navigator) {
            // Listen to Service Worker updates
            navigator.serviceWorker.addEventListener('controllerchange', () => {
                if (this.options.debug) {
                    console.log('🔄 Service Worker controller changed');
                }
                
                // Check for updates after controller change
                setTimeout(() => {
                    this.checkForUpdates();
                }, 1000);
            });
            
            // Listen to messages from Service Worker
            navigator.serviceWorker.addEventListener('message', (event) => {
                if (event.data && event.data.type === 'SW_ACTIVATED') {
                    if (this.options.debug) {
                        console.log('✅ Service Worker activated');
                    }
                    
                    // Check for updates after activation
                    setTimeout(() => {
                        this.checkForUpdates();
                    }, 1000);
                }
            });
        }
    }
    
    /**
     * Handle errors
     */
    handleError(message, error) {
        const errorMessage = `${message}: ${error.message || error}`;
        
        if (this.options.debug) {
            console.error('❌ UpdateManager error:', errorMessage, error);
        }
        
        if (this.options.onError) {
            this.options.onError(new Error(errorMessage));
        }
    }
    
    /**
     * Destroy manager (cleanup)
     */
    destroy() {
        this.stopPeriodicCheck();
        this.updatePromise = null;
        
        if (this.options.debug) {
            console.log('🗑️ UpdateManager destroyed');
        }
    }
}

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = UpdateManager;
} else {
    window.UpdateManager = UpdateManager;
}

