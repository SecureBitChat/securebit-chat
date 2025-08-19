class PayPerSessionManager {
    constructor(config = {}) {
        this.sessionPrices = {
            demo: { sats: 0, hours: 0.1, usd: 0.00, securityLevel: 'basic' }, 
            basic: { sats: 5000, hours: 1, usd: 2.00, securityLevel: 'enhanced' },
            premium: { sats: 20000, hours: 6, usd: 8.00, securityLevel: 'maximum' }
        };
        
        this.currentSession = null;
        this.sessionTimer = null;
        this.onSessionExpired = null;
        this.staticLightningAddress = "dullpastry62@walletofsatoshi.com";
        
        // Storage of used preimage to prevent reuse
        this.usedPreimages = new Set();
        this.preimageCleanupInterval = null;
        
        // FIXED DEMO mode: Stricter control
        this.demoSessions = new Map(); 
        this.maxDemoSessionsPerUser = 3; 
        this.demoCooldownPeriod = 24 * 60 * 60 * 1000; 
        this.demoSessionCooldown = 1 * 60 * 1000; 
        this.demoSessionMaxDuration = 6 * 60 * 1000; 
        
        // NEW: Global tracking of active demo sessions
        this.activeDemoSessions = new Set(); 
        this.maxGlobalDemoSessions = 10; 
        
        // NEW: Tracking of terminated sessions to prevent rapid reconnection
        this.completedDemoSessions = new Map(); 
        this.minTimeBetweenCompletedSessions = 15 * 60 * 1000; 

        // Minimum cost for paid sessions (protection against micropayment attacks)
        this.minimumPaymentSats = 1000;
        
        this.verificationConfig = {
            method: config.method || 'lnbits',
            apiUrl: config.apiUrl || 'https://demo.lnbits.com',
            apiKey: config.apiKey || 'a7226682253f4dd7bdb2d9487a9a59f8', 
            walletId: config.walletId || '649903697b03457d8b12c4eae7b2fab9',
            isDemo: config.isDemo !== undefined ? config.isDemo : true,
            demoTimeout: 30000, 
            retryAttempts: 3,
            invoiceExpiryMinutes: 15
        };
        
        // Rate limiting for API requests
        this.lastApiCall = 0;
        this.apiCallMinInterval = 1000; 
        
        // Run periodic tasks
        this.startPreimageCleanup();
        this.startDemoSessionCleanup();
        this.startActiveDemoSessionCleanup();
        
        this.globalDemoCounter = 0;
        this.memoryStorage = new Map();
        this.currentTabId = null;
        this.tabHeartbeatInterval = null;
        this.initializePersistentStorage();
        this.performEnhancedCleanup();
        const multiTabCheck = this.checkMultiTabProtection();
        if (!multiTabCheck.allowed) {
            console.warn('❌ Multi-tab protection triggered:', multiTabCheck.message);
        }
        
        console.log('💰 PayPerSessionManager initialized with TIERED security levels');
        
        setInterval(() => {
            this.savePersistentData();
        }, 30000);
        this.notifySecurityUpdate = () => {
            document.dispatchEvent(new CustomEvent('security-level-updated', {
                detail: { timestamp: Date.now(), manager: 'webrtc' }
            }));
        };
        console.log('💰 PayPerSessionManager initialized with ENHANCED secure demo mode and auto-save');
    }

    getSecurityLevelForSession(sessionType) {
        const pricing = this.sessionPrices[sessionType];
        if (!pricing) return 'basic';
        
        return pricing.securityLevel || 'basic';
    }

    // Check if the function is allowed for the given session type
    isFeatureAllowedForSession(sessionType, feature) {
        const securityLevel = this.getSecurityLevelForSession(sessionType);
        
        const featureMatrix = {
            'basic': {
                // DEMO сессии - только базовые функции
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
                
                // Advanced features are DISABLED for demo
                hasNestedEncryption: false,
                hasPacketPadding: false,
                hasPacketReordering: false,
                hasAntiFingerprinting: false,
                hasFakeTraffic: false,
                hasDecoyChannels: false,
                hasMessageChunking: false
            },
            'enhanced': {
                // BASIC paid sessions - improved security
                hasEncryption: true,
                hasECDH: true,
                hasECDSA: true,
                hasMutualAuth: true,
                hasMetadataProtection: true,
                hasEnhancedReplayProtection: true,
                hasNonExtractableKeys: true,
                hasRateLimiting: true,
                hasEnhancedValidation: true,
                hasPFS: true,
                
                // Partially enabled advanced features
                hasNestedEncryption: true,
                hasPacketPadding: true,
                hasPacketReordering: false, 
                hasAntiFingerprinting: false,
                hasFakeTraffic: false, 
                hasDecoyChannels: false,
                hasMessageChunking: false
            },
            'maximum': {
                // PREMIUM sessions - all functions included
                hasEncryption: true,
                hasECDH: true,
                hasECDSA: true,
                hasMutualAuth: true,
                hasMetadataProtection: true,
                hasEnhancedReplayProtection: true,
                hasNonExtractableKeys: true,
                hasRateLimiting: true,
                hasEnhancedValidation: true,
                hasPFS: true,
                
                // ALL advanced features
                hasNestedEncryption: true,
                hasPacketPadding: true,
                hasPacketReordering: true,
                hasAntiFingerprinting: true,
                hasFakeTraffic: true,
                hasDecoyChannels: true,
                hasMessageChunking: true
            }
        };

        return featureMatrix[securityLevel]?.[feature] || false;
    }

    // ============================================
    // FIXED DEMO MODE: Improved controls and management
    // ============================================

    startActiveDemoSessionCleanup() {
        setInterval(() => {
            const now = Date.now();
            let cleanedCount = 0;
            
            for (const preimage of this.activeDemoSessions) {
                const demoTimestamp = this.extractDemoTimestamp(preimage);
                if (demoTimestamp && (now - demoTimestamp) > this.demoSessionMaxDuration) {
                    this.activeDemoSessions.delete(preimage);
                    cleanedCount++;
                }
            }
            
            if (cleanedCount > 0) {
                console.log(`🧹 Cleaned ${cleanedCount} expired active demo sessions`);
            }
        }, 30000); 
    }
    

   startDemoSessionCleanup() {
        setInterval(() => {
            const now = Date.now();
            const maxAge = 25 * 60 * 60 * 1000; 
            
            let cleanedCount = 0;
            for (const [identifier, data] of this.demoSessions.entries()) {
                if (now - data.lastUsed > maxAge) {
                    this.demoSessions.delete(identifier);
                    cleanedCount++;
                }
                
                if (data.sessions) {
                    const originalCount = data.sessions.length;
                    data.sessions = data.sessions.filter(session => 
                        now - session.timestamp < maxAge
                    );
                    
                    if (data.sessions.length === 0 && now - data.lastUsed > maxAge) {
                        this.demoSessions.delete(identifier);
                        cleanedCount++;
                    }
                }
            }
            
            for (const [identifier, sessions] of this.completedDemoSessions.entries()) {
                const filteredSessions = sessions.filter(session => 
                    now - session.endTime < maxAge
                );
                
                if (filteredSessions.length === 0) {
                    this.completedDemoSessions.delete(identifier);
                } else {
                    this.completedDemoSessions.set(identifier, filteredSessions);
                }
            }
            
            if (cleanedCount > 0) {
                console.log(`🧹 Cleaned ${cleanedCount} old demo session records`);
            }
        }, 60 * 60 * 1000); 
    }

    // IMPROVED user fingerprint generation
    generateAdvancedUserFingerprint() {
        try {
            const basicComponents = [
                navigator.userAgent || '',
                navigator.language || '',
                screen.width + 'x' + screen.height,
                Intl.DateTimeFormat().resolvedOptions().timeZone || '',
                navigator.hardwareConcurrency || 0,
                navigator.deviceMemory || 0,
                navigator.platform || '',
                navigator.cookieEnabled ? '1' : '0',
                window.screen.colorDepth || 0,
                window.screen.pixelDepth || 0,
                navigator.maxTouchPoints || 0,
                navigator.onLine ? '1' : '0'
            ];

            const hardwareComponents = [];
            
            // WebGL fingerprint 
            try {
                const canvas = document.createElement('canvas');
                const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                if (gl) {
                    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                    if (debugInfo) {
                        hardwareComponents.push(gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || '');
                        hardwareComponents.push(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || '');
                    }
                    hardwareComponents.push(gl.getParameter(gl.VERSION) || '');
                    hardwareComponents.push(gl.getParameter(gl.SHADING_LANGUAGE_VERSION) || '');
                }
            } catch (e) {
                hardwareComponents.push('webgl_error');
            }

            // Canvas print 
            try {
                const canvas = document.createElement('canvas');
                canvas.width = 200;
                canvas.height = 50;
                const ctx = canvas.getContext('2d');
                ctx.textBaseline = 'top';
                ctx.font = '14px Arial';
                ctx.fillText('SecureBit Demo Fingerprint 🔒', 2, 2);
                ctx.fillStyle = 'rgba(255,0,0,0.5)';
                ctx.fillRect(50, 10, 20, 20);
                hardwareComponents.push(canvas.toDataURL());
            } catch (e) {
                hardwareComponents.push('canvas_error');
            }

            // Audio fingerprint 
            try {
                const audioContext = new (window.AudioContext || window.webkitAudioContext)();
                const oscillator = audioContext.createOscillator();
                const analyser = audioContext.createAnalyser();
                const gain = audioContext.createGain();
                
                oscillator.connect(analyser);
                analyser.connect(gain);
                gain.connect(audioContext.destination);
                
                oscillator.frequency.setValueAtTime(1000, audioContext.currentTime);
                gain.gain.setValueAtTime(0, audioContext.currentTime);
                
                hardwareComponents.push(audioContext.sampleRate.toString());
                hardwareComponents.push(audioContext.state);
                hardwareComponents.push(analyser.frequencyBinCount.toString());
                
                audioContext.close();
            } catch (e) {
                hardwareComponents.push('audio_error');
            }

            // CPU Performance 
            const cpuBenchmark = this.performCPUBenchmark();
            hardwareComponents.push(cpuBenchmark);

            const allComponents = [...basicComponents, ...hardwareComponents];

            let primaryHash = 0;
            let secondaryHash = 0;
            let tertiaryHash = 0;
            
            const primaryStr = allComponents.slice(0, 8).join('|');
            const secondaryStr = allComponents.slice(8, 16).join('|');
            const tertiaryStr = allComponents.slice(16).join('|');
            
            for (let i = 0; i < primaryStr.length; i++) {
                const char = primaryStr.charCodeAt(i);
                primaryHash = ((primaryHash << 7) - primaryHash) + char;
                primaryHash = primaryHash & primaryHash;
            }

            for (let i = 0; i < secondaryStr.length; i++) {
                const char = secondaryStr.charCodeAt(i);
                secondaryHash = ((secondaryHash << 11) - secondaryHash) + char;
                secondaryHash = secondaryHash & secondaryHash;
            }
            
            for (let i = 0; i < tertiaryStr.length; i++) {
                const char = tertiaryStr.charCodeAt(i);
                tertiaryHash = ((tertiaryHash << 13) - tertiaryHash) + char;
                tertiaryHash = tertiaryHash & tertiaryHash;
            }
            
            const combined = `${Math.abs(primaryHash).toString(36)}_${Math.abs(secondaryHash).toString(36)}_${Math.abs(tertiaryHash).toString(36)}`;
            
            console.log('🔒 Enhanced fingerprint generated:', {
                components: allComponents.length,
                primaryLength: primaryStr.length,
                secondaryLength: secondaryStr.length,
                tertiaryLength: tertiaryStr.length,
                fingerprintLength: combined.length
            });
            
            return combined;
            
        } catch (error) {
            console.warn('Failed to generate enhanced fingerprint:', error);
            return 'fallback_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 9);
        }
    }

    performCPUBenchmark() {
        const start = performance.now();
        let result = 0;
        
        for (let i = 0; i < 100000; i++) {
            result += Math.sin(i) * Math.cos(i);
        }
        
        const end = performance.now();
        const duration = Math.round(end - start);
        
        if (duration < 5) return 'fast_cpu';
        if (duration < 15) return 'medium_cpu';
        if (duration < 30) return 'slow_cpu';
        return 'very_slow_cpu';
    }

    initializePersistentStorage() {
        this.storageKeys = {
            demoSessions: 'sb_demo_sessions_v2',
            completedSessions: 'sb_completed_sessions_v2',
            globalCounter: 'sb_global_demo_counter_v2',
            lastCleanup: 'sb_last_cleanup_v2',
            hardwareFingerprint: 'sb_hw_fingerprint_v2'
        };
        
        this.loadPersistentData();
    }

    loadPersistentData() {
        try {
            const savedDemoSessions = this.getFromStorage(this.storageKeys.demoSessions);
            if (savedDemoSessions) {
                const parsed = JSON.parse(savedDemoSessions);
                for (const [key, value] of Object.entries(parsed)) {
                    this.demoSessions.set(key, value);
                }
            }
            
            const savedCompletedSessions = this.getFromStorage(this.storageKeys.completedSessions);
            if (savedCompletedSessions) {
                const parsed = JSON.parse(savedCompletedSessions);
                for (const [key, value] of Object.entries(parsed)) {
                    this.completedDemoSessions.set(key, value);
                }
            }
            
            const savedGlobalCounter = this.getFromStorage(this.storageKeys.globalCounter);
            if (savedGlobalCounter) {
                this.globalDemoCounter = parseInt(savedGlobalCounter) || 0;
            } else {
                this.globalDemoCounter = 0;
            }
            
            console.log('📊 Persistent data loaded:', {
                demoSessions: this.demoSessions.size,
                completedSessions: this.completedDemoSessions.size,
                globalCounter: this.globalDemoCounter
            });
            
        } catch (error) {
            console.warn('Failed to load persistent data:', error);
            this.globalDemoCounter = 0;
        }
    }

    savePersistentData() {
        try {
            const demoSessionsObj = Object.fromEntries(this.demoSessions);
            this.setToStorage(this.storageKeys.demoSessions, JSON.stringify(demoSessionsObj));
            
            const completedSessionsObj = Object.fromEntries(this.completedDemoSessions);
            this.setToStorage(this.storageKeys.completedSessions, JSON.stringify(completedSessionsObj));
            
            this.setToStorage(this.storageKeys.globalCounter, this.globalDemoCounter.toString());
            
            this.setToStorage(this.storageKeys.lastCleanup, Date.now().toString());
            
        } catch (error) {
            console.warn('Failed to save persistent data:', error);
        }
    }

    getFromStorage(key) {
        try {
            if (typeof localStorage !== 'undefined') {
                const value = localStorage.getItem(key);
                if (value) return value;
            }
        } catch (e) {}
        
        try {
            if (typeof sessionStorage !== 'undefined') {
                const value = sessionStorage.getItem(key);
                if (value) return value;
            }
        } catch (e) {}
        
        try {
            if ('caches' in window) {
            }
        } catch (e) {}
        
        return null;
    }

    setToStorage(key, value) {
        try {
            if (typeof localStorage !== 'undefined') {
                localStorage.setItem(key, value);
            }
        } catch (e) {}
        
        try {
            if (typeof sessionStorage !== 'undefined') {
                sessionStorage.setItem(key, value);
            }
        } catch (e) {}
        
        if (!this.memoryStorage) this.memoryStorage = new Map();
        this.memoryStorage.set(key, value);
    }

    checkAntiResetProtection(userFingerprint) {
        if (!this.globalDemoCounter) {
            this.globalDemoCounter = 0;
        }
        
        const hardwareFingerprint = this.getHardwareFingerprint();
        
        const savedHardwareFingerprint = this.getFromStorage(this.storageKeys.hardwareFingerprint);
        
        if (savedHardwareFingerprint && savedHardwareFingerprint !== hardwareFingerprint) {
            console.warn('🚨 Hardware fingerprint mismatch detected - possible reset attempt');
            
            this.globalDemoCounter += 5;
            this.savePersistentData();
            
            return {
                isValid: false,
                reason: 'hardware_mismatch',
                penalty: 5
            };
        }
        
        this.setToStorage(this.storageKeys.hardwareFingerprint, hardwareFingerprint);
        
        if (this.globalDemoCounter >= 10) {
            return {
                isValid: false,
                reason: 'global_limit_exceeded',
                globalCount: this.globalDemoCounter
            };
        }
        
        return {
            isValid: true,
            globalCount: this.globalDemoCounter
        };
    }

    getHardwareFingerprint() {
        const components = [];

        components.push(navigator.hardwareConcurrency || 0);
        components.push(navigator.deviceMemory || 0);
        
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl');
            if (gl) {
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if (debugInfo) {
                    components.push(gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || '');
                    components.push(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || '');
                }
            }
        } catch (e) {
            components.push('webgl_unavailable');
        }
        
        components.push(screen.width);
        components.push(screen.height);
        components.push(screen.colorDepth);

        components.push(Intl.DateTimeFormat().resolvedOptions().timeZone);
        
        let hash = 0;
        const str = components.join('|');
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        
        return Math.abs(hash).toString(36);
    }

    registerEnhancedDemoSessionUsage(userFingerprint, preimage) {
        const session = this.registerDemoSessionUsage(userFingerprint, preimage);
        
        this.savePersistentData();

        console.log('📊 Enhanced demo session registered:', {
            userFingerprint: userFingerprint.substring(0, 12),
            globalCount: this.globalDemoCounter,
            sessionId: session.sessionId,
            timestamp: new Date().toISOString()
        });
        
        return session;
    }

    // COMPLETELY REWRITTEN demo session limits check
    checkEnhancedDemoSessionLimits(userFingerprint) {
        const antiResetCheck = this.checkAntiResetProtection(userFingerprint);
        if (!antiResetCheck.isValid) {
            return {
                allowed: false,
                reason: antiResetCheck.reason,
                message: this.getAntiResetMessage(antiResetCheck),
                globalCount: antiResetCheck.globalCount,
                penalty: antiResetCheck.penalty
            };
        }
        
        const regularCheck = this.checkDemoSessionLimits(userFingerprint);
        
        if (regularCheck.allowed) {
            this.globalDemoCounter++;
            this.savePersistentData();
        }
        
        return {
            ...regularCheck,
            globalCount: this.globalDemoCounter
        };
    }



    getAntiResetMessage(antiResetCheck) {
        switch (antiResetCheck.reason) {
            case 'hardware_mismatch':
                return 'An attempt to reset restrictions was detected. Access to demo mode is temporarily restricted.';
            case 'global_limit_exceeded':
                return `Global demo session limit exceeded (${antiResetCheck.globalCount}/10). A paid session is required to continue.`;
            default:
                return 'Access to demo mode is restricted for security reasons.';
        }
    }



    // FIXED demo session usage registration
        registerDemoSessionUsage(userFingerprint, preimage) {
        const now = Date.now();
        const userData = this.demoSessions.get(userFingerprint) || {
            count: 0,
            lastUsed: 0,
            sessions: [],
            firstUsed: now
        };
        
        userData.count++;
        userData.lastUsed = now;
        
        // Add a new session with preimage for tracking
        const newSession = {
            timestamp: now,
            sessionId: crypto.getRandomValues(new Uint32Array(1))[0].toString(36),
            duration: this.demoSessionMaxDuration,
            preimage: preimage, 
            status: 'active'
        };
        
        userData.sessions.push(newSession);
        
        // Clear old sessions (only those older than 24 hours)
        userData.sessions = userData.sessions.filter(session => 
            now - session.timestamp < this.demoCooldownPeriod
        );
        
        // NEW: Add to global set of active sessions
        this.activeDemoSessions.add(preimage);
        
        this.demoSessions.set(userFingerprint, userData);
        
        console.log(`📊 Demo session registered for user ${userFingerprint.substring(0, 12)} (${userData.sessions.length}/${this.maxDemoSessionsPerUser} today)`);
        console.log(`🌐 Global active demo sessions: ${this.activeDemoSessions.size}/${this.maxGlobalDemoSessions}`);
        
        return newSession;
    }

    performEnhancedCleanup() {
        const now = Date.now();
        const lastCleanup = parseInt(this.getFromStorage(this.storageKeys.lastCleanup)) || 0;
        
        if (now - lastCleanup < 6 * 60 * 60 * 1000) {
            return;
        }
        
        console.log('🧹 Performing enhanced cleanup...');
        
        const maxAge = 25 * 60 * 60 * 1000;
        let cleanedSessions = 0;
        
        for (const [identifier, data] of this.demoSessions.entries()) {
            if (now - data.lastUsed > maxAge) {
                this.demoSessions.delete(identifier);
                cleanedSessions++;
            }
        }
        
        let cleanedCompleted = 0;
        for (const [identifier, sessions] of this.completedDemoSessions.entries()) {
            const filteredSessions = sessions.filter(session => 
                now - session.endTime < maxAge
            );
            
            if (filteredSessions.length === 0) {
                this.completedDemoSessions.delete(identifier);
                cleanedCompleted++;
            } else {
                this.completedDemoSessions.set(identifier, filteredSessions);
            }
        }
        
        const weekAgo = 7 * 24 * 60 * 60 * 1000;
        if (now - lastCleanup > weekAgo) {
            this.globalDemoCounter = Math.max(0, this.globalDemoCounter - 3);
            console.log('🔄 Global demo counter reset (weekly):', this.globalDemoCounter);
        }
        
        this.savePersistentData();
        
        console.log('✅ Enhanced cleanup completed:', {
            cleanedSessions,
            cleanedCompleted,
            globalCounter: this.globalDemoCounter
        });
    }

    checkMultiTabProtection() {
        const tabId = 'tab_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        const activeTabsKey = 'sb_active_tabs';
        
        try {
            const activeTabsStr = this.getFromStorage(activeTabsKey);
            const activeTabs = activeTabsStr ? JSON.parse(activeTabsStr) : [];
            
            const now = Date.now();
            const validTabs = activeTabs.filter(tab => now - tab.timestamp < 30000);
            
            if (validTabs.length >= 2) {
                return {
                    allowed: false,
                    reason: 'multiple_tabs',
                    message: 'Demo mode is only available in one tab at a time..'
                };
            }

            validTabs.push({
                tabId: tabId,
                timestamp: now
            });
            
            this.setToStorage(activeTabsKey, JSON.stringify(validTabs));
            this.currentTabId = tabId;

            this.startTabHeartbeat();
            
            return {
                allowed: true,
                tabId: tabId
            };
            
        } catch (error) {
            console.warn('Multi-tab protection error:', error);
            return { allowed: true }; 
        }
    }

    startTabHeartbeat() {
        if (this.tabHeartbeatInterval) {
            clearInterval(this.tabHeartbeatInterval);
        }
        
        this.tabHeartbeatInterval = setInterval(() => {
            this.updateTabHeartbeat();
        }, 10000); 
    }

    updateTabHeartbeat() {
        if (!this.currentTabId) return;
        
        try {
            const activeTabsKey = 'sb_active_tabs';
            const activeTabsStr = this.getFromStorage(activeTabsKey);
            const activeTabs = activeTabsStr ? JSON.parse(activeTabsStr) : [];
            
            const updatedTabs = activeTabs.map(tab => {
                if (tab.tabId === this.currentTabId) {
                    return {
                        ...tab,
                        timestamp: Date.now()
                    };
                }
                return tab;
            });
            
            this.setToStorage(activeTabsKey, JSON.stringify(updatedTabs));
            
        } catch (error) {
            console.warn('Tab heartbeat update failed:', error);
        }
    }

    // NEW method: Register demo session completion
    registerDemoSessionCompletion(userFingerprint, sessionDuration, preimage) {
        const now = Date.now();
        
        // Remove from active sessions
        if (preimage) {
            this.activeDemoSessions.delete(preimage);
        }
        
        // Add to completed sessions
        const completedSessions = this.completedDemoSessions.get(userFingerprint) || [];
        completedSessions.push({
            endTime: now,
            duration: sessionDuration,
            preimage: preimage ? preimage.substring(0, 16) + '...' : 'unknown' // Логируем только часть для безопасности
        });
        
        // Store only the last completed sessions
        const filteredSessions = completedSessions
            .filter(session => now - session.endTime < this.minTimeBetweenCompletedSessions)
            .slice(-5); 
        
        this.completedDemoSessions.set(userFingerprint, filteredSessions);
        
        // Update the status in the user's master data
        const userData = this.demoSessions.get(userFingerprint);
        if (userData && userData.sessions) {
            const session = userData.sessions.find(s => s.preimage === preimage);
            if (session) {
                session.status = 'completed';
                session.endTime = now;
            }
        }
        
        console.log(`✅ Demo session completed for user ${userFingerprint.substring(0, 12)}`);
        console.log(`🌐 Global active demo sessions: ${this.activeDemoSessions.size}/${this.maxGlobalDemoSessions}`);
    }

    // ENHANCED demo preimage generation with additional protection
    generateSecureDemoPreimage() {
        try {
            const timestamp = Date.now();
            const randomBytes = crypto.getRandomValues(new Uint8Array(24));
            const timestampBytes = new Uint8Array(4);
            const versionBytes = new Uint8Array(4);
            
            // Pack the timestamp
            const timestampSeconds = Math.floor(timestamp / 1000);
            timestampBytes[0] = (timestampSeconds >>> 24) & 0xFF;
            timestampBytes[1] = (timestampSeconds >>> 16) & 0xFF;
            timestampBytes[2] = (timestampSeconds >>> 8) & 0xFF;
            timestampBytes[3] = timestampSeconds & 0xFF;
            
            // IMPROVED version marker with additional protection
            versionBytes[0] = 0xDE; 
            versionBytes[1] = 0xE0; 
            versionBytes[2] = 0x00; 
            versionBytes[3] = 0x02; 
            
            const combined = new Uint8Array(32);
            combined.set(versionBytes, 0);
            combined.set(timestampBytes, 4);
            combined.set(randomBytes, 8);
            
            const preimage = Array.from(combined).map(b => b.toString(16).padStart(2, '0')).join('');
            
            console.log(`🎮 Generated SECURE demo preimage v2: ${preimage.substring(0, 16)}...`);
            return preimage;
            
        } catch (error) {
            console.error('Failed to generate demo preimage:', error);
            throw new Error('Failed to generate secure demo preimage');
        }
    }

    // UPDATED demo preimage check
    isDemoPreimage(preimage) {
        if (!preimage || typeof preimage !== 'string' || preimage.length !== 64) {
            return false;
        }
        
        // Check the demo marker (support versions 1 and 2)
        const lower = preimage.toLowerCase();
        return lower.startsWith('dee00001') || lower.startsWith('dee00002');
    }

    // Extract timestamp from demo preimage
    extractDemoTimestamp(preimage) {
        if (!this.isDemoPreimage(preimage)) {
            return null;
        }
        
        try {
            const timestampHex = preimage.slice(8, 16);
            const timestampSeconds = parseInt(timestampHex, 16);
            return timestampSeconds * 1000;
        } catch (error) {
            console.error('Failed to extract demo timestamp:', error);
            return null;
        }
    }

    // ============================================
    // VALIDATION AND CHECKS
    // ============================================

    validateSessionType(sessionType) {
        if (!sessionType || typeof sessionType !== 'string') {
            throw new Error('Session type must be a non-empty string');
        }
        
        if (!this.sessionPrices[sessionType]) {
            throw new Error(`Invalid session type: ${sessionType}. Allowed: ${Object.keys(this.sessionPrices).join(', ')}`);
        }
        
        const pricing = this.sessionPrices[sessionType];
        
        if (sessionType === 'demo') {
            return true;
        }
        
        if (pricing.sats < this.minimumPaymentSats) {
            throw new Error(`Session type ${sessionType} below minimum payment threshold (${this.minimumPaymentSats} sats)`);
        }
        
        return true;
    }

    calculateEntropy(str) {
        const freq = {};
        for (let char of str) {
            freq[char] = (freq[char] || 0) + 1;
        }
        
        let entropy = 0;
        const length = str.length;
        for (let char in freq) {
            const p = freq[char] / length;
            entropy -= p * Math.log2(p);
        }
        
        return entropy;
    }

    // ============================================
    // ENHANCED verification with additional checks
    // ============================================

    async verifyCryptographically(preimage, paymentHash) {
        try {
            // Basic validation
            if (!preimage || typeof preimage !== 'string' || preimage.length !== 64) {
                throw new Error('Invalid preimage format');
            }
            
            if (!/^[0-9a-fA-F]{64}$/.test(preimage)) {
                throw new Error('Preimage must be valid hexadecimal');
            }
            
            if (this.isDemoPreimage(preimage)) {
                console.log('🎮 Demo preimage detected - performing ENHANCED validation...');
                
                // CHECK 1: Preimage duplicates
                if (this.usedPreimages.has(preimage)) {
                    throw new Error('Demo preimage already used - replay attack prevented');
                }
                
                // CHECK 2: Global Activity
                if (this.activeDemoSessions.has(preimage)) {
                    throw new Error('Demo preimage already active - concurrent usage prevented');
                }
                
                // CHECK 3: Timestamp validation
                const demoTimestamp = this.extractDemoTimestamp(preimage);
                if (!demoTimestamp) {
                    throw new Error('Invalid demo preimage timestamp');
                }
                
                const now = Date.now();
                const age = now - demoTimestamp;
                
                // Demo preimage must not be older than 15 minutes
                if (age > 15 * 60 * 1000) {
                    throw new Error(`Demo preimage expired (age: ${Math.round(age / (60 * 1000))} minutes)`);
                }

                if (age < -2 * 60 * 1000) {
                    throw new Error('Demo preimage timestamp from future - possible clock manipulation');
                }
                
                // CHECK 4: FIXED calling limits - use the CORRECT method
                const userFingerprint = this.generateAdvancedUserFingerprint(); 
                const limitsCheck = this.checkEnhancedDemoSessionLimits(userFingerprint); 
                
                if (!limitsCheck.allowed) {
                    throw new Error(`Demo session limits exceeded: ${limitsCheck.message}`);
                }
                
                // FIX: For demo sessions, do NOT add preimage to usedPreimages here,
                // as this will only be done after successful activation
                this.registerEnhancedDemoSessionUsage(userFingerprint, preimage); 
                
                console.log('✅ Demo preimage ENHANCED validation passed');
                return true;
            }
            
            // For regular preimage - standard checks
            if (this.usedPreimages.has(preimage)) {
                throw new Error('Preimage already used - replay attack prevented');
            }
            
            // Checking entropy
            const entropy = this.calculateEntropy(preimage);
            if (entropy < 3.5) {
                throw new Error(`Preimage has insufficient entropy: ${entropy.toFixed(2)}`);
            }
            
            // Cryptographic verification SHA256(preimage) = paymentHash
            const preimageBytes = new Uint8Array(preimage.match(/.{2}/g).map(byte => parseInt(byte, 16)));
            const hashBuffer = await crypto.subtle.digest('SHA-256', preimageBytes);
            const computedHash = Array.from(new Uint8Array(hashBuffer))
                .map(b => b.toString(16).padStart(2, '0')).join('');
            
            const isValid = computedHash === paymentHash.toLowerCase();
            
            if (isValid) {
                this.usedPreimages.add(preimage);
                console.log('✅ Standard preimage cryptographic validation passed');
            }
            
            return isValid;
            
        } catch (error) {
            console.error('❌ Cryptographic verification failed:', error.message);
            return false;
        }
    }


    // ============================================
    // LIGHTNING NETWORK INTEGRATION
    // ============================================

    // Creating a Lightning invoice
    async createLightningInvoice(sessionType) {
        const pricing = this.sessionPrices[sessionType];
        if (!pricing) throw new Error('Invalid session type');

        try {
            console.log(`Creating ${sessionType} invoice for ${pricing.sats} sats...`);

            const now = Date.now();
            if (now - this.lastApiCall < this.apiCallMinInterval) {
                throw new Error('API rate limit: please wait before next request');
            }
            this.lastApiCall = now;

            const healthCheck = await fetch(`${this.verificationConfig.apiUrl}/api/v1/health`, {
                method: 'GET',
                headers: {
                    'X-Api-Key': this.verificationConfig.apiKey
                },
                signal: AbortSignal.timeout(5000)
            });

            if (!healthCheck.ok) {
                throw new Error(`LNbits API unavailable: ${healthCheck.status}`);
            }

            const response = await fetch(`${this.verificationConfig.apiUrl}/api/v1/payments`, {
                method: 'POST',
                headers: {
                    'X-Api-Key': this.verificationConfig.apiKey,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    out: false,
                    amount: pricing.sats,
                    memo: `SecureBit.chat ${sessionType} session (${pricing.hours}h) - ${Date.now()}`,
                    unit: 'sat',
                    expiry: this.verificationConfig.invoiceExpiryMinutes * 60
                }),
                signal: AbortSignal.timeout(10000)
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error('LNbits API error response:', errorText);
                throw new Error(`LNbits API error ${response.status}: ${errorText}`);
            }

            const data = await response.json();
            
            console.log('✅ Lightning invoice created successfully');
            
            return {
                paymentRequest: data.bolt11 || data.payment_request,
                paymentHash: data.payment_hash,
                checkingId: data.checking_id || data.payment_hash,
                amount: data.amount || pricing.sats,
                sessionType: sessionType,
                createdAt: Date.now(),
                expiresAt: Date.now() + (this.verificationConfig.invoiceExpiryMinutes * 60 * 1000),
                description: data.description || data.memo || `SecureBit.chat ${sessionType} session`,
                bolt11: data.bolt11 || data.payment_request,
                memo: data.memo || `SecureBit.chat ${sessionType} session`
            };

        } catch (error) {
            console.error('❌ Lightning invoice creation failed:', error);
            
            if (this.verificationConfig.isDemo && error.message.includes('API')) {
                console.log('🔄 Creating demo invoice for testing...');
                return this.createDemoInvoice(sessionType);
            }
            
            throw error;
        }
    }

    // Creating a demo invoice for testing
    createDemoInvoice(sessionType) {
        const pricing = this.sessionPrices[sessionType];
        const demoHash = Array.from(crypto.getRandomValues(new Uint8Array(32)))
            .map(b => b.toString(16).padStart(2, '0')).join('');
        
        return {
            paymentRequest: `lntb${pricing.sats}1p${demoHash.substring(0, 16)}...`,
            paymentHash: demoHash,
            checkingId: demoHash,
            amount: pricing.sats,
            sessionType: sessionType,
            createdAt: Date.now(),
            expiresAt: Date.now() + (5 * 60 * 1000),
            description: `SecureBit.chat ${sessionType} session (DEMO)`,
            isDemo: true
        };
    }

    // Checking payment status via LNbits
    async checkPaymentStatus(checkingId) {
        try {
            console.log(`🔍 Checking payment status for: ${checkingId?.substring(0, 8)}...`);

            const now = Date.now();
            if (now - this.lastApiCall < this.apiCallMinInterval) {
                throw new Error('API rate limit exceeded');
            }
            this.lastApiCall = now;

            const response = await fetch(`${this.verificationConfig.apiUrl}/api/v1/payments/${checkingId}`, {
                method: 'GET',
                headers: {
                    'X-Api-Key': this.verificationConfig.apiKey,
                    'Content-Type': 'application/json'
                },
                signal: AbortSignal.timeout(10000)
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error('Payment status check failed:', errorText);
                throw new Error(`Payment check failed: ${response.status} - ${errorText}`);
            }

            const data = await response.json();
            console.log('📊 Payment status retrieved successfully');
            
            return {
                paid: data.paid || false,
                preimage: data.preimage || null,
                details: data.details || {},
                amount: data.amount || 0,
                fee: data.fee || 0,
                timestamp: data.timestamp || Date.now(),
                bolt11: data.bolt11 || null
            };

        } catch (error) {
            console.error('❌ Payment status check error:', error);
            
            if (this.verificationConfig.isDemo && error.message.includes('API')) {
                console.log('🔄 Returning demo payment status...');
                return {
                    paid: false,
                    preimage: null,
                    details: { demo: true },
                    amount: 0,
                    fee: 0,
                    timestamp: Date.now()
                };
            }
            
            throw error;
        }
    }

    // Payment verification via LNbits API
    async verifyPaymentLNbits(preimage, paymentHash) {
        try {
            console.log(`🔐 Verifying payment via LNbits API...`);
            
            if (!this.verificationConfig.apiUrl || !this.verificationConfig.apiKey) {
                throw new Error('LNbits API configuration missing');
            }

            const now = Date.now();
            if (now - this.lastApiCall < this.apiCallMinInterval) {
                throw new Error('API rate limit: please wait before next verification');
            }
            this.lastApiCall = now;

            const response = await fetch(`${this.verificationConfig.apiUrl}/api/v1/payments/${paymentHash}`, {
                method: 'GET',
                headers: {
                    'X-Api-Key': this.verificationConfig.apiKey,
                    'Content-Type': 'application/json'
                },
                signal: AbortSignal.timeout(10000)
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error('LNbits verification failed:', errorText);
                throw new Error(`API request failed: ${response.status} - ${errorText}`);
            }

            const paymentData = await response.json();
            console.log('📋 Payment verification data received from LNbits');
            
            const isPaid = paymentData.paid === true;
            const preimageMatches = paymentData.preimage === preimage;
            const amountValid = paymentData.amount >= this.minimumPaymentSats;
            
            const paymentTimestamp = paymentData.timestamp || paymentData.time || 0;
            const paymentAge = now - (paymentTimestamp * 1000);
            const maxPaymentAge = 24 * 60 * 60 * 1000;
            
            if (paymentAge > maxPaymentAge && paymentTimestamp > 0) {
                throw new Error(`Payment too old: ${Math.round(paymentAge / (60 * 60 * 1000))} hours (max: 24h)`);
            }
            
            if (isPaid && preimageMatches && amountValid) {
                console.log('✅ Payment verified successfully via LNbits');
                return {
                    verified: true,
                    amount: paymentData.amount,
                    fee: paymentData.fee || 0,
                    timestamp: paymentTimestamp || now,
                    method: 'lnbits',
                    verificationTime: now,
                    paymentAge: paymentAge
                };
            }

            console.log('❌ LNbits payment verification failed:', {
                paid: isPaid,
                preimageMatch: preimageMatches,
                amountValid: amountValid,
                paymentAge: Math.round(paymentAge / (60 * 1000)) + ' minutes'
            });
            
            return {
                verified: false,
                reason: 'Payment verification failed: not paid, preimage mismatch, insufficient amount, or payment too old',
                method: 'lnbits',
                details: {
                    paid: isPaid,
                    preimageMatch: preimageMatches,
                    amountValid: amountValid,
                    paymentAge: paymentAge
                }
            };
            
        } catch (error) {
            console.error('❌ LNbits payment verification failed:', error);
            return {
                verified: false,
                reason: error.message,
                method: 'lnbits',
                error: true
            };
        }
    }

    // ============================================
    // BASIC LOGIC OF PAYMENT VERIFICATION
    // ============================================

    // The main method of payment verification
    async verifyPayment(preimage, paymentHash) {
        console.log(`🔐 Starting payment verification...`);
        
        try {
            if (!preimage || !paymentHash) {
                throw new Error('Missing preimage or payment hash');
            }
            
            if (typeof preimage !== 'string' || typeof paymentHash !== 'string') {
                throw new Error('Preimage and payment hash must be strings');
            }
            
            // Special demo preimage processing with ENHANCED checks
            if (this.isDemoPreimage(preimage)) {
                console.log('🎮 Processing demo session verification...');
                
                // Cryptographic verification already includes all necessary checks
                const cryptoValid = await this.verifyCryptographically(preimage, paymentHash);
                if (!cryptoValid) {
                    return { 
                        verified: false, 
                        reason: 'Demo preimage verification failed',
                        stage: 'crypto'
                    };
                }
                
                console.log('✅ Demo session verified successfully');
                return { 
                    verified: true, 
                    method: 'demo',
                    sessionType: 'demo',
                    isDemo: true,
                    warning: 'Demo session - limited duration (6 minutes)'
                };
            }
            
            // Cryptographic verification for regular preimage
            const cryptoValid = await this.verifyCryptographically(preimage, paymentHash);
            if (!cryptoValid) {
                return { 
                    verified: false, 
                    reason: 'Cryptographic verification failed',
                    stage: 'crypto'
                };
            }

            console.log('✅ Cryptographic verification passed');

            // Check via Lightning Network (if not demo mode)
            if (!this.verificationConfig.isDemo) {
                switch (this.verificationConfig.method) {
                    case 'lnbits':
                        const lnbitsResult = await this.verifyPaymentLNbits(preimage, paymentHash);
                        if (!lnbitsResult.verified) {
                            return {
                                verified: false,
                                reason: lnbitsResult.reason || 'LNbits verification failed',
                                stage: 'lightning',
                                details: lnbitsResult.details
                            };
                        }
                        return lnbitsResult;
                        
                    default:
                        console.warn('Unknown verification method, using crypto-only verification');
                        return { 
                            verified: true, 
                            method: 'crypto-only',
                            warning: 'Lightning verification skipped - unknown method'
                        };
                }
            } else {
                console.warn('🚨 DEMO MODE: Lightning payment verification bypassed - FOR DEVELOPMENT ONLY');
                return { 
                    verified: true, 
                    method: 'demo-mode',
                    warning: 'DEMO MODE - Lightning verification bypassed'
                };
            }
            
        } catch (error) {
            console.error('❌ Payment verification failed:', error);
            return { 
                verified: false, 
                reason: error.message,
                stage: 'error'
            };
        }
    }

    // ============================================
    // SESSION MANAGEMENT
    // ============================================

    // ============================================
    // REWORKED session activation methods
    // ============================================

    async safeActivateSession(sessionType, preimage, paymentHash) {
        try {
            console.log(`🚀 Attempting to activate ${sessionType} session...`);
            
            if (!sessionType || !preimage || !paymentHash) {
                return { 
                    success: false, 
                    reason: 'Missing required parameters: sessionType, preimage, or paymentHash' 
                };
            }
            
            try {
                this.validateSessionType(sessionType);
            } catch (error) {
                return { success: false, reason: error.message };
            }
            
            if (this.hasActiveSession()) {
                return { 
                    success: false, 
                    reason: 'Active session already exists. Please wait for it to expire or disconnect.' 
                };
            }
            
            if (sessionType === 'demo') {
                if (!this.isDemoPreimage(preimage)) {
                    return {
                        success: false,
                        reason: 'Invalid demo preimage format. Please use the generated demo preimage.'
                    };
                }
                
                const userFingerprint = this.generateAdvancedUserFingerprint();
                const demoCheck = this.checkEnhancedDemoSessionLimits(userFingerprint);
                
                if (!demoCheck.allowed) {
                    console.log(`⚠️ Demo session cooldown active, but allowing activation for development`);
                    
                    if (demoCheck.reason === 'global_limit_exceeded') {
                        return {
                            success: false,
                            reason: demoCheck.message,
                            demoLimited: true,
                            timeUntilNext: demoCheck.timeUntilNext,
                            remaining: demoCheck.remaining
                        };
                    }
                    
                    console.log(`🔄 Bypassing demo cooldown for development purposes`);
                }
                
                if (this.activeDemoSessions.has(preimage)) {
                    if (!this.currentSession || !this.hasActiveSession()) {
                        console.log(`🔄 Demo session with preimage ${preimage.substring(0, 16)}... was interrupted, allowing reactivation`);
                        this.activeDemoSessions.delete(preimage);
                    } else {
                        return {
                            success: false,
                            reason: 'Demo session with this preimage is already active',
                            demoLimited: true
                        };
                    }
                }
            }
            
            let verificationResult;
            
            if (sessionType === 'demo') {
                console.log('🎮 Using special demo verification for activation...');
                verificationResult = await this.verifyDemoSessionForActivation(preimage, paymentHash);
            } else {
                verificationResult = await this.verifyPayment(preimage, paymentHash);
            }
            
            if (!verificationResult.verified) {
                return {
                    success: false,
                    reason: verificationResult.reason,
                    stage: verificationResult.stage,
                    method: verificationResult.method,
                    demoLimited: verificationResult.demoLimited,
                    timeUntilNext: verificationResult.timeUntilNext,
                    remaining: verificationResult.remaining
                };
            }
            
            // Session activation
            const session = this.activateSession(sessionType, preimage);
            
            console.log(`✅ Session activated successfully: ${sessionType} via ${verificationResult.method}`);
            return {
                success: true,
                sessionType: sessionType,
                method: verificationResult.method,
                details: verificationResult,
                timeLeft: this.getTimeLeft(),
                sessionId: session.id,
                warning: verificationResult.warning,
                isDemo: verificationResult.isDemo || false,
                remaining: verificationResult.remaining
            };
            
        } catch (error) {
            console.error('❌ Session activation failed:', error);
            return {
                success: false,
                reason: error.message,
                method: 'error'
            };
        }
    }

    // REWORKED session activation
    activateSession(sessionType, preimage) {
        if (this.hasActiveSession()) {
            return this.currentSession;
        }
        if (this.sessionTimer) {
            clearInterval(this.sessionTimer);
            this.sessionTimer = null;
        }

        const pricing = this.sessionPrices[sessionType];
        const now = Date.now();
        
        let duration;
        if (sessionType === 'demo') {
            duration = this.demoSessionMaxDuration;
        } else {
            duration = pricing.hours * 60 * 60 * 1000;
        }
        
        const expiresAt = now + duration;
        const sessionId = Array.from(crypto.getRandomValues(new Uint8Array(16)))
            .map(b => b.toString(16).padStart(2, '0')).join('');

        this.currentSession = {
            id: sessionId,
            type: sessionType,
            startTime: now,
            expiresAt: expiresAt,
            preimage: preimage,
            isDemo: sessionType === 'demo',
            securityLevel: this.getSecurityLevelForSession(sessionType)
        };

        this.startSessionTimer();
        
        if (sessionType === 'demo') {
            setTimeout(() => {
                this.handleDemoSessionExpiry(preimage);
            }, duration);
        }
        
        const durationMinutes = Math.round(duration / (60 * 1000));
        const securityLevel = this.currentSession ? this.currentSession.securityLevel : 'unknown';
        console.log(`📅 Session ${sessionId.substring(0, 8)}... activated for ${durationMinutes} minutes with ${securityLevel} security`);
        
        if (sessionType === 'demo') {
            this.activeDemoSessions.add(preimage);
            this.usedPreimages.add(preimage);
            console.log(`🌐 Demo session added to active sessions. Total: ${this.activeDemoSessions.size}/${this.maxGlobalDemoSessions}`);
        }
        
        // SENDING SECURITY LEVEL INFORMATION TO WebRTC
        const activatedSession = this.currentSession; 
        setTimeout(() => {
                    if (activatedSession) {
            this.notifySessionActivated(activatedSession);
        }
            // Notify WebRTC manager about session type
            if (window.webrtcManager && window.webrtcManager.configureSecurityForSession && activatedSession) {
                const securityLevel = activatedSession.securityLevel || this.getSecurityLevelForSession(sessionType);
                window.webrtcManager.configureSecurityForSession(sessionType, securityLevel);
            }
        }, 100);
        
        return this.currentSession;
    }

    // UPDATED method for getting session information
    getSessionInfo() {
        if (!this.currentSession) {
            return null;
        }

        const securityLevel = this.getSecurityLevelForSession(this.currentSession.type);
        const pricing = this.sessionPrices[this.currentSession.type];

        return {
            ...this.currentSession,
            securityLevel: securityLevel,
            securityDescription: this.getSecurityDescription(securityLevel),
            pricing: pricing,
            timeLeft: this.getTimeLeft(),
            isConnected: this.hasActiveSession()
        };
    }

    getSecurityDescription(level) {
        const descriptions = {
            'basic': {
                title: 'Basic Security',
                features: [
                    'End-to-end encryption',
                    'Basic key exchange',
                    'Rate limiting',
                    'Message integrity'
                ],
                limitations: [
                    'No advanced obfuscation',
                    'No traffic padding',
                    'No decoy channels'
                ]
            },
            'enhanced': {
                title: 'Enhanced Security',
                features: [
                    'All basic features',
                    'ECDSA signatures',
                    'Metadata protection',
                    'Perfect forward secrecy',
                    'Nested encryption',
                    'Packet padding'
                ],
                limitations: [
                    'Limited traffic obfuscation',
                    'No fake traffic generation'
                ]
            },
            'maximum': {
                title: 'Maximum Security',
                features: [
                    'All enhanced features',
                    'Traffic obfuscation',
                    'Fake traffic generation',
                    'Decoy channels',
                    'Anti-fingerprinting',
                    'Message chunking',
                    'Packet reordering protection'
                ],
                limitations: []
            }
        };

        return descriptions[level] || descriptions['basic'];
    }

    notifySessionActivated(session = null) {
        const targetSession = session || this.currentSession;

        if (!targetSession) return;
        if (targetSession.notified) {
            return;
        }
        
        const timeLeft = Math.max(0, targetSession.expiresAt - Date.now());
        const sessionType = targetSession.type;
        

        
        if (window.updateSessionTimer) {
            window.updateSessionTimer(timeLeft, sessionType);
        }
        
        document.dispatchEvent(new CustomEvent('session-activated', {
            detail: {
                sessionId: targetSession.id,
                timeLeft: timeLeft,
                sessionType: sessionType,
                isDemo: targetSession.isDemo,
                timestamp: Date.now()
            }
        }));
        
        if (window.forceUpdateHeader) {
            window.forceUpdateHeader(timeLeft, sessionType);
        }

        if (window.debugSessionManager) {
            window.debugSessionManager();
        }
        targetSession.notified = true;
    }

    handleDemoSessionExpiry(preimage) {
        if (this.currentSession && this.currentSession.preimage === preimage) {
            const userFingerprint = this.generateAdvancedUserFingerprint(); 
            const sessionDuration = Date.now() - this.currentSession.startTime;
            
            this.registerDemoSessionCompletion(userFingerprint, sessionDuration, preimage);
            
            console.log(`⏰ Demo session auto-expired for preimage ${preimage.substring(0, 16)}...`);
        }
    }

    startSessionTimer() {
        if (this.sessionTimer) {
            clearInterval(this.sessionTimer);
        }

        this.sessionTimer = setInterval(() => {
            if (!this.hasActiveSession()) {
                this.expireSession();
            }
        }, 60000);
    }

    expireSession() {
        if (this.sessionTimer) {
            clearInterval(this.sessionTimer);
            this.sessionTimer = null;
        }
        
        const expiredSession = this.currentSession;
        
        if (expiredSession && expiredSession.isDemo) {
            const userFingerprint = this.generateAdvancedUserFingerprint(); 
            const sessionDuration = Date.now() - expiredSession.startTime;
            this.registerDemoSessionCompletion(userFingerprint, sessionDuration, expiredSession.preimage);
        }
        
        this.currentSession = null;
        
        if (expiredSession) {
            console.log(`⏰ Session ${expiredSession.id.substring(0, 8)}... expired`);
        }
        
        if (this.onSessionExpired) {
            this.onSessionExpired();
        }
    }

    hasActiveSession() {
        if (!this.currentSession) {
            return false;
        }
        
        const isActive = Date.now() < this.currentSession.expiresAt;
        
        return isActive;
    }

    getTimeLeft() {
        if (!this.currentSession) return 0;
        return Math.max(0, this.currentSession.expiresAt - Date.now());
    }

    forceUpdateTimer() {
        if (this.currentSession) {
            const timeLeft = this.getTimeLeft();
            if (window.DEBUG_MODE && Math.floor(Date.now() / 30000) !== Math.floor((Date.now() - 1000) / 30000)) {
                console.log(`⏱️ Timer updated: ${Math.ceil(timeLeft / 1000)}s left`);
            }
            return timeLeft;
        }
        return 0;
    }

    // ============================================
    // DEMO MODE: Custom Methods
    // ============================================

    // UPDATED demo session creation
    createDemoSession() {
        const userFingerprint = this.generateAdvancedUserFingerprint(); 
        const demoCheck = this.checkEnhancedDemoSessionLimits(userFingerprint); 
        
        if (!demoCheck.allowed) {
            return {
                success: false,
                reason: demoCheck.message,
                timeUntilNext: demoCheck.timeUntilNext,
                remaining: demoCheck.remaining,
                blockingReason: demoCheck.reason
            };
        }
        
        // Checking the global limit
        if (this.activeDemoSessions.size >= this.maxGlobalDemoSessions) {
            return {
                success: false,
                reason: `Too many demo sessions active globally (${this.activeDemoSessions.size}/${this.maxGlobalDemoSessions}). Please try again later.`,
                blockingReason: 'global_limit',
                globalActive: this.activeDemoSessions.size,
                globalLimit: this.maxGlobalDemoSessions
            };
        }
        
        try {
            const demoPreimage = this.generateSecureDemoPreimage();
            const demoPaymentHash = 'demo_' + Array.from(crypto.getRandomValues(new Uint8Array(16)))
                .map(b => b.toString(16).padStart(2, '0')).join('');
            
            return {
                success: true,
                sessionType: 'demo',
                preimage: demoPreimage,
                paymentHash: demoPaymentHash,
                duration: this.sessionPrices.demo.hours,
                durationMinutes: Math.round(this.demoSessionMaxDuration / (60 * 1000)),
                warning: `Demo session - limited to ${Math.round(this.demoSessionMaxDuration / (60 * 1000))} minutes`,
                remaining: demoCheck.remaining - 1,
                globalActive: this.activeDemoSessions.size + 1,
                globalLimit: this.maxGlobalDemoSessions
            };
        } catch (error) {
            console.error('Failed to create demo session:', error);
            return {
                success: false,
                reason: 'Failed to generate demo session. Please try again.',
                remaining: demoCheck.remaining
            };
        }
    }


    // UPDATED information about demo limits
    getDemoSessionInfo() {
        const userFingerprint = this.generateAdvancedUserFingerprint(); 
        const userData = this.demoSessions.get(userFingerprint);
        const now = Date.now();
        
        if (!userData) {
            return {
                available: this.maxDemoSessionsPerUser,
                used: 0,
                total: this.maxDemoSessionsPerUser,
                nextAvailable: 'immediately',
                cooldownMinutes: 0,
                durationMinutes: Math.round(this.demoSessionMaxDuration / (60 * 1000)),
                canUseNow: this.activeDemoSessions.size < this.maxGlobalDemoSessions,
                globalActive: this.activeDemoSessions.size,
                globalLimit: this.maxGlobalDemoSessions,
                debugInfo: 'New user, no restrictions'
            };
        }
        
        // Counting sessions for the last 24 hours
        const sessionsLast24h = userData.sessions.filter(session => 
            now - session.timestamp < this.demoCooldownPeriod
        );
        
        const available = Math.max(0, this.maxDemoSessionsPerUser - sessionsLast24h.length);
        
        // We check all possible blockages
        let cooldownMs = 0;
        let nextAvailable = 'immediately';
        let blockingReason = null;
        let debugInfo = '';
        
        // Global limit
        if (this.activeDemoSessions.size >= this.maxGlobalDemoSessions) {
            nextAvailable = 'when global limit decreases';
            blockingReason = 'global_limit';
            debugInfo = `Global limit: ${this.activeDemoSessions.size}/${this.maxGlobalDemoSessions}`;
        }
        // Daily limit
        else if (available === 0) {
            const oldestSession = Math.min(...sessionsLast24h.map(s => s.timestamp));
            cooldownMs = this.demoCooldownPeriod - (now - oldestSession);
            nextAvailable = `${Math.ceil(cooldownMs / (60 * 1000))} minutes`;
            blockingReason = 'daily_limit';
            debugInfo = `Daily limit reached: ${sessionsLast24h.length}/${this.maxDemoSessionsPerUser}`;
        }
        // Cooldown between sessions
        else if (userData.lastUsed && (now - userData.lastUsed) < this.demoSessionCooldown) {
            cooldownMs = this.demoSessionCooldown - (now - userData.lastUsed);
            nextAvailable = `${Math.ceil(cooldownMs / (60 * 1000))} minutes`;
            blockingReason = 'session_cooldown';
            const lastUsedMinutes = Math.round((now - userData.lastUsed) / (60 * 1000));
            debugInfo = `Cooldown active: last used ${lastUsedMinutes}min ago, need ${Math.ceil(cooldownMs / (60 * 1000))}min more`;
        }
        // Cooldown after completed session
        else {
            const completedSessions = this.completedDemoSessions.get(userFingerprint) || [];
            const recentCompletedSessions = completedSessions.filter(session =>
                now - session.endTime < this.minTimeBetweenCompletedSessions
            );
            
            if (recentCompletedSessions.length > 0) {
                const lastCompletedSession = Math.max(...recentCompletedSessions.map(s => s.endTime));
                cooldownMs = this.minTimeBetweenCompletedSessions - (now - lastCompletedSession);
                nextAvailable = `${Math.ceil(cooldownMs / (60 * 1000))} minutes`;
                blockingReason = 'completion_cooldown';
                const completedMinutes = Math.round((now - lastCompletedSession) / (60 * 1000));
                debugInfo = `Completion cooldown: last session ended ${completedMinutes}min ago`;
            } else {
                debugInfo = `Ready to use: ${available} sessions available`;
            }
        }
        
        const canUseNow = available > 0 && 
                         cooldownMs <= 0 && 
                         this.activeDemoSessions.size < this.maxGlobalDemoSessions;
        
        return {
            available: available,
            used: sessionsLast24h.length,
            total: this.maxDemoSessionsPerUser,
            nextAvailable: nextAvailable,
            cooldownMinutes: Math.ceil(cooldownMs / (60 * 1000)),
            durationMinutes: Math.round(this.demoSessionMaxDuration / (60 * 1000)),
            canUseNow: canUseNow,
            blockingReason: blockingReason,
            globalActive: this.activeDemoSessions.size,
            globalLimit: this.maxGlobalDemoSessions,
            completionCooldownMinutes: Math.round(this.minTimeBetweenCompletedSessions / (60 * 1000)),
            sessionCooldownMinutes: Math.round(this.demoSessionCooldown / (60 * 1000)),
            debugInfo: debugInfo,
            lastUsed: userData.lastUsed ? new Date(userData.lastUsed).toLocaleString() : 'Never'
        };
    }



    // ============================================
    // ADDITIONAL VERIFICATION METHODS
    // ============================================

    // Verification method via LND (Lightning Network Daemon)
    async verifyPaymentLND(preimage, paymentHash) {
        try {
            if (!this.verificationConfig.nodeUrl || !this.verificationConfig.macaroon) {
                throw new Error('LND configuration missing');
            }

            const response = await fetch(`${this.verificationConfig.nodeUrl}/v1/invoice/${paymentHash}`, {
                method: 'GET',
                headers: {
                    'Grpc-Metadata-macaroon': this.verificationConfig.macaroon,
                    'Content-Type': 'application/json'
                },
                signal: AbortSignal.timeout(10000)
            });

            if (!response.ok) {
                throw new Error(`LND API request failed: ${response.status}`);
            }

            const invoiceData = await response.json();
            
            if (invoiceData.settled && invoiceData.r_preimage === preimage) {
                return {
                    verified: true,
                    amount: invoiceData.value,
                    method: 'lnd',
                    timestamp: Date.now()
                };
            }

            return { verified: false, reason: 'LND verification failed', method: 'lnd' };
        } catch (error) {
            console.error('LND payment verification failed:', error);
            return { verified: false, reason: error.message, method: 'lnd' };
        }
    }

    // Verification method via CLN (Core Lightning)
    async verifyPaymentCLN(preimage, paymentHash) {
        try {
            if (!this.verificationConfig.nodeUrl) {
                throw new Error('CLN configuration missing');
            }

            const response = await fetch(`${this.verificationConfig.nodeUrl}/v1/listinvoices`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    payment_hash: paymentHash
                }),
                signal: AbortSignal.timeout(10000)
            });

            if (!response.ok) {
                throw new Error(`CLN API request failed: ${response.status}`);
            }

            const data = await response.json();
            
            if (data.invoices && data.invoices.length > 0) {
                const invoice = data.invoices[0];
                if (invoice.status === 'paid' && invoice.payment_preimage === preimage) {
                    return {
                        verified: true,
                        amount: invoice.amount_msat / 1000,
                        method: 'cln',
                        timestamp: Date.now()
                    };
                }
            }

            return { verified: false, reason: 'CLN verification failed', method: 'cln' };
        } catch (error) {
            console.error('CLN payment verification failed:', error);
            return { verified: false, reason: error.message, method: 'cln' };
        }
    }

    // Verification method via BTCPay Server
    async verifyPaymentBTCPay(preimage, paymentHash) {
        try {
            if (!this.verificationConfig.apiUrl || !this.verificationConfig.apiKey) {
                throw new Error('BTCPay Server configuration missing');
            }

            const response = await fetch(`${this.verificationConfig.apiUrl}/api/v1/invoices/${paymentHash}`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${this.verificationConfig.apiKey}`,
                    'Content-Type': 'application/json'
                },
                signal: AbortSignal.timeout(10000)
            });

            if (!response.ok) {
                throw new Error(`BTCPay API request failed: ${response.status}`);
            }

            const invoiceData = await response.json();
            
            if (invoiceData.status === 'Settled' && 
                invoiceData.payment && 
                invoiceData.payment.preimage === preimage) {
                return {
                    verified: true,
                    amount: invoiceData.amount,
                    method: 'btcpay',
                    timestamp: Date.now()
                };
            }

            return { verified: false, reason: 'BTCPay verification failed', method: 'btcpay' };
        } catch (error) {
            console.error('BTCPay payment verification failed:', error);
            return { verified: false, reason: error.message, method: 'btcpay' };
        }
    }

    // ============================================
    // UTILITY METHODS
    // ============================================

    // Creating a regular invoice (not a demo)
    createInvoice(sessionType) {
        this.validateSessionType(sessionType);
        const pricing = this.sessionPrices[sessionType];

        const randomBytes = crypto.getRandomValues(new Uint8Array(32));
        const timestamp = Date.now();
        const sessionEntropy = crypto.getRandomValues(new Uint8Array(16));
        
        const combinedEntropy = new Uint8Array(48);
        combinedEntropy.set(randomBytes, 0);
        combinedEntropy.set(new Uint8Array(new BigUint64Array([BigInt(timestamp)]).buffer), 32);
        combinedEntropy.set(sessionEntropy, 40);
        
        const paymentHash = Array.from(crypto.getRandomValues(new Uint8Array(32)))
            .map(b => b.toString(16).padStart(2, '0')).join('');

        return {
            amount: pricing.sats,
            memo: `SecureBit.chat ${sessionType} session (${pricing.hours}h) - ${timestamp}`,
            sessionType: sessionType,
            timestamp: timestamp,
            paymentHash: paymentHash,
            lightningAddress: this.staticLightningAddress,
            entropy: Array.from(sessionEntropy).map(b => b.toString(16).padStart(2, '0')).join(''),
            expiresAt: timestamp + (this.verificationConfig.invoiceExpiryMinutes * 60 * 1000)
        };
    }

    // Checking if a session can be activated
    canActivateSession() {
        return !this.hasActiveSession();
    }

    // Reset session (if there are security errors)
    resetSession() {
        if (this.sessionTimer) {
            clearInterval(this.sessionTimer);
            this.sessionTimer = null;
        }
        
        const resetSession = this.currentSession;
        
        // IMPORTANT: For demo sessions, we register forced termination
        if (resetSession && resetSession.isDemo) {
            const userFingerprint = this.generateAdvancedUserFingerprint(); 
            const sessionDuration = Date.now() - resetSession.startTime;
            this.registerDemoSessionCompletion(userFingerprint, sessionDuration, resetSession.preimage);
        }
        
        this.currentSession = null;
        this.sessionStartTime = null;
        this.sessionEndTime = null;
        
        if (resetSession && resetSession.preimage) {
            this.activeDemoSessions.delete(resetSession.preimage);
        }
        
        document.dispatchEvent(new CustomEvent('session-reset', {
            detail: { 
                timestamp: Date.now(),
                reason: 'security_reset'
            }
        }));
        
        setTimeout(() => {
            if (this.currentSession) {
                this.currentSession = null;
            }
        }, 100);
    }

    // Cleaning old preimages (every 24 hours)
    startPreimageCleanup() {
        this.preimageCleanupInterval = setInterval(() => {
            if (this.usedPreimages.size > 10000) {
                const oldSize = this.usedPreimages.size;
                this.usedPreimages.clear();
                console.log(`🧹 Cleaned ${oldSize} old preimages for memory management`);
            }
        }, 24 * 60 * 60 * 1000);
    }

    // Complete manager cleanup
    cleanup() {
        if (this.sessionTimer) {
            clearInterval(this.sessionTimer);
            this.sessionTimer = null;
        }
        if (this.preimageCleanupInterval) {
            clearInterval(this.preimageCleanupInterval);
            this.preimageCleanupInterval = null;
        }
        
        // IMPORTANT: We register the end of the current demo session during cleanup
        if (this.currentSession && this.currentSession.isDemo) {
            const userFingerprint = this.generateAdvancedUserFingerprint(); 
            const sessionDuration = Date.now() - this.currentSession.startTime;
            this.registerDemoSessionCompletion(userFingerprint, sessionDuration, this.currentSession.preimage);
        }
        
        this.currentSession = null;
        this.sessionStartTime = null;
        this.sessionEndTime = null;
        
        if (this.currentSession && this.currentSession.preimage) {
            this.activeDemoSessions.delete(this.currentSession.preimage);
        }
        
        document.dispatchEvent(new CustomEvent('session-cleanup', {
            detail: { 
                timestamp: Date.now(),
                reason: 'complete_cleanup'
            }
        }));
        
        setTimeout(() => {
            if (this.currentSession) {
                this.currentSession = null;
            }
        }, 100);
    }

    getUsageStats() {
        const stats = {
            totalDemoUsers: this.demoSessions.size,
            usedPreimages: this.usedPreimages.size,
            activeDemoSessions: this.activeDemoSessions.size,
            globalDemoLimit: this.maxGlobalDemoSessions,
            currentSession: this.currentSession ? {
                type: this.currentSession.type,
                timeLeft: this.getTimeLeft(),
                isDemo: this.currentSession.isDemo
            } : null,
            config: {
                maxDemoSessions: this.maxDemoSessionsPerUser,
                demoCooldown: this.demoSessionCooldown / (60 * 1000),
                demoMaxDuration: this.demoSessionMaxDuration / (60 * 1000),
                completionCooldown: this.minTimeBetweenCompletedSessions / (60 * 1000)
            }
        };
        
        return stats;
    }

    getVerifiedDemoSession() {
        const userFingerprint = this.generateAdvancedUserFingerprint(); 
        const userData = this.demoSessions.get(userFingerprint);
        
        console.log('🔍 Searching for verified demo session:', {
            userFingerprint: userFingerprint.substring(0, 12),
            hasUserData: !!userData,
            sessionsCount: userData?.sessions?.length || 0,
            currentSession: this.currentSession ? {
                type: this.currentSession.type,
                timeLeft: this.getTimeLeft(),
                isActive: this.hasActiveSession()
            } : null
        });
        
        if (!userData || !userData.sessions || userData.sessions.length === 0) {
            console.log('❌ No user data or sessions found');
            return null;
        }

        const lastSession = userData.sessions[userData.sessions.length - 1];
        if (!lastSession || !lastSession.preimage) {
            console.log('❌ Last session is invalid:', lastSession);
            return null;
        }
        
        if (!this.isDemoPreimage(lastSession.preimage)) {
            console.log('❌ Last session preimage is not demo format:', lastSession.preimage.substring(0, 16) + '...');
            return null;
        }
        
        if (this.activeDemoSessions.has(lastSession.preimage)) {
            console.log('⚠️ Demo session is already in activeDemoSessions, checking if truly active...');
            if (this.hasActiveSession()) {
                console.log('❌ Demo session is truly active, cannot reactivate');
                return null;
            } else {
                console.log('🔄 Demo session was interrupted, can be reactivated');
            }
        }
        
        const verifiedSession = {
            preimage: lastSession.preimage,
            paymentHash: lastSession.paymentHash || 'demo_' + Date.now(),
            sessionType: 'demo',
            timestamp: lastSession.timestamp
        };
        
        console.log('✅ Found verified demo session:', {
            preimage: verifiedSession.preimage.substring(0, 16) + '...',
            timestamp: new Date(verifiedSession.timestamp).toLocaleTimeString(),
            canActivate: !this.hasActiveSession()
        });
        
        return verifiedSession;
    }

    checkDemoSessionLimits(userFingerprint) {
        const userData = this.demoSessions.get(userFingerprint);
        const now = Date.now();
        
        console.log(`🔍 Checking demo limits for user ${userFingerprint.substring(0, 12)}...`);
        
        // CHECK 1: Global limit of simultaneous demo sessions
        if (this.activeDemoSessions.size >= this.maxGlobalDemoSessions) {
            console.log(`❌ Global demo limit reached: ${this.activeDemoSessions.size}/${this.maxGlobalDemoSessions}`);
            return {
                allowed: false,
                reason: 'global_limit_exceeded',
                message: `Too many demo sessions active globally (${this.activeDemoSessions.size}/${this.maxGlobalDemoSessions}). Please try again later.`,
                remaining: 0,
                debugInfo: `Global sessions: ${this.activeDemoSessions.size}/${this.maxGlobalDemoSessions}`
            };
        }
        
        if (!userData) {
            // First demo session for this user
            console.log(`✅ First demo session for user ${userFingerprint.substring(0, 12)}`);
            return { 
                allowed: true, 
                reason: 'first_demo_session',
                remaining: this.maxDemoSessionsPerUser,
                debugInfo: 'First time user'
            };
        }
        
        // CHECK 2: Limit sessions per 24 hours (STRICT check)
        const sessionsLast24h = userData.sessions.filter(session => 
            now - session.timestamp < this.demoCooldownPeriod
        );
        
        console.log(`📊 Sessions in last 24h for user ${userFingerprint.substring(0, 12)}: ${sessionsLast24h.length}/${this.maxDemoSessionsPerUser}`);
        
        if (sessionsLast24h.length >= this.maxDemoSessionsPerUser) {
            const oldestSession = Math.min(...sessionsLast24h.map(s => s.timestamp));
            const timeUntilNext = this.demoCooldownPeriod - (now - oldestSession);
            
            console.log(`❌ Daily demo limit exceeded for user ${userFingerprint.substring(0, 12)}`);
            return { 
                allowed: false, 
                reason: 'daily_limit_exceeded',
                timeUntilNext: timeUntilNext,
                message: `Daily demo limit reached (${this.maxDemoSessionsPerUser}/day). Next session available in ${Math.ceil(timeUntilNext / (60 * 1000))} minutes.`,
                remaining: 0,
                debugInfo: `Used ${sessionsLast24h.length}/${this.maxDemoSessionsPerUser} today`
            };
        }
        
        // CHECK 3: Cooldown between sessions (FIXED LOGIC)
        if (userData.lastUsed && (now - userData.lastUsed) < this.demoSessionCooldown) {
            const timeUntilNext = this.demoSessionCooldown - (now - userData.lastUsed);
            const minutesLeft = Math.ceil(timeUntilNext / (60 * 1000));
            
            console.log(`⏰ Cooldown active for user ${userFingerprint.substring(0, 12)}: ${minutesLeft} minutes`);
            
            return { 
                allowed: false, 
                reason: 'session_cooldown',
                timeUntilNext: timeUntilNext,
                message: `Please wait ${minutesLeft} minutes between demo sessions. This prevents abuse and ensures fair access for all users.`,
                remaining: this.maxDemoSessionsPerUser - sessionsLast24h.length,
                debugInfo: `Cooldown: ${minutesLeft}min left, last used: ${Math.round((now - userData.lastUsed) / (60 * 1000))}min ago`
            };
        }
        
        // CHECK 4: NEW - Check for completed sessions
        const completedSessions = this.completedDemoSessions.get(userFingerprint) || [];
        const recentCompletedSessions = completedSessions.filter(session =>
            now - session.endTime < this.minTimeBetweenCompletedSessions
        );
        
        if (recentCompletedSessions.length > 0) {
            const lastCompletedSession = Math.max(...recentCompletedSessions.map(s => s.endTime));
            const timeUntilNext = this.minTimeBetweenCompletedSessions - (now - lastCompletedSession);
            
            console.log(`⏰ Recent session completed, waiting period active for user ${userFingerprint.substring(0, 12)}`);
            return {
                allowed: false,
                reason: 'recent_session_completed',
                timeUntilNext: timeUntilNext,
                message: `Please wait ${Math.ceil(timeUntilNext / (60 * 1000))} minutes after your last session before starting a new one.`,
                remaining: this.maxDemoSessionsPerUser - sessionsLast24h.length,
                debugInfo: `Last session ended ${Math.round((now - lastCompletedSession) / (60 * 1000))}min ago`
            };
        }
        
        console.log(`✅ Demo session approved for user ${userFingerprint.substring(0, 12)}`);
        return { 
            allowed: true, 
            reason: 'within_limits',
            remaining: this.maxDemoSessionsPerUser - sessionsLast24h.length,
            debugInfo: `Available: ${this.maxDemoSessionsPerUser - sessionsLast24h.length}/${this.maxDemoSessionsPerUser}`
        };
    }

    createDemoSessionForActivation() {
        const userFingerprint = this.generateAdvancedUserFingerprint(); // ИСПРАВЛЕНО!
        
        if (this.activeDemoSessions.size >= this.maxGlobalDemoSessions) {
            return {
                success: false,
                reason: `Too many demo sessions active globally (${this.activeDemoSessions.size}/${this.maxGlobalDemoSessions}). Please try again later.`,
                blockingReason: 'global_limit'
            };
        }
        
        try {
            const demoPreimage = this.generateSecureDemoPreimage();
            const demoPaymentHash = 'demo_' + Array.from(crypto.getRandomValues(new Uint8Array(16)))
                .map(b => b.toString(16).padStart(2, '0')).join('');
            
            console.log('🔄 Created demo session for activation:', {
                preimage: demoPreimage.substring(0, 16) + '...',
                paymentHash: demoPaymentHash.substring(0, 16) + '...'
            });
            
            return {
                success: true,
                sessionType: 'demo',
                preimage: demoPreimage,
                paymentHash: demoPaymentHash,
                duration: this.sessionPrices.demo.hours,
                durationMinutes: Math.round(this.demoSessionMaxDuration / (60 * 1000)),
                warning: `Demo session - limited to ${Math.round(this.demoSessionMaxDuration / (60 * 1000))} minutes`,
                globalActive: this.activeDemoSessions.size + 1,
                globalLimit: this.maxGlobalDemoSessions
            };
        } catch (error) {
            console.error('Failed to create demo session for activation:', error);
            return {
                success: false,
                reason: 'Failed to generate demo session for activation. Please try again.'
            };
        }
    }

    async verifyDemoSessionForActivation(preimage, paymentHash) {
        console.log('🎮 Verifying demo session for activation (bypassing limits)...');
        
        try {
            if (!preimage || !paymentHash) {
                throw new Error('Missing preimage or payment hash');
            }
            
            if (typeof preimage !== 'string' || typeof paymentHash !== 'string') {
                throw new Error('Preimage and payment hash must be strings');
            }
            
            if (!this.isDemoPreimage(preimage)) {
                throw new Error('Invalid demo preimage format');
            }
            
            const entropy = this.calculateEntropy(preimage);
            if (entropy < 3.5) {
                throw new Error(`Demo preimage has insufficient entropy: ${entropy.toFixed(2)}`);
            }
            
            if (this.activeDemoSessions.has(preimage)) {
                throw new Error('Demo session with this preimage is already active');
            }
            
            console.log('✅ Demo session verified for activation successfully');
            return { 
                verified: true, 
                method: 'demo-activation',
                sessionType: 'demo',
                isDemo: true,
                warning: 'Demo session - limited duration (6 minutes)'
            };
            
        } catch (error) {
            console.error('❌ Demo session verification for activation failed:', error);
            return { 
                verified: false, 
                reason: error.message,
                stage: 'demo-activation'
            };
        }
    }
}

export { PayPerSessionManager };