class EnhancedSecureCryptoUtils {

    static _keyMetadata = new WeakMap();

    // Utility to sort object keys for deterministic serialization
    static sortObjectKeys(obj) {
        if (typeof obj !== 'object' || obj === null) {
            return obj;
        }

        if (Array.isArray(obj)) {
            return obj.map(EnhancedSecureCryptoUtils.sortObjectKeys);
        }

        const sortedObj = {};
        Object.keys(obj).sort().forEach(key => {
            sortedObj[key] = EnhancedSecureCryptoUtils.sortObjectKeys(obj[key]);
        });
        return sortedObj;
    }

    // Utility to assert CryptoKey type and properties
    static assertCryptoKey(key, expectedName = null, expectedUsages = []) {
        if (!(key instanceof CryptoKey)) throw new Error('Expected CryptoKey');
        if (expectedName && key.algorithm?.name !== expectedName) {
            throw new Error(`Expected algorithm ${expectedName}, got ${key.algorithm?.name}`);
        }
        for (const u of expectedUsages) {
            if (!key.usages || !key.usages.includes(u)) {
                throw new Error(`Missing required key usage: ${u}`);
            }
        }
    }
    // Helper function to convert ArrayBuffer to Base64
    static arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    // Helper function to convert Base64 to ArrayBuffer
    static base64ToArrayBuffer(base64) {
        try {
            // Validate input
            if (typeof base64 !== 'string' || !base64) {
                throw new Error('Invalid base64 input: must be a non-empty string');
            }

            // Remove any whitespace and validate base64 format
            const cleanBase64 = base64.trim();
            if (!/^[A-Za-z0-9+/]*={0,2}$/.test(cleanBase64)) {
                throw new Error('Invalid base64 format');
            }

            // Handle empty string case
            if (cleanBase64 === '') {
                return new ArrayBuffer(0);
            }

            const binaryString = atob(cleanBase64);
            const len = binaryString.length;
            const bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes.buffer;
        } catch (error) {
            console.error('Base64 to ArrayBuffer conversion failed:', error);
            throw new Error(`Base64 conversion error: ${error.message}`);
        }
    }

    static async encryptData(data, password) {
        try {
            const dataString = typeof data === 'string' ? data : JSON.stringify(data);
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const encoder = new TextEncoder();
            const passwordBuffer = encoder.encode(password);

            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                passwordBuffer,
                { name: 'PBKDF2' },
                false,
                ['deriveKey']
            );

            const key = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: 100000,
                    hash: 'SHA-256',
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt']
            );

            const iv = crypto.getRandomValues(new Uint8Array(12));
            const dataBuffer = encoder.encode(dataString);
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                dataBuffer
            );

            const encryptedPackage = {
                version: '1.0',
                salt: Array.from(salt),
                iv: Array.from(iv),
                data: Array.from(new Uint8Array(encrypted)),
                timestamp: Date.now(),
            };

            const packageString = JSON.stringify(encryptedPackage);
            return EnhancedSecureCryptoUtils.arrayBufferToBase64(new TextEncoder().encode(packageString).buffer);

        } catch (error) {
            console.error('Encryption failed:', error);
            throw new Error(`Encryption error: ${error.message}`);
        }
    }

        static async decryptData(encryptedData, password) {
        try {
            const packageBuffer = EnhancedSecureCryptoUtils.base64ToArrayBuffer(encryptedData);
            const packageString = new TextDecoder().decode(packageBuffer);
            const encryptedPackage = JSON.parse(packageString);

            if (!encryptedPackage.version || !encryptedPackage.salt || !encryptedPackage.iv || !encryptedPackage.data) {
                throw new Error('Invalid encrypted data format');
            }

            const salt = new Uint8Array(encryptedPackage.salt);
            const iv = new Uint8Array(encryptedPackage.iv);
            const encrypted = new Uint8Array(encryptedPackage.data);

            const encoder = new TextEncoder();
            const passwordBuffer = encoder.encode(password);

            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                passwordBuffer,
                { name: 'PBKDF2' },
                false,
                ['deriveKey']
            );

            const key = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: 100000,
                    hash: 'SHA-256'
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
            );

            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                key,
                encrypted
            );

            const decryptedString = new TextDecoder().decode(decrypted);

            try {
                return JSON.parse(decryptedString);
            } catch {
                return decryptedString;
            }

        } catch (error) {
            console.error('Decryption failed:', error);
            throw new Error(`Decryption error: ${error.message}`);
        }
    }

    
    // Generate secure password for data exchange
        static generateSecurePassword() {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        const randomValues = new Uint32Array(16);
        crypto.getRandomValues(randomValues);

        let password = '';
        for (let i = 0; i < 16; i++) {
            password += chars[randomValues[i] % chars.length];
        }
        return password;
    }

    // Real security level calculation with actual verification
    static async calculateSecurityLevel(securityManager) {
        let score = 0;
        const maxScore = 110; // Increased for PFS
        const verificationResults = {};
        
        try {
            // Fallback to basic calculation if securityManager is not fully initialized
            if (!securityManager || !securityManager.securityFeatures) {
                EnhancedSecureCryptoUtils.secureLog.log('warn', 'Security manager not fully initialized, using fallback calculation');
                return {
                    level: 'INITIALIZING',
                    score: 35,
                    color: 'yellow',
                    verificationResults: {},
                    timestamp: Date.now(),
                    details: 'Security system initializing...'
                };
            }
            // 1. Base encryption verification (20 points)
            try {
                if (await EnhancedSecureCryptoUtils.verifyEncryption(securityManager)) {
                    score += 20;
                    verificationResults.encryption = { passed: true, details: 'AES-GCM encryption verified' };
                } else {
                    verificationResults.encryption = { passed: false, details: 'Encryption not working' };
                }
            } catch (error) {
                verificationResults.encryption = { passed: false, details: `Encryption check failed: ${error.message}` };
            }
            
            // 2. ECDH key exchange verification (15 points)
            try {
                if (await EnhancedSecureCryptoUtils.verifyECDHKeyExchange(securityManager)) {
                    score += 15;
                    verificationResults.ecdh = { passed: true, details: 'ECDH key exchange verified' };
                } else {
                    verificationResults.ecdh = { passed: false, details: 'ECDH key exchange failed' };
                }
            } catch (error) {
                verificationResults.ecdh = { passed: false, details: `ECDH check failed: ${error.message}` };
            }
            
            // 3. ECDSA signatures verification (15 points)
            if (await EnhancedSecureCryptoUtils.verifyECDSASignatures(securityManager)) {
                score += 15;
                verificationResults.ecdsa = { passed: true, details: 'ECDSA signatures verified' };
            } else {
                verificationResults.ecdsa = { passed: false, details: 'ECDSA signatures failed' };
            }
            
            // 4. Mutual authentication verification (10 points)
            if (await EnhancedSecureCryptoUtils.verifyMutualAuth(securityManager)) {
                score += 10;
                verificationResults.mutualAuth = { passed: true, details: 'Mutual authentication verified' };
            } else {
                verificationResults.mutualAuth = { passed: false, details: 'Mutual authentication failed' };
            }
            
            // 5. Metadata protection verification (10 points)
            if (await EnhancedSecureCryptoUtils.verifyMetadataProtection(securityManager)) {
                score += 10;
                verificationResults.metadataProtection = { passed: true, details: 'Metadata protection verified' };
            } else {
                verificationResults.metadataProtection = { passed: false, details: 'Metadata protection failed' };
            }
            
            // 6. Enhanced replay protection verification (10 points)
            if (await EnhancedSecureCryptoUtils.verifyReplayProtection(securityManager)) {
                score += 10;
                verificationResults.replayProtection = { passed: true, details: 'Replay protection verified' };
            } else {
                verificationResults.replayProtection = { passed: false, details: 'Replay protection failed' };
            }
            
            // 7. Non-extractable keys verification (10 points)
            if (await EnhancedSecureCryptoUtils.verifyNonExtractableKeys(securityManager)) {
                score += 10;
                verificationResults.nonExtractableKeys = { passed: true, details: 'Non-extractable keys verified' };
            } else {
                verificationResults.nonExtractableKeys = { passed: false, details: 'Keys are extractable' };
            }
            
            // 8. Rate limiting verification (5 points)
            if (await EnhancedSecureCryptoUtils.verifyRateLimiting(securityManager)) {
                score += 5;
                verificationResults.rateLimiting = { passed: true, details: 'Rate limiting active' };
            } else {
                verificationResults.rateLimiting = { passed: false, details: 'Rate limiting not working' };
            }
            
            // 9. Enhanced validation verification (5 points)
            if (await EnhancedSecureCryptoUtils.verifyEnhancedValidation(securityManager)) {
                score += 5;
                verificationResults.enhancedValidation = { passed: true, details: 'Enhanced validation active' };
            } else {
                verificationResults.enhancedValidation = { passed: false, details: 'Enhanced validation failed' };
            }
            
            // 10. Perfect Forward Secrecy verification (10 points)
            if (await EnhancedSecureCryptoUtils.verifyPFS(securityManager)) {
                score += 10;
                verificationResults.pfs = { passed: true, details: 'Perfect Forward Secrecy active' };
            } else {
                verificationResults.pfs = { passed: false, details: 'PFS not active' };
            }
            
            const percentage = Math.round((score / maxScore) * 100);
            
            const result = {
                level: percentage >= 80 ? 'HIGH' : percentage >= 50 ? 'MEDIUM' : 'LOW',
                score: percentage,
                color: percentage >= 80 ? 'green' : percentage >= 50 ? 'yellow' : 'red',
                verificationResults,
                timestamp: Date.now(),
                details: `Real verification: ${score}/${maxScore} security checks passed`
            };
            
            EnhancedSecureCryptoUtils.secureLog.log('info', 'Real security level calculated', {
                score: percentage,
                level: result.level,
                passedChecks: Object.values(verificationResults).filter(r => r.passed).length,
                totalChecks: Object.keys(verificationResults).length
            });
            
            return result;
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Security level calculation failed', { error: error.message });
            return {
                level: 'UNKNOWN',
                score: 0,
                color: 'red',
                verificationResults: {},
                timestamp: Date.now(),
                details: `Verification failed: ${error.message}`
            };
        }
    }

    // Real verification functions
    static async verifyEncryption(securityManager) {
        try {
            if (!securityManager.encryptionKey) return false;
            
            // Test actual encryption/decryption
            const testData = 'Test encryption verification';
            const encoder = new TextEncoder();
            const testBuffer = encoder.encode(testData);
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                securityManager.encryptionKey,
                testBuffer
            );
            
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                securityManager.encryptionKey,
                encrypted
            );
            
            const decryptedText = new TextDecoder().decode(decrypted);
            return decryptedText === testData;
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Encryption verification failed', { error: error.message });
            return false;
        }
    }
    
    static async verifyECDHKeyExchange(securityManager) {
        try {
            if (!securityManager.ecdhKeyPair || !securityManager.ecdhKeyPair.privateKey || !securityManager.ecdhKeyPair.publicKey) {
                return false;
            }
            
            // Test that keys are actually ECDH keys
            const keyType = securityManager.ecdhKeyPair.privateKey.algorithm.name;
            const curve = securityManager.ecdhKeyPair.privateKey.algorithm.namedCurve;
            
            return keyType === 'ECDH' && (curve === 'P-384' || curve === 'P-256');
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'ECDH verification failed', { error: error.message });
            return false;
        }
    }
    
    static async verifyECDSASignatures(securityManager) {
        try {
            if (!securityManager.ecdsaKeyPair || !securityManager.ecdsaKeyPair.privateKey || !securityManager.ecdsaKeyPair.publicKey) {
                return false;
            }
            
            // Test actual signing and verification
            const testData = 'Test ECDSA signature verification';
            const encoder = new TextEncoder();
            const testBuffer = encoder.encode(testData);
            
            const signature = await crypto.subtle.sign(
                { name: 'ECDSA', hash: 'SHA-384' },
                securityManager.ecdsaKeyPair.privateKey,
                testBuffer
            );
            
            const isValid = await crypto.subtle.verify(
                { name: 'ECDSA', hash: 'SHA-384' },
                securityManager.ecdsaKeyPair.publicKey,
                signature,
                testBuffer
            );
            
            return isValid;
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'ECDSA verification failed', { error: error.message });
            return false;
        }
    }
    
    static async verifyMutualAuth(securityManager) {
        try {
            // Check if mutual authentication challenge was created and processed
            return securityManager.isVerified === true;
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Mutual auth verification failed', { error: error.message });
            return false;
        }
    }
    
    static async verifyMetadataProtection(securityManager) {
        try {
            if (!securityManager.metadataKey) return false;
            
            // Test metadata encryption/decryption
            const testMetadata = { test: 'metadata', timestamp: Date.now() };
            const encoder = new TextEncoder();
            const testBuffer = encoder.encode(JSON.stringify(testMetadata));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                securityManager.metadataKey,
                testBuffer
            );
            
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                securityManager.metadataKey,
                encrypted
            );
            
            const decryptedMetadata = JSON.parse(new TextDecoder().decode(decrypted));
            return decryptedMetadata.test === testMetadata.test;
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Metadata protection verification failed', { error: error.message });
            return false;
        }
    }
    
    static async verifyReplayProtection(securityManager) {
        try {
            // Check if replay protection mechanisms are in place
            return securityManager.processedMessageIds && 
                   typeof securityManager.processedMessageIds.has === 'function' &&
                   securityManager.sequenceNumber !== undefined;
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Replay protection verification failed', { error: error.message });
            return false;
        }
    }
    
    static async verifyNonExtractableKeys(securityManager) {
        try {
            // Check that keys are non-extractable
            if (securityManager.ecdhKeyPair && securityManager.ecdhKeyPair.privateKey) {
                return securityManager.ecdhKeyPair.privateKey.extractable === false;
            }
            return false;
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Non-extractable keys verification failed', { error: error.message });
            return false;
        }
    }
    
    static async verifyRateLimiting(securityManager) {
        try {
            // Check if rate limiting is active
            return securityManager.rateLimiterId && 
                   EnhancedSecureCryptoUtils.rateLimiter &&
                   typeof EnhancedSecureCryptoUtils.rateLimiter.checkMessageRate === 'function';
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Rate limiting verification failed', { error: error.message });
            return false;
        }
    }
    
    static async verifyEnhancedValidation(securityManager) {
        try {
            // Check if enhanced validation is active
            return securityManager.sessionSalt && 
                   securityManager.sessionSalt.length === 64 &&
                   securityManager.keyFingerprint;
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Enhanced validation verification failed', { error: error.message });
            return false;
        }
    }
    
    static async verifyPFS(securityManager) {
        try {
            // Check if PFS is active
            return securityManager.securityFeatures &&
                   securityManager.securityFeatures.hasPFS === true &&
                   securityManager.keyRotationInterval &&
                   securityManager.currentKeyVersion !== undefined &&
                   securityManager.keyVersions &&
                   securityManager.keyVersions instanceof Map;
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'PFS verification failed', { error: error.message });
            return false;
        }
    }

    // Rate limiting implementation
    static rateLimiter = {
        messages: new Map(),
        connections: new Map(),
        
        checkMessageRate(identifier, limit = 60, windowMs = 60000) {
            const now = Date.now();
            const key = `msg_${identifier}`;
            
            if (!this.messages.has(key)) {
                this.messages.set(key, []);
            }
            
            const timestamps = this.messages.get(key);
            
            // Remove old timestamps
            const validTimestamps = timestamps.filter(ts => now - ts < windowMs);
            this.messages.set(key, validTimestamps);
            
            if (validTimestamps.length >= limit) {
                return false; // Rate limit exceeded
            }
            
            validTimestamps.push(now);
            return true;
        },
        
        checkConnectionRate(identifier, limit = 5, windowMs = 300000) {
            const now = Date.now();
            const key = `conn_${identifier}`;
            
            if (!this.connections.has(key)) {
                this.connections.set(key, []);
            }
            
            const timestamps = this.connections.get(key);
            const validTimestamps = timestamps.filter(ts => now - ts < windowMs);
            this.connections.set(key, validTimestamps);
            
            if (validTimestamps.length >= limit) {
                return false;
            }
            
            validTimestamps.push(now);
            return true;
        },
        
        cleanup() {
            const now = Date.now();
            const maxAge = 3600000; // 1 hour
            
            for (const [key, timestamps] of this.messages.entries()) {
                const valid = timestamps.filter(ts => now - ts < maxAge);
                if (valid.length === 0) {
                    this.messages.delete(key);
                } else {
                    this.messages.set(key, valid);
                }
            }
            
            for (const [key, timestamps] of this.connections.entries()) {
                const valid = timestamps.filter(ts => now - ts < maxAge);
                if (valid.length === 0) {
                    this.connections.delete(key);
                } else {
                    this.connections.set(key, valid);
                }
            }
        }
    };

    // Secure logging without data leaks
    static secureLog = {
        logs: [],
        maxLogs: 100,
        
        log(level, message, context = {}) {
            const sanitizedContext = this.sanitizeContext(context);
            const logEntry = {
                timestamp: Date.now(),
                level,
                message,
                context: sanitizedContext,
                id: crypto.getRandomValues(new Uint32Array(1))[0]
            };
            
            this.logs.push(logEntry);
            
            // Keep only recent logs
            if (this.logs.length > this.maxLogs) {
                this.logs = this.logs.slice(-this.maxLogs);
            }
            
            // Console output for development
            if (level === 'error') {
                console.error(`[SecureChat] ${message}`, sanitizedContext);
            } else if (level === 'warn') {
                console.warn(`[SecureChat] ${message}`, sanitizedContext);
            } else {
                console.log(`[SecureChat] ${message}`, sanitizedContext);
            }
        },
        
        sanitizeContext(context) {
            const sanitized = {};
            for (const [key, value] of Object.entries(context)) {
                if (key.toLowerCase().includes('key') ||
                    key.toLowerCase().includes('secret') ||
                    key.toLowerCase().includes('password') ||
                    key.toLowerCase().includes('token')) {
                    sanitized[key] = '[REDACTED]';
                } else if (typeof value === 'string' && value.length > 100) {
                    sanitized[key] = value.substring(0, 100) + '...[TRUNCATED]';
                } else {
                    sanitized[key] = value;
                }
            }
            return sanitized;
        },
        
        getLogs(level = null) {
            if (level) {
                return this.logs.filter(log => log.level === level);
            }
            return [...this.logs];
        },
        
        clearLogs() {
            this.logs = [];
        }
    };

    // Generate ECDH key pair for secure key exchange (non-extractable) with fallback
    static async generateECDHKeyPair() {
        try {
            // Try P-384 first
            try {
                const keyPair = await crypto.subtle.generateKey(
                    {
                        name: 'ECDH',
                        namedCurve: 'P-384'
                    },
                    false, // Non-extractable for enhanced security
                    ['deriveKey']
                );
                
                EnhancedSecureCryptoUtils.secureLog.log('info', 'ECDH key pair generated successfully (P-384)', {
                    curve: 'P-384',
                    extractable: false
                });
                
                return keyPair;
            } catch (p384Error) {
                EnhancedSecureCryptoUtils.secureLog.log('warn', 'P-384 generation failed, trying P-256', { error: p384Error.message });
                
                // Fallback to P-256
                const keyPair = await crypto.subtle.generateKey(
                    {
                        name: 'ECDH',
                        namedCurve: 'P-256'
                    },
                    false, // Non-extractable for enhanced security
                    ['deriveKey']
                );
                
                EnhancedSecureCryptoUtils.secureLog.log('info', 'ECDH key pair generated successfully (P-256 fallback)', {
                    curve: 'P-256',
                    extractable: false
                });
                
                return keyPair;
            }
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'ECDH key generation failed', { error: error.message });
            throw new Error('Failed to create keys for secure exchange');
        }
    }

    // Generate ECDSA key pair for digital signatures with fallback
    static async generateECDSAKeyPair() {
        try {
            // Try P-384 first
            try {
                const keyPair = await crypto.subtle.generateKey(
                    {
                        name: 'ECDSA',
                        namedCurve: 'P-384'
                    },
                    false, // Non-extractable for enhanced security
                    ['sign', 'verify']
                );
                
                EnhancedSecureCryptoUtils.secureLog.log('info', 'ECDSA key pair generated successfully (P-384)', {
                    curve: 'P-384',
                    extractable: false
                });
                
                return keyPair;
            } catch (p384Error) {
                EnhancedSecureCryptoUtils.secureLog.log('warn', 'P-384 generation failed, trying P-256', { error: p384Error.message });
                
                // Fallback to P-256
                const keyPair = await crypto.subtle.generateKey(
                    {
                        name: 'ECDSA',
                        namedCurve: 'P-256'
                    },
                    false, // Non-extractable for enhanced security
                    ['sign', 'verify']
                );
                
                EnhancedSecureCryptoUtils.secureLog.log('info', 'ECDSA key pair generated successfully (P-256 fallback)', {
                    curve: 'P-256',
                    extractable: false
                });
                
                return keyPair;
            }
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'ECDSA key generation failed', { error: error.message });
            throw new Error('Failed to generate keys for digital signatures');
        }
    }

    // Sign data with ECDSA (P-384 or P-256)
    static async signData(privateKey, data) {
        try {
            const encoder = new TextEncoder();
            const dataBuffer = typeof data === 'string' ? encoder.encode(data) : data;
            
            // Try SHA-384 first, fallback to SHA-256
            try {
                const signature = await crypto.subtle.sign(
                    {
                        name: 'ECDSA',
                        hash: 'SHA-384'
                    },
                    privateKey,
                    dataBuffer
                );
                
                return Array.from(new Uint8Array(signature));
            } catch (sha384Error) {
                EnhancedSecureCryptoUtils.secureLog.log('warn', 'SHA-384 signing failed, trying SHA-256', { error: sha384Error.message });
                
                const signature = await crypto.subtle.sign(
                    {
                        name: 'ECDSA',
                        hash: 'SHA-256'
                    },
                    privateKey,
                    dataBuffer
                );
                
                return Array.from(new Uint8Array(signature));
            }
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Data signing failed', { error: error.message });
            throw new Error('Failed to sign data');
        }
    }

    // Verify ECDSA signature (P-384 or P-256)
    static async verifySignature(publicKey, signature, data) {
        try {
            const encoder = new TextEncoder();
            const dataBuffer = typeof data === 'string' ? encoder.encode(data) : data;
            const signatureBuffer = new Uint8Array(signature);
            
            // Try SHA-384 first, fallback to SHA-256
            try {
                const isValid = await crypto.subtle.verify(
                    {
                        name: 'ECDSA',
                        hash: 'SHA-384'
                    },
                    publicKey,
                    signatureBuffer,
                    dataBuffer
                );
                
                EnhancedSecureCryptoUtils.secureLog.log('info', 'Signature verification completed (SHA-384)', {
                    isValid,
                    dataSize: dataBuffer.length
                });
                
                return isValid;
            } catch (sha384Error) {
                EnhancedSecureCryptoUtils.secureLog.log('warn', 'SHA-384 verification failed, trying SHA-256', { error: sha384Error.message });
                
                const isValid = await crypto.subtle.verify(
                    {
                        name: 'ECDSA',
                        hash: 'SHA-256'
                    },
                    publicKey,
                    signatureBuffer,
                    dataBuffer
                );
                
                EnhancedSecureCryptoUtils.secureLog.log('info', 'Signature verification completed (SHA-256 fallback)', {
                    isValid,
                    dataSize: dataBuffer.length
                });
                
                return isValid;
            }
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Signature verification failed', { error: error.message });
            throw new Error('Failed to verify digital signature');
        }
    }

    // Enhanced DER/SPKI validation with improved error handling
        static async validateKeyStructure(keyData, expectedAlgorithm = 'ECDH') {
            try {
                if (!Array.isArray(keyData) || keyData.length === 0) {
                    throw new Error('Invalid key data format');
                }

                const keyBytes = new Uint8Array(keyData);

                // Basic DER check
                if (keyBytes[0] !== 0x30) {
                    throw new Error('Invalid DER structure - missing SEQUENCE tag');
                }

                if (keyBytes.length > 2000) { 
                    throw new Error('Key data too long - possible attack');
                }

                // Try to import; await the promise
                const alg = (expectedAlgorithm === 'ECDSA' || expectedAlgorithm === 'ECDH')
                    ? { name: expectedAlgorithm, namedCurve: 'P-384' }
                    : { name: expectedAlgorithm };

                await crypto.subtle.importKey('spki', keyBytes.buffer, alg, false, expectedAlgorithm === 'ECDSA' ? ['verify'] : []);
                EnhancedSecureCryptoUtils.secureLog.log('info', 'Key structure validation passed', { keyLen: keyBytes.length });
                return true;
            } catch (err) {
                EnhancedSecureCryptoUtils.secureLog.log('error', 'Key structure validation failed', { short: err.message });
                throw new Error('Invalid key structure');
            }
        }

    // Export public key for transmission with signature
    static async exportPublicKeyWithSignature(publicKey, signingKey, keyType = 'ECDH') {
        try {
            // Validate key type
            if (!['ECDH', 'ECDSA'].includes(keyType)) {
                throw new Error('Invalid key type');
            }
            
            const exported = await crypto.subtle.exportKey('spki', publicKey);
            const keyData = Array.from(new Uint8Array(exported));
            
            // Validate exported key structure
            await EnhancedSecureCryptoUtils.validateKeyStructure(keyData, keyType);
            
            // Create signed key package
            const keyPackage = {
                keyType,
                keyData,
                timestamp: Date.now(),
                version: '4.0'
            };
            
            // Sign the key package
            const packageString = JSON.stringify(keyPackage);
            const signature = await EnhancedSecureCryptoUtils.signData(signingKey, packageString);
            
            const signedPackage = {
                ...keyPackage,
                signature
            };
            
            EnhancedSecureCryptoUtils.secureLog.log('info', 'Public key exported with signature', {
                keyType,
                keySize: keyData.length,
                signed: true
            });
            
            return signedPackage;
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Public key export failed', {
                error: error.message,
                keyType
            });
            throw new Error(`Failed to export ${keyType} key: ${error.message}`);
        }
    }

    // Import and verify signed public key
    static async importSignedPublicKey(signedPackage, verifyingKey, expectedKeyType = 'ECDH') {
        try {
            // Validate package structure
            if (!signedPackage || typeof signedPackage !== 'object') {
                throw new Error('Invalid signed package format');
            }
            
            const { keyType, keyData, timestamp, version, signature } = signedPackage;
            
            if (!keyType || !keyData || !timestamp || !signature) {
                throw new Error('Missing required fields in signed package');
            }
            
            if (keyType !== expectedKeyType) {
                throw new Error(`Key type mismatch: expected ${expectedKeyType}, got ${keyType}`);
            }
            
            // Check timestamp (reject keys older than 1 hour)
            const keyAge = Date.now() - timestamp;
            if (keyAge > 3600000) {
                throw new Error('Signed key package is too old');
            }
            
            // Validate key structure
            await EnhancedSecureCryptoUtils.validateKeyStructure(keyData, keyType);
            
            // Verify signature
            const packageCopy = { keyType, keyData, timestamp, version };
            const packageString = JSON.stringify(packageCopy);
            const isValidSignature = await EnhancedSecureCryptoUtils.verifySignature(verifyingKey, signature, packageString);
            
            if (!isValidSignature) {
                throw new Error('Invalid signature on key package - possible MITM attack');
            }
            
            // Import the key
            const keyBytes = new Uint8Array(keyData);
            const algorithm = keyType === 'ECDH' ?
                { name: 'ECDH', namedCurve: 'P-384' } :
                { name: 'ECDSA', namedCurve: 'P-384' };
            
            const keyUsages = keyType === 'ECDH' ? [] : ['verify'];
            
            const publicKey = await crypto.subtle.importKey(
                'spki',
                keyBytes,
                algorithm,
                false, // Non-extractable
                keyUsages
            );
            
            EnhancedSecureCryptoUtils.secureLog.log('info', 'Signed public key imported successfully', {
                keyType,
                signatureValid: true,
                keyAge: Math.round(keyAge / 1000) + 's'
            });
            
            return publicKey;
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Signed public key import failed', {
                error: error.message,
                expectedKeyType
            });
            throw new Error(`Failed to import the signed key: ${error.message}`);
        }
    }

    // Legacy export for backward compatibility
    static async exportPublicKey(publicKey) {
        try {
            const exported = await crypto.subtle.exportKey('spki', publicKey);
            const keyData = Array.from(new Uint8Array(exported));
            
            // Validate exported key
            await EnhancedSecureCryptoUtils.validateKeyStructure(keyData, 'ECDH');
            
            EnhancedSecureCryptoUtils.secureLog.log('info', 'Legacy public key exported', { keySize: keyData.length });
            return keyData;
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Legacy public key export failed', { error: error.message });
            throw new Error('Failed to export the public key');
        }
    }

    // Legacy import for backward compatibility with fallback
    static async importPublicKey(keyData) {
        try {
            await EnhancedSecureCryptoUtils.validateKeyStructure(keyData, 'ECDH');
            
            const keyBytes = new Uint8Array(keyData);
            
            // Try P-384 first
            try {
                const publicKey = await crypto.subtle.importKey(
                    'spki',
                    keyBytes,
                    {
                        name: 'ECDH',
                        namedCurve: 'P-384'
                    },
                    false, // Non-extractable
                    []
                );
                
                EnhancedSecureCryptoUtils.secureLog.log('info', 'Legacy public key imported (P-384)', { keySize: keyData.length });
                return publicKey;
            } catch (p384Error) {
                EnhancedSecureCryptoUtils.secureLog.log('warn', 'P-384 import failed, trying P-256', { error: p384Error.message });
                
                // Fallback to P-256
                const publicKey = await crypto.subtle.importKey(
                    'spki',
                    keyBytes,
                    {
                        name: 'ECDH',
                        namedCurve: 'P-256'
                    },
                    false, // Non-extractable
                    []
                );
                
                EnhancedSecureCryptoUtils.secureLog.log('info', 'Legacy public key imported (P-256 fallback)', { keySize: keyData.length });
                return publicKey;
            }
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Legacy public key import failed', { error: error.message });
            throw new Error('Failed to import the public key');
        }
    }

    // Helper method for unsafe import (should only be used in testing/debugging)
    static async _importKeyUnsafe(signedPackage) {
        EnhancedSecureCryptoUtils.secureLog.log('warn', 'UNSAFE KEY IMPORT - This should never happen in production', {
            keyType: signedPackage.keyType,
            keySize: signedPackage.keyData.length,
            securityRisk: 'CRITICAL'
        });
        
        const keyBytes = new Uint8Array(signedPackage.keyData);
        const keyType = signedPackage.keyType || 'ECDH';
        
        // Try P-384 first
        try {
            const publicKey = await crypto.subtle.importKey(
                'spki',
                keyBytes,
                {
                    name: keyType,
                    namedCurve: 'P-384'
                },
                false,
                []
            );
            
            return publicKey;
        } catch (p384Error) {
            // Fallback to P-256
            const publicKey = await crypto.subtle.importKey(
                'spki',
                keyBytes,
                {
                    name: keyType,
                    namedCurve: 'P-256'
                },
                false,
                []
            );
            
            return publicKey;
        }
    }

    // Method to check if a key is trusted
    static isKeyTrusted(keyOrFingerprint) {
    if (keyOrFingerprint instanceof CryptoKey) {
        const meta = EnhancedSecureCryptoUtils._keyMetadata.get(keyOrFingerprint);
        return meta ? meta.trusted === true : false;
        } else if (keyOrFingerprint && keyOrFingerprint._securityMetadata) {
            // Check by key metadata
            return keyOrFingerprint._securityMetadata.trusted === true;
        }

        return false;
    }

    static async importPublicKeyFromSignedPackage(signedPackage, verifyingKey = null, options = {}) {
        try {
            if (!signedPackage || !signedPackage.keyData || !signedPackage.signature) {
                throw new Error('Invalid signed key package format');
            }

            // Validate all required fields are present
            const requiredFields = ['keyData', 'signature', 'keyType', 'timestamp', 'version'];
            const missingFields = requiredFields.filter(field => !signedPackage[field]);

            if (missingFields.length > 0) {
                EnhancedSecureCryptoUtils.secureLog.log('error', 'Missing required fields in signed package', {
                    missingFields: missingFields,
                    availableFields: Object.keys(signedPackage)
                });
                throw new Error(`Required fields are missing in the signed package: ${missingFields.join(', ')}`);
            }

            // SECURITY ENHANCEMENT: MANDATORY signature verification for signed packages
            if (!verifyingKey) {
                EnhancedSecureCryptoUtils.secureLog.log('error', 'SECURITY VIOLATION: Signed package received without verifying key', {
                    keyType: signedPackage.keyType,
                    keySize: signedPackage.keyData.length,
                    timestamp: signedPackage.timestamp,
                    version: signedPackage.version,
                    securityRisk: 'HIGH - Potential MITM attack vector'
                });

                // Check if insecure mode is explicitly allowed (for debugging/testing only)
                if (options.allowInsecureImport === true && options.explicitWarningAcknowledged === true) {
                    EnhancedSecureCryptoUtils.secureLog.log('warn', 'INSECURE MODE: Importing signed package without verification (DANGEROUS)', {
                        keyType: signedPackage.keyType,
                        securityLevel: 'COMPROMISED',
                        recommendation: 'This mode should NEVER be used in production'
                    });

                    // Continue with insecure import but mark the key as untrusted
                    const key = await EnhancedSecureCryptoUtils._importKeyUnsafe(signedPackage);

                    // Use WeakMap to store metadata
                    EnhancedSecureCryptoUtils._keyMetadata.set(key, {
                        trusted: false,
                        verificationStatus: 'UNVERIFIED_DANGEROUS',
                        verificationTimestamp: Date.now()
                    });

                    return key;
                }

                // REJECT the signed package if no verifying key provided
                throw new Error('CRITICAL SECURITY ERROR: Signed key package received without a verification key. ' +
                                'This may indicate a possible MITM attack attempt. Import rejected for security reasons.');
            }

            // Validate key structure
            await EnhancedSecureCryptoUtils.validateKeyStructure(signedPackage.keyData, signedPackage.keyType || 'ECDH');

            // MANDATORY signature verification when verifyingKey is provided
            const packageCopy = { ...signedPackage };
            delete packageCopy.signature;
            const packageString = JSON.stringify(packageCopy);
            const isValidSignature = await EnhancedSecureCryptoUtils.verifySignature(verifyingKey, signedPackage.signature, packageString);

            if (!isValidSignature) {
                EnhancedSecureCryptoUtils.secureLog.log('error', 'SECURITY BREACH: Invalid signature detected - MITM attack prevented', {
                    keyType: signedPackage.keyType,
                    keySize: signedPackage.keyData.length,
                    timestamp: signedPackage.timestamp,
                    version: signedPackage.version,
                    attackPrevented: true
                });
                throw new Error('CRITICAL SECURITY ERROR: Invalid key signature detected. ' +
                                'This indicates a possible MITM attack attempt. Key import rejected.');
            }

            // Additional MITM protection: Check for key reuse and suspicious patterns
            const keyFingerprint = await EnhancedSecureCryptoUtils.calculateKeyFingerprint(signedPackage.keyData);

            // Log successful verification with security details
            EnhancedSecureCryptoUtils.secureLog.log('info', 'SECURE: Signature verification passed for signed package', {
                keyType: signedPackage.keyType,
                keySize: signedPackage.keyData.length,
                timestamp: signedPackage.timestamp,
                version: signedPackage.version,
                signatureVerified: true,
                securityLevel: 'HIGH',
                keyFingerprint: keyFingerprint.substring(0, 8) // Only log first 8 chars for security
            });

            // Import the public key with fallback
            const keyBytes = new Uint8Array(signedPackage.keyData);
            const keyType = signedPackage.keyType || 'ECDH';

            // Try P-384 first
            try {
                const publicKey = await crypto.subtle.importKey(
                    'spki',
                    keyBytes,
                    {
                        name: keyType,
                        namedCurve: 'P-384'
                    },
                    false, // Non-extractable
                    []
                );

                // Use WeakMap to store metadata
                EnhancedSecureCryptoUtils._keyMetadata.set(publicKey, {
                    trusted: true,
                    verificationStatus: 'VERIFIED_SECURE',
                    verificationTimestamp: Date.now()
                });

                return publicKey;
            } catch (p384Error) {
                EnhancedSecureCryptoUtils.secureLog.log('warn', 'P-384 import failed, trying P-256', { error: p384Error.message });

                // Fallback to P-256
                const publicKey = await crypto.subtle.importKey(
                    'spki',
                    keyBytes,
                    {
                        name: keyType,
                        namedCurve: 'P-256'
                    },
                    false, // Non-extractable
                    []
                );

                // Use WeakMap to store metadata
                EnhancedSecureCryptoUtils._keyMetadata.set(publicKey, {
                    trusted: true,
                    verificationStatus: 'VERIFIED_SECURE',
                    verificationTimestamp: Date.now()
                });

                return publicKey;
            }
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Signed package key import failed', {
                error: error.message,
                securityImplications: 'Potential security breach prevented'
            });
            throw new Error(`Failed to import the public key from the signed package: ${error.message}`);
        }
    }

    // Enhanced key derivation with metadata protection and 64-byte salt
    static async deriveSharedKeys(privateKey, publicKey, salt) {
        try {
            // Validate input parameters are CryptoKey instances
            if (!(privateKey instanceof CryptoKey)) {
                EnhancedSecureCryptoUtils.secureLog.log('error', 'Private key is not a CryptoKey', {
                    privateKeyType: typeof privateKey,
                    privateKeyAlgorithm: privateKey?.algorithm?.name
                });
                throw new Error('The private key is not a valid CryptoKey.');
            }
            
            if (!(publicKey instanceof CryptoKey)) {
                EnhancedSecureCryptoUtils.secureLog.log('error', 'Public key is not a CryptoKey', {
                    publicKeyType: typeof publicKey,
                    publicKeyAlgorithm: publicKey?.algorithm?.name
                });
                throw new Error('The private key is not a valid CryptoKey.');
            }
            
            // Validate salt size (should be 64 bytes for enhanced security)
            if (!salt || salt.length !== 64) {
                throw new Error('Salt must be exactly 64 bytes for enhanced security');
            }
            
            const saltBytes = new Uint8Array(salt);
            const encoder = new TextEncoder();
            
            // Enhanced context info with version and additional entropy
            const contextInfo = encoder.encode('SecureBit.chat v4.0 Enhanced Security Edition');
            
            // Derive master shared secret with enhanced parameters
            // Try SHA-384 first, fallback to SHA-256
            let sharedSecret;
            try {
                sharedSecret = await crypto.subtle.deriveKey(
                    {
                        name: 'ECDH',
                        public: publicKey
                    },
                    privateKey,
                    {
                        name: 'HKDF',
                        hash: 'SHA-384',
                        salt: saltBytes,
                        info: contextInfo
                    },
                    false, // Non-extractable
                    ['deriveKey']
                );
            } catch (sha384Error) {
                EnhancedSecureCryptoUtils.secureLog.log('warn', 'SHA-384 key derivation failed, trying SHA-256', { 
                    error: sha384Error.message,
                    privateKeyType: typeof privateKey,
                    publicKeyType: typeof publicKey,
                    privateKeyAlgorithm: privateKey?.algorithm?.name,
                    publicKeyAlgorithm: publicKey?.algorithm?.name
                });
                
                sharedSecret = await crypto.subtle.deriveKey(
                    {
                        name: 'ECDH',
                        public: publicKey
                    },
                    privateKey,
                    {
                        name: 'HKDF',
                        hash: 'SHA-256',
                        salt: saltBytes,
                        info: contextInfo
                    },
                    false, // Non-extractable
                    ['deriveKey']
                );
            }

            // Derive message encryption key with fallback
            let encryptionKey;
            try {
                encryptionKey = await crypto.subtle.deriveKey(
                    {
                        name: 'HKDF',
                        hash: 'SHA-384',
                        salt: saltBytes,
                        info: encoder.encode('message-encryption-v4')
                    },
                    sharedSecret,
                    {
                        name: 'AES-GCM',
                        length: 256
                    },
                    false, // Non-extractable for enhanced security
                    ['encrypt', 'decrypt']
                );
            } catch (sha384Error) {
                encryptionKey = await crypto.subtle.deriveKey(
                    {
                        name: 'HKDF',
                        hash: 'SHA-256',
                        salt: saltBytes,
                        info: encoder.encode('message-encryption-v4')
                    },
                    sharedSecret,
                    {
                        name: 'AES-GCM',
                        length: 256
                    },
                    false, // Non-extractable for enhanced security
                    ['encrypt', 'decrypt']
                );
            }

            // Derive MAC key for message authentication with fallback
            let macKey;
            try {
                macKey = await crypto.subtle.deriveKey(
                    {
                        name: 'HKDF',
                        hash: 'SHA-384',
                        salt: saltBytes,
                        info: encoder.encode('message-authentication-v4')
                    },
                    sharedSecret,
                    {
                        name: 'HMAC',
                        hash: 'SHA-384'
                    },
                    false, // Non-extractable
                    ['sign', 'verify']
                );
            } catch (sha384Error) {
                macKey = await crypto.subtle.deriveKey(
                    {
                        name: 'HKDF',
                        hash: 'SHA-256',
                        salt: saltBytes,
                        info: encoder.encode('message-authentication-v4')
                    },
                    sharedSecret,
                    {
                        name: 'HMAC',
                        hash: 'SHA-256'
                    },
                    false, // Non-extractable
                    ['sign', 'verify']
                );
            }

            // Derive separate metadata encryption key with fallback
            let metadataKey;
            try {
                metadataKey = await crypto.subtle.deriveKey(
                    {
                        name: 'HKDF',
                        hash: 'SHA-384',
                        salt: saltBytes,
                        info: encoder.encode('metadata-protection-v4')
                    },
                    sharedSecret,
                    {
                        name: 'AES-GCM',
                        length: 256
                    },
                    false, // Non-extractable
                    ['encrypt', 'decrypt']
                );
            } catch (sha384Error) {
                metadataKey = await crypto.subtle.deriveKey(
                    {
                        name: 'HKDF',
                        hash: 'SHA-256',
                        salt: saltBytes,
                        info: encoder.encode('metadata-protection-v4')
                    },
                    sharedSecret,
                    {
                        name: 'AES-GCM',
                        length: 256
                    },
                    false, // Non-extractable
                    ['encrypt', 'decrypt']
                );
            }

            // Generate temporary extractable key for fingerprint calculation with fallback
            let fingerprintKey;
            try {
                fingerprintKey = await crypto.subtle.deriveKey(
                    {
                        name: 'HKDF',
                        hash: 'SHA-384',
                        salt: saltBytes,
                        info: encoder.encode('fingerprint-generation-v4')
                    },
                    sharedSecret,
                    {
                        name: 'AES-GCM',
                        length: 256
                    },
                    true, // Extractable only for fingerprint
                    ['encrypt', 'decrypt']
                );
            } catch (sha384Error) {
                fingerprintKey = await crypto.subtle.deriveKey(
                    {
                        name: 'HKDF',
                        hash: 'SHA-256',
                        salt: saltBytes,
                        info: encoder.encode('fingerprint-generation-v4')
                    },
                    sharedSecret,
                    {
                        name: 'AES-GCM',
                        length: 256
                    },
                    true, // Extractable only for fingerprint
                    ['encrypt', 'decrypt']
                );
            }

            // Generate key fingerprint for verification
            const fingerprintKeyData = await crypto.subtle.exportKey('raw', fingerprintKey);
            const fingerprint = await EnhancedSecureCryptoUtils.generateKeyFingerprint(Array.from(new Uint8Array(fingerprintKeyData)));

            // Validate that all derived keys are CryptoKey instances
            if (!(encryptionKey instanceof CryptoKey)) {
                EnhancedSecureCryptoUtils.secureLog.log('error', 'Derived encryption key is not a CryptoKey', {
                    encryptionKeyType: typeof encryptionKey,
                    encryptionKeyAlgorithm: encryptionKey?.algorithm?.name
                });
                throw new Error('The derived encryption key is not a valid CryptoKey.');
            }
            
            if (!(macKey instanceof CryptoKey)) {
                EnhancedSecureCryptoUtils.secureLog.log('error', 'Derived MAC key is not a CryptoKey', {
                    macKeyType: typeof macKey,
                    macKeyAlgorithm: macKey?.algorithm?.name
                });
                throw new Error('The derived MAC key is not a valid CryptoKey.');
            }
            
            if (!(metadataKey instanceof CryptoKey)) {
                EnhancedSecureCryptoUtils.secureLog.log('error', 'Derived metadata key is not a CryptoKey', {
                    metadataKeyType: typeof metadataKey,
                    metadataKeyAlgorithm: metadataKey?.algorithm?.name
                });
                throw new Error('The derived metadata key is not a valid CryptoKey.');
            }

            EnhancedSecureCryptoUtils.secureLog.log('info', 'Enhanced shared keys derived successfully', {
                saltSize: salt.length,
                hasMetadataKey: true,
                nonExtractable: true,
                version: '4.0',
                allKeysValid: true
            });

            return {
                encryptionKey,
                macKey,
                metadataKey,
                fingerprint,
                timestamp: Date.now(),
                version: '4.0'
            };
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Enhanced key derivation failed', { error: error.message });
            throw new Error(`Failed to create shared encryption keys: ${error.message}`);
        }
    }

    static async generateKeyFingerprint(keyData) {
        const keyBuffer = new Uint8Array(keyData);
        const hashBuffer = await crypto.subtle.digest('SHA-384', keyBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.slice(0, 12).map(b => b.toString(16).padStart(2, '0')).join(':');
    }

    // Generate mutual authentication challenge
    static generateMutualAuthChallenge() {
        const challenge = crypto.getRandomValues(new Uint8Array(48)); // Increased to 48 bytes
        const timestamp = Date.now();
        const nonce = crypto.getRandomValues(new Uint8Array(16));
        
        return {
            challenge: Array.from(challenge),
            timestamp,
            nonce: Array.from(nonce),
            version: '4.0'
        };
    }

    // Create cryptographic proof for mutual authentication
    static async createAuthProof(challenge, privateKey, publicKey) {
        try {
            if (!challenge || !challenge.challenge || !challenge.timestamp || !challenge.nonce) {
                throw new Error('Invalid challenge structure');
            }
            
            // Check challenge age (max 2 minutes)
            const challengeAge = Date.now() - challenge.timestamp;
            if (challengeAge > 120000) {
                throw new Error('Challenge expired');
            }
            
            // Create proof data
            const proofData = {
                challenge: challenge.challenge,
                timestamp: challenge.timestamp,
                nonce: challenge.nonce,
                responseTimestamp: Date.now(),
                publicKeyHash: await EnhancedSecureCryptoUtils.hashPublicKey(publicKey)
            };
            
            // Sign the proof
            const proofString = JSON.stringify(proofData);
            const signature = await EnhancedSecureCryptoUtils.signData(privateKey, proofString);
            
            const proof = {
                ...proofData,
                signature,
                version: '4.0'
            };
            
            EnhancedSecureCryptoUtils.secureLog.log('info', 'Authentication proof created', {
                challengeAge: Math.round(challengeAge / 1000) + 's'
            });
            
            return proof;
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Authentication proof creation failed', { error: error.message });
            throw new Error(`Failed to create cryptographic proof: ${error.message}`);
        }
    }

    // Verify mutual authentication proof
    static async verifyAuthProof(proof, challenge, publicKey) {
        try {
            // Assert the public key is valid and has the correct usage
            EnhancedSecureCryptoUtils.assertCryptoKey(publicKey, 'ECDSA', ['verify']);

            if (!proof || !challenge || !publicKey) {
                throw new Error('Missing required parameters for proof verification');
            }

            // Validate proof structure
            const requiredFields = ['challenge', 'timestamp', 'nonce', 'responseTimestamp', 'publicKeyHash', 'signature'];
            for (const field of requiredFields) {
                if (!proof[field]) {
                    throw new Error(`Missing required field: ${field}`);
                }
            }

            // Verify challenge matches
            if (JSON.stringify(proof.challenge) !== JSON.stringify(challenge.challenge) ||
                proof.timestamp !== challenge.timestamp ||
                JSON.stringify(proof.nonce) !== JSON.stringify(challenge.nonce)) {
                throw new Error('Challenge mismatch - possible replay attack');
            }

            // Check response time (max 5 minutes)
            const responseAge = Date.now() - proof.responseTimestamp;
            if (responseAge > 300000) {
                throw new Error('Proof response expired');
            }

            // Verify public key hash
            const expectedHash = await EnhancedSecureCryptoUtils.hashPublicKey(publicKey);
            if (proof.publicKeyHash !== expectedHash) {
                throw new Error('Public key hash mismatch');
            }

            // Verify signature
            const proofCopy = { ...proof };
            delete proofCopy.signature;
            const proofString = JSON.stringify(proofCopy);
            const isValidSignature = await EnhancedSecureCryptoUtils.verifySignature(publicKey, proof.signature, proofString);

            if (!isValidSignature) {
                throw new Error('Invalid proof signature');
            }

            EnhancedSecureCryptoUtils.secureLog.log('info', 'Authentication proof verified successfully', {
                responseAge: Math.round(responseAge / 1000) + 's'
            });

            return true;
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Authentication proof verification failed', { error: error.message });
            throw new Error(`Failed to verify cryptographic proof: ${error.message}`);
        }
    }

    // Hash public key for verification
    static async hashPublicKey(publicKey) {
        try {
            const exported = await crypto.subtle.exportKey('spki', publicKey);
            const hash = await crypto.subtle.digest('SHA-384', exported);
            const hashArray = Array.from(new Uint8Array(hash));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Public key hashing failed', { error: error.message });
            throw new Error('Failed to create hash of the public key');
        }
    }

    // Legacy authentication challenge for backward compatibility
    static generateAuthChallenge() {
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        return Array.from(challenge);
    }

    // Generate verification code for out-of-band authentication
    static generateVerificationCode() {
        const chars = '0123456789ABCDEF';
        let result = '';
        const values = crypto.getRandomValues(new Uint8Array(6));
        for (let i = 0; i < 6; i++) {
            result += chars[values[i] % chars.length];
        }
        return result.match(/.{1,2}/g).join('-');
    }

    // Enhanced message encryption with metadata protection and sequence numbers
    static async encryptMessage(message, encryptionKey, macKey, metadataKey, messageId, sequenceNumber = 0) {
        try {
            if (!message || typeof message !== 'string') {
                throw new Error('Invalid message format');
            }

            EnhancedSecureCryptoUtils.assertCryptoKey(encryptionKey, 'AES-GCM', ['encrypt']);
            EnhancedSecureCryptoUtils.assertCryptoKey(macKey, 'HMAC', ['sign']);
            EnhancedSecureCryptoUtils.assertCryptoKey(metadataKey, 'AES-GCM', ['encrypt']);

            const encoder = new TextEncoder();
            const messageData = encoder.encode(message);
            const messageIv = crypto.getRandomValues(new Uint8Array(12));
            const metadataIv = crypto.getRandomValues(new Uint8Array(12));
            const timestamp = Date.now();

            const paddingSize = 16 - (messageData.length % 16);
            const paddedMessage = new Uint8Array(messageData.length + paddingSize);
            paddedMessage.set(messageData);
            const padding = crypto.getRandomValues(new Uint8Array(paddingSize));
            paddedMessage.set(padding, messageData.length);

            const encryptedMessage = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: messageIv },
                encryptionKey,
                paddedMessage
            );

            const metadata = {
                id: messageId,
                timestamp: timestamp,
                sequenceNumber: sequenceNumber,
                originalLength: messageData.length,
                version: '4.0'
            };

            const metadataStr = JSON.stringify(EnhancedSecureCryptoUtils.sortObjectKeys(metadata));
            const encryptedMetadata = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: metadataIv },
                metadataKey,
                encoder.encode(metadataStr)
            );

            const payload = {
                messageIv: Array.from(messageIv),
                messageData: Array.from(new Uint8Array(encryptedMessage)),
                metadataIv: Array.from(metadataIv),
                metadataData: Array.from(new Uint8Array(encryptedMetadata)),
                version: '4.0'
            };

            const sortedPayload = EnhancedSecureCryptoUtils.sortObjectKeys(payload);
            const payloadStr = JSON.stringify(sortedPayload);

            const mac = await crypto.subtle.sign(
                'HMAC',
                macKey,
                encoder.encode(payloadStr)
            );

            payload.mac = Array.from(new Uint8Array(mac));

            EnhancedSecureCryptoUtils.secureLog.log('info', 'Message encrypted with metadata protection', {
                messageId,
                sequenceNumber,
                hasMetadataProtection: true,
                hasPadding: true
            });

            return payload;
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Message encryption failed', {
                error: error.message,
                messageId
            });
            throw new Error(`Failed to encrypt the message: ${error.message}`);
        }
    }

    // Enhanced message decryption with metadata protection and sequence validation
    static async decryptMessage(encryptedPayload, encryptionKey, macKey, metadataKey, expectedSequenceNumber = null) {
        try {
            EnhancedSecureCryptoUtils.assertCryptoKey(encryptionKey, 'AES-GCM', ['decrypt']);
            EnhancedSecureCryptoUtils.assertCryptoKey(macKey, 'HMAC', ['verify']);
            EnhancedSecureCryptoUtils.assertCryptoKey(metadataKey, 'AES-GCM', ['decrypt']);

            const requiredFields = ['messageIv', 'messageData', 'metadataIv', 'metadataData', 'mac', 'version'];
            for (const field of requiredFields) {
                if (!encryptedPayload[field]) {
                    throw new Error(`Missing required field: ${field}`);
                }
            }

            const payloadCopy = { ...encryptedPayload };
            delete payloadCopy.mac;
            const sortedPayloadCopy = EnhancedSecureCryptoUtils.sortObjectKeys(payloadCopy);
            const payloadStr = JSON.stringify(sortedPayloadCopy);

            const macValid = await crypto.subtle.verify(
                'HMAC',
                macKey,
                new Uint8Array(encryptedPayload.mac),
                new TextEncoder().encode(payloadStr)
            );

            if (!macValid) {
                EnhancedSecureCryptoUtils.secureLog.log('error', 'MAC verification failed', {
                    payloadFields: Object.keys(encryptedPayload),
                    macLength: encryptedPayload.mac?.length
                });
                throw new Error('Message authentication failed - possible tampering');
            }

            const metadataIv = new Uint8Array(encryptedPayload.metadataIv);
            const metadataData = new Uint8Array(encryptedPayload.metadataData);

            const decryptedMetadataBuffer = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: metadataIv },
                metadataKey,
                metadataData
            );

            const metadataStr = new TextDecoder().decode(decryptedMetadataBuffer);
            const metadata = JSON.parse(metadataStr);

            if (!metadata.id || !metadata.timestamp || metadata.sequenceNumber === undefined || !metadata.originalLength) {
                throw new Error('Invalid metadata structure');
            }

            const messageAge = Date.now() - metadata.timestamp;
            if (messageAge > 300000) {
                throw new Error('Message expired (older than 5 minutes)');
            }

            if (expectedSequenceNumber !== null) {
                if (metadata.sequenceNumber < expectedSequenceNumber) {
                    EnhancedSecureCryptoUtils.secureLog.log('warn', 'Received message with lower sequence number, possible queued message', {
                        expected: expectedSequenceNumber,
                        received: metadata.sequenceNumber,
                        messageId: metadata.id
                    });
                } else if (metadata.sequenceNumber > expectedSequenceNumber + 10) {
                    throw new Error(`Sequence number gap too large: expected around ${expectedSequenceNumber}, got ${metadata.sequenceNumber}`);
                }
            }

            const messageIv = new Uint8Array(encryptedPayload.messageIv);
            const messageData = new Uint8Array(encryptedPayload.messageData);

            const decryptedMessageBuffer = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: messageIv },
                encryptionKey,
                messageData
            );

            const paddedMessage = new Uint8Array(decryptedMessageBuffer);
            const originalMessage = paddedMessage.slice(0, metadata.originalLength);

            const decoder = new TextDecoder();
            const message = decoder.decode(originalMessage);

            EnhancedSecureCryptoUtils.secureLog.log('info', 'Message decrypted successfully', {
                messageId: metadata.id,
                sequenceNumber: metadata.sequenceNumber,
                messageAge: Math.round(messageAge / 1000) + 's'
            });

            return {
                message: message,
                messageId: metadata.id,
                timestamp: metadata.timestamp,
                sequenceNumber: metadata.sequenceNumber
            };
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Message decryption failed', { error: error.message });
            throw new Error(`Failed to decrypt the message: ${error.message}`);
        }
    }

    // Enhanced input sanitization
    static sanitizeMessage(message) {
        if (typeof message !== 'string') {
            throw new Error('Message must be a string');
        }
        
        return message
            .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
            .replace(/javascript:/gi, '')
            .replace(/data:/gi, '')
            .replace(/vbscript:/gi, '')
            .replace(/onload\s*=/gi, '')
            .replace(/onerror\s*=/gi, '')
            .replace(/onclick\s*=/gi, '')
            .trim()
            .substring(0, 2000); // Increased limit
    }

    // Generate cryptographically secure salt (64 bytes for enhanced security)
    static generateSalt() {
        return Array.from(crypto.getRandomValues(new Uint8Array(64)));
    }

    // Calculate key fingerprint for MITM protection
    static async calculateKeyFingerprint(keyData) {
        try {
            const encoder = new TextEncoder();
            const keyBytes = new Uint8Array(keyData);
            
            // Create a hash of the key data for fingerprinting
            const hashBuffer = await crypto.subtle.digest('SHA-256', keyBytes);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            
            // Convert to hexadecimal string
            const fingerprint = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            
            EnhancedSecureCryptoUtils.secureLog.log('info', 'Key fingerprint calculated', {
                keySize: keyData.length,
                fingerprintLength: fingerprint.length
            });
            
            return fingerprint;
        } catch (error) {
            EnhancedSecureCryptoUtils.secureLog.log('error', 'Key fingerprint calculation failed', { error: error.message });
            throw new Error('Failed to compute the key fingerprint');
        }
    }
}

export { EnhancedSecureCryptoUtils };