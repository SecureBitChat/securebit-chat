class PayPerSessionManager {
    constructor(config = {}) {
        this.sessionPrices = {
            // БЕЗОПАСНЫЙ demo режим с ограничениями
            demo: { sats: 0, hours: 0.1, usd: 0.00 }, // 6 минут для тестирования
            basic: { sats: 500, hours: 1, usd: 0.20 },
            premium: { sats: 1000, hours: 4, usd: 0.40 },
            extended: { sats: 2000, hours: 24, usd: 0.80 }
        };
        
        this.currentSession = null;
        this.sessionTimer = null;
        this.onSessionExpired = null;
        this.staticLightningAddress = "dullpastry62@walletofsatoshi.com";
        
        // Хранилище использованных preimage для предотвращения повторного использования
        this.usedPreimages = new Set();
        this.preimageCleanupInterval = null;
        
        // DEMO режим: Контроль для предотвращения злоупотреблений
        this.demoSessions = new Map(); // fingerprint -> { count, lastUsed, sessions }
        this.maxDemoSessionsPerUser = 3; // Максимум 3 demo сессии на пользователя
        this.demoCooldownPeriod = 60 * 60 * 1000; // 1 час между сериями demo сессий
        this.demoSessionCooldown = 5 * 60 * 1000; // 5 минут между отдельными demo сессиями
        this.demoSessionMaxDuration = 6 * 60 * 1000; // 6 минут максимум на demo сессию
        
        // Минимальная стоимость для платных сессий (защита от микроплатежей-атак)
        this.minimumPaymentSats = 100;
        
        this.verificationConfig = {
            method: config.method || 'lnbits',
            apiUrl: config.apiUrl || 'https://demo.lnbits.com',
            apiKey: config.apiKey || '623515641d2e4ebcb1d5992d6d78419c', 
            walletId: config.walletId || 'bcd00f561c7b46b4a7b118f069e68997',
            isDemo: config.isDemo !== undefined ? config.isDemo : true, // По умолчанию demo режим включен
            demoTimeout: 30000, 
            retryAttempts: 3,
            invoiceExpiryMinutes: 15
        };
        
        // Rate limiting для API запросов
        this.lastApiCall = 0;
        this.apiCallMinInterval = 1000; // Минимум 1 секунда между API вызовами
        
        // Запуск периодических задач
        this.startPreimageCleanup();
        this.startDemoSessionCleanup();
        
        console.log('💰 PayPerSessionManager initialized with secure demo mode');
    }

    // ============================================
    // DEMO РЕЖИМ: Управление и контроль
    // ============================================

    // Очистка старых demo сессий (каждый час)
    startDemoSessionCleanup() {
        setInterval(() => {
            const now = Date.now();
            const maxAge = 24 * 60 * 60 * 1000; // 24 часа
            
            let cleanedCount = 0;
            for (const [identifier, data] of this.demoSessions.entries()) {
                if (now - data.lastUsed > maxAge) {
                    this.demoSessions.delete(identifier);
                    cleanedCount++;
                }
            }
            
            if (cleanedCount > 0) {
                console.log(`🧹 Cleaned ${cleanedCount} old demo session records`);
            }
        }, 60 * 60 * 1000); // Каждый час
    }

    // Генерация отпечатка пользователя для контроля demo сессий
    generateUserFingerprint() {
        try {
            const components = [
                navigator.userAgent || '',
                navigator.language || '',
                screen.width + 'x' + screen.height,
                Intl.DateTimeFormat().resolvedOptions().timeZone || '',
                navigator.hardwareConcurrency || 0,
                navigator.deviceMemory || 0,
                navigator.platform || '',
                navigator.cookieEnabled ? '1' : '0'
            ];
            
            // Создаем детерминированный хеш для идентификации
            let hash = 0;
            const str = components.join('|');
            for (let i = 0; i < str.length; i++) {
                const char = str.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash; // Преобразуем в 32-битное целое
            }
            
            return Math.abs(hash).toString(36);
        } catch (error) {
            console.warn('Failed to generate user fingerprint:', error);
            // Fallback на случайный ID (менее эффективен для контроля лимитов)
            return 'fallback_' + Math.random().toString(36).substr(2, 9);
        }
    }

    // Проверка лимитов demo сессий для пользователя
    checkDemoSessionLimits(userFingerprint) {
        const userData = this.demoSessions.get(userFingerprint);
        const now = Date.now();
        
        if (!userData) {
            // Первая demo сессия для этого пользователя
            return { 
                allowed: true, 
                reason: 'first_demo_session',
                remaining: this.maxDemoSessionsPerUser
            };
        }
        
        // Фильтруем активные сессии (в пределах cooldown периода)
        const activeSessions = userData.sessions.filter(session => 
            now - session.timestamp < this.demoCooldownPeriod
        );
        
        // Проверяем количество demo сессий
        if (activeSessions.length >= this.maxDemoSessionsPerUser) {
            const oldestSession = Math.min(...activeSessions.map(s => s.timestamp));
            const timeUntilNext = this.demoCooldownPeriod - (now - oldestSession);
            
            return { 
                allowed: false, 
                reason: 'demo_limit_exceeded',
                timeUntilNext: timeUntilNext,
                message: `Demo limit reached (${this.maxDemoSessionsPerUser}/day). Try again in ${Math.ceil(timeUntilNext / (60 * 1000))} minutes.`,
                remaining: 0
            };
        }
        
        // Проверяем кулдаун между отдельными сессиями
        if (userData.lastUsed && (now - userData.lastUsed) < this.demoSessionCooldown) {
            const timeUntilNext = this.demoSessionCooldown - (now - userData.lastUsed);
            return { 
                allowed: false, 
                reason: 'demo_cooldown',
                timeUntilNext: timeUntilNext,
                message: `Please wait ${Math.ceil(timeUntilNext / (60 * 1000))} minutes between demo sessions.`,
                remaining: this.maxDemoSessionsPerUser - activeSessions.length
            };
        }
        
        return { 
            allowed: true, 
            reason: 'within_limits',
            remaining: this.maxDemoSessionsPerUser - activeSessions.length
        };
    }

    // Регистрация использования demo сессии
    registerDemoSessionUsage(userFingerprint) {
        const now = Date.now();
        const userData = this.demoSessions.get(userFingerprint) || {
            count: 0,
            lastUsed: 0,
            sessions: [],
            firstUsed: now
        };
        
        userData.count++;
        userData.lastUsed = now;
        userData.sessions.push({
            timestamp: now,
            sessionId: crypto.getRandomValues(new Uint32Array(1))[0].toString(36),
            duration: this.demoSessionMaxDuration
        });
        
        // Храним только актуальные сессии (в пределах cooldown периода)
        userData.sessions = userData.sessions
            .filter(session => now - session.timestamp < this.demoCooldownPeriod)
            .slice(-this.maxDemoSessionsPerUser);
        
        this.demoSessions.set(userFingerprint, userData);
        
        console.log(`📊 Demo session registered for user ${userFingerprint.substring(0, 8)}... (${userData.sessions.length}/${this.maxDemoSessionsPerUser})`);
    }

    // Генерация криптографически стойкого demo preimage
    generateSecureDemoPreimage() {
        try {
            const timestamp = Date.now();
            const randomBytes = crypto.getRandomValues(new Uint8Array(24)); // 24 байта случайных данных
            const timestampBytes = new Uint8Array(4); // 4 байта для timestamp
            const versionBytes = new Uint8Array(4); // 4 байта для версии и маркеров
            
            // Упаковываем timestamp в 4 байта (секунды)
            const timestampSeconds = Math.floor(timestamp / 1000);
            timestampBytes[0] = (timestampSeconds >>> 24) & 0xFF;
            timestampBytes[1] = (timestampSeconds >>> 16) & 0xFF;
            timestampBytes[2] = (timestampSeconds >>> 8) & 0xFF;
            timestampBytes[3] = timestampSeconds & 0xFF;
            
            // Маркер demo версии
            versionBytes[0] = 0xDE; // 'DE'mo
            versionBytes[1] = 0xE0; // de'MO' (E0 вместо MO)
            versionBytes[2] = 0x00; // версия 0
            versionBytes[3] = 0x01; // подверсия 1
            
            // Комбинируем все компоненты (32 байта total)
            const combined = new Uint8Array(32);
            combined.set(versionBytes, 0);      // Байты 0-3: маркер версии
            combined.set(timestampBytes, 4);    // Байты 4-7: timestamp
            combined.set(randomBytes, 8);       // Байты 8-31: случайные данные
            
            const preimage = Array.from(combined).map(b => b.toString(16).padStart(2, '0')).join('');
            
            console.log(`🎮 Generated secure demo preimage: ${preimage.substring(0, 16)}...`);
            return preimage;
            
        } catch (error) {
            console.error('Failed to generate demo preimage:', error);
            throw new Error('Failed to generate secure demo preimage');
        }
    }

    // Проверка, является ли preimage demo
    isDemoPreimage(preimage) {
        if (!preimage || typeof preimage !== 'string' || preimage.length !== 64) {
            return false;
        }
        
        // Проверяем маркер demo (первые 8 символов = 4 байта)
        return preimage.toLowerCase().startsWith('dee00001');
    }

    // Извлечение timestamp из demo preimage
    extractDemoTimestamp(preimage) {
        if (!this.isDemoPreimage(preimage)) {
            return null;
        }
        
        try {
            // Timestamp находится в байтах 4-7 (символы 8-15)
            const timestampHex = preimage.slice(8, 16);
            const timestampSeconds = parseInt(timestampHex, 16);
            return timestampSeconds * 1000; // Преобразуем в миллисекунды
        } catch (error) {
            console.error('Failed to extract demo timestamp:', error);
            return null;
        }
    }

    // ============================================
    // ВАЛИДАЦИЯ И ПРОВЕРКИ
    // ============================================

    // Валидация типа сессии
    validateSessionType(sessionType) {
        if (!sessionType || typeof sessionType !== 'string') {
            throw new Error('Session type must be a non-empty string');
        }
        
        if (!this.sessionPrices[sessionType]) {
            throw new Error(`Invalid session type: ${sessionType}. Allowed: ${Object.keys(this.sessionPrices).join(', ')}`);
        }
        
        const pricing = this.sessionPrices[sessionType];
        
        // Для demo сессии особая логика
        if (sessionType === 'demo') {
            return true; // Demo всегда валидна по типу, лимиты проверяем отдельно
        }
        
        // Для платных сессий проверяем минимальную стоимость
        if (pricing.sats < this.minimumPaymentSats) {
            throw new Error(`Session type ${sessionType} below minimum payment threshold (${this.minimumPaymentSats} sats)`);
        }
        
        return true;
    }

    // Вычисление энтропии строки
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

    // Усиленная криптографическая проверка preimage
    async verifyCryptographically(preimage, paymentHash) {
        try {
            // Базовая валидация формата
            if (!preimage || typeof preimage !== 'string') {
                throw new Error('Preimage must be a string');
            }
            
            if (preimage.length !== 64) {
                throw new Error(`Invalid preimage length: ${preimage.length}, expected 64`);
            }
            
            if (!/^[0-9a-fA-F]{64}$/.test(preimage)) {
                throw new Error('Preimage must be valid hexadecimal');
            }
            
            // СПЕЦИАЛЬНАЯ обработка demo preimage
            if (this.isDemoPreimage(preimage)) {
                console.log('🎮 Demo preimage detected - performing enhanced validation...');
                
                // Извлекаем и проверяем timestamp
                const demoTimestamp = this.extractDemoTimestamp(preimage);
                if (!demoTimestamp) {
                    throw new Error('Invalid demo preimage timestamp');
                }
                
                const now = Date.now();
                const age = now - demoTimestamp;
                
                // Demo preimage не должен быть старше 15 минут
                if (age > 15 * 60 * 1000) {
                    throw new Error(`Demo preimage expired (age: ${Math.round(age / (60 * 1000))} minutes)`);
                }
                
                // Demo preimage не должен быть из будущего (защита от clock attack)
                if (age < -2 * 60 * 1000) { // Допускаем 2 минуты расхождения часов
                    throw new Error('Demo preimage timestamp from future - possible clock manipulation');
                }
                
                // Проверяем на повторное использование
                if (this.usedPreimages.has(preimage)) {
                    throw new Error('Demo preimage already used - replay attack prevented');
                }
                
                // Demo preimage валиден
                this.usedPreimages.add(preimage);
                console.log('✅ Demo preimage cryptographic validation passed');
                return true;
            }
            
            // Для обычных preimage - СТРОГИЕ проверки
            
            // Запрет на простые/предсказуемые паттерны
            const forbiddenPatterns = [
                '0'.repeat(64),                    // Все нули
                '1'.repeat(64),                    // Все единицы
                'a'.repeat(64),                    // Все 'a'
                'f'.repeat(64),                    // Все 'f'
                '0123456789abcdef'.repeat(4),      // Повторяющийся паттерн
                'deadbeef'.repeat(8),              // Известный тестовый паттерн
                'cafebabe'.repeat(8),              // Известный тестовый паттерн
                'feedface'.repeat(8),              // Известный тестовый паттерн
                'baadf00d'.repeat(8),              // Известный тестовый паттерн
                'c0ffee'.repeat(10) + 'c0ff'       // Известный тестовый паттерн
            ];
            
            if (forbiddenPatterns.includes(preimage.toLowerCase())) {
                throw new Error('Forbidden preimage pattern detected - possible test/attack attempt');
            }
            
            // Проверка на повторное использование
            if (this.usedPreimages.has(preimage)) {
                throw new Error('Preimage already used - replay attack prevented');
            }
            
            // Проверка энтропии (должна быть достаточно высокой для hex строки)
            const entropy = this.calculateEntropy(preimage);
            if (entropy < 3.5) { // Минимальная энтропия для 64-символьной hex строки
                throw new Error(`Preimage has insufficient entropy: ${entropy.toFixed(2)} (minimum: 3.5)`);
            }
            
            // Стандартная криптографическая проверка SHA256(preimage) = paymentHash
            const preimageBytes = new Uint8Array(preimage.match(/.{2}/g).map(byte => parseInt(byte, 16)));
            const hashBuffer = await crypto.subtle.digest('SHA-256', preimageBytes);
            const computedHash = Array.from(new Uint8Array(hashBuffer))
                .map(b => b.toString(16).padStart(2, '0')).join('');
            
            const isValid = computedHash === paymentHash.toLowerCase();
            
            if (isValid) {
                // Сохраняем использованный preimage
                this.usedPreimages.add(preimage);
                console.log('✅ Standard preimage cryptographic validation passed');
            } else {
                console.log('❌ SHA256 verification failed:', {
                    computed: computedHash.substring(0, 16) + '...',
                    expected: paymentHash.substring(0, 16) + '...'
                });
            }
            
            return isValid;
            
        } catch (error) {
            console.error('❌ Cryptographic verification failed:', error.message);
            return false;
        }
    }

    // ============================================
    // LIGHTNING NETWORK ИНТЕГРАЦИЯ
    // ============================================

    // Создание Lightning invoice
    async createLightningInvoice(sessionType) {
        const pricing = this.sessionPrices[sessionType];
        if (!pricing) throw new Error('Invalid session type');

        try {
            console.log(`Creating ${sessionType} invoice for ${pricing.sats} sats...`);

            // Проверка доступности API с rate limiting
            const now = Date.now();
            if (now - this.lastApiCall < this.apiCallMinInterval) {
                throw new Error('API rate limit: please wait before next request');
            }
            this.lastApiCall = now;

            // Проверка health API
            const healthCheck = await fetch(`${this.verificationConfig.apiUrl}/api/v1/health`, {
                method: 'GET',
                headers: {
                    'X-Api-Key': this.verificationConfig.apiKey
                },
                signal: AbortSignal.timeout(5000) // 5 секунд timeout
            });

            if (!healthCheck.ok) {
                throw new Error(`LNbits API unavailable: ${healthCheck.status}`);
            }

            // Создание invoice
            const response = await fetch(`${this.verificationConfig.apiUrl}/api/v1/payments`, {
                method: 'POST',
                headers: {
                    'X-Api-Key': this.verificationConfig.apiKey,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    out: false, // incoming payment
                    amount: pricing.sats,
                    memo: `LockBit.chat ${sessionType} session (${pricing.hours}h) - ${Date.now()}`,
                    unit: 'sat',
                    expiry: this.verificationConfig.invoiceExpiryMinutes * 60 // В секундах
                }),
                signal: AbortSignal.timeout(10000) // 10 секунд timeout
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
                description: data.description || data.memo || `LockBit.chat ${sessionType} session`,
                bolt11: data.bolt11 || data.payment_request,
                memo: data.memo || `LockBit.chat ${sessionType} session`
            };

        } catch (error) {
            console.error('❌ Lightning invoice creation failed:', error);
            
            // Для demo режима создаем фиктивный invoice
            if (this.verificationConfig.isDemo && error.message.includes('API')) {
                console.log('🔄 Creating demo invoice for testing...');
                return this.createDemoInvoice(sessionType);
            }
            
            throw error;
        }
    }

    // Создание demo invoice для тестирования
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
            expiresAt: Date.now() + (5 * 60 * 1000), // 5 минут
            description: `LockBit.chat ${sessionType} session (DEMO)`,
            isDemo: true
        };
    }

    // Проверка статуса платежа через LNbits
    async checkPaymentStatus(checkingId) {
        try {
            console.log(`🔍 Checking payment status for: ${checkingId?.substring(0, 8)}...`);

            // Rate limiting
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
                signal: AbortSignal.timeout(10000) // 10 секунд timeout
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
            
            // Для demo режима возвращаем фиктивный статус
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

    // Верификация платежа через LNbits API
    async verifyPaymentLNbits(preimage, paymentHash) {
        try {
            console.log(`🔐 Verifying payment via LNbits API...`);
            
            if (!this.verificationConfig.apiUrl || !this.verificationConfig.apiKey) {
                throw new Error('LNbits API configuration missing');
            }

            // Rate limiting
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
                signal: AbortSignal.timeout(10000) // 10 секунд timeout
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error('LNbits verification failed:', errorText);
                throw new Error(`API request failed: ${response.status} - ${errorText}`);
            }

            const paymentData = await response.json();
            console.log('📋 Payment verification data received from LNbits');
            
            // Строгая проверка всех условий
            const isPaid = paymentData.paid === true;
            const preimageMatches = paymentData.preimage === preimage;
            const amountValid = paymentData.amount >= this.minimumPaymentSats;
            
            // Проверка возраста платежа (не старше 24 часов)
            const paymentTimestamp = paymentData.timestamp || paymentData.time || 0;
            const paymentAge = now - (paymentTimestamp * 1000); // LNbits timestamp в секундах
            const maxPaymentAge = 24 * 60 * 60 * 1000; // 24 часа
            
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
    // ОСНОВНАЯ ЛОГИКА ВЕРИФИКАЦИИ ПЛАТЕЖЕЙ
    // ============================================

    // Главный метод верификации платежей
    async verifyPayment(preimage, paymentHash) {
        console.log(`🔐 Starting payment verification...`);
        
        try {
            // Этап 1: Базовые проверки формата
            if (!preimage || !paymentHash) {
                throw new Error('Missing preimage or payment hash');
            }
            
            if (typeof preimage !== 'string' || typeof paymentHash !== 'string') {
                throw new Error('Preimage and payment hash must be strings');
            }
            
            // Этап 2: Специальная обработка demo preimage
            if (this.isDemoPreimage(preimage)) {
                console.log('🎮 Processing demo session verification...');
                
                // Проверяем лимиты demo сессий
                const userFingerprint = this.generateUserFingerprint();
                const demoCheck = this.checkDemoSessionLimits(userFingerprint);
                
                if (!demoCheck.allowed) {
                    return {
                        verified: false,
                        reason: demoCheck.message,
                        stage: 'demo_limits',
                        demoLimited: true,
                        timeUntilNext: demoCheck.timeUntilNext,
                        remaining: demoCheck.remaining
                    };
                }
                
                // Криптографическая проверка demo preimage
                const cryptoValid = await this.verifyCryptographically(preimage, paymentHash);
                if (!cryptoValid) {
                    return { 
                        verified: false, 
                        reason: 'Demo preimage cryptographic verification failed',
                        stage: 'crypto'
                    };
                }
                
                // Регистрируем использование demo сессии
                this.registerDemoSessionUsage(userFingerprint);
                
                console.log('✅ Demo session verified successfully');
                return { 
                    verified: true, 
                    method: 'demo',
                    sessionType: 'demo',
                    isDemo: true,
                    warning: 'Demo session - limited duration (6 minutes)',
                    remaining: demoCheck.remaining - 1
                };
            }
            
            // Этап 3: Криптографическая проверка для обычных preimage (ОБЯЗАТЕЛЬНАЯ)
            const cryptoValid = await this.verifyCryptographically(preimage, paymentHash);
            if (!cryptoValid) {
                return { 
                    verified: false, 
                    reason: 'Cryptographic verification failed',
                    stage: 'crypto'
                };
            }

            console.log('✅ Cryptographic verification passed');

            // Этап 4: Проверка через Lightning Network (если не demo режим)
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
                        
                    case 'lnd':
                        const lndResult = await this.verifyPaymentLND(preimage, paymentHash);
                        return lndResult.verified ? lndResult : { 
                            verified: false, 
                            reason: 'LND verification failed',
                            stage: 'lightning'
                        };
                        
                    case 'cln':
                        const clnResult = await this.verifyPaymentCLN(preimage, paymentHash);
                        return clnResult.verified ? clnResult : { 
                            verified: false, 
                            reason: 'CLN verification failed',
                            stage: 'lightning'
                        };
                        
                    case 'btcpay':
                        const btcpayResult = await this.verifyPaymentBTCPay(preimage, paymentHash);
                        return btcpayResult.verified ? btcpayResult : { 
                            verified: false, 
                            reason: 'BTCPay verification failed',
                            stage: 'lightning'
                        };
                    
                    default:
                        console.warn('Unknown verification method, using crypto-only verification');
                        return { 
                            verified: true, 
                            method: 'crypto-only',
                            warning: 'Lightning verification skipped - unknown method'
                        };
                }
            } else {
                // Demo режим для обычных платежей (только для разработки)
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
    // УПРАВЛЕНИЕ СЕССИЯМИ
    // ============================================

    // Безопасная активация сессии
    async safeActivateSession(sessionType, preimage, paymentHash) {
        try {
            console.log(`🚀 Attempting to activate ${sessionType} session...`);
            
            // Валидация входных данных
            if (!sessionType || !preimage || !paymentHash) {
                return { 
                    success: false, 
                    reason: 'Missing required parameters: sessionType, preimage, or paymentHash' 
                };
            }
            
            // Валидация типа сессии
            try {
                this.validateSessionType(sessionType);
            } catch (error) {
                return { 
                    success: false, 
                    reason: error.message 
                };
            }
            
            // Проверка существующей активной сессии
            if (this.hasActiveSession()) {
                return { 
                    success: false, 
                    reason: 'Active session already exists. Please wait for it to expire or disconnect.' 
                };
            }
            
            // Специальная обработка demo сессий
            if (sessionType === 'demo') {
                if (!this.isDemoPreimage(preimage)) {
                    return {
                        success: false,
                        reason: 'Invalid demo preimage format. Please use the generated demo preimage.'
                    };
                }
                
                // Дополнительная проверка лимитов demo
                const userFingerprint = this.generateUserFingerprint();
                const demoCheck = this.checkDemoSessionLimits(userFingerprint);
                
                if (!demoCheck.allowed) {
                    return {
                        success: false,
                        reason: demoCheck.message,
                        demoLimited: true,
                        timeUntilNext: demoCheck.timeUntilNext,
                        remaining: demoCheck.remaining
                    };
                }
            }
            
            // Верификация платежа
            const verificationResult = await this.verifyPayment(preimage, paymentHash);
            
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
            
            // Активация сессии
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

    // Активация сессии с уникальным ID
    activateSession(sessionType, preimage) {
        // Очищаем предыдущую сессию
        this.cleanup();

        const pricing = this.sessionPrices[sessionType];
        const now = Date.now();
        
        // Для demo сессий ограничиваем время
        let duration;
        if (sessionType === 'demo') {
            duration = this.demoSessionMaxDuration; // 6 минут
        } else {
            duration = pricing.hours * 60 * 60 * 1000; // Обычная длительность
        }
        
        const expiresAt = now + duration;
        
        // Генерируем уникальный ID сессии
        const sessionId = Array.from(crypto.getRandomValues(new Uint8Array(16)))
            .map(b => b.toString(16).padStart(2, '0')).join('');

        this.currentSession = {
            id: sessionId,
            type: sessionType,
            startTime: now,
            expiresAt: expiresAt,
            preimage: preimage, // Сохраняем для возможной проверки
            isDemo: sessionType === 'demo'
        };

        this.startSessionTimer();
        
        const durationMinutes = Math.round(duration / (60 * 1000));
        console.log(`📅 Session ${sessionId.substring(0, 8)}... activated for ${durationMinutes} minutes`);
        
        return this.currentSession;
    }

    // Запуск таймера сессии
    startSessionTimer() {
        if (this.sessionTimer) {
            clearInterval(this.sessionTimer);
        }

        this.sessionTimer = setInterval(() => {
            if (!this.hasActiveSession()) {
                this.expireSession();
            }
        }, 60000); // Проверяем каждую минуту
    }

    // Истечение сессии
    expireSession() {
        if (this.sessionTimer) {
            clearInterval(this.sessionTimer);
            this.sessionTimer = null;
        }
        
        const expiredSession = this.currentSession;
        this.currentSession = null;
        
        if (expiredSession) {
            console.log(`⏰ Session ${expiredSession.id.substring(0, 8)}... expired`);
        }
        
        if (this.onSessionExpired) {
            this.onSessionExpired();
        }
    }

    // Проверка активной сессии
    hasActiveSession() {
        if (!this.currentSession) return false;
        const isActive = Date.now() < this.currentSession.expiresAt;
        
        if (!isActive && this.currentSession) {
            // Сессия истекла, очищаем
            this.currentSession = null;
        }
        
        return isActive;
    }

    // Получение оставшегося времени сессии
    getTimeLeft() {
        if (!this.currentSession) return 0;
        return Math.max(0, this.currentSession.expiresAt - Date.now());
    }

    // Принудительное обновление таймера (для UI)
    forceUpdateTimer() {
        if (this.currentSession) {
            const timeLeft = this.getTimeLeft();
            console.log(`⏱️ Timer updated: ${Math.ceil(timeLeft / 1000)}s left`);
            return timeLeft;
        }
        return 0;
    }

    // ============================================
    // DEMO РЕЖИМ: Пользовательские методы
    // ============================================

    // Создание demo сессии для пользователя
    createDemoSession() {
        const userFingerprint = this.generateUserFingerprint();
        const demoCheck = this.checkDemoSessionLimits(userFingerprint);
        
        if (!demoCheck.allowed) {
            return {
                success: false,
                reason: demoCheck.message,
                timeUntilNext: demoCheck.timeUntilNext,
                remaining: demoCheck.remaining
            };
        }
        
        try {
            const demoPreimage = this.generateSecureDemoPreimage();
            // Для demo сессий paymentHash не используется, но создаем для совместимости
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
                remaining: demoCheck.remaining - 1
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

    // Получение информации о demo лимитах
    getDemoSessionInfo() {
        const userFingerprint = this.generateUserFingerprint();
        const userData = this.demoSessions.get(userFingerprint);
        const now = Date.now();
        
        if (!userData) {
            return {
                available: this.maxDemoSessionsPerUser,
                used: 0,
                total: this.maxDemoSessionsPerUser,
                nextAvailable: 'immediately',
                cooldownMinutes: 0,
                durationMinutes: Math.round(this.demoSessionMaxDuration / (60 * 1000))
            };
        }
        
        // Подсчитываем активные сессии
        const activeSessions = userData.sessions.filter(session => 
            now - session.timestamp < this.demoCooldownPeriod
        );
        
        const available = Math.max(0, this.maxDemoSessionsPerUser - activeSessions.length);
        
        // Рассчитываем кулдаун
        let cooldownMs = 0;
        let nextAvailable = 'immediately';
        
        if (available === 0) {
            // Если лимит исчерпан, показываем время до освобождения слота
            const oldestSession = Math.min(...activeSessions.map(s => s.timestamp));
            cooldownMs = this.demoCooldownPeriod - (now - oldestSession);
            nextAvailable = `${Math.ceil(cooldownMs / (60 * 1000))} minutes`;
        } else if (userData.lastUsed && (now - userData.lastUsed) < this.demoSessionCooldown) {
            // Если есть слоты, но действует кулдаун между сессиями
            cooldownMs = this.demoSessionCooldown - (now - userData.lastUsed);
            nextAvailable = `${Math.ceil(cooldownMs / (60 * 1000))} minutes`;
        }
        
        return {
            available: available,
            used: activeSessions.length,
            total: this.maxDemoSessionsPerUser,
            nextAvailable: nextAvailable,
            cooldownMinutes: Math.ceil(cooldownMs / (60 * 1000)),
            durationMinutes: Math.round(this.demoSessionMaxDuration / (60 * 1000)),
            canUseNow: available > 0 && cooldownMs <= 0
        };
    }

    // ============================================
    // ДОПОЛНИТЕЛЬНЫЕ МЕТОДЫ ВЕРИФИКАЦИИ
    // ============================================

    // Метод верификации через LND (Lightning Network Daemon)
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

    // Метод верификации через CLN (Core Lightning)
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

    // Метод верификации через BTCPay Server
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
    // UTILITY МЕТОДЫ
    // ============================================

    // Создание обычного invoice (не demo)
    createInvoice(sessionType) {
        this.validateSessionType(sessionType);
        const pricing = this.sessionPrices[sessionType];

        // Генерируем криптографически стойкий payment hash
        const randomBytes = crypto.getRandomValues(new Uint8Array(32));
        const timestamp = Date.now();
        const sessionEntropy = crypto.getRandomValues(new Uint8Array(16));
        
        // Комбинируем источники энтропии
        const combinedEntropy = new Uint8Array(48);
        combinedEntropy.set(randomBytes, 0);
        combinedEntropy.set(new Uint8Array(new BigUint64Array([BigInt(timestamp)]).buffer), 32);
        combinedEntropy.set(sessionEntropy, 40);
        
        const paymentHash = Array.from(crypto.getRandomValues(new Uint8Array(32)))
            .map(b => b.toString(16).padStart(2, '0')).join('');

        return {
            amount: pricing.sats,
            memo: `LockBit.chat ${sessionType} session (${pricing.hours}h) - ${timestamp}`,
            sessionType: sessionType,
            timestamp: timestamp,
            paymentHash: paymentHash,
            lightningAddress: this.staticLightningAddress,
            entropy: Array.from(sessionEntropy).map(b => b.toString(16).padStart(2, '0')).join(''),
            expiresAt: timestamp + (this.verificationConfig.invoiceExpiryMinutes * 60 * 1000)
        };
    }

    // Проверка возможности активации сессии
    canActivateSession() {
        return !this.hasActiveSession();
    }

    // Сброс сессии (при ошибках безопасности)
    resetSession() {
        if (this.sessionTimer) {
            clearInterval(this.sessionTimer);
            this.sessionTimer = null;
        }
        
        const resetSession = this.currentSession;
        this.currentSession = null;
        
        if (resetSession) {
            console.log(`🔄 Session ${resetSession.id.substring(0, 8)}... reset due to security issue`);
        }
    }

    // Очистка старых preimage (каждые 24 часа)
    startPreimageCleanup() {
        this.preimageCleanupInterval = setInterval(() => {
            // В продакшене preimage должны храниться в защищенной БД permanently
            // Здесь упрощенная версия для управления памятью
            if (this.usedPreimages.size > 10000) {
                // В реальном приложении нужно удалять только старые preimage
                const oldSize = this.usedPreimages.size;
                this.usedPreimages.clear();
                console.log(`🧹 Cleaned ${oldSize} old preimages for memory management`);
            }
        }, 24 * 60 * 60 * 1000); // 24 часа
    }

    // Полная очистка менеджера
    cleanup() {
        // Очистка таймеров
        if (this.sessionTimer) {
            clearInterval(this.sessionTimer);
            this.sessionTimer = null;
        }
        if (this.preimageCleanupInterval) {
            clearInterval(this.preimageCleanupInterval);
            this.preimageCleanupInterval = null;
        }
        
        // Очистка текущей сессии
        this.currentSession = null;
        
        // В продакшене НЕ очищаем usedPreimages и demoSessions
        // Они должны сохраняться между перезапусками
        
        console.log('🧹 PayPerSessionManager cleaned up');
    }

    // Получение статистики использования
    getUsageStats() {
        const stats = {
            totalDemoUsers: this.demoSessions.size,
            usedPreimages: this.usedPreimages.size,
            currentSession: this.currentSession ? {
                type: this.currentSession.type,
                timeLeft: this.getTimeLeft(),
                isDemo: this.currentSession.isDemo
            } : null,
            config: {
                maxDemoSessions: this.maxDemoSessionsPerUser,
                demoCooldown: this.demoSessionCooldown / (60 * 1000), // в минутах
                demoMaxDuration: this.demoSessionMaxDuration / (60 * 1000) // в минутах
            }
        };
        
        return stats;
    }
}

export { PayPerSessionManager };