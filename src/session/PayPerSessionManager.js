class PayPerSessionManager {
    constructor(config = {}) {
        this.sessionPrices = {
            free: { sats: 0, hours: 1/60, usd: 0.00 },
            basic: { sats: 500, hours: 1, usd: 0.20 },
            premium: { sats: 1000, hours: 4, usd: 0.40 },
            extended: { sats: 2000, hours: 24, usd: 0.80 }
        };
        this.currentSession = null;
        this.sessionTimer = null;
        this.onSessionExpired = null;
        this.staticLightningAddress = "dullpastry62@walletofsatoshi.com";
        
        // Конфигурация для LNbits (ваши реальные данные)
        this.verificationConfig = {
            method: config.method || 'lnbits',
            apiUrl: config.apiUrl || 'https://demo.lnbits.com',
            apiKey: config.apiKey || '623515641d2e4ebcb1d5992d6d78419c', // Ваш Invoice/read ключ
            walletId: config.walletId || 'bcd00f561c7b46b4a7b118f069e68997',
            // Дополнительные настройки для демо
            isDemo: true,
            demoTimeout: 30000, // 30 секунд для демо
            retryAttempts: 3
        };
    }

    hasActiveSession() {
        if (!this.currentSession) return false;
        return Date.now() < this.currentSession.expiresAt;
    }

    createInvoice(sessionType) {
        const pricing = this.sessionPrices[sessionType];
        if (!pricing) throw new Error('Invalid session type');

        return {
            amount: pricing.sats,
            memo: `LockBit.chat ${sessionType} session (${pricing.hours}h)`,
            sessionType: sessionType,
            timestamp: Date.now(),
            paymentHash: Array.from(crypto.getRandomValues(new Uint8Array(32)))
                .map(b => b.toString(16).padStart(2, '0')).join(''),
            lightningAddress: this.staticLightningAddress
        };
    }

    // Создание реального Lightning инвойса через LNbits
    async createLightningInvoice(sessionType) {
        const pricing = this.sessionPrices[sessionType];
        if (!pricing) throw new Error('Invalid session type');

        try {
            console.log(`Creating ${sessionType} invoice for ${pricing.sats} sats...`);

            // Проверяем доступность API
            const healthCheck = await fetch(`${this.verificationConfig.apiUrl}/api/v1/health`, {
                method: 'GET',
                headers: {
                    'X-Api-Key': this.verificationConfig.apiKey
                }
            });

            if (!healthCheck.ok) {
                throw new Error(`LNbits API недоступен: ${healthCheck.status}`);
            }

            const response = await fetch(`${this.verificationConfig.apiUrl}/api/v1/payments`, {
                method: 'POST',
                headers: {
                    'X-Api-Key': this.verificationConfig.apiKey,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    out: false, // incoming payment
                    amount: pricing.sats,
                    memo: `LockBit.chat ${sessionType} session (${pricing.hours}h)`,
                    unit: 'sat',
                    expiry: this.verificationConfig.isDemo ? 300 : 900 // 5 минут для демо, 15 для продакшена
                })
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error('LNbits API response:', errorText);
                throw new Error(`LNbits API error ${response.status}: ${errorText}`);
            }

            const data = await response.json();
            
            console.log('✅ Lightning invoice created successfully!', data);
            
            return {
                paymentRequest: data.bolt11 || data.payment_request, // BOLT11 invoice для QR кода
                paymentHash: data.payment_hash,
                checkingId: data.checking_id || data.payment_hash, // Для проверки статуса
                amount: data.amount || pricing.sats,
                sessionType: sessionType,
                createdAt: Date.now(),
                expiresAt: Date.now() + (this.verificationConfig.isDemo ? 5 * 60 * 1000 : 15 * 60 * 1000), // 5 минут для демо
                description: data.description || data.memo || `LockBit.chat ${sessionType} session`,
                lnurl: data.lnurl || null,
                memo: data.memo || `LockBit.chat ${sessionType} session`,
                bolt11: data.bolt11 || data.payment_request,
                // Дополнительные поля для совместимости
                payment_request: data.bolt11 || data.payment_request,
                checking_id: data.checking_id || data.payment_hash
            };

        } catch (error) {
            console.error('❌ Error creating Lightning invoice:', error);
            
            // Для демо режима создаем фиктивный инвойс
            if (this.verificationConfig.isDemo && error.message.includes('API')) {
                console.log('🔄 Creating demo invoice for testing...');
                return this.createDemoInvoice(sessionType);
            }
            
            throw error;
        }
    }

    // Создание демо инвойса для тестирования
    createDemoInvoice(sessionType) {
        const pricing = this.sessionPrices[sessionType];
        const demoHash = Array.from(crypto.getRandomValues(new Uint8Array(32)))
            .map(b => b.toString(16).padStart(2, '0')).join('');
        
        return {
            paymentRequest: `lntb${pricing.sats}1p${demoHash}...`, // Фиктивный BOLT11
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
            console.log(`🔍 Checking payment status for: ${checkingId}`);

            const response = await fetch(`${this.verificationConfig.apiUrl}/api/v1/payments/${checkingId}`, {
                method: 'GET',
                headers: {
                    'X-Api-Key': this.verificationConfig.apiKey,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error('Payment status check failed:', errorText);
                throw new Error(`Payment check failed: ${response.status} - ${errorText}`);
            }

            const data = await response.json();
            console.log('📊 Payment status response:', data);
            
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
            console.error('❌ Error checking payment status:', error);
            
            // Для демо режима возвращаем фиктивный статус
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

    // Метод 1: Верификация через LNbits API
    async verifyPaymentLNbits(preimage, paymentHash) {
        try {
            console.log(`🔐 Verifying payment via LNbits: ${paymentHash}`);
            
            if (!this.verificationConfig.apiUrl || !this.verificationConfig.apiKey) {
                throw new Error('LNbits API configuration missing');
            }

            const response = await fetch(`${this.verificationConfig.apiUrl}/api/v1/payments/${paymentHash}`, {
                method: 'GET',
                headers: {
                    'X-Api-Key': this.verificationConfig.apiKey,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error('LNbits verification failed:', errorText);
                throw new Error(`API request failed: ${response.status} - ${errorText}`);
            }

            const paymentData = await response.json();
            console.log('📋 Payment verification data:', paymentData);
            
            // Проверяем статус платежа
            if (paymentData.paid && paymentData.preimage === preimage) {
                console.log('✅ Payment verified successfully via LNbits');
                return {
                    verified: true,
                    amount: paymentData.amount,
                    fee: paymentData.fee || 0,
                    timestamp: paymentData.timestamp || Date.now(),
                    method: 'lnbits'
                };
            }

            console.log('❌ Payment verification failed: paid=', paymentData.paid, 'preimage match=', paymentData.preimage === preimage);
            return {
                verified: false,
                reason: 'Payment not paid or preimage mismatch',
                method: 'lnbits'
            };
            
        } catch (error) {
            console.error('❌ LNbits payment verification failed:', error);
            
            // Для демо режима возвращаем успешную верификацию
            if (this.verificationConfig.isDemo && error.message.includes('API')) {
                console.log('🔄 Demo payment verification successful');
                return {
                    verified: true,
                    amount: 0,
                    fee: 0,
                    timestamp: Date.now(),
                    method: 'demo'
                };
            }
            
            return {
                verified: false,
                reason: error.message,
                method: 'lnbits'
            };
        }
    }

    // Метод 2: Верификация через LND REST API
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
                }
            });

            if (!response.ok) {
                throw new Error(`LND API request failed: ${response.status}`);
            }

            const invoiceData = await response.json();
            
            // Проверяем, что инвойс оплачен и preimage совпадает
            if (invoiceData.settled && invoiceData.r_preimage === preimage) {
                return true;
            }

            return false;
        } catch (error) {
            console.error('LND payment verification failed:', error);
            return false;
        }
    }

    // Метод 3: Верификация через Core Lightning (CLN)
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
                })
            });

            if (!response.ok) {
                throw new Error(`CLN API request failed: ${response.status}`);
            }

            const data = await response.json();
            
            if (data.invoices && data.invoices.length > 0) {
                const invoice = data.invoices[0];
                if (invoice.status === 'paid' && invoice.payment_preimage === preimage) {
                    return true;
                }
            }

            return false;
        } catch (error) {
            console.error('CLN payment verification failed:', error);
            return false;
        }
    }

    // Метод 4: Верификация через Wallet of Satoshi API (если доступен)
    async verifyPaymentWOS(preimage, paymentHash) {
        try {
            // Wallet of Satoshi обычно не предоставляет публичного API
            // Этот метод для примера структуры
            console.warn('Wallet of Satoshi API verification not implemented');
            return false;
        } catch (error) {
            console.error('WOS payment verification failed:', error);
            return false;
        }
    }

    // Метод 5: Верификация через BTCPay Server
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
                }
            });

            if (!response.ok) {
                throw new Error(`BTCPay API request failed: ${response.status}`);
            }

            const invoiceData = await response.json();
            
            if (invoiceData.status === 'Settled' && invoiceData.payment && invoiceData.payment.preimage === preimage) {
                return true;
            }

            return false;
        } catch (error) {
            console.error('BTCPay payment verification failed:', error);
            return false;
        }
    }

    // Криптографическая верификация preimage
    async verifyCryptographically(preimage, paymentHash) {
        try {
            // Преобразуем preimage в байты
            const preimageBytes = new Uint8Array(preimage.match(/.{2}/g).map(byte => parseInt(byte, 16)));
            
            // Вычисляем SHA256 от preimage
            const hashBuffer = await crypto.subtle.digest('SHA-256', preimageBytes);
            const computedHash = Array.from(new Uint8Array(hashBuffer))
                .map(b => b.toString(16).padStart(2, '0')).join('');
            
            // Сравниваем с payment_hash
            return computedHash === paymentHash;
        } catch (error) {
            console.error('Cryptographic verification failed:', error);
            return false;
        }
    }

    // Основной метод верификации платежа
    async verifyPayment(preimage, paymentHash) {
        console.log(`🔐 Verifying payment: preimage=${preimage}, hash=${paymentHash}`);
        
        // Базовые проверки формата
        if (!preimage || preimage.length !== 64) {
            console.log('❌ Invalid preimage length');
            return { verified: false, reason: 'Invalid preimage length' };
        }
        
        if (!/^[0-9a-fA-F]{64}$/.test(preimage)) {
            console.log('❌ Invalid preimage format');
            return { verified: false, reason: 'Invalid preimage format' };
        }
        
        // Для бесплатных сессий
        if (preimage === '0'.repeat(64)) {
            console.log('✅ Free session preimage accepted');
            return { verified: true, method: 'free' };
        }
        
        // Проверяем, что preimage не является заглушкой
        const dummyPreimages = ['1'.repeat(64), 'a'.repeat(64), 'f'.repeat(64)];
        if (dummyPreimages.includes(preimage)) {
            console.log('❌ Dummy preimage detected');
            return { verified: false, reason: 'Dummy preimage detected' };
        }

        try {
            // Сначала проверяем криптографически
            const cryptoValid = await this.verifyCryptographically(preimage, paymentHash);
            if (!cryptoValid) {
                console.log('❌ Cryptographic verification failed');
                return { verified: false, reason: 'Cryptographic verification failed' };
            }

            console.log('✅ Cryptographic verification passed');

            // Затем проверяем через выбранный метод
            switch (this.verificationConfig.method) {
                case 'lnbits':
                    const lnbitsResult = await this.verifyPaymentLNbits(preimage, paymentHash);
                    return lnbitsResult.verified ? lnbitsResult : { verified: false, reason: 'LNbits verification failed' };
                    
                case 'lnd':
                    const lndResult = await this.verifyPaymentLND(preimage, paymentHash);
                    return lndResult ? { verified: true, method: 'lnd' } : { verified: false, reason: 'LND verification failed' };
                    
                case 'cln':
                    const clnResult = await this.verifyPaymentCLN(preimage, paymentHash);
                    return clnResult ? { verified: true, method: 'cln' } : { verified: false, reason: 'CLN verification failed' };
                    
                case 'btcpay':
                    const btcpayResult = await this.verifyPaymentBTCPay(preimage, paymentHash);
                    return btcpayResult ? { verified: true, method: 'btcpay' } : { verified: false, reason: 'BTCPay verification failed' };
                    
                case 'walletofsatoshi':
                    const wosResult = await this.verifyPaymentWOS(preimage, paymentHash);
                    return wosResult ? { verified: true, method: 'wos' } : { verified: false, reason: 'WOS verification failed' };
                    
                default:
                    console.warn('Unknown verification method, using crypto-only verification');
                    return { verified: cryptoValid, method: 'crypto-only' };
            }
        } catch (error) {
            console.error('❌ Payment verification failed:', error);
            return { verified: false, reason: error.message };
        }
    }

    // Остальные методы остаются без изменений...
    activateSession(sessionType, preimage) {
        // Очистка предыдущей сессии
        this.cleanup();

        const pricing = this.sessionPrices[sessionType];
        const now = Date.now();
        const expiresAt = now + (pricing.hours * 60 * 60 * 1000);

        this.currentSession = {
            type: sessionType,
            startTime: now,
            expiresAt: expiresAt,
            preimage: preimage
        };

        this.startSessionTimer();
        return this.currentSession;
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
        }
        
        this.currentSession = null;
        
        if (this.onSessionExpired) {
            this.onSessionExpired();
        }
    }

    getTimeLeft() {
        if (!this.currentSession) return 0;
        return Math.max(0, this.currentSession.expiresAt - Date.now());
    }

    forceUpdateTimer() {
        if (this.currentSession) {
            const timeLeft = this.getTimeLeft();
            console.log('Timer updated:', timeLeft, 'ms left');
            return timeLeft;
        }
        return 0;
    }

    cleanup() {
        if (this.sessionTimer) {
            clearInterval(this.sessionTimer);
        }
        this.currentSession = null;
    }

    resetSession() {
        if (this.sessionTimer) {
            clearInterval(this.sessionTimer);
        }
        this.currentSession = null;
        console.log('Session reset due to failed verification');
    }

    canActivateSession() {
        return !this.hasActiveSession() && !this.currentSession;
    }

    async safeActivateSession(sessionType, preimage, paymentHash) {
        try {
            console.log(`🚀 Activating session: ${sessionType} with preimage: ${preimage}`);
            
            if (!sessionType || !preimage) {
                console.warn('❌ Session activation failed: missing sessionType or preimage');
                return { success: false, reason: 'Missing sessionType or preimage' };
            }
            
            if (!this.sessionPrices[sessionType]) {
                console.warn('❌ Session activation failed: invalid session type');
                return { success: false, reason: 'Invalid session type' };
            }
            
            // Верифицируем платеж
            const verificationResult = await this.verifyPayment(preimage, paymentHash);
            
            if (verificationResult.verified) {
                this.activateSession(sessionType, preimage);
                console.log(`✅ Session activated successfully: ${sessionType} via ${verificationResult.method}`);
                return {
                    success: true,
                    sessionType: sessionType,
                    method: verificationResult.method,
                    details: verificationResult,
                    timeLeft: this.getTimeLeft()
                };
            } else {
                console.log('❌ Payment verification failed:', verificationResult.reason);
                return {
                    success: false,
                    reason: verificationResult.reason,
                    method: verificationResult.method
                };
            }
        } catch (error) {
            console.error('❌ Session activation failed:', error);
            return {
                success: false,
                reason: error.message,
                method: 'error'
            };
        }
    }
}

export { PayPerSessionManager };