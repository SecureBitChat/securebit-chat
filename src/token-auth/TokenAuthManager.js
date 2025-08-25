// ============================================
// TOKEN AUTHENTICATION MANAGER
// ============================================
// Система авторизации через ERC-20/ERC-721 токены
// Поддерживает MetaMask и другие Web3 кошельки
// ============================================

class TokenAuthManager {
    constructor() {
        this.currentSession = null;
        this.walletAddress = null;
        this.tokenContract = null;
        this.isInitialized = false;
        this.sessionTimeout = null;
        this.heartbeatInterval = null;
        
        // Константы
        this.TOKEN_TYPES = {
            MONTHLY: 'monthly',
            YEARLY: 'yearly'
        };
        
        this.SESSION_TIMEOUT = 30 * 60 * 1000; // 30 минут
        this.HEARTBEAT_INTERVAL = 5 * 60 * 1000; // 5 минут
        
        // События
        this.events = {
            onLogin: null,
            onLogout: null,
            onTokenExpired: null,
            onSessionExpired: null,
            onWalletConnected: null,
            onWalletDisconnected: null
        };
        
        this.initialize();
    }
    
    // Инициализация системы
    async initialize() {
        try {
            // Проверяем поддержку Web3
            if (typeof window.ethereum !== 'undefined') {
                console.log('✅ Web3 detected');
                await this.setupWeb3();
            } else {
                console.warn('⚠️ Web3 not detected, MetaMask required');
                this.showWeb3RequiredMessage();
            }
            
            // Проверяем существующие сессии
            await this.checkExistingSession();
            
            this.isInitialized = true;
            console.log('✅ TokenAuthManager initialized');
            
        } catch (error) {
            console.error('❌ TokenAuthManager initialization failed:', error);
            throw error;
        }
    }
    
    // Настройка Web3 соединения
    async setupWeb3() {
        try {
            // Запрашиваем доступ к аккаунтам
            const accounts = await window.ethereum.request({ 
                method: 'eth_requestAccounts' 
            });
            
            if (accounts.length > 0) {
                this.walletAddress = accounts[0];
                console.log('🔗 Wallet connected:', this.walletAddress);
                
                // Подписываемся на изменения аккаунтов
                window.ethereum.on('accountsChanged', (accounts) => {
                    this.handleAccountChange(accounts);
                });
                
                // Подписываемся на изменения сети
                window.ethereum.on('chainChanged', (chainId) => {
                    this.handleChainChange(chainId);
                });
                
                this.triggerEvent('onWalletConnected', this.walletAddress);
                
            } else {
                throw new Error('No accounts found');
            }
            
        } catch (error) {
            console.error('❌ Web3 setup failed:', error);
            throw error;
        }
    }
    
    // Проверка существующей сессии
    async checkExistingSession() {
        try {
            const sessionData = localStorage.getItem('securebit_token_session');
            if (sessionData) {
                const session = JSON.parse(sessionData);
                
                // Проверяем валидность сессии
                if (this.isSessionValid(session)) {
                    this.currentSession = session;
                    console.log('✅ Existing session restored');
                    
                    // Запускаем мониторинг сессии
                    this.startSessionMonitoring();
                    
                    return true;
                } else {
                    // Удаляем невалидную сессию
                    localStorage.removeItem('securebit_token_session');
                    console.log('🗑️ Invalid session removed');
                }
            }
            
            return false;
            
        } catch (error) {
            console.error('❌ Session check failed:', error);
            return false;
        }
    }
    
    // Проверка валидности сессии
    isSessionValid(session) {
        if (!session || !session.tokenId || !session.expiresAt) {
            return false;
        }
        
        const now = Date.now();
        const expiresAt = new Date(session.expiresAt).getTime();
        
        return now < expiresAt;
    }
    
    // Авторизация через токен
    async authenticateWithToken(tokenId, tokenType) {
        try {
            if (!this.walletAddress) {
                throw new Error('Wallet not connected');
            }
            
            console.log('🔐 Authenticating with token:', { tokenId, tokenType, wallet: this.walletAddress });
            
            // Проверяем токен в смарт-контракте
            const tokenValid = await this.validateTokenInContract(tokenId, tokenType);
            
            if (!tokenValid) {
                throw new Error('Invalid or expired token');
            }
            
            // Создаем новую сессию
            const session = await this.createSession(tokenId, tokenType);
            
            // Завершаем старые сессии на других устройствах
            await this.terminateOtherSessions(tokenId);
            
            // Сохраняем сессию
            this.currentSession = session;
            localStorage.setItem('securebit_token_session', JSON.stringify(session));
            
            // Запускаем мониторинг
            this.startSessionMonitoring();
            
            console.log('✅ Authentication successful');
            this.triggerEvent('onLogin', session);
            
            return session;
            
        } catch (error) {
            console.error('❌ Authentication failed:', error);
            throw error;
        }
    }
    
    // Проверка токена в смарт-контракте
    async validateTokenInContract(tokenId, tokenType) {
        try {
            // Здесь будет логика проверки токена через Web3
            // Пока используем заглушку для тестирования
            console.log('🔍 Validating token in contract:', { tokenId, tokenType });
            
            // Имитация проверки токена
            const isValid = await this.mockTokenValidation(tokenId, tokenType);
            
            return isValid;
            
        } catch (error) {
            console.error('❌ Token validation failed:', error);
            return false;
        }
    }
    
    // Заглушка для тестирования валидации токена
    async mockTokenValidation(tokenId, tokenType) {
        // Имитируем задержку сети
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Простая проверка для демонстрации
        const tokenHash = this.hashString(tokenId + tokenType + this.walletAddress);
        const isValid = tokenHash % 10 !== 0; // 90% токенов валидны
        
        console.log('🔍 Mock token validation result:', { tokenId, tokenType, isValid });
        
        return isValid;
    }
    
    // Создание новой сессии
    async createSession(tokenId, tokenType) {
        const now = Date.now();
        const expiresAt = this.calculateTokenExpiry(tokenType);
        
        const session = {
            id: this.generateSessionId(),
            tokenId: tokenId,
            tokenType: tokenType,
            walletAddress: this.walletAddress,
            createdAt: now,
            expiresAt: expiresAt,
            lastActivity: now,
            signature: await this.signSessionData(tokenId, tokenType)
        };
        
        console.log('📝 Session created:', session);
        return session;
    }
    
    // Расчет времени истечения токена
    calculateTokenExpiry(tokenType) {
        const now = Date.now();
        
        switch (tokenType) {
            case this.TOKEN_TYPES.MONTHLY:
                return now + (30 * 24 * 60 * 60 * 1000); // 30 дней
            case this.TOKEN_TYPES.YEARLY:
                return now + (365 * 24 * 60 * 60 * 1000); // 365 дней
            default:
                throw new Error('Invalid token type');
        }
    }
    
    // Генерация ID сессии
    generateSessionId() {
        return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }
    
    // Подпись данных сессии
    async signSessionData(tokenId, tokenType) {
        try {
            const message = `SecureBit Token Auth\nToken: ${tokenId}\nType: ${tokenType}\nWallet: ${this.walletAddress}\nTimestamp: ${Date.now()}`;
            
            const signature = await window.ethereum.request({
                method: 'personal_sign',
                params: [message, this.walletAddress]
            });
            
            return signature;
            
        } catch (error) {
            console.error('❌ Session signing failed:', error);
            throw error;
        }
    }
    
    // Завершение сессий на других устройствах
    async terminateOtherSessions(tokenId) {
        try {
            // Отправляем сигнал о завершении через WebRTC или WebSocket
            // Пока используем заглушку
            console.log('🔄 Terminating other sessions for token:', tokenId);
            
            // Здесь будет логика уведомления других устройств
            // о необходимости завершения сессии
            
        } catch (error) {
            console.error('❌ Session termination failed:', error);
        }
    }
    
    // Запуск мониторинга сессии
    startSessionMonitoring() {
        if (this.sessionTimeout) {
            clearTimeout(this.sessionTimeout);
        }
        
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
        }
        
        // Таймер истечения сессии
        const timeUntilExpiry = this.currentSession.expiresAt - Date.now();
        this.sessionTimeout = setTimeout(() => {
            this.handleSessionExpired();
        }, timeUntilExpiry);
        
        // Периодическая проверка активности
        this.heartbeatInterval = setInterval(() => {
            this.updateSessionActivity();
        }, this.HEARTBEAT_INTERVAL);
        
        console.log('⏰ Session monitoring started');
    }
    
    // Обработка истечения сессии
    handleSessionExpired() {
        console.log('⏰ Session expired');
        
        this.currentSession = null;
        localStorage.removeItem('securebit_token_session');
        
        this.triggerEvent('onSessionExpired');
        this.triggerEvent('onLogout');
        
        // Показываем уведомление пользователю
        this.showSessionExpiredMessage();
    }
    
    // Обновление активности сессии
    updateSessionActivity() {
        if (this.currentSession) {
            this.currentSession.lastActivity = Date.now();
            localStorage.setItem('securebit_token_session', JSON.stringify(this.currentSession));
        }
    }
    
    // Выход из системы
    async logout() {
        try {
            console.log('🚪 Logging out');
            
            if (this.currentSession) {
                // Завершаем сессию
                await this.terminateOtherSessions(this.currentSession.tokenId);
                
                this.currentSession = null;
                localStorage.removeItem('securebit_token_session');
            }
            
            // Очищаем таймеры
            if (this.sessionTimeout) {
                clearTimeout(this.sessionTimeout);
                this.sessionTimeout = null;
            }
            
            if (this.heartbeatInterval) {
                clearInterval(this.heartbeatInterval);
                this.heartbeatInterval = null;
            }
            
            this.triggerEvent('onLogout');
            console.log('✅ Logout successful');
            
        } catch (error) {
            console.error('❌ Logout failed:', error);
        }
    }
    
    // Обработка смены аккаунта
    async handleAccountChange(accounts) {
        console.log('🔄 Account changed:', accounts);
        
        if (accounts.length === 0) {
            // Пользователь отключил кошелек
            await this.logout();
            this.walletAddress = null;
            this.triggerEvent('onWalletDisconnected');
        } else {
            // Пользователь сменил аккаунт
            const newAddress = accounts[0];
            if (newAddress !== this.walletAddress) {
                this.walletAddress = newAddress;
                await this.logout(); // Завершаем старую сессию
                this.triggerEvent('onWalletConnected', newAddress);
            }
        }
    }
    
    // Обработка смены сети
    async handleChainChange(chainId) {
        console.log('🔄 Chain changed:', chainId);
        
        // Проверяем, поддерживается ли новая сеть
        const supportedChains = ['0x1', '0x3', '0x5']; // Mainnet, Ropsten, Goerli
        
        if (!supportedChains.includes(chainId)) {
            console.warn('⚠️ Unsupported network:', chainId);
            // Показываем предупреждение пользователю
            this.showUnsupportedNetworkMessage(chainId);
        }
    }
    
    // Проверка статуса авторизации
    isAuthenticated() {
        return this.currentSession !== null && this.isSessionValid(this.currentSession);
    }
    
    // Получение текущей сессии
    getCurrentSession() {
        return this.currentSession;
    }
    
    // Получение информации о токене
    getTokenInfo() {
        if (!this.currentSession) {
            return null;
        }
        
        const now = Date.now();
        const expiresAt = this.currentSession.expiresAt;
        const timeLeft = expiresAt - now;
        
        return {
            tokenId: this.currentSession.tokenId,
            tokenType: this.currentSession.tokenType,
            expiresAt: expiresAt,
            timeLeft: timeLeft,
            isExpired: timeLeft <= 0,
            formattedTimeLeft: this.formatTimeLeft(timeLeft)
        };
    }
    
    // Форматирование оставшегося времени
    formatTimeLeft(timeLeft) {
        if (timeLeft <= 0) {
            return 'Expired';
        }
        
        const days = Math.floor(timeLeft / (24 * 60 * 60 * 1000));
        const hours = Math.floor((timeLeft % (24 * 60 * 60 * 1000)) / (60 * 60 * 1000));
        const minutes = Math.floor((timeLeft % (60 * 60 * 1000)) / (60 * 1000));
        
        if (days > 0) {
            return `${days}d ${hours}h`;
        } else if (hours > 0) {
            return `${hours}h ${minutes}m`;
        } else {
            return `${minutes}m`;
        }
    }
    
    // Установка обработчиков событий
    on(event, callback) {
        if (this.events.hasOwnProperty(event)) {
            this.events[event] = callback;
        }
    }
    
    // Вызов событий
    triggerEvent(event, data) {
        if (this.events[event] && typeof this.events[event] === 'function') {
            this.events[event](data);
        }
    }
    
    // Утилиты
    hashString(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        return Math.abs(hash);
    }
    
    // Показ сообщений пользователю
    showWeb3RequiredMessage() {
        // Показываем сообщение о необходимости Web3
        const message = 'Web3 wallet (MetaMask) required for authentication';
        console.warn('⚠️', message);
        // Здесь можно добавить UI уведомление
    }
    
    showSessionExpiredMessage() {
        const message = 'Your session has expired. Please authenticate again.';
        console.warn('⏰', message);
        // Здесь можно добавить UI уведомление
    }
    
    showUnsupportedNetworkMessage(chainId) {
        const message = `Unsupported network detected: ${chainId}. Please switch to a supported network.`;
        console.warn('⚠️', message);
        // Здесь можно добавить UI уведомление
    }
    
    // Очистка ресурсов
    destroy() {
        if (this.sessionTimeout) {
            clearTimeout(this.sessionTimeout);
        }
        
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
        }
        
        this.currentSession = null;
        this.walletAddress = null;
        this.isInitialized = false;
        
        console.log('🗑️ TokenAuthManager destroyed');
    }
}

export { TokenAuthManager };
