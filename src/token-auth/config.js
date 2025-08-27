// ============================================
// TOKEN AUTHENTICATION CONFIGURATION
// ============================================
// Конфигурация модуля токен-авторизации
// Настройки для разных сетей и окружений
// ============================================

export const TOKEN_AUTH_CONFIG = {
    // Основные настройки
    APP_NAME: 'SecureBit',
    APP_VERSION: '4.02.442',
    
    // Настройки Web3
    WEB3: {
        // Поддерживаемые сети
        SUPPORTED_NETWORKS: {
            // Mainnet
            '0x1': {
                name: 'Ethereum Mainnet',
                chainId: '0x1',
                rpcUrl: 'https://mainnet.infura.io/v3/YOUR_INFURA_KEY',
                blockExplorer: 'https://etherscan.io',
                currency: {
                    name: 'Ether',
                    symbol: 'ETH',
                    decimals: 18
                },
                isTestnet: false
            },
            
            // Goerli (тестовая сеть)
            '0x5': {
                name: 'Goerli Testnet',
                chainId: '0x5',
                rpcUrl: 'https://goerli.infura.io/v3/YOUR_INFURA_KEY',
                blockExplorer: 'https://goerli.etherscan.io',
                currency: {
                    name: 'Goerli Ether',
                    symbol: 'ETH',
                    decimals: 18
                },
                isTestnet: true
            },
            
            // Sepolia (тестовая сеть)
            '0xaa36a7': {
                name: 'Sepolia Testnet',
                chainId: '0xaa36a7',
                rpcUrl: 'https://sepolia.infura.io/v3/YOUR_INFURA_KEY',
                blockExplorer: 'https://sepolia.etherscan.io',
                currency: {
                    name: 'Sepolia Ether',
                    symbol: 'ETH',
                    decimals: 18
                },
                isTestnet: true
            }
        },
        
        // Настройки по умолчанию
        DEFAULT_NETWORK: '0x5', // Goerli для тестирования
        AUTO_SWITCH_NETWORK: true,
        REQUEST_PERMISSIONS: ['eth_accounts', 'eth_requestAccounts']
    },
    
    // Настройки смарт-контракта
    CONTRACT: {
        // Адреса контрактов для разных сетей
        ADDRESSES: {
            '0x1': '0x0000000000000000000000000000000000000000', // Заменить на реальный адрес
            '0x5': '0x0000000000000000000000000000000000000000', // Заменить на реальный адрес
            '0xaa36a7': '0x0000000000000000000000000000000000000000' // Заменить на реальный адрес
        },
        
        // Настройки токенов
        TOKENS: {
            MONTHLY: {
                name: 'Monthly Access Token',
                symbol: 'SBAT-M',
                duration: 30 * 24 * 60 * 60 * 1000, // 30 дней в миллисекундах
                price: {
                    wei: '10000000000000000', // 0.01 ETH
                    eth: 0.01
                },
                features: ['Basic access', '30 days validity', 'Renewable']
            },
            
            YEARLY: {
                name: 'Yearly Access Token',
                symbol: 'SBAT-Y',
                duration: 365 * 24 * 60 * 60 * 1000, // 365 дней в миллисекундах
                price: {
                    wei: '100000000000000000', // 0.1 ETH
                    eth: 0.1
                },
                features: ['Premium access', '365 days validity', 'Renewable', '17% discount']
            }
        },
        
        // Настройки газа
        GAS: {
            ESTIMATE_MARGIN: 1.2, // 20% запас для газа
            MAX_GAS_LIMIT: 500000,
            DEFAULT_GAS_PRICE: '20000000000' // 20 Gwei
        }
    },
    
    // Настройки сессий
    SESSION: {
        // Таймауты
        TIMEOUTS: {
            SESSION_EXPIRY: 30 * 60 * 1000, // 30 минут
            HEARTBEAT_INTERVAL: 5 * 60 * 1000, // 5 минут
            TOKEN_CHECK_INTERVAL: 60 * 1000, // 1 минута
            WARNING_BEFORE_EXPIRY: 24 * 60 * 60 * 1000 // 1 день
        },
        
        // Настройки безопасности
        SECURITY: {
            MAX_SESSIONS_PER_TOKEN: 1,
            AUTO_LOGOUT_ON_EXPIRY: true,
            CLEAR_SESSION_ON_WALLET_CHANGE: true,
            VALIDATE_SIGNATURE: true
        },
        
        // Настройки хранения
        STORAGE: {
            SESSION_KEY: 'securebit_token_session',
            WALLET_KEY: 'securebit_wallet_address',
            SETTINGS_KEY: 'securebit_token_settings'
        }
    },
    
    // Настройки UI
    UI: {
        // Темизация
        THEME: {
            PRIMARY_COLOR: '#ff6b35',
            SUCCESS_COLOR: '#10b981',
            WARNING_COLOR: '#f59e0b',
            ERROR_COLOR: '#ef4444',
            INFO_COLOR: '#3b82f6'
        },
        
        // Анимации
        ANIMATIONS: {
            MODAL_OPEN_DURATION: 300,
            TOAST_DURATION: 5000,
            LOADING_SPINNER_DURATION: 1000
        },
        
        // Уведомления
        NOTIFICATIONS: {
            ENABLE_BROWSER_NOTIFICATIONS: true,
            ENABLE_TOAST_NOTIFICATIONS: true,
            ENABLE_SOUND_NOTIFICATIONS: false,
            SHOW_EXPIRY_WARNINGS: true
        }
    },
    
    // Настройки логирования
    LOGGING: {
        LEVEL: 'info', // debug, info, warn, error
        ENABLE_CONSOLE: true,
        ENABLE_REMOTE: false,
        REMOTE_ENDPOINT: 'https://logs.securebit.chat/api/logs',
        
        // Фильтры
        FILTERS: {
            INCLUDE_WEB3_EVENTS: true,
            INCLUDE_CONTRACT_CALLS: true,
            INCLUDE_USER_ACTIONS: true,
            INCLUDE_ERRORS: true
        }
    },
    
    // Настройки тестирования
    TESTING: {
        ENABLE_MOCK_MODE: false,
        MOCK_TOKEN_VALIDATION: true,
        MOCK_PURCHASE: false,
        MOCK_NETWORK_DELAY: 1000
    },
    
    // Настройки производительности
    PERFORMANCE: {
        // Кэширование
        CACHE: {
            ENABLE_TOKEN_CACHE: true,
            TOKEN_CACHE_TTL: 5 * 60 * 1000, // 5 минут
            PRICE_CACHE_TTL: 60 * 1000, // 1 минута
            STATS_CACHE_TTL: 10 * 60 * 1000 // 10 минут
        },
        
        // Оптимизации
        OPTIMIZATIONS: {
            LAZY_LOAD_COMPONENTS: true,
            DEBOUNCE_INPUT_CHANGES: 300,
            THROTTLE_API_CALLS: 1000,
            BATCH_UPDATE_UI: true
        }
    },
    
    // Настройки интеграции
    INTEGRATION: {
        // WebRTC интеграция
        WEBRTC: {
            ENABLE_SESSION_SYNC: true,
            SESSION_SYNC_INTERVAL: 30 * 1000, // 30 секунд
            AUTO_TERMINATE_OTHER_SESSIONS: true
        },
        
        // PWA интеграция
        PWA: {
            ENABLE_OFFLINE_MODE: false,
            CACHE_TOKEN_DATA: true,
            SYNC_ON_RECONNECT: true
        }
    }
};

// Функции для работы с конфигурацией
export const ConfigUtils = {
    // Получение конфигурации для конкретной сети
    getNetworkConfig(chainId) {
        return TOKEN_AUTH_CONFIG.WEB3.SUPPORTED_NETWORKS[chainId] || null;
    },
    
    // Получение адреса контракта для сети
    getContractAddress(chainId) {
        return TOKEN_AUTH_CONFIG.CONTRACT.ADDRESSES[chainId] || null;
    },
    
    // Получение конфигурации токена
    getTokenConfig(tokenType) {
        return TOKEN_AUTH_CONFIG.CONTRACT.TOKENS[tokenType.toUpperCase()] || null;
    },
    
    // Проверка поддержки сети
    isNetworkSupported(chainId) {
        return TOKEN_AUTH_CONFIG.WEB3.SUPPORTED_NETWORKS.hasOwnProperty(chainId);
    },
    
    // Получение сети по умолчанию
    getDefaultNetwork() {
        return TOKEN_AUTH_CONFIG.WEB3.DEFAULT_NETWORK;
    },
    
    // Получение всех поддерживаемых сетей
    getSupportedNetworks() {
        return Object.keys(TOKEN_AUTH_CONFIG.WEB3.SUPPORTED_NETWORKS);
    },
    
    // Получение настроек сессии
    getSessionConfig() {
        return TOKEN_AUTH_CONFIG.SESSION;
    },
    
    // Получение настроек UI
    getUIConfig() {
        return TOKEN_AUTH_CONFIG.UI;
    },
    
    // Проверка режима тестирования
    isTestMode() {
        return TOKEN_AUTH_CONFIG.TESTING.ENABLE_MOCK_MODE;
    },
    
    // Получение настроек логирования
    getLoggingConfig() {
        return TOKEN_AUTH_CONFIG.LOGGING;
    }
};

// Экспорт конфигурации по умолчанию
export default TOKEN_AUTH_CONFIG;
