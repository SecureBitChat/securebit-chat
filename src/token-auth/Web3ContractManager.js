// ============================================
// WEB3 CONTRACT MANAGER
// ============================================
// Управление смарт-контрактом токенов доступа
// Интеграция с MetaMask и другими Web3 провайдерами
// ============================================

class Web3ContractManager {
    constructor() {
        this.contract = null;
        this.web3 = null;
        this.contractAddress = null;
        this.contractABI = null;
        this.isInitialized = false;
        
        // Адреса контрактов для разных сетей
        this.CONTRACT_ADDRESSES = {
            // Mainnet
            '0x1': '0x0000000000000000000000000000000000000000', // Заменить на реальный адрес
            // Ropsten (тестовая сеть)
            '0x3': '0x0000000000000000000000000000000000000000', // Заменить на реальный адрес
            // Goerli (тестовая сеть)
            '0x5': '0x0000000000000000000000000000000000000000', // Заменить на реальный адрес
            // Sepolia (тестовая сеть)
            '0xaa36a7': '0x0000000000000000000000000000000000000000' // Заменить на реальный адрес
        };
        
        // ABI контракта (упрощенная версия)
        this.CONTRACT_ABI = [
            // События
            {
                "anonymous": false,
                "inputs": [
                    {"indexed": true, "name": "tokenId", "type": "uint256"},
                    {"indexed": true, "name": "owner", "type": "address"},
                    {"indexed": false, "name": "tokenType", "type": "uint8"},
                    {"indexed": false, "name": "expiryDate", "type": "uint256"}
                ],
                "name": "TokenMinted",
                "type": "event"
            },
            {
                "anonymous": false,
                "inputs": [
                    {"indexed": true, "name": "tokenId", "type": "uint256"},
                    {"indexed": true, "name": "owner", "type": "address"}
                ],
                "name": "TokenExpired",
                "type": "event"
            },
            {
                "anonymous": false,
                "inputs": [
                    {"indexed": true, "name": "tokenId", "type": "uint256"},
                    {"indexed": false, "name": "newExpiryDate", "type": "uint256"}
                ],
                "name": "TokenRenewed",
                "type": "event"
            },
            
            // Функции чтения
            {
                "inputs": [{"name": "tokenId", "type": "uint256"}],
                "name": "isTokenValid",
                "outputs": [{"name": "", "type": "bool"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"name": "tokenId", "type": "uint256"}],
                "name": "getTokenInfo",
                "outputs": [
                    {"name": "tokenId", "type": "uint256"},
                    {"name": "owner", "type": "address"},
                    {"name": "expiryDate", "type": "uint256"},
                    {"name": "tokenType", "type": "uint8"},
                    {"name": "isActive", "type": "bool"},
                    {"name": "createdAt", "type": "uint256"},
                    {"name": "metadata", "type": "string"}
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"name": "user", "type": "address"}],
                "name": "getUserTokens",
                "outputs": [{"name": "", "type": "uint256[]"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"name": "user", "type": "address"}],
                "name": "getActiveUserTokens",
                "outputs": [{"name": "", "type": "uint256[]"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"name": "user", "type": "address"}],
                "name": "hasActiveToken",
                "outputs": [{"name": "", "type": "bool"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "monthlyPrice",
                "outputs": [{"name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "yearlyPrice",
                "outputs": [{"name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "getStats",
                "outputs": [
                    {"name": "totalTokens", "type": "uint256"},
                    {"name": "activeTokens", "type": "uint256"},
                    {"name": "monthlyTokens", "type": "uint256"},
                    {"name": "yearlyTokens", "type": "uint256"}
                ],
                "stateMutability": "view",
                "type": "function"
            },
            
            // Функции записи
            {
                "inputs": [],
                "name": "purchaseMonthlyToken",
                "outputs": [],
                "stateMutability": "payable",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "purchaseYearlyToken",
                "outputs": [],
                "stateMutability": "payable",
                "type": "function"
            },
            {
                "inputs": [{"name": "tokenId", "type": "uint256"}],
                "name": "deactivateToken",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"name": "tokenId", "type": "uint256"}],
                "name": "renewToken",
                "outputs": [],
                "stateMutability": "payable",
                "type": "function"
            }
        ];
        
        this.initialize();
    }
    
    // Инициализация Web3 и контракта
    async initialize() {
        try {
            // Проверяем поддержку Web3
            if (typeof window.ethereum !== 'undefined') {
                console.log('✅ Web3 detected');
                
                // Создаем Web3 экземпляр
                this.web3 = new Web3(window.ethereum);
                
                // Получаем текущую сеть
                const chainId = await this.getCurrentChainId();
                console.log('🔗 Current chain ID:', chainId);
                
                // Получаем адрес контракта для текущей сети
                this.contractAddress = this.CONTRACT_ADDRESSES[chainId];
                
                if (!this.contractAddress || this.contractAddress === '0x0000000000000000000000000000000000000000') {
                    console.warn('⚠️ Contract not deployed on current network:', chainId);
                    this.showContractNotDeployedMessage(chainId);
                    return;
                }
                
                // Создаем экземпляр контракта
                this.contract = new this.web3.eth.Contract(
                    this.CONTRACT_ABI,
                    this.contractAddress
                );
                
                console.log('📋 Contract initialized:', this.contractAddress);
                this.isInitialized = true;
                
            } else {
                throw new Error('Web3 not detected');
            }
            
        } catch (error) {
            console.error('❌ Web3ContractManager initialization failed:', error);
            throw error;
        }
    }
    
    // Получение текущего Chain ID
    async getCurrentChainId() {
        try {
            const chainId = await window.ethereum.request({ method: 'eth_chainId' });
            return chainId;
        } catch (error) {
            console.error('❌ Failed to get chain ID:', error);
            throw error;
        }
    }
    
    // Проверка валидности токена
    async isTokenValid(tokenId) {
        try {
            if (!this.isInitialized || !this.contract) {
                throw new Error('Contract not initialized');
            }
            
            const result = await this.contract.methods.isTokenValid(tokenId).call();
            console.log('🔍 Token validation result:', { tokenId, isValid: result });
            
            return result;
            
        } catch (error) {
            console.error('❌ Token validation failed:', error);
            return false;
        }
    }
    
    // Получение информации о токене
    async getTokenInfo(tokenId) {
        try {
            if (!this.isInitialized || !this.contract) {
                throw new Error('Contract not initialized');
            }
            
            const result = await this.contract.methods.getTokenInfo(tokenId).call();
            
            // Преобразуем результат в удобный формат
            const tokenInfo = {
                tokenId: result.tokenId,
                owner: result.owner,
                expiryDate: parseInt(result.expiryDate),
                tokenType: parseInt(result.tokenType),
                isActive: result.isActive,
                createdAt: parseInt(result.createdAt),
                metadata: result.metadata
            };
            
            console.log('📋 Token info retrieved:', tokenInfo);
            return tokenInfo;
            
        } catch (error) {
            console.error('❌ Failed to get token info:', error);
            throw error;
        }
    }
    
    // Получение токенов пользователя
    async getUserTokens(userAddress) {
        try {
            if (!this.isInitialized || !this.contract) {
                throw new Error('Contract not initialized');
            }
            
            const result = await this.contract.methods.getUserTokens(userAddress).call();
            const tokenIds = result.map(id => parseInt(id));
            
            console.log('👤 User tokens retrieved:', { user: userAddress, tokens: tokenIds });
            return tokenIds;
            
        } catch (error) {
            console.error('❌ Failed to get user tokens:', error);
            throw error;
        }
    }
    
    // Получение активных токенов пользователя
    async getActiveUserTokens(userAddress) {
        try {
            if (!this.isInitialized || !this.contract) {
                throw new Error('Contract not initialized');
            }
            
            const result = await this.contract.methods.getActiveUserTokens(userAddress).call();
            const tokenIds = result.map(id => parseInt(id));
            
            console.log('✅ Active user tokens retrieved:', { user: userAddress, activeTokens: tokenIds });
            return tokenIds;
            
        } catch (error) {
            console.error('❌ Failed to get active user tokens:', error);
            throw error;
        }
    }
    
    // Проверка наличия активного токена у пользователя
    async hasActiveToken(userAddress) {
        try {
            if (!this.isInitialized || !this.contract) {
                throw new Error('Contract not initialized');
            }
            
            const result = await this.contract.methods.hasActiveToken(userAddress).call();
            console.log('🔍 Active token check:', { user: userAddress, hasActive: result });
            
            return result;
            
        } catch (error) {
            console.error('❌ Failed to check active token:', error);
            return false;
        }
    }
    
    // Получение цен токенов
    async getTokenPrices() {
        try {
            if (!this.isInitialized || !this.contract) {
                throw new Error('Contract not initialized');
            }
            
            const [monthlyPrice, yearlyPrice] = await Promise.all([
                this.contract.methods.monthlyPrice().call(),
                this.contract.methods.yearlyPrice().call()
            ]);
            
            const prices = {
                monthly: this.web3.utils.fromWei(monthlyPrice, 'ether'),
                yearly: this.web3.utils.fromWei(yearlyPrice, 'ether'),
                monthlyWei: monthlyPrice,
                yearlyWei: yearlyPrice
            };
            
            console.log('💰 Token prices retrieved:', prices);
            return prices;
            
        } catch (error) {
            console.error('❌ Failed to get token prices:', error);
            throw error;
        }
    }
    
    // Получение статистики контракта
    async getContractStats() {
        try {
            if (!this.isInitialized || !this.contract) {
                throw new Error('Contract not initialized');
            }
            
            const result = await this.contract.methods.getStats().call();
            
            const stats = {
                totalTokens: parseInt(result.totalTokens),
                activeTokens: parseInt(result.activeTokens),
                monthlyTokens: parseInt(result.monthlyTokens),
                yearlyTokens: parseInt(result.yearlyTokens)
            };
            
            console.log('📊 Contract stats retrieved:', stats);
            return stats;
            
        } catch (error) {
            console.error('❌ Failed to get contract stats:', error);
            throw error;
        }
    }
    
    // Покупка месячного токена
    async purchaseMonthlyToken(price) {
        try {
            if (!this.isInitialized || !this.contract) {
                throw new Error('Contract not initialized');
            }
            
            const accounts = await this.web3.eth.getAccounts();
            const userAddress = accounts[0];
            
            console.log('🛒 Purchasing monthly token:', { user: userAddress, price: price });
            
            const result = await this.contract.methods.purchaseMonthlyToken().send({
                from: userAddress,
                value: price
            });
            
            console.log('✅ Monthly token purchased:', result);
            return result;
            
        } catch (error) {
            console.error('❌ Monthly token purchase failed:', error);
            throw error;
        }
    }
    
    // Покупка годового токена
    async purchaseYearlyToken(price) {
        try {
            if (!this.isInitialized || !this.contract) {
                throw new Error('Contract not initialized');
            }
            
            const accounts = await this.web3.eth.getAccounts();
            const userAddress = accounts[0];
            
            console.log('🛒 Purchasing yearly token:', { user: userAddress, price: price });
            
            const result = await this.contract.methods.purchaseYearlyToken().send({
                from: userAddress,
                value: price
            });
            
            console.log('✅ Yearly token purchased:', result);
            return result;
            
        } catch (error) {
            console.error('❌ Yearly token purchase failed:', error);
            throw error;
        }
    }
    
    // Деактивация токена
    async deactivateToken(tokenId) {
        try {
            if (!this.isInitialized || !this.contract) {
                throw new Error('Contract not initialized');
            }
            
            const accounts = await this.web3.eth.getAccounts();
            const userAddress = accounts[0];
            
            console.log('🚫 Deactivating token:', { tokenId, user: userAddress });
            
            const result = await this.contract.methods.deactivateToken(tokenId).send({
                from: userAddress
            });
            
            console.log('✅ Token deactivated:', result);
            return result;
            
        } catch (error) {
            console.error('❌ Token deactivation failed:', error);
            throw error;
        }
    }
    
    // Продление токена
    async renewToken(tokenId, price) {
        try {
            if (!this.isInitialized || !this.contract) {
                throw new Error('Contract not initialized');
            }
            
            const accounts = await this.web3.eth.getAccounts();
            const userAddress = accounts[0];
            
            console.log('🔄 Renewing token:', { tokenId, user: userAddress, price: price });
            
            const result = await this.contract.methods.renewToken(tokenId).send({
                from: userAddress,
                value: price
            });
            
            console.log('✅ Token renewed:', result);
            return result;
            
        } catch (error) {
            console.error('❌ Token renewal failed:', error);
            throw error;
        }
    }
    
    // Получение событий о создании токенов
    async getTokenMintedEvents(fromBlock = 0, toBlock = 'latest') {
        try {
            if (!this.isInitialized || !this.contract) {
                throw new Error('Contract not initialized');
            }
            
            const events = await this.contract.getPastEvents('TokenMinted', {
                fromBlock: fromBlock,
                toBlock: toBlock
            });
            
            console.log('📝 Token minted events retrieved:', events.length);
            return events;
            
        } catch (error) {
            console.error('❌ Failed to get token minted events:', error);
            throw error;
        }
    }
    
    // Получение событий о продлении токенов
    async getTokenRenewedEvents(fromBlock = 0, toBlock = 'latest') {
        try {
            if (!this.isInitialized || !this.contract) {
                throw new Error('Contract not initialized');
            }
            
            const events = await this.contract.getPastEvents('TokenRenewed', {
                fromBlock: fromBlock,
                toBlock: toBlock
            });
            
            console.log('🔄 Token renewed events retrieved:', events.length);
            return events;
            
        } catch (error) {
            console.error('❌ Failed to get token renewed events:', error);
            throw error;
        }
    }
    
    // Проверка поддержки сети
    isNetworkSupported(chainId) {
        return this.CONTRACT_ADDRESSES.hasOwnProperty(chainId);
    }
    
    // Получение поддерживаемых сетей
    getSupportedNetworks() {
        return Object.keys(this.CONTRACT_ADDRESSES).map(chainId => ({
            chainId: chainId,
            name: this.getNetworkName(chainId),
            contractAddress: this.CONTRACT_ADDRESSES[chainId]
        }));
    }
    
    // Получение названия сети
    getNetworkName(chainId) {
        const networkNames = {
            '0x1': 'Ethereum Mainnet',
            '0x3': 'Ropsten Testnet',
            '0x5': 'Goerli Testnet',
            '0xaa36a7': 'Sepolia Testnet'
        };
        
        return networkNames[chainId] || 'Unknown Network';
    }
    
    // Переключение на поддерживаемую сеть
    async switchToNetwork(chainId) {
        try {
            if (!this.isNetworkSupported(chainId)) {
                throw new Error(`Network ${chainId} is not supported`);
            }
            
            await window.ethereum.request({
                method: 'wallet_switchEthereumChain',
                params: [{ chainId: chainId }]
            });
            
            console.log('🔄 Switched to network:', chainId);
            
        } catch (error) {
            console.error('❌ Failed to switch network:', error);
            throw error;
        }
    }
    
    // Добавление новой сети
    async addNetwork(chainId, networkName, rpcUrl, blockExplorerUrl) {
        try {
            await window.ethereum.request({
                method: 'wallet_addEthereumChain',
                params: [{
                    chainId: chainId,
                    chainName: networkName,
                    rpcUrls: [rpcUrl],
                    blockExplorerUrls: [blockExplorerUrl],
                    nativeCurrency: {
                        name: 'Ether',
                        symbol: 'ETH',
                        decimals: 18
                    }
                }]
            });
            
            console.log('➕ Network added:', { chainId, name: networkName });
            
        } catch (error) {
            console.error('❌ Failed to add network:', error);
            throw error;
        }
    }
    
    // Показ сообщений пользователю
    showContractNotDeployedMessage(chainId) {
        const message = `Smart contract not deployed on network ${chainId}. Please switch to a supported network or deploy the contract.`;
        console.warn('⚠️', message);
        // Здесь можно добавить UI уведомление
    }
    
    // Получение статуса инициализации
    getInitializationStatus() {
        return {
            isInitialized: this.isInitialized,
            web3: !!this.web3,
            contract: !!this.contract,
            contractAddress: this.contractAddress,
            currentChainId: this.web3 ? this.web3.currentProvider.chainId : null
        };
    }
    
    // Очистка ресурсов
    destroy() {
        this.contract = null;
        this.web3 = null;
        this.contractAddress = null;
        this.isInitialized = false;
        
        console.log('🗑️ Web3ContractManager destroyed');
    }
}

export { Web3ContractManager };
