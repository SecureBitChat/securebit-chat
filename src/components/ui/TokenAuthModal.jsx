// ============================================
// TOKEN AUTHENTICATION MODAL
// ============================================
// Модальное окно для авторизации через Web3 токены
// Поддерживает покупку, проверку и управление токенами
// ============================================

const TokenAuthModal = ({ 
    isOpen, 
    onClose, 
    onAuthenticated,
    tokenAuthManager,
    web3ContractManager 
}) => {
    const [currentStep, setCurrentStep] = React.useState('connect'); // connect, purchase, authenticate, success
    const [walletAddress, setWalletAddress] = React.useState('');
    const [isConnecting, setIsConnecting] = React.useState(false);
    const [isPurchasing, setIsPurchasing] = React.useState(false);
    const [isAuthenticating, setIsAuthenticating] = React.useState(false);
    const [selectedTokenType, setSelectedTokenType] = React.useState('monthly');
    const [tokenPrices, setTokenPrices] = React.useState(null);
    const [userTokens, setUserTokens] = React.useState([]);
    const [activeToken, setActiveToken] = React.useState(null);
    const [error, setError] = React.useState('');
    const [success, setSuccess] = React.useState('');
    
    // Состояния для разных шагов
    const [purchaseAmount, setPurchaseAmount] = React.useState('');
    const [tokenId, setTokenId] = React.useState('');
    
    React.useEffect(() => {
        if (isOpen) {
            initializeModal();
        }
    }, [isOpen]);
    
    // Инициализация модального окна
    const initializeModal = async () => {
        try {
            setCurrentStep('connect');
            setError('');
            setSuccess('');
            
            // Проверяем статус кошелька
            if (tokenAuthManager && tokenAuthManager.walletAddress) {
                setWalletAddress(tokenAuthManager.walletAddress);
                await checkUserTokens();
                setCurrentStep('authenticate');
            }
            
        } catch (error) {
            console.error('Modal initialization failed:', error);
            setError('Failed to initialize authentication');
        }
    };
    
    // Подключение кошелька
    const connectWallet = async () => {
        try {
            setIsConnecting(true);
            setError('');
            
            if (!tokenAuthManager) {
                throw new Error('Token auth manager not available');
            }
            
            // Инициализируем Web3
            await tokenAuthManager.initialize();
            
            if (tokenAuthManager.walletAddress) {
                setWalletAddress(tokenAuthManager.walletAddress);
                await checkUserTokens();
                setCurrentStep('authenticate');
            } else {
                throw new Error('Failed to connect wallet');
            }
            
        } catch (error) {
            console.error('Wallet connection failed:', error);
            setError(error.message || 'Failed to connect wallet');
        } finally {
            setIsConnecting(false);
        }
    };
    
    // Проверка токенов пользователя
    const checkUserTokens = async () => {
        try {
            if (!web3ContractManager || !walletAddress) return;
            
            // Получаем активные токены пользователя
            const activeTokens = await web3ContractManager.getActiveUserTokens(walletAddress);
            
            if (activeTokens.length > 0) {
                // Получаем информацию о первом активном токене
                const tokenInfo = await web3ContractManager.getTokenInfo(activeTokens[0]);
                setActiveToken(tokenInfo);
                setUserTokens(activeTokens);
            }
            
        } catch (error) {
            console.error('Failed to check user tokens:', error);
        }
    };
    
    // Получение цен токенов
    const loadTokenPrices = async () => {
        try {
            if (!web3ContractManager) return;
            
            const prices = await web3ContractManager.getTokenPrices();
            setTokenPrices(prices);
            
        } catch (error) {
            console.error('Failed to load token prices:', error);
        }
    };
    
    // Покупка токена
    const purchaseToken = async () => {
        try {
            setIsPurchasing(true);
            setError('');
            
            if (!web3ContractManager || !walletAddress) {
                throw new Error('Web3 contract manager not available');
            }
            
            let result;
            if (selectedTokenType === 'monthly') {
                result = await web3ContractManager.purchaseMonthlyToken(tokenPrices.monthlyWei);
            } else {
                result = await web3ContractManager.purchaseYearlyToken(tokenPrices.yearlyWei);
            }
            
            // Получаем ID токена из события
            const tokenId = result.events.TokenMinted.returnValues.tokenId;
            setTokenId(tokenId);
            
            setSuccess(`Token purchased successfully! Token ID: ${tokenId}`);
            setCurrentStep('authenticate');
            
            // Обновляем список токенов
            await checkUserTokens();
            
        } catch (error) {
            console.error('Token purchase failed:', error);
            setError(error.message || 'Failed to purchase token');
        } finally {
            setIsPurchasing(false);
        }
    };
    
    // Авторизация через токен
    const authenticateWithToken = async (tokenId) => {
        try {
            setIsAuthenticating(true);
            setError('');
            
            if (!tokenAuthManager) {
                throw new Error('Token auth manager not available');
            }
            
            // Определяем тип токена
            let tokenType = 'monthly';
            if (activeToken) {
                tokenType = activeToken.tokenType === 0 ? 'monthly' : 'yearly';
            }
            
            // Авторизуемся через токен
            const session = await tokenAuthManager.authenticateWithToken(tokenId, tokenType);
            
            setSuccess('Authentication successful!');
            setCurrentStep('success');
            
            // Вызываем callback
            if (onAuthenticated) {
                onAuthenticated(session);
            }
            
        } catch (error) {
            console.error('Authentication failed:', error);
            setError(error.message || 'Failed to authenticate');
        } finally {
            setIsAuthenticating(false);
        }
    };
    
    // Переключение на шаг покупки
    const goToPurchase = () => {
        setCurrentStep('purchase');
        loadTokenPrices();
    };
    
    // Переключение на шаг авторизации
    const goToAuthenticate = () => {
        setCurrentStep('authenticate');
    };
    
    // Закрытие модального окна
    const handleClose = () => {
        setCurrentStep('connect');
        setError('');
        setSuccess('');
        setTokenId('');
        setActiveToken(null);
        onClose();
    };
    
    // Форматирование цены
    const formatPrice = (price) => {
        if (!price) return 'Loading...';
        return `${parseFloat(price).toFixed(4)} ETH`;
    };
    
    // Форматирование времени истечения
    const formatExpiry = (timestamp) => {
        if (!timestamp) return 'Unknown';
        const date = new Date(timestamp * 1000);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    };
    
    // Получение названия типа токена
    const getTokenTypeName = (type) => {
        return type === 0 ? 'Monthly' : 'Yearly';
    };
    
    // Рендер шага подключения
    const renderConnectStep = () => (
        <div className="text-center">
            <div className="mb-6">
                <i className="fas fa-wallet text-4xl text-blue-500 mb-4"></i>
                <h3 className="text-xl font-semibold mb-2">Connect Your Wallet</h3>
                <p className="text-gray-600">Connect your MetaMask or other Web3 wallet to continue</p>
            </div>
            
            <button
                onClick={connectWallet}
                disabled={isConnecting}
                className="bg-blue-500 hover:bg-blue-600 disabled:bg-gray-400 text-white px-6 py-3 rounded-lg font-medium transition-colors"
            >
                {isConnecting ? (
                    <>
                        <i className="fas fa-spinner fa-spin mr-2"></i>
                        Connecting...
                    </>
                ) : (
                    <>
                        <i className="fas fa-wallet mr-2"></i>
                        Connect Wallet
                    </>
                )}
            </button>
            
            {error && (
                <div className="mt-4 p-3 bg-red-100 border border-red-300 text-red-700 rounded-lg">
                    {error}
                </div>
            )}
        </div>
    );
    
    // Рендер шага покупки
    const renderPurchaseStep = () => (
        <div>
            <div className="mb-6">
                <h3 className="text-xl font-semibold mb-2">Purchase Access Token</h3>
                <p className="text-gray-600">Choose your subscription plan</p>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                <div 
                    className={`border-2 rounded-lg p-4 cursor-pointer transition-colors ${
                        selectedTokenType === 'monthly' 
                            ? 'border-blue-500 bg-blue-50' 
                            : 'border-gray-200 hover:border-gray-300'
                    }`}
                    onClick={() => setSelectedTokenType('monthly')}
                >
                    <div className="text-center">
                        <i className="fas fa-calendar-alt text-2xl text-blue-500 mb-2"></i>
                        <h4 className="font-semibold">Monthly Plan</h4>
                        <p className="text-2xl font-bold text-blue-600">
                            {formatPrice(tokenPrices?.monthly)}
                        </p>
                        <p className="text-sm text-gray-600">30 days access</p>
                    </div>
                </div>
                
                <div 
                    className={`border-2 rounded-lg p-4 cursor-pointer transition-colors ${
                        selectedTokenType === 'yearly' 
                            ? 'border-blue-500 bg-blue-50' 
                            : 'border-gray-200 hover:border-gray-300'
                    }`}
                    onClick={() => setSelectedTokenType('yearly')}
                >
                    <div className="text-center">
                        <i className="fas fa-calendar text-2xl text-green-500 mb-2"></i>
                        <h4 className="font-semibold">Yearly Plan</h4>
                        <p className="text-2xl font-bold text-green-600">
                            {formatPrice(tokenPrices?.yearly)}
                        </p>
                        <p className="text-sm text-gray-600">365 days access</p>
                        <div className="mt-2">
                            <span className="bg-green-100 text-green-800 text-xs px-2 py-1 rounded-full">
                                Save 17%
                            </span>
                        </div>
                    </div>
                </div>
            </div>
            
            <div className="flex justify-between items-center">
                <button
                    onClick={() => setCurrentStep('connect')}
                    className="text-gray-600 hover:text-gray-800 transition-colors"
                >
                    <i className="fas fa-arrow-left mr-2"></i>
                    Back
                </button>
                
                <button
                    onClick={purchaseToken}
                    disabled={isPurchasing || !tokenPrices}
                    className="bg-green-500 hover:bg-green-600 disabled:bg-gray-400 text-white px-6 py-3 rounded-lg font-medium transition-colors"
                >
                    {isPurchasing ? (
                        <>
                            <i className="fas fa-spinner fa-spin mr-2"></i>
                            Purchasing...
                        </>
                    ) : (
                        <>
                            <i className="fas fa-credit-card mr-2"></i>
                            Purchase Token
                        </>
                    )}
                </button>
            </div>
            
            {error && (
                <div className="mt-4 p-3 bg-red-100 border border-red-300 text-red-700 rounded-lg">
                    {error}
                </div>
            )}
        </div>
    );
    
    // Рендер шага авторизации
    const renderAuthenticateStep = () => (
        <div>
            <div className="mb-6">
                <h3 className="text-xl font-semibold mb-2">Authenticate with Token</h3>
                <p className="text-gray-600">Use your access token to authenticate</p>
            </div>
            
            {activeToken ? (
                <div className="bg-green-50 border border-green-200 rounded-lg p-4 mb-4">
                    <div className="flex items-center mb-2">
                        <i className="fas fa-check-circle text-green-500 mr-2"></i>
                        <span className="font-semibold text-green-800">Active Token Found</span>
                    </div>
                    <div className="text-sm text-green-700">
                        <p><strong>Token ID:</strong> {activeToken.tokenId}</p>
                        <p><strong>Type:</strong> {getTokenTypeName(activeToken.tokenType)}</p>
                        <p><strong>Expires:</strong> {formatExpiry(activeToken.expiryDate)}</p>
                    </div>
                </div>
            ) : (
                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-4">
                    <div className="flex items-center mb-2">
                        <i className="fas fa-exclamation-triangle text-yellow-500 mr-2"></i>
                        <span className="font-semibold text-yellow-800">No Active Token</span>
                    </div>
                    <p className="text-sm text-yellow-700">
                        You don't have an active access token. Please purchase one first.
                    </p>
                </div>
            )}
            
            {tokenId && (
                <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-4">
                    <div className="flex items-center mb-2">
                        <i className="fas fa-info-circle text-blue-500 mr-2"></i>
                        <span className="font-semibold text-blue-800">New Token Purchased</span>
                    </div>
                    <p className="text-sm text-blue-700">
                        <strong>Token ID:</strong> {tokenId}
                    </p>
                </div>
            )}
            
            <div className="space-y-3">
                {activeToken && (
                    <button
                        onClick={() => authenticateWithToken(activeToken.tokenId)}
                        disabled={isAuthenticating}
                        className="w-full bg-green-500 hover:bg-green-600 disabled:bg-gray-400 text-white px-6 py-3 rounded-lg font-medium transition-colors"
                    >
                        {isAuthenticating ? (
                            <>
                                <i className="fas fa-spinner fa-spin mr-2"></i>
                                Authenticating...
                            </>
                        ) : (
                            <>
                                <i className="fas fa-sign-in-alt mr-2"></i>
                                Authenticate with Active Token
                            </>
                        )}
                    </button>
                )}
                
                {tokenId && (
                    <button
                        onClick={() => authenticateWithToken(tokenId)}
                        disabled={isAuthenticating}
                        className="w-full bg-blue-500 hover:bg-blue-600 disabled:bg-gray-400 text-white px-6 py-3 rounded-lg font-medium transition-colors"
                    >
                        {isAuthenticating ? (
                            <>
                                <i className="fas fa-spinner fa-spin mr-2"></i>
                                Authenticating...
                            </>
                        ) : (
                            <>
                                <i className="fas fa-sign-in-alt mr-2"></i>
                                Authenticate with New Token
                            </>
                        )}
                    </button>
                )}
                
                <button
                    onClick={goToPurchase}
                    className="w-full bg-gray-500 hover:bg-gray-600 text-white px-6 py-3 rounded-lg font-medium transition-colors"
                >
                    <i className="fas fa-plus mr-2"></i>
                    Purchase New Token
                </button>
            </div>
            
            {error && (
                <div className="mt-4 p-3 bg-red-100 border border-red-300 text-red-700 rounded-lg">
                    {error}
                </div>
            )}
            
            {success && (
                <div className="mt-4 p-3 bg-green-100 border border-green-300 text-green-700 rounded-lg">
                    {success}
                </div>
            )}
        </div>
    );
    
    // Рендер шага успеха
    const renderSuccessStep = () => (
        <div className="text-center">
            <div className="mb-6">
                <i className="fas fa-check-circle text-6xl text-green-500 mb-4"></i>
                <h3 className="text-xl font-semibold mb-2">Authentication Successful!</h3>
                <p className="text-gray-600">You are now authenticated and can access the service</p>
            </div>
            
            <button
                onClick={handleClose}
                className="bg-green-500 hover:bg-green-600 text-white px-6 py-3 rounded-lg font-medium transition-colors"
            >
                <i className="fas fa-check mr-2"></i>
                Continue
            </button>
        </div>
    );
    
    // Рендер основного контента
    const renderContent = () => {
        switch (currentStep) {
            case 'connect':
                return renderConnectStep();
            case 'purchase':
                return renderPurchaseStep();
            case 'authenticate':
                return renderAuthenticateStep();
            case 'success':
                return renderSuccessStep();
            default:
                return renderConnectStep();
        }
    };
    
    if (!isOpen) return null;
    
    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
            <div className="bg-white rounded-lg shadow-xl max-w-md w-full max-h-[90vh] overflow-y-auto">
                {/* Header */}
                <div className="flex items-center justify-between p-6 border-b">
                    <h2 className="text-xl font-semibold">Token Authentication</h2>
                    <button
                        onClick={handleClose}
                        className="text-gray-400 hover:text-gray-600 transition-colors"
                    >
                        <i className="fas fa-times text-xl"></i>
                    </button>
                </div>
                
                {/* Content */}
                <div className="p-6">
                    {renderContent()}
                </div>
                
                {/* Footer */}
                <div className="p-6 border-t bg-gray-50">
                    <div className="text-center text-sm text-gray-600">
                        <p>Secure authentication powered by Web3</p>
                        <p className="mt-1">Your wallet address: {walletAddress ? `${walletAddress.substring(0, 6)}...${walletAddress.substring(38)}` : 'Not connected'}</p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default TokenAuthModal;
