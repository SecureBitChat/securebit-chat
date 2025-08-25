// ============================================
// TOKEN STATUS COMPONENT
// ============================================
// Компонент для отображения статуса токена доступа
// Показывает информацию о текущем токене и времени до истечения
// ============================================

const TokenStatus = ({ 
    tokenAuthManager, 
    web3ContractManager,
    onShowTokenModal 
}) => {
    const [tokenInfo, setTokenInfo] = React.useState(null);
    const [timeLeft, setTimeLeft] = React.useState('');
    const [isExpired, setIsExpired] = React.useState(false);
    const [isLoading, setIsLoading] = React.useState(true);
    const [updateInterval, setUpdateInterval] = React.useState(null);
    
    React.useEffect(() => {
        if (tokenAuthManager) {
            loadTokenStatus();
            startUpdateTimer();
        }
        
        return () => {
            if (updateInterval) {
                clearInterval(updateInterval);
            }
        };
    }, [tokenAuthManager]);
    
    // Загрузка статуса токена
    const loadTokenStatus = async () => {
        try {
            setIsLoading(true);
            
            if (!tokenAuthManager || !tokenAuthManager.isAuthenticated()) {
                setTokenInfo(null);
                setTimeLeft('');
                setIsExpired(false);
                return;
            }
            
            const session = tokenAuthManager.getCurrentSession();
            if (!session) {
                setTokenInfo(null);
                return;
            }
            
            // Получаем информацию о токене
            const info = tokenAuthManager.getTokenInfo();
            setTokenInfo(info);
            
            // Проверяем, не истек ли токен
            const now = Date.now();
            const expiresAt = info.expiresAt;
            const timeRemaining = expiresAt - now;
            
            if (timeRemaining <= 0) {
                setIsExpired(true);
                setTimeLeft('Expired');
            } else {
                setIsExpired(false);
                updateTimeLeft(timeRemaining);
            }
            
        } catch (error) {
            console.error('Failed to load token status:', error);
            setTokenInfo(null);
        } finally {
            setIsLoading(false);
        }
    };
    
    // Запуск таймера обновления
    const startUpdateTimer = () => {
        const interval = setInterval(() => {
            if (tokenInfo && !isExpired) {
                const now = Date.now();
                const expiresAt = tokenInfo.expiresAt;
                const timeRemaining = expiresAt - now;
                
                if (timeRemaining <= 0) {
                    setIsExpired(true);
                    setTimeLeft('Expired');
                    // Уведомляем о истечении токена
                    handleTokenExpired();
                } else {
                    updateTimeLeft(timeRemaining);
                }
            }
        }, 1000); // Обновляем каждую секунду
        
        setUpdateInterval(interval);
    };
    
    // Обновление оставшегося времени
    const updateTimeLeft = (timeRemaining) => {
        const days = Math.floor(timeRemaining / (24 * 60 * 60 * 1000));
        const hours = Math.floor((timeRemaining % (24 * 60 * 60 * 1000)) / (60 * 60 * 1000));
        const minutes = Math.floor((timeRemaining % (60 * 60 * 1000)) / (60 * 1000));
        const seconds = Math.floor((timeRemaining % (60 * 1000)) / 1000);
        
        let timeString = '';
        
        if (days > 0) {
            timeString = `${days}d ${hours}h`;
        } else if (hours > 0) {
            timeString = `${hours}h ${minutes}m`;
        } else if (minutes > 0) {
            timeString = `${minutes}m ${seconds}s`;
        } else {
            timeString = `${seconds}s`;
        }
        
        setTimeLeft(timeString);
    };
    
    // Обработка истечения токена
    const handleTokenExpired = () => {
        // Показываем уведомление
        showExpiredNotification();
        
        // Можно также автоматически открыть модальное окно для покупки нового токена
        // if (onShowTokenModal) {
        //     setTimeout(() => onShowTokenModal(), 2000);
        // }
    };
    
    // Показ уведомления об истечении
    const showExpiredNotification = () => {
        // Создаем уведомление в браузере
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification('SecureBit Token Expired', {
                body: 'Your access token has expired. Please purchase a new one to continue.',
                icon: '/logo/icon-192x192.png',
                tag: 'token-expired'
            });
        }
        
        // Показываем toast уведомление
        showToast('Token expired', 'Your access token has expired. Please purchase a new one.', 'warning');
    };
    
    // Показ toast уведомления
    const showToast = (title, message, type = 'info') => {
        // Создаем toast элемент
        const toast = document.createElement('div');
        toast.className = `fixed top-4 right-4 z-50 p-4 rounded-lg shadow-lg max-w-sm ${
            type === 'warning' ? 'bg-yellow-500 text-white' :
            type === 'error' ? 'bg-red-500 text-white' :
            type === 'success' ? 'bg-green-500 text-white' :
            'bg-blue-500 text-white'
        }`;
        
        toast.innerHTML = `
            <div class="flex items-start">
                <div class="flex-shrink-0">
                    <i class="fas fa-${type === 'warning' ? 'exclamation-triangle' : 
                                       type === 'error' ? 'times-circle' : 
                                       type === 'success' ? 'check-circle' : 'info-circle'}"></i>
                </div>
                <div class="ml-3 flex-1">
                    <p class="font-medium">${title}</p>
                    <p class="text-sm opacity-90">${message}</p>
                </div>
                <button class="ml-4 text-white opacity-70 hover:opacity-100" onclick="this.parentElement.parentElement.remove()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
        
        document.body.appendChild(toast);
        
        // Автоматически удаляем через 5 секунд
        setTimeout(() => {
            if (toast.parentElement) {
                toast.remove();
            }
        }, 5000);
    };
    
    // Получение названия типа токена
    const getTokenTypeName = (type) => {
        return type === 'monthly' ? 'Monthly' : 'Yearly';
    };
    
    // Получение иконки типа токена
    const getTokenTypeIcon = (type) => {
        return type === 'monthly' ? 'fa-calendar-alt' : 'fa-calendar';
    };
    
    // Получение цвета для типа токена
    const getTokenTypeColor = (type) => {
        return type === 'monthly' ? 'text-blue-500' : 'text-green-500';
    };
    
    // Получение цвета для статуса
    const getStatusColor = () => {
        if (isExpired) return 'text-red-500';
        if (tokenInfo && tokenInfo.timeLeft < 24 * 60 * 60 * 1000) return 'text-yellow-500'; // Меньше дня
        return 'text-green-500';
    };
    
    // Получение иконки статуса
    const getStatusIcon = () => {
        if (isExpired) return 'fa-times-circle';
        if (tokenInfo && tokenInfo.timeLeft < 24 * 60 * 60 * 1000) return 'fa-exclamation-triangle';
        return 'fa-check-circle';
    };
    
    // Если токен не загружен или не авторизован
    if (isLoading) {
        return (
            <div className="flex items-center space-x-2 px-3 py-2 bg-gray-100 rounded-lg">
                <i className="fas fa-spinner fa-spin text-gray-400"></i>
                <span className="text-sm text-gray-500">Loading token...</span>
            </div>
        );
    }
    
    if (!tokenInfo) {
        return (
            <button
                onClick={onShowTokenModal}
                className="flex items-center space-x-2 px-3 py-2 bg-blue-100 hover:bg-blue-200 text-blue-700 rounded-lg transition-colors"
            >
                <i className="fas fa-key"></i>
                <span className="text-sm font-medium">Connect Token</span>
            </button>
        );
    }
    
    // Если токен истек
    if (isExpired) {
        return (
            <button
                onClick={onShowTokenModal}
                className="flex items-center space-x-2 px-3 py-2 bg-red-100 hover:bg-red-200 text-red-700 rounded-lg transition-colors"
            >
                <i className="fas fa-exclamation-triangle"></i>
                <span className="text-sm font-medium">Token Expired</span>
                <i className="fas fa-arrow-right text-xs"></i>
            </button>
        );
    }
    
    // Отображение активного токена
    return (
        <div className="flex items-center space-x-3">
            {/* Статус токена */}
            <div className="flex items-center space-x-2 px-3 py-2 bg-green-100 rounded-lg">
                <i className={`fas ${getStatusIcon()} ${getStatusColor()}`}></i>
                <div className="text-sm">
                    <div className="font-medium text-gray-800">
                        {getTokenTypeName(tokenInfo.tokenType)} Token
                    </div>
                    <div className={`text-xs ${getStatusColor()}`}>
                        {timeLeft} left
                    </div>
                </div>
            </div>
            
            {/* Информация о токене */}
            <div className="hidden md:flex items-center space-x-2 px-3 py-2 bg-gray-100 rounded-lg">
                <i className={`fas ${getTokenTypeIcon(tokenInfo.tokenType)} ${getTokenTypeColor(tokenInfo.tokenType)}`}></i>
                <div className="text-sm">
                    <div className="text-gray-800">
                        ID: {tokenInfo.tokenId}
                    </div>
                    <div className="text-xs text-gray-500">
                        {getTokenTypeName(tokenInfo.tokenType)}
                    </div>
                </div>
            </div>
            
            {/* Кнопка управления */}
            <button
                onClick={onShowTokenModal}
                className="flex items-center space-x-2 px-3 py-2 bg-blue-100 hover:bg-blue-200 text-blue-700 rounded-lg transition-colors"
                title="Manage token"
            >
                <i className="fas fa-cog"></i>
                <span className="hidden sm:inline text-sm font-medium">Manage</span>
            </button>
        </div>
    );
};

export default TokenStatus;
