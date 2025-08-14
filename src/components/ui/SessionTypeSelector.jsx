const React = window.React;

const SessionTypeSelector = ({ onSelectType, onCancel, sessionManager }) => {
    const [selectedType, setSelectedType] = React.useState(null);
    const [demoInfo, setDemoInfo] = React.useState(null);

    // Получаем информацию о demo лимитах при загрузке
    React.useEffect(() => {
        if (sessionManager && sessionManager.getDemoSessionInfo) {
            const info = sessionManager.getDemoSessionInfo();
            setDemoInfo(info);
        }
    }, [sessionManager]);

    const sessionTypes = [
        { 
            id: 'demo', 
            name: 'Demo', 
            duration: '6 minutes', 
            price: '0 sat', 
            usd: '$0.00', 
            popular: true,
            description: 'Limited testing session',
            warning: demoInfo ? `Available: ${demoInfo.available}/${demoInfo.total}` : 'Loading...'
        },
        { 
            id: 'basic', 
            name: 'Basic', 
            duration: '1 hour', 
            price: '500 sat', 
            usd: '$0.20' 
        },
        { 
            id: 'premium', 
            name: 'Premium', 
            duration: '4 hours', 
            price: '1000 sat', 
            usd: '$0.40', 
            popular: true 
        },
        { 
            id: 'extended', 
            name: 'Extended', 
            duration: '24 hours', 
            price: '2000 sat', 
            usd: '$0.80' 
        }
    ];

    const handleTypeSelect = (typeId) => {
        if (typeId === 'demo') {
            // Проверяем доступность demo сессии
            if (demoInfo && !demoInfo.canUseNow) {
                alert(`Demo session not available now. ${demoInfo.nextAvailable}`);
                return;
            }
        }
        setSelectedType(typeId);
    };

    return React.createElement('div', { className: 'space-y-6' }, [
        React.createElement('div', { key: 'header', className: 'text-center' }, [
            React.createElement('h3', { 
                key: 'title', 
                className: 'text-xl font-semibold text-white mb-2' 
            }, 'Choose a plan'),
            React.createElement('p', { 
                key: 'subtitle', 
                className: 'text-gray-300 text-sm' 
            }, 'Pay via Lightning Network or use limited demo session')
        ]),
        
        React.createElement('div', { key: 'types', className: 'space-y-3' }, 
            sessionTypes.map(type => 
                React.createElement('div', {
                    key: type.id,
                    onClick: () => handleTypeSelect(type.id),
                    className: `card-minimal rounded-lg p-4 cursor-pointer border-2 transition-all ${
                        selectedType === type.id ? 'border-orange-500 bg-orange-500/10' : 'border-gray-600 hover:border-orange-400'
                    } ${type.popular ? 'relative' : ''} ${
                        type.id === 'demo' && demoInfo && !demoInfo.canUseNow ? 'opacity-50 cursor-not-allowed' : ''
                    }`
                }, [
                    type.popular && React.createElement('div', { 
                        key: 'badge', 
                        className: 'absolute -top-2 right-3 bg-orange-500 text-white text-xs px-2 py-1 rounded-full' 
                    }, type.id === 'demo' ? 'Demo' : 'Popular'),
                    
                    React.createElement('div', { key: 'content', className: 'flex items-center justify-between' }, [
                        React.createElement('div', { key: 'info' }, [
                            React.createElement('h4', { 
                                key: 'name', 
                                className: 'text-lg font-semibold text-white' 
                            }, type.name),
                            React.createElement('p', { 
                                key: 'duration', 
                                className: 'text-gray-300 text-sm' 
                            }, type.duration),
                            type.description && React.createElement('p', {
                                key: 'description',
                                className: 'text-xs text-gray-400 mt-1'
                            }, type.description),
                            type.id === 'demo' && React.createElement('p', {
                                key: 'warning',
                                className: `text-xs mt-1 ${
                                    demoInfo && demoInfo.canUseNow ? 'text-green-400' : 'text-yellow-400'
                                }`
                            }, type.warning)
                        ]),
                        React.createElement('div', { key: 'pricing', className: 'text-right' }, [
                            React.createElement('div', { 
                                key: 'sats', 
                                className: 'text-lg font-bold text-orange-400' 
                            }, type.price),
                            React.createElement('div', { 
                                key: 'usd', 
                                className: 'text-xs text-gray-400' 
                            }, type.usd)
                        ])
                    ])
                ])
            )
        ),
        
        // Информация о demo лимитах
        demoInfo && React.createElement('div', { 
            key: 'demo-info', 
            className: 'bg-blue-900/20 border border-blue-700 rounded-lg p-3' 
        }, [
            React.createElement('div', { 
                key: 'demo-header', 
                className: 'text-blue-300 text-sm font-medium mb-2' 
            }, '📱 Demo Session Limits'),
            React.createElement('div', { 
                key: 'demo-details', 
                className: 'text-blue-200 text-xs space-y-1' 
            }, [
                React.createElement('div', { key: 'limit' }, 
                    `• Maximum ${demoInfo.total} demo sessions per day`),
                React.createElement('div', { key: 'cooldown' }, 
                    `• 5 minutes between sessions, 1 hour between series`),
                React.createElement('div', { key: 'duration' }, 
                    `• Each session limited to ${demoInfo.durationMinutes} minutes`),
                React.createElement('div', { key: 'status' }, 
                    `• Status: ${demoInfo.canUseNow ? 'Available now' : `Next available: ${demoInfo.nextAvailable}`}`)
            ])
        ]),
        
        React.createElement('div', { key: 'buttons', className: 'flex space-x-3' }, [
            React.createElement('button', { 
                key: 'continue', 
                onClick: () => selectedType && onSelectType(selectedType), 
                disabled: !selectedType || (selectedType === 'demo' && demoInfo && !demoInfo.canUseNow), 
                className: 'flex-1 lightning-button text-white py-3 px-4 rounded-lg font-medium disabled:opacity-50' 
            }, [
                React.createElement('i', { className: 'fas fa-bolt mr-2' }), 
                selectedType === 'demo' ? 'Start Demo Session' : 'Continue to payment'
            ]),
            React.createElement('button', { 
                key: 'cancel', 
                onClick: onCancel, 
                className: 'px-6 py-3 bg-gray-600 hover:bg-gray-500 text-white rounded-lg' 
            }, 'Cancel')
        ])
    ]);
};

window.SessionTypeSelector = SessionTypeSelector;