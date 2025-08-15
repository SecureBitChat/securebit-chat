const SessionTypeSelector = ({ onSelectType, onCancel, sessionManager }) => {
    const [selectedType, setSelectedType] = React.useState(null);
    const [demoInfo, setDemoInfo] = React.useState(null);
    const [refreshTimer, setRefreshTimer] = React.useState(null);
    const [lastRefresh, setLastRefresh] = React.useState(Date.now());

    // We receive up-to-date information about demo limits
    const updateDemoInfo = React.useCallback(() => {
        if (sessionManager && sessionManager.getDemoSessionInfo) {
            try {
                const info = sessionManager.getDemoSessionInfo();
                if (window.DEBUG_MODE) {
            console.log('🔄 Demo info updated:', info);
        }
                setDemoInfo(info);
                setLastRefresh(Date.now());
            } catch (error) {
                console.error('Failed to get demo info:', error);
            }
        }
    }, [sessionManager]);

    // Update information on load and every 10 seconds
    React.useEffect(() => {
        updateDemoInfo();
        
        const interval = setInterval(updateDemoInfo, 10000); 
        setRefreshTimer(interval);
        
        return () => {
            if (interval) clearInterval(interval);
        };
    }, [updateDemoInfo]);

    // Clear timer on unmount
    React.useEffect(() => {
        return () => {
            if (refreshTimer) {
                clearInterval(refreshTimer);
            }
        };
    }, [refreshTimer]);

    const sessionTypes = [
        { 
            id: 'demo', 
            name: 'Demo', 
            duration: '6 minutes', 
            price: '0 sat', 
            usd: '$0.00', 
            popular: false,
            description: 'Limited testing session',
            features: ['End-to-end encryption', 'Basic features', 'No payment required']
        },
        { 
            id: 'basic', 
            name: 'Basic', 
            duration: '1 hour', 
            price: '500 sat', 
            usd: '$0.20',
            features: ['End-to-end encryption', 'Full features', '1 hour duration']
        },
        { 
            id: 'premium', 
            name: 'Premium', 
            duration: '4 hours', 
            price: '1000 sat', 
            usd: '$0.40', 
            popular: true,
            features: ['End-to-end encryption', 'Full features', '4 hours duration', 'Priority support']
        },
        { 
            id: 'extended', 
            name: 'Extended', 
            duration: '24 hours', 
            price: '2000 sat', 
            usd: '$0.80',
            features: ['End-to-end encryption', 'Full features', '24 hours duration', 'Priority support']
        }
    ];

    const handleTypeSelect = (typeId) => {
        console.log(`🎯 Selecting session type: ${typeId}`);
        
        if (typeId === 'demo') {
            if (demoInfo && !demoInfo.canUseNow) {
                let message = `Demo session not available.\n\n`;
                
                if (demoInfo.blockingReason === 'global_limit') {
                    message += `Reason: Too many global demo sessions active (${demoInfo.globalActive}/${demoInfo.globalLimit})\n`;
                    message += `Please try again in a few minutes.`;
                } else if (demoInfo.blockingReason === 'daily_limit') {
                    message += `Reason: Daily limit reached (${demoInfo.used}/${demoInfo.total})\n`;
                    message += `Next available: ${demoInfo.nextAvailable}`;
                } else if (demoInfo.blockingReason === 'session_cooldown') {
                    message += `Reason: Cooldown between sessions\n`;
                    message += `Next available: ${demoInfo.nextAvailable}`;
                } else if (demoInfo.blockingReason === 'completion_cooldown') {
                    message += `Reason: Wait period after last session\n`;
                    message += `Next available: ${demoInfo.nextAvailable}`;
                } else {
                    message += `Next available: ${demoInfo.nextAvailable}`;
                }
                
                alert(message);
                return;
            }
        }
        setSelectedType(typeId);
    };

    const formatCooldownTime = (minutes) => {
        if (minutes >= 60) {
            const hours = Math.floor(minutes / 60);
            const remainingMinutes = minutes % 60;
            return `${hours}h ${remainingMinutes}m`;
        }
        return `${minutes}m`;
    };

    return React.createElement('div', { className: 'space-y-6' }, [
        React.createElement('div', { key: 'header', className: 'text-center' }, [
            React.createElement('h3', { 
                key: 'title', 
                className: 'text-xl font-semibold text-white mb-2' 
            }, 'Choose Your Session'),
            React.createElement('p', { 
                key: 'subtitle', 
                className: 'text-gray-300 text-sm' 
            }, 'Pay via Lightning Network or try our demo session')
        ]),
        
        React.createElement('div', { key: 'types', className: 'space-y-3' }, 
            sessionTypes.map(type => {
                const isDemo = type.id === 'demo';
                const isDisabled = isDemo && demoInfo && !demoInfo.canUseNow;
                
                return React.createElement('div', {
                    key: type.id,
                    onClick: () => !isDisabled && handleTypeSelect(type.id),
                    className: `card-minimal rounded-lg p-4 border-2 transition-all ${
                        selectedType === type.id ? 'border-orange-500 bg-orange-500/10' : 'border-gray-600 hover:border-orange-400'
                    } ${type.popular ? 'relative' : ''} ${
                        isDisabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'
                    }`
                }, [
                    type.popular && React.createElement('div', { 
                        key: 'badge', 
                        className: 'absolute -top-2 right-3 bg-orange-500 text-white text-xs px-2 py-1 rounded-full' 
                    }, 'Popular'),
                    
                    React.createElement('div', { key: 'content', className: 'flex items-start justify-between' }, [
                        React.createElement('div', { key: 'info', className: 'flex-1' }, [
                            React.createElement('div', { key: 'header', className: 'flex items-center gap-2 mb-2' }, [
                                React.createElement('h4', { 
                                    key: 'name', 
                                    className: 'text-lg font-semibold text-white' 
                                }, type.name),
                                isDemo && React.createElement('span', {
                                    key: 'demo-badge',
                                    className: 'text-xs bg-blue-500/20 text-blue-300 px-2 py-1 rounded-full'
                                }, 'FREE')
                            ]),
                            React.createElement('p', { 
                                key: 'duration', 
                                className: 'text-gray-300 text-sm mb-1' 
                            }, `Duration: ${type.duration}`),
                            type.description && React.createElement('p', {
                                key: 'description',
                                className: 'text-xs text-gray-400 mb-2'
                            }, type.description),
                            
                            isDemo && demoInfo && React.createElement('div', {
                                key: 'demo-status',
                                className: 'text-xs mb-2'
                            }, [
                                React.createElement('div', {
                                    key: 'availability',
                                    className: demoInfo.canUseNow ? 'text-green-400' : 'text-yellow-400'
                                }, demoInfo.canUseNow ? 
                                    `✅ Available (${demoInfo.available}/${demoInfo.total} today)` : 
                                    `⏰ Next: ${demoInfo.nextAvailable}`
                                ),
                                demoInfo.globalActive > 0 && React.createElement('div', {
                                    key: 'global-status',
                                    className: 'text-blue-300 mt-1'
                                }, `🌐 Global: ${demoInfo.globalActive}/${demoInfo.globalLimit} active`)
                            ]),
                            
                            type.features && React.createElement('div', {
                                key: 'features',
                                className: 'text-xs text-gray-400 space-y-1'
                            }, type.features.map((feature, index) => 
                                React.createElement('div', {
                                    key: index,
                                    className: 'flex items-center gap-1'
                                }, [
                                    React.createElement('i', {
                                        key: 'check',
                                        className: 'fas fa-check text-green-400 w-3'
                                    }),
                                    React.createElement('span', {
                                        key: 'text'
                                    }, feature)
                                ])
                            ))
                        ]),
                        React.createElement('div', { key: 'pricing', className: 'text-right' }, [
                            React.createElement('div', { 
                                key: 'sats', 
                                className: `text-lg font-bold ${isDemo ? 'text-green-400' : 'text-orange-400'}` 
                            }, type.price),
                            React.createElement('div', { 
                                key: 'usd', 
                                className: 'text-xs text-gray-400' 
                            }, type.usd)
                        ])
                    ])
                ])
            })
        ),
        
        demoInfo && React.createElement('div', { 
            key: 'demo-info', 
            className: 'bg-gradient-to-r from-blue-900/20 to-purple-900/20 border border-blue-700/50 rounded-lg p-4' 
        }, [
            React.createElement('div', { 
                key: 'demo-header', 
                className: 'flex items-center gap-2 text-blue-300 text-sm font-medium mb-3' 
            }, [
                React.createElement('i', {
                    key: 'icon',
                    className: 'fas fa-info-circle'
                }),
                React.createElement('span', {
                    key: 'title'
                }, 'Demo Session Information')
            ]),
            React.createElement('div', { 
                key: 'demo-details', 
                className: 'grid grid-cols-1 md:grid-cols-2 gap-3 text-blue-200 text-xs' 
            }, [
                React.createElement('div', { key: 'limits', className: 'space-y-1' }, [
                    React.createElement('div', { key: 'daily' }, `📅 Daily limit: ${demoInfo.total} sessions`),
                    React.createElement('div', { key: 'duration' }, `⏱️ Duration: ${demoInfo.durationMinutes} minutes each`),
                    React.createElement('div', { key: 'cooldown' }, `⏰ Cooldown: ${demoInfo.sessionCooldownMinutes} min between sessions`)
                ]),
                React.createElement('div', { key: 'status', className: 'space-y-1' }, [
                    React.createElement('div', { key: 'used' }, `📊 Used today: ${demoInfo.used}/${demoInfo.total}`),
                    React.createElement('div', { key: 'global' }, `🌐 Global active: ${demoInfo.globalActive}/${demoInfo.globalLimit}`),
                    React.createElement('div', { 
                        key: 'next', 
                        className: demoInfo.canUseNow ? 'text-green-300' : 'text-yellow-300' 
                    }, `🎯 Status: ${demoInfo.canUseNow ? 'Available now' : demoInfo.nextAvailable}`)
                ])
            ]),
            React.createElement('div', {
                key: 'last-updated',
                className: 'text-xs text-gray-400 mt-3 text-center'
            }, `Last updated: ${new Date(lastRefresh).toLocaleTimeString()}`)
        ]),
        
        React.createElement('div', { key: 'buttons', className: 'flex space-x-3' }, [
            React.createElement('button', { 
                key: 'continue', 
                onClick: () => {
                    if (selectedType) {
                        console.log(`🚀 Proceeding with session type: ${selectedType}`);
                        onSelectType(selectedType);
                    }
                }, 
                disabled: !selectedType || (selectedType === 'demo' && demoInfo && !demoInfo.canUseNow), 
                className: 'flex-1 lightning-button text-white py-3 px-4 rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-all' 
            }, [
                React.createElement('i', { 
                    key: 'icon',
                    className: selectedType === 'demo' ? 'fas fa-play mr-2' : 'fas fa-bolt mr-2' 
                }), 
                selectedType === 'demo' ? 'Start Demo Session' : 'Continue to Payment'
            ]),
            React.createElement('button', { 
                key: 'cancel', 
                onClick: onCancel, 
                className: 'px-6 py-3 bg-gray-600 hover:bg-gray-500 text-white rounded-lg transition-all' 
            }, 'Cancel'),
            React.createElement('button', { 
                key: 'refresh', 
                onClick: updateDemoInfo, 
                className: 'px-3 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-all', 
                title: 'Refresh demo status'
            }, React.createElement('i', { className: 'fas fa-sync-alt' }))
        ]),


    ]);
};

window.SessionTypeSelector = SessionTypeSelector;