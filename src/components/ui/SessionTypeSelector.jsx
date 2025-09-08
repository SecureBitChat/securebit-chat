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
            securityLevel: 'Basic',
            securityBadge: 'BASIC',
            securityColor: 'bg-blue-500/20 text-blue-300',
            description: 'Limited testing session with basic security',
            features: [
                'Basic end-to-end encryption', 
                'Simple key exchange', 
                'Message integrity',
                'Rate limiting'
            ],
            limitations: [
                'No advanced security features',
                'No traffic obfuscation',
                'No metadata protection'
            ]
        },
        { 
            id: 'basic', 
            name: 'Basic', 
            duration: '1 hour', 
            price: '5,000 sat', 
            usd: '$2.00',
            securityLevel: 'Enhanced',
            securityBadge: 'ENHANCED',
            securityColor: 'bg-orange-500/20 text-orange-300',
            popular: true,
            description: 'Full featured session with enhanced security',
            features: [
                'All basic features',
                'ECDSA digital signatures', 
                'Metadata protection', 
                'Perfect forward secrecy',
                'Nested encryption',
                'Packet padding',
                'Complete ASN.1 validation',
                'OID and EC point verification',
                'SPKI structure validation',
                '18-layer security architecture',
                'ASN.1 Validated'
            ],
            limitations: [
                'Limited traffic obfuscation',
                'No fake traffic generation'
            ]
        },
        { 
            id: 'premium', 
            name: 'Premium', 
            duration: '6 hours', 
            price: '20,000 sat', 
            usd: '$8.00',
            securityLevel: 'Maximum',
            securityBadge: 'MAXIMUM',
            securityColor: 'bg-green-500/20 text-green-300',
            description: 'Extended session with maximum security protection',
            features: [
                'All enhanced features',
                'Traffic obfuscation', 
                'Fake traffic generation',
                'Decoy channels',
                'Anti-fingerprinting',
                'Message chunking',
                'Advanced replay protection',
                'Complete ASN.1 validation',
                'OID and EC point verification',
                'SPKI structure validation',
                '18-layer security architecture',
                'ASN.1 Validated'
            ],
            limitations: []
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
            }, 'Different security levels for different needs')
        ]),
        
        React.createElement('div', { key: 'types', className: 'space-y-4' }, 
            sessionTypes.map(type => {
                const isDemo = type.id === 'demo';
                const isDisabled = isDemo && demoInfo && !demoInfo.canUseNow;
                
                return React.createElement('div', {
                    key: type.id,
                    onClick: () => !isDisabled && handleTypeSelect(type.id),
                    className: `relative card-minimal ${selectedType === type.id ? 'card-minimal--selected' : ''} rounded-lg p-5 border-2 transition-all ${
                        selectedType === type.id
                            ? 'border-orange-500 bg-orange-500/15 ring-2 ring-orange-400 ring-offset-2 ring-offset-black/30'
                            : 'border-gray-600 hover:border-orange-400'
                    } ${type.popular && selectedType !== type.id ? 'ring-2 ring-orange-500/30' : ''} ${
                        isDisabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'
                    }`
                }, [
                    // Popular badge
                    type.popular && React.createElement('div', { 
                        key: 'popular-badge', 
                        className: 'absolute -top-2 right-3 bg-orange-500 text-white text-xs px-3 py-1 rounded-full font-medium' 
                    }, 'Most Popular'),
                    
                    React.createElement('div', { key: 'content', className: 'space-y-4' }, [
                        // Header with name and security level
                        React.createElement('div', { key: 'header', className: 'flex items-start justify-between' }, [
                            React.createElement('div', { key: 'title-section' }, [
                                React.createElement('div', { key: 'name-row', className: 'flex items-center gap-3 mb-2' }, [
                                    React.createElement('h4', { 
                                        key: 'name', 
                                        className: 'text-xl font-bold text-white' 
                                    }, type.name),
                                    isDemo && React.createElement('span', {
                                        key: 'free-badge',
                                        className: 'text-xs bg-blue-500/20 text-blue-300 px-2 py-1 rounded-full font-medium'
                                    }, 'FREE'),
                                    React.createElement('span', {
                                        key: 'security-badge',
                                        className: `text-xs px-2 py-1 rounded-full font-medium ${type.securityColor}`
                                    }, type.securityBadge)
                                ]),
                                React.createElement('p', { 
                                    key: 'duration', 
                                    className: 'text-gray-300 font-medium mb-1' 
                                }, `Duration: ${type.duration}`),
                                React.createElement('p', {
                                    key: 'description',
                                    className: 'text-sm text-gray-400'
                                }, type.description)
                            ]),
                            React.createElement('div', { key: 'pricing', className: 'text-right' }, [
                                React.createElement('div', { 
                                    key: 'sats', 
                                    className: `text-xl font-bold ${isDemo ? 'text-green-400' : 'text-orange-400'}` 
                                }, type.price),
                                React.createElement('div', { 
                                    key: 'usd', 
                                    className: 'text-sm text-gray-400' 
                                }, type.usd)
                            ])
                        ]),

                        // Demo status info
                        isDemo && demoInfo && React.createElement('div', {
                            key: 'demo-status',
                            className: 'p-3 bg-blue-900/20 border border-blue-700/30 rounded-lg'
                        }, [
                            React.createElement('div', {
                                key: 'availability',
                                className: `text-sm font-medium ${demoInfo.canUseNow ? 'text-green-400' : 'text-yellow-400'}`
                            }, demoInfo.canUseNow ? 
                                `✅ Available (${demoInfo.available}/${demoInfo.total} today)` : 
                                `⏰ Next: ${demoInfo.nextAvailable}`
                            ),
                            demoInfo.globalActive > 0 && React.createElement('div', {
                                key: 'global-status',
                                className: 'text-blue-300 text-xs mt-1'
                            }, `🌐 Global: ${demoInfo.globalActive}/${demoInfo.globalLimit} active`)
                        ]),

                        // Security features
                        React.createElement('div', { key: 'features-section', className: 'space-y-3' }, [
                            React.createElement('div', { key: 'features' }, [
                                React.createElement('h5', {
                                    key: 'features-title',
                                    className: 'text-sm font-medium text-green-300 mb-2 flex items-center'
                                }, [
                                    React.createElement('i', {
                                        key: 'shield-icon',
                                        className: 'fas fa-shield-alt mr-2'
                                    }),
                                    'Security Features'
                                ]),
                                React.createElement('div', {
                                    key: 'features-list',
                                    className: 'grid grid-cols-1 gap-1'
                                }, type.features.map((feature, index) => 
                                    React.createElement('div', {
                                        key: index,
                                        className: 'flex items-center gap-2 text-xs text-gray-300'
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

                            // Limitations (if any)
                            type.limitations && type.limitations.length > 0 && React.createElement('div', { key: 'limitations' }, [
                                React.createElement('h5', {
                                    key: 'limitations-title',
                                    className: 'text-sm font-medium text-yellow-300 mb-2 flex items-center'
                                }, [
                                    React.createElement('i', {
                                        key: 'info-icon',
                                        className: 'fas fa-info-circle mr-2'
                                    }),
                                    'Limitations'
                                ]),
                                React.createElement('div', {
                                    key: 'limitations-list',
                                    className: 'grid grid-cols-1 gap-1'
                                }, type.limitations.map((limitation, index) => 
                                    React.createElement('div', {
                                        key: index,
                                        className: 'flex items-center gap-2 text-xs text-gray-400'
                                    }, [
                                        React.createElement('i', {
                                            key: 'minus',
                                            className: 'fas fa-minus text-yellow-400 w-3'
                                        }),
                                        React.createElement('span', {
                                            key: 'text'
                                        }, limitation)
                                    ])
                                ))
                            ])
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
                key: 'security-note',
                className: 'mt-3 p-2 bg-yellow-500/10 border border-yellow-500/20 rounded text-yellow-200 text-xs'
            }, '⚠️ Demo sessions use basic security only. Upgrade to paid sessions for enhanced protection.'),
            React.createElement('div', {
                key: 'last-updated',
                className: 'text-xs text-gray-400 mt-2 text-center'
            }, `Last updated: ${new Date(lastRefresh).toLocaleTimeString()}`)
        ]),

        // Action buttons
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
            
        ])
    ]);
};

window.SessionTypeSelector = SessionTypeSelector;