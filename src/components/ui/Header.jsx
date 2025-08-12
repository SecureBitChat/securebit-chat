const React = window.React;

const EnhancedMinimalHeader = ({ 
    status, 
    fingerprint, 
    verificationCode, 
    onDisconnect, 
    isConnected, 
    securityLevel, 
    sessionManager, 
    sessionTimeLeft 
}) => {
    const getStatusConfig = () => {
        switch (status) {
            case 'connected':
                return {
                text: 'Connected',
                className: 'status-connected',
                badgeClass: 'bg-green-500/10 text-green-400 border-green-500/20'
            };
            case 'verifying':
                return {
                    text: 'Verifying...',
                    className: 'status-verifying',
                    badgeClass: 'bg-purple-500/10 text-purple-400 border-purple-500/20'
                };
            case 'connecting':
                return {
                    text: 'Connecting...',
                    className: 'status-connecting',
                    badgeClass: 'bg-blue-500/10 text-blue-400 border-blue-500/20'
                };
            case 'retrying':
                return {
                    text: 'Retrying...',
                    className: 'status-connecting',
                    badgeClass: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
                };
            case 'failed':
                return {
                    text: 'Error',
                    className: 'status-failed',
                    badgeClass: 'bg-red-500/10 text-red-400 border-red-500/20'
                };
            case 'reconnecting':
                return {
                    text: 'Reconnecting...',
                    className: 'status-connecting',
                    badgeClass: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
                };
            case 'peer_disconnected':
                return {
                    text: 'Peer disconnected',
                    className: 'status-failed',
                    badgeClass: 'bg-orange-500/10 text-orange-400 border-orange-500/20'
                };
            default:
                return {
                    text: 'Not connected',
                    className: 'status-disconnected',
                    badgeClass: 'bg-gray-500/10 text-gray-400 border-gray-500/20'
                };

        }
    };

    const config = getStatusConfig();

    const handleSecurityClick = () => {
        if (securityLevel?.verificationResults) {
            alert('Security check details:\n\n' + 
                Object.entries(securityLevel.verificationResults)
                    .map(([key, result]) => `${key}: ${result.passed ? '✅' : '❌'} ${result.details}`)
                    .join('\n')
            );
        }
    };

    return React.createElement('header', {
        className: 'header-minimal sticky top-0 z-50'
    }, [
        React.createElement('div', {
            key: 'container',
            className: 'max-w-7xl mx-auto px-4 sm:px-6 lg:px-8'
        }, [
            React.createElement('div', {
                key: 'content',
                className: 'flex items-center justify-between h-16'
            }, [
                React.createElement('div', {
                    key: 'logo-section',
                    className: 'flex items-center space-x-2 sm:space-x-3'
                }, [
                    React.createElement('div', {
                        key: 'logo',
                        className: 'icon-container w-8 h-8 sm:w-10 sm:h-10'
                    }, [
                        React.createElement('i', {
                            className: 'fas fa-shield-halved accent-orange text-sm sm:text-base'
                        })
                    ]),
                    React.createElement('div', {
                        key: 'title-section'
                    }, [
                        React.createElement('h1', {
                            key: 'title',
                            className: 'text-lg sm:text-xl font-semibold text-primary'
                        }, 'LockBit.chat'),
                        React.createElement('p', {
                            key: 'subtitle',
                            className: 'text-xs sm:text-sm text-muted hidden sm:block'
                        }, 'End-to-end freedom')
                    ])
                ]),

                // Status and Controls - Mobile Responsive
                React.createElement('div', {
                    key: 'status-section',
                    className: 'flex items-center space-x-2 sm:space-x-3'
                }, [
                    (() => {
                        const hasActive = sessionManager?.hasActiveSession();
                        const hasTimer = !!window.SessionTimer;
                        console.log('Header SessionTimer check:', { 
                            hasActive, 
                            hasTimer, 
                            sessionTimeLeft, 
                            sessionType: sessionManager?.currentSession?.type 
                        });
                        
                        return hasActive && hasTimer && React.createElement(window.SessionTimer, {
                            key: 'session-timer',
                            timeLeft: sessionTimeLeft,
                            sessionType: sessionManager.currentSession?.type || 'unknown'
                        });
                    })(),

                    // Security Level Indicator - Hidden on mobile, shown on tablet+ (Clickable)
                    securityLevel && React.createElement('div', {
                        key: 'security-level',
                        className: 'hidden md:flex items-center space-x-2 cursor-pointer hover:opacity-80 transition-opacity duration-200',
                        onClick: handleSecurityClick,
                        title: 'Нажмите для просмотра деталей безопасности'
                    }, [
                        React.createElement('div', {
                            key: 'security-icon',
                            className: `w-6 h-6 rounded-full flex items-center justify-center ${
                                securityLevel.color === 'green' ? 'bg-green-500/20' :
                                securityLevel.color === 'yellow' ? 'bg-yellow-500/20' : 'bg-red-500/20'
                            }`
                        }, [
                            React.createElement('i', {
                                className: `fas fa-shield-alt text-xs ${
                                    securityLevel.color === 'green' ? 'text-green-400' :
                                    securityLevel.color === 'yellow' ? 'text-yellow-400' : 'text-red-400'
                                }`
                            })
                        ]),
                        React.createElement('div', {
                            key: 'security-info',
                            className: 'flex flex-col'
                        }, [
                            React.createElement('div', {
                                key: 'security-level-text',
                                className: 'text-xs font-medium text-primary'
                            }, `${securityLevel.level} (${securityLevel.score}%)`),
                            securityLevel.details && React.createElement('div', {
                                key: 'security-details',
                                className: 'text-xs text-muted mt-1 hidden lg:block'
                            }, securityLevel.details),
                            React.createElement('div', {
                                key: 'security-progress',
                                className: 'w-16 h-1 bg-gray-600 rounded-full overflow-hidden'
                            }, [
                                React.createElement('div', {
                                    key: 'progress-bar',
                                    className: `h-full transition-all duration-500 ${
                                        securityLevel.color === 'green' ? 'bg-green-400' :
                                        securityLevel.color === 'yellow' ? 'bg-yellow-400' : 'bg-red-400'
                                    }`,
                                    style: { width: `${securityLevel.score}%` }
                                })
                            ])
                        ])
                    ]),

                    // Mobile Security Indicator - Only icon on mobile (Clickable)
                    securityLevel && React.createElement('div', {
                        key: 'mobile-security',
                        className: 'md:hidden flex items-center'
                    }, [
                        React.createElement('div', {
                            key: 'mobile-security-icon',
                            className: `w-8 h-8 rounded-full flex items-center justify-center cursor-pointer hover:opacity-80 transition-opacity duration-200 ${
                                securityLevel.color === 'green' ? 'bg-green-500/20' :
                                securityLevel.color === 'yellow' ? 'bg-yellow-500/20' : 'bg-red-500/20'
                            }`,
                            title: `${securityLevel.level} (${securityLevel.score}%) - Click for details`,
                            onClick: handleSecurityClick
                        }, [
                            React.createElement('i', {
                                className: `fas fa-shield-alt text-sm ${
                                    securityLevel.color === 'green' ? 'text-green-400' :
                                    securityLevel.color === 'yellow' ? 'text-yellow-400' : 'text-red-400'
                                }`
                            })
                        ])
                    ]),

                    // Status Badge - Compact on mobile
                    React.createElement('div', {
                        key: 'status-badge',
                        className: `px-2 sm:px-3 py-1.5 rounded-lg border ${config.badgeClass} flex items-center space-x-1 sm:space-x-2`
                    }, [
                        React.createElement('span', {
                            key: 'status-dot',
                            className: `status-dot ${config.className}`
                        }),
                        React.createElement('span', {
                            key: 'status-text',
                            className: 'text-xs sm:text-sm font-medium'
                        }, config.text)
                    ]),

                    // Disconnect Button - Icon only on mobile
                    isConnected && React.createElement('button', {
                        key: 'disconnect-btn',
                        onClick: onDisconnect,
                        className: 'p-1.5 sm:px-3 sm:py-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 rounded-lg transition-all duration-200 text-sm'
                    }, [
                        React.createElement('i', {
                            key: 'disconnect-icon',
                            className: 'fas fa-power-off sm:mr-2'
                        }),
                        React.createElement('span', {
                            key: 'disconnect-text',
                            className: 'hidden sm:inline'
                        }, 'Disconnect')
                    ])
                ])
            ])
        ])
    ]);
};

window.EnhancedMinimalHeader = EnhancedMinimalHeader;