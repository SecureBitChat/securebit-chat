const EnhancedMinimalHeader = ({ 
    status, 
    fingerprint, 
    verificationCode, 
    onDisconnect, 
    isConnected, 
    securityLevel, 
    sessionManager, 
    sessionTimeLeft,
    webrtcManager 
}) => {
    const [currentTimeLeft, setCurrentTimeLeft] = React.useState(sessionTimeLeft || 0);
    const [hasActiveSession, setHasActiveSession] = React.useState(false);
    const [sessionType, setSessionType] = React.useState('unknown');
    const [realSecurityLevel, setRealSecurityLevel] = React.useState(null);

    React.useEffect(() => {
        const updateSessionInfo = () => {
            if (sessionManager) {
                const isActive = sessionManager.hasActiveSession();
                const timeLeft = sessionManager.getTimeLeft();
                const currentSession = sessionManager.currentSession;
                
                setHasActiveSession(isActive);
                setCurrentTimeLeft(timeLeft);
                setSessionType(currentSession?.type || 'unknown');
            }
        };

        updateSessionInfo();
        const interval = setInterval(updateSessionInfo, 1000);
        return () => clearInterval(interval);
    }, [sessionManager]);

    React.useEffect(() => {
        const updateSecurityStatus = () => {
            try {
                const activeWebrtcManager = webrtcManager || window.webrtcManager;
                const activeSessionManager = sessionManager || window.sessionManager;
                
                if (activeWebrtcManager && activeWebrtcManager.getSecurityStatus) {
                    const securityStatus = activeWebrtcManager.getSecurityStatus();
                    const sessionInfo = activeSessionManager ? activeSessionManager.getSessionInfo() : null;

                    if (window.DEBUG_MODE) {
                        console.log('🔍 Header security update:', {
                            hasWebrtcManager: !!activeWebrtcManager,
                            hasSessionManager: !!activeSessionManager,
                            securityStatus: securityStatus,
                            sessionInfo: sessionInfo
                        });
                    }

                    const realLevel = calculateRealSecurityLevel(securityStatus, sessionInfo);
                    setRealSecurityLevel(realLevel);
                    
                    if (window.DEBUG_MODE) {
                        console.log('🔍 Calculated real security level:', realLevel);
                    }
                }
            } catch (error) {
                console.warn('⚠️ Error updating security status:', error);
            }
        };

        updateSecurityStatus();
        const interval = setInterval(updateSecurityStatus, 3000); 
        return () => clearInterval(interval);
    }, [webrtcManager, sessionManager]);

    const calculateRealSecurityLevel = (securityStatus, sessionInfo) => {
        if (!securityStatus) {
            return {
                level: 'Unknown',
                score: 0,
                color: 'red',
                details: 'Security status not available'
            };
        }

        const activeFeatures = securityStatus.activeFeaturesNames || [];
        const totalFeatures = securityStatus.totalFeatures || 12;
        const sessionType = sessionInfo?.type || securityStatus.sessionType || 'unknown';
        const securityLevel = securityStatus.securityLevel || 'basic';
        const stage = securityStatus.stage || 1;

        let finalScore = securityStatus.score || 0;
        let level = 'Basic';
        let color = 'red';

        // score от crypto utils
        if (finalScore > 0) {
            if (finalScore >= 90) {
                level = 'Maximum';
                color = 'green';
            } else if (finalScore >= 60) {
                level = 'Enhanced';
                color = sessionType === 'demo' ? 'yellow' : 'green';
            } else if (finalScore >= 30) {
                level = 'Basic';
                color = 'yellow';
            } else {
                level = 'Low';
                color = 'red';
            }
        } else {
            const baseScores = {
                'basic': 30,    
                'enhanced': 65, 
                'maximum': 90   
            };

            const featureScore = totalFeatures > 0 ? Math.min(40, (activeFeatures.length / totalFeatures) * 40) : 0;
            finalScore = Math.min(100, (baseScores[securityLevel] || 30) + featureScore);

            if (sessionType === 'demo') {
                level = 'Basic';
                color = finalScore >= 40 ? 'yellow' : 'red';
            } else if (securityLevel === 'enhanced') {
                level = 'Enhanced';
                color = finalScore >= 70 ? 'green' : 'yellow';
            } else if (securityLevel === 'maximum') {
                level = 'Maximum';
                color = 'green';
            } else {
                level = 'Basic';
                color = finalScore >= 50 ? 'yellow' : 'red';
            }
        }

        return {
            level: level,
            score: Math.round(finalScore),
            color: color,
            details: `${activeFeatures.length}/${totalFeatures} security features active`,
            activeFeatures: activeFeatures,
            sessionType: sessionType,
            stage: stage,
            securityLevel: securityLevel
        };
    };

    React.useEffect(() => {
        if (sessionManager?.hasActiveSession()) {
            setCurrentTimeLeft(sessionManager.getTimeLeft());
            setHasActiveSession(true);
        } else {
            setHasActiveSession(false);
        }
    }, [sessionManager, sessionTimeLeft]);

    const handleSecurityClick = () => {
        const currentSecurity = realSecurityLevel || securityLevel;
        
        if (!currentSecurity) {
            alert('Security information not available');
            return;
        }

        if (currentSecurity.activeFeatures) {
            const activeList = currentSecurity.activeFeatures.map(feature => 
                `✅ ${feature.replace('has', '').replace(/([A-Z])/g, ' $1').trim()}`
            ).join('\n');
            
            const message = `Security Level: ${currentSecurity.level} (${currentSecurity.score}%)\n` +
                          `Session Type: ${currentSecurity.sessionType}\n` +
                          `Stage: ${currentSecurity.stage}\n\n` +
                          `Active Security Features:\n${activeList || 'No features detected'}\n\n` +
                          `${currentSecurity.details || 'No additional details'}`;
            
            alert(message);
        } else if (currentSecurity.verificationResults) {
            alert('Security check details:\n\n' + 
                Object.entries(currentSecurity.verificationResults)
                    .map(([key, result]) => `${key}: ${result.passed ? '✅' : '❌'} ${result.details}`)
                    .join('\n')
            );
        } else {
            alert(`Security Level: ${currentSecurity.level}\nScore: ${currentSecurity.score}%\nDetails: ${currentSecurity.details || 'No additional details available'}`);
        }
    };

    const shouldShowTimer = hasActiveSession && currentTimeLeft > 0 && window.SessionTimer;

    React.useEffect(() => {
        const handleForceUpdate = (event) => {
            if (sessionManager) {
                const isActive = sessionManager.hasActiveSession();
                const timeLeft = sessionManager.getTimeLeft();
                const currentSession = sessionManager.currentSession;
                
                setHasActiveSession(isActive);
                setCurrentTimeLeft(timeLeft);
                setSessionType(currentSession?.type || 'unknown');
            }
        };

        document.addEventListener('force-header-update', handleForceUpdate);
        return () => document.removeEventListener('force-header-update', handleForceUpdate);
    }, [sessionManager]);

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
    const displaySecurityLevel = realSecurityLevel || securityLevel;

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
                // Logo and Title
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
                        }, 'SecureBit.chat'),
                        React.createElement('p', {
                            key: 'subtitle',
                            className: 'text-xs sm:text-sm text-muted hidden sm:block'
                        }, 'End-to-end freedom. v4.1.1')
                    ])
                ]),

                // Status and Controls - Responsive
                React.createElement('div', {
                    key: 'status-section',
                    className: 'flex items-center space-x-2 sm:space-x-3'
                }, [
                    // Session Timer
                    shouldShowTimer && React.createElement(window.SessionTimer, {
                        key: 'session-timer',
                        timeLeft: currentTimeLeft,
                        sessionType: sessionType,
                        sessionManager: sessionManager
                    }),

                    // Security Level Indicator 
                    displaySecurityLevel && React.createElement('div', {
                        key: 'security-level',
                        className: 'hidden md:flex items-center space-x-2 cursor-pointer hover:opacity-80 transition-opacity duration-200',
                        onClick: handleSecurityClick,
                        title: `${displaySecurityLevel.level} (${displaySecurityLevel.score}%) - ${displaySecurityLevel.details || 'Click for details'}`
                    }, [
                        React.createElement('div', {
                            key: 'security-icon',
                            className: `w-6 h-6 rounded-full flex items-center justify-center ${
                                displaySecurityLevel.color === 'green' ? 'bg-green-500/20' :
                                displaySecurityLevel.color === 'yellow' ? 'bg-yellow-500/20' : 'bg-red-500/20'
                            }`
                        }, [
                            React.createElement('i', {
                                className: `fas fa-shield-alt text-xs ${
                                    displaySecurityLevel.color === 'green' ? 'text-green-400' :
                                    displaySecurityLevel.color === 'yellow' ? 'text-yellow-400' : 'text-red-400'
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
                            }, `${displaySecurityLevel.level} (${displaySecurityLevel.score}%)`),
                            React.createElement('div', {
                                key: 'security-details',
                                className: 'text-xs text-muted mt-1 hidden lg:block'
                            }, displaySecurityLevel.details || `Stage ${displaySecurityLevel.stage || 1}`),
                            React.createElement('div', {
                                key: 'security-progress',
                                className: 'w-16 h-1 bg-gray-600 rounded-full overflow-hidden'
                            }, [
                                React.createElement('div', {
                                    key: 'progress-bar',
                                    className: `h-full transition-all duration-500 ${
                                        displaySecurityLevel.color === 'green' ? 'bg-green-400' :
                                        displaySecurityLevel.color === 'yellow' ? 'bg-yellow-400' : 'bg-red-400'
                                    }`,
                                    style: { width: `${displaySecurityLevel.score}%` }
                                })
                            ])
                        ])
                    ]),

                    // Mobile Security Indicator
                    displaySecurityLevel && React.createElement('div', {
                        key: 'mobile-security',
                        className: 'md:hidden flex items-center'
                    }, [
                        React.createElement('div', {
                            key: 'mobile-security-icon',
                            className: `w-8 h-8 rounded-full flex items-center justify-center cursor-pointer hover:opacity-80 transition-opacity duration-200 ${
                                displaySecurityLevel.color === 'green' ? 'bg-green-500/20' :
                                displaySecurityLevel.color === 'yellow' ? 'bg-yellow-500/20' : 'bg-red-500/20'
                            }`,
                            title: `${displaySecurityLevel.level} (${displaySecurityLevel.score}%) - Click for details`,
                            onClick: handleSecurityClick
                        }, [
                            React.createElement('i', {
                                className: `fas fa-shield-alt text-sm ${
                                    displaySecurityLevel.color === 'green' ? 'text-green-400' :
                                    displaySecurityLevel.color === 'yellow' ? 'text-yellow-400' : 'text-red-400'
                                }`
                            })
                        ])
                    ]),

                    // Status Badge
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

                    // Disconnect Button
                    isConnected && React.createElement('button', {
                        key: 'disconnect-btn',
                        onClick: onDisconnect,
                        className: 'p-1.5 sm:px-3 sm:py-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 rounded-lg transition-all duration-200 text-sm'
                    }, [
                        React.createElement('i', {
                            className: 'fas fa-power-off sm:mr-2'
                        }),
                        React.createElement('span', {
                            className: 'hidden sm:inline'
                        }, 'Disconnect')
                    ])
                ])
            ])
        ])
    ]);
};

window.EnhancedMinimalHeader = EnhancedMinimalHeader;

console.log('✅ EnhancedMinimalHeader v4.1.1 loaded with real security status integration');