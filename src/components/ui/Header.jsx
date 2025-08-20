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
    const [lastSecurityUpdate, setLastSecurityUpdate] = React.useState(0);

    // ============================================
    // FIXED SECURITY UPDATE LOGIC
    // ============================================
    
    React.useEffect(() => {
        let isUpdating = false; 
        let lastUpdateAttempt = 0; 
        
        const updateRealSecurityStatus = async () => {
            const now = Date.now();
            if (now - lastUpdateAttempt < 10000) { 
                return;
            }

            if (isUpdating) {
                return;
            }
            
            isUpdating = true;
            lastUpdateAttempt = now;
            
            try {
                if (!webrtcManager || !isConnected) {
                    return;
                }
                
                const activeWebrtcManager = webrtcManager;
                
                let realSecurityData = null;
                
                if (typeof activeWebrtcManager.getRealSecurityLevel === 'function') {
                    realSecurityData = await activeWebrtcManager.getRealSecurityLevel();
                } else if (typeof activeWebrtcManager.calculateAndReportSecurityLevel === 'function') {
                    realSecurityData = await activeWebrtcManager.calculateAndReportSecurityLevel();
                } else {
                    realSecurityData = await window.EnhancedSecureCryptoUtils.calculateSecurityLevel(activeWebrtcManager);
                }
                
                if (window.DEBUG_MODE) {
                    console.log('🔐 REAL security level calculated:', {
                        level: realSecurityData?.level,
                        score: realSecurityData?.score,
                        passedChecks: realSecurityData?.passedChecks,
                        totalChecks: realSecurityData?.totalChecks,
                        isRealData: realSecurityData?.isRealData,
                        sessionType: realSecurityData?.sessionType,
                        maxPossibleScore: realSecurityData?.maxPossibleScore,
                        verificationResults: realSecurityData?.verificationResults ? Object.keys(realSecurityData.verificationResults) : []
                    });
                }
                
                if (realSecurityData && realSecurityData.isRealData !== false) {
                    const currentScore = realSecurityLevel?.score || 0;
                    const newScore = realSecurityData.score || 0;

                    if (currentScore !== newScore || !realSecurityLevel) {
                        setRealSecurityLevel(realSecurityData);
                        setLastSecurityUpdate(now);
                        
                        if (window.DEBUG_MODE) {
                            console.log('✅ Security level updated in header component:', {
                                oldScore: currentScore,
                                newScore: newScore,
                                sessionType: realSecurityData.sessionType
                            });
                        }
                    } else if (window.DEBUG_MODE) {
                        console.log('ℹ️ Security level unchanged, skipping update');
                    }
                } else {
                    console.warn('⚠️ Security calculation returned invalid data');
                }
                
            } catch (error) {
                console.error('❌ Error in real security calculation:', error);
            } finally {
                isUpdating = false;
            }
        };

        if (isConnected) {
            updateRealSecurityStatus();
            
            if (!realSecurityLevel || realSecurityLevel.score < 50) {
                const retryInterval = setInterval(() => {
                    if (!realSecurityLevel || realSecurityLevel.score < 50) {
                        updateRealSecurityStatus();
                    } else {
                        clearInterval(retryInterval);
                    }
                }, 5000); 
                
                setTimeout(() => clearInterval(retryInterval), 30000);
            }
        }

        const interval = setInterval(updateRealSecurityStatus, 30000);
        
        return () => clearInterval(interval);
    }, [webrtcManager, isConnected, lastSecurityUpdate, realSecurityLevel]);

    // ============================================
    // FIXED EVENT HANDLERS
    // ============================================

    React.useEffect(() => {
        const handleSecurityUpdate = (event) => {
            if (window.DEBUG_MODE) {
                console.log('🔒 Security level update event received:', event.detail);
            }

            setTimeout(() => {
                setLastSecurityUpdate(0);
            }, 100);
        };

        const handleRealSecurityCalculated = (event) => {
            if (window.DEBUG_MODE) {
                console.log('🔐 Real security calculated event:', event.detail);
            }
            
            if (event.detail && event.detail.securityData) {
                setRealSecurityLevel(event.detail.securityData);
                setLastSecurityUpdate(Date.now());
            }
        };

        document.addEventListener('security-level-updated', handleSecurityUpdate);
        document.addEventListener('real-security-calculated', handleRealSecurityCalculated);
        
        window.forceHeaderSecurityUpdate = (webrtcManager) => {
            if (window.DEBUG_MODE) {
                console.log('🔄 Force header security update called');
            }
            
            if (webrtcManager && window.EnhancedSecureCryptoUtils) {
                window.EnhancedSecureCryptoUtils.calculateSecurityLevel(webrtcManager)
                    .then(securityData => {
                        if (securityData && securityData.isRealData !== false) {
                            setRealSecurityLevel(securityData);
                            setLastSecurityUpdate(Date.now());
                            console.log('✅ Header security level force-updated');
                        }
                    })
                    .catch(error => {
                        console.error('❌ Force update failed:', error);
                    });
            } else {
                setLastSecurityUpdate(0); 
            }
        };

        return () => {
            document.removeEventListener('security-level-updated', handleSecurityUpdate);
            document.removeEventListener('real-security-calculated', handleRealSecurityCalculated);
        };
    }, []);

    // ============================================
    // REST of the component logic
    // ============================================

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
        if (sessionManager?.hasActiveSession()) {
            setCurrentTimeLeft(sessionManager.getTimeLeft());
            setHasActiveSession(true);
        } else {
            setHasActiveSession(false);
            setRealSecurityLevel(null);
            setLastSecurityUpdate(0);
            setSessionType('unknown');
        }
    }, [sessionManager, sessionTimeLeft]);

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

        // Connection cleanup handler (use existing event from module)
        const handleConnectionCleaned = () => {
            if (window.DEBUG_MODE) {
                console.log('🧹 Connection cleaned - clearing security data in header');
            }

            setRealSecurityLevel(null);
            setLastSecurityUpdate(0);

            setHasActiveSession(false);
            setCurrentTimeLeft(0);
            setSessionType('unknown');
        };

        const handlePeerDisconnect = () => {
            if (window.DEBUG_MODE) {
                console.log('👋 Peer disconnect detected - clearing security data in header');
            }

            setRealSecurityLevel(null);
            setLastSecurityUpdate(0);
        };

        document.addEventListener('force-header-update', handleForceUpdate);
        document.addEventListener('peer-disconnect', handlePeerDisconnect);
        document.addEventListener('connection-cleaned', handleConnectionCleaned);
        
        return () => {
            document.removeEventListener('force-header-update', handleForceUpdate);
            document.removeEventListener('peer-disconnect', handlePeerDisconnect);
            document.removeEventListener('connection-cleaned', handleConnectionCleaned);
        };
    }, [sessionManager]);

    // ============================================
    // SECURITY INDICATOR CLICK HANDLER
    // ============================================

    const handleSecurityClick = () => {
        if (!realSecurityLevel) {
            alert('Security verification in progress...\nPlease wait for real-time cryptographic verification to complete.');
            return;
        }

        // Detailed information about the REAL security check
        let message = `🔒 REAL-TIME SECURITY VERIFICATION\n\n`;
        message += `Security Level: ${realSecurityLevel.level} (${realSecurityLevel.score}%)\n`;
        message += `Session Type: ${realSecurityLevel.sessionType || 'demo'}\n`;
        message += `Verification Time: ${new Date(realSecurityLevel.timestamp).toLocaleTimeString()}\n`;
        message += `Data Source: ${realSecurityLevel.isRealData ? 'Real Cryptographic Tests' : 'Simulated Data'}\n\n`;
        
        if (realSecurityLevel.verificationResults) {
            message += 'DETAILED CRYPTOGRAPHIC TESTS:\n';
            message += '=' + '='.repeat(40) + '\n';
            
            const passedTests = Object.entries(realSecurityLevel.verificationResults).filter(([key, result]) => result.passed);
            const failedTests = Object.entries(realSecurityLevel.verificationResults).filter(([key, result]) => !result.passed);
            
            if (passedTests.length > 0) {
                message += '✅ PASSED TESTS:\n';
                passedTests.forEach(([key, result]) => {
                    const testName = key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
                    message += `   ${testName}: ${result.details}\n`;
                });
                message += '\n';
            }
            
            if (failedTests.length > 0) {
                message += '❌ UNAVAILABLE/Failed TESTS:\n';
                failedTests.forEach(([key, result]) => {
                    const testName = key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
                    message += `   ${testName}: ${result.details}\n`;
                });
                message += '\n';
            }
            
            message += `SUMMARY:\n`;
            message += `Passed: ${realSecurityLevel.passedChecks}/${realSecurityLevel.totalChecks} tests\n`;
        }
        
        // Add information about what is available in other sessions
        message += `\n📋 WHAT'S AVAILABLE IN OTHER SESSIONS:\n`;
        message += '=' + '='.repeat(40) + '\n';
        
        if (realSecurityLevel.sessionType === 'demo') {
            message += `🔒 BASIC SESSION (5,000 sat - $2.00):\n`;
            message += `   • ECDSA Digital Signatures\n`;
            message += `   • Metadata Protection\n`;
            message += `   • Perfect Forward Secrecy\n`;
            message += `   • Nested Encryption\n`;
            message += `   • Packet Padding\n\n`;
            
            message += `🚀 PREMIUM SESSION (20,000 sat - $8.00):\n`;
            message += `   • All Basic + Enhanced features\n`;
            message += `   • Traffic Obfuscation\n`;
            message += `   • Fake Traffic Generation\n`;
            message += `   • Decoy Channels\n`;
            message += `   • Anti-Fingerprinting\n`;
            message += `   • Message Chunking\n`;
            message += `   • Advanced Replay Protection\n`;
        } else if (realSecurityLevel.sessionType === 'basic') {
            message += `🚀 PREMIUM SESSION (20,000 sat - $8.00):\n`;
            message += `   • Traffic Obfuscation\n`;
            message += `   • Fake Traffic Generation\n`;
            message += `   • Decoy Channels\n`;
            message += `   • Anti-Fingerprinting\n`;
            message += `   • Message Chunking\n`;
            message += `   • Advanced Replay Protection\n`;
        }
        
        message += `\n${realSecurityLevel.details || 'Real cryptographic verification completed'}`;
        
        if (realSecurityLevel.isRealData) {
            message += '\n\n✅ This is REAL-TIME verification using actual cryptographic functions.';
        } else {
            message += '\n\n⚠️ Warning: This data may be simulated. Connection may not be fully established.';
        }
        
        alert(message);
    };

    // ============================================
    // DISPLAY UTILITIES
    // ============================================

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
    
    const shouldShowTimer = hasActiveSession && currentTimeLeft > 0 && window.SessionTimer;

    // ============================================
    // DATA RELIABILITY INDICATOR
    // ============================================

    const getSecurityIndicatorDetails = () => {
        if (!displaySecurityLevel) {
            return {
                tooltip: 'Security verification in progress...',
                isVerified: false,
                dataSource: 'loading'
            };
        }
        
        const isRealData = displaySecurityLevel.isRealData !== false;
        const baseTooltip = `${displaySecurityLevel.level} (${displaySecurityLevel.score}%)`;
        
        if (isRealData) {
            return {
                tooltip: `${baseTooltip} - Real-time verification ✅`,
                isVerified: true,
                dataSource: 'real'
            };
        } else {
            return {
                tooltip: `${baseTooltip} - Estimated (connection establishing...)`,
                isVerified: false,
                dataSource: 'estimated'
            };
        }
    };

    const securityDetails = getSecurityIndicatorDetails();

    // ============================================
    // ADDING global methods for debugging
    // ============================================

    React.useEffect(() => {
        window.debugHeaderSecurity = () => {
            console.log('🔍 Header Security Debug:', {
                realSecurityLevel,
                lastSecurityUpdate,
                isConnected,
                webrtcManagerProp: !!webrtcManager,
                windowWebrtcManager: !!window.webrtcManager,
                cryptoUtils: !!window.EnhancedSecureCryptoUtils,
                displaySecurityLevel: displaySecurityLevel,
                securityDetails: securityDetails
            });
        };
        
        return () => {
            delete window.debugHeaderSecurity;
        };
    }, [realSecurityLevel, lastSecurityUpdate, isConnected, webrtcManager, displaySecurityLevel, securityDetails]);

    // ============================================
    // RENDER
    // ============================================

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
                        }, 'End-to-end freedom. v4.01.222')
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

                    displaySecurityLevel && React.createElement('div', {
                        key: 'security-level',
                        className: 'hidden md:flex items-center space-x-2 cursor-pointer hover:opacity-80 transition-opacity duration-200',
                        onClick: handleSecurityClick,
                        title: securityDetails.tooltip
                    }, [
                        React.createElement('div', {
                            key: 'security-icon',
                            className: `w-6 h-6 rounded-full flex items-center justify-center relative ${
                                displaySecurityLevel.color === 'green' ? 'bg-green-500/20' :
                                displaySecurityLevel.color === 'orange' ? 'bg-orange-500/20' :
                                displaySecurityLevel.color === 'yellow' ? 'bg-yellow-500/20' : 'bg-red-500/20'
                            } ${securityDetails.isVerified ? '' : 'animate-pulse'}`
                        }, [
                            React.createElement('i', {
                                className: `fas fa-shield-alt text-xs ${
                                    displaySecurityLevel.color === 'green' ? 'text-green-400' :
                                    displaySecurityLevel.color === 'orange' ? 'text-orange-400' :
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
                                className: 'text-xs font-medium text-primary flex items-center space-x-1'
                            }, [
                                React.createElement('span', {}, `${displaySecurityLevel.level} (${displaySecurityLevel.score}%)`)
                            ]),
                            React.createElement('div', {
                                key: 'security-details',
                                className: 'text-xs text-muted mt-1 hidden lg:block'
                            }, securityDetails.dataSource === 'real' ? 
                                `${displaySecurityLevel.passedChecks || 0}/${displaySecurityLevel.totalChecks || 0} tests` :
                                (displaySecurityLevel.details || `Stage ${displaySecurityLevel.stage || 1}`)
                            ),
                            React.createElement('div', {
                                key: 'security-progress',
                                className: 'w-16 h-1 bg-gray-600 rounded-full overflow-hidden'
                            }, [
                                React.createElement('div', {
                                    key: 'progress-bar',
                                    className: `h-full transition-all duration-500 ${
                                        displaySecurityLevel.color === 'green' ? 'bg-green-400' :
                                        displaySecurityLevel.color === 'orange' ? 'bg-orange-400' :
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
                            className: `w-8 h-8 rounded-full flex items-center justify-center cursor-pointer hover:opacity-80 transition-opacity duration-200 relative ${
                                displaySecurityLevel.color === 'green' ? 'bg-green-500/20' :
                                displaySecurityLevel.color === 'orange' ? 'bg-orange-500/20' :
                                displaySecurityLevel.color === 'yellow' ? 'bg-yellow-500/20' : 'bg-red-500/20'
                            } ${securityDetails.isVerified ? '' : 'animate-pulse'}`,
                            title: securityDetails.tooltip,
                            onClick: handleSecurityClick
                        }, [
                            React.createElement('i', {
                                className: `fas fa-shield-alt text-sm ${
                                    displaySecurityLevel.color === 'green' ? 'text-green-400' :
                                    displaySecurityLevel.color === 'orange' ? 'text-orange-400' :
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
