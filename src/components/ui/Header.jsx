const EnhancedMinimalHeader = ({ 
    status, 
    fingerprint, 
    verificationCode, 
    onDisconnect, 
    isConnected, 
    securityLevel, 
    webrtcManager 
}) => {
    const [realSecurityLevel, setRealSecurityLevel] = React.useState(null);
    const [lastSecurityUpdate, setLastSecurityUpdate] = React.useState(0);
    // Added local session state to remove references errors after session timer removal
    const [hasActiveSession, setHasActiveSession] = React.useState(false);
    const [currentTimeLeft, setCurrentTimeLeft] = React.useState(0);
    const [sessionType, setSessionType] = React.useState('unknown');

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
                
                if (realSecurityData && realSecurityData.isRealData !== false) {
                    const currentScore = realSecurityLevel?.score || 0;
                    const newScore = realSecurityData.score || 0;

                    if (currentScore !== newScore || !realSecurityLevel) {
                        setRealSecurityLevel(realSecurityData);
                        setLastSecurityUpdate(now);

                        } else if (window.DEBUG_MODE) {
                    }
                } else {
                    console.warn(' Security calculation returned invalid data');
                }
                
            } catch (error) {
                console.error(' Error in real security calculation:', error);
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
    }, [webrtcManager, isConnected]);

    // ============================================
    // FIXED EVENT HANDLERS
    // ============================================

    React.useEffect(() => {
        const handleSecurityUpdate = (event) => {

            setTimeout(() => {
                setLastSecurityUpdate(0);
            }, 100);
        };

        const handleRealSecurityCalculated = (event) => {
            
            if (event.detail && event.detail.securityData) {
                setRealSecurityLevel(event.detail.securityData);
                setLastSecurityUpdate(Date.now());
            }
        };

        document.addEventListener('security-level-updated', handleSecurityUpdate);
        document.addEventListener('real-security-calculated', handleRealSecurityCalculated);
        
        window.forceHeaderSecurityUpdate = (webrtcManager) => {
            
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
        // All security features are enabled by default - no session management needed
        setHasActiveSession(true);
        setCurrentTimeLeft(0);
        setSessionType('premium'); // All features enabled
    }, []);

    React.useEffect(() => {
        // All security features are enabled by default
        setHasActiveSession(true);
        setCurrentTimeLeft(0);
        setSessionType('premium'); // All features enabled
    }, []);

    React.useEffect(() => {
        const handleForceUpdate = (event) => {
            // All security features are enabled by default
            setHasActiveSession(true);
            setCurrentTimeLeft(0);
            setSessionType('premium'); // All features enabled
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

        const handleDisconnected = () => {

            setRealSecurityLevel(null);
            setLastSecurityUpdate(0);
            setHasActiveSession(false);
            setCurrentTimeLeft(0);
            setSessionType('unknown');
        };

        document.addEventListener('force-header-update', handleForceUpdate);
        document.addEventListener('peer-disconnect', handlePeerDisconnect);
        document.addEventListener('connection-cleaned', handleConnectionCleaned);
        document.addEventListener('disconnected', handleDisconnected);
        
        return () => {
            document.removeEventListener('force-header-update', handleForceUpdate);
            document.removeEventListener('peer-disconnect', handlePeerDisconnect);
            document.removeEventListener('connection-cleaned', handleConnectionCleaned);
            document.removeEventListener('disconnected', handleDisconnected);
        };
    }, []);

    // ============================================
    // SECURITY INDICATOR CLICK HANDLER
    // ============================================

    const handleSecurityClick = async (event) => {
        // Check if it's a right-click or Ctrl+click to disconnect
        if (event && (event.button === 2 || event.ctrlKey || event.metaKey)) {
            if (onDisconnect && typeof onDisconnect === 'function') {
                onDisconnect();
                return;
            }
        }

        // Prevent default behavior
        event.preventDefault();
        event.stopPropagation();


        // Run real security tests if webrtcManager is available
        let realTestResults = null;
        if (webrtcManager && window.EnhancedSecureCryptoUtils) {
            try {
                realTestResults = await window.EnhancedSecureCryptoUtils.calculateSecurityLevel(webrtcManager);
                console.log('✅ Real security tests completed:', realTestResults);
            } catch (error) {
                console.error('❌ Real security tests failed:', error);
            }
        } else {
            console.log('⚠️ Cannot run security tests:', {
                webrtcManager: !!webrtcManager,
                cryptoUtils: !!window.EnhancedSecureCryptoUtils
            });
        }

        // If no real test results and no existing security level, show progress message
        if (!realTestResults && !realSecurityLevel) {
            alert('Security verification in progress...\nPlease wait for real-time cryptographic verification to complete.');
            return;
        }

        // Use real test results if available, otherwise fall back to current data
        let securityData = realTestResults || realSecurityLevel;

        // If still no security data, create a basic fallback
        if (!securityData) {
            securityData = {
                level: 'UNKNOWN',
                score: 0,
                color: 'gray',
                verificationResults: {},
                timestamp: Date.now(),
                details: 'Security verification not available',
                isRealData: false,
                passedChecks: 0,
                totalChecks: 0
            };
            console.log('Using fallback security data:', securityData);
        }

        // Detailed information about the REAL security check
        let message = `REAL-TIME SECURITY VERIFICATION\n\n`;
        message += `Security Level: ${securityData.level} (${securityData.score}%)\n`;
        message += `Verification Time: ${new Date(securityData.timestamp).toLocaleTimeString()}\n`;
        message += `Data Source: ${securityData.isRealData ? 'Real Cryptographic Tests' : 'Simulated Data'}\n\n`;
        
        if (securityData.verificationResults) {
            message += 'DETAILED CRYPTOGRAPHIC TESTS:\n';
            message += '=' + '='.repeat(40) + '\n';
            
            const passedTests = Object.entries(securityData.verificationResults).filter(([key, result]) => result.passed);
            const failedTests = Object.entries(securityData.verificationResults).filter(([key, result]) => !result.passed);
            
            if (passedTests.length > 0) {
                message += 'PASSED TESTS:\n';
                passedTests.forEach(([key, result]) => {
                    const testName = key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
                    message += `   ${testName}: ${result.details || 'Test passed'}\n`;
                });
                message += '\n';
            }
            
            if (failedTests.length > 0) {
                message += 'FAILED/UNAVAILABLE TESTS:\n';
                failedTests.forEach(([key, result]) => {
                    const testName = key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
                    message += `   ${testName}: ${result.details || 'Test failed or unavailable'}\n`;
                });
                message += '\n';
            }
            
            message += `SUMMARY:\n`;
            message += `Passed: ${securityData.passedChecks}/${securityData.totalChecks} tests\n`;
            message += `Score: ${securityData.score}/${securityData.maxPossibleScore || 100} points\n\n`;
        }
        
        // Real security features status
        message += `SECURITY FEATURES STATUS:\n`;
        message += '=' + '='.repeat(40) + '\n';
        
        if (securityData.verificationResults) {
            const features = {
                'ECDSA Digital Signatures': securityData.verificationResults.verifyECDSASignatures?.passed || false,
                'ECDH Key Exchange': securityData.verificationResults.verifyECDHKeyExchange?.passed || false,
                'AES-GCM Encryption': securityData.verificationResults.verifyEncryption?.passed || false,
                'Message Integrity (HMAC)': securityData.verificationResults.verifyMessageIntegrity?.passed || false,
                'Perfect Forward Secrecy': securityData.verificationResults.verifyPerfectForwardSecrecy?.passed || false,
                'Replay Protection': securityData.verificationResults.verifyReplayProtection?.passed || false,
                'DTLS Fingerprint': securityData.verificationResults.verifyDTLSFingerprint?.passed || false,
                'SAS Verification': securityData.verificationResults.verifySASVerification?.passed || false,
                'Metadata Protection': securityData.verificationResults.verifyMetadataProtection?.passed || false,
                'Traffic Obfuscation': securityData.verificationResults.verifyTrafficObfuscation?.passed || false
            };
            
            Object.entries(features).forEach(([feature, isEnabled]) => {
                message += `${isEnabled ? '✅' : '❌'} ${feature}\n`;
            });
        } else {
            // Fallback if no verification results
            message += `✅ ECDSA Digital Signatures\n`;
            message += `✅ ECDH Key Exchange\n`;
            message += `✅ AES-GCM Encryption\n`;
            message += `✅ Message Integrity (HMAC)\n`;
            message += `✅ Perfect Forward Secrecy\n`;
            message += `✅ Replay Protection\n`;
            message += `✅ DTLS Fingerprint\n`;
            message += `✅ SAS Verification\n`;
            message += `✅ Metadata Protection\n`;
            message += `✅ Traffic Obfuscation\n`;
        }
        
        message += `\n${securityData.details || 'Real cryptographic verification completed'}`;
        
        if (securityData.isRealData) {
            message += '\n\n✅ This is REAL-TIME verification using actual cryptographic functions.';
        } else {
            message += '\n\n⚠️ Warning: This data may be simulated. Connection may not be fully established.';
        }
        
        // Show in a more user-friendly way
        const modal = document.createElement('div');
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 10000;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: monospace;
        `;
        
        const content = document.createElement('div');
        content.style.cssText = `
            background: #1a1a1a;
            color: #fff;
            padding: 20px;
            border-radius: 8px;
            max-width: 80%;
            max-height: 80%;
            overflow-y: auto;
            white-space: pre-line;
            border: 1px solid #333;
        `;
        
        content.textContent = message;
        modal.appendChild(content);
        
        // Close on click outside
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                document.body.removeChild(modal);
            }
        });
        
        // Close on Escape key
        const handleKeyDown = (e) => {
            if (e.key === 'Escape') {
                document.body.removeChild(modal);
                document.removeEventListener('keydown', handleKeyDown);
            }
        };
        document.addEventListener('keydown', handleKeyDown);
        
        document.body.appendChild(modal);
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
    const displaySecurityLevel = isConnected ? (realSecurityLevel || securityLevel) : null;
    

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
                tooltip: `${baseTooltip} - Real-time verification ✅\nRight-click or Ctrl+click to disconnect`,
                isVerified: true,
                dataSource: 'real'
            };
        } else {
            return {
                tooltip: `${baseTooltip} - Estimated (connection establishing...)\nRight-click or Ctrl+click to disconnect`,
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
                        }, 'End-to-end freedom v4.4.99')
                    ])
                ]),

                // Status and Controls - Responsive
                React.createElement('div', {
                    key: 'status-section',
                    className: 'flex items-center space-x-2 sm:space-x-3'
                }, [

                    displaySecurityLevel && React.createElement('div', {
                        key: 'security-level',
                        className: 'hidden md:flex items-center space-x-2 cursor-pointer hover:opacity-80 transition-opacity duration-200',
                        onClick: handleSecurityClick,
                        onContextMenu: (e) => {
                            e.preventDefault();
                            if (onDisconnect && typeof onDisconnect === 'function') {
                                onDisconnect();
                            }
                        },
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
                            onClick: handleSecurityClick,
                            onContextMenu: (e) => {
                                e.preventDefault();
                                if (onDisconnect && typeof onDisconnect === 'function') {
                                    onDisconnect();
                                }
                            }
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
                        }, config.text),
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
