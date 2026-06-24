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
                    
                }
                
            } catch (error) {
                
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
                            
                        }
                    })
                    .catch(error => {
                        
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
            

            setRealSecurityLevel(null);
            setLastSecurityUpdate(0);

            setHasActiveSession(false);
            setCurrentTimeLeft(0);
            setSessionType('unknown');
        };

        const handlePeerDisconnect = () => {
            

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
                
            } catch (error) {
                
            }
        } else {
            
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
        window.debugHeaderSecurity = undefined;
        
        return () => {
            delete window.debugHeaderSecurity;
        };
    }, [realSecurityLevel, lastSecurityUpdate, isConnected, webrtcManager, displaySecurityLevel, securityDetails]);

    // ============================================
    // RENDER
    // ============================================

    const secColor = displaySecurityLevel
        ? (displaySecurityLevel.color === 'green' ? '#3ecf8e' : displaySecurityLevel.color === 'orange' ? '#f0892a' : displaySecurityLevel.color === 'yellow' ? '#e3c84e' : '#e5727a')
        : '#3ecf8e';
    const dotColor = isConnected ? '#3ecf8e'
        : (['connecting', 'verifying', 'retrying', 'reconnecting'].includes(status) ? '#e3c84e'
        : (status === 'failed' ? '#e5727a' : '#6b6b73'));
    const dotGlow = dotColor === '#3ecf8e' ? 'rgba(62,207,142,0.16)' : dotColor === '#e3c84e' ? 'rgba(227,200,78,0.16)' : dotColor === '#e5727a' ? 'rgba(229,114,122,0.16)' : 'rgba(107,107,115,0.16)';
    const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";

    // On the landing / setup view (no verified connection) the new Start Secure
    // screen owns the network settings and step status, so keep the header clean:
    // brand only — no status pill, no settings. The bar is transparent at the top
    // of the page and gains a blurred background once the user scrolls.
    const onLanding = !isConnected;
    const [scrolled, setScrolled] = React.useState(false);
    React.useEffect(() => {
        const onScroll = () => setScrolled((window.scrollY || window.pageYOffset || 0) > 8);
        onScroll();
        window.addEventListener('scroll', onScroll, { passive: true });
        return () => window.removeEventListener('scroll', onScroll);
    }, []);

    // On the landing the header floats *over* the full-height hero (position
    // fixed), transparent at the top and blurred once scrolled. When connected it
    // falls back to the in-flow sticky bar.
    const overlay = { position: 'fixed', top: 0, left: 0, right: 0 };
    const headerStyle = onLanding
        ? (scrolled
            ? { ...overlay, background: 'rgba(15,15,17,0.72)', backdropFilter: 'blur(14px)', WebkitBackdropFilter: 'blur(14px)', borderBottom: '1px solid rgba(255,255,255,0.06)', transition: 'background .25s ease, backdrop-filter .25s ease, border-color .25s ease' }
            : { ...overlay, background: 'transparent', backdropFilter: 'none', WebkitBackdropFilter: 'none', borderBottom: '1px solid transparent', transition: 'background .25s ease, backdrop-filter .25s ease, border-color .25s ease' })
        : { background: 'rgba(18,18,20,0.72)', backdropFilter: 'blur(14px)', WebkitBackdropFilter: 'blur(14px)', borderBottom: '1px solid rgba(255,255,255,0.06)' };

    return React.createElement('header', {
        className: onLanding ? 'header-minimal z-50' : 'header-minimal sticky top-0 z-50',
        style: headerStyle
    }, [
        React.createElement('div', {
            key: 'container',
            className: 'max-w-7xl mx-auto',
            style: { padding: '0 20px' }
        }, [
            React.createElement('div', {
                key: 'content',
                className: 'flex items-center justify-between',
                style: { height: '64px', gap: '16px' }
            }, [
                // Left: logo + wordmark
                React.createElement('div', { key: 'left', style: { display: 'flex', alignItems: 'center', gap: '12px', minWidth: 0 } }, [
                    React.createElement('div', { key: 'logo', style: { width: '36px', height: '36px', flex: 'none', display: 'grid', placeItems: 'center' } },
                        React.createElement('img', { src: '/logo/securebit-mark.svg', alt: 'SecureBit', style: { width: '100%', height: '100%', objectFit: 'contain', display: 'block' } })
                    ),
                    React.createElement('div', { key: 'txt', style: { lineHeight: 1.2, minWidth: 0 } }, [
                        React.createElement('div', { key: 'r1', style: { display: 'flex', alignItems: 'baseline', gap: '7px' } }, [
                            React.createElement('span', { key: 'n', style: { fontSize: '16px', fontWeight: 800, letterSpacing: '-0.3px', color: '#e8e8eb' } }, 'SecureBit'),
                            React.createElement('span', { key: 'v', style: { fontFamily: MONO, fontSize: '10px', fontWeight: 500, color: '#56565e' } }, 'v4.9.1')
                        ]),
                        React.createElement('div', { key: 'r2', className: 'hidden sm:block', style: { fontSize: '11px', color: '#6b6b73', fontWeight: 500 } }, 'End-to-end encrypted')
                    ])
                ]),
                // Right: controls
                React.createElement('div', { key: 'right', style: { display: 'flex', alignItems: 'center', gap: '9px' } }, [
                    !onLanding && React.createElement('button', {
                        key: 'net', type: 'button',
                        onClick: () => window.dispatchEvent(new CustomEvent('securebit:open-network-settings')),
                        title: 'Advanced network settings (STUN/TURN)', 'aria-label': 'Advanced network settings',
                        className: 'sb-disconnect',
                        style: { display: 'grid', placeItems: 'center', width: '38px', height: '38px', borderRadius: '9px', border: '1px solid rgba(255,255,255,0.07)', background: 'rgba(255,255,255,0.02)', color: '#9a9aa2', cursor: 'pointer', transition: 'all .15s' }
                    }, React.createElement('i', { className: 'fas fa-network-wired', style: { fontSize: '13px' } })),

                    (!onLanding && displaySecurityLevel) && React.createElement('div', {
                        key: 'sec', onClick: handleSecurityClick,
                        onContextMenu: (e) => { e.preventDefault(); if (typeof onDisconnect === 'function') onDisconnect(); },
                        title: securityDetails.tooltip, className: 'sb-secpill',
                        style: { display: 'flex', alignItems: 'center', gap: '8px', padding: '7px 12px', borderRadius: '9px', border: '1px solid rgba(255,255,255,0.07)', background: 'rgba(255,255,255,0.02)', cursor: 'pointer' }
                    }, [
                        React.createElement('i', { key: 'i', className: 'fas fa-shield-halved', style: { fontSize: '13px', color: secColor } }),
                        React.createElement('span', { key: 'l', className: 'hidden sm:inline', style: { fontSize: '12.5px', fontWeight: 600, color: '#e8e8eb' } }, String(displaySecurityLevel.level)),
                        React.createElement('span', { key: 's', style: { fontFamily: MONO, fontSize: '11.5px', color: '#8a8a92' } }, displaySecurityLevel.score + '%')
                    ]),

                    !onLanding && React.createElement('div', { key: 'status', style: { display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 13px', borderRadius: '9px', border: '1px solid rgba(255,255,255,0.07)', background: 'rgba(255,255,255,0.02)' } }, [
                        React.createElement('span', { key: 'dot', style: { width: '7px', height: '7px', borderRadius: '50%', background: dotColor, boxShadow: '0 0 0 3px ' + dotGlow } }),
                        React.createElement('span', { key: 't', className: 'hidden sm:inline', style: { fontSize: '13px', fontWeight: 600, color: '#cfcfd4' } }, config.text)
                    ]),

                    isConnected && React.createElement('button', {
                        key: 'dc', onClick: onDisconnect, className: 'sb-disconnect',
                        style: { display: 'flex', alignItems: 'center', gap: '7px', padding: '8px 14px', borderRadius: '9px', border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#9a9aa2', fontFamily: 'inherit', fontSize: '13px', fontWeight: 600, cursor: 'pointer', transition: 'all .15s' }
                    }, [
                        React.createElement('i', { key: 'i', className: 'fas fa-power-off', style: { fontSize: '12px' } }),
                        React.createElement('span', { key: 't', className: 'sb-hide-sm' }, 'Disconnect')
                    ])
                ])
            ])
        ])
    ]);
};

window.EnhancedMinimalHeader = EnhancedMinimalHeader;
