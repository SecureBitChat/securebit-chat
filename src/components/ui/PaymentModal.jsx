const React = window.React;
const { useState, useEffect, useRef } = React;

const PaymentModal = ({ isOpen, onClose, sessionManager, onSessionPurchased }) => {
    const [step, setStep] = React.useState('select');
    const [selectedType, setSelectedType] = React.useState(null);
    const [invoice, setInvoice] = React.useState(null);
    const [paymentStatus, setPaymentStatus] = React.useState('pending');
    const [error, setError] = React.useState('');
    const [paymentMethod, setPaymentMethod] = React.useState('webln'); 
    const [preimageInput, setPreimageInput] = React.useState('');
    const [isProcessing, setIsProcessing] = React.useState(false);
    const [qrCodeUrl, setQrCodeUrl] = React.useState('');
    const [paymentTimer, setPaymentTimer] = React.useState(null);
    const [timeLeft, setTimeLeft] = React.useState(0);
    const [showSecurityDetails, setShowSecurityDetails] = React.useState(false);
    const pollInterval = React.useRef(null);

    React.useEffect(() => {
        if (!isOpen) {
            resetModal();
            if (pollInterval.current) {
                clearInterval(pollInterval.current);
            }
            if (paymentTimer) {
                clearInterval(paymentTimer);
            }
        }
    }, [isOpen]);

    const resetModal = () => {
        setStep('select');
        setSelectedType(null);
        setInvoice(null);
        setPaymentStatus('pending');
        setError('');
        setPaymentMethod('webln');
        setPreimageInput('');
        setIsProcessing(false);
        setQrCodeUrl('');
        setTimeLeft(0);
        setShowSecurityDetails(false);
    };

    const getSecurityFeaturesInfo = (sessionType) => {
        const features = {
            demo: {
                title: 'Demo Session - Basic Security',
                description: 'Limited testing session with basic security features',
                available: [
                    '🔐 Basic end-to-end encryption (AES-GCM 256)',
                    '🔑 Simple key exchange (ECDH P-384)',
                    '✅ Message integrity verification',
                    '⚡ Rate limiting protection'
                ],
                unavailable: [
                    '🔐 ECDSA Digital Signatures',
                    '🛡️ Metadata Protection',
                    '🔄 Perfect Forward Secrecy',
                    '🔐 Nested Encryption',
                    '📦 Packet Padding',
                    '🎭 Traffic Obfuscation',
                    '🎪 Fake Traffic Generation',
                    '🕵️ Decoy Channels',
                    '🚫 Anti-Fingerprinting',
                    '📝 Message Chunking',
                    '🔄 Advanced Replay Protection'
                ],
                upgrade: {
                    next: 'Basic Session (5,000 sat - $2.00)',
                    features: [
                        '🔐 ECDSA Digital Signatures',
                        '🛡️ Metadata Protection',
                        '🔄 Perfect Forward Secrecy',
                        '🔐 Nested Encryption',
                        '📦 Packet Padding'
                    ]
                }
            },
            basic: {
                title: 'Basic Session - Enhanced Security',
                description: 'Full featured session with enhanced security features',
                available: [
                    '🔐 Basic end-to-end encryption (AES-GCM 256)',
                    '🔑 Simple key exchange (ECDH P-384)',
                    '✅ Message integrity verification',
                    '⚡ Rate limiting protection',
                    '🔐 ECDSA Digital Signatures',
                    '🛡️ Metadata Protection',
                    '🔄 Perfect Forward Secrecy',
                    '🔐 Nested Encryption',
                    '📦 Packet Padding',
                    '🔒 Complete ASN.1 validation',
                    '🔍 OID and EC point verification',
                    '🏗️ SPKI structure validation',
                    '🛡️ 18-layer security architecture'
                ],
                unavailable: [
                    '🎭 Traffic Obfuscation',
                    '🎪 Fake Traffic Generation',
                    '🕵️ Decoy Channels',
                    '🚫 Anti-Fingerprinting',
                    '📝 Message Chunking',
                    '🔄 Advanced Replay Protection'
                ],
                upgrade: {
                    next: 'Premium Session (20,000 sat - $8.00)',
                    features: [
                        '🎭 Traffic Obfuscation',
                        '🎪 Fake Traffic Generation',
                        '🕵️ Decoy Channels',
                        '🚫 Anti-Fingerprinting',
                        '📝 Message Chunking',
                        '🔄 Advanced Replay Protection'
                    ]
                }
            },
            premium: {
                title: 'Premium Session - Maximum Security',
                description: 'Extended session with maximum security protection',
                available: [
                    '🔐 Basic end-to-end encryption (AES-GCM 256)',
                    '🔑 Simple key exchange (ECDH P-384)',
                    '✅ Message integrity verification',
                    '⚡ Rate limiting protection',
                    '🔐 ECDSA Digital Signatures',
                    '🛡️ Metadata Protection',
                    '🔄 Perfect Forward Secrecy',
                    '🔐 Nested Encryption',
                    '📦 Packet Padding',
                    '🎭 Traffic Obfuscation',
                    '🎪 Fake Traffic Generation',
                    '🕵️ Decoy Channels',
                    '🚫 Anti-Fingerprinting',
                    '📝 Message Chunking',
                    '🔄 Advanced Replay Protection',
                    '🔒 Complete ASN.1 validation',
                    '🔍 OID and EC point verification',
                    '🏗️ SPKI structure validation',
                    '🛡️ 18-layer security architecture',
                    '🚀 ASN.1 Validated'
                ],
                unavailable: [],
                upgrade: {
                    next: 'Maximum security achieved!',
                    features: ['🎉 All security features unlocked!']
                }
            }
        };
        
        return features[sessionType] || features.demo;
    };

    const handleSelectType = async (type) => {
        setSelectedType(type);
        setError('');
        
        if (type === 'demo') {
            try {
                if (!sessionManager || !sessionManager.createDemoSession) {
                    throw new Error('Demo session manager not available');
                }
                
                const demoSession = sessionManager.createDemoSession();
                if (!demoSession.success) {
                    throw new Error(demoSession.reason);
                }
                
                setInvoice({ 
                    sessionType: 'demo',
                    amount: 0,
                    paymentHash: demoSession.paymentHash,
                    memo: `Demo session (${demoSession.durationMinutes} minutes)`,
                    createdAt: Date.now(),
                    isDemo: true,
                    preimage: demoSession.preimage,
                    warning: demoSession.warning,
                    securityLevel: 'Basic'
                });
                setPaymentStatus('demo');
            } catch (error) {
                setError(`Demo session creation failed: ${error.message}`);
                return;
            }
        } else {
            await createRealInvoice(type);
        }
        setStep('payment');
    };

    const createRealInvoice = async (type) => {
        setPaymentStatus('creating');
        setIsProcessing(true);
        setError('');

        try {
            console.log(`Creating Lightning invoice for ${type} session...`);
            
            if (!sessionManager) {
                throw new Error('Session manager not initialized');
            }

            const createdInvoice = await sessionManager.createLightningInvoice(type);
            
            if (!createdInvoice || !createdInvoice.paymentRequest) {
                throw new Error('Failed to create Lightning invoice');
            }

            createdInvoice.securityLevel = sessionManager.getSecurityLevelForSession(type);

            setInvoice(createdInvoice);
            setPaymentStatus('created');

            try {
                const dataUrl = await window.generateQRCode(createdInvoice.paymentRequest, { size: 300, margin: 2, errorCorrectionLevel: 'M' });
                setQrCodeUrl(dataUrl);
            } catch (e) {
                console.warn('QR local generation failed, showing placeholder');
                const dataUrl = await window.generateQRCode(createdInvoice.paymentRequest, { size: 300 });
                setQrCodeUrl(dataUrl);
            }

            const expirationTime = 15 * 60 * 1000;
            setTimeLeft(expirationTime);
            
            const timer = setInterval(() => {
                setTimeLeft(prev => {
                    const newTime = prev - 1000;
                    if (newTime <= 0) {
                        clearInterval(timer);
                        setPaymentStatus('expired');
                        setError('Payment time has expired. Create a new invoice.');
                        return 0;
                    }
                    return newTime;
                });
            }, 1000);
            setPaymentTimer(timer);

            startPaymentPolling(createdInvoice.checkingId);

            console.log('✅ Lightning invoice created successfully:', createdInvoice);

        } catch (err) {
            console.error('❌ Invoice creation failed:', err);
            setError(`Invoice creation error: ${err.message}`);
            setPaymentStatus('failed');
        } finally {
            setIsProcessing(false);
        }
    };

    const startPaymentPolling = (checkingId) => {
        if (pollInterval.current) {
            clearInterval(pollInterval.current);
        }

        pollInterval.current = setInterval(async () => {
            try {
                const status = await sessionManager.checkPaymentStatus(checkingId);
                
                if (status.paid && status.preimage) {
                    clearInterval(pollInterval.current);
                    setPaymentStatus('paid');
                    await handlePaymentSuccess(status.preimage);
                }
            } catch (error) {
                console.warn('Payment status check failed:', error);
            }
        }, 3000); 
    };

    const handleWebLNPayment = async () => {
        if (!window.webln) {
            setError('WebLN is not supported. Please install the Alby or Zeus wallet.');
            return;
        }

        if (!invoice || !invoice.paymentRequest) {
            setError('Invoice is not ready for payment.');
            return;
        }

        setIsProcessing(true);
        setError('');
        setPaymentStatus('paying');

        try {
            await window.webln.enable();
            
            const result = await window.webln.sendPayment(invoice.paymentRequest);
            
            if (result.preimage) {
                setPaymentStatus('paid');
                await handlePaymentSuccess(result.preimage);
            } else {
                throw new Error('Payment does not contain preimage');
            }
        } catch (err) {
            console.error('❌ WebLN payment failed:', err);
            setError(`WebLN payment error: ${err.message}`);
            setPaymentStatus('created'); 
        } finally {
            setIsProcessing(false);
        }
    };

    const handleManualVerification = async () => {
        const trimmedPreimage = preimageInput.trim();
        
        if (!trimmedPreimage) {
            setError('Enter payment preimage');
            return;
        }
        
        if (trimmedPreimage.length !== 64) {
            setError('The preimage must be exactly 64 characters long.');
            return;
        }
        
        if (!/^[0-9a-fA-F]{64}$/.test(trimmedPreimage)) {
            setError('The preimage must contain only hexadecimal characters (0-9, a-f, A-F).');
            return;
        }
        
        const dummyPreimages = ['1'.repeat(64), 'a'.repeat(64), 'f'.repeat(64), '0'.repeat(64)];
        if (dummyPreimages.includes(trimmedPreimage) && selectedType !== 'demo') {
            setError('The entered preimage is invalid. Please use the actual preimage from the payment.');
            return;
        }
        
        setIsProcessing(true);
        setError('');
        setPaymentStatus('paying');

        try {
            await handlePaymentSuccess(trimmedPreimage);
        } catch (err) {
            setError(err.message);
            setPaymentStatus('created');
        } finally {
            setIsProcessing(false);
        }
    };

    const handleDemoSession = async () => {
        setIsProcessing(true);
        setError('');
        
        try {
            if (!invoice?.preimage) {
                throw new Error('Demo preimage not available');
            }
            
            const isValid = await sessionManager.verifyPayment(invoice.preimage, invoice.paymentHash);
            
            if (isValid && isValid.verified) {
                onSessionPurchased({ 
                    type: 'demo', 
                    preimage: invoice.preimage,
                    paymentHash: invoice.paymentHash,
                    amount: 0,
                    isDemo: true,
                    warning: invoice.warning,
                    securityLevel: 'basic'
                });
                
                setTimeout(() => {
                    onClose();
                }, 1500);
            } else {
                throw new Error(isValid?.reason || 'Demo session verification failed');
            }
        } catch (err) {
            setError(`Demo session activation error: ${err.message}`);
        } finally {
            setIsProcessing(false);
        }
    };

    const handlePaymentSuccess = async (preimage) => {
        try {
            console.log('🔍 Verifying payment...', { selectedType, preimage });
            
            let isValid;
            if (selectedType === 'demo') {
                return;
            } else {
                isValid = await sessionManager.verifyPayment(preimage, invoice.paymentHash);
            }
            
            if (isValid) {
                if (pollInterval.current) {
                    clearInterval(pollInterval.current);
                }
                if (paymentTimer) {
                    clearInterval(paymentTimer);
                }

                onSessionPurchased({ 
                    type: selectedType, 
                    preimage,
                    paymentHash: invoice.paymentHash,
                    amount: invoice.amount,
                    securityLevel: invoice.securityLevel || (selectedType === 'basic' ? 'enhanced' : 'maximum')
                });
                
                setTimeout(() => {
                    onClose();
                }, 1500);
                
            } else {
                throw new Error('Payment verification failed. Please check the preimage for correctness or try again.');
            }
        } catch (error) {
            console.error('❌ Payment verification failed:', error);
            throw error;
        }
    };

    const copyToClipboard = async (text) => {
        try {
            await navigator.clipboard.writeText(text);
        } catch (err) {
            console.error('Failed to copy:', err);
        }
    };

    const formatTime = (ms) => {
        const minutes = Math.floor(ms / 60000);
        const seconds = Math.floor((ms % 60000) / 1000);
        return `${minutes}:${seconds.toString().padStart(2, '0')}`;
    };

    const getSecurityBadgeColor = (level) => {
        switch (level?.toLowerCase()) {
            case 'basic': return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
            case 'enhanced': return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
            case 'maximum': return 'bg-green-500/20 text-green-300 border-green-500/30';
            default: return 'bg-gray-500/20 text-gray-300 border-gray-500/30';
        }
    };

    const pricing = sessionManager?.sessionPrices || {
        demo: { sats: 0, hours: 0.1, usd: 0.00 },
        basic: { sats: 5000, hours: 1, usd: 2.00 },
        premium: { sats: 20000, hours: 6, usd: 8.00 }
    };

    if (!isOpen) return null;

    return React.createElement('div', { 
        className: 'fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4' 
    }, [
        React.createElement('div', { 
            key: 'modal', 
            className: 'card-minimal rounded-xl p-6 max-w-lg w-full max-h-[90vh] overflow-y-auto custom-scrollbar' 
        }, [
            React.createElement('div', { 
                key: 'header', 
                className: 'flex items-center justify-between mb-6' 
            }, [
                React.createElement('h2', { 
                    key: 'title', 
                    className: 'text-xl font-semibold text-primary' 
                }, step === 'select' ? 'Select session type' : 
                   step === 'details' ? 'Security Features Details' : 'Session payment'),
                React.createElement('button', { 
                    key: 'close',
                    onClick: onClose, 
                    className: 'text-gray-400 hover:text-white transition-colors' 
                }, React.createElement('i', { className: 'fas fa-times' }))
            ]),

            step === 'select' && window.SessionTypeSelector && React.createElement(window.SessionTypeSelector, { 
                key: 'selector', 
                onSelectType: handleSelectType, 
                onCancel: onClose,
                sessionManager: sessionManager
            }),

            step === 'payment' && React.createElement('div', { 
                key: 'payment-step', 
                className: 'space-y-6' 
            }, [
                React.createElement('div', { 
                    key: 'session-info', 
                    className: 'text-center p-4 bg-orange-500/10 border border-orange-500/20 rounded-lg' 
                }, [
                    React.createElement('h3', { 
                        key: 'session-title', 
                        className: 'text-lg font-semibold text-orange-400 mb-2' 
                    }, [
                        `${selectedType.charAt(0).toUpperCase() + selectedType.slice(1)} session`,
                        invoice?.securityLevel && React.createElement('span', {
                            key: 'security-badge',
                            className: `text-xs px-2 py-1 rounded-full border ${getSecurityBadgeColor(invoice.securityLevel)}`
                        }, invoice.securityLevel.toUpperCase())
                    ]),
                    React.createElement('div', { 
                        key: 'session-details', 
                        className: 'text-sm text-secondary' 
                    }, [
                        React.createElement('div', { key: 'amount' }, `${pricing[selectedType].sats} sat for ${pricing[selectedType].hours}h`),
                        pricing[selectedType].usd > 0 && React.createElement('div', { 
                            key: 'usd', 
                            className: 'text-gray-400' 
                        }, `≈ ${pricing[selectedType].usd} USD`),
                        React.createElement('button', {
                            key: 'details-btn',
                            onClick: () => setStep('details'),
                            className: 'mt-2 text-xs text-blue-400 hover:text-blue-300 underline cursor-pointer'
                        }, '📋 View Security Details')
                    ])
                ]),

                timeLeft > 0 && paymentStatus === 'created' && React.createElement('div', { 
                    key: 'timer', 
                    className: 'text-center p-3 bg-yellow-500/10 border border-yellow-500/20 rounded' 
                }, [
                    React.createElement('div', { 
                        key: 'timer-text', 
                        className: 'text-yellow-400 font-medium' 
                    }, `⏱️ Time to pay: ${formatTime(timeLeft)}`)
                ]),

                paymentStatus === 'demo' && React.createElement('div', { 
                    key: 'demo-payment', 
                    className: 'space-y-4' 
                }, [
                    React.createElement('div', { 
                        key: 'demo-info', 
                        className: 'p-4 bg-green-500/10 border border-green-500/20 rounded text-green-300 text-sm text-center' 
                    }, [
                        React.createElement('div', { key: 'demo-title', className: 'font-medium mb-1' }, '🎮 Demo Session Available'),
                        React.createElement('div', { key: 'demo-details', className: 'text-xs' }, 
                            `Limited to ${invoice?.durationMinutes || 6} minutes for testing`)
                    ]),
                    invoice?.warning && React.createElement('div', {
                        key: 'demo-warning',
                        className: 'p-3 bg-yellow-500/10 border border-yellow-500/20 rounded text-yellow-300 text-xs text-center'
                    }, invoice.warning),
                    React.createElement('div', {
                        key: 'demo-preimage',
                        className: 'p-3 bg-gray-800/50 rounded border border-gray-600 text-xs font-mono text-gray-300'
                    }, [
                        React.createElement('div', { key: 'preimage-label', className: 'text-gray-400 mb-1' }, 'Demo Preimage:'),
                        React.createElement('div', { key: 'preimage-value', className: 'break-all' }, 
                            invoice?.preimage || 'Generating...')
                    ]),
                    React.createElement('button', { 
                        key: 'demo-btn',
                        onClick: handleDemoSession,
                        disabled: isProcessing,
                        className: 'w-full bg-green-600 hover:bg-green-500 text-white py-3 px-4 rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed'
                    }, [
                        React.createElement('i', { 
                            key: 'demo-icon',
                            className: `fas ${isProcessing ? 'fa-spinner fa-spin' : 'fa-play'} mr-2` 
                        }),
                        isProcessing ? 'Activating...' : 'Activate Demo Session'
                    ])
                ]),

                paymentStatus === 'creating' && React.createElement('div', { 
                    key: 'creating', 
                    className: 'text-center p-4' 
                }, [
                    React.createElement('i', { className: 'fas fa-spinner fa-spin text-orange-400 text-2xl mb-2' }),
                    React.createElement('div', { className: 'text-primary' }, 'Creating Lightning invoice...'),
                    React.createElement('div', { className: 'text-secondary text-sm mt-1' }, 'Connecting to the Lightning Network...')
                ]),

                (paymentStatus === 'created' || paymentStatus === 'paying') && invoice && React.createElement('div', { 
                    key: 'payment-methods', 
                    className: 'space-y-6' 
                }, [
                    qrCodeUrl && React.createElement('div', { 
                        key: 'qr-section', 
                        className: 'text-center' 
                    }, [
                        React.createElement('div', { 
                            key: 'qr-container', 
                            className: 'bg-white p-4 rounded-lg inline-block' 
                        }, [
                            React.createElement('img', { 
                                key: 'qr-img',
                                src: qrCodeUrl, 
                                alt: 'Lightning Payment QR Code', 
                                className: 'w-48 h-48' 
                            })
                        ]),
                        React.createElement('div', { 
                            key: 'qr-hint', 
                            className: 'text-xs text-gray-400 mt-2' 
                        }, 'Scan with any Lightning wallet')
                    ]),

                    invoice.paymentRequest && React.createElement('div', { 
                        key: 'payment-request', 
                        className: 'space-y-2' 
                    }, [
                        React.createElement('div', { 
                            key: 'pr-label', 
                            className: 'text-sm font-medium text-primary' 
                        }, 'Lightning Payment Request:'),
                        React.createElement('div', { 
                            key: 'pr-container',
                            className: 'p-3 bg-gray-800/50 rounded border border-gray-600 text-xs font-mono text-gray-300 cursor-pointer hover:bg-gray-700/50 transition-colors',
                            onClick: () => copyToClipboard(invoice.paymentRequest),
                            title: 'Click to copy'
                        }, [
                            invoice.paymentRequest.substring(0, 60) + '...',
                            React.createElement('i', { key: 'copy-icon', className: 'fas fa-copy ml-2 text-orange-400' })
                        ])
                    ]),

                    // WebLN Payment
                    React.createElement('div', { 
                        key: 'webln-section', 
                        className: 'space-y-3' 
                    }, [
                        React.createElement('h4', { 
                            key: 'webln-title', 
                            className: 'text-primary font-medium flex items-center' 
                        }, [
                            React.createElement('i', { key: 'bolt-icon', className: 'fas fa-bolt text-orange-400 mr-2' }),
                            'WebLN wallet (recommended)'
                        ]),
                        React.createElement('div', { 
                            key: 'webln-info', 
                            className: 'text-xs text-gray-400 mb-2' 
                        }, 'Alby, Zeus, or other WebLN-compatible wallets'),
                        React.createElement('button', { 
                            key: 'webln-btn',
                            onClick: handleWebLNPayment,
                            disabled: isProcessing || paymentStatus === 'paying',
                            className: 'w-full bg-orange-600 hover:bg-orange-500 text-white py-3 px-4 rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors'
                        }, [
                            React.createElement('i', { 
                                key: 'webln-icon',
                                className: `fas ${isProcessing ? 'fa-spinner fa-spin' : 'fa-bolt'} mr-2` 
                            }),
                            paymentStatus === 'paying' ? 'Processing payment...' : 'Pay via WebLN'
                        ])
                    ]),

                    // Divider
                    React.createElement('div', { 
                        key: 'divider', 
                        className: 'text-center text-gray-400 text-sm' 
                    }, '— or —'),
                    
                    // Manual Verification
                    React.createElement('div', { 
                        key: 'manual-section', 
                        className: 'space-y-3' 
                    }, [
                        React.createElement('h4', { 
                            key: 'manual-title', 
                            className: 'text-primary font-medium' 
                        }, 'Manual payment confirmation'),
                        React.createElement('div', { 
                            key: 'manual-info', 
                            className: 'text-xs text-gray-400' 
                        }, 'Pay the invoice in any wallet and enter the preimage.:'),
                        React.createElement('input', { 
                            key: 'preimage-input',
                            type: 'text',
                            value: preimageInput,
                            onChange: (e) => setPreimageInput(e.target.value),
                            placeholder: 'Enter the preimage (64 hex characters)...',
                            className: 'w-full p-3 bg-gray-800 border border-gray-600 rounded text-white placeholder-gray-400 text-sm font-mono',
                            maxLength: 64
                        }),
                        React.createElement('button', { 
                            key: 'verify-btn',
                            onClick: handleManualVerification,
                            disabled: isProcessing || !preimageInput.trim(),
                            className: 'w-full bg-green-600 hover:bg-green-500 text-white py-3 px-4 rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors'
                        }, [
                            React.createElement('i', { 
                                key: 'verify-icon',
                                className: `fas ${isProcessing ? 'fa-spinner fa-spin' : 'fa-check'} mr-2` 
                            }),
                            isProcessing ? 'Checking payment...' : 'Confirm payment'
                        ])
                    ])
                ]),

                // Success State
                paymentStatus === 'paid' && React.createElement('div', { 
                    key: 'success', 
                    className: 'text-center p-6 bg-green-500/10 border border-green-500/20 rounded-lg' 
                }, [
                    React.createElement('i', { key: 'success-icon', className: 'fas fa-check-circle text-green-400 text-3xl mb-3' }),
                    React.createElement('div', { key: 'success-title', className: 'text-green-300 font-semibold text-lg mb-1' }, '✅ Payment confirmed!'),
                    React.createElement('div', { key: 'success-text', className: 'text-green-400 text-sm' }, 'The session will be activated upon connecting to the chat.')
                ]),

                // Error State
                error && React.createElement('div', { 
                    key: 'error', 
                    className: 'p-4 bg-red-500/10 border border-red-500/20 rounded-lg' 
                }, [
                    React.createElement('div', { 
                        key: 'error-content', 
                        className: 'flex items-start space-x-3' 
                    }, [
                        React.createElement('i', { key: 'error-icon', className: 'fas fa-exclamation-triangle text-red-400 mt-0.5' }),
                        React.createElement('div', { key: 'error-text', className: 'flex-1' }, [
                            React.createElement('div', { key: 'error-message', className: 'text-red-400 text-sm' }, error),
                            (error.includes('invoice') || paymentStatus === 'failed') && React.createElement('button', { 
                                key: 'retry-btn',
                                onClick: () => createRealInvoice(selectedType),
                                className: 'mt-2 text-orange-400 hover:text-orange-300 underline text-sm'
                            }, 'Create a new invoice')
                        ])
                    ])
                ]),

                paymentStatus !== 'paid' && React.createElement('div', { 
                    key: 'back-section', 
                    className: 'pt-4 border-t border-gray-600' 
                }, [
                    React.createElement('button', { 
                        key: 'back-btn',
                        onClick: () => setStep('select'),
                        className: 'w-full bg-gray-600 hover:bg-gray-500 text-white py-2 px-4 rounded transition-colors'
                    }, [
                        React.createElement('i', { key: 'back-icon', className: 'fas fa-arrow-left mr-2' }),
                        'Choose another session'
                    ])
                ])
            ]),

            // Security Details Step
            step === 'details' && React.createElement('div', { 
                key: 'details-step', 
                className: 'space-y-6' 
            }, [
                React.createElement('div', { 
                    key: 'details-header', 
                    className: 'text-center p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg' 
                }, [
                    React.createElement('h3', { 
                        key: 'details-title', 
                        className: 'text-lg font-semibold text-blue-400 mb-2' 
                    }, getSecurityFeaturesInfo(selectedType).title),
                    React.createElement('p', { 
                        key: 'details-description', 
                        className: 'text-sm text-blue-300' 
                    }, getSecurityFeaturesInfo(selectedType).description)
                ]),

                // Available Features
                React.createElement('div', { key: 'available-features' }, [
                    React.createElement('h4', {
                        key: 'available-title',
                        className: 'text-sm font-medium text-green-300 mb-3 flex items-center'
                    }, [
                        React.createElement('i', {
                            key: 'check-icon',
                            className: 'fas fa-check-circle mr-2'
                        }),
                        'Available Security Features'
                    ]),
                    React.createElement('div', {
                        key: 'available-list',
                        className: 'grid grid-cols-1 gap-2'
                    }, getSecurityFeaturesInfo(selectedType).available.map((feature, index) => 
                        React.createElement('div', {
                            key: index,
                            className: 'flex items-center gap-2 text-sm text-green-300'
                        }, [
                            React.createElement('i', {
                                key: 'check',
                                className: 'fas fa-check text-green-400 w-4'
                            }),
                            React.createElement('span', {
                                key: 'text'
                            }, feature)
                        ])
                    ))
                ]),

                // Unavailable Features (if any)
                getSecurityFeaturesInfo(selectedType).unavailable.length > 0 && React.createElement('div', { key: 'unavailable-features' }, [
                    React.createElement('h4', {
                        key: 'unavailable-title',
                        className: 'text-sm font-medium text-red-300 mb-3 flex items-center'
                    }, [
                        React.createElement('i', {
                            key: 'minus-icon',
                            className: 'fas fa-minus-circle mr-2'
                        }),
                        'Not Available in This Session'
                    ]),
                    React.createElement('div', {
                        key: 'unavailable-list',
                        className: 'grid grid-cols-1 gap-2'
                    }, getSecurityFeaturesInfo(selectedType).unavailable.map((feature, index) => 
                        React.createElement('div', {
                            key: index,
                            className: 'flex items-center gap-2 text-sm text-red-300'
                        }, [
                            React.createElement('i', {
                                key: 'minus',
                                className: 'fas fa-minus text-red-400 w-4'
                            }),
                            React.createElement('span', {
                                key: 'text'
                            }, feature)
                        ])
                    ))
                ]),

                // Upgrade Information
                React.createElement('div', { key: 'upgrade-info' }, [
                    React.createElement('h4', {
                        key: 'upgrade-title',
                        className: 'text-sm font-medium text-blue-300 mb-3 flex items-center'
                    }, [
                        React.createElement('i', {
                            key: 'upgrade-icon',
                            className: 'fas fa-arrow-up mr-2'
                        }),
                        'Upgrade for More Security'
                    ]),
                    React.createElement('div', {
                        key: 'upgrade-content',
                        className: 'p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg'
                    }, [
                        React.createElement('div', {
                            key: 'upgrade-next',
                            className: 'text-sm font-medium text-blue-300 mb-2'
                        }, getSecurityFeaturesInfo(selectedType).upgrade.next),
                        React.createElement('div', {
                            key: 'upgrade-features',
                            className: 'grid grid-cols-1 gap-1'
                        }, getSecurityFeaturesInfo(selectedType).upgrade.features.map((feature, index) => 
                            React.createElement('div', {
                                key: index,
                                className: 'flex items-center gap-2 text-xs text-blue-300'
                            }, [
                                React.createElement('i', {
                                    key: 'arrow',
                                    className: 'fas fa-arrow-right text-blue-400 w-3'
                                }),
                                React.createElement('span', {
                                    key: 'text'
                                }, feature)
                            ])
                        ))
                    ])
                ]),

                // Back Button
                React.createElement('div', { 
                    key: 'details-back-section', 
                    className: 'pt-4 border-t border-gray-600' 
                }, [
                    React.createElement('button', { 
                        key: 'details-back-btn',
                        onClick: () => setStep('payment'),
                        className: 'w-full bg-gray-600 hover:bg-gray-500 text-white py-2 px-4 rounded transition-colors'
                    }, [
                        React.createElement('i', { key: 'back-icon', className: 'fas fa-arrow-left mr-2' }),
                        'Back to Payment'
                    ])
                ])
            ])
        ])
    ]);
};

window.PaymentModal = PaymentModal;