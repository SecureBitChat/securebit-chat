const React = window.React;
const { useState, useEffect, useRef } = React;

const PaymentModal = ({ isOpen, onClose, sessionManager, onSessionPurchased }) => {
    const [step, setStep] = useState('select');
    const [selectedType, setSelectedType] = useState(null);
    const [invoice, setInvoice] = useState(null);
    const [paymentStatus, setPaymentStatus] = useState('pending'); // pending, creating, created, paying, paid, failed, expired
    const [error, setError] = useState('');
    const [paymentMethod, setPaymentMethod] = useState('webln'); // webln, manual, qr
    const [preimageInput, setPreimageInput] = useState('');
    const [isProcessing, setIsProcessing] = useState(false);
    const [qrCodeUrl, setQrCodeUrl] = useState('');
    const [paymentTimer, setPaymentTimer] = useState(null);
    const [timeLeft, setTimeLeft] = useState(0);
    const pollInterval = useRef(null);

    // Cleanup на закрытие
    useEffect(() => {
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
    };

    const handleSelectType = async (type) => {
        setSelectedType(type);
        setError('');
        
        if (type === 'free') {
            // Для бесплатной сессии создаем фиктивный инвойс
            setInvoice({ 
                sessionType: 'free',
                amount: 1,
                paymentHash: '0'.repeat(64),
                memo: 'Free session (1 minute)',
                createdAt: Date.now()
            });
            setPaymentStatus('free');
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
            console.log(`Creating real Lightning invoice for ${type} session...`);
            
            if (!sessionManager) {
                throw new Error('Session manager не инициализирован');
            }

            // Создаем реальный Lightning инвойс через LNbits
            const createdInvoice = await sessionManager.createLightningInvoice(type);
            
            if (!createdInvoice || !createdInvoice.paymentRequest) {
                throw new Error('Не удалось создать Lightning инвойс');
            }

            setInvoice(createdInvoice);
            setPaymentStatus('created');

            // Создаем QR код для инвойса
            const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(createdInvoice.paymentRequest)}`;
            setQrCodeUrl(qrUrl);

            // Запускаем таймер на 15 минут
            const expirationTime = 15 * 60 * 1000; // 15 минут
            setTimeLeft(expirationTime);
            
            const timer = setInterval(() => {
                setTimeLeft(prev => {
                    const newTime = prev - 1000;
                    if (newTime <= 0) {
                        clearInterval(timer);
                        setPaymentStatus('expired');
                        setError('Время для оплаты истекло. Создайте новый инвойс.');
                        return 0;
                    }
                    return newTime;
                });
            }, 1000);
            setPaymentTimer(timer);

            // Запускаем автопроверку статуса платежа
            startPaymentPolling(createdInvoice.checkingId);

            console.log('✅ Lightning invoice created successfully:', createdInvoice);

        } catch (err) {
            console.error('❌ Invoice creation failed:', err);
            setError(`Ошибка создания инвойса: ${err.message}`);
            setPaymentStatus('failed');
        } finally {
            setIsProcessing(false);
        }
    };

    // Автопроверка статуса платежа каждые 3 секунды
    const startPaymentPolling = (checkingId) => {
        if (pollInterval.current) {
            clearInterval(pollInterval.current);
        }

        pollInterval.current = setInterval(async () => {
            try {
                const status = await sessionManager.checkPaymentStatus(checkingId);
                
                if (status.paid && status.preimage) {
                    console.log('✅ Payment confirmed automatically!', status);
                    clearInterval(pollInterval.current);
                    setPaymentStatus('paid');
                    await handlePaymentSuccess(status.preimage);
                }
            } catch (error) {
                console.warn('Payment status check failed:', error);
                // Продолжаем проверять, не останавливаем polling из-за одной ошибки
            }
        }, 3000); // Проверяем каждые 3 секунды
    };

    const handleWebLNPayment = async () => {
        if (!window.webln) {
            setError('WebLN не поддерживается. Установите кошелек Alby или Zeus');
            return;
        }

        if (!invoice || !invoice.paymentRequest) {
            setError('Инвойс не готов для оплаты');
            return;
        }

        setIsProcessing(true);
        setError('');
        setPaymentStatus('paying');

        try {
            console.log('🔌 Enabling WebLN...');
            await window.webln.enable();
            
            console.log('💰 Sending WebLN payment...');
            const result = await window.webln.sendPayment(invoice.paymentRequest);
            
            if (result.preimage) {
                console.log('✅ WebLN payment successful!', result);
                setPaymentStatus('paid');
                await handlePaymentSuccess(result.preimage);
            } else {
                throw new Error('Платеж не содержит preimage');
            }
        } catch (err) {
            console.error('❌ WebLN payment failed:', err);
            setError(`Ошибка WebLN платежа: ${err.message}`);
            setPaymentStatus('created'); // Возвращаем к состоянию "создан"
        } finally {
            setIsProcessing(false);
        }
    };

    const handleManualVerification = async () => {
        const trimmedPreimage = preimageInput.trim();
        
        if (!trimmedPreimage) {
            setError('Введите preimage платежа');
            return;
        }
        
        if (trimmedPreimage.length !== 64) {
            setError('Preimage должен содержать ровно 64 символа');
            return;
        }
        
        if (!/^[0-9a-fA-F]{64}$/.test(trimmedPreimage)) {
            setError('Preimage должен содержать только шестнадцатеричные символы (0-9, a-f, A-F)');
            return;
        }
        
        // Проверяем на простые/тестовые preimage
        const dummyPreimages = ['1'.repeat(64), 'a'.repeat(64), 'f'.repeat(64), '0'.repeat(64)];
        if (dummyPreimages.includes(trimmedPreimage) && selectedType !== 'free') {
            setError('Введенный preimage недействителен. Используйте настоящий preimage от платежа.');
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

    const handleFreeSession = async () => {
        setIsProcessing(true);
        setError('');
        
        try {
            await handlePaymentSuccess('0'.repeat(64));
        } catch (err) {
            setError(`Ошибка активации бесплатной сессии: ${err.message}`);
        } finally {
            setIsProcessing(false);
        }
    };

    const handlePaymentSuccess = async (preimage) => {
        try {
            console.log('🔍 Verifying payment...', { selectedType, preimage });
            
            let isValid;
            if (selectedType === 'free') {
                isValid = true;
            } else {
                // Верифицируем реальный платеж
                isValid = await sessionManager.verifyPayment(preimage, invoice.paymentHash);
            }
            
            if (isValid) {
                console.log('✅ Payment verified successfully!');
                
                // Останавливаем polling и таймеры
                if (pollInterval.current) {
                    clearInterval(pollInterval.current);
                }
                if (paymentTimer) {
                    clearInterval(paymentTimer);
                }
                
                // Передаем данные о покупке
                onSessionPurchased({ 
                    type: selectedType, 
                    preimage,
                    paymentHash: invoice.paymentHash,
                    amount: invoice.amount
                });
                
                // Закрываем модалку с задержкой для показа успеха
                setTimeout(() => {
                    onClose();
                }, 1500);
                
            } else {
                throw new Error('Платеж не прошел верификацию. Проверьте правильность preimage или попробуйте снова.');
            }
        } catch (error) {
            console.error('❌ Payment verification failed:', error);
            throw error;
        }
    };

    const copyToClipboard = async (text) => {
        try {
            await navigator.clipboard.writeText(text);
            // Можно добавить visual feedback
        } catch (err) {
            console.error('Failed to copy:', err);
        }
    };

    const formatTime = (ms) => {
        const minutes = Math.floor(ms / 60000);
        const seconds = Math.floor((ms % 60000) / 1000);
        return `${minutes}:${seconds.toString().padStart(2, '0')}`;
    };

    const pricing = sessionManager?.sessionPrices || {
        free: { sats: 1, hours: 1/60, usd: 0.00 },
        basic: { sats: 500, hours: 1, usd: 0.20 },
        premium: { sats: 1000, hours: 4, usd: 0.40 },
        extended: { sats: 2000, hours: 24, usd: 0.80 }
    };

    if (!isOpen) return null;

    return React.createElement('div', { 
        className: 'fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4' 
    }, [
        React.createElement('div', { 
            key: 'modal', 
            className: 'card-minimal rounded-xl p-6 max-w-lg w-full max-h-[90vh] overflow-y-auto custom-scrollbar' 
        }, [
            // Header с кнопкой закрытия
            React.createElement('div', { 
                key: 'header', 
                className: 'flex items-center justify-between mb-6' 
            }, [
                React.createElement('h2', { 
                    key: 'title', 
                    className: 'text-xl font-semibold text-primary' 
                }, step === 'select' ? 'Выберите тип сессии' : 'Оплата сессии'),
                React.createElement('button', { 
                    key: 'close',
                    onClick: onClose, 
                    className: 'text-gray-400 hover:text-white transition-colors' 
                }, React.createElement('i', { className: 'fas fa-times' }))
            ]),

            // Step 1: Session Type Selection
            step === 'select' && window.SessionTypeSelector && React.createElement(window.SessionTypeSelector, { 
                key: 'selector', 
                onSelectType: handleSelectType, 
                onCancel: onClose 
            }),

            // Step 2: Payment Processing
            step === 'payment' && React.createElement('div', { 
                key: 'payment-step', 
                className: 'space-y-6' 
            }, [
                // Session Info
                React.createElement('div', { 
                    key: 'session-info', 
                    className: 'text-center p-4 bg-orange-500/10 border border-orange-500/20 rounded-lg' 
                }, [
                    React.createElement('h3', { 
                        key: 'session-title', 
                        className: 'text-lg font-semibold text-orange-400 mb-2' 
                    }, `${selectedType.charAt(0).toUpperCase() + selectedType.slice(1)} сессия`),
                    React.createElement('div', { 
                        key: 'session-details', 
                        className: 'text-sm text-secondary' 
                    }, [
                        React.createElement('div', { key: 'amount' }, `${pricing[selectedType].sats} сат за ${pricing[selectedType].hours}ч`),
                        pricing[selectedType].usd > 0 && React.createElement('div', { 
                            key: 'usd', 
                            className: 'text-gray-400' 
                        }, `≈ $${pricing[selectedType].usd} USD`)
                    ])
                ]),

                // Timer для платных сессий
                timeLeft > 0 && paymentStatus === 'created' && React.createElement('div', { 
                    key: 'timer', 
                    className: 'text-center p-3 bg-yellow-500/10 border border-yellow-500/20 rounded' 
                }, [
                    React.createElement('div', { 
                        key: 'timer-text', 
                        className: 'text-yellow-400 font-medium' 
                    }, `⏱️ Время на оплату: ${formatTime(timeLeft)}`)
                ]),

                // Бесплатная сессия
                paymentStatus === 'free' && React.createElement('div', { 
                    key: 'free-payment', 
                    className: 'space-y-4' 
                }, [
                    React.createElement('div', { 
                        key: 'free-info', 
                        className: 'p-4 bg-blue-500/10 border border-blue-500/20 rounded text-blue-300 text-sm text-center' 
                    }, '🎉 Бесплатная сессия на 1 минуту'),
                    React.createElement('button', { 
                        key: 'free-btn',
                        onClick: handleFreeSession,
                        disabled: isProcessing,
                        className: 'w-full bg-blue-600 hover:bg-blue-500 text-white py-3 px-4 rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed'
                    }, [
                        React.createElement('i', { 
                            key: 'free-icon',
                            className: `fas ${isProcessing ? 'fa-spinner fa-spin' : 'fa-play'} mr-2` 
                        }),
                        isProcessing ? 'Активация...' : 'Активировать бесплатную сессию'
                    ])
                ]),

                // Создание инвойса
                paymentStatus === 'creating' && React.createElement('div', { 
                    key: 'creating', 
                    className: 'text-center p-4' 
                }, [
                    React.createElement('i', { className: 'fas fa-spinner fa-spin text-orange-400 text-2xl mb-2' }),
                    React.createElement('div', { className: 'text-primary' }, 'Создание Lightning инвойса...'),
                    React.createElement('div', { className: 'text-secondary text-sm mt-1' }, 'Подключение к Lightning Network...')
                ]),

                // Платная сессия с инвойсом
                (paymentStatus === 'created' || paymentStatus === 'paying') && invoice && React.createElement('div', { 
                    key: 'payment-methods', 
                    className: 'space-y-6' 
                }, [
                    // QR Code
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
                        }, 'Сканируйте любым Lightning кошельком')
                    ]),

                    // Payment Request для копирования
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
                            title: 'Нажмите для копирования'
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
                            'WebLN кошелек (рекомендуется)'
                        ]),
                        React.createElement('div', { 
                            key: 'webln-info', 
                            className: 'text-xs text-gray-400 mb-2' 
                        }, 'Alby, Zeus, или другие WebLN совместимые кошельки'),
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
                            paymentStatus === 'paying' ? 'Обработка платежа...' : 'Оплатить через WebLN'
                        ])
                    ]),

                    // Divider
                    React.createElement('div', { 
                        key: 'divider', 
                        className: 'text-center text-gray-400 text-sm' 
                    }, '— или —'),
                    
                    // Manual Verification
                    React.createElement('div', { 
                        key: 'manual-section', 
                        className: 'space-y-3' 
                    }, [
                        React.createElement('h4', { 
                            key: 'manual-title', 
                            className: 'text-primary font-medium' 
                        }, 'Ручное подтверждение платежа'),
                        React.createElement('div', { 
                            key: 'manual-info', 
                            className: 'text-xs text-gray-400' 
                        }, 'Оплатите инвойс в любом кошельке и введите preimage:'),
                        React.createElement('input', { 
                            key: 'preimage-input',
                            type: 'text',
                            value: preimageInput,
                            onChange: (e) => setPreimageInput(e.target.value),
                            placeholder: 'Введите preimage (64 hex символа)...',
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
                            isProcessing ? 'Проверка платежа...' : 'Подтвердить платеж'
                        ])
                    ])
                ]),

                // Success State
                paymentStatus === 'paid' && React.createElement('div', { 
                    key: 'success', 
                    className: 'text-center p-6 bg-green-500/10 border border-green-500/20 rounded-lg' 
                }, [
                    React.createElement('i', { key: 'success-icon', className: 'fas fa-check-circle text-green-400 text-3xl mb-3' }),
                    React.createElement('div', { key: 'success-title', className: 'text-green-300 font-semibold text-lg mb-1' }, '✅ Платеж подтвержден!'),
                    React.createElement('div', { key: 'success-text', className: 'text-green-400 text-sm' }, 'Сессия будет активирована при подключении к чату')
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
                            (error.includes('инвойса') || paymentStatus === 'failed') && React.createElement('button', { 
                                key: 'retry-btn',
                                onClick: () => createRealInvoice(selectedType),
                                className: 'mt-2 text-orange-400 hover:text-orange-300 underline text-sm'
                            }, 'Создать новый инвойс')
                        ])
                    ])
                ]),

                // Back button (кроме случая успешной оплаты)
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
                        'Выбрать другую сессию'
                    ])
                ])
            ])
        ])
    ]);
};

window.PaymentModal = PaymentModal;