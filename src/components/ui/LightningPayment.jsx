const React = window.React;
const { useState, useEffect } = React;

const IntegratedLightningPayment = ({ sessionType, onSuccess, onCancel, paymentManager }) => {
    const [paymentMethod, setPaymentMethod] = useState('webln');
    const [preimage, setPreimage] = useState('');
    const [isProcessing, setIsProcessing] = useState(false);
    const [error, setError] = useState('');
    const [invoice, setInvoice] = useState(null);
    const [paymentStatus, setPaymentStatus] = useState('pending'); // pending, created, paid, expired
    const [qrCodeUrl, setQrCodeUrl] = useState('');

    // Создаем инвойс при загрузке компонента
    useEffect(() => {
        createInvoice();
    }, [sessionType]);

    const createInvoice = async () => {
        if (sessionType === 'free') {
            // Для бесплатной сессии не нужен инвойс
            setPaymentStatus('free');
            return;
        }

        setIsProcessing(true);
        setError('');

        try {
            console.log('Creating Lightning invoice for', sessionType);
            console.log('Payment manager available:', !!paymentManager);
            
            if (!paymentManager) {
                throw new Error('Payment manager not available. Please check sessionManager initialization.');
            }

            // Создаем инвойс через paymentManager
            const createdInvoice = await paymentManager.createLightningInvoice(sessionType);

            if (!createdInvoice) {
                throw new Error('Failed to create invoice');
            }

            setInvoice(createdInvoice);
            setPaymentStatus('created');

            // Создаем QR код
            if (createdInvoice.paymentRequest) {
                const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(createdInvoice.paymentRequest)}`;
                setQrCodeUrl(qrUrl);
            }

            console.log('Invoice created successfully:', createdInvoice);

        } catch (err) {
            console.error('Invoice creation failed:', err);
            setError(`Ошибка создания инвойса: ${err.message}`);
        } finally {
            setIsProcessing(false);
        }
    };

    const handleWebLNPayment = async () => {
        if (!window.webln) {
            setError('WebLN не поддерживается. Используйте кошелек Alby или Zeus');
            return;
        }

        if (!invoice || !invoice.paymentRequest) {
            setError('Инвойс не готов для оплаты');
            return;
        }

        setIsProcessing(true);
        setError('');

        try {
            console.log('Enabling WebLN...');
            await window.webln.enable();
            
            console.log('Sending WebLN payment...');
            const result = await window.webln.sendPayment(invoice.paymentRequest);
            
            if (result.preimage) {
                console.log('WebLN payment successful, preimage:', result.preimage);
                setPaymentStatus('paid');
                
                // Активируем сессию
                await activateSession(result.preimage);
            } else {
                setError('Платеж не содержит preimage');
            }
        } catch (err) {
            console.error('WebLN payment failed:', err);
            setError(`Ошибка WebLN: ${err.message}`);
        } finally {
            setIsProcessing(false);
        }
    };

    const handleManualVerification = async () => {
        const trimmedPreimage = preimage.trim();
        
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
        
        if (trimmedPreimage === '1'.repeat(64) || 
            trimmedPreimage === 'a'.repeat(64) || 
            trimmedPreimage === 'f'.repeat(64)) {
            setError('Введенный preimage слишком простой. Проверьте правильность ключа.');
            return;
        }
        
        setError('');
        setIsProcessing(true);

        try {
            await activateSession(trimmedPreimage);
        } catch (err) {
            setError(`Ошибка активации: ${err.message}`);
        } finally {
            setIsProcessing(false);
        }
    };

    const activateSession = async (preimageValue) => {
        try {
            console.log('🚀 Activating session with preimage:', preimageValue);
            console.log('Payment manager available:', !!paymentManager);
            console.log('Invoice available:', !!invoice);
            
            let result;
            if (paymentManager) {
                const paymentHash = invoice?.paymentHash || 'dummy_hash';
                console.log('Using payment hash:', paymentHash);
                result = await paymentManager.safeActivateSession(sessionType, preimageValue, paymentHash);
            } else {
                console.warn('Payment manager not available, using fallback');
                // Fallback если paymentManager недоступен
                result = { success: true, method: 'fallback' };
            }

            if (result.success) {
                console.log('✅ Session activated successfully:', result);
                setPaymentStatus('paid');
                onSuccess(preimageValue, invoice);
            } else {
                console.error('❌ Session activation failed:', result);
                throw new Error(`Session activation failed: ${result.reason}`);
            }

        } catch (err) {
            console.error('❌ Session activation failed:', err);
            throw err;
        }
    };

    const handleFreeSession = async () => {
        setIsProcessing(true);
        try {
            await activateSession('0'.repeat(64));
        } catch (err) {
            setError(`Ошибка активации бесплатной сессии: ${err.message}`);
        } finally {
            setIsProcessing(false);
        }
    };

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text).then(() => {
            // Можно добавить уведомление о копировании
        });
    };

    const pricing = {
        free: { sats: 1, hours: 1/60 },
        basic: { sats: 500, hours: 1 },
        premium: { sats: 1000, hours: 4 },
        extended: { sats: 2000, hours: 24 }
    }[sessionType];

    return React.createElement('div', { className: 'space-y-4 max-w-md mx-auto' }, [
        // Header
        React.createElement('div', { key: 'header', className: 'text-center' }, [
            React.createElement('h3', { 
                key: 'title', 
                className: 'text-xl font-semibold text-white mb-2' 
            }, sessionType === 'free' ? 'Бесплатная сессия' : 'Оплата Lightning'),
            React.createElement('div', { 
                key: 'amount', 
                className: 'text-2xl font-bold text-orange-400' 
            }, sessionType === 'free' 
                ? '1 сат за 1 минуту' 
                : `${pricing.sats} сат за ${pricing.hours}ч`
            ),
            sessionType !== 'free' && React.createElement('div', { 
                key: 'usd', 
                className: 'text-sm text-gray-400 mt-1' 
            }, `≈ $${(pricing.sats * 0.0004).toFixed(2)} USD`)
        ]),

        // Loading State
        isProcessing && paymentStatus === 'pending' && React.createElement('div', { 
            key: 'loading', 
            className: 'text-center' 
        }, [
            React.createElement('div', { 
                key: 'spinner', 
                className: 'text-orange-400' 
            }, [
                React.createElement('i', { className: 'fas fa-spinner fa-spin mr-2' }),
                'Создание инвойса...'
            ])
        ]),

        // Free Session
        sessionType === 'free' && React.createElement('div', { 
            key: 'free-session', 
            className: 'space-y-3' 
        }, [
            React.createElement('div', { 
                key: 'info', 
                className: 'p-3 bg-blue-500/10 border border-blue-500/20 rounded text-blue-300 text-sm' 
            }, 'Будет активирована бесплатная сессия на 1 минуту.'),
            React.createElement('button', { 
                key: 'start-btn',
                onClick: handleFreeSession,
                disabled: isProcessing,
                className: 'w-full bg-blue-600 hover:bg-blue-500 text-white py-3 px-4 rounded-lg font-medium disabled:opacity-50'
            }, [
                React.createElement('i', { 
                    key: 'icon',
                    className: `fas ${isProcessing ? 'fa-spinner fa-spin' : 'fa-play'} mr-2` 
                }),
                isProcessing ? 'Активация...' : 'Начать бесплатную сессию'
            ])
        ]),

        // Paid Sessions
        sessionType !== 'free' && paymentStatus === 'created' && invoice && React.createElement('div', { 
            key: 'paid-session', 
            className: 'space-y-4' 
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
                        alt: 'Payment QR Code', 
                        className: 'w-48 h-48' 
                    })
                ]),
                React.createElement('div', { 
                    key: 'qr-hint', 
                    className: 'text-xs text-gray-400 mt-2' 
                }, 'Сканируйте QR код любым Lightning кошельком')
            ]),

            // Payment Request
            invoice.paymentRequest && React.createElement('div', { 
                key: 'payment-request', 
                className: 'space-y-2' 
            }, [
                React.createElement('div', { 
                    key: 'label', 
                    className: 'text-sm font-medium text-white' 
                }, 'Payment Request:'),
                React.createElement('div', { 
                    key: 'request',
                    className: 'p-3 bg-gray-800 rounded border text-xs font-mono text-gray-300 cursor-pointer hover:bg-gray-700',
                    onClick: () => copyToClipboard(invoice.paymentRequest)
                }, [
                    invoice.paymentRequest.substring(0, 50) + '...',
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
                    className: 'text-white font-medium flex items-center' 
                }, [
                    React.createElement('i', { key: 'bolt-icon', className: 'fas fa-bolt text-orange-400 mr-2' }),
                    'WebLN кошелек (Alby, Zeus)'
                ]),
                React.createElement('button', { 
                    key: 'webln-btn',
                    onClick: handleWebLNPayment,
                    disabled: isProcessing,
                    className: 'w-full bg-orange-600 hover:bg-orange-500 text-white py-3 px-4 rounded-lg font-medium disabled:opacity-50'
                }, [
                    React.createElement('i', { 
                        key: 'webln-icon',
                        className: `fas ${isProcessing ? 'fa-spinner fa-spin' : 'fa-bolt'} mr-2` 
                    }),
                    isProcessing ? 'Обработка...' : 'Оплатить через WebLN'
                ])
            ]),

            // Manual Payment
            React.createElement('div', { 
                key: 'divider', 
                className: 'text-center text-gray-400' 
            }, 'или'),
            
            React.createElement('div', { 
                key: 'manual-section', 
                className: 'space-y-3' 
            }, [
                React.createElement('h4', { 
                    key: 'manual-title', 
                    className: 'text-white font-medium' 
                }, 'Ручная проверка платежа'),
                React.createElement('input', { 
                    key: 'preimage-input',
                    type: 'text',
                    value: preimage,
                    onChange: (e) => setPreimage(e.target.value),
                    placeholder: 'Введите preimage после оплаты...',
                    className: 'w-full p-3 bg-gray-800 border border-gray-600 rounded text-white placeholder-gray-400 text-sm'
                }),
                React.createElement('button', { 
                    key: 'verify-btn',
                    onClick: handleManualVerification,
                    disabled: isProcessing,
                    className: 'w-full bg-green-600 hover:bg-green-500 text-white py-3 px-4 rounded-lg font-medium disabled:opacity-50'
                }, [
                    React.createElement('i', { 
                        key: 'verify-icon',
                        className: `fas ${isProcessing ? 'fa-spinner fa-spin' : 'fa-check'} mr-2` 
                    }),
                    isProcessing ? 'Проверка...' : 'Подтвердить платеж'
                ])
            ])
        ]),

        // Success State
        paymentStatus === 'paid' && React.createElement('div', { 
            key: 'success', 
            className: 'text-center p-4 bg-green-500/10 border border-green-500/20 rounded' 
        }, [
            React.createElement('i', { key: 'success-icon', className: 'fas fa-check-circle text-green-400 text-2xl mb-2' }),
            React.createElement('div', { key: 'success-text', className: 'text-green-300 font-medium' }, 'Платеж подтвержден!'),
            React.createElement('div', { key: 'success-subtext', className: 'text-green-400 text-sm' }, 'Сессия активирована')
        ]),

        // Error State
        error && React.createElement('div', { 
            key: 'error', 
            className: 'p-3 bg-red-500/10 border border-red-500/20 rounded text-red-400 text-sm' 
        }, [
            React.createElement('i', { key: 'error-icon', className: 'fas fa-exclamation-triangle mr-2' }),
            error,
            error.includes('инвойса') && React.createElement('button', { 
                key: 'retry-btn',
                onClick: createInvoice,
                className: 'ml-2 text-orange-400 hover:text-orange-300 underline'
            }, 'Попробовать снова')
        ]),

        // Cancel Button
        React.createElement('button', { 
            key: 'cancel-btn',
            onClick: onCancel,
            className: 'w-full bg-gray-600 hover:bg-gray-500 text-white py-2 px-4 rounded'
        }, 'Отмена')
    ]);
};

window.LightningPayment = IntegratedLightningPayment;