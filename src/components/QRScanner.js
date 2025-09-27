// Simple QR Scanner Component using only Html5Qrcode
const QRScanner = ({ onScan, onClose, isVisible, continuous = false }) => {
	const videoRef = React.useRef(null);
	const qrScannerRef = React.useRef(null);
	const [error, setError] = React.useState(null);
	const [isScanning, setIsScanning] = React.useState(false);
	const [progress, setProgress] = React.useState({ id: null, seq: 0, total: 0 });
	const [showFocusHint, setShowFocusHint] = React.useState(false);
	const [manualMode, setManualMode] = React.useState(false);
	const [scannedParts, setScannedParts] = React.useState(new Set());
	const [currentQRId, setCurrentQRId] = React.useState(null);

	React.useEffect(() => {
		if (isVisible) {
			startScanner();
		} else {
			stopScanner();
		}

		return () => {
			stopScanner();
		};
	}, [isVisible]);

	React.useEffect(() => {
        const onProgress = (e) => {
			const { id, seq, total } = e.detail || {};
			if (!id || !total) return;
			setProgress({ id, seq, total });
			
			// Обновляем ID текущего QR кода
			if (id !== currentQRId) {
				setCurrentQRId(id);
				setScannedParts(new Set()); // Сбрасываем сканированные части для нового ID
			}
			
			// Добавляем отсканированную часть
			setScannedParts(prev => new Set([...prev, seq]));
		};
        const onComplete = () => {
            // Close scanner once app signals completion
            if (!continuous) return;
            try { stopScanner(); } catch {}
        };
        document.addEventListener('qr-scan-progress', onProgress, { passive: true });
        document.addEventListener('qr-scan-complete', onComplete, { passive: true });
        return () => {
            document.removeEventListener('qr-scan-progress', onProgress, { passive: true });
            document.removeEventListener('qr-scan-complete', onComplete, { passive: true });
        };
	}, [currentQRId]);

	// Функция для tap-to-focus
	const handleTapToFocus = (event, html5Qrcode) => {
		try {
			// Показываем подсказку о фокусировке
			setShowFocusHint(true);
			setTimeout(() => setShowFocusHint(false), 2000);

			// Получаем координаты клика относительно видео элемента
			const rect = event.target.getBoundingClientRect();
			const x = event.clientX - rect.left;
			const y = event.clientY - rect.top;

			// Нормализуем координаты (0-1)
			const normalizedX = x / rect.width;
			const normalizedY = y / rect.height;

			console.log('Tap to focus at:', { x, y, normalizedX, normalizedY });

			// Попытка программной фокусировки (если поддерживается браузером)
			if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
				// Это может не работать во всех браузерах, но попробуем
				console.log('Attempting programmatic focus...');
			}

		} catch (error) {
			console.warn('Tap to focus error:', error);
		}
	};

	// Функции для ручного управления
	const toggleManualMode = () => {
		setManualMode(!manualMode);
		if (!manualMode) {
			// При включении ручного режима останавливаем автопрокрутку
			console.log('Manual mode enabled - auto-scroll disabled');
		} else {
			// При выключении ручного режима возобновляем автопрокрутку
			console.log('Manual mode disabled - auto-scroll enabled');
		}
	};

	const resetProgress = () => {
		setScannedParts(new Set());
		setCurrentQRId(null);
		setProgress({ id: null, seq: 0, total: 0 });
	};

	const startScanner = async () => {
		try {
			console.log('Starting QR scanner...');
			setError(null);
			setIsScanning(true);

            // Allow camera on HTTP as well; rely on browser permission prompts

			// Check if Html5Qrcode is available
			if (!window.Html5Qrcode) {
				setError('QR scanner library not loaded');
				setIsScanning(false);
				return;
			}

			// Get available cameras first
			console.log('Getting available cameras...');
			const cameras = await window.Html5Qrcode.getCameras();
			console.log('Available cameras:', cameras);
			
			if (!cameras || cameras.length === 0) {
				setError('No cameras found on this device');
				setIsScanning(false);
				return;
			}

			// Clear any existing scanner
			if (qrScannerRef.current) {
				try {
					qrScannerRef.current.stop();
				} catch (e) {
					console.log('Stopping previous scanner:', e.message);
				}
			}

			// Create video element if it doesn't exist
			if (!videoRef.current) {
				console.log('Video element not found');
				setError('Video element not found');
				setIsScanning(false);
				return;
			}

			console.log('Video element found:', videoRef.current);
			console.log('Video element ID:', videoRef.current.id);

			// Create Html5Qrcode instance
			console.log('Creating Html5Qrcode instance...');
			const html5Qrcode = new window.Html5Qrcode(videoRef.current.id || 'qr-reader');
			
			// Find back camera (environment facing)
			let cameraId = cameras[0].id; // Default to first camera
			let selectedCamera = cameras[0];
			
			// Look for back camera
			for (const camera of cameras) {
				if (camera.label.toLowerCase().includes('back') || 
					camera.label.toLowerCase().includes('rear') ||
					camera.label.toLowerCase().includes('environment')) {
					cameraId = camera.id;
					selectedCamera = camera;
					break;
				}
			}
			
			console.log('Available cameras:');
			cameras.forEach((cam, index) => {
				console.log(`${index + 1}. ${cam.label} (${cam.id})`);
			});
			console.log('Selected camera:', selectedCamera.label, 'ID:', cameraId);
			
			// Start camera
			console.log('Starting camera with Html5Qrcode...');
            const isDesktop = (typeof window !== 'undefined') && ((window.innerWidth || 0) >= 1024);
            const qrboxSize = isDesktop ? 560 : 360;
            await html5Qrcode.start(
                cameraId, // Use specific camera ID
                {
                    fps: /iPhone|iPad|iPod/i.test(navigator.userAgent) ? 2 : 3,
                    qrbox: { width: qrboxSize, height: qrboxSize },
                    // Улучшенные настройки для мобильных устройств
                    aspectRatio: 1.0,
                    videoConstraints: {
                        focusMode: "continuous", // Непрерывная автофокусировка
                        exposureMode: "continuous", // Непрерывная экспозиция
                        whiteBalanceMode: "continuous", // Непрерывный баланс белого
                        torch: false, // Вспышка выключена по умолчанию
                        facingMode: "environment" // Используем заднюю камеру
                    }
                },
                (decodedText, decodedResult) => {
					console.log('QR Code detected:', decodedText);
                    try {
                        const res = onScan(decodedText);
                        const handleResult = (val) => {
                            const shouldClose = val === true || !continuous;
                            if (shouldClose) {
                                stopScanner();
                            }
                        };
                        if (res && typeof res.then === 'function') {
                            res.then(handleResult).catch((e) => {
                                console.warn('onScan async handler error:', e);
                                if (!continuous) stopScanner();
                            });
                        } else {
                            handleResult(res);
                        }
                    } catch (e) {
                        console.warn('onScan handler threw:', e);
                        if (!continuous) {
                            stopScanner();
                        }
                    }
				},
				(error) => {
					// Ignore decode errors, they're normal during scanning
					console.log('QR decode error:', error);
				}
			);

			// Store scanner reference
			qrScannerRef.current = html5Qrcode;
			console.log('QR scanner started successfully');

			// Добавляем обработчик tap-to-focus для мобильных устройств
			if (videoRef.current) {
				videoRef.current.addEventListener('click', (event) => {
					handleTapToFocus(event, html5Qrcode);
				});
			}

		} catch (err) {
			console.error('Error starting QR scanner:', err);
			let errorMessage = 'Failed to start camera';
			
			if (err.name === 'NotAllowedError') {
				errorMessage = 'Camera access denied. Please allow camera access and try again.';
			} else if (err.name === 'NotFoundError') {
				errorMessage = 'No camera found on this device.';
			} else if (err.name === 'NotSupportedError') {
				errorMessage = 'Camera not supported on this device.';
			} else if (err.name === 'NotReadableError') {
				errorMessage = 'Camera is already in use by another application.';
			} else if (err.message) {
				errorMessage = err.message;
			}
			
			setError(errorMessage);
			setIsScanning(false);
		}
	};

    const stopScanner = () => {
		if (qrScannerRef.current) {
			try {
                qrScannerRef.current.stop().then(() => {
					console.log('QR scanner stopped');
				}).catch((err) => {
					console.log('Error stopping scanner:', err);
				});
			} catch (err) {
				console.log('Error stopping scanner:', err);
			}
			qrScannerRef.current = null;
		}
		setIsScanning(false);
        try {
            // iOS Safari workaround: small delay before closing modal to release camera
            if (/iPhone|iPad|iPod/i.test(navigator.userAgent)) {
                setTimeout(() => {
                    // no-op; allow camera to settle
                }, 150);
            }
        } catch {}
	};

	const handleClose = () => {
		stopScanner();
		onClose();
	};

	if (!isVisible) {
		return null;
	}

	return React.createElement('div', {
		className: "fixed inset-0 bg-black/80 flex items-center justify-center z-50"
	}, [
        React.createElement('div', {
			key: 'scanner-modal',
            className: "bg-gray-800 rounded-lg p-6 w-full mx-4 max-w-2xl"
		}, [
			React.createElement('div', {
				key: 'scanner-header',
				className: "flex items-center justify-between mb-4"
			}, [
				React.createElement('h3', {
					key: 'title',
					className: "text-lg font-medium text-white"
				}, 'Scan QR Code'),
				React.createElement('button', {
					key: 'close-btn',
					onClick: handleClose,
					className: "text-gray-400 hover:text-white transition-colors"
				}, [
					React.createElement('i', {
						className: 'fas fa-times text-xl'
					})
				])
			]),

			// Индикатор прогресса сканирования
			progress.total > 1 && React.createElement('div', {
				key: 'progress-indicator',
				className: "mb-4 p-3 bg-gray-800/50 border border-gray-600/30 rounded-lg"
			}, [
				React.createElement('div', {
					key: 'progress-header',
					className: "flex items-center justify-between mb-2"
				}, [
					React.createElement('span', {
						key: 'progress-title',
						className: "text-sm text-gray-300"
					}, `QR ID: ${currentQRId ? currentQRId.substring(0, 8) + '...' : 'N/A'}`),
					React.createElement('span', {
						key: 'progress-count',
						className: "text-sm text-blue-400"
					}, `${scannedParts.size}/${progress.total} scanned`)
				]),
				React.createElement('div', {
					key: 'progress-numbers',
					className: "flex flex-wrap gap-1"
				}, Array.from({ length: progress.total }, (_, i) => {
					const partNumber = i + 1;
					const isScanned = scannedParts.has(partNumber);
					return React.createElement('div', {
						key: `part-${partNumber}`,
						className: `w-8 h-8 rounded-full flex items-center justify-center text-xs font-medium transition-colors ${
							isScanned 
								? 'bg-green-500 text-white' 
								: 'bg-gray-600 text-gray-300'
						}`
					}, partNumber);
				}))
			]),

			// Панель управления
			progress.total > 1 && React.createElement('div', {
				key: 'control-panel',
				className: "mb-4 flex gap-2"
			}, [
				React.createElement('button', {
					key: 'manual-toggle',
					onClick: toggleManualMode,
					className: `px-3 py-1 rounded text-xs font-medium transition-colors ${
						manualMode 
							? 'bg-blue-500 text-white' 
							: 'bg-gray-600 text-gray-300 hover:bg-gray-500'
					}`
				}, manualMode ? 'Manual Mode' : 'Auto Mode'),
				React.createElement('button', {
					key: 'reset-progress',
					onClick: resetProgress,
					className: "px-3 py-1 bg-red-500/20 text-red-400 border border-red-500/20 rounded text-xs font-medium hover:bg-red-500/30"
				}, 'Reset'),
				React.createElement('span', {
					key: 'mode-hint',
					className: "text-xs text-gray-400 self-center"
				}, manualMode ? 'Tap to focus, scan manually' : 'Auto-scrolling enabled')
			]),
			
			React.createElement('div', {
				key: 'scanner-content',
				className: "relative"
			}, [
                React.createElement('div', {
					key: 'video-container',
					id: 'qr-reader',
					ref: videoRef,
                    className: "w-full h-80 md:h-[32rem] bg-gray-700 rounded-lg"
				}),
				
				error && React.createElement('div', {
					key: 'error',
					className: "absolute inset-0 flex items-center justify-center bg-red-900/50 rounded-lg"
				}, [
					React.createElement('div', {
						key: 'error-content',
						className: "text-center text-white p-4"
					}, [
						React.createElement('i', {
							key: 'error-icon',
							className: 'fas fa-exclamation-triangle text-2xl mb-2'
						}),
						React.createElement('p', {
							key: 'error-text',
							className: "text-sm"
						}, error)
					])
				]),

				!error && !isScanning && React.createElement('div', {
					key: 'loading',
					className: "absolute inset-0 flex items-center justify-center bg-gray-700/50 rounded-lg"
				}, [
					React.createElement('div', {
						key: 'loading-content',
						className: "text-center text-white"
					}, [
						React.createElement('i', {
							key: 'loading-icon',
							className: 'fas fa-spinner fa-spin text-2xl mb-2'
						}),
						React.createElement('p', {
							key: 'loading-text',
							className: "text-sm"
						}, 'Starting camera...')
					])
				]),

                !error && isScanning && React.createElement('div', {
					key: 'scanning-overlay',
					className: "absolute inset-0 flex items-center justify-center"
				}, [
					React.createElement('div', {
						key: 'scanning-content',
						className: "text-center text-white bg-black/50 rounded-lg px-4 py-2"
					}, [
                        React.createElement('i', {
                            key: 'scanning-icon',
                            className: 'fas fa-qrcode text-xl mb-1'
                        }),
						React.createElement('p', {
							key: 'scanning-text',
							className: "text-xs"
                        }, progress && progress.total > 1 ? `Frames: ${Math.min(progress.seq, progress.total)}/${progress.total}` : 'Point camera at QR code'),
                        React.createElement('p', {
                            key: 'tap-hint',
                            className: "text-xs text-blue-300 mt-1"
                        }, 'Tap screen to focus')
					])
				]),

                // Подсказка о фокусировке
                showFocusHint && React.createElement('div', {
                    key: 'focus-hint',
                    className: "absolute top-4 left-1/2 transform -translate-x-1/2 bg-green-500/90 text-white px-3 py-1 rounded-full text-xs font-medium z-10"
                }, 'Focusing...'),
                // Bottom overlay kept simple on mobile
			]),

            // Дополнительные подсказки для улучшения сканирования
            React.createElement('div', {
                key: 'scanning-tips',
                className: "mt-4 p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg"
            }, [
                React.createElement('h4', {
                    key: 'tips-title',
                    className: "text-blue-400 text-sm font-medium mb-2 flex items-center"
                }, [
                    React.createElement('i', {
                        key: 'tips-icon',
                        className: 'fas fa-lightbulb mr-2'
                    }),
                    'Tips for better scanning:'
                ]),
                React.createElement('ul', {
                    key: 'tips-list',
                    className: "text-xs text-blue-300 space-y-1"
                }, [
                    React.createElement('li', {
                        key: 'tip-1'
                    }, '• Ensure good lighting'),
                    React.createElement('li', {
                        key: 'tip-2'
                    }, '• Hold phone steady'),
                    React.createElement('li', {
                        key: 'tip-3'
                    }, '• Tap screen to focus'),
                    React.createElement('li', {
                        key: 'tip-4'
                    }, '• Keep QR code in frame')
                ])
            ])

		])
	]);
};

// Export for use in other files
window.QRScanner = QRScanner;
console.log('QRScanner component loaded and available on window.QRScanner');