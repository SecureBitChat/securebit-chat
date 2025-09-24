// Simple QR Scanner Component using only Html5Qrcode
const QRScanner = ({ onScan, onClose, isVisible, continuous = false }) => {
	const videoRef = React.useRef(null);
	const qrScannerRef = React.useRef(null);
	const [error, setError] = React.useState(null);
	const [isScanning, setIsScanning] = React.useState(false);
	const [progress, setProgress] = React.useState({ id: null, seq: 0, total: 0 });

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
	}, []);

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
                    qrbox: { width: qrboxSize, height: qrboxSize }
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
                        }, progress && progress.total > 1 ? `Frames: ${Math.min(progress.seq, progress.total)}/${progress.total}` : 'Point camera at QR code')
					])
				]),
                // Bottom overlay kept simple on mobile
			]),

		])
	]);
};

// Export for use in other files
window.QRScanner = QRScanner;
console.log('QRScanner component loaded and available on window.QRScanner');