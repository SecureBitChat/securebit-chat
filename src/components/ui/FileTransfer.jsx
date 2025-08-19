// File Transfer Component for Chat Interface
const FileTransferComponent = ({ webrtcManager, isConnected }) => {
    const [dragOver, setDragOver] = React.useState(false);
    const [transfers, setTransfers] = React.useState({ sending: [], receiving: [] });
    const fileInputRef = React.useRef(null);

    // Update transfers periodically
    React.useEffect(() => {
        if (!isConnected || !webrtcManager) return;

        const updateTransfers = () => {
            const currentTransfers = webrtcManager.getFileTransfers();
            setTransfers(currentTransfers);
        };

        const interval = setInterval(updateTransfers, 500);
        return () => clearInterval(interval);
    }, [isConnected, webrtcManager]);

    // Setup file transfer callbacks
    React.useEffect(() => {
        if (!webrtcManager) return;

        webrtcManager.setFileTransferCallbacks(
            // Progress callback
            (progress) => {
                const currentTransfers = webrtcManager.getFileTransfers();
                setTransfers(currentTransfers);
            },
            
            // File received callback
            (fileData) => {
                // Auto-download received file
                const url = URL.createObjectURL(fileData.fileBlob);
                const a = document.createElement('a');
                a.href = url;
                a.download = fileData.fileName;
                a.click();
                URL.revokeObjectURL(url);
                
                // Update transfer list
                const currentTransfers = webrtcManager.getFileTransfers();
                setTransfers(currentTransfers);
            },
            
            // Error callback
            (error) => {
                console.error('File transfer error:', error);
                const currentTransfers = webrtcManager.getFileTransfers();
                setTransfers(currentTransfers);
            }
        );
    }, [webrtcManager]);

    const handleFileSelect = async (files) => {
        if (!isConnected || !webrtcManager) {
            alert('Соединение не установлено. Сначала установите соединение.');
            return;
        }

        // Дополнительная проверка состояния соединения
        if (!webrtcManager.isConnected() || !webrtcManager.isVerified) {
            alert('Соединение не готово для передачи файлов. Дождитесь завершения установки соединения.');
            return;
        }

        for (const file of files) {
            try {
                await webrtcManager.sendFile(file);
            } catch (error) {
                // Более мягкая обработка ошибок - не закрываем сессию
                console.error(`Failed to send ${file.name}:`, error);
                
                // Показываем пользователю ошибку, но не закрываем соединение
                if (error.message.includes('Connection not ready')) {
                    alert(`Файл ${file.name} не может быть отправлен сейчас. Проверьте соединение и попробуйте снова.`);
                } else if (error.message.includes('File too large')) {
                    alert(`Файл ${file.name} слишком большой. Максимальный размер: 100 MB`);
                } else if (error.message.includes('Maximum concurrent transfers')) {
                    alert(`Достигнут лимит одновременных передач. Дождитесь завершения текущих передач.`);
                } else {
                    alert(`Ошибка отправки файла ${file.name}: ${error.message}`);
                }
            }
        }
    };

    const handleDrop = (e) => {
        e.preventDefault();
        setDragOver(false);
        
        const files = Array.from(e.dataTransfer.files);
        handleFileSelect(files);
    };

    const handleDragOver = (e) => {
        e.preventDefault();
        setDragOver(true);
    };

    const handleDragLeave = (e) => {
        e.preventDefault();
        setDragOver(false);
    };

    const handleFileInputChange = (e) => {
        const files = Array.from(e.target.files);
        handleFileSelect(files);
        e.target.value = ''; // Reset input
    };

    const formatFileSize = (bytes) => {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    if (!isConnected) {
        return React.createElement('div', {
            className: "p-4 text-center text-muted"
        }, 'Передача файлов доступна только при установленном соединении');
    }

    // Проверяем дополнительное состояние соединения
    const isConnectionReady = webrtcManager && webrtcManager.isConnected() && webrtcManager.isVerified;
    
    if (!isConnectionReady) {
        return React.createElement('div', {
            className: "p-4 text-center text-yellow-600"
        }, [
            React.createElement('i', {
                key: 'icon',
                className: 'fas fa-exclamation-triangle mr-2'
            }),
            'Соединение устанавливается... Передача файлов будет доступна после завершения установки.'
        ]);
    }

    return React.createElement('div', {
        className: "file-transfer-component"
    }, [
        // File Drop Zone
        React.createElement('div', {
            key: 'drop-zone',
            className: `file-drop-zone ${dragOver ? 'drag-over' : ''}`,
            onDrop: handleDrop,
            onDragOver: handleDragOver,
            onDragLeave: handleDragLeave,
            onClick: () => fileInputRef.current?.click()
        }, [
            React.createElement('div', {
                key: 'drop-content',
                className: "drop-content"
            }, [
                React.createElement('i', {
                    key: 'icon',
                    className: 'fas fa-cloud-upload-alt text-2xl mb-2 text-blue-400'
                }),
                React.createElement('p', {
                    key: 'text',
                    className: "text-primary font-medium"
                }, 'Перетащите файлы сюда или нажмите для выбора'),
                React.createElement('p', {
                    key: 'subtext',
                    className: "text-muted text-sm"
                }, 'Максимальный размер: 100 МБ на файл')
            ])
        ]),

        // Hidden file input
        React.createElement('input', {
            key: 'file-input',
            ref: fileInputRef,
            type: 'file',
            multiple: true,
            className: 'hidden',
            onChange: handleFileInputChange
        }),

        // Active Transfers
        (transfers.sending.length > 0 || transfers.receiving.length > 0) && React.createElement('div', {
            key: 'transfers',
            className: "active-transfers mt-4"
        }, [
            React.createElement('h4', {
                key: 'title',
                className: "text-primary font-medium mb-3 flex items-center"
            }, [
                React.createElement('i', {
                    key: 'icon',
                    className: 'fas fa-exchange-alt mr-2'
                }),
                'Передача файлов'
            ]),

            // Sending files
            ...transfers.sending.map(transfer => 
                React.createElement('div', {
                    key: `send-${transfer.fileId}`,
                    className: "transfer-item bg-blue-500/10 border border-blue-500/20 rounded-lg p-3 mb-2"
                }, [
                    React.createElement('div', {
                        key: 'header',
                        className: "flex items-center justify-between mb-2"
                    }, [
                        React.createElement('div', {
                            key: 'info',
                            className: "flex items-center"
                        }, [
                            React.createElement('i', {
                                key: 'icon',
                                className: 'fas fa-upload text-blue-400 mr-2'
                            }),
                            React.createElement('span', {
                                key: 'name',
                                className: "text-primary font-medium text-sm"
                            }, transfer.fileName),
                            React.createElement('span', {
                                key: 'size',
                                className: "text-muted text-xs ml-2"
                            }, formatFileSize(transfer.fileSize))
                        ]),
                        React.createElement('button', {
                            key: 'cancel',
                            onClick: () => webrtcManager.cancelFileTransfer(transfer.fileId),
                            className: "text-red-400 hover:text-red-300 text-xs"
                        }, [
                            React.createElement('i', {
                                className: 'fas fa-times'
                            })
                        ])
                    ]),
                    React.createElement('div', {
                        key: 'progress',
                        className: "progress-bar"
                    }, [
                        React.createElement('div', {
                            key: 'fill',
                            className: "progress-fill bg-blue-400",
                            style: { width: `${transfer.progress}%` }
                        }),
                        React.createElement('span', {
                            key: 'text',
                            className: "progress-text text-xs"
                        }, `${transfer.progress.toFixed(1)}% • ${transfer.status}`)
                    ])
                ])
            ),

            // Receiving files
            ...transfers.receiving.map(transfer => 
                React.createElement('div', {
                    key: `recv-${transfer.fileId}`,
                    className: "transfer-item bg-green-500/10 border border-green-500/20 rounded-lg p-3 mb-2"
                }, [
                    React.createElement('div', {
                        key: 'header',
                        className: "flex items-center justify-between mb-2"
                    }, [
                        React.createElement('div', {
                            key: 'info',
                            className: "flex items-center"
                        }, [
                            React.createElement('i', {
                                key: 'icon',
                                className: 'fas fa-download text-green-400 mr-2'
                            }),
                            React.createElement('span', {
                                key: 'name',
                                className: "text-primary font-medium text-sm"
                            }, transfer.fileName),
                            React.createElement('span', {
                                key: 'size',
                                className: "text-muted text-xs ml-2"
                            }, formatFileSize(transfer.fileSize))
                        ]),
                        React.createElement('button', {
                            key: 'cancel',
                            onClick: () => webrtcManager.cancelFileTransfer(transfer.fileId),
                            className: "text-red-400 hover:text-red-300 text-xs"
                        }, [
                            React.createElement('i', {
                                className: 'fas fa-times'
                            })
                        ])
                    ]),
                    React.createElement('div', {
                        key: 'progress',
                        className: "progress-bar"
                    }, [
                        React.createElement('div', {
                            key: 'fill',
                            className: "progress-fill bg-green-400",
                            style: { width: `${transfer.progress}%` }
                        }),
                        React.createElement('span', {
                            key: 'text',
                            className: "progress-text text-xs"
                        }, `${transfer.progress.toFixed(1)}% • ${transfer.status}`)
                    ])
                ])
            )
        ])
    ]);
};

// Export
window.FileTransferComponent = FileTransferComponent;