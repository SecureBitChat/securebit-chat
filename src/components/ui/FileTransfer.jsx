// File Transfer Component for Chat Interface - Fixed Version
const FileTransferComponent = ({ webrtcManager, isConnected, pendingIncomingFiles = [], onIncomingDecision }) => {
    const [dragOver, setDragOver] = React.useState(false);
    const [transfers, setTransfers] = React.useState({ sending: [], receiving: [] });
    const fileInputRef = React.useRef(null);

    // Update transfers periodically via polling — no callback registration needed here
    React.useEffect(() => {
        if (!isConnected || !webrtcManager) return;

        const updateTransfers = () => {
            const currentTransfers = webrtcManager.getFileTransfers();
            setTransfers(currentTransfers);
        };

        const interval = setInterval(updateTransfers, 500);
        return () => clearInterval(interval);
    }, [isConnected, webrtcManager]);

    // Clear transfers UI when connection drops
    React.useEffect(() => {
        if (isConnected) return;
        setTransfers({ sending: [], receiving: [] });
    }, [isConnected]);

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
                // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Валидация файла перед отправкой
                const validation = webrtcManager.validateFile(file);
                if (!validation.isValid) {
                    const errorMessage = validation.errors.join('. ');
                    alert(`Файл ${file.name} не может быть отправлен: ${errorMessage}`);
                    continue;
                }

                await webrtcManager.sendFile(file);
            } catch (error) {
                // Более мягкая обработка ошибок - не закрываем сессию
                
                // Показываем пользователю ошибку, но не закрываем соединение
                if (error.message.includes('Connection not ready')) {
                    alert(`Файл ${file.name} не может быть отправлен сейчас. Проверьте соединение и попробуйте снова.`);
                } else if (error.message.includes('File too large') || error.message.includes('exceeds maximum')) {
                    alert(`Файл ${file.name} слишком большой: ${error.message}`);
                } else if (error.message.includes('Maximum concurrent transfers')) {
                    alert(`Достигнут лимит одновременных передач. Дождитесь завершения текущих передач.`);
                } else if (error.message.includes('File type not allowed')) {
                    alert(`Тип файла ${file.name} не поддерживается: ${error.message}`);
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

    const getStatusIcon = (status) => {
        switch (status) {
            case 'metadata_sent':
            case 'preparing':
                return 'fas fa-cog fa-spin';
            case 'transmitting':
            case 'receiving':
                return 'fas fa-exchange-alt fa-pulse';
            case 'assembling':
                return 'fas fa-puzzle-piece fa-pulse';
            case 'completed':
                return 'fas fa-check text-green-400';
            case 'failed':
                return 'fas fa-times text-red-400';
            default:
                return 'fas fa-circle';
        }
    };

    const getStatusText = (status) => {
        switch (status) {
            case 'metadata_sent':
                return 'Подготовка...';
            case 'transmitting':
                return 'Отправка...';
            case 'receiving':
                return 'Получение...';
            case 'assembling':
                return 'Сборка файла...';
            case 'completed':
                return 'Завершено';
            case 'failed':
                return 'Ошибка';
            default:
                return status;
        }
    };

    const handleIncomingDecision = async (fileId, accepted) => {
        if (typeof onIncomingDecision === 'function') {
            await onIncomingDecision(fileId, accepted);
        }
        setTransfers(webrtcManager.getFileTransfers());
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
                }, 'Drag files here or click to select'),
                React.createElement('p', {
                    key: 'subtext',
                    className: "text-muted text-sm"
                }, 'Maximum size: 100 MB per file')
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

        pendingIncomingFiles.length > 0 && React.createElement('div', {
            key: 'incoming-consent',
            className: "mt-4 space-y-2"
        }, pendingIncomingFiles.map(file => React.createElement('div', {
            key: file.fileId,
            className: "rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3"
        }, [
            React.createElement('div', {
                key: 'info',
                className: "mb-3 flex items-center justify-between gap-3"
            }, [
                React.createElement('div', { key: 'text' }, [
                    React.createElement('div', {
                        key: 'title',
                        className: "text-sm font-medium text-primary"
                    }, 'Incoming file request'),
                    React.createElement('div', {
                        key: 'meta',
                        className: "text-xs text-secondary"
                    }, `${file.fileName} · ${formatFileSize(file.fileSize)} · ${file.mimeType}`)
                ])
            ]),
            React.createElement('div', {
                key: 'actions',
                className: "flex gap-2"
            }, [
                React.createElement('button', {
                    key: 'accept',
                    onClick: () => handleIncomingDecision(file.fileId, true),
                    className: "rounded-md bg-green-500/20 px-3 py-2 text-sm text-green-300 hover:bg-green-500/30"
                }, 'Accept'),
                React.createElement('button', {
                    key: 'reject',
                    onClick: () => handleIncomingDecision(file.fileId, false),
                    className: "rounded-md bg-red-500/20 px-3 py-2 text-sm text-red-300 hover:bg-red-500/30"
                }, 'Reject')
            ])
        ]))),

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
                        React.createElement('div', {
                            key: 'text',
                            className: "progress-text text-xs flex items-center justify-between"
                        }, [
                            React.createElement('span', {
                                key: 'status',
                                className: "flex items-center"
                            }, [
                                React.createElement('i', {
                                    key: 'icon',
                                    className: `${getStatusIcon(transfer.status)} mr-1`
                                }),
                                getStatusText(transfer.status)
                            ]),
                            React.createElement('span', {
                                key: 'percent'
                            }, `${transfer.progress.toFixed(1)}%`)
                        ])
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
                        React.createElement('div', { key: 'actions', className: 'flex items-center space-x-2' }, [
                            transfer.status === 'completed' ? React.createElement('button', {
                                key: 'download',
                                className: 'text-green-400 hover:text-green-300 text-xs flex items-center',
                                onClick: async () => {
                                    try {
                                        const url = await webrtcManager.getReceivedFileObjectURL(transfer.fileId);
                                        if (!url) { alert('This file is no longer available for download.'); return; }
                                        const a = document.createElement('a');
                                        a.href = url;
                                        a.download = transfer.fileName || 'file';
                                        a.click();
                                        setTimeout(() => webrtcManager.revokeReceivedFileObjectURL(url), 10000);
                                    } catch (e) {
                                        alert(e.message || 'This file is no longer available for download.');
                                    }
                                }
                            }, [
                                React.createElement('i', { key: 'i', className: 'fas fa-download mr-1' }),
                                'Download'
                            ]) : null,
                            React.createElement('button', {
                                key: 'cancel',
                                onClick: () => webrtcManager.cancelFileTransfer(transfer.fileId),
                                className: "text-red-400 hover:text-red-300 text-xs"
                            }, [
                                React.createElement('i', {
                                    className: 'fas fa-times'
                                })
                            ])
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
                        React.createElement('div', {
                            key: 'text',
                            className: "progress-text text-xs flex items-center justify-between"
                        }, [
                            React.createElement('span', {
                                key: 'status',
                                className: "flex items-center"
                            }, [
                                React.createElement('i', {
                                    key: 'icon',
                                    className: `${getStatusIcon(transfer.status)} mr-1`
                                }),
                                getStatusText(transfer.status)
                            ]),
                            React.createElement('span', {
                                key: 'percent'
                            }, `${transfer.progress.toFixed(1)}%`)
                        ])
                    ])
                ])
            )
        ])
    ]);
};

// Export
window.FileTransferComponent = FileTransferComponent;
