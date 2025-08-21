// File Transfer Component for Chat Interface - Fixed Version
const FileTransferComponent = ({ webrtcManager, isConnected }) => {
    const [dragOver, setDragOver] = React.useState(false);
    const [transfers, setTransfers] = React.useState({ sending: [], receiving: [] });
    const [readyFiles, setReadyFiles] = React.useState([]); // файлы, готовые к скачиванию
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

    // Setup file transfer callbacks - ИСПРАВЛЕНИЕ: НЕ отправляем промежуточные сообщения в чат
    React.useEffect(() => {
        if (!webrtcManager) return;

        webrtcManager.setFileTransferCallbacks(
            // Progress callback - ТОЛЬКО обновляем UI, НЕ отправляем в чат
            (progress) => {
                console.log(`📁 UI Progress: ${progress.fileName}: ${progress.progress.toFixed(1)}% (${progress.status})`);
                
                // Обновляем только локальное состояние
                const currentTransfers = webrtcManager.getFileTransfers();
                setTransfers(currentTransfers);
                
                // НЕ отправляем сообщения в чат!
            },
            
            // File received callback - добавляем кнопку скачивания в UI
            (fileData) => {
                console.log(`📥 File received in UI: ${fileData.fileName}`);
                // Добавляем в список готовых к скачиванию
                setReadyFiles(prev => {
                    // избегаем дублей по fileId
                    if (prev.some(f => f.fileId === fileData.fileId)) return prev;
                    return [...prev, {
                        fileId: fileData.fileId,
                        fileName: fileData.fileName,
                        fileSize: fileData.fileSize,
                        mimeType: fileData.mimeType,
                        getBlob: fileData.getBlob,
                        getObjectURL: fileData.getObjectURL,
                        revokeObjectURL: fileData.revokeObjectURL
                    }];
                });

                // Обновляем список активных передач
                const currentTransfers = webrtcManager.getFileTransfers();
                setTransfers(currentTransfers);
            },
            
            // Error callback
            (error) => {
                console.error('File transfer error in UI:', error);
                const currentTransfers = webrtcManager.getFileTransfers();
                setTransfers(currentTransfers);
                
                // ИСПРАВЛЕНИЕ: НЕ дублируем сообщения об ошибках
                // Уведомления об ошибках уже отправляются в WebRTC менеджере
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
                console.log(`🚀 Starting file upload from UI: ${file.name}`);
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
                            // Кнопка скачать, если файл уже готов (есть в readyFiles)
                            (() => {
                                const rf = readyFiles.find(f => f.fileId === transfer.fileId);
                                if (!rf || transfer.status !== 'completed') return null;
                                return React.createElement('button', {
                                    key: 'download',
                                    className: 'text-green-400 hover:text-green-300 text-xs flex items-center',
                                    onClick: async () => {
                                        try {
                                            const url = await rf.getObjectURL();
                                            const a = document.createElement('a');
                                            a.href = url;
                                            a.download = rf.fileName || 'file';
                                            a.click();
                                            rf.revokeObjectURL(url);
                                        } catch (e) {
                                            alert('Не удалось начать скачивание: ' + e.message);
                                        }
                                    }
                                }, [
                                    React.createElement('i', { key: 'i', className: 'fas fa-download mr-1' }),
                                    'Скачать'
                                ]);
                            })(),
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