// File Transfer Component for Chat Interface - Fixed Version
const FileTransferComponent = ({ webrtcManager, isConnected, pendingIncomingFiles = [], onIncomingDecision, showDropzone = true }) => {
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

    // Segmented (per-chunk) progress — squares fill as chunks transfer, like a
    // download manager. For large files chunks are grouped into a fixed grid;
    // for small files it's literally one square per chunk.
    const renderProgress = (transfer, color) => {
        const total = transfer.totalChunks || 0;
        const done = transfer.transferredChunks || 0;
        const isDone = transfer.status === 'completed';
        const squares = total > 0 ? Math.min(total, 32) : 24;
        let filled;
        if (isDone) filled = squares;
        else if (total > 0) filled = Math.floor((done / total) * squares);
        else filled = Math.floor(((transfer.progress || 0) / 100) * squares);
        filled = Math.max(0, Math.min(squares, filled));

        return React.createElement('div', { key: 'progress' }, [
            React.createElement('div', {
                key: 'squares',
                style: { display: 'flex', flexWrap: 'wrap', gap: '3px', marginBottom: '7px' }
            }, Array.from({ length: squares }, (_, i) => React.createElement('div', {
                key: i,
                style: {
                    width: '11px', height: '11px', borderRadius: '2px',
                    background: i < filled ? color : 'rgba(255,255,255,0.07)',
                    border: '1px solid ' + (i < filled ? 'transparent' : 'rgba(255,255,255,0.05)'),
                    boxShadow: i < filled ? `0 0 5px ${color}55` : 'none',
                    transition: 'background .2s ease, box-shadow .2s ease'
                }
            }))),
            React.createElement('div', {
                key: 'text',
                style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11.5px', color: '#8a8a92' }
            }, [
                React.createElement('span', { key: 'status', style: { display: 'inline-flex', alignItems: 'center', gap: '5px' } }, [
                    React.createElement('i', { key: 'icon', className: getStatusIcon(transfer.status) }),
                    getStatusText(transfer.status)
                ]),
                React.createElement('span', {
                    key: 'count',
                    style: { fontFamily: "'JetBrains Mono', ui-monospace, monospace", color: i_done(transfer) ? color : '#8a8a92' }
                }, total > 0 ? `${Math.min(done, total)} / ${total} chunks` : `${(transfer.progress || 0).toFixed(0)}%`)
            ])
        ]);
    };
    const i_done = (t) => t.status === 'completed';

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
        // File Drop Zone (SecureBit Chat design) — only when the panel is opened to SEND,
        // so a receiver never sees the "send attachments" UI.
        showDropzone && React.createElement('div', {
            key: 'drop-zone',
            onDrop: handleDrop,
            onDragOver: handleDragOver,
            onDragLeave: handleDragLeave,
            style: {
                position: 'relative',
                border: '1.5px dashed ' + (dragOver ? 'rgba(240,137,42,0.7)' : 'rgba(255,255,255,0.14)'),
                borderRadius: '14px',
                background: dragOver ? 'rgba(240,137,42,0.07)' : '#141416',
                padding: '24px 22px',
                textAlign: 'center',
                transition: 'all .15s'
            }
        }, [
            React.createElement('div', {
                key: 'icon-box',
                style: { width: '42px', height: '42px', margin: '0 auto 10px', borderRadius: '12px', display: 'grid', placeItems: 'center', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }
            }, React.createElement('i', { className: 'fas fa-arrow-up-from-bracket', style: { color: '#9a9aa2', fontSize: '18px' } })),
            React.createElement('div', { key: 'title', style: { fontSize: '14px', fontWeight: 700, color: '#e8e8eb' } }, 'Drag & drop files here'),
            React.createElement('div', { key: 'sub', style: { fontSize: '12px', color: '#7b7b83', marginTop: '4px' } }, 'Encrypted end-to-end before transfer · up to 100 MB'),
            React.createElement('button', {
                key: 'browse',
                type: 'button',
                onClick: () => fileInputRef.current?.click(),
                className: 'sb-send',
                style: { marginTop: '14px', display: 'inline-flex', alignItems: 'center', gap: '7px', padding: '9px 16px', borderRadius: '9px', border: 'none', background: '#f0892a', color: '#1a0f04', fontFamily: 'inherit', fontSize: '13px', fontWeight: 700, cursor: 'pointer' }
            }, [
                React.createElement('i', { key: 'i', className: 'fas fa-folder-open', style: { fontSize: '13px' } }),
                'Browse device'
            ])
        ]),

        // Hidden file input
        showDropzone && React.createElement('input', {
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
            style: { borderRadius: '12px', border: '1px solid rgba(255,255,255,0.08)', background: '#161618', padding: '12px 14px' }
        }, [
            React.createElement('div', {
                key: 'info',
                style: { marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '11px' }
            }, [
                React.createElement('div', { key: 'ic', style: { flex: 'none', width: '34px', height: '34px', borderRadius: '9px', display: 'grid', placeItems: 'center', background: 'rgba(240,137,42,0.12)', border: '1px solid rgba(240,137,42,0.22)' } },
                    React.createElement('i', { className: 'fas fa-file-arrow-down', style: { color: '#f0892a', fontSize: '15px' } })
                ),
                React.createElement('div', { key: 'text', style: { minWidth: 0 } }, [
                    React.createElement('div', {
                        key: 'title',
                        style: { fontSize: '13px', fontWeight: 600, color: '#e8e8eb' }
                    }, 'Incoming file request'),
                    React.createElement('div', {
                        key: 'meta',
                        style: { fontSize: '11.5px', color: '#7b7b83', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }
                    }, `${file.fileName} · ${formatFileSize(file.fileSize)} · ${file.mimeType}`)
                ])
            ]),
            React.createElement('div', {
                key: 'actions',
                style: { display: 'flex', gap: '8px' }
            }, [
                React.createElement('button', {
                    key: 'accept',
                    onClick: () => handleIncomingDecision(file.fileId, true),
                    style: { display: 'inline-flex', alignItems: 'center', gap: '6px', borderRadius: '8px', border: 'none', background: '#f0892a', color: '#1a0f04', padding: '8px 14px', fontSize: '13px', fontWeight: 700, cursor: 'pointer' }
                }, [React.createElement('i', { key: 'i', className: 'fas fa-check', style: { fontSize: '12px' } }), 'Accept']),
                React.createElement('button', {
                    key: 'reject',
                    onClick: () => handleIncomingDecision(file.fileId, false),
                    style: { display: 'inline-flex', alignItems: 'center', gap: '6px', borderRadius: '8px', border: '1px solid rgba(229,114,122,0.3)', background: 'rgba(229,114,122,0.08)', color: '#e5727a', padding: '8px 14px', fontSize: '13px', fontWeight: 600, cursor: 'pointer' }
                }, [React.createElement('i', { key: 'i', className: 'fas fa-xmark', style: { fontSize: '12px' } }), 'Reject'])
            ])
        ]))),

        // Active Transfers
        (transfers.sending.length > 0 || transfers.receiving.length > 0) && React.createElement('div', {
            key: 'transfers',
            className: "active-transfers mt-4"
        }, [
            React.createElement('h4', {
                key: 'title',
                style: { display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12.5px', fontWeight: 600, color: '#8a8a92', marginBottom: '10px' }
            }, [
                React.createElement('i', {
                    key: 'icon',
                    className: 'fas fa-right-left',
                    style: { fontSize: '12px' }
                }),
                'File transfers'
            ]),

            // Sending files
            ...transfers.sending.map(transfer =>
                React.createElement('div', {
                    key: `send-${transfer.fileId}`,
                    style: { borderRadius: '11px', border: '1px solid rgba(255,255,255,0.07)', background: '#161618', padding: '12px', marginBottom: '8px' }
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
                                className: 'fas fa-arrow-up',
                                style: { color: '#f0892a', fontSize: '13px', marginRight: '8px' }
                            }),
                            React.createElement('span', {
                                key: 'name',
                                className: "font-medium text-sm",
                                style: { color: '#e8e8eb' }
                            }, transfer.fileName),
                            React.createElement('span', {
                                key: 'size',
                                className: "text-xs ml-2",
                                style: { color: '#7b7b83' }
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
                    renderProgress(transfer, '#f0892a')
                ])
            ),

            // Receiving files
            ...transfers.receiving.map(transfer => 
                React.createElement('div', {
                    key: `recv-${transfer.fileId}`,
                    style: { borderRadius: '11px', border: '1px solid rgba(255,255,255,0.07)', background: '#161618', padding: '12px', marginBottom: '8px' }
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
                                className: 'fas fa-arrow-down',
                                style: { color: '#3ecf8e', fontSize: '13px', marginRight: '8px' }
                            }),
                            React.createElement('span', {
                                key: 'name',
                                className: "font-medium text-sm",
                                style: { color: '#e8e8eb' }
                            }, transfer.fileName),
                            React.createElement('span', {
                                key: 'size',
                                className: "text-xs ml-2",
                                style: { color: '#7b7b83' }
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
                    renderProgress(transfer, '#3ecf8e')
                ])
            )
        ])
    ]);
};

// Export
window.FileTransferComponent = FileTransferComponent;
