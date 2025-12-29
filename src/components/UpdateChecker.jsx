/**
 * UpdateChecker - React component for automatic update checking
 * 
 * Wraps the application and automatically detects new versions,
 * showing a modal window with update progress
 */

const UpdateChecker = ({ children, onUpdateAvailable, debug = false }) => {
    const [updateState, setUpdateState] = React.useState({
        hasUpdate: false,
        isUpdating: false,
        progress: 0,
        currentVersion: null,
        newVersion: null,
        showModal: false
    });
    
    const updateManagerRef = React.useRef(null);
    
    // Initialize UpdateManager
    React.useEffect(() => {
        // Check that UpdateManager is available
        if (typeof window === 'undefined' || !window.UpdateManager) {
            console.error('❌ UpdateManager not found. Make sure updateManager.js is loaded.');
            return;
        }
        
        // Create UpdateManager instance
        updateManagerRef.current = new window.UpdateManager({
            versionUrl: '/meta.json',
            checkInterval: 60000, // 1 minute
            checkOnLoad: true,
            debug: debug,
            onUpdateAvailable: (updateInfo) => {
                setUpdateState(prev => ({
                    ...prev,
                    hasUpdate: true,
                    currentVersion: updateInfo.currentVersion,
                    newVersion: updateInfo.newVersion,
                    showModal: true
                }));
                
                // Call external callback if available
                if (onUpdateAvailable) {
                    onUpdateAvailable(updateInfo);
                }
            },
            onError: (error) => {
                if (debug) {
                    console.warn('Update check error (non-critical):', error);
                }
            }
        });
        
        // Cleanup on unmount
        return () => {
            if (updateManagerRef.current) {
                updateManagerRef.current.destroy();
            }
        };
    }, [onUpdateAvailable, debug]);
    
    // Force update handler
    const handleForceUpdate = async () => {
        if (!updateManagerRef.current || updateState.isUpdating) {
            return;
        }
        
        setUpdateState(prev => ({
            ...prev,
            isUpdating: true,
            progress: 0
        }));
        
        try {
            // Simulate update progress
            const progressSteps = [
                { progress: 10, message: 'Saving data...' },
                { progress: 30, message: 'Clearing Service Worker caches...' },
                { progress: 50, message: 'Unregistering Service Workers...' },
                { progress: 70, message: 'Clearing browser cache...' },
                { progress: 90, message: 'Updating version...' },
                { progress: 100, message: 'Reloading application...' }
            ];
            
            for (const step of progressSteps) {
                await new Promise(resolve => setTimeout(resolve, 300));
                setUpdateState(prev => ({
                    ...prev,
                    progress: step.progress
                }));
            }
            
            // Start force update
            await updateManagerRef.current.forceUpdate();
            
        } catch (error) {
            console.error('❌ Update failed:', error);
            setUpdateState(prev => ({
                ...prev,
                isUpdating: false,
                progress: 0
            }));
            
            // Show error to user
            alert('Update error. Please refresh the page manually (Ctrl+F5 or Cmd+Shift+R)');
        }
    };
    
    // Close modal (not recommended, but leaving the option)
    const handleCloseModal = () => {
        // Warn user
        if (window.confirm('New version available. Update is recommended for security and stability. Continue without update?')) {
            setUpdateState(prev => ({
                ...prev,
                showModal: false
            }));
        }
    };
    
    // Format version for display
    const formatVersion = (version) => {
        if (!version) return 'N/A';
        // If version is timestamp, format as date
        if (/^\d+$/.test(version)) {
            const date = new Date(parseInt(version));
            return date.toLocaleString('en-US', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit'
            });
        }
        return version;
    };
    
    return React.createElement(React.Fragment, null, [
        // Main application content
        children,
        
        // Update modal window
        updateState.showModal && React.createElement('div', {
            key: 'update-modal',
            className: 'fixed inset-0 z-[9999] flex items-center justify-center bg-black/80 backdrop-blur-sm',
            style: {
                animation: 'fadeIn 0.3s ease-in-out'
            }
        }, [
            React.createElement('div', {
                key: 'modal-content',
                className: 'bg-white dark:bg-gray-800 rounded-2xl shadow-2xl p-8 max-w-md w-full mx-4 border border-gray-200 dark:border-gray-700',
                style: {
                    animation: 'slideUp 0.3s ease-out'
                }
            }, [
                // Header
                React.createElement('div', {
                    key: 'header',
                    className: 'text-center mb-6'
                }, [
                    React.createElement('div', {
                        key: 'icon',
                        className: 'w-16 h-16 mx-auto mb-4 bg-blue-500/10 rounded-full flex items-center justify-center'
                    }, [
                        React.createElement('i', {
                            key: 'icon-fa',
                            className: 'fas fa-sync-alt text-blue-500 text-2xl animate-spin'
                        })
                    ]),
                    React.createElement('h2', {
                        key: 'title',
                        className: 'text-2xl font-bold text-gray-900 dark:text-white mb-2'
                    }, 'Update Available'),
                    React.createElement('p', {
                        key: 'subtitle',
                        className: 'text-gray-600 dark:text-gray-300 text-sm'
                    }, 'A new version of the application has been detected')
                ]),
                
                // Version information
                React.createElement('div', {
                    key: 'version-info',
                    className: 'bg-gray-50 dark:bg-gray-900 rounded-lg p-4 mb-6 space-y-2'
                }, [
                    React.createElement('div', {
                        key: 'current',
                        className: 'flex justify-between items-center'
                    }, [
                        React.createElement('span', {
                            key: 'current-label',
                            className: 'text-sm text-gray-600 dark:text-gray-400'
                        }, 'Current version:'),
                        React.createElement('span', {
                            key: 'current-value',
                            className: 'text-sm font-mono text-gray-900 dark:text-white'
                        }, formatVersion(updateState.currentVersion))
                    ]),
                    React.createElement('div', {
                        key: 'new',
                        className: 'flex justify-between items-center'
                    }, [
                        React.createElement('span', {
                            key: 'new-label',
                            className: 'text-sm text-gray-600 dark:text-gray-400'
                        }, 'New version:'),
                        React.createElement('span', {
                            key: 'new-value',
                            className: 'text-sm font-mono text-blue-600 dark:text-blue-400 font-semibold'
                        }, formatVersion(updateState.newVersion))
                    ])
                ]),
                
                // Update progress
                updateState.isUpdating && React.createElement('div', {
                    key: 'progress',
                    className: 'mb-6'
                }, [
                    React.createElement('div', {
                        key: 'progress-bar',
                        className: 'w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2.5 mb-2'
                    }, [
                        React.createElement('div', {
                            key: 'progress-fill',
                            className: 'bg-blue-500 h-2.5 rounded-full transition-all duration-300',
                            style: {
                                width: `${updateState.progress}%`
                            }
                        })
                    ]),
                    React.createElement('p', {
                        key: 'progress-text',
                        className: 'text-center text-sm text-gray-600 dark:text-gray-400'
                    }, `${updateState.progress}%`)
                ]),
                
                // Action buttons
                !updateState.isUpdating && React.createElement('div', {
                    key: 'actions',
                    className: 'flex gap-3'
                }, [
                    React.createElement('button', {
                        key: 'update-btn',
                        onClick: handleForceUpdate,
                        className: 'flex-1 bg-blue-500 hover:bg-blue-600 text-white font-semibold py-3 px-6 rounded-lg transition-colors duration-200 flex items-center justify-center gap-2',
                        disabled: updateState.isUpdating
                    }, [
                        React.createElement('i', {
                            key: 'update-icon',
                            className: 'fas fa-download'
                        }),
                        React.createElement('span', {
                            key: 'update-text'
                        }, 'Update Now')
                    ]),
                    React.createElement('button', {
                        key: 'close-btn',
                        onClick: handleCloseModal,
                        className: 'px-4 py-3 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors duration-200',
                        disabled: updateState.isUpdating
                    }, [
                        React.createElement('i', {
                            key: 'close-icon',
                            className: 'fas fa-times'
                        })
                    ])
                ]),
                
                // Update indicator
                updateState.isUpdating && React.createElement('div', {
                    key: 'updating',
                    className: 'text-center'
                }, [
                    React.createElement('p', {
                        key: 'updating-text',
                        className: 'text-sm text-gray-600 dark:text-gray-400'
                    }, 'Update in progress...')
                ])
            ])
        ])
    ]);
};

// Export for use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = UpdateChecker;
} else {
    window.UpdateChecker = UpdateChecker;
}

