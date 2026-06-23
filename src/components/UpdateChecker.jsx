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
    
    const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
    const SANS = "'Manrope', system-ui, -apple-system, sans-serif";

    // Update modal — translated from the Claude Design component
    // (Update Notification.dc.html). Styling is inline so it tracks the design.
    return React.createElement(React.Fragment, null, [
        // Main application content
        children,

        updateState.showModal && React.createElement('div', {
            key: 'update-modal',
            style: {
                position: 'fixed', inset: 0, zIndex: 9999, display: 'flex', alignItems: 'center', justifyContent: 'center',
                padding: '24px', background: 'rgba(8,8,10,0.55)', backdropFilter: 'blur(3px)', WebkitBackdropFilter: 'blur(3px)',
                animation: 'unFade .3s ease', fontFamily: SANS
            }
        }, [
            React.createElement('style', { key: 'kf', dangerouslySetInnerHTML: { __html:
                '@keyframes unPop{from{opacity:0;transform:scale(.96) translateY(10px)}to{opacity:1;transform:scale(1) translateY(0)}}' +
                '@keyframes unFade{from{opacity:0}to{opacity:1}}' +
                '@keyframes unSpin{to{transform:rotate(360deg)}}'
            } }),

            React.createElement('div', {
                key: 'card',
                style: {
                    position: 'relative', width: '440px', maxWidth: 'calc(100vw - 48px)', borderRadius: '22px',
                    background: '#121214', border: '1px solid rgba(255,255,255,0.08)', padding: '36px 32px 28px',
                    textAlign: 'center', boxShadow: '0 30px 70px rgba(0,0,0,0.6)', animation: 'unPop .32s cubic-bezier(.2,.7,.3,1)'
                }
            }, [
                // spinning update icon
                React.createElement('div', {
                    key: 'icon',
                    style: { display: 'inline-flex', width: '64px', height: '64px', borderRadius: '50%', alignItems: 'center', justifyContent: 'center', background: 'rgba(240,137,42,0.12)', border: '1px solid rgba(240,137,42,0.3)', marginBottom: '20px' }
                }, React.createElement('svg', {
                    width: 28, height: 28, viewBox: '0 0 24 24', fill: 'none', stroke: '#f0892a', strokeWidth: 2, strokeLinecap: 'round', strokeLinejoin: 'round',
                    style: { animation: 'unSpin 6s linear infinite' },
                    dangerouslySetInnerHTML: { __html: '<path d="M21 8a8.5 8.5 0 0 0-15.6-2.5M3 4v4h4"/><path d="M3 16a8.5 8.5 0 0 0 15.6 2.5M21 20v-4h-4"/>' }
                })),

                React.createElement('h2', { key: 'title', style: { margin: '0 0 9px', fontSize: '26px', fontWeight: 800, letterSpacing: '-0.7px', color: '#f4f4f6' } }, 'Update available'),
                React.createElement('p', { key: 'sub', style: { margin: '0 0 24px', fontSize: '14.5px', lineHeight: 1.55, color: '#9a9aa2' } }, 'A newer version of SecureBit has been detected.'),

                // version comparison
                React.createElement('div', {
                    key: 'vbox',
                    style: { borderRadius: '14px', background: '#0c0c0e', border: '1px solid rgba(255,255,255,0.06)', padding: '16px 18px', marginBottom: '24px', textAlign: 'left' }
                }, [
                    React.createElement('div', { key: 'cur', style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '14px', padding: '5px 0' } }, [
                        React.createElement('span', { key: 'l', style: { fontSize: '13.5px', fontWeight: 500, color: '#8a8a92' } }, 'Current version'),
                        React.createElement('span', { key: 'v', style: { fontFamily: MONO, fontSize: '13px', fontWeight: 500, color: '#9a9aa2', whiteSpace: 'nowrap' } }, formatVersion(updateState.currentVersion))
                    ]),
                    React.createElement('div', { key: 'sep', style: { height: '1px', background: 'rgba(255,255,255,0.05)', margin: '4px 0' } }),
                    React.createElement('div', { key: 'new', style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '14px', padding: '5px 0' } }, [
                        React.createElement('span', { key: 'l', style: { display: 'inline-flex', alignItems: 'center', gap: '8px', fontSize: '13.5px', fontWeight: 600, color: '#e8e8eb' } }, [
                            React.createElement('span', { key: 'd', style: { width: '6px', height: '6px', borderRadius: '50%', background: '#f0892a' } }),
                            'New version'
                        ]),
                        React.createElement('span', { key: 'v', style: { fontFamily: MONO, fontSize: '13px', fontWeight: 700, color: '#f0892a', whiteSpace: 'nowrap' } }, formatVersion(updateState.newVersion))
                    ])
                ]),

                // progress while updating, otherwise the action buttons
                updateState.isUpdating
                    ? React.createElement('div', { key: 'progress' }, [
                        React.createElement('div', {
                            key: 'bar',
                            style: { width: '100%', height: '8px', borderRadius: '99px', background: '#0c0c0e', border: '1px solid rgba(255,255,255,0.06)', overflow: 'hidden', marginBottom: '10px' }
                        }, React.createElement('div', { key: 'fill', style: { height: '100%', width: `${updateState.progress}%`, background: 'linear-gradient(90deg,#3ecf8e,#f0892a)', transition: 'width .3s ease' } })),
                        React.createElement('p', { key: 't', style: { margin: 0, fontFamily: MONO, fontSize: '12px', color: '#8a8a92' } }, `Updating… ${updateState.progress}%`)
                    ])
                    : React.createElement('div', { key: 'actions', style: { display: 'flex', alignItems: 'center', gap: '12px' } }, [
                        React.createElement('button', {
                            key: 'update',
                            onClick: handleForceUpdate,
                            style: { flex: 1, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '10px', padding: '15px 20px', borderRadius: '13px', border: 'none', background: '#f0892a', color: '#1a0f04', fontFamily: 'inherit', fontSize: '15.5px', fontWeight: 700, letterSpacing: '-0.2px', cursor: 'pointer', boxShadow: '0 8px 24px rgba(240,137,42,0.28)', transition: 'all .2s cubic-bezier(.2,.7,.3,1)' },
                            onMouseEnter: (e) => { e.currentTarget.style.background = '#ff9637'; e.currentTarget.style.transform = 'translateY(-2px)'; },
                            onMouseLeave: (e) => { e.currentTarget.style.background = '#f0892a'; e.currentTarget.style.transform = 'none'; }
                        }, [
                            React.createElement('svg', { key: 'i', width: 18, height: 18, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 2.1, strokeLinecap: 'round', strokeLinejoin: 'round', dangerouslySetInnerHTML: { __html: '<path d="M12 3v11"/><path d="M7.5 10.5L12 15l4.5-4.5"/><path d="M5 20h14"/>' } }),
                            'Update now'
                        ]),
                        React.createElement('button', {
                            key: 'later',
                            onClick: handleCloseModal,
                            title: 'Later',
                            style: { flex: 'none', width: '50px', height: '50px', borderRadius: '13px', display: 'grid', placeItems: 'center', border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.025)', color: '#9a9aa2', cursor: 'pointer', transition: 'all .18s cubic-bezier(.2,.7,.3,1)' },
                            onMouseEnter: (e) => { e.currentTarget.style.color = '#e5727a'; e.currentTarget.style.borderColor = 'rgba(229,114,122,0.4)'; },
                            onMouseLeave: (e) => { e.currentTarget.style.color = '#9a9aa2'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)'; }
                        }, React.createElement('svg', { width: 17, height: 17, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 2.1, strokeLinecap: 'round', strokeLinejoin: 'round', dangerouslySetInnerHTML: { __html: '<path d="M6 6l12 12M18 6L6 18"/>' } }))
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

