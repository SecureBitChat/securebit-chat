// SessionTimer Component - v4.2.12 - ECDH + DTLS + SAS
const SessionTimer = ({ timeLeft, sessionType, sessionManager, onDisconnect }) => {
    const [currentTime, setCurrentTime] = React.useState(timeLeft || 0);
    const [showExpiredMessage, setShowExpiredMessage] = React.useState(false);
    const [initialized, setInitialized] = React.useState(false);
    const [connectionBroken, setConnectionBroken] = React.useState(false);
    

    const [loggedHidden, setLoggedHidden] = React.useState(false);

    React.useEffect(() => {
        if (connectionBroken) {
            if (!loggedHidden) {
                console.log('⏱️ SessionTimer initialization skipped - connection broken');
                setLoggedHidden(true);
            }
            return;
        }
        
        let initialTime = 0;
        
        if (sessionManager?.hasActiveSession()) {
            initialTime = sessionManager.getTimeLeft();
        } else if (timeLeft && timeLeft > 0) {
            initialTime = timeLeft;
        }

        if (initialTime <= 0) {
            setCurrentTime(0);
            setInitialized(false);
            setLoggedHidden(true);
            return;
        }

        if (connectionBroken) {
            setCurrentTime(0);
            setInitialized(false);
            setLoggedHidden(true);
            return;
        }
        setCurrentTime(initialTime);
        setInitialized(true);
        setLoggedHidden(false); 
    }, [sessionManager, connectionBroken]);

    React.useEffect(() => {
        if (connectionBroken) {
            if (!loggedHidden) {
                setLoggedHidden(true);
            }
            return;
        }
        
        if (timeLeft && timeLeft > 0) {
            setCurrentTime(timeLeft);
        }
        setLoggedHidden(false);
    }, [timeLeft, connectionBroken]);

    React.useEffect(() => {
        if (!initialized) {
            return;
        }

        if (connectionBroken) {
            if (!loggedHidden) {
                setLoggedHidden(true);
            }
            return;
        }

        if (!currentTime || currentTime <= 0 || !sessionManager) {
            return;
        }

        const interval = setInterval(() => {
            if (connectionBroken) {
                setCurrentTime(0);
                clearInterval(interval);
                return;
            }
            
            if (sessionManager?.hasActiveSession()) {
                const newTime = sessionManager.getTimeLeft();
                setCurrentTime(newTime);

                if (window.DEBUG_MODE && Math.floor(Date.now() / 30000) !== Math.floor((Date.now() - 1000) / 30000)) {
                    console.log('⏱️ Timer tick:', Math.floor(newTime / 1000) + 's');
                }

                if (newTime <= 0) {
                    setShowExpiredMessage(true);
                    setTimeout(() => setShowExpiredMessage(false), 5000);
                    clearInterval(interval);
                }
            } else {
                setCurrentTime(0);
                clearInterval(interval);
            }
        }, 1000);

        return () => {
            clearInterval(interval);
        };
    }, [initialized, currentTime, sessionManager, connectionBroken]);

    React.useEffect(() => {
        const handleSessionTimerUpdate = (event) => {
            if (connectionBroken) {
                return;
            }
            
            if (event.detail.timeLeft && event.detail.timeLeft > 0) {
                setCurrentTime(event.detail.timeLeft);
            }
        };

        const handleForceHeaderUpdate = (event) => {
            if (connectionBroken) {
                return;
            }
            
            if (sessionManager && sessionManager.hasActiveSession()) {
                const newTime = sessionManager.getTimeLeft();
                setCurrentTime(newTime);
            } else {
                setCurrentTime(event.detail.timeLeft);
            }
        };

        const handlePeerDisconnect = (event) => {
            setConnectionBroken(true);
            setCurrentTime(0);
            setShowExpiredMessage(false);
            setLoggedHidden(false);
        };

        const handleNewConnection = (event) => {
            setConnectionBroken(false);
            setLoggedHidden(false); 
        };

        const handleConnectionCleaned = (event) => {
            setConnectionBroken(true);
            setCurrentTime(0);
            setShowExpiredMessage(false);
            setInitialized(false);
            setLoggedHidden(false);
        };

        const handleSessionReset = (event) => {
            setConnectionBroken(true);
            setCurrentTime(0);
            setShowExpiredMessage(false);
            setInitialized(false);
            setLoggedHidden(false);
        };

        const handleSessionCleanup = (event) => {
            setConnectionBroken(true);
            setCurrentTime(0);
            setShowExpiredMessage(false);
            setInitialized(false);
            setLoggedHidden(false);
        };

        const handleDisconnected = (event) => {
            setConnectionBroken(true);
            setCurrentTime(0);
            setShowExpiredMessage(false);
            setInitialized(false);
            setLoggedHidden(false);
        };

        document.addEventListener('session-timer-update', handleSessionTimerUpdate);
        document.addEventListener('force-header-update', handleForceHeaderUpdate);
        document.addEventListener('peer-disconnect', handlePeerDisconnect);
        document.addEventListener('new-connection', handleNewConnection);
        document.addEventListener('connection-cleaned', handleConnectionCleaned);
        document.addEventListener('session-reset', handleSessionReset);
        document.addEventListener('session-cleanup', handleSessionCleanup);
        document.addEventListener('disconnected', handleDisconnected);

        return () => {
            document.removeEventListener('session-timer-update', handleSessionTimerUpdate);
            document.removeEventListener('force-header-update', handleForceHeaderUpdate);
            document.removeEventListener('peer-disconnect', handlePeerDisconnect);
            document.removeEventListener('new-connection', handleNewConnection);
            document.removeEventListener('connection-cleaned', handleConnectionCleaned);
            document.removeEventListener('session-reset', handleSessionReset);
            document.removeEventListener('session-cleanup', handleSessionCleanup);
            document.removeEventListener('disconnected', handleDisconnected);
        };
    }, [sessionManager]);

    if (showExpiredMessage) {
        return React.createElement('div', {
            className: 'session-timer expired flex items-center space-x-2 px-3 py-1.5 rounded-lg animate-pulse',
            style: { background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.2) 0%, rgba(220, 38, 38, 0.2) 100%)' }
        }, [
            React.createElement('i', {
                key: 'icon',
                className: 'fas fa-exclamation-triangle text-red-400'
            }),
            React.createElement('span', {
                key: 'message',
                className: 'text-red-400 text-sm font-medium'
            }, 'Session Expired!')
        ]);
    }

    if (!sessionManager) {
        if (!loggedHidden) {
            console.log('⏱️ SessionTimer hidden - no sessionManager');
            setLoggedHidden(true);
        }
        return null;
    }

    if (connectionBroken) {
        if (!loggedHidden) {
            console.log('⏱️ SessionTimer hidden - connection broken');
            setLoggedHidden(true);
        }
        return null;
    }

    if (!currentTime || currentTime <= 0) {
        if (!loggedHidden) {
            console.log('⏱️ SessionTimer hidden - no time left, currentTime:', currentTime);
            setLoggedHidden(true);
        }
        return null;
    }

    if (loggedHidden) {
        setLoggedHidden(false);
    }

    const totalMinutes = Math.floor(currentTime / (60 * 1000));
    const totalSeconds = Math.floor(currentTime / 1000);
    
    const isDemo = sessionType === 'demo';
    const isWarning = isDemo ? totalMinutes <= 2 : totalMinutes <= 10;
    const isCritical = isDemo ? totalSeconds <= 60 : totalMinutes <= 5;

    const formatTime = (ms) => {
        const hours = Math.floor(ms / (60 * 60 * 1000));
        const minutes = Math.floor((ms % (60 * 60 * 1000)) / (60 * 1000));
        const seconds = Math.floor((ms % (60 * 1000)) / 1000);

        if (hours > 0) {
            return `${hours}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        } else {
            return `${minutes}:${seconds.toString().padStart(2, '0')}`;
        }
    };

    const getTimerStyle = () => {
        const totalDuration = sessionType === 'demo' ? 6 * 60 * 1000 : 60 * 60 * 1000;
        const timeProgress = (totalDuration - currentTime) / totalDuration;
        
        let backgroundColor, textColor, iconColor, iconClass, shouldPulse;
        
        if (timeProgress <= 0.33) {
            backgroundColor = 'linear-gradient(135deg, rgba(34, 197, 94, 0.15) 0%, rgba(22, 163, 74, 0.15) 100%)';
            textColor = 'text-green-400';
            iconColor = 'text-green-400';
            iconClass = 'fas fa-clock';
            shouldPulse = false;
        } else if (timeProgress <= 0.66) {
            backgroundColor = 'linear-gradient(135deg, rgba(234, 179, 8, 0.15) 0%, rgba(202, 138, 4, 0.15) 100%)';
            textColor = 'text-yellow-400';
            iconColor = 'text-yellow-400';
            iconClass = 'fas fa-clock';
            shouldPulse = false;
        } else {
            backgroundColor = 'linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(220, 38, 38, 0.15) 100%)';
            textColor = 'text-red-400';
            iconColor = 'text-red-400';
            iconClass = 'fas fa-exclamation-triangle';
            shouldPulse = true;
        }
        
        return { backgroundColor, textColor, iconColor, iconClass, shouldPulse };
    };

    const timerStyle = getTimerStyle();
    
    const handleTimerClick = () => {
        if (onDisconnect && typeof onDisconnect === 'function') {
            onDisconnect();
        }
    };

    return React.createElement('div', {
        className: `session-timer flex items-center space-x-2 px-3 py-1.5 rounded-lg transition-all duration-500 cursor-pointer hover:opacity-80 ${
            isDemo ? 'demo-session' : ''
        } ${timerStyle.shouldPulse ? 'animate-pulse' : ''}`,
        style: { background: timerStyle.backgroundColor },
        onClick: handleTimerClick,
        title: 'Click to disconnect and clear session'
    }, [
        React.createElement('i', {
            key: 'icon',
            className: `${timerStyle.iconClass} ${timerStyle.iconColor}`
        }),
        React.createElement('span', {
            key: 'time',
            className: `text-sm font-mono font-semibold ${timerStyle.textColor}`
        }, formatTime(currentTime)),
        React.createElement('div', {
            key: 'progress',
            className: 'ml-2 w-16 h-1 bg-gray-700 rounded-full overflow-hidden'
        }, [
            React.createElement('div', {
                key: 'progress-bar',
                className: `${timerStyle.textColor.replace('text-', 'bg-')} h-full rounded-full transition-all duration-500`,
                style: { 
                    width: `${Math.max(0, Math.min(100, (currentTime / (sessionType === 'demo' ? 6 * 60 * 1000 : 60 * 60 * 1000)) * 100))}%`
                }
            })
        ])
    ]);
};

window.SessionTimer = SessionTimer;

window.updateSessionTimer = (newTimeLeft, newSessionType) => {
    document.dispatchEvent(new CustomEvent('session-timer-update', {
        detail: { timeLeft: newTimeLeft, sessionType: newSessionType }
    }));
};

