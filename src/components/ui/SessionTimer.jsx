const SessionTimer = ({ timeLeft, sessionType, sessionManager }) => {
    const [currentTime, setCurrentTime] = React.useState(timeLeft || 0);
    const [showExpiredMessage, setShowExpiredMessage] = React.useState(false);
    const [initialized, setInitialized] = React.useState(false);
    const [connectionBroken, setConnectionBroken] = React.useState(false); 


    React.useEffect(() => {
        if (connectionBroken) {
            console.log('⏱️ SessionTimer initialization skipped - connection broken');
            return;
        }
        
        let initialTime = 0;
        
        if (sessionManager?.hasActiveSession()) {
            initialTime = sessionManager.getTimeLeft();
            console.log('⏱️ SessionTimer initialized from sessionManager:', Math.floor(initialTime / 1000) + 's');
        } else if (timeLeft && timeLeft > 0) {
            initialTime = timeLeft;
            console.log('⏱️ SessionTimer initialized from props:', Math.floor(initialTime / 1000) + 's');
        }
        
        setCurrentTime(initialTime);
        setInitialized(true);
    }, [sessionManager, connectionBroken]); 

    React.useEffect(() => {
        if (connectionBroken) {
            console.log('⏱️ SessionTimer props update skipped - connection broken');
            return;
        }
        
        if (timeLeft && timeLeft > 0) {
            setCurrentTime(timeLeft);
        }
    }, [timeLeft, connectionBroken]);

    React.useEffect(() => {
        if (!initialized) {
            return;
        }

        if (connectionBroken) {
            console.log('⏱️ Timer interval skipped - connection broken');
            return;
        }

        if (!currentTime || currentTime <= 0 || !sessionManager) {
            return;
        }


        const interval = setInterval(() => {
            if (connectionBroken) {
                console.log('⏱️ Timer interval stopped - connection broken');
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
                    console.log('⏱️ Session expired!');
                    setShowExpiredMessage(true);
                    setTimeout(() => setShowExpiredMessage(false), 5000);
                    clearInterval(interval);
                }
            } else {
                console.log('⏱️ Session inactive, stopping timer');
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

            if (event.detail.timeLeft && event.detail.timeLeft > 0) {
                setCurrentTime(event.detail.timeLeft);
            }
        };

        const handleForceHeaderUpdate = (event) => {

            if (sessionManager && sessionManager.hasActiveSession()) {
                const newTime = sessionManager.getTimeLeft();
                setCurrentTime(newTime);
            }
        };

        const handlePeerDisconnect = (event) => {
            console.log('🔌 Peer disconnect detected in SessionTimer - stopping timer permanently');
            setConnectionBroken(true); 
            setCurrentTime(0);
            setShowExpiredMessage(false);
        };

        const handleNewConnection = (event) => {
            console.log('🔌 New connection detected in SessionTimer - resetting connection state');
            setConnectionBroken(false); 
        };

        document.addEventListener('session-timer-update', handleSessionTimerUpdate);
        document.addEventListener('force-header-update', handleForceHeaderUpdate);
        document.addEventListener('peer-disconnect', handlePeerDisconnect);
        document.addEventListener('new-connection', handleNewConnection);

        return () => {
            document.removeEventListener('session-timer-update', handleSessionTimerUpdate);
            document.removeEventListener('force-header-update', handleForceHeaderUpdate);
            document.removeEventListener('peer-disconnect', handlePeerDisconnect);
            document.removeEventListener('new-connection', handleNewConnection);
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
        console.log('⏱️ SessionTimer hidden - no sessionManager');
        return null;
    }

    if (connectionBroken) {
        console.log('⏱️ SessionTimer hidden - connection broken');
        return null;
    }

    if (!currentTime || currentTime <= 0) {
        console.log('⏱️ SessionTimer hidden - no time left');
        return null;
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
    
    return React.createElement('div', {
        className: `session-timer flex items-center space-x-2 px-3 py-1.5 rounded-lg transition-all duration-500 ${
            isDemo ? 'demo-session' : ''
        } ${timerStyle.shouldPulse ? 'animate-pulse' : ''}`,
        style: { background: timerStyle.backgroundColor }
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
    console.log('⏱️ Global timer update:', { newTimeLeft, newSessionType });
    document.dispatchEvent(new CustomEvent('session-timer-update', {
        detail: { timeLeft: newTimeLeft, sessionType: newSessionType }
    }));
};

console.log('✅ SessionTimer loaded with fixes and improvements');