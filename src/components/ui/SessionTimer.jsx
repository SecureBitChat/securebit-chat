const React = window.React;

const SessionTimer = ({ timeLeft, sessionType }) => {
    // Отладочная информация
    console.log('SessionTimer render:', { timeLeft, sessionType });
    
    if (!timeLeft || timeLeft <= 0) {
        console.log('SessionTimer: no time left, not rendering');
        return null;
    }

    const totalMinutes = Math.floor(timeLeft / (60 * 1000));
    const isWarning = totalMinutes <= 10;
    const isCritical = totalMinutes <= 5;

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

    return React.createElement('div', {
        className: `session-timer ${isCritical ? 'critical' : isWarning ? 'warning' : ''}`
    }, [
        React.createElement('i', {
            key: 'icon',
            className: 'fas fa-clock'
        }),
        React.createElement('span', {
            key: 'time'
        }, formatTime(timeLeft)),
        React.createElement('span', {
            key: 'type',
            className: 'text-xs opacity-80'
        }, sessionType?.toUpperCase() || '')
    ]);
};

window.SessionTimer = SessionTimer;