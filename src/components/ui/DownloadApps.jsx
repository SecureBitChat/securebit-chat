const DownloadApps = () => {
    const apps = [
        { id: 'web', name: 'Web App', subtitle: 'Browser Version', icon: 'fas fa-globe', platform: 'Web', isActive: true, url: 'https://securebit.chat/', color: 'green' },
        { id: 'windows', name: 'Windows', subtitle: 'Desktop App', icon: 'fab fa-windows', platform: 'Desktop', isActive: true, url: 'https://securebit.chat/download/windows/SecureBit%20Chat%20Setup%204.1.222.exe', color: 'blue' },
        { id: 'macos', name: 'macOS', subtitle: 'Desktop App', icon: 'fab fa-safari', platform: 'Desktop', isActive: false, url: '#', color: 'gray' }, 
        { id: 'linux', name: 'Linux', subtitle: 'Desktop App', icon: 'fab fa-linux', platform: 'Desktop', isActive: false, url: '#', color: 'orange' },
        { id: 'ios', name: 'iOS', subtitle: 'iPhone & iPad', icon: 'fab fa-apple', platform: 'Mobile', isActive: false, url: 'https://apps.apple.com/app/securebit-chat/', color: 'white' },
        { id: 'android', name: 'Android', subtitle: 'Google Play', icon: 'fab fa-android', platform: 'Mobile', isActive: false, url: 'https://play.google.com/store/apps/details?id=com.securebit.chat', color: 'green' }
    ];

    const handleDownload = (app) => {
        if (app.isActive) window.open(app.url, '_blank');
    };

    const desktopApps = apps.filter(a => a.platform !== 'Mobile');
    const mobileApps = apps.filter(a => a.platform === 'Mobile');

    const cardSize = "w-28 h-28"; 

    const colorClasses = {
        green: 'text-green-500',
        blue: 'text-blue-500',
        blueios: 'text-blue-600',
        gray: 'text-gray-500',
        orange: 'text-orange-500',
    };

    const renderAppCard = (app) => (
        React.createElement('div', {
            key: app.id,
            className: `group relative ${cardSize} rounded-2xl overflow-hidden card-minimal cursor-pointer`
        }, [
            React.createElement('i', {
                key: 'bg-icon',
                className: `${app.icon} absolute text-[3rem] ${app.isActive ? colorClasses[app.color] : 'text-white/10'} top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none transition-all duration-500 group-hover:scale-105`
            }),
            React.createElement('div', {
                key: 'overlay',
                className: "absolute inset-0 bg-black/30 backdrop-blur-md flex flex-col items-center justify-center text-center opacity-0 transition-opacity duration-300 group-hover:opacity-100"
            }, [
                React.createElement('h4', { key: 'name', className: `text-sm font-semibold text-primary mb-1` }, app.name),
                React.createElement('p', { key: 'subtitle', className: `text-xs text-secondary mb-2` }, app.subtitle),
                app.isActive ?
                    React.createElement('button', {
                        key: 'btn',
                        onClick: () => handleDownload(app),
                        className: `px-2 py-1 rounded-xl bg-emerald-500 text-black font-medium hover:bg-emerald-600 transition-colors text-xs`
                    }, app.id === "web" ? "Launch" : "Download")
                    :
                    React.createElement('span', { key: 'coming', className: "text-gray-400 font-medium text-xs" }, "Coming Soon")
            ])
        ])
    );

    return React.createElement('div', { className: "mt-20 px-6" }, [
        // Header
        React.createElement('div', { key: 'header', className: "text-center max-w-3xl mx-auto mb-12" }, [
            React.createElement('h3', { key: 'title', className: "text-3xl font-bold text-primary mb-3" }, 'Download SecureBit.chat'),
            React.createElement('p', { key: 'subtitle', className: "text-secondary text-lg mb-5" }, 'Stay secure on every device. Choose your platform and start chatting privately.')
        ]),

        // Desktop Apps
        React.createElement('div', { key: 'desktop-row', className: "hidden sm:flex justify-center flex-wrap gap-6 mb-6" },
            desktopApps.map(renderAppCard)
        ),

        // Mobile Apps
        React.createElement('div', { key: 'mobile-row', className: "flex justify-center gap-6" },
            mobileApps.map(renderAppCard)
        )
    ]);
};

window.DownloadApps = DownloadApps;
