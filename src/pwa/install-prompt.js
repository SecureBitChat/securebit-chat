class PWAInstallPrompt {
    constructor() {
        this.deferredPrompt = null;
        this.isInstalled = false;
        this.installButton = null;
        this.installBanner = null;
        this.dismissedCount = 0;
        this.maxDismissals = 3;
        this.installationChecked = false;
        // Per-page-load dismissal: hide the pill until the next reload/visit
        // instead of locking it out for 24h, so it reliably comes back.
        this.userDismissed = false;

        this.init();
    }

    init() {

        this.checkInstallationStatus();


        
        this.setupEventListeners();
        this.createInstallButton();
        this.loadInstallPreferences();

        if (this.isIOSSafari()) {
            this.startInstallationMonitoring();
        }

    }

    checkInstallationStatus() {

        const isStandalone = window.matchMedia('(display-mode: standalone)').matches;
        const isIOSStandalone = window.navigator.standalone === true;
        const hasInstallPreference = this.loadInstallPreferences().installed;
        

        if (isStandalone || isIOSStandalone || hasInstallPreference) {
            this.isInstalled = true;
            console.log('📱 App is already installed as PWA');
            document.body.classList.add('pwa-installed');
            document.body.classList.remove('pwa-browser');

            this.hideInstallPrompts();

            if (this.isIOSSafari()) {
                document.body.classList.add('ios-pwa');
            }
            
            this.installationChecked = true;
            return true;
        }

        this.isInstalled = false;
        document.body.classList.add('pwa-browser');
        document.body.classList.remove('pwa-installed');
        
        if (this.isIOSSafari()) {
            document.body.classList.add('ios-safari');
        }
        
        this.installationChecked = true;
        return false;
    }

    startInstallationMonitoring() {
        let wasStandalone = window.navigator.standalone;
        
        const checkStandalone = () => {
            const isStandalone = window.navigator.standalone;
            
            if (isStandalone && !wasStandalone && !this.isInstalled) {
                this.isInstalled = true;
                this.hideInstallPrompts();
                this.showInstallSuccess();
                document.body.classList.remove('pwa-browser', 'ios-safari');
                document.body.classList.add('pwa-installed', 'ios-pwa');

                this.saveInstallPreference('installed', true);
            }
            
            wasStandalone = isStandalone;
        };

        setInterval(checkStandalone, 2000);

        window.addEventListener('visibilitychange', () => {
            if (!document.hidden) {
                setTimeout(checkStandalone, 1000);
            }
        });

        window.addEventListener('focus', () => {
            setTimeout(checkStandalone, 500);
        });
    }

    setupEventListeners() {
        window.addEventListener('beforeinstallprompt', (event) => {
            // Don't prevent default - let browser show its own banner
            this.deferredPrompt = event;

            if (this.checkInstallationStatus()) {
                return; 
            }

            if (!this.isInstalled && this.shouldShowPrompt()) {
                setTimeout(() => this.showInstallOptions(), 1000);
            }
        });

        window.addEventListener('appinstalled', () => {
            this.isInstalled = true;
            this.hideInstallPrompts();
            this.showInstallSuccess();
            this.saveInstallPreference('installed', true);
            
            document.body.classList.remove('pwa-browser', 'ios-safari');
            document.body.classList.add('pwa-installed');
        });

        window.addEventListener('visibilitychange', () => {
            if (document.hidden) return;
            
            setTimeout(() => {
                const wasInstalled = this.isInstalled;
                this.checkInstallationStatus();

                if (!wasInstalled && this.isInstalled) {
                    this.hideInstallPrompts();
                    this.showInstallSuccess();
                }
            }, 1000);
        });

        window.addEventListener('focus', () => {
            setTimeout(() => {
                const wasInstalled = this.isInstalled;
                this.checkInstallationStatus();
                
                if (!wasInstalled && this.isInstalled) {
                    this.hideInstallPrompts();
                    this.showInstallSuccess();
                }
            }, 500);
        });
    }

    createInstallButton() {
        if (this.isInstalled) {
            return;
        }
        
        // Compact "pill" install prompt — translated from the Claude Design
        // component (Install Prompt.dc.html, compact variant). Styling is inline
        // so it tracks the design without relying on Tailwind/global CSS.
        this.installButton = document.createElement('div');
        this.installButton.id = 'pwa-install-button';
        this.installButton.className = 'hidden';
        this.installButton.style.cssText = "position:fixed; bottom:24px; right:24px; z-index:50; font-family:'Manrope',system-ui,-apple-system,sans-serif;";

        this.installButton.innerHTML = `
        <div style="position:relative; display:inline-flex;">
            <button class="close-btn" type="button" title="Dismiss" aria-label="Dismiss" style="position:absolute; top:-11px; right:-11px; z-index:3; width:28px; height:28px; padding:0; border-radius:50%; display:grid; place-items:center; border:1px solid rgba(255,255,255,0.1); background:#1a1a1d; color:#9a9aa2; cursor:pointer; transition:all .18s cubic-bezier(.2,.7,.3,1);">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="pointer-events:none;"><path d="M6 6l12 12M18 6L6 18"/></svg>
            </button>
            <button class="install-pill" type="button" style="display:inline-flex; align-items:center; gap:11px; padding:15px 26px 15px 22px; border-radius:15px; border:none; background:#f0892a; color:#1a0f04; font-family:inherit; font-size:16px; font-weight:700; letter-spacing:-0.2px; cursor:pointer; box-shadow:0 10px 30px rgba(240,137,42,0.32); transition:all .2s cubic-bezier(.2,.7,.3,1);">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" style="pointer-events:none;"><path d="M12 3v11"/><path d="M7.5 10.5L12 15l4.5-4.5"/><path d="M5 20h14"/></svg>
                Install App
            </button>
        </div>
        `;

        const pill = this.installButton.querySelector('.install-pill');
        pill.addEventListener('mouseenter', () => { pill.style.background = '#ff9637'; pill.style.transform = 'translateY(-2px)'; });
        pill.addEventListener('mouseleave', () => { pill.style.background = '#f0892a'; pill.style.transform = 'none'; });

        const closeBtn = this.installButton.querySelector('.close-btn');
        closeBtn.addEventListener('mouseenter', () => { closeBtn.style.color = '#e5727a'; closeBtn.style.borderColor = 'rgba(229,114,122,0.4)'; closeBtn.style.background = '#201416'; });
        closeBtn.addEventListener('mouseleave', () => { closeBtn.style.color = '#9a9aa2'; closeBtn.style.borderColor = 'rgba(255,255,255,0.1)'; closeBtn.style.background = '#1a1a1d'; });

        this.installButton.addEventListener('click', (e) => {
            if (!e.target.closest('.close-btn')) {
                this.handleInstallClick();
            }
        });

        closeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            this.dismissInstallPrompt();
        });

        document.body.appendChild(this.installButton);
    }

    createInstallBanner() {
        if (this.isInstalled || this.installBanner) {
            return;
        }

        this.installBanner = document.createElement('div');
        this.installBanner.id = 'pwa-install-banner';
        this.installBanner.className = 'pwa-install-banner fixed bottom-0 left-0 right-0 transform translate-y-full transition-transform duration-300 z-40';
        this.installBanner.innerHTML = `
            <div class="bg-gray-800/95 backdrop-blur-sm border-t border-gray-600/30 p-4">
                <div class="max-w-4xl mx-auto flex items-center justify-between">
                    <div class="flex items-center space-x-4">
                        <div class="w-12 h-12 bg-orange-500/10 border border-orange-500/20 rounded-lg flex items-center justify-center">
                            <i class="fas fa-shield-halved text-orange-400 text-xl"></i>
                        </div>
                        <div>
                            <div class="font-medium text-white">Install SecureBit.chat</div>
                            <div class="text-sm text-gray-300">Get the native app experience with enhanced security</div>
                        </div>
                    </div>
                    <div class="flex items-center space-x-3">
                        <button class="install-btn bg-orange-500 hover:bg-orange-600 text-white px-4 py-2 rounded-lg font-medium transition-colors" data-action="install">
                            <i class="fas fa-download mr-2"></i>
                            Install
                        </button>
                        <button class="close-btn text-gray-400 hover:text-white px-3 py-2 rounded-lg transition-colors" data-action="close">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                </div>
            </div>
        `;

        // Handle banner actions
        this.installBanner.addEventListener('click', (event) => {
            const action = event.target.closest('[data-action]')?.dataset.action;
            
            if (action === 'install') {
                this.handleInstallClick();
            } else if (action === 'close') {
                this.dismissInstallPrompt();
            }
        });

        document.body.appendChild(this.installBanner);
    }

    showInstallOptions() {
        
        if (this.isIOSSafari()) {
            this.showInstallButton();
        } else if (this.isMobileDevice()) {
            this.showInstallBanner();
        } else {
            this.showInstallButton();
        }
    }

    showInstallButton() {

        
        if (this.installButton && !this.isInstalled) {
            this.installButton.classList.remove('hidden');
            
            // Add entrance animation
            setTimeout(() => {
                this.installButton.style.transform = 'scale(1.1)';
                setTimeout(() => {
                    this.installButton.style.transform = 'scale(1)';
                }, 200);
            }, 100);

        } else {
        }
    }

    showInstallBanner() {
        if (this.checkInstallationStatus()) {
            return;
        }
        
        if (!this.installBanner) {
            this.createInstallBanner();
        }
        
        if (this.installBanner && !this.isInstalled) {
            setTimeout(() => {
                this.installBanner.classList.add('show');
                this.installBanner.style.transform = 'translateY(0)';
            }, 1000);

        } else {
        }
    }

    hideInstallPrompts() {
        
        if (this.installButton) {
            this.installButton.classList.add('hidden');
            if (this.isInstalled) {
                this.installButton.remove();
                this.installButton = null;
            }
            console.log('💿 Install button hidden');
        }
        
        if (this.installBanner) {
            this.installBanner.classList.remove('show');
            this.installBanner.style.transform = 'translateY(100%)';
            if (this.isInstalled) {
                setTimeout(() => {
                    if (this.installBanner) {
                        this.installBanner.remove();
                        this.installBanner = null;
                    }
                }, 300);
            }
        }
    }

    async handleInstallClick() {
        if (this.isIOSSafari()) {
            this.showIOSInstallInstructions();
            return;
        }

        if (!this.deferredPrompt) {
            console.warn('⚠️ Install prompt not available');
            this.showFallbackInstructions();
            return;
        }

        try {
            
            const result = await this.deferredPrompt.prompt();

            if (result.outcome === 'accepted') {
                this.isInstalled = true; 
                this.hideInstallPrompts();
                this.saveInstallPreference('accepted', true);
                this.saveInstallPreference('installed', true);
            } else {
                this.handleInstallDismissal();
            }

            this.deferredPrompt = null;

        } catch (error) {
            console.error('❌ Install prompt failed:', error);
            this.showFallbackInstructions();
        }
    }

    showIOSInstallInstructions() {
        const modal = document.createElement('div');
        modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4 backdrop-blur-sm';
        modal.innerHTML = `
            <div class="bg-gray-800 rounded-xl p-6 max-w-sm w-full text-center">
                <div class="w-16 h-16 bg-blue-500/10 rounded-full flex items-center justify-center mx-auto mb-4">
                    <i class="fab fa-apple text-blue-400 text-2xl"></i>
                </div>
                <h3 class="text-xl font-semibold text-white mb-4">Install on iOS</h3>
                
                <div class="space-y-4 text-left text-sm text-gray-300 mb-6">
                    <div class="flex items-start space-x-3">
                        <div class="w-8 h-8 bg-blue-500 rounded-full text-white flex items-center justify-center text-sm font-bold flex-shrink-0 mt-0.5">1</div>
                        <div class="flex-1">
                            <div class="font-medium text-white mb-1">Tap the Share button</div>
                            <div class="flex items-center text-blue-400">
                                <i class="fas fa-share mr-2"></i>
                                <span>Usually at the bottom of Safari</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="flex items-start space-x-3">
                        <div class="w-8 h-8 bg-blue-500 rounded-full text-white flex items-center justify-center text-sm font-bold flex-shrink-0 mt-0.5">2</div>
                        <div class="flex-1">
                            <div class="font-medium text-white mb-1">Find "Add to Home Screen"</div>
                            <div class="text-gray-400">Scroll down in the share menu</div>
                        </div>
                    </div>
                    
                    <div class="flex items-start space-x-3">
                        <div class="w-8 h-8 bg-blue-500 rounded-full text-white flex items-center justify-center text-sm font-bold flex-shrink-0 mt-0.5">3</div>
                        <div class="flex-1">
                            <div class="font-medium text-white mb-1">Tap "Add"</div>
                            <div class="text-gray-400">Confirm to install SecureBit.chat</div>
                        </div>
                    </div>
                </div>
                
                <div class="bg-orange-500/10 border border-orange-500/20 rounded-lg p-3 mb-4">
                    <p class="text-orange-300 text-xs">
                        <i class="fas fa-info-circle mr-1"></i>
                        After installation, open SecureBit from your home screen for the best experience.
                    </p>
                </div>
                
                <div class="flex space-x-3">
                    <button class="got-it-btn flex-1 bg-blue-500 hover:bg-blue-600 text-white py-3 px-4 rounded-lg font-medium transition-colors">
                        Got it
                    </button>
                    <button class="close-btn flex-1 bg-gray-600 hover:bg-gray-500 text-white py-3 px-4 rounded-lg font-medium transition-colors">
                        Close
                    </button>
                </div>
            </div>
        `;
        
        const gotItBtn = modal.querySelector('.got-it-btn');
        const closeBtn = modal.querySelector('.close-btn');
        
        gotItBtn.addEventListener('click', () => {
            modal.remove();
            this.saveInstallPreference('ios_instructions_shown', Date.now());
        });
        
        closeBtn.addEventListener('click', () => {
            modal.remove();
            this.dismissedCount++;
            this.saveInstallPreference('dismissed', this.dismissedCount);
        });
        
        document.body.appendChild(modal);
        this.saveInstallPreference('ios_instructions_shown', Date.now());
    }

    showFallbackInstructions() {
        // Per-browser install guide — translated from the Claude Design component
        // (Install Guide.dc.html). Styling is inline so it tracks the design.
        const modal = document.createElement('div');
        modal.id = 'pwa-install-guide';
        modal.style.cssText = "position:fixed; inset:0; z-index:9999; display:flex; align-items:center; justify-content:center; padding:24px; background:rgba(8,8,10,0.55); backdrop-filter:blur(3px); -webkit-backdrop-filter:blur(3px); animation:igFade .3s ease; font-family:'Manrope',system-ui,-apple-system,sans-serif;";

        const rowIcon = {
            chromeEdge: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 9h18"/><path d="M12 12v4M10 14l2 2 2-2"/>',
            firefox: '<path d="M6 3h12v18l-6-4-6 4z"/>',
            safari: '<path d="M12 15V4M8.5 7.5L12 4l3.5 3.5"/><path d="M6 11H5a1 1 0 0 0-1 1v7a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-7a1 1 0 0 0-1-1h-1"/>'
        };

        const row = (icon, title, desc, delay, nowrap) => `
            <div style="display:flex; align-items:center; gap:14px; padding:14px 16px; border-radius:13px; background:#161618; border:1px solid rgba(255,255,255,0.06); animation:igRow ${delay} cubic-bezier(.2,.7,.3,1);">
                <div style="flex:none; width:40px; height:40px; border-radius:11px; display:grid; place-items:center; background:rgba(240,137,42,0.1); border:1px solid rgba(240,137,42,0.22);">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f0892a" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">${icon}</svg>
                </div>
                <div style="flex:1; min-width:0;">
                    <div style="font-size:14.5px; font-weight:700; color:#f4f4f6; margin-bottom:2px;">${title}</div>
                    <div style="font-size:13px; color:#8a8a92;${nowrap ? ' white-space:nowrap;' : ''}">${desc}</div>
                </div>
            </div>`;

        modal.innerHTML = `
            <div style="position:relative; z-index:2; width:480px; max-width:calc(100vw - 48px); border-radius:22px; background:#121214; border:1px solid rgba(255,255,255,0.08); padding:34px 30px 26px; box-shadow:0 30px 70px rgba(0,0,0,0.6); animation:igPop .32s cubic-bezier(.2,.7,.3,1);">
                <button class="close-x" type="button" title="Close" aria-label="Close" style="position:absolute; top:18px; right:18px; width:30px; height:30px; padding:0; border-radius:9px; display:grid; place-items:center; border:1px solid rgba(255,255,255,0.08); background:rgba(255,255,255,0.02); color:#8a8a92; cursor:pointer; transition:all .18s cubic-bezier(.2,.7,.3,1);">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" style="pointer-events:none;"><path d="M6 6l12 12M18 6L6 18"/></svg>
                </button>

                <div style="text-align:center; margin-bottom:24px;">
                    <div style="display:inline-flex; width:60px; height:60px; border-radius:16px; align-items:center; justify-content:center; background:rgba(240,137,42,0.12); border:1px solid rgba(240,137,42,0.3); margin-bottom:18px;">
                        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#f0892a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v11"/><path d="M7.5 10.5L12 15l4.5-4.5"/><path d="M5 20h14"/></svg>
                    </div>
                    <h3 style="margin:0 0 10px; font-size:24px; font-weight:800; letter-spacing:-0.6px; color:#f4f4f6;">Install SecureBit</h3>
                    <p style="margin:0 auto; max-width:380px; font-size:14px; line-height:1.55; color:#9a9aa2;">Your browser handles installs its own way. Pick the steps that match yours.</p>
                </div>

                <div style="display:flex; flex-direction:column; gap:10px; margin-bottom:22px;">
                    ${row(rowIcon.chromeEdge, 'Chrome / Edge', 'Click the install icon in the address bar', '.34s', false)}
                    ${row(rowIcon.firefox, 'Firefox', 'Add a bookmark to your home screen', '.42s', false)}
                    ${row(rowIcon.safari, 'Safari', 'Share &rarr; Add to Home Screen', '.5s', true)}
                </div>

                <button class="got-it" type="button" style="width:100%; padding:14px 20px; border-radius:13px; border:1px solid rgba(255,255,255,0.1); background:rgba(255,255,255,0.03); color:#e8e8eb; font-family:inherit; font-size:15px; font-weight:700; cursor:pointer; transition:all .2s cubic-bezier(.2,.7,.3,1);">Got it</button>
            </div>
        `;

        const closeX = modal.querySelector('.close-x');
        closeX.addEventListener('mouseenter', () => { closeX.style.color = '#e5727a'; closeX.style.borderColor = 'rgba(229,114,122,0.4)'; });
        closeX.addEventListener('mouseleave', () => { closeX.style.color = '#8a8a92'; closeX.style.borderColor = 'rgba(255,255,255,0.08)'; });

        const gotIt = modal.querySelector('.got-it');
        gotIt.addEventListener('mouseenter', () => { gotIt.style.borderColor = 'rgba(255,255,255,0.22)'; gotIt.style.background = 'rgba(255,255,255,0.06)'; });
        gotIt.addEventListener('mouseleave', () => { gotIt.style.borderColor = 'rgba(255,255,255,0.1)'; gotIt.style.background = 'rgba(255,255,255,0.03)'; });

        const close = () => modal.remove();
        closeX.addEventListener('click', close);
        gotIt.addEventListener('click', close);
        modal.addEventListener('click', (e) => { if (e.target === modal) close(); });

        if (!document.getElementById('pwa-install-guide-kf')) {
            const style = document.createElement('style');
            style.id = 'pwa-install-guide-kf';
            style.textContent = '@keyframes igPop{from{opacity:0;transform:scale(.96) translateY(10px)}to{opacity:1;transform:scale(1) translateY(0)}}@keyframes igFade{from{opacity:0}to{opacity:1}}@keyframes igRow{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}';
            document.head.appendChild(style);
        }

        document.body.appendChild(modal);
    }

    showInstallSuccess() {
        
        const notification = document.createElement('div');
        notification.className = 'fixed top-4 right-4 bg-green-500 text-white p-4 rounded-lg shadow-lg z-50 max-w-sm transform translate-x-full transition-transform duration-300';
        
        const successText = this.isIOSSafari() ? 
            'iOS App installed! Open from home screen.' : 
            'SecureBit.chat is now on your device';
            
        notification.innerHTML = `
            <div class="flex items-center space-x-3">
                <div class="w-8 h-8 bg-white/20 rounded-full flex items-center justify-center">
                    <i class="fas fa-check text-lg"></i>
                </div>
                <div>
                    <div class="font-medium">App Installed!</div>
                    <div class="text-sm opacity-90">${successText}</div>
                </div>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.classList.remove('translate-x-full');
        }, 100);
        
        setTimeout(() => {
            notification.classList.add('translate-x-full');
            setTimeout(() => notification.remove(), 300);
        }, 5000);

        this.hideInstallPrompts();
    }

    shouldShowPrompt() {
        if (this.checkInstallationStatus()) {
            return false;
        }
        
        const preferences = this.loadInstallPreferences();
        
        if (preferences.installed) {
            this.isInstalled = true;
            this.hideInstallPrompts();
            return false;
        }
        
        // Hidden only for the current page load once the user dismisses it;
        // a reload or a fresh visit surfaces it again (until installed).
        if (this.userDismissed) return false;

        if (this.isIOSSafari()) {
            const lastShown = preferences.ios_instructions_shown;

            if (lastShown && Date.now() - lastShown < 24 * 60 * 60 * 1000) {
                return false;
            }

            return true;
        }

        return true;
    }

    dismissInstallPrompt() {
        this.userDismissed = true;
        this.dismissedCount++;
        this.hideInstallPrompts();
        this.saveInstallPreference('dismissed', this.dismissedCount);
    }

    handleInstallDismissal() {
        this.dismissedCount++;
        this.saveInstallPreference('dismissed', this.dismissedCount);
        
        if (this.dismissedCount < this.maxDismissals) {
            setTimeout(() => {
                if (!this.isInstalled && this.shouldShowPrompt()) {
                    this.showInstallButton();
                }
            }, 300000); 
        }
    }

    showFinalDismissalMessage() {
        const notification = document.createElement('div');
        notification.className = 'fixed bottom-4 left-4 right-4 bg-blue-500/90 text-white p-4 rounded-lg shadow-lg z-50 backdrop-blur-sm';
        notification.innerHTML = `
            <div class="flex items-start space-x-3">
                <div class="w-8 h-8 bg-white/20 rounded-full flex items-center justify-center flex-shrink-0">
                    <i class="fas fa-info text-sm"></i>
                </div>
                <div class="flex-1">
                    <div class="font-medium mb-1">Install Anytime</div>
                    <div class="text-sm opacity-90 mb-3">
                        You can still install SecureBit.chat from your browser's menu for the best experience.
                    </div>
                    <button class="ok-btn text-sm bg-white/20 hover:bg-white/30 px-3 py-1 rounded transition-colors">
                        OK
                    </button>
                </div>
            </div>
        `;
        
        const okBtn = notification.querySelector('.ok-btn');
        okBtn.addEventListener('click', () => {
            notification.remove();
        });
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 10000);
    }

    saveInstallPreference(action, value) {
        const preferences = this.loadInstallPreferences();
        preferences[action] = value;
        
        if (action === 'dismissed') {
            preferences.lastDismissed = Date.now();
        }
        
        try {
            localStorage.setItem('pwa_install_prefs', JSON.stringify(preferences));
        } catch (error) {
            console.warn('⚠️ Could not save install preferences:', error);
        }
    }

    loadInstallPreferences() {
        try {
            const saved = localStorage.getItem('pwa_install_prefs');
            return saved ? JSON.parse(saved) : { dismissed: 0, installed: false };
        } catch (error) {
            console.warn('⚠️ Could not load install preferences:', error);
            return { dismissed: 0, installed: false };
        }
    }

    isMobileDevice() {
        return /Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
    }

    isIOSSafari() {
        const userAgent = navigator.userAgent;
        const isIOS = /iPad|iPhone|iPod/.test(userAgent);
        const isSafari = /Safari/.test(userAgent) && !/CriOS|FxiOS|EdgiOS/.test(userAgent);
        return isIOS && isSafari;
    }

    // Public API methods
    showInstallPrompt() {
        
        if (this.isIOSSafari()) {
            this.showIOSInstallInstructions();
        } else if (this.deferredPrompt && !this.isInstalled) {
            this.handleInstallClick();
        } else {
            this.showFallbackInstructions();
        }
    }

    hideInstallPrompt() {
        this.hideInstallPrompts();
    }

    getInstallStatus() {
        this.checkInstallationStatus();
        
        return {
            isInstalled: this.isInstalled,
            canPrompt: !!this.deferredPrompt && !this.isInstalled,
            isIOSSafari: this.isIOSSafari(),
            dismissedCount: this.dismissedCount,
            shouldShowPrompt: this.shouldShowPrompt()
        };
    }

    resetDismissals() {
        this.dismissedCount = 0;
        this.saveInstallPreference('dismissed', 0);
    }

    // Method for setting service worker registration
    setServiceWorkerRegistration(registration) {
        this.swRegistration = registration;
    }

    forceInstallationCheck() {
        this.installationChecked = false;
        const wasInstalled = this.isInstalled;
        const isNowInstalled = this.checkInstallationStatus();
        
        if (!wasInstalled && isNowInstalled) {
            this.hideInstallPrompts();
            this.showInstallSuccess();
        }
        
        return isNowInstalled;
    }
}

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PWAInstallPrompt;
} else {
    window.PWAInstallPrompt = PWAInstallPrompt;
}

// Auto-initialize
if (typeof window !== 'undefined') {
    window.addEventListener('DOMContentLoaded', () => {
        if (!window.pwaInstallPrompt) {
            window.pwaInstallPrompt = new PWAInstallPrompt();
        }
    });
    
    window.addEventListener('load', () => {
        if (window.pwaInstallPrompt) {
            setTimeout(() => {
                window.pwaInstallPrompt.forceInstallationCheck();
            }, 1000);
        }
    });
}