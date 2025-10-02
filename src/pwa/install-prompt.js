class PWAInstallPrompt {
    constructor() {
        this.deferredPrompt = null;
        this.isInstalled = false;
        this.installButton = null;
        this.installBanner = null;
        this.dismissedCount = 0;
        this.maxDismissals = 3;
        this.installationChecked = false;
        
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
            event.preventDefault();
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
        
        this.installButton = document.createElement('div');
        this.installButton.id = 'pwa-install-button';
        this.installButton.className = 'hidden fixed bottom-6 right-6 bg-gradient-to-r from-orange-500 to-orange-600 hover:from-orange-600 hover:to-orange-700 text-white px-6 py-3 rounded-full shadow-lg transition-all duration-300 z-50 flex items-center space-x-3 group';
        
        const buttonText = this.isIOSSafari() ? 'Install App' : 'Install App';
        const buttonIcon = this.isIOSSafari() ? 'fas fa-share' : 'fas fa-download';
        
        this.installButton.innerHTML = `
        <i class="${buttonIcon} transition-transform group-hover:scale-110"></i>
        <span class="font-medium">${buttonText}</span>
        <button class="close-btn absolute -top-2 -right-2 w-6 h-6 bg-red-500 hover:bg-red-600 rounded-full text-white text-xs flex items-center justify-center transition-colors">
            ×
        </button>
        `;


        this.installButton.addEventListener('click', (e) => {
            if (!e.target.classList.contains('close-btn')) {
                this.handleInstallClick();
            }
        });

        const closeBtn = this.installButton.querySelector('.close-btn');
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
        const modal = document.createElement('div');
        modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4 backdrop-blur-sm';
        modal.innerHTML = `
            <div class="bg-gray-800 rounded-xl p-6 max-w-md w-full text-center">
                <div class="w-16 h-16 bg-orange-500/10 rounded-full flex items-center justify-center mx-auto mb-4">
                    <i class="fas fa-download text-orange-400 text-2xl"></i>
                </div>
                <h3 class="text-xl font-semibold text-white mb-4">Install SecureBit.chat</h3>
                <p class="text-gray-300 text-sm mb-6 leading-relaxed">
                    To install this app, look for the install option in your browser menu or address bar. 
                    Different browsers have different install methods.
                </p>
                
                <div class="space-y-3 text-left text-sm">
                    <div class="bg-gray-700/50 rounded-lg p-3">
                        <div class="font-medium text-white mb-1">Chrome/Edge</div>
                        <div class="text-gray-400">Look for install icon in address bar</div>
                    </div>
                    <div class="bg-gray-700/50 rounded-lg p-3">
                        <div class="font-medium text-white mb-1">Firefox</div>
                        <div class="text-gray-400">Add bookmark to home screen</div>
                    </div>
                    <div class="bg-gray-700/50 rounded-lg p-3">
                        <div class="font-medium text-white mb-1">Safari</div>
                        <div class="text-gray-400">Share → Add to Home Screen</div>
                    </div>
                </div>
                
                <button class="close-btn w-full bg-orange-500 hover:bg-orange-600 text-white py-3 px-4 rounded-lg font-medium transition-colors mt-6">
                    Close
                </button>
            </div>
        `;
        
        const closeBtn = modal.querySelector('.close-btn');
        closeBtn.addEventListener('click', () => {
            modal.remove();
        });
        
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
        
        if (this.isIOSSafari()) {
            const lastShown = preferences.ios_instructions_shown;
            
            if (lastShown && Date.now() - lastShown < 24 * 60 * 60 * 1000) {
                return false;
            }
            
            return true;
        }

        if (preferences.dismissed >= this.maxDismissals) return false;
        
        const lastDismissed = preferences.lastDismissed;
        if (lastDismissed && Date.now() - lastDismissed < 24 * 60 * 60 * 1000) {
            return false;
        }
        
        return true;
    }

    dismissInstallPrompt() {
        this.dismissedCount++;
        this.hideInstallPrompts();
        this.saveInstallPreference('dismissed', this.dismissedCount);
        
        // Show encouraging message on final dismissal
        if (this.dismissedCount >= this.maxDismissals) {
            this.showFinalDismissalMessage();
        }
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