// PWA Install Prompt Manager for SecureBit.chat
// Enhanced Security Edition v4.01.212

class PWAInstallPrompt {
    constructor() {
        this.deferredPrompt = null;
        this.isInstalled = false;
        this.installButton = null;
        this.installBanner = null;
        this.dismissedCount = 0;
        this.maxDismissals = 3;
        
        this.init();
    }

    init() {
        console.log('💿 PWA Install Prompt initializing...');
        
        this.checkInstallationStatus();
        this.setupEventListeners();
        this.createInstallButton();
        this.loadInstallPreferences();
        
        console.log('✅ PWA Install Prompt initialized');
    }

    checkInstallationStatus() {
        // Check if app is already installed
        if (window.matchMedia('(display-mode: standalone)').matches || 
            window.navigator.standalone === true) {
            this.isInstalled = true;
            console.log('📱 App is already installed as PWA');
            document.body.classList.add('pwa-installed');
            return true;
        }
        
        // Check for iOS Safari specific installation
        if (this.isIOSSafari()) {
            this.isInstalled = window.navigator.standalone === true;
        }
        
        document.body.classList.add(this.isInstalled ? 'pwa-installed' : 'pwa-browser');
        return this.isInstalled;
    }

    setupEventListeners() {
        // Capture the install prompt event
        window.addEventListener('beforeinstallprompt', (event) => {
            console.log('💿 Install prompt event captured');
            event.preventDefault();
            this.deferredPrompt = event;
            
            if (!this.isInstalled && this.shouldShowPrompt()) {
                this.showInstallOptions();
            }
        });

        // Handle successful installation
        window.addEventListener('appinstalled', () => {
            console.log('✅ PWA installed successfully');
            this.isInstalled = true;
            this.hideInstallPrompts();
            this.showInstallSuccess();
            this.saveInstallPreference('installed', true);
            
            // Update UI for installed state
            document.body.classList.remove('pwa-browser');
            document.body.classList.add('pwa-installed');
        });

        // Handle iOS installation detection
        if (this.isIOSSafari()) {
            window.addEventListener('visibilitychange', () => {
                if (document.hidden) return;
                
                setTimeout(() => {
                    if (window.navigator.standalone && !this.isInstalled) {
                        this.isInstalled = true;
                        this.hideInstallPrompts();
                        this.showInstallSuccess();
                    }
                }, 1000);
            });
        }
    }

    createInstallButton() {
        // Create floating install button
        this.installButton = document.createElement('button');
        this.installButton.id = 'pwa-install-button';
        this.installButton.className = 'hidden fixed bottom-6 right-6 bg-gradient-to-r from-orange-500 to-orange-600 hover:from-orange-600 hover:to-orange-700 text-white px-6 py-3 rounded-full shadow-lg transition-all duration-300 z-50 flex items-center space-x-3 group';
        this.installButton.innerHTML = `
            <i class="fas fa-download transition-transform group-hover:scale-110"></i>
            <span class="font-medium">Install App</span>
            <div class="absolute -top-1 -right-1 w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
        `;
        
        this.installButton.addEventListener('click', () => {
            this.handleInstallClick();
        });
        
        document.body.appendChild(this.installButton);
    }

    createInstallBanner() {
        if (this.installBanner) return;

        this.installBanner = document.createElement('div');
        this.installBanner.id = 'pwa-install-banner';
        this.installBanner.className = 'pwa-install-banner fixed bottom-0 left-0 right-0 transform translate-y-full transition-transform duration-300 z-40';
        this.installBanner.innerHTML = `
            <div class="content">
                <div class="icon">
                    <i class="fas fa-shield-halved text-2xl"></i>
                </div>
                <div class="text">
                    <div class="title">Install SecureBit.chat</div>
                    <div class="subtitle">Get the native app experience with enhanced security</div>
                </div>
            </div>
            <div class="actions">
                <button class="install-btn" data-action="install">
                    <i class="fas fa-download mr-2"></i>
                    Install
                </button>
                <button class="dismiss-btn" data-action="dismiss">
                    Later
                </button>
            </div>
        `;

        // Handle banner actions
        this.installBanner.addEventListener('click', (event) => {
            const action = event.target.closest('[data-action]')?.dataset.action;
            
            if (action === 'install') {
                this.handleInstallClick();
            } else if (action === 'dismiss') {
                this.dismissInstallPrompt();
            }
        });

        document.body.appendChild(this.installBanner);
    }

    showInstallOptions() {
        if (this.isInstalled) return;
        
        // For mobile devices, show banner
        if (this.isMobileDevice()) {
            this.showInstallBanner();
        } else {
            // For desktop, show floating button
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
            
            console.log('💿 Install button shown');
        }
    }

    showInstallBanner() {
        if (!this.installBanner) {
            this.createInstallBanner();
        }
        
        if (this.installBanner && !this.isInstalled) {
            setTimeout(() => {
                this.installBanner.classList.add('show');
            }, 1000);
            
            console.log('💿 Install banner shown');
        }
    }

    hideInstallPrompts() {
        if (this.installButton) {
            this.installButton.classList.add('hidden');
        }
        
        if (this.installBanner) {
            this.installBanner.classList.remove('show');
        }
    }

    async handleInstallClick() {
        if (this.isIOSSafari()) {
            this.showIOSInstructions();
            return;
        }

        if (!this.deferredPrompt) {
            console.warn('⚠️ Install prompt not available');
            this.showFallbackInstructions();
            return;
        }

        try {
            console.log('💿 Showing install prompt...');
            
            // Show the install prompt
            const result = await this.deferredPrompt.prompt();
            console.log('💿 Install prompt result:', result.outcome);

            if (result.outcome === 'accepted') {
                console.log('✅ User accepted install prompt');
                this.hideInstallPrompts();
                this.saveInstallPreference('accepted', true);
            } else {
                console.log('❌ User dismissed install prompt');
                this.handleInstallDismissal();
            }

            // Clear the deferred prompt
            this.deferredPrompt = null;

        } catch (error) {
            console.error('❌ Install prompt failed:', error);
            this.showFallbackInstructions();
        }
    }

    showIOSInstructions() {
        const modal = document.createElement('div');
        modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4';
        modal.innerHTML = `
            <div class="bg-gray-800 rounded-xl p-6 max-w-sm w-full text-center">
                <div class="w-16 h-16 bg-blue-500/10 rounded-full flex items-center justify-center mx-auto mb-4">
                    <i class="fab fa-apple text-blue-400 text-2xl"></i>
                </div>
                <h3 class="text-xl font-semibold text-white mb-4">Install on iOS</h3>
                <div class="space-y-3 text-left text-sm text-gray-300">
                    <div class="flex items-center space-x-3">
                        <div class="w-6 h-6 bg-blue-500 rounded text-white flex items-center justify-center text-xs font-bold">1</div>
                        <span>Tap the Share button <i class="fas fa-share text-blue-400"></i></span>
                    </div>
                    <div class="flex items-center space-x-3">
                        <div class="w-6 h-6 bg-blue-500 rounded text-white flex items-center justify-center text-xs font-bold">2</div>
                        <span>Select "Add to Home Screen"</span>
                    </div>
                    <div class="flex items-center space-x-3">
                        <div class="w-6 h-6 bg-blue-500 rounded text-white flex items-center justify-center text-xs font-bold">3</div>
                        <span>Tap "Add" to install</span>
                    </div>
                </div>
                <button onclick="this.parentElement.parentElement.remove()" 
                        class="w-full bg-blue-500 hover:bg-blue-600 text-white py-3 px-4 rounded-lg font-medium transition-colors mt-6">
                    Got it
                </button>
            </div>
        `;
        
        document.body.appendChild(modal);
    }

    showFallbackInstructions() {
        const modal = document.createElement('div');
        modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4';
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
                
                <button onclick="this.parentElement.parentElement.remove()" 
                        class="w-full bg-orange-500 hover:bg-orange-600 text-white py-3 px-4 rounded-lg font-medium transition-colors mt-6">
                    Close
                </button>
            </div>
        `;
        
        document.body.appendChild(modal);
    }

    showInstallSuccess() {
        const notification = document.createElement('div');
        notification.className = 'fixed top-4 right-4 bg-green-500 text-white p-4 rounded-lg shadow-lg z-50 max-w-sm transform translate-x-full transition-transform duration-300';
        notification.innerHTML = `
            <div class="flex items-center space-x-3">
                <div class="w-8 h-8 bg-white/20 rounded-full flex items-center justify-center">
                    <i class="fas fa-check text-lg"></i>
                </div>
                <div>
                    <div class="font-medium">App Installed!</div>
                    <div class="text-sm opacity-90">SecureBit.chat is now on your device</div>
                </div>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        // Animate in
        setTimeout(() => {
            notification.classList.remove('translate-x-full');
        }, 100);
        
        // Auto-remove after 4 seconds
        setTimeout(() => {
            notification.classList.add('translate-x-full');
            setTimeout(() => notification.remove(), 300);
        }, 4000);
    }

    dismissInstallPrompt() {
        this.dismissedCount++;
        this.hideInstallPrompts();
        this.saveInstallPreference('dismissed', this.dismissedCount);
        
        console.log(`💿 Install prompt dismissed (${this.dismissedCount}/${this.maxDismissals})`);
        
        // Show encouraging message on final dismissal
        if (this.dismissedCount >= this.maxDismissals) {
            this.showFinalDismissalMessage();
        }
    }

    handleInstallDismissal() {
        this.dismissedCount++;
        this.saveInstallPreference('dismissed', this.dismissedCount);
        
        if (this.dismissedCount < this.maxDismissals) {
            // Show reminder after some time
            setTimeout(() => {
                if (!this.isInstalled && this.shouldShowPrompt()) {
                    this.showInstallButton();
                }
            }, 300000); // 5 minutes
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
                    <button onclick="this.parentElement.parentElement.remove()" 
                            class="text-sm bg-white/20 hover:bg-white/30 px-3 py-1 rounded transition-colors">
                        OK
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 10000);
    }

    shouldShowPrompt() {
        const preferences = this.loadInstallPreferences();
        
        // Don't show if already installed
        if (this.isInstalled) return false;
        
        // Don't show if dismissed too many times
        if (preferences.dismissed >= this.maxDismissals) return false;
        
        // Don't show if recently dismissed (less than 24 hours)
        const lastDismissed = preferences.lastDismissed;
        if (lastDismissed && Date.now() - lastDismissed < 24 * 60 * 60 * 1000) {
            return false;
        }
        
        return true;
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
        return /iPad|iPhone|iPod/.test(userAgent) && /Safari/.test(userAgent) && !/CriOS|FxiOS/.test(userAgent);
    }

    // Public API methods
    showInstallPrompt() {
        if (this.deferredPrompt && !this.isInstalled) {
            this.handleInstallClick();
        } else {
            this.showFallbackInstructions();
        }
    }

    hideInstallPrompt() {
        this.hideInstallPrompts();
    }

    getInstallStatus() {
        return {
            isInstalled: this.isInstalled,
            canPrompt: !!this.deferredPrompt,
            dismissedCount: this.dismissedCount,
            shouldShowPrompt: this.shouldShowPrompt()
        };
    }

    resetDismissals() {
        this.dismissedCount = 0;
        this.saveInstallPreference('dismissed', 0);
        console.log('💿 Install dismissals reset');
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
}