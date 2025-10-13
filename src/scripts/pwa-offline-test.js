// PWA Offline Test Script for SecureBit.chat
// Enhanced Security Edition v4.3.120
// Tests offline functionality and cache status

class PWAOfflineTester {
    constructor() {
        this.testResults = [];
        this.isRunning = false;
    }

    async runTests() {
        if (this.isRunning) {
            console.warn('⚠️ Tests already running');
            return;
        }

        this.isRunning = true;
        this.testResults = [];
        
        console.log('🧪 Starting PWA Offline Tests...');
        
        try {
            await this.testServiceWorkerRegistration();
            await this.testCacheStatus();
            await this.testOfflineResources();
            await this.testOnlineResources();
            
            this.showTestResults();
        } catch (error) {
            console.error('❌ Test failed:', error);
            this.addTestResult('Test Suite', false, `Test suite failed: ${error.message}`);
        } finally {
            this.isRunning = false;
        }
    }

    async testServiceWorkerRegistration() {
        try {
            if ('serviceWorker' in navigator) {
                const registration = await navigator.serviceWorker.getRegistration();
                if (registration) {
                    this.addTestResult('Service Worker Registration', true, 'Service worker is registered');
                } else {
                    this.addTestResult('Service Worker Registration', false, 'No service worker found');
                }
            } else {
                this.addTestResult('Service Worker Support', false, 'Service worker not supported');
            }
        } catch (error) {
            this.addTestResult('Service Worker Registration', false, `Error: ${error.message}`);
        }
    }

    async testCacheStatus() {
        try {
            if ('caches' in window) {
                const cacheNames = await caches.keys();
                const totalCached = 0;
                
                for (const cacheName of cacheNames) {
                    const cache = await caches.open(cacheName);
                    const keys = await cache.keys();
                    totalCached += keys.length;
                }
                
                if (totalCached > 0) {
                    this.addTestResult('Cache Status', true, `${totalCached} resources cached`);
                } else {
                    this.addTestResult('Cache Status', false, 'No resources cached');
                }
            } else {
                this.addTestResult('Cache API Support', false, 'Cache API not supported');
            }
        } catch (error) {
            this.addTestResult('Cache Status', false, `Error: ${error.message}`);
        }
    }

    async testOfflineResources() {
        const criticalResources = [
            '/',
            '/index.html',
            '/manifest.json',
            '/dist/app.js',
            '/dist/app-boot.js',
            '/libs/react/react.production.min.js',
            '/libs/react-dom/react-dom.production.min.js',
            '/assets/tailwind.css'
        ];

        let cachedCount = 0;
        
        for (const resource of criticalResources) {
            try {
                const cached = await caches.match(resource);
                if (cached) {
                    cachedCount++;
                }
            } catch (error) {
                console.warn(`⚠️ Failed to check cache for ${resource}:`, error);
            }
        }

        const success = cachedCount >= criticalResources.length * 0.8; // 80% success rate
        this.addTestResult('Critical Resources Cached', success, 
            `${cachedCount}/${criticalResources.length} critical resources cached`);
    }

    async testOnlineResources() {
        try {
            // Test if we can fetch a simple resource
            const response = await fetch('/favicon.ico', { 
                method: 'HEAD',
                cache: 'no-cache'
            });
            
            if (response.ok) {
                this.addTestResult('Network Connectivity', true, 'Network is accessible');
            } else {
                this.addTestResult('Network Connectivity', false, `Network error: ${response.status}`);
            }
        } catch (error) {
            this.addTestResult('Network Connectivity', false, `Network error: ${error.message}`);
        }
    }

    addTestResult(testName, passed, message) {
        this.testResults.push({
            name: testName,
            passed,
            message,
            timestamp: new Date().toISOString()
        });
        
        console.log(`${passed ? '✅' : '❌'} ${testName}: ${message}`);
    }

    showTestResults() {
        const passedTests = this.testResults.filter(test => test.passed).length;
        const totalTests = this.testResults.length;
        const successRate = Math.round((passedTests / totalTests) * 100);

        const modal = document.createElement('div');
        modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4 backdrop-blur-sm';
        modal.innerHTML = `
            <div class="bg-gray-800 rounded-xl p-6 max-w-2xl w-full max-h-[80vh] overflow-y-auto">
                <div class="flex items-center mb-6">
                    <div class="w-12 h-12 bg-blue-500/10 rounded-full flex items-center justify-center mr-4">
                        <i class="fas fa-vial text-blue-400 text-xl"></i>
                    </div>
                    <h3 class="text-xl font-semibold text-white">PWA Offline Test Results</h3>
                </div>
                
                <div class="mb-6 p-4 rounded-lg ${successRate >= 80 ? 'bg-green-500/10 border border-green-500/20' : 'bg-red-500/10 border border-red-500/20'}">
                    <div class="flex items-center justify-between">
                        <div>
                            <div class="font-medium text-white">Overall Score</div>
                            <div class="text-sm text-gray-300">${passedTests}/${totalTests} tests passed</div>
                        </div>
                        <div class="text-2xl font-bold ${successRate >= 80 ? 'text-green-400' : 'text-red-400'}">
                            ${successRate}%
                        </div>
                    </div>
                </div>
                
                <div class="space-y-3">
                    ${this.testResults.map(test => `
                        <div class="flex items-center justify-between p-3 rounded-lg ${test.passed ? 'bg-green-500/10 border border-green-500/20' : 'bg-red-500/10 border border-red-500/20'}">
                            <div class="flex items-center space-x-3">
                                <i class="fas ${test.passed ? 'fa-check-circle text-green-400' : 'fa-times-circle text-red-400'}"></i>
                                <div>
                                    <div class="font-medium text-white">${test.name}</div>
                                    <div class="text-sm text-gray-300">${test.message}</div>
                                </div>
                            </div>
                        </div>
                    `).join('')}
                </div>
                
                <div class="mt-6 space-y-3">
                    <div class="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
                        <h4 class="font-medium text-blue-300 mb-2">Recommendations:</h4>
                        <ul class="text-sm text-blue-200 space-y-1">
                            ${this.getRecommendations().map(rec => `<li>• ${rec}</li>`).join('')}
                        </ul>
                    </div>
                    
                    <div class="flex space-x-3">
                        <button onclick="window.pwaOfflineTester.runTests(); this.parentElement.parentElement.parentElement.remove();" 
                                class="flex-1 bg-blue-500 hover:bg-blue-600 text-white py-3 px-4 rounded-lg font-medium transition-colors">
                            Run Tests Again
                        </button>
                        <button onclick="this.parentElement.parentElement.remove()" 
                                class="flex-1 bg-gray-600 hover:bg-gray-500 text-white py-3 px-4 rounded-lg font-medium transition-colors">
                            Close
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
    }

    getRecommendations() {
        const recommendations = [];
        
        const failedTests = this.testResults.filter(test => !test.passed);
        
        if (failedTests.some(test => test.name.includes('Service Worker'))) {
            recommendations.push('Ensure service worker is properly registered and active');
        }
        
        if (failedTests.some(test => test.name.includes('Cache'))) {
            recommendations.push('Check cache configuration and ensure resources are being cached');
        }
        
        if (failedTests.some(test => test.name.includes('Network'))) {
            recommendations.push('Verify network connectivity and server availability');
        }
        
        if (recommendations.length === 0) {
            recommendations.push('All tests passed! Your PWA offline functionality is working correctly.');
        }
        
        return recommendations;
    }

    // Public API
    getTestResults() {
        return this.testResults;
    }

    clearResults() {
        this.testResults = [];
    }
}

// Singleton pattern
let instance = null;

const PWAOfflineTesterAPI = {
    getInstance() {
        if (!instance) {
            instance = new PWAOfflineTester();
        }
        return instance;
    },
    
    runTests() {
        return this.getInstance().runTests();
    }
};

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PWAOfflineTesterAPI;
} else if (typeof window !== 'undefined' && !window.PWAOfflineTester) {
    window.PWAOfflineTester = PWAOfflineTesterAPI;
}

// Auto-initialize
if (typeof window !== 'undefined' && !window.pwaOfflineTester) {
    window.pwaOfflineTester = PWAOfflineTesterAPI.getInstance();
    
    // Add global function for easy access
    window.testPWAOffline = () => {
        window.pwaOfflineTester.runTests();
    };
}
