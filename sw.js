// SecureBit.chat Service Worker
// Enhanced Security Edition v4.01.441

const CACHE_NAME = 'securebit-v4.0.3';
const STATIC_CACHE = 'securebit-static-v4.0.3';
const DYNAMIC_CACHE = 'securebit-dynamic-v4.0.3';

// Files to cache for offline functionality (excluding external CDNs that may have CORS issues)
const STATIC_ASSETS = [
    '/',
    '/index.html',
    '/manifest.json',
    '/src/crypto/EnhancedSecureCryptoUtils.js',
    '/src/network/EnhancedSecureWebRTCManager.js',
    '/src/session/PayPerSessionManager.js',
    '/src/components/ui/SessionTimer.jsx',
    '/src/components/ui/Header.jsx',
    '/src/components/ui/PasswordModal.jsx',
    '/src/components/ui/SessionTypeSelector.jsx',
    '/src/components/ui/LightningPayment.jsx',
    '/src/components/ui/PaymentModal.jsx',
    '/src/components/ui/DownloadApps.jsx',
    '/src/styles/main.css',
    '/src/styles/animations.css',
    '/src/styles/components.css',
    '/src/styles/pwa.css',
    '/logo/favicon.ico'
];

// Sensitive files that should never be cached
const SENSITIVE_PATTERNS = [
    /\/api\//,
    /preimage/,
    /payment/,
    /session/,
    /auth/,
    /verification/
];

// Network first patterns (always try network first)
const NETWORK_FIRST_PATTERNS = [
    /\.js$/,
    /\.jsx$/,
    /\/src\//,
    /api/,
    /lightning/
];

// Cache first patterns (static assets)
const CACHE_FIRST_PATTERNS = [
    /\.css$/,
    /\.png$/,
    /\.jpg$/,
    /\.svg$/,
    /\.ico$/,
    /fonts/,
    /logo/
];

self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'PWA_INSTALLED') {
        self.clients.matchAll().then(clients => {
            clients.forEach(client => {
                client.postMessage({ type: 'PWA_INSTALL_DETECTED' });
            });
        });
    }
});
// Install event - cache static assets with better error handling
self.addEventListener('install', (event) => {
    console.log('🔧 Service Worker installing...');
    
    event.waitUntil(
        caches.open(STATIC_CACHE)
            .then(async (cache) => {
                console.log('📦 Caching static assets...');
                
                // Cache assets one by one to handle failures gracefully
                const cachePromises = STATIC_ASSETS.map(async (url) => {
                    try {
                        // Skip sensitive patterns
                        if (SENSITIVE_PATTERNS.some(pattern => pattern.test(url))) {
                            return;
                        }
                        
                        await cache.add(url);
                        console.log(`✅ Cached: ${url}`);
                    } catch (error) {
                        console.warn(`⚠️ Failed to cache ${url}:`, error.message);
                        // Continue with other assets even if one fails
                    }
                });
                
                await Promise.allSettled(cachePromises);
                console.log('✅ Static assets caching completed');
                
                // Force activation of new service worker
                return self.skipWaiting();
            })
            .catch((error) => {
                console.error('❌ Failed to open cache:', error);
                // Still skip waiting to activate the service worker
                return self.skipWaiting();
            })
    );
});

// Activate event - clean up old caches and notify about updates
self.addEventListener('activate', (event) => {
    console.log('🚀 Service Worker activating...');
    
    event.waitUntil(
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames.map(cacheName => {
                    // Remove old caches
                    if (cacheName !== STATIC_CACHE && cacheName !== DYNAMIC_CACHE && cacheName !== CACHE_NAME) {
                        console.log(`🗑️ Removing old cache: ${cacheName}`);
                        return caches.delete(cacheName);
                    }
                })
            );
        }).then(() => {
            console.log('✅ Service Worker activated and old caches cleaned');
            
            // Notify all clients about the update
            return self.clients.claim().then(() => {
                self.clients.matchAll().then(clients => {
                    clients.forEach(client => {
                        client.postMessage({
                            type: 'SW_ACTIVATED',
                            timestamp: Date.now()
                        });
                    });
                });
            });
        })
    );
});

// Удаляем дублирующийся код activate event

// Fetch event - handle requests with security-aware caching
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    
    // Skip non-GET requests
    if (event.request.method !== 'GET') {
        return;
    }
    
    // Skip sensitive endpoints
    if (SENSITIVE_PATTERNS.some(pattern => pattern.test(url.pathname))) {
        console.log('🔒 Skipping cache for sensitive endpoint:', url.pathname);
        return;
    }
    
    // Skip chrome-extension and non-http requests
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        return;
    }
    
    event.respondWith(handleRequest(event.request));
});

// Smart request handling with security considerations
async function handleRequest(request) {
    const url = new URL(request.url);
    
    try {
        // Strategy 1: Cache First (for static assets)
        if (CACHE_FIRST_PATTERNS.some(pattern => pattern.test(url.pathname))) {
            return await cacheFirst(request);
        }
        
        // Strategy 2: Network First (for dynamic content and security-critical files)
        if (NETWORK_FIRST_PATTERNS.some(pattern => pattern.test(url.pathname))) {
            return await networkFirst(request);
        }
        
        // Strategy 3: Stale While Revalidate (for main pages)
        return await staleWhileRevalidate(request);
        
    } catch (error) {
        console.error('❌ Request handling failed:', error);
        return await handleOffline(request);
    }
}

// Cache First strategy with Response cloning fix
async function cacheFirst(request) {
    const cachedResponse = await caches.match(request);
    if (cachedResponse) {
        return cachedResponse;
    }
    
    try {
        const networkResponse = await fetch(request);
        if (networkResponse && networkResponse.ok) {
            // Clone the response before using it
            const responseToCache = networkResponse.clone();
            const cache = await caches.open(STATIC_CACHE);
            cache.put(request, responseToCache);
        }
        return networkResponse;
    } catch (error) {
        console.warn('⚠️ Cache-first strategy failed:', error.message);
        return await handleOffline(request);
    }
}

// Network First strategy with Response cloning fix
async function networkFirst(request) {
    try {
        const networkResponse = await fetch(request);
        if (networkResponse && networkResponse.ok) {
            // Only cache non-sensitive successful responses
            if (!SENSITIVE_PATTERNS.some(pattern => pattern.test(request.url))) {
                // Clone the response before caching
                const responseToCache = networkResponse.clone();
                const cache = await caches.open(DYNAMIC_CACHE);
                cache.put(request, responseToCache);
            }
        }
        return networkResponse;
    } catch (error) {
        console.warn('⚠️ Network-first strategy failed:', error.message);
        const cachedResponse = await caches.match(request);
        if (cachedResponse) {
            return cachedResponse;
        }
        return await handleOffline(request);
    }
}

// Stale While Revalidate strategy with Response cloning fix
async function staleWhileRevalidate(request) {
    const cachedResponse = await caches.match(request);
    
    const networkResponsePromise = fetch(request)
        .then((networkResponse) => {
            if (networkResponse && networkResponse.ok && 
                !SENSITIVE_PATTERNS.some(pattern => pattern.test(request.url))) {
                // Clone the response before caching
                const responseToCache = networkResponse.clone();
                caches.open(DYNAMIC_CACHE)
                    .then(cache => cache.put(request, responseToCache))
                    .catch(error => console.warn('⚠️ Cache update failed:', error.message));
            }
            return networkResponse;
        })
        .catch(error => {
            console.warn('⚠️ Network request failed:', error.message);
            return null;
        });
    
    return cachedResponse || networkResponsePromise || handleOffline(request);
}

// Offline fallback
async function handleOffline(request) {
    const url = new URL(request.url);
    
    // For navigation requests, return cached index.html
    if (request.destination === 'document') {
        const cachedIndex = await caches.match('/');
        if (cachedIndex) {
            return cachedIndex;
        }
    }
    
    // For images, return a placeholder or cached version
    if (request.destination === 'image') {
        return new Response(
            '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200" viewBox="0 0 200 200"><rect width="200" height="200" fill="#1a1a1a"/><text x="100" y="100" text-anchor="middle" fill="#666" font-size="14">Offline</text></svg>',
            { headers: { 'Content-Type': 'image/svg+xml' } }
        );
    }
    
    // Return a generic offline response
    return new Response(
        JSON.stringify({ error: 'Offline', message: 'Network unavailable' }), 
        {
            status: 503,
            statusText: 'Service Unavailable',
            headers: { 'Content-Type': 'application/json' }
        }
    );
}

// Background sync for failed requests
self.addEventListener('sync', (event) => {
    console.log('🔄 Background sync triggered:', event.tag);
    
    if (event.tag === 'retry-failed-requests') {
        event.waitUntil(retryFailedRequests());
    }
});

// Retry failed requests when back online
async function retryFailedRequests() {
    console.log('🔄 Retrying failed requests...');
}

// Push notification handler
self.addEventListener('push', (event) => {
    console.log('📨 Push notification received');

});

// Notification click handler
self.addEventListener('notificationclick', (event) => {
    console.log('🔔 Notification clicked');
    event.notification.close();
    
    event.waitUntil(
        clients.openWindow('/')
    );
});

// Message handler for communication with main thread
self.addEventListener('message', (event) => {
    console.log('💬 Message from main thread:', event.data);
    
    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting();
    }
    
    if (event.data && event.data.type === 'CACHE_CLEAR') {
        event.waitUntil(clearCaches());
    }
    
    if (event.data && event.data.type === 'CACHE_STATUS') {
        event.waitUntil(getCacheStatus().then(status => {
            event.ports[0].postMessage(status);
        }));
    }
});

// Clear all caches
async function clearCaches() {
    const cacheNames = await caches.keys();
    await Promise.all(
        cacheNames.map(cacheName => caches.delete(cacheName))
    );
    console.log('🗑️ All caches cleared');
}

// Get cache status
async function getCacheStatus() {
    const cacheNames = await caches.keys();
    const status = {};
    
    for (const cacheName of cacheNames) {
        const cache = await caches.open(cacheName);
        const keys = await cache.keys();
        status[cacheName] = keys.length;
    }
    
    return status;
}

// Error handler
self.addEventListener('error', (event) => {
    console.error('❌ Service Worker error:', event.error);
});

// Unhandled rejection handler
self.addEventListener('unhandledrejection', (event) => {
    console.error('❌ Service Worker unhandled rejection:', event.reason);
});

console.log('🔧 SecureBit.chat Service Worker loaded - Enhanced Security Edition v4.01.441');