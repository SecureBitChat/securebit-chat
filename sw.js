// SecureBit.chat Service Worker
// Conservative PWA Edition v4.7.56 - Minimal Caching Strategy
// Enhanced with version-aware cache management

// Dynamic version detection from meta.json
let APP_VERSION = 'v4.7.56';
let CACHE_NAME = 'securebit-pwa-v4.7.56';
let STATIC_CACHE = 'securebit-pwa-static-v4.7.56';
let DYNAMIC_CACHE = 'securebit-pwa-dynamic-v4.7.56';

// Load version from meta.json on install
async function getAppVersion() {
    try {
        const response = await fetch('/meta.json?t=' + Date.now(), {
            cache: 'no-store',
            headers: {
                'Cache-Control': 'no-cache, no-store, must-revalidate'
            }
        });
        if (response.ok) {
            const meta = await response.json();
            const version = meta.version || meta.buildVersion || 'v4.7.56';
            APP_VERSION = version;
            CACHE_NAME = `securebit-pwa-${version}`;
            STATIC_CACHE = `securebit-pwa-static-${version}`;
            DYNAMIC_CACHE = `securebit-pwa-dynamic-${version}`;
            return version;
        }
    } catch (error) {
        console.warn('⚠️ Failed to load version from meta.json, using default');
    }
    return APP_VERSION;
}

// Essential files for PWA offline functionality
// DO NOT include JS files from dist/ - they should load from network for updates
const STATIC_ASSETS = [
    '/',
    '/index.html',
    '/manifest.json',
    
    // DO NOT cache /dist/app.js and /dist/app-boot.js - they should be updated
    // This allows the update system to work correctly
    
    // Essential styles for PWA
    '/src/styles/pwa.css',
    
    // PWA icons (required for install)
    '/logo/icon-192x192.png',
    '/logo/icon-512x512.png',
    '/logo/favicon.ico',
    
    // PWA components only
    '/src/pwa/pwa-manager.js',
    '/src/pwa/install-prompt.js',
    '/src/scripts/pwa-register.js',
    '/src/scripts/pwa-offline-test.js'
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
    /\/api\//,
    /\/session\//,
    /\/payment\//,
    /\/verification\//,
    /preimage/,
    /auth/
];

// Cache first patterns (only essential PWA assets)
const CACHE_FIRST_PATTERNS = [
    /manifest\.json$/,
    /logo\/icon-.*\.png$/,
    /logo\/favicon\.ico$/,
    /src\/styles\/pwa\.css$/,
    /src\/pwa\/.*\.js$/,
    /src\/scripts\/pwa-.*\.js$/
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
    
    event.waitUntil(
        getAppVersion().then(async (version) => {
            console.log('📦 Service Worker installing with version:', version);
            
            return caches.open(STATIC_CACHE)
                .then(async (cache) => {
                    
                    // Cache assets one by one to handle failures gracefully
                    const cachePromises = STATIC_ASSETS.map(async (url) => {
                        try {
                            // Skip sensitive patterns
                            if (SENSITIVE_PATTERNS.some(pattern => pattern.test(url))) {
                                return;
                            }
                            
                            // Add cache-busting for meta.json
                            if (url.includes('meta.json')) {
                                url = url + '?t=' + Date.now();
                            }
                            
                            await cache.add(url);
                        } catch (error) {
                            console.warn(`⚠️ Failed to cache ${url}:`, error.message);
                            // Continue with other assets even if one fails
                        }
                    });
                    
                    await Promise.allSettled(cachePromises);
                    
                    // Force activation of new service worker
                    return self.skipWaiting();
                })
                .catch((error) => {
                    console.error('❌ Failed to open cache:', error);
                    // Still skip waiting to activate the service worker
                    return self.skipWaiting();
                });
        })
    );
});

// Activate event - clean up old caches and notify about updates
self.addEventListener('activate', (event) => {
    
    event.waitUntil(
        getAppVersion().then(async (version) => {
            console.log('✅ Service Worker activating with version:', version);
            
            const cacheNames = await caches.keys();
            
            // Remove all old caches that don't match current version
            const deletePromises = cacheNames.map(cacheName => {
                // Remove caches that don't match current version
                if (cacheName !== STATIC_CACHE && 
                    cacheName !== DYNAMIC_CACHE && 
                    cacheName !== CACHE_NAME &&
                    cacheName.startsWith('securebit-pwa-')) {
                    console.log(`🗑️ Removing old cache: ${cacheName}`);
                    return caches.delete(cacheName);
                }
            });
            
            await Promise.all(deletePromises);
            
            // Notify all clients about the update
            return self.clients.claim().then(() => {
                self.clients.matchAll().then(clients => {
                    clients.forEach(client => {
                        client.postMessage({
                            type: 'SW_ACTIVATED',
                            version: version,
                            timestamp: Date.now()
                        });
                    });
                });
            });
        })
    );
});

// Removed duplicate activate event code

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
    
    // Network-first for meta.json (never cache)
    if (url.pathname === '/meta.json' || url.pathname.endsWith('/meta.json')) {
        event.respondWith(
            fetch(event.request, {
                cache: 'no-store',
                headers: {
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache'
                }
            }).catch(() => {
                // Fallback if network is unavailable
                return new Response(JSON.stringify({ 
                    version: APP_VERSION,
                    error: 'Network unavailable'
                }), {
                    headers: { 'Content-Type': 'application/json' }
                });
            })
        );
        return;
    }
    
    // Network-first for JS files from dist/ (don't cache for updates)
    if (url.pathname.startsWith('/dist/') && (url.pathname.endsWith('.js') || url.pathname.endsWith('.mjs'))) {
        event.respondWith(
            fetch(event.request, {
                cache: 'no-store',
                headers: {
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache'
                }
            }).catch((error) => {
                // Log error for debugging
                console.warn('⚠️ Failed to fetch JS file:', url.pathname, error.message);
                // Try to get from cache as fallback
                return caches.match(event.request).then(cachedResponse => {
                    if (cachedResponse) {
                        console.log('📦 Using cached version of:', url.pathname);
                        return cachedResponse;
                    }
                    // Only return 503 if no cache available
                    return new Response('Network unavailable', { 
                        status: 503,
                        statusText: 'Service Unavailable',
                        headers: { 'Content-Type': 'text/plain' }
                    });
                });
            })
        );
        return;
    }
    
    event.respondWith(handleRequest(event.request));
});

// Conservative request handling - only cache PWA essentials
async function handleRequest(request) {
    const url = new URL(request.url);
    
    try {
        // Strategy 1: Cache First (only for essential PWA assets)
        if (CACHE_FIRST_PATTERNS.some(pattern => pattern.test(url.pathname))) {
            return await cacheFirst(request);
        }
        
        // Strategy 2: Network First (for all other requests)
        if (NETWORK_FIRST_PATTERNS.some(pattern => pattern.test(url.pathname))) {
            return await networkFirst(request);
        }
        
        // Strategy 3: Network First for everything else (no aggressive caching)
        return await networkFirst(request);
        
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
                cache.put(request, responseToCache).catch(err => {
                    console.warn('⚠️ Cache put failed (non-critical):', err.message);
                });
            }
            return networkResponse;
        }
        // If response is not ok, try cache
        const cachedResponse = await caches.match(request);
        if (cachedResponse) {
            return cachedResponse;
        }
        return networkResponse; // Return the non-ok response anyway
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

// Offline fallback - minimal caching for PWA only
async function handleOffline(request) {
    const url = new URL(request.url);
    
    // For navigation requests, return cached index.html
    if (request.destination === 'document' || request.mode === 'navigate') {
        const cachedIndex = await caches.match('/index.html');
        if (cachedIndex) {
            return cachedIndex;
        }
        
        // Fallback to root if index.html not found
        const cachedRoot = await caches.match('/');
        if (cachedRoot) {
            return cachedRoot;
        }
    }
    
    // For PWA assets, try to return cached version
    if (CACHE_FIRST_PATTERNS.some(pattern => pattern.test(url.pathname))) {
        const cachedAsset = await caches.match(request);
        if (cachedAsset) {
            return cachedAsset;
        }
    }
    
    // Return a generic offline response for everything else
    return new Response(
        JSON.stringify({ 
            error: 'Offline', 
            message: 'Network unavailable - PWA offline mode',
            url: url.pathname
        }), 
        {
            status: 503,
            statusText: 'Service Unavailable',
            headers: { 'Content-Type': 'application/json' }
        }
    );
}

// Background sync for failed requests
self.addEventListener('sync', (event) => {
    
    if (event.tag === 'retry-failed-requests') {
        event.waitUntil(retryFailedRequests());
    }
});

async function retryFailedRequests() {
    try {
        // Get all cached requests that failed
        const cache = await caches.open(DYNAMIC_CACHE);
        const requests = await cache.keys();
        
        for (const request of requests) {
            try {
                // Try to fetch the request again
                const response = await fetch(request);
                if (response.ok) {
                    // Update cache with successful response
                    await cache.put(request, response);
                }
            } catch (error) {
                console.warn('⚠️ Retry failed for:', request.url, error.message);
            }
        }
    } catch (error) {
        console.error('❌ Failed to retry requests:', error);
    }
}



// Notification click handler
self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    
    event.waitUntil(
        clients.openWindow('/')
    );
});

// Message handler for communication with main thread
self.addEventListener('message', (event) => {
    
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
