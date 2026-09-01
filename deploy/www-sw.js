// Self-destructing service worker, served ONLY at https://www.securebit.chat/sw.js.
//
// www.securebit.chat answered TLS for the first time when its Fly certificate was
// issued, and for the couple of minutes before the redirect below shipped it served
// the real app. That was long enough for visitors to register the site's service
// worker against the www origin. A registered worker outlives the server change: it
// keeps serving its cached app shell, so the 301 is never reached, while every
// subresource request does reach the network, gets redirected to the apex, and is
// then refused by the page's own CSP (`script-src 'self'` — and 'self' is www).
//
// The redirect cannot clear this on its own. A service worker script is re-fetched
// to check for updates, and the spec fails that update if the script URL redirects
// at all, let alone cross-origin — so a plain 301 on /sw.js pins the stale worker in
// place permanently. The only way out is to answer /sw.js with a real script that
// takes over and then removes itself.
//
// It is served with no-store, so browsers re-check it on every navigation rather
// than trusting a cached copy for 24 hours.

self.addEventListener('install', () => {
    // Do not wait for the old worker's clients to go away — they are exactly the
    // broken tabs this exists to rescue.
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil((async () => {
        // Drop the app shell the previous worker cached under this origin, so nothing
        // can be replayed from it if the unregister below is interrupted.
        const names = await caches.keys();
        await Promise.all(names.map((name) => caches.delete(name)));

        await self.registration.unregister();

        // Reload whatever is still open. With no worker left, the navigation reaches
        // nginx and follows the 301 to the apex, where the app actually lives.
        const clients = await self.clients.matchAll({ type: 'window' });
        for (const client of clients) {
            try {
                await client.navigate(client.url);
            } catch (_) {
                // A client that refuses to be navigated (cross-origin owner, or already
                // gone) is not worth failing activation over; its next reload is clean.
            }
        }
    })());
});

// Deliberately no fetch handler: until the unregister lands, requests should go
// straight to the network, which is where the redirect is.
