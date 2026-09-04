// beforeinstallprompt lands once, early, and never comes back.
//
// Chrome fires it as soon as it has decided the page is installable — which on
// Android is usually before install-prompt.js (a module, so deferred) has even
// been evaluated. A listener registered later never sees it, and the event is
// not replayed. Worse, without preventDefault() Chrome runs its own default
// action for the event, and the object we stashed can no longer be prompted
// with: prompt() rejects, handleInstallClick() falls through to the manual
// guide, and the user ends up using "Add to Home screen" — which mints a
// browser shortcut, not a WebAPK. That is the whole bug: the app looked
// installable, the button did nothing real, and the icon that landed on the
// home screen opened a Chrome tab.
//
// So this file is a classic, blocking <script> in <head>: it is the first
// listener on the page, it takes the event out of Chrome's hands, and it holds
// it until PWAInstallPrompt is ready to adopt it.
(function () {
    if (window.__pwaInstallCapture) return;
    window.__pwaInstallCapture = true;

    window.__pwaInstallEvent = null;
    window.__pwaAppInstalled = false;

    window.addEventListener('beforeinstallprompt', function (event) {
        event.preventDefault();
        window.__pwaInstallEvent = event;

        // If the prompt UI is already up, hand it over now; otherwise its
        // constructor picks the event up from window.__pwaInstallEvent.
        if (window.pwaInstallPrompt && typeof window.pwaInstallPrompt.adoptInstallEvent === 'function') {
            window.pwaInstallPrompt.adoptInstallEvent(event);
        }
    });

    window.addEventListener('appinstalled', function () {
        window.__pwaInstallEvent = null;
        window.__pwaAppInstalled = true;
    });
})();
